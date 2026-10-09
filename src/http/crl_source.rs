//! A [`CrlSource`] that downloads lists over HTTP. Behind the `net` feature; the revocation checking
//! itself (`crate::revocation`) is pure and is handed whatever a source returns.

use crate::revocation::{Crl, CrlSource, Revocation};
use crate::verify_error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How many lists the cache keeps at most.
const MAX_LISTS: usize = 64;
/// How many bytes of lists (as downloaded) the cache keeps at most.
const MAX_BYTES: usize = 64 << 20;
/// A list is fetched again in the background, while the one in the cache is still used, once less than this share of its
/// window is left (or less than an hour, whichever is more).
const REFRESH_SHARE: i64 = 10;

/// Fetches CRLs over plain HTTP from the distribution points named in a certificate, and keeps
/// them until their `nextUpdate`.
///
/// The download is not a secure channel and does not need to be: the list is verified against the
/// certificate's issuer before it counts. Fetches are limited in size (16 MiB) and time (10 s),
/// follow no more than three redirects, and only `http://` URLs are used.
///
/// The cache holds at most 64 lists and 64 MiB of them; the one used longest ago goes first. A list whose window is nearly
/// over (less than a tenth of it, or an hour, left) is fetched again on a thread of its own while the one in the cache is
/// still used, so that a busy client does not wait for the download when the list runs out; a list whose window has ended is
/// fetched before it is used.
pub struct HttpCrlSource {
    inner: Arc<Inner>,
}

struct Inner {
    client: crate::http::Client,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    /// url -> the list, its size as downloaded, and when it was last used
    lists: HashMap<String, Entry>,
    bytes: usize,
    clock: u64,
}

struct Entry {
    crl: Arc<Crl>,
    size: usize,
    used: u64,
    /// A fetch of a newer one is under way.
    refreshing: bool,
}

impl HttpCrlSource {
    pub fn new() -> HttpCrlSource {
        let mut tls = crate::tls::ClientConfig::new(crate::x509::TrustStore::empty());
        tls.revocation = Revocation::off();
        let client = crate::http::Client::with_tls_config(tls)
            .allow_insecure_http(true)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .total_timeout(Duration::from_secs(20))
            .max_redirects(3)
            .max_body_bytes(16 << 20);
        HttpCrlSource { inner: Arc::new(Inner { client, cache: Mutex::new(Cache::default()) }) }
    }

    /// How many lists are cached, and their size in bytes as downloaded.
    pub fn cached(&self) -> (usize, usize) {
        let c = self.inner.lock();
        (c.lists.len(), c.bytes)
    }
}

impl Default for HttpCrlSource {
    fn default() -> Self {
        HttpCrlSource::new()
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Downloads and parses the list at `url`, with its size.
    fn download(&self, url: &str) -> Result<(Arc<Crl>, usize)> {
        let response = self.client.get(url).map_err(|e| Error::Unavailable(format!("{}: {}", url, e)))?;
        if response.status != 200 {
            return Err(Error::Unavailable(format!("CRL download answered {}", response.status)));
        }
        let crl = if response.body.starts_with(b"-----BEGIN") {
            Crl::from_pem(&String::from_utf8_lossy(&response.body))?
        } else {
            Crl::from_der(&response.body)?
        };
        Ok((Arc::new(crl), response.body.len()))
    }

    /// Puts a list in the cache, making room for it by dropping the ones used longest ago.
    fn store(&self, url: &str, crl: Arc<Crl>, size: usize) {
        let mut c = self.lock();
        c.clock += 1;
        let used = c.clock;
        if let Some(old) = c.lists.remove(url) {
            c.bytes -= old.size;
        }
        if size > MAX_BYTES {
            return;
        }
        while c.lists.len() >= MAX_LISTS || c.bytes + size > MAX_BYTES {
            let Some(oldest) = c.lists.iter().min_by_key(|(_, e)| e.used).map(|(u, _)| u.clone()) else { break };
            if let Some(e) = c.lists.remove(&oldest) {
                c.bytes -= e.size;
            }
        }
        c.bytes += size;
        c.lists.insert(url.to_string(), Entry { crl, size, used, refreshing: false });
    }
}

/// Whether a list that is still good at `now` is near enough to its end to be fetched again.
fn due_for_refresh(crl: &Crl, now: i64) -> bool {
    let until = crl.valid_until();
    let window = (until - crl.this_update()).max(0);
    until - now < (window / REFRESH_SHARE).max(3600)
}

impl CrlSource for HttpCrlSource {
    fn fetch(&self, url: &str) -> Result<Arc<Crl>> {
        if !url.starts_with("http://") {
            return Err(Error::Unavailable(format!("not fetching a CRL from {:?}: only http:// URLs are used", url)));
        }
        let now = crate::sys::now_unix();
        let cached = {
            let mut c = self.inner.lock();
            c.clock += 1;
            let clock = c.clock;
            match c.lists.get_mut(url) {
                Some(e) if !e.crl.is_stale(now) => {
                    e.used = clock;
                    let refresh = !e.refreshing && due_for_refresh(&e.crl, now);
                    if refresh {
                        e.refreshing = true;
                    }
                    Some((e.crl.clone(), refresh))
                }
                _ => None,
            }
        };
        if let Some((crl, refresh)) = cached {
            if refresh {
                // the next list, fetched while this one is still used; if that fails, the next use tries again
                let inner = self.inner.clone();
                let at = url.to_string();
                let started = std::thread::Builder::new().name("pratique CRL refresh".into()).spawn(move || {
                    match inner.download(&at) {
                        Ok((fresh, size)) => inner.store(&at, fresh, size),
                        Err(_) => {
                            if let Some(e) = inner.lock().lists.get_mut(&at) {
                                e.refreshing = false;
                            }
                        }
                    }
                });
                if started.is_err() {
                    if let Some(e) = self.inner.lock().lists.get_mut(url) {
                        e.refreshing = false;
                    }
                }
            }
            return Ok(crl);
        }
        let (crl, size) = self.inner.download(url)?;
        self.inner.store(url, crl.clone(), size);
        Ok(crl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves `answers` (one raw HTTP response per connection, in order) on a local port.
    fn serve(answers: Vec<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = Arc::new(AtomicUsize::new(0));
        let count = served.clone();
        std::thread::spawn(move || {
            for answer in answers {
                let Ok((mut s, _)) = listener.accept() else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(&answer);
            }
        });
        (port, served)
    }

    fn http_ok(body: &[u8]) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn the_http_source_downloads_parses_and_refuses_bad_answers() {
        let good = include_bytes!("../../tests/data/rev_crl_empty.der").as_slice();
        let (port, served) = serve(vec![
            http_ok(good),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            http_ok(b"this is not a CRL"),
            http_ok(good),
        ]);
        let source = HttpCrlSource::new();
        let url = format!("http://127.0.0.1:{}/inter.crl", port);
        let crl = source.fetch(&url).unwrap();
        assert_eq!(crl.len(), 1);
        // the fixture's window closed long before the real clock (nextUpdate is 2026-09-20 in the
        // fixtures), so the cached copy is stale and the next call downloads again
        assert!(crl.is_stale(crate::sys::now_unix()));
        let err = source.fetch(&url).err().expect("a 404 is an error").to_string();
        assert!(err.contains("404"), "{}", err);
        assert!(source.fetch(&url).is_err(), "garbage is not a CRL");
        assert!(source.fetch(&url).is_ok());
        assert_eq!(served.load(Ordering::SeqCst), 4);
        // only plain http is used: nothing is sent for other schemes
        for bad in ["https://crl.example.test/x.crl", "ldap://crl.example.test/x", "file:///etc/passwd", "ftp://example.test/x.crl"] {
            let err = source.fetch(bad).err().expect("only http:// URLs are fetched").to_string();
            assert!(err.contains("only http://"), "{}: {}", bad, err);
        }
        assert_eq!(served.load(Ordering::SeqCst), 4);
    }
}
