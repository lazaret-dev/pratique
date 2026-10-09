//! An [`OcspSource`] that asks responders over HTTP. Behind the `net` feature; the checking of what it gets back
//! (`crate::revocation`) is pure and is handed whatever it returns.

use crate::revocation::{ocsp_response_valid_until, OcspSource, Revocation};
use crate::verify_error::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// How many responses the cache keeps at most; the one used longest ago goes first.
const MAX_CACHED: usize = 1024;
/// The largest response taken (a response is usually under 4 KiB; one with a responder certificate a little more).
const MAX_RESPONSE: usize = 256 << 10;

/// Asks OCSP responders (RFC 6960) over plain HTTP: the request is POSTed as `application/ocsp-request` to the responder the
/// certificate names, and the answer kept until the end of its window (its `nextUpdate`), for at most 1024 certificates.
///
/// Plain HTTP is what OCSP is served over, and it does not need to be more: the response is verified (signed by the
/// certificate's issuer or by a responder it authorized, about this certificate, in its window) before it counts, every
/// time it is used. Requests are limited in size (256 KiB of answer) and time (5 s to connect, 10 s per read or write,
/// 20 s in all), follow at most three redirects, and go only to `http://` URLs. Requests carry no nonce: the responders of
/// the public CAs answer from responses they signed in advance and ignore one (RFC 5019), and what stops an old response is
/// its window, which is checked.
pub struct HttpOcspSource {
    client: crate::http::Client,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    /// (url, request) -> (response, valid until, last used)
    entries: HashMap<(String, Vec<u8>), (Vec<u8>, i64, u64)>,
    clock: u64,
}

impl HttpOcspSource {
    pub fn new() -> HttpOcspSource {
        let mut tls = crate::tls::ClientConfig::new(crate::x509::TrustStore::empty());
        tls.revocation = Revocation::off();
        let client = crate::http::Client::with_tls_config(tls)
            .allow_insecure_http(true)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .total_timeout(Duration::from_secs(20))
            .max_redirects(3)
            .max_body_bytes(MAX_RESPONSE as u64);
        HttpOcspSource { client, cache: Mutex::new(Cache::default()) }
    }

    /// How many responses are cached.
    pub fn cached(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).entries.len()
    }
}

impl Default for HttpOcspSource {
    fn default() -> Self {
        HttpOcspSource::new()
    }
}

impl OcspSource for HttpOcspSource {
    fn fetch(&self, url: &str, request: &[u8]) -> Result<Vec<u8>> {
        if !url.starts_with("http://") {
            return Err(Error::Unavailable(format!("not asking the OCSP responder at {:?}: only http:// URLs are used", url)));
        }
        let now = crate::sys::now_unix();
        let key = (url.to_string(), request.to_vec());
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.clock += 1;
            let clock = cache.clock;
            if let Some((response, until, used)) = cache.entries.get_mut(&key) {
                if now <= *until {
                    *used = clock;
                    return Ok(response.clone());
                }
            }
        }
        let response = self
            .client
            .request("POST", url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request.to_vec())
            .send()
            .map_err(|e| Error::Unavailable(format!("{}: {}", url, e)))?;
        if response.status != 200 {
            return Err(Error::Unavailable(format!("the OCSP responder answered {}", response.status)));
        }
        let body = response.body;
        // kept only if it is a successful response with a window that has not ended (it is verified when it is used)
        if let Some(until) = ocsp_response_valid_until(&body).filter(|&u| u >= now) {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.clock += 1;
            let clock = cache.clock;
            if cache.entries.len() >= MAX_CACHED && !cache.entries.contains_key(&key) {
                if let Some(oldest) = cache.entries.iter().min_by_key(|(_, (_, _, used))| *used).map(|(k, _)| k.clone()) {
                    cache.entries.remove(&oldest);
                }
            }
            cache.entries.insert(key, (body.clone(), until, clock));
        }
        Ok(body)
    }
}
