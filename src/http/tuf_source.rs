//! Fetching a TUF repository over HTTPS for [`crate::tuf`] (BACKLOG B-82), and with it Sigstore's trusted root and npm's
//! keys. Behind the `net` feature; the TUF client itself is pure and is handed whatever this fetches.

use crate::http::Client;
use crate::trust_root::KeyRing;
use crate::tuf::{self, Fetched, Local, Request, TargetFile, Updater};

/// A TUF repository over HTTP(S): metadata under one URL, target files under another.
pub struct TufSource {
    client: Client,
    metadata_url: String,
    targets_url: String,
}

fn slash(url: &str) -> String {
    if url.ends_with('/') { url.to_string() } else { format!("{url}/") }
}

impl TufSource {
    /// A repository with its metadata at `repository_url` and its targets under `repository_url/targets/`, as Sigstore's
    /// is laid out.
    pub fn new(client: Client, repository_url: &str) -> TufSource {
        let base = slash(repository_url);
        TufSource { client, targets_url: format!("{base}targets/"), metadata_url: base }
    }

    /// A repository with its metadata and its targets at URLs of their own.
    pub fn with_urls(client: Client, metadata_url: &str, targets_url: &str) -> TufSource {
        TufSource { client, metadata_url: slash(metadata_url), targets_url: slash(targets_url) }
    }

    /// Sigstore's public repository, [`tuf::SIGSTORE_REPOSITORY`].
    pub fn sigstore(client: Client) -> TufSource {
        TufSource::new(client, tuf::SIGSTORE_REPOSITORY)
    }

    /// One file: its bytes (at most one byte more than asked for, so that a longer file is seen as one), or "not found"
    /// for a 404 or 403 (which is how a repository says there is no newer root), or an error.
    fn get(&self, base: &str, r: &Request) -> Result<Fetched, String> {
        let url = format!("{base}{}", r.path);
        let resp = self.client.request("GET", &url).max_body_bytes(r.max_length.saturating_add(1)).send().map_err(|e| e.to_string())?;
        match resp.status {
            200 => Ok(Fetched::Data(resp.body)),
            403 | 404 => Ok(Fetched::NotFound),
            s => Err(format!("{url}: HTTP {s}")),
        }
    }

    /// Brings `updater` up to date from this repository ([`tuf::refresh`]).
    pub fn refresh(&self, updater: &mut Updater, local: Local) -> Result<(), tuf::Error> {
        tuf::refresh(updater, local, &mut |r| self.get(&self.metadata_url, r))
    }

    /// Finds and fetches a target, after [`refresh`](Self::refresh) ([`tuf::fetch_target`]).
    pub fn fetch_target(&self, updater: &mut Updater, path: &str) -> Result<(TargetFile, Vec<u8>), tuf::Error> {
        let (m, t) = (&self.metadata_url, &self.targets_url);
        tuf::fetch_target(updater, path, &mut |r| self.get(m, r), &mut |r| self.get(t, r))
    }
}

/// What [`sigstore_trust`] brings back: Sigstore's trusted root and npm's keys as the repository gives them (read them
/// with [`crate::trust_root::TrustedRoot::parse`] and [`KeyRing::from_tuf_npm_keys`]), and the TUF metadata to keep for
/// the next refresh.
pub struct SigstoreTrust {
    /// `trusted_root.json`.
    pub trusted_root: Vec<u8>,
    /// `registry.npmjs.org/keys.json`.
    pub npm_keys: Vec<u8>,
    /// The newest TUF root: start from it next time instead of [`tuf::SIGSTORE_ROOT`].
    pub tuf_root: Vec<u8>,
    /// The timestamp and snapshot, to give back as [`Local`] next time (rollback protection).
    pub timestamp: Vec<u8>,
    pub snapshot: Vec<u8>,
}

/// Sigstore's trusted root and npm's keys from Sigstore's TUF repository, verified, at `now` (Unix seconds): starting from
/// `tuf_root` ([`tuf::SIGSTORE_ROOT`] the first time, then the [`SigstoreTrust::tuf_root`] of the last refresh) and the
/// timestamp and snapshot kept from then, if any.
pub fn sigstore_trust(client: &Client, tuf_root: &[u8], local: Local, now: i64) -> Result<SigstoreTrust, tuf::Error> {
    let source = TufSource::sigstore(client.clone());
    let mut u = Updater::new(tuf_root, now)?;
    source.refresh(&mut u, local)?;
    let (_, trusted_root) = source.fetch_target(&mut u, tuf::SIGSTORE_TRUSTED_ROOT_TARGET)?;
    let (_, npm_keys) = source.fetch_target(&mut u, tuf::NPM_KEYS_TARGET)?;
    let (timestamp, snapshot) = (u.timestamp().map(|t| t.1.to_vec()).unwrap_or_default(), u.snapshot().map(|s| s.1.to_vec()).unwrap_or_default());
    Ok(SigstoreTrust { trusted_root, npm_keys, tuf_root: u.root_bytes().to_vec(), timestamp, snapshot })
}

/// npm's registry keys straight from the registry (`https://registry.npmjs.org/-/npm/v1/keys`), read with
/// [`KeyRing::from_npm_keys`]. They are only as trustworthy as the TLS connection to the registry; the same keys through
/// Sigstore's TUF repository ([`sigstore_trust`]) are signed by Sigstore's keys as well, and carry the period each key may
/// be used for attestations.
pub fn npm_registry_keys(client: &Client) -> Result<KeyRing, String> {
    let resp = client.request("GET", "https://registry.npmjs.org/-/npm/v1/keys").max_body_bytes(1 << 20).send().map_err(|e| e.to_string())?;
    if resp.status != 200 {
        return Err(format!("HTTP {}", resp.status));
    }
    KeyRing::from_npm_keys(&resp.body).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testserver::{response, Reply, TestServer};
    use crate::json::{self, Value};
    use crate::pem::base64_decode_strict;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// A case of tests/data/tuf/synthetic.json: its time, bootstrap root, files (by path under `metadata/` and `targets/`),
    /// target and the target's bytes.
    fn synthetic(name: &str) -> (i64, Vec<u8>, BTreeMap<String, Vec<u8>>, String, Vec<u8>) {
        let doc = json::parse(include_bytes!("../../tests/data/tuf/synthetic.json")).unwrap();
        let blobs = doc.get("blobs").and_then(Value::as_object).unwrap();
        let blob = |h: &Value| base64_decode_strict(blobs.get(h.as_str().unwrap()).and_then(Value::as_str).unwrap()).unwrap();
        let c = doc.get("cases").and_then(Value::as_array).unwrap().iter().find(|c| c.get("name").and_then(Value::as_str) == Some(name)).unwrap();
        let files = c.get("files").and_then(Value::as_object).unwrap().iter().map(|(p, h)| (p.to_string(), blob(h))).collect();
        (doc.get("now").and_then(Value::as_int64).unwrap(), blob(c.get("bootstrap").unwrap()), files, c.get("target").and_then(Value::as_str).unwrap().into(), blob(c.get("content").unwrap()))
    }

    fn serve(files: BTreeMap<String, Vec<u8>>) -> TestServer {
        let files = Arc::new(files);
        TestServer::start_tls(move |seen| {
            let path = seen.path().trim_start_matches("/repo/");
            match files.get(path) {
                Some(b) => Reply::Send(response(200, &[], b)),
                None => Reply::Send(response(404, &[], b"not found")),
            }
        })
    }

    #[test]
    fn a_repository_over_https_gives_its_targets() {
        for (name, rotations) in [("two root rotations", 3), ("npm's keys through the delegated role", 1)] {
            let (now, bootstrap, files, target, content) = synthetic(name);
            let server = serve(files);
            let source = TufSource::with_urls(server.client(), &server.url("/repo/metadata"), &server.url("/repo/targets/"));
            let mut u = Updater::new(&bootstrap, now).unwrap();
            source.refresh(&mut u, Local::default()).unwrap();
            assert_eq!(u.root().common.version, rotations);
            let (info, data) = source.fetch_target(&mut u, &target).unwrap();
            assert_eq!((info.path.as_str(), data.as_slice()), (target.as_str(), content.as_slice()));
            // what was asked for, in order: roots until one is missing, timestamp, snapshot, targets, (role,) target
            let asked: Vec<String> = server.requests().iter().map(|s| s.path().to_string()).collect();
            assert_eq!(asked.iter().filter(|p| p.ends_with(".root.json")).count() as u64, rotations);
            assert!(asked.iter().position(|p| p.ends_with("timestamp.json")) < asked.iter().position(|p| p.contains("snapshot.json")), "{asked:?}");
            assert!(asked.last().unwrap().starts_with("/repo/targets/"), "{asked:?}");
        }
    }

    #[test]
    fn a_failing_repository_is_an_error_not_a_missing_file() {
        let (now, bootstrap, mut files, target, _) = synthetic("the trusted root");
        files.remove("metadata/timestamp.json");
        let server = serve(files);
        let source = TufSource::new(server.client(), &server.url("/repo/metadata"));
        let mut u = Updater::new(&bootstrap, now).unwrap();
        let e = source.refresh(&mut u, Local::default()).unwrap_err();
        assert!(matches!(e, tuf::Error::Fetch(ref m) if m.contains("timestamp.json is not in the repository")), "{e}");
        // a server error is not "not found"
        let server = TestServer::start_tls(|_| Reply::Send(response(500, &[], b"")));
        let source = TufSource::new(server.client(), &server.url("/repo/metadata"));
        let mut u = Updater::new(&bootstrap, now).unwrap();
        let e = source.refresh(&mut u, Local::default()).unwrap_err();
        assert!(matches!(e, tuf::Error::Fetch(ref m) if m.contains("HTTP 500")), "{e}");
        let _ = target;
    }

    #[test]
    fn a_file_longer_than_allowed_is_not_read_whole() {
        let (now, bootstrap, mut files, _, _) = synthetic("the trusted root");
        // a timestamp of a megabyte: more than the 16 KiB a timestamp may have
        files.insert("metadata/timestamp.json".into(), vec![b' '; 1 << 20]);
        let server = serve(files);
        let source = TufSource::new(server.client(), &server.url("/repo/metadata"));
        let mut u = Updater::new(&bootstrap, now).unwrap();
        let e = source.refresh(&mut u, Local::default()).unwrap_err();
        assert!(matches!(e, tuf::Error::Fetch(_) | tuf::Error::LengthOrHash(_)), "{e}");
    }

    #[test]
    fn the_sigstore_source_is_the_public_repository() {
        let s = TufSource::sigstore(Client::new().unwrap());
        assert_eq!((s.metadata_url.as_str(), s.targets_url.as_str()), ("https://tuf-repo-cdn.sigstore.dev/", "https://tuf-repo-cdn.sigstore.dev/targets/"));
        let s = TufSource::with_urls(Client::new().unwrap(), "https://m.example/a", "https://t.example/b/");
        assert_eq!((s.metadata_url.as_str(), s.targets_url.as_str()), ("https://m.example/a/", "https://t.example/b/"));
    }
}
