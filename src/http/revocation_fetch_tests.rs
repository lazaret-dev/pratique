//! Revocation evidence that the client asks for (BACKLOG B-63, B-64): OCSP requests and the sources that send them, the
//! responders and CRLs of intermediates, the deferred check of the async client, and the caches of the HTTP sources.
//!
//! The chains here are made by the test PKI (Ed25519, a root, an intermediate and a leaf, each naming a responder and a
//! distribution point), and so are the OCSP responses and CRLs, signed by the issuers' keys; the sources are stubs that
//! hand them out and write down who asked, or the HTTP sources against scripted servers.

use super::testserver::{response, Reply, Seen, TestServer};
use super::{HttpCrlSource, HttpOcspSource};
use crate::asyncio::block_on;
use crate::revocation::{ocsp_request, ChainEvidence, Crl, CrlSource, OcspSource, Revocation, RevocationMode};
use crate::tls::pki::{crl, issue, ocsp_response, CertSpec, KeyPair, OcspStatus};
use crate::tls::server::ServerConfig;
use crate::tls::ClientConfig;
use crate::verify_error::{Error, Result};
use crate::x509::{Certificate, TrustStore};
use crate::Client;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DAY: i64 = 86_400;

/// A root, an intermediate and a leaf for `localhost` and 127.0.0.1. The intermediate names the root's responder
/// (`http://ocsp.root.test/`) and list (`http://crl.root.test/root.crl`), the leaf the intermediate's.
struct Chain {
    now: i64,
    root: Vec<u8>,
    root_key: KeyPair,
    inter: Vec<u8>,
    inter_key: KeyPair,
    leaf: Vec<u8>,
    leaf_key: KeyPair,
}

const ROOT_OCSP: &str = "http://ocsp.root.test/";
const ROOT_CRL: &str = "http://crl.root.test/root.crl";
const INTER_OCSP: &str = "http://ocsp.inter.test/";
const INTER_CRL: &str = "http://crl.inter.test/inter.crl";

impl Chain {
    fn new() -> Chain {
        let now = crate::sys::now_unix();
        let (root_key, inter_key, leaf_key) = (KeyPair::from_seed([1; 32]), KeyPair::from_seed([2; 32]), KeyPair::from_seed([3; 32]));
        let root_spec = CertSpec { not_before: now - 400 * DAY, not_after: now + 365 * DAY, serial: 1, ..CertSpec::ca("Revocation Root") };
        let root = issue(&root_spec, &root_key, None);
        let inter_spec = CertSpec {
            not_before: now - 300 * DAY,
            not_after: now + 300 * DAY,
            serial: 0x8123, // the top bit set: the INTEGER has a leading zero, which a request must repeat
            ocsp_uris: vec![ROOT_OCSP.into()],
            crl_uris: vec![ROOT_CRL.into()],
            ..CertSpec::ca("Revocation Intermediate")
        };
        let inter = issue(&inter_spec, &inter_key, Some((&root_spec.common_name, &root_key)));
        let leaf_spec = CertSpec {
            not_before: now - DAY,
            not_after: now + 30 * DAY,
            serial: 77,
            ocsp_uris: vec!["ldap://not.used.test/".into(), INTER_OCSP.into()],
            crl_uris: vec![INTER_CRL.into()],
            ..CertSpec::server(&["localhost", "127.0.0.1"])
        };
        let leaf = issue(&leaf_spec, &leaf_key, Some((&inter_spec.common_name, &inter_key)));
        Chain { now, root, root_key, inter, inter_key, leaf, leaf_key }
    }

    fn trust(&self) -> TrustStore {
        let mut t = TrustStore::empty();
        t.add_der(&self.root).unwrap();
        t
    }

    fn path(&self) -> Vec<Vec<u8>> {
        vec![self.leaf.clone(), self.inter.clone(), self.root.clone()]
    }

    /// An OCSP response about the leaf (from the intermediate) or the intermediate (from the root).
    fn ocsp(&self, about_leaf: bool, status: OcspStatus) -> Vec<u8> {
        if about_leaf {
            ocsp_response(&self.inter, &self.inter_key, &self.leaf, status, self.now - 3600, Some(self.now + 3 * DAY))
        } else {
            ocsp_response(&self.root, &self.root_key, &self.inter, status, self.now - 3600, Some(self.now + 3 * DAY))
        }
    }

    /// The intermediate's CRL (about the leaf) or the root's (about the intermediate), listing it as revoked or not.
    fn crl(&self, about_leaf: bool, revoked: bool) -> Arc<Crl> {
        let leaf_entry = [(&[77u8][..], self.now - DAY)];
        let inter_entry = [(&[0x81u8, 0x23][..], self.now - DAY)];
        let der = if about_leaf {
            crl("Revocation Intermediate", &self.inter_key, self.now - DAY, self.now + 6 * DAY, if revoked { &leaf_entry[..] } else { &[] })
        } else {
            crl("Revocation Root", &self.root_key, self.now - DAY, self.now + 6 * DAY, if revoked { &inter_entry[..] } else { &[] })
        };
        Arc::new(Crl::from_der(&der).unwrap())
    }

    /// The revocation check of the whole path with these settings, nothing stapled.
    fn check(&self, cfg: &Revocation) -> Result<()> {
        let sent = vec![self.leaf.clone(), self.inter.clone()];
        crate::revocation::check_path(cfg, &self.path(), &ChainEvidence { sent: &sent, staples: &[None, None] }, self.now)
    }
}

/// A source that answers from a table by URL (an error for a URL it does not have) and writes down every question.
#[derive(Default)]
struct Stub {
    ocsp: Mutex<HashMap<String, Vec<u8>>>,
    crls: Mutex<HashMap<String, Arc<Crl>>>,
    asked: Mutex<Vec<(String, String)>>,
}

impl Stub {
    fn answer_ocsp(&self, url: &str, response: Vec<u8>) {
        self.ocsp.lock().unwrap().insert(url.into(), response);
    }
    fn answer_crl(&self, url: &str, list: Arc<Crl>) {
        self.crls.lock().unwrap().insert(url.into(), list);
    }
    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().iter().map(|(u, _)| u.clone()).collect()
    }
    fn threads(&self) -> Vec<String> {
        self.asked.lock().unwrap().iter().map(|(_, t)| t.clone()).collect()
    }
    fn note(&self, url: &str) {
        let thread = thread::current().name().unwrap_or("").to_string();
        self.asked.lock().unwrap().push((url.into(), thread));
    }
}

impl OcspSource for Stub {
    fn fetch(&self, url: &str, _request: &[u8]) -> Result<Vec<u8>> {
        self.note(url);
        self.ocsp.lock().unwrap().get(url).cloned().ok_or_else(|| Error::Unavailable(format!("no answer from {url}")))
    }
}

impl CrlSource for Stub {
    fn fetch(&self, url: &str) -> Result<Arc<Crl>> {
        self.note(url);
        self.crls.lock().unwrap().get(url).cloned().ok_or_else(|| Error::Unavailable(format!("nothing at {url}")))
    }
}

fn with_stub(mode: RevocationMode, stub: &Arc<Stub>) -> Revocation {
    Revocation::new(mode).with_ocsp_source(stub.clone()).with_crl_source(stub.clone())
}

#[test]
fn a_request_names_the_certificate_as_its_issuers_responses_do() {
    let c = Chain::new();
    let leaf = Certificate::from_der(&c.leaf).unwrap();
    let inter = Certificate::from_der(&c.inter).unwrap();
    let request = ocsp_request(&leaf, &inter);
    // OCSPRequest { TBSRequest { requestList { Request { CertID } } } }: the CertID is the one a response about it carries
    let response = c.ocsp(true, OcspStatus::Good);
    let cert_id = &request[8..];
    assert_eq!(request[..8], [0x30, request[1], 0x30, request[3], 0x30, request[5], 0x30, request[7]]);
    assert_eq!(cert_id.len(), request[7] as usize);
    assert!(response.windows(cert_id.len()).any(|w| w == cert_id), "the response's CertID differs");
    // and the intermediate's serial keeps its leading zero byte
    let root = Certificate::from_der(&c.root).unwrap();
    let r = ocsp_request(&inter, &root);
    assert!(r.ends_with(&[0x02, 0x03, 0x00, 0x81, 0x23]), "{r:02x?}");
    // the responder URLs come from the certificates, in order
    assert_eq!(leaf.ocsp_uris(), ["ldap://not.used.test/", INTER_OCSP]);
    assert_eq!(inter.ocsp_uris(), [ROOT_OCSP]);
    assert_eq!(leaf.crl_uris(), [INTER_CRL]);
}

#[test]
fn the_leafs_responder_settles_it_when_nothing_else_does() {
    let c = Chain::new();
    // good: hard-fail is satisfied, and only the http:// responder of the leaf was asked
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    c.check(&with_stub(RevocationMode::HardFail, &stub)).unwrap();
    assert_eq!(stub.asked(), [INTER_OCSP]);
    // revoked: refused in both modes
    for mode in [RevocationMode::SoftFail, RevocationMode::HardFail] {
        let stub = Arc::new(Stub::default());
        stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Revoked(c.now - DAY)));
        let e = c.check(&with_stub(mode, &stub)).unwrap_err().to_string();
        assert!(e.contains("certificate_revoked") && e.contains("OCSP responder"), "{mode:?}: {e}");
    }
    // unknown, unreachable, or a response that is not about this certificate (the intermediate's) or not signed by its
    // issuer: soft-fail goes on, hard-fail refuses, and the CRL is asked next
    let forged = ocsp_response(&c.inter, &c.leaf_key, &c.leaf, OcspStatus::Good, c.now - 3600, Some(c.now + DAY));
    for (what, answer) in [("unknown", Some(c.ocsp(true, OcspStatus::Unknown))), ("unreachable", None), ("someone else's", Some(c.ocsp(false, OcspStatus::Good))), ("forged", Some(forged))] {
        let stub = Arc::new(Stub::default());
        if let Some(a) = answer {
            stub.answer_ocsp(INTER_OCSP, a);
        }
        c.check(&with_stub(RevocationMode::SoftFail, &stub)).unwrap();
        assert_eq!(stub.asked(), [INTER_OCSP, INTER_CRL], "{what}");
        let e = c.check(&with_stub(RevocationMode::HardFail, &stub)).unwrap_err().to_string();
        assert!(e.contains("no valid evidence"), "{what}: {e}");
        // and the CRL, when there is one, settles it
        stub.answer_crl(INTER_CRL, c.crl(true, false));
        c.check(&with_stub(RevocationMode::HardFail, &stub)).unwrap();
        stub.answer_crl(INTER_CRL, c.crl(true, true));
        let e = c.check(&with_stub(RevocationMode::SoftFail, &stub)).unwrap_err().to_string();
        assert!(e.contains("certificate_revoked") && e.contains("fetched CRL"), "{what}: {e}");
    }
}

#[test]
fn what_is_stapled_or_supplied_first_means_no_source_is_asked() {
    let c = Chain::new();
    let stub = Arc::new(Stub::default());
    let sent = vec![c.leaf.clone(), c.inter.clone()];
    let staples = vec![Some(c.ocsp(true, OcspStatus::Good)), None];
    crate::revocation::check_path(&with_stub(RevocationMode::HardFail, &stub), &c.path(), &ChainEvidence { sent: &sent, staples: &staples }, c.now).unwrap();
    let supplied = with_stub(RevocationMode::HardFail, &stub).with_crl(Crl::from_der(&crl("Revocation Intermediate", &c.inter_key, c.now - DAY, c.now + DAY, &[])).unwrap());
    c.check(&supplied).unwrap();
    assert!(stub.asked().is_empty(), "{:?}", stub.asked());
    // nor with revocation off
    c.check(&with_stub(RevocationMode::Off, &stub)).unwrap();
    assert!(stub.asked().is_empty());
}

#[test]
fn intermediates_are_asked_about_with_whole_chain_only() {
    let c = Chain::new();
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    // by default the intermediate is not asked about, and hard-fail does not want evidence for it
    c.check(&with_stub(RevocationMode::HardFail, &stub)).unwrap();
    assert_eq!(stub.asked(), [INTER_OCSP]);
    // with the whole chain it is, and hard-fail wants it
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    let e = c.check(&with_stub(RevocationMode::HardFail, &stub).whole_chain()).unwrap_err().to_string();
    assert!(e.contains("no valid evidence") && e.contains("Revocation Intermediate"), "{e}");
    assert_eq!(stub.asked(), [INTER_OCSP, ROOT_OCSP, ROOT_CRL]);
    c.check(&with_stub(RevocationMode::SoftFail, &stub).whole_chain()).unwrap();
    // the root's responder says good: hard-fail is satisfied
    stub.answer_ocsp(ROOT_OCSP, c.ocsp(false, OcspStatus::Good));
    c.check(&with_stub(RevocationMode::HardFail, &stub).whole_chain()).unwrap();
    // a revoked intermediate, by the root's responder or by its CRL, fails it
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    stub.answer_ocsp(ROOT_OCSP, c.ocsp(false, OcspStatus::Revoked(c.now - DAY)));
    let e = c.check(&with_stub(RevocationMode::SoftFail, &stub).whole_chain()).unwrap_err().to_string();
    assert!(e.contains("certificate_revoked") && e.contains("Revocation Intermediate"), "{e}");
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    stub.answer_crl(ROOT_CRL, c.crl(false, true));
    assert!(c.check(&with_stub(RevocationMode::SoftFail, &stub).whole_chain()).unwrap_err().to_string().contains("certificate_revoked"));
}

#[test]
fn a_deferred_check_asks_nothing_until_it_is_finished() {
    let c = Chain::new();
    let stub = Arc::new(Stub::default());
    let cfg = with_stub(RevocationMode::HardFail, &stub);
    assert!(cfg.fetches() && !cfg.is_deferred() && cfg.deferred().is_deferred());
    // nothing asked, and missing evidence not held against the chain
    c.check(&cfg.deferred()).unwrap();
    assert!(stub.asked().is_empty());
    // but a revoked staple still fails it
    let sent = vec![c.leaf.clone(), c.inter.clone()];
    let staples = vec![Some(c.ocsp(true, OcspStatus::Revoked(c.now - DAY))), None];
    let e = crate::revocation::check_path(&cfg.deferred(), &c.path(), &ChainEvidence { sent: &sent, staples: &staples }, c.now).unwrap_err();
    assert!(e.to_string().contains("certificate_revoked"));
    // with no source there is nothing to defer
    assert!(!Revocation::hard_fail().deferred().is_deferred());
}

// ------------------------------------------------------------------------------------------------ the TLS clients

/// A TLS test server that serves the chain (leaf and intermediate) and answers every request with its path.
fn server(c: &Chain) -> TestServer {
    let config = ServerConfig::new(vec![c.leaf.clone(), c.inter.clone()], c.leaf_key.clone());
    TestServer::start_tls_with(|seen: &Seen| Reply::Send(response(200, &[], seen.path().as_bytes())), move |_| config)
}

fn client(c: &Chain, revocation: Revocation) -> Client {
    Client::with_tls_config(ClientConfig::new(c.trust()).with_revocation(revocation)).timeout(Duration::from_secs(5))
}

#[test]
fn the_blocking_client_asks_during_the_handshake() {
    let c = Chain::new();
    let s = server(&c);
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    assert_eq!(client(&c, with_stub(RevocationMode::HardFail, &stub)).get(&s.url("/ok")).unwrap().text(), "/ok");
    assert_eq!(stub.asked(), [INTER_OCSP]);
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Revoked(c.now - DAY)));
    let e = client(&c, with_stub(RevocationMode::SoftFail, &stub)).get(&s.url("/no")).unwrap_err().to_string();
    assert!(e.contains("certificate_revoked"), "{e}");
}

#[test]
fn the_async_client_asks_on_its_worker_pool_after_the_handshake() {
    let c = Chain::new();
    let s = server(&c);
    let stub = Arc::new(Stub::default());
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Good));
    let ok = client(&c, with_stub(RevocationMode::HardFail, &stub)).into_async();
    assert_eq!(block_on(ok.get(&s.url("/ok"))).unwrap().text(), "/ok");
    assert_eq!(stub.asked(), [INTER_OCSP]);
    // not on the thread that polls the request (the test's), but on a worker
    assert!(stub.threads().iter().all(|t| t == "pratique-worker"), "{:?}", stub.threads());
    // the connection is reused without asking again
    assert_eq!(block_on(ok.get(&s.url("/again"))).unwrap().text(), "/again");
    assert_eq!(stub.asked().len(), 1);
    // revoked: the request fails, and so does hard-fail without evidence
    stub.answer_ocsp(INTER_OCSP, c.ocsp(true, OcspStatus::Revoked(c.now - DAY)));
    let e = block_on(client(&c, with_stub(RevocationMode::SoftFail, &stub)).into_async().get(&s.url("/no"))).unwrap_err().to_string();
    assert!(e.contains("certificate_revoked"), "{e}");
    let empty = Arc::new(Stub::default());
    let e = block_on(client(&c, with_stub(RevocationMode::HardFail, &empty)).into_async().get(&s.url("/no"))).unwrap_err().to_string();
    assert!(e.contains("no valid evidence"), "{e}");
    // and soft-fail with nothing to say goes through
    assert_eq!(block_on(client(&c, with_stub(RevocationMode::SoftFail, &empty)).into_async().get(&s.url("/soft"))).unwrap().text(), "/soft");
}

// ------------------------------------------------------------------------------------------------ the HTTP sources

/// A server that answers each connection with the next of `answers` (a raw HTTP response) and keeps what was asked
/// (head and body).
fn scripted(answers: Vec<Vec<u8>>) -> (u16, Arc<Mutex<Vec<(String, Vec<u8>)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    thread::spawn(move || {
        for answer in answers {
            let Ok((mut sock, _)) = listener.accept() else { return };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && sock.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).to_string();
            let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = sock.read_exact(&mut body);
            s.lock().unwrap().push((head, body));
            let _ = sock.write_all(&answer);
        }
    });
    (port, seen)
}

fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

#[test]
fn the_http_ocsp_source_posts_the_request_and_keeps_the_answer_for_its_window() {
    let c = Chain::new();
    let leaf = Certificate::from_der(&c.leaf).unwrap();
    let inter = Certificate::from_der(&c.inter).unwrap();
    let request = ocsp_request(&leaf, &inter);
    let good = c.ocsp(true, OcspStatus::Good);
    let old = ocsp_response(&c.inter, &c.inter_key, &c.leaf, OcspStatus::Good, c.now - 10 * DAY, Some(c.now - DAY));
    let (port, seen) = scripted(vec![http_ok(&good), http_ok(&old), http_ok(&old), b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec()]);
    let source = HttpOcspSource::new();
    let url = format!("http://127.0.0.1:{port}/ocsp");
    assert_eq!(source.fetch(&url, &request).unwrap(), good);
    {
        let seen = seen.lock().unwrap();
        let (head, body) = &seen[0];
        assert!(head.starts_with("POST /ocsp HTTP/1.1"), "{head}");
        assert!(head.to_ascii_lowercase().contains("content-type: application/ocsp-request"), "{head}");
        assert_eq!(body, &request);
    }
    // the same question again: from the cache
    assert_eq!(source.fetch(&url, &request).unwrap(), good);
    assert_eq!((seen.lock().unwrap().len(), source.cached()), (1, 1));
    // another question goes out; an answer whose window has ended is handed over (it fails when it is checked) and not kept
    let other = ocsp_request(&inter, &Certificate::from_der(&c.root).unwrap());
    assert_eq!(source.fetch(&url, &other).unwrap(), old);
    assert_eq!(source.fetch(&url, &other).unwrap(), old);
    assert_eq!((seen.lock().unwrap().len(), source.cached()), (3, 1));
    // an error status is an error; other schemes are never asked
    assert!(source.fetch(&url, &[1, 2, 3]).unwrap_err().to_string().contains("500"));
    for bad in ["https://ocsp.example.test/", "ldap://ocsp.example.test/"] {
        assert!(source.fetch(bad, &request).unwrap_err().to_string().contains("only http://"));
    }
    assert_eq!(seen.lock().unwrap().len(), 4);
}

#[test]
fn the_http_crl_source_keeps_a_bounded_cache_and_fetches_the_next_list_in_good_time() {
    let c = Chain::new();
    // a list with half an hour of its window left: used, and the next one fetched in the background
    let ending = crl("Revocation Intermediate", &c.inter_key, c.now - DAY, c.now + 1800, &[]);
    let next = crl("Revocation Intermediate", &c.inter_key, c.now, c.now + 7 * DAY, &[]);
    let (port, seen) = scripted(vec![http_ok(&ending), http_ok(&next)]);
    let source = HttpCrlSource::new();
    let url = format!("http://127.0.0.1:{port}/inter.crl");
    assert_eq!(source.fetch(&url).unwrap().next_update(), Some(c.now + 1800));
    // the second use gets the list it has at once and starts the fetch of the next
    assert_eq!(source.fetch(&url).unwrap().next_update(), Some(c.now + 1800));
    let deadline = Instant::now() + Duration::from_secs(5);
    while source.fetch(&url).unwrap().next_update() != Some(c.now + 7 * DAY) {
        assert!(Instant::now() < deadline, "the next list never came");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(seen.lock().unwrap().len(), 2);
    // a fresh list is not fetched again
    for _ in 0..3 {
        source.fetch(&url).unwrap();
    }
    assert_eq!(seen.lock().unwrap().len(), 2);

    // at most 64 lists are kept: the ones used longest ago go
    let fresh = crl("Revocation Intermediate", &c.inter_key, c.now, c.now + 7 * DAY, &[]);
    let (port, seen) = scripted(vec![http_ok(&fresh); 70]);
    let source = HttpCrlSource::new();
    for i in 0..70 {
        source.fetch(&format!("http://127.0.0.1:{port}/{i}.crl")).unwrap();
    }
    let (lists, bytes) = source.cached();
    assert_eq!(lists, 64);
    assert_eq!(bytes, 64 * fresh.len());
    assert_eq!(seen.lock().unwrap().len(), 70);
}
