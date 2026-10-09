//! Tests of `Expect: 100-continue` in the blocking client ([`RequestBuilder::expect_continue`]): the body waits for the go-ahead,
//! is never sent when the server answers first, goes after the wait when the server says nothing (over TCP and over TLS), and
//! goes again without the expectation after a 417, and after a redirect that keeps it. (The async client's are in
//! `async_timeout_tests`, which uses the servers here.)

use super::testserver::{response, Reply, Seen, TestServer};
use crate::tls::ClientConfig;
use crate::x509::TrustStore;
use crate::Client;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A server on plain TCP that runs `script` on each connection (with its number, from 0) on a thread of its own.
pub(super) fn raw_server(script: impl Fn(usize, TcpStream) + Send + Sync + 'static) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let script = Arc::new(script);
    let c = count.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let n = c.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            thread::spawn(move || script(n, stream));
        }
    });
    (port, count)
}

pub(super) fn client() -> Client {
    Client::with_tls_config(ClientConfig::new(TrustStore::empty())).allow_insecure_http(true).timeout(Duration::from_secs(5))
}

/// Reads up to the end of a request head.
pub(super) fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

pub(super) fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

pub(super) fn length(head: &str) -> usize {
    header(head, "content-length").map_or(0, |v| v.parse().unwrap())
}

/// Reads exactly `n` bytes.
pub(super) fn read_body(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).unwrap();
    body
}

/// What arrives within `wait` (the bytes that came, until the client closed or the time ran out).
pub(super) fn arrives_within(s: &mut TcpStream, wait: Duration) -> usize {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut buf = [0u8; 4096];
    let mut total = 0;
    let end = Instant::now() + wait;
    while Instant::now() < end {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => break,
        }
    }
    s.set_read_timeout(None).unwrap();
    total
}

pub(super) const UPLOAD: usize = 300_000;

pub(super) fn upload() -> Vec<u8> {
    (0..UPLOAD).map(|i| (i % 251) as u8).collect()
}

#[test]
fn the_body_waits_for_the_go_ahead() {
    let early = Arc::new(Mutex::new(None));
    let e = early.clone();
    let (port, _) = raw_server(move |_, mut s| {
        let head = read_head(&mut s);
        assert_eq!(header(&head, "expect"), Some("100-continue"));
        // nothing of the body comes before the go-ahead
        *e.lock().unwrap() = Some(arrives_within(&mut s, Duration::from_millis(300)));
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        let body = read_body(&mut s, length(&head));
        let reply = format!("got {}", body.len());
        s.write_all(&response(200, &[], reply.as_bytes())).unwrap();
        let _ = arrives_within(&mut s, Duration::from_secs(2));
    });
    let t0 = Instant::now();
    let r = client().expect_continue_timeout(Duration::from_secs(10)).request("PUT", &format!("http://127.0.0.1:{port}/up")).body(upload()).expect_continue().send().unwrap();
    assert_eq!((r.status, r.text()), (200, format!("got {UPLOAD}")));
    assert_eq!(*early.lock().unwrap(), Some(0), "body bytes arrived before the go-ahead");
    // it went on the go-ahead, not after the ten seconds
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
}

#[test]
fn an_answer_before_the_body_means_the_body_is_never_sent() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let r2 = received.clone();
    let (port, connections) = raw_server(move |_, mut s| {
        let head = read_head(&mut s);
        assert_eq!(header(&head, "expect"), Some("100-continue"));
        s.write_all(&response(401, &["WWW-Authenticate: Bearer"], b"who are you")).unwrap();
        // what comes after the answer: nothing, and then the client closes
        r2.lock().unwrap().push(arrives_within(&mut s, Duration::from_secs(2)));
    });
    let client = client().expect_continue_timeout(Duration::from_secs(10));
    let url = format!("http://127.0.0.1:{port}/up");
    let t0 = Instant::now();
    let r = client.request("POST", &url).body(upload()).expect_continue().send().unwrap();
    assert_eq!((r.status, r.text().as_str()), (401, "who are you"));
    assert!(t0.elapsed() < Duration::from_secs(5));
    // the connection, on which the server might still be waiting for the body, is not used again
    let r = client.request("POST", &url).body(upload()).expect_continue().send().unwrap();
    assert_eq!(r.status, 401);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.lock().unwrap().len() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*received.lock().unwrap(), vec![0, 0], "body bytes were sent after the answer");
}

#[test]
fn a_server_that_says_nothing_gets_the_body_after_the_wait() {
    // (/silent: the test server waits for the body without a go-ahead)
    let echo = |seen: &Seen| Reply::Send(response(200, &[], format!("got {}", seen.body.len()).as_bytes()));
    for server in [TestServer::start(echo), TestServer::start_tls(echo)] {
        let client = server.client().expect_continue_timeout(Duration::from_millis(300));
        let t0 = Instant::now();
        let r = client.request("POST", &server.url("/silent")).body(upload()).expect_continue().send().unwrap();
        assert_eq!(r.text(), format!("got {UPLOAD}"));
        assert!(t0.elapsed() >= Duration::from_millis(250), "{:?}", t0.elapsed());
        // the connection came through the wait in good order (a read that timed out, over TLS too) and is used again
        let r = client.request("POST", &server.url("/up")).body(upload()).expect_continue().send().unwrap();
        assert_eq!(r.text(), format!("got {UPLOAD}"));
        let r = client.get(&server.url("/after")).unwrap();
        assert_eq!(r.text(), "got 0");
        assert_eq!(server.connections(), 1);
        let seen = server.requests();
        assert_eq!(seen.len(), 3);
        assert!(seen[0].has_header("Expect: 100-continue") && seen[1].has_header("Expect: 100-continue"));
    }
}

#[test]
fn over_tls_the_go_ahead_ends_the_wait() {
    let server = TestServer::start_tls(|seen: &Seen| Reply::Send(response(200, &[], format!("got {}", seen.body.len()).as_bytes())));
    let client = server.client().expect_continue_timeout(Duration::from_secs(10));
    let t0 = Instant::now();
    for _ in 0..3 {
        let r = client.request("PUT", &server.url("/up")).body(upload()).expect_continue().send().unwrap();
        assert_eq!(r.text(), format!("got {UPLOAD}"));
    }
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_417_sends_the_request_again_without_the_expectation() {
    let heads = Arc::new(Mutex::new(Vec::new()));
    let h = heads.clone();
    let (port, connections) = raw_server(move |_, mut s| {
        let head = read_head(&mut s);
        h.lock().unwrap().push(head.clone());
        if header(&head, "expect").is_some() {
            s.write_all(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n").unwrap();
            let _ = arrives_within(&mut s, Duration::from_secs(2));
            return;
        }
        let body = read_body(&mut s, length(&head));
        s.write_all(&response(200, &[], format!("got {}", body.len()).as_bytes())).unwrap();
        let _ = arrives_within(&mut s, Duration::from_secs(2));
    });
    let r = client().request("POST", &format!("http://127.0.0.1:{port}/up")).body(upload()).expect_continue().send().unwrap();
    assert_eq!((r.status, r.text()), (200, format!("got {UPLOAD}")));
    let heads = heads.lock().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(header(&heads[1], "expect").is_none(), "{}", heads[1]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[test]
fn a_redirect_that_keeps_the_body_gets_it_only_where_it_leads() {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let b = bodies.clone();
    let (port, _) = raw_server(move |_, mut s| {
        let head = read_head(&mut s);
        let path = head.split(' ').nth(1).unwrap_or("").to_string();
        if path == "/old" {
            s.write_all(&response(307, &["Location: /new"], b"")).unwrap();
            b.lock().unwrap().push(("/old".to_string(), arrives_within(&mut s, Duration::from_secs(2))));
            return;
        }
        assert_eq!(header(&head, "expect"), Some("100-continue"), "the redirect keeps the expectation");
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        let body = read_body(&mut s, length(&head));
        b.lock().unwrap().push((path, body.len()));
        s.write_all(&response(201, &[], b"stored")).unwrap();
        let _ = arrives_within(&mut s, Duration::from_secs(2));
    });
    let r = client().expect_continue_timeout(Duration::from_secs(10)).request("PUT", &format!("http://127.0.0.1:{port}/old")).body(upload()).expect_continue().send().unwrap();
    assert_eq!((r.status, r.text().as_str()), (201, "stored"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while bodies.lock().unwrap().len() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut got = bodies.lock().unwrap().clone();
    got.sort();
    assert_eq!(got, vec![("/new".to_string(), UPLOAD), ("/old".to_string(), 0)]);
}

#[test]
fn the_wait_never_outlasts_the_requests_own_time() {
    // a server that never answers: the total timeout is what ends it, as an error, and well before the wait would
    let (port, _) = raw_server(|_, mut s| {
        let _ = read_head(&mut s);
        let _ = arrives_within(&mut s, Duration::from_secs(5));
    });
    let t0 = Instant::now();
    let r = client()
        .expect_continue_timeout(Duration::from_secs(30))
        .total_timeout(Duration::from_millis(400))
        .request("POST", &format!("http://127.0.0.1:{port}/up"))
        .body(upload())
        .expect_continue()
        .send();
    assert!(r.is_err());
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
}

#[test]
fn a_request_without_a_body_or_without_the_header_does_not_wait() {
    let server = TestServer::start(|seen: &Seen| Reply::Send(response(200, &[], format!("got {}", seen.body.len()).as_bytes())));
    let client = server.client().expect_continue_timeout(Duration::from_secs(10));
    let t0 = Instant::now();
    // (a /silent server would hold a request that waited for ten seconds)
    let r = client.request("POST", &server.url("/silent/empty")).expect_continue().send().unwrap();
    assert_eq!(r.text(), "got 0");
    let r = client.request("POST", &server.url("/silent/plain")).body(upload()).send().unwrap();
    assert_eq!(r.text(), format!("got {UPLOAD}"));
    assert!(t0.elapsed() < Duration::from_secs(5));
    // and the builder does not say it twice
    let _ = client.request("POST", &server.url("/twice")).header("expect", "100-continue").body("x").expect_continue().send().unwrap();
    assert_eq!(server.requests()[2].head.to_ascii_lowercase().matches("expect:").count(), 1);
}
