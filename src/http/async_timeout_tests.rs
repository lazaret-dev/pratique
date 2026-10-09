//! The async client's time limits with any connector (BACKLOG B-61): a connector whose streams never time out by themselves
//! still has the connect timeout, the read timeout and the total time limit kept by the client's timers, a reused connection
//! gets the limits of the request that reuses it, and `Expect: 100-continue` waits for the go-ahead as the blocking client
//! does (with the default connector, which keeps its own timeouts, and with one that does not).

use super::async_client::{AsyncClient, Connect};
use super::expect_tests::{arrives_within, header, length, raw_server, read_body, read_head, upload, UPLOAD};
use super::testserver::{response, Reply, Seen, TestServer};
use super::ConnectOptions;
use crate::asyncio::{block_on, Pool, ThreadedStream};
use crate::error::Error;
use crate::Client;
use std::future::Future;
use std::io::{self, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How much later than its limit a timeout may end on a loaded machine.
const SLACK: Duration = Duration::from_millis(800);

/// A connector whose streams never time out by themselves (no socket timeouts, no deadline), and which can be told never to
/// finish connecting.
#[derive(Clone)]
struct Untimed {
    pool: Pool,
    hang: bool,
}

impl Connect for Untimed {
    type Stream = ThreadedStream;

    fn connect<'a>(&'a self, host: &'a str, port: u16, _opts: ConnectOptions) -> Pin<Box<dyn Future<Output = io::Result<ThreadedStream>> + Send + 'a>> {
        if self.hang {
            return Box::pin(std::future::pending());
        }
        let (host, pool) = (host.to_string(), self.pool.clone());
        let task = self.pool.spawn_blocking(move || TcpStream::connect((host.as_str(), port)));
        Box::pin(async move {
            let tcp = task.await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
            Ok(ThreadedStream::new(tcp, pool))
        })
    }

    fn reuse(&self, stream: &mut ThreadedStream, _opts: ConnectOptions) -> bool {
        stream.peer_quiet()
    }
}

fn untimed(client: Client) -> AsyncClient<Untimed> {
    AsyncClient::with_connector(client, Untimed { pool: Pool::new(8), hang: false })
}

fn is_timeout(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == io::ErrorKind::TimedOut)
}

/// A reply that holds the connection without a word for `secs`.
fn silence(secs: u64) -> Reply {
    Reply::Run(Box::new(move |_| {
        thread::sleep(Duration::from_secs(secs));
        false
    }))
}

/// A reply that starts a long body and sends a byte of it every 50 ms for `secs`.
fn drip(secs: u64) -> Reply {
    Reply::Run(Box::new(move |w| {
        let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n");
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if w.write_all(b"x").and_then(|_| w.flush()).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }))
}

#[test]
fn a_server_that_never_answers_is_timed_out_by_the_client_whatever_the_connector() {
    for tls in [false, true] {
        let server = if tls { TestServer::start_tls(|_| silence(4)) } else { TestServer::start(|_| silence(4)) };
        let client = untimed(server.client().timeout(Duration::from_millis(300)));
        let t0 = Instant::now();
        let e = block_on(client.get(&server.url("/quiet"))).unwrap_err();
        let took = t0.elapsed();
        assert!(is_timeout(&e), "tls {tls}: {e}");
        assert!(took >= Duration::from_millis(300) && took < Duration::from_millis(300) + SLACK, "tls {tls}: {took:?}");
    }
}

#[test]
fn the_total_time_limit_ends_a_dripping_body_whatever_the_connector() {
    let server = TestServer::start(|_| drip(5));
    let client = untimed(server.client().timeout(Duration::from_secs(2)).total_timeout(Duration::from_millis(500)));
    let t0 = Instant::now();
    let e = block_on(client.get(&server.url("/drip"))).unwrap_err();
    assert!(is_timeout(&e) && e.to_string().contains("total time limit"), "{e}");
    assert!(t0.elapsed() < Duration::from_millis(500) + SLACK, "{:?}", t0.elapsed());
}

#[test]
fn a_connect_that_never_finishes_is_given_up_after_the_connect_timeout() {
    let client = AsyncClient::with_connector(
        Client::new().unwrap().allow_insecure_http(true).connect_timeout(Duration::from_millis(200)),
        Untimed { pool: Pool::new(1), hang: true },
    );
    let t0 = Instant::now();
    let e = block_on(client.get("http://127.0.0.1:9/")).unwrap_err();
    assert!(is_timeout(&e) && e.to_string().contains("connecting"), "{e}");
    assert!(t0.elapsed() >= Duration::from_millis(200) && t0.elapsed() < Duration::from_millis(200) + SLACK);
    // and the total time limit, if it is sooner
    let client = AsyncClient::with_connector(
        Client::new().unwrap().allow_insecure_http(true).connect_timeout(Duration::from_secs(10)).total_timeout(Duration::from_millis(150)),
        Untimed { pool: Pool::new(1), hang: true },
    );
    let e = block_on(client.get("http://127.0.0.1:9/")).unwrap_err();
    assert!(e.to_string().contains("total time limit"), "{e}");
}

#[test]
fn a_reused_connection_gets_the_limits_of_the_request_that_reuses_it() {
    // the first request's total time limit has long passed when the second goes on the same connection
    let server = TestServer::start(|seen: &Seen| Reply::Send(response(200, &[], seen.path().as_bytes())));
    let client = untimed(server.client().total_timeout(Duration::from_millis(300)));
    assert_eq!(block_on(client.get(&server.url("/one"))).unwrap().text(), "/one");
    thread::sleep(Duration::from_millis(450));
    assert_eq!(block_on(client.get(&server.url("/two"))).unwrap().text(), "/two");
    assert_eq!(server.connections(), 1);
}

#[test]
fn requests_that_finish_in_time_are_not_disturbed_by_the_timers() {
    let server = TestServer::start_tls(|seen: &Seen| Reply::Send(response(200, &[], &vec![b'y'; seen.path().len() * 1000])));
    let client = untimed(server.client().timeout(Duration::from_millis(500)).total_timeout(Duration::from_secs(10)));
    for i in 0..20 {
        let path = format!("/{}", "p".repeat(i + 1));
        let r = block_on(client.get(&server.url(&path))).unwrap();
        assert_eq!(r.body.len(), path.len() * 1000);
    }
    assert_eq!(server.connections(), 1);
}

// ------------------------------------------------------------------------------------------------ Expect: 100-continue

#[test]
fn the_async_body_waits_for_the_go_ahead() {
    let early = Arc::new(Mutex::new(None));
    let e = early.clone();
    let (port, _) = raw_server(move |_, mut s| {
        let head = read_head(&mut s);
        assert_eq!(header(&head, "expect"), Some("100-continue"));
        *e.lock().unwrap() = Some(arrives_within(&mut s, Duration::from_millis(300)));
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        let body = read_body(&mut s, length(&head));
        s.write_all(&response(200, &[], format!("got {}", body.len()).as_bytes())).unwrap();
        let _ = arrives_within(&mut s, Duration::from_secs(2));
    });
    let blocking = super::expect_tests::client().expect_continue_timeout(Duration::from_secs(10));
    for client in [blocking.clone().into_async()] {
        let t0 = Instant::now();
        let r = block_on(client.request("PUT", &format!("http://127.0.0.1:{port}/up")).body(upload()).expect_continue().send()).unwrap();
        assert_eq!((r.status, r.text()), (200, format!("got {UPLOAD}")));
        assert_eq!(*early.lock().unwrap(), Some(0), "body bytes arrived before the go-ahead");
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }
    let r = block_on(untimed(blocking).request("PUT", &format!("http://127.0.0.1:{port}/up")).body(upload()).expect_continue().send()).unwrap();
    assert_eq!((r.status, r.text()), (200, format!("got {UPLOAD}")));
    assert_eq!(*early.lock().unwrap(), Some(0));
}

#[test]
fn an_answer_before_the_async_body_means_the_body_is_never_sent() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let r2 = received.clone();
    let (port, connections) = raw_server(move |_, mut s| {
        let _ = read_head(&mut s);
        s.write_all(&response(401, &["WWW-Authenticate: Bearer"], b"who are you")).unwrap();
        r2.lock().unwrap().push(arrives_within(&mut s, Duration::from_secs(2)));
    });
    let client = super::expect_tests::client().expect_continue_timeout(Duration::from_secs(10)).into_async();
    let url = format!("http://127.0.0.1:{port}/up");
    let t0 = Instant::now();
    for _ in 0..2 {
        let r = block_on(client.request("POST", &url).body(upload()).expect_continue().send()).unwrap();
        assert_eq!((r.status, r.text().as_str()), (401, "who are you"));
    }
    assert!(t0.elapsed() < Duration::from_secs(5));
    // the connection, on which the server might still be waiting for the body, is not used again
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.lock().unwrap().len() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*received.lock().unwrap(), vec![0, 0], "body bytes were sent after the answer");
}

#[test]
fn a_silent_server_gets_the_async_body_after_the_wait_and_the_connection_goes_on() {
    let echo = |seen: &Seen| Reply::Send(response(200, &[], format!("got {}", seen.body.len()).as_bytes()));
    for server in [TestServer::start(echo), TestServer::start_tls(echo)] {
        for untimed_connector in [false, true] {
            let blocking = server.client().expect_continue_timeout(Duration::from_millis(300));
            let url = server.url("/silent");
            let t0 = Instant::now();
            let r = if untimed_connector {
                block_on(untimed(blocking).request("POST", &url).body(upload()).expect_continue().send())
            } else {
                block_on(blocking.into_async().request("POST", &url).body(upload()).expect_continue().send())
            }
            .unwrap();
            assert_eq!(r.text(), format!("got {UPLOAD}"));
            assert!(t0.elapsed() >= Duration::from_millis(250), "untimed {untimed_connector}: {:?}", t0.elapsed());
            assert!(t0.elapsed() < Duration::from_secs(4), "untimed {untimed_connector}: {:?}", t0.elapsed());
        }
        assert!(server.requests().iter().all(|s| s.has_header("Expect: 100-continue")));
    }
    // the connection came through the wait in good order and is used again (one client, three requests, one connection)
    let server = TestServer::start_tls(echo);
    let client = server.client().expect_continue_timeout(Duration::from_millis(300)).into_async();
    let r = block_on(client.request("POST", &server.url("/silent")).body(upload()).expect_continue().send()).unwrap();
    assert_eq!(r.text(), format!("got {UPLOAD}"));
    let r = block_on(client.request("POST", &server.url("/up")).body(upload()).expect_continue().send()).unwrap();
    assert_eq!(r.text(), format!("got {UPLOAD}"));
    assert_eq!(block_on(client.get(&server.url("/after"))).unwrap().text(), "got 0");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_417_sends_the_async_request_again_without_the_expectation() {
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
    let client = super::expect_tests::client().into_async();
    let r = block_on(client.request("POST", &format!("http://127.0.0.1:{port}/up")).body(upload()).expect_continue().send()).unwrap();
    assert_eq!((r.status, r.text()), (200, format!("got {UPLOAD}")));
    let heads = heads.lock().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(header(&heads[1], "expect").is_none(), "{}", heads[1]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[test]
fn the_async_wait_never_outlasts_the_requests_own_time() {
    let (port, _) = raw_server(|_, mut s| {
        let _ = read_head(&mut s);
        let _ = arrives_within(&mut s, Duration::from_secs(5));
    });
    let blocking = super::expect_tests::client().expect_continue_timeout(Duration::from_secs(30)).total_timeout(Duration::from_millis(400));
    let url = format!("http://127.0.0.1:{port}/up");
    let t0 = Instant::now();
    assert!(block_on(blocking.clone().into_async().request("POST", &url).body(upload()).expect_continue().send()).is_err());
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    let t0 = Instant::now();
    assert!(block_on(untimed(blocking).request("POST", &url).body(upload()).expect_continue().send()).is_err());
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
}
