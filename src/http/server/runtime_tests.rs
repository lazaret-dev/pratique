//! The runtime (B-112): timeouts that a slow client cannot stretch (slowloris, in each phase), limits on connections,
//! graceful shutdown for both versions of HTTP, the access log, and certificates and staples kept fresh.

use super::super::h2::frame::{self, flag, kind, setting, ErrorCode};
use super::test_util::{responses, Raw};
use super::*;
use crate::crypto::ecdsa::Curve;
use crate::tls::certs::{CertStore, CertifiedKey};
use crate::tls::pki::{issue, ocsp_response, CertSpec, KeyPair, OcspStatus, TestPki};
use crate::tls::server::ServerConfig;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn quick() -> Limits {
    Limits {
        handshake_timeout: Duration::from_millis(400),
        idle_timeout: Duration::from_millis(400),
        head_timeout: Duration::from_millis(400),
        body_grace: Duration::from_millis(200),
        body_min_rate: 20_000,
        body_wait: Duration::from_millis(400),
        write_timeout: Duration::from_millis(400),
        upgraded_idle_timeout: Duration::from_millis(400),
        ..Limits::default()
    }
}

fn app(mut req: Request) -> Response {
    match req.path() {
        "/slow" => {
            thread::sleep(Duration::from_millis(300));
            Response::text(200, "slow\n")
        }
        "/huge" => Response::bytes(200, "x/y", vec![7; 50 << 20]),
        "/body" => match req.read_body(1 << 22) {
            Ok(b) => Response::text(200, format!("{}", b.len())),
            Err(e) => Response::text(400, format!("body: {e}")),
        },
        _ => Response::text(200, format!("hello {}\n", req.path())),
    }
}

fn plain(limits: Limits) -> Server {
    ServerBuilder::new(app)
        .plain("127.0.0.1:0")
        .limits(limits)
        .start()
        .unwrap()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Reads until the server closes; how long that took, and what came.
fn until_closed(s: &mut TcpStream) -> (Duration, Vec<u8>) {
    let t = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return (t.elapsed(), out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(t.elapsed() < Duration::from_secs(5), "{what}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn listeners_serve_tls_and_plain_and_the_access_log_sees_each_request() {
    let pki = TestPki::new(&["127.0.0.1"]).unwrap();
    let tls = Arc::new(ServerConfig::from_pki(&pki).with_alpn(&["h2", "http/1.1"]));
    let log = Arc::new(Mutex::new(Vec::new()));
    let server = {
        let log = log.clone();
        ServerBuilder::new(app)
            .tls("127.0.0.1:0", tls)
            .plain_with("127.0.0.1:0", redirect_to_https(Some(8443)))
            .access_log(move |e| {
                log.lock().unwrap().push(format!(
                    "{} {} {} {} {} {:?}",
                    e.method, e.target, e.version, e.status, e.bytes, e.user_agent
                ))
            })
            .start()
            .unwrap()
    };
    let (tls_addr, plain_addr) = (server.local_addrs()[0], server.local_addrs()[1]);
    let client =
        crate::http::Client::with_tls_config(crate::tls::ClientConfig::new(pki.trust_store()))
            .http2(true);
    let r = client
        .get(&format!("https://127.0.0.1:{}/a", tls_addr.port()))
        .unwrap();
    assert_eq!(
        (r.status, r.version, r.text()),
        (200, crate::http::HttpVersion::Http2, "hello /a\n".into())
    );
    let mut s = connect(plain_addr);
    s.write_all(b"GET /b?c HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1\r\nConnection: close\r\n\r\n").unwrap();
    let (_, out) = until_closed(&mut s);
    let r = &responses(&out, &[])[0];
    assert_eq!(
        (r.status, r.header("location")),
        (301, Some("https://example.com:8443/b?c"))
    );
    wait_for("two log lines", || log.lock().unwrap().len() == 2);
    let lines = log.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| l.starts_with("GET /a HTTP/2 200 9 ")),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"GET /b?c HTTP/1.1 301 0 Some(\"test/1\")".to_string()),
        "{lines:?}"
    );
    assert_eq!(server.stats().accepted, 2);
    server.shutdown(Duration::from_secs(1));
}

#[test]
fn slow_heads_bodies_readers_and_idle_connections_are_closed_in_time() {
    let server = plain(quick());
    let addr = server.local_addrs()[0];
    // slowloris: a head a byte every 100 ms never finishes, however close each byte is to the last
    let mut s = connect(addr);
    let writer = {
        let mut w = s.try_clone().unwrap();
        thread::spawn(move || {
            for b in b"GET / HTTP/1.1\r\nHost: a\r\nX: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                if w.write_all(&[*b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let (took, out) = until_closed(&mut s);
    assert!(
        out.is_empty() && took < Duration::from_millis(1500),
        "closed after {took:?}"
    );
    writer.join().unwrap();
    // idle: a request, its answer, and then the connection waits too long
    let mut s = connect(addr);
    s.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    let (took, out) = until_closed(&mut s);
    assert_eq!(responses(&out, &[])[0].text(), "hello /x\n");
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_millis(1500),
        "idle for {took:?}"
    );
    // a body sent slower than the minimum rate: the handler's read fails, and the connection closes
    let mut s = connect(addr);
    s.write_all(b"POST /body HTTP/1.1\r\nHost: a\r\nContent-Length: 1000000\r\n\r\n")
        .unwrap();
    let w = {
        let mut w = s.try_clone().unwrap();
        thread::spawn(move || {
            for _ in 0..30 {
                if w.write_all(&[b'x'; 1000]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let (took, out) = until_closed(&mut s);
    let r = &responses(&out, &[])[0];
    assert!(r.status == 400 && r.text().contains("too long"), "{r:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    w.join().unwrap();
    // a client that does not read: the write gives up
    let before = server.stats().timed_out;
    let mut s = connect(addr);
    s.write_all(b"GET /huge HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    wait_for("the write to time out", || {
        server.stats().timed_out > before
    });
    drop(s);
    server.shutdown(Duration::from_secs(1));
}

#[test]
fn a_handshake_has_its_time_in_all() {
    let pki = TestPki::new(&["127.0.0.1"]).unwrap();
    let server = ServerBuilder::new(app)
        .tls("127.0.0.1:0", Arc::new(ServerConfig::from_pki(&pki)))
        .limits(quick())
        .start()
        .unwrap();
    let addr = server.local_addrs()[0];
    let mut s = connect(addr);
    let (took, _) = until_closed(&mut s);
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_millis(1500),
        "silent: {took:?}"
    );
    // the first bytes of a ClientHello, one every 100 ms
    let mut s = connect(addr);
    let mut w = s.try_clone().unwrap();
    let t = thread::spawn(move || {
        for b in [
            0x16u8, 3, 1, 0, 200, 1, 0, 0, 196, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ] {
            if w.write_all(&[b]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let (took, _) = until_closed(&mut s);
    assert!(took < Duration::from_millis(1500), "trickled: {took:?}");
    t.join().unwrap();
    server.shutdown(Duration::from_secs(1));
}

#[test]
fn connections_past_the_limits_are_closed_at_once() {
    let server = plain(Limits {
        max_connections_per_ip: 2,
        idle_timeout: Duration::from_secs(5),
        ..quick()
    });
    let addr = server.local_addrs()[0];
    let held: Vec<TcpStream> = (0..2).map(|_| connect(addr)).collect();
    wait_for("two open", || server.stats().open == 2);
    let mut third = connect(addr);
    let (took, out) = until_closed(&mut third);
    assert!(
        out.is_empty() && took < Duration::from_millis(300),
        "{took:?}"
    );
    assert_eq!(server.stats().refused, 1);
    drop(held);
    wait_for("the others closed", || server.stats().open == 0);
    let mut s = connect(addr);
    s.write_all(b"GET /again HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert_eq!(responses(&until_closed(&mut s).1, &[])[0].status, 200);
    server.shutdown(Duration::from_secs(1));
}

#[test]
fn shutdown_finishes_what_is_under_way_and_closes_the_rest() {
    // The requests under way are held until the idle connection has closed, so the shutdown is seen to close it while
    // they still run, whatever the machine's speed. (With requests that took 300 ms and a bound of 300 ms on that close,
    // as this was, the test passed on Linux though the idle connection closed only once they were over: 321 ms on macOS's
    // runner, Oct 30, and the whole grace of 3 s on Windows, whose read the shutdown did not wake. B-119.)
    let held = Arc::new((Mutex::new(true), Condvar::new()));
    let under_way = Arc::new(AtomicUsize::new(0));
    let server = {
        let (held, under_way) = (held.clone(), under_way.clone());
        Arc::new(
            ServerBuilder::new(move |req: Request| {
                if req.path() != "/slow" {
                    return app(req);
                }
                under_way.fetch_add(1, Ordering::SeqCst);
                let (lock, cv) = &*held;
                let mut h = lock.lock().unwrap();
                let give_up = Instant::now() + Duration::from_secs(10);
                while *h && Instant::now() < give_up {
                    h = cv.wait_timeout(h, Duration::from_millis(50)).unwrap().0;
                }
                Response::text(200, "slow\n")
            })
            .plain("127.0.0.1:0")
            .limits(Limits {
                idle_timeout: Duration::from_secs(30),
                ..quick()
            })
            .start()
            .unwrap(),
        )
    };
    let addr = server.local_addrs()[0];
    // idle after a request
    let mut idle = connect(addr);
    idle.write_all(b"GET /first HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 1024];
    assert!(idle.read(&mut buf).unwrap() > 0);
    // in the middle of a request, HTTP/1.1
    let mut busy = connect(addr);
    busy.write_all(b"GET /slow HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    // in the middle of a request, HTTP/2
    let mut h2 = Raw::connect_to(addr, &[]);
    h2.get(1, "/slow");
    wait_for("both requests under way", || {
        under_way.load(Ordering::SeqCst) == 2
    });
    let t = Instant::now();
    let stopper = {
        let server = server.clone();
        thread::spawn(move || server.shutdown(Duration::from_secs(3)))
    };
    // at once: while the others are under way, and long before the grace of 3 s is over
    let (took, _) = until_closed(&mut idle);
    assert!(
        took < Duration::from_millis(1000),
        "the idle connection closed at once: {took:?}"
    );
    *held.0.lock().unwrap() = false;
    held.1.notify_all();
    let (_, out) = until_closed(&mut busy);
    let r = &responses(&out, &[])[0];
    assert_eq!(
        (r.status, r.text(), r.header("connection")),
        (200, "slow\n".into(), Some("close"))
    );
    let frames = h2.until(|f| f.is(kind::GOAWAY));
    assert_eq!(
        frames
            .last()
            .map(|f| u32::from_be_bytes(f.p[4..8].try_into().unwrap())),
        Some(0),
        "GOAWAY with no error"
    );
    let (status, _, body) = h2.response(1);
    assert_eq!((status, body), (200, b"slow\n".to_vec()));
    drop(h2);
    stopper.join().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "the shutdown did not wait for its deadline: {:?}",
        t.elapsed()
    );
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err() || {
            let mut s = connect(addr);
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            until_closed(&mut s).1.is_empty()
        }
    );
}

#[test]
fn a_shutdown_lets_a_slow_client_have_all_of_a_response_whose_handler_has_returned() {
    // B-119: an HTTP/2 stream is over for the server once its last frame is framed, and a shutdown that began while
    // that frame was still being sent to a slow client stopped the connection's reading at once, which on Windows also
    // cancels the send: the client lost the tail of the response. Here the handler has returned, the whole body is
    // framed as one DATA frame that ends the stream, its send waits for a client that does not read yet, and then the
    // shutdown begins: the client, reading slowly, must have every byte, then the GOAWAY, then the end of the connection,
    // and the shutdown must end with the connection, long before its grace.
    const N: usize = 12 << 20;
    let body: Arc<Vec<u8>> = Arc::new((0..N).map(|i| (i % 251) as u8).collect());
    let returned = Arc::new(AtomicUsize::new(0));
    let server = {
        let (body, returned) = (body.clone(), returned.clone());
        let mut http = HttpConfig::default();
        http.h2.stream_send_buffer = 16 << 20;
        Arc::new(
            ServerBuilder::new(move |_req: Request| {
                let r = Response::bytes(200, "application/octet-stream", body.to_vec());
                returned.fetch_add(1, Ordering::SeqCst);
                r
            })
            .plain("127.0.0.1:0")
            .http_config(http)
            .limits(Limits {
                idle_timeout: Duration::from_secs(30),
                write_timeout: Duration::from_secs(30),
                ..Limits::default()
            })
            .start()
            .unwrap(),
        )
    };
    // no window for response data yet, and frames as large as there are
    let mut c = Raw::connect_to(
        server.local_addrs()[0],
        &[
            (setting::INITIAL_WINDOW_SIZE, 0),
            (setting::MAX_FRAME_SIZE, 16_777_215),
        ],
    );
    c.get(1, "/big");
    let head = c.until(|f| f.h.stream == 1 && f.is(kind::HEADERS));
    assert!(
        head.last()
            .is_some_and(|f| f.fields.contains(&(":status".into(), "200".into()))),
        "{head:?}"
    );
    wait_for("the handler to return", || {
        returned.load(Ordering::SeqCst) == 1
    });
    thread::sleep(Duration::from_millis(100));
    // the window for all of it, the connection's first: the server frames the body as one DATA frame that ends the
    // stream, and sends it to a client that reads nothing yet (more than the sockets hold on any system)
    let mut out = Vec::new();
    frame::write_window_update(&mut out, 0, N as u32);
    c.send(&out);
    thread::sleep(Duration::from_millis(50));
    out.clear();
    frame::write_window_update(&mut out, 1, N as u32);
    c.send(&out);
    thread::sleep(Duration::from_millis(300));
    // the shutdown begins while that send waits for the client
    let t = Instant::now();
    let stopper = {
        let server = server.clone();
        thread::spawn(move || server.shutdown(Duration::from_secs(20)))
    };
    thread::sleep(Duration::from_millis(300));
    // and the client reads, slowly, to the end of the connection
    c.read_slowly(Duration::from_millis(1));
    let mut got = Vec::with_capacity(N);
    let (mut ended, mut goaway) = (false, None);
    while let Some(f) = c.next() {
        if f.is(kind::DATA) && f.h.stream == 1 {
            got.extend_from_slice(&f.p);
            ended |= f.h.has(flag::END_STREAM);
        } else if f.is(kind::GOAWAY) {
            goaway = Some(u32::from_be_bytes(f.p[4..8].try_into().unwrap()));
        } else {
            assert!(!f.is(kind::RST_STREAM), "{f:?}");
        }
    }
    assert!(
        ended && got[..] == body[..],
        "{} bytes of {N}, the stream {}",
        got.len(),
        if ended { "ended" } else { "not ended" }
    );
    assert_eq!(goaway, Some(0), "GOAWAY with no error");
    stopper.join().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "the shutdown waited for its grace: {:?}",
        t.elapsed()
    );
}

#[test]
fn a_connection_accepted_as_the_shutdown_begins_is_closed_not_served() {
    // B-119: a connection accepted just before the shutdown began, and entered among the connections just after the
    // shutdown had taken its list of those to close, was never asked to close: it was served as if nothing had happened,
    // and cut at the end of the grace. The accept is held between its look at the shutdown and the entry while the
    // shutdown runs (it has no connection to wait for, and is over at once).
    let held = Arc::new((Mutex::new(true), Condvar::new()));
    let arrived = Arc::new(AtomicUsize::new(0));
    let server = {
        let (held, arrived) = (held.clone(), arrived.clone());
        ServerBuilder::new(app)
            .plain("127.0.0.1:0")
            .limits(Limits {
                idle_timeout: Duration::from_secs(30),
                ..quick()
            })
            .before_entry(move || {
                if arrived.fetch_add(1, Ordering::SeqCst) == 0 {
                    let (lock, cv) = &*held;
                    let mut h = lock.lock().unwrap();
                    let give_up = Instant::now() + Duration::from_secs(10);
                    while *h && Instant::now() < give_up {
                        h = cv.wait_timeout(h, Duration::from_millis(50)).unwrap().0;
                    }
                }
            })
            .start()
            .unwrap()
    };
    let addr = server.local_addrs()[0];
    let mut s = connect(addr);
    s.write_all(b"GET /late HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    wait_for("the accept to be held", || {
        arrived.load(Ordering::SeqCst) == 1
    });
    let t = Instant::now();
    server.handle().shutdown(Duration::from_secs(3));
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "the shutdown had a connection to wait for: {:?}",
        t.elapsed()
    );
    *held.0.lock().unwrap() = false;
    held.1.notify_all();
    let (took, out) = until_closed(&mut s);
    assert!(
        out.is_empty() && took < Duration::from_secs(2),
        "the connection was served ({} bytes) or kept open ({took:?})",
        out.len()
    );
    server.shutdown(Duration::from_secs(1));
    assert_eq!(server.stats().accepted, 0);
}

#[test]
fn an_idle_http1_connection_the_shutdown_takes_is_stopped_and_answers_nothing_more() {
    // B-119: the shutdown stops an idle HTTP/1.1 connection at once. A request that comes just as it does is not
    // answered: the stop cancels on Windows a send under way, and the response would be cut short. (The connection's
    // wait ends with the request as the shutdown takes the connection.)
    let stops = Arc::new(AtomicUsize::new(0));
    let ctl = {
        let stops = stops.clone();
        runtime::Ctl::detached_with_stop(move || {
            stops.fetch_add(1, Ordering::SeqCst);
        })
    };
    let waited = ctl.idle_wait(|| {
        ctl.begin_close();
        "a request"
    });
    assert_eq!((waited, stops.load(Ordering::SeqCst)), (None, 1));
    // a connection busy with a request when the shutdown begins is not stopped, and waits for no other
    let stops = Arc::new(AtomicUsize::new(0));
    let ctl = {
        let stops = stops.clone();
        runtime::Ctl::detached_with_stop(move || {
            stops.fetch_add(1, Ordering::SeqCst);
        })
    };
    assert_eq!(ctl.idle_wait(|| "a request"), Some("a request"));
    ctl.begin_close();
    assert_eq!(stops.load(Ordering::SeqCst), 0);
    assert_eq!(ctl.idle_wait(|| "another"), None);
}

/// A socket whose first send is cancelled as the system reports one: Windows may have sent some of it, elsewhere a
/// send that says Interrupted sent nothing.
struct CancelledOnce {
    sent: Arc<Mutex<Vec<u8>>>,
    cancelled: bool,
}

impl Read for CancelledOnce {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl Write for CancelledOnce {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.cancelled {
            self.cancelled = true;
            let partial = if cfg!(windows) { buf.len() / 2 } else { 0 };
            self.sent.lock().unwrap().extend_from_slice(&buf[..partial]);
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.sent.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::tls::Duplex for CancelledOnce {
    fn duplicate(&self) -> std::io::Result<Self> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

impl Socket for CancelledOnce {
    fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
    fn shutdown(&self) {}
    fn shutdown_write(&self) {}
}

#[test]
fn a_send_that_was_cancelled_is_not_sent_again() {
    // B-119: on Windows a send that the stop of a connection cancelled fails with no count of what it sent, which may
    // be some of it; `write_all` sends again after Interrupted, and the client would read those bytes twice. The
    // server's writes end the connection instead. (Elsewhere Interrupted means that nothing was sent: it is sent again.)
    let sent = Arc::new(Mutex::new(Vec::new()));
    let socket = CancelledOnce {
        sent: sent.clone(),
        cancelled: false,
    };
    let mut timed =
        runtime::Timed::new(socket, runtime::Timer::new(), Duration::from_secs(1)).unwrap();
    let result = timed.write_all(b"0123456789").map_err(|e| e.kind());
    let sent = sent.lock().unwrap().clone();
    if cfg!(windows) {
        assert_eq!(
            (result, &sent[..]),
            (Err(std::io::ErrorKind::ConnectionAborted), &b"01234"[..])
        );
    } else {
        assert_eq!((result, &sent[..]), (Ok(()), &b"0123456789"[..]));
    }
}

#[test]
fn an_idle_http2_connection_is_not_kept_alive_by_pings() {
    let server = plain(quick());
    let mut c = Raw::connect_to(server.local_addrs()[0], &[]);
    c.get(1, "/");
    assert_eq!(c.response(1).0, 200);
    let t = Instant::now();
    let mut closed = false;
    while t.elapsed() < Duration::from_secs(3) {
        c.raw_frame(kind::PING, 0, 0, b"keepme!!");
        if c.until(|f| f.is(kind::PING))
            .last()
            .is_none_or(|f| !f.is(kind::PING))
        {
            closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        closed && t.elapsed() < Duration::from_millis(1500),
        "closed {closed} after {:?}",
        t.elapsed()
    );
    server.shutdown(Duration::from_secs(1));
}

#[test]
fn http2_handlers_past_the_server_limit_are_refused_and_their_waits_end() {
    let server = plain(Limits {
        max_h2_handlers: 1,
        ..quick()
    });
    let mut c = Raw::connect_to(
        server.local_addrs()[0],
        &[(setting::INITIAL_WINDOW_SIZE, 0)],
    );
    c.get(1, "/slow");
    c.get(3, "/slow");
    assert_eq!(
        c.reset_of(3),
        Some(ErrorCode::REFUSED_STREAM.0),
        "one handler at a time in the whole server"
    );
    // stream 1's answer waits for a window that never opens: the handler gives up at the write timeout
    let frames = c.until(|f| f.h.stream == 1 && f.is(kind::RST_STREAM));
    assert_eq!(
        frames
            .last()
            .map(|f| u32::from_be_bytes(f.p[..4].try_into().unwrap())),
        Some(ErrorCode::CANCEL.0)
    );
    // a body that stops coming: the handler gives up at the body wait
    let mut out = Vec::new();
    frame::write_settings(&mut out, &[(setting::INITIAL_WINDOW_SIZE, 65_535)]);
    c.send(&out);
    c.headers(
        5,
        &[
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "a"),
            (":path", "/body"),
        ],
        false,
    );
    c.data(5, b"some of it", false);
    let t = Instant::now();
    let frames =
        c.until(|f| f.h.stream == 5 && (f.is(kind::RST_STREAM) || f.h.has(flag::END_STREAM)));
    assert!(
        frames.last().is_some_and(|f| f.is(kind::RST_STREAM)),
        "{:?}",
        frames.last()
    );
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    server.shutdown(Duration::from_secs(1));
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = crate::pem::base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out + &format!("-----END {label}-----\n")
}

#[test]
fn certificates_are_reloaded_when_their_files_change() {
    let dir = std::env::temp_dir().join(format!("pratique-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (chain, key) = (dir.join("chain.pem"), dir.join("key.pem"));
    let write = |name: &str| {
        let k = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        let pki = TestPki::with_keys(CertSpec::server(&[name]), &KeyPair::generate().unwrap(), k);
        std::fs::write(&chain, pem("CERTIFICATE", &pki.chain[0])).unwrap();
        std::fs::write(
            &key,
            &pki.server_key.signing_key().to_pkcs8_pem().unwrap()[..],
        )
        .unwrap();
    };
    write("a.test");
    let store = Arc::new(CertStore::single(
        CertifiedKey::from_pem(
            &std::fs::read_to_string(&chain).unwrap(),
            &std::fs::read_to_string(&key).unwrap(),
        )
        .unwrap(),
    ));
    let reports = Arc::new(Mutex::new(Vec::new()));
    let reloader = {
        let reports = reports.clone();
        reload_certificates(
            store.clone(),
            vec![(chain.clone(), key.clone())],
            Duration::from_millis(50),
            move |r| reports.lock().unwrap().push(r.to_string()),
        )
    };
    let names = || store.certificates()[0].dns_names().to_vec();
    assert_eq!(names(), vec!["a.test".to_string()]);
    thread::sleep(Duration::from_millis(1100)); // a later modification time than the first files', on any file system
    write("b.test");
    wait_for("the new certificate", || {
        names() == vec!["b.test".to_string()]
    });
    // a key that does not match is refused, and the store keeps what it had
    thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        &key,
        &KeyPair::generate_ecdsa(Curve::P256)
            .unwrap()
            .signing_key()
            .to_pkcs8_pem()
            .unwrap()[..],
    )
    .unwrap();
    wait_for("the report of the refusal", || {
        reports
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains("not reloaded"))
    });
    assert_eq!(names(), vec!["b.test".to_string()]);
    drop(reloader);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ocsp_staples_are_fetched_checked_and_kept_fresh() {
    // a responder, served by this server: Good for one certificate, Revoked for the other
    let root_key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let root_spec = CertSpec::ca("pratique test ocsp root");
    let root = issue(&root_spec, &root_key, None);
    let leaves: Arc<Mutex<Vec<(Vec<u8>, OcspStatus)>>> = Arc::new(Mutex::new(Vec::new()));
    let asked = Arc::new(AtomicUsize::new(0));
    let responder = {
        let (root, root_key) = (
            root.clone(),
            KeyPair::from_key(root_key.signing_key().clone()),
        );
        let (leaves, asked) = (leaves.clone(), asked.clone());
        ServerBuilder::new(move |mut req: Request| {
            asked.fetch_add(1, Ordering::SeqCst);
            let _ = req.read_body(1 << 16);
            let path = req.path().to_string();
            let leaves = leaves.lock().unwrap();
            let (leaf, status) = &leaves[if path.ends_with("/revoked") { 1 } else { 0 }];
            let now = crate::sys::now_unix();
            Response::bytes(
                200,
                "application/ocsp-response",
                ocsp_response(&root, &root_key, leaf, *status, now - 60, Some(now + 7200)),
            )
        })
        .plain("127.0.0.1:0")
        .start()
        .unwrap()
    };
    let url = format!(
        "http://127.0.0.1:{}/ocsp",
        responder.local_addrs()[0].port()
    );
    let make = |path: &str| {
        let key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        let spec = CertSpec {
            ocsp_uris: vec![format!("{url}{path}")],
            ..CertSpec::server(&["stapled.test"])
        };
        let leaf = issue(&spec, &key, Some((&root_spec.common_name, &root_key)));
        (
            CertifiedKey::new(vec![leaf.clone(), root.clone()], key.signing_key().clone()).unwrap(),
            leaf,
        )
    };
    let (good, good_der) = make("");
    let (revoked, revoked_der) = make("/revoked");
    leaves.lock().unwrap().extend([
        (good_der, OcspStatus::Good),
        (
            revoked_der,
            OcspStatus::Revoked(crate::sys::now_unix() - 3600),
        ),
    ]);
    let store = Arc::new(CertStore::new());
    store.add(good);
    store.add(revoked);
    let reports = Arc::new(Mutex::new(Vec::new()));
    let refresher = {
        let reports = reports.clone();
        refresh_ocsp_staples(store.clone(), move |r| {
            reports.lock().unwrap().push(r.to_string())
        })
    };
    wait_for("a staple for the good certificate", || {
        store.certificates()[0].ocsp_staple().is_some()
    });
    wait_for("the report on the revoked one", || {
        reports
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains("certificate 1") && r.contains("not a good"))
    });
    assert!(
        store.certificates()[1].ocsp_staple().is_none(),
        "a revoked certificate's answer is never stapled"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    drop(refresher);
    responder.shutdown(Duration::from_secs(1));
}
