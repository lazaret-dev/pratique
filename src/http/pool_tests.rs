//! Tests of connection reuse (keep-alive) and of streaming bodies, over plain TCP and over TLS against the
//! crate's own TLS server. What these settle, that the unit tests of `idle` and `parser` cannot: that a
//! connection really goes back to the pool when its response is complete and not before, that a connection
//! that died while it waited is replaced (and a request that may not be repeated is not repeated), that limits
//! and timeouts apply to the request that uses a connection and not to the one that opened it, and that a body
//! reaches the caller as it arrives.

use super::testserver::*;
use crate::error::Error;
use std::io::Read;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Runs `test` against a plain server and against a TLS one, each answering with `handler`.
fn each_transport<H>(handler: H, test: impl Fn(&TestServer, bool))
where
    H: Fn(&Seen) -> Reply + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    for tls in [false, true] {
        let h = handler.clone();
        let server = if tls { TestServer::start_tls(move |s| h(s)) } else { TestServer::start(move |s| h(s)) };
        test(&server, tls);
    }
}

fn hello(seen: &Seen) -> Reply {
    ok(&format!("hello {}", seen.path()))
}

fn read_all(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out)?;
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ reuse

#[test]
fn requests_one_after_another_share_a_connection() {
    each_transport(hello, |server, tls| {
        let client = server.client();
        for i in 0..6 {
            let r = client.get(&server.url(&format!("/{i}"))).unwrap();
            assert_eq!(r.text(), format!("hello /{i}"), "tls {tls}");
            assert_eq!(client.idle_connections(), 1, "tls {tls}: the connection waits in the pool between requests");
        }
        assert_eq!(server.connections(), 1, "tls {tls}");
        let seen = server.requests();
        assert!(seen.iter().all(|s| s.conn == 0), "tls {tls}");
        assert_eq!(seen.iter().map(|s| s.nth).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5]);
        assert!(!seen[1].head.to_ascii_lowercase().contains("connection:"), "no Connection header is sent when connections are kept");
    });
}

#[test]
fn the_read_buffer_of_a_finished_response_is_used_for_the_next_one() {
    // (a new one is 32 KiB zeroed, a good part of the work of a small request on a connection that is used again: B-90)
    each_transport(hello, |server, tls| {
        let client = server.client();
        client.get(&server.url("/first")).unwrap();
        let kept = super::stream::spare_scratch();
        assert!(kept.is_some(), "tls {tls}: the buffer was not kept");
        for i in 0..3 {
            let mut s = client.get_stream(&server.url(&format!("/{i}"))).unwrap();
            assert_eq!(read_all(&mut s).unwrap(), format!("hello /{i}").as_bytes());
            drop(s);
            assert_eq!(super::stream::spare_scratch(), kept, "tls {tls}: a new buffer was made");
        }
    });
}

#[test]
fn without_keep_alive_each_request_has_its_own_connection() {
    each_transport(hello, |server, tls| {
        let client = server.client().keep_alive(false);
        for i in 0..3 {
            client.get(&server.url(&format!("/{i}"))).unwrap();
            assert_eq!(client.idle_connections(), 0, "tls {tls}");
        }
        assert_eq!(server.connections(), 3, "tls {tls}");
        assert!(server.requests().iter().all(|s| s.has_header("Connection: close")));
    });
}

#[test]
fn a_request_with_a_body_is_framed_right_on_a_connection_that_has_been_used() {
    each_transport(|s| ok(&format!("{} {} bytes", s.method(), s.body.len())), |server, tls| {
        let client = server.client();
        assert_eq!(client.get(&server.url("/")).unwrap().text(), "GET 0 bytes");
        let upload = big_body(100_000);
        let r = client.request("POST", &server.url("/up")).header("X-Mark", "one").body(upload.clone()).send().unwrap();
        assert_eq!(r.text(), "POST 100000 bytes", "tls {tls}");
        assert_eq!(client.request("PUT", &server.url("/up")).body(b"abc".to_vec()).send().unwrap().text(), "PUT 3 bytes");
        let seen = server.requests();
        assert_eq!(seen.iter().map(|s| s.conn).collect::<Vec<_>>(), [0, 0, 0], "tls {tls}: one connection");
        assert_eq!(seen[1].method(), "POST");
        assert_eq!(seen[1].header("content-length"), Some("100000"));
        assert_eq!(seen[1].header("x-mark"), Some("one"));
        assert_eq!(seen[1].body, upload);
        assert_eq!(seen[2].body, b"abc");
    });
}

#[test]
fn clones_share_the_pool_and_separate_clients_do_not() {
    each_transport(hello, |server, tls| {
        let a = server.client();
        let b = a.clone();
        a.get(&server.url("/1")).unwrap();
        b.get(&server.url("/2")).unwrap();
        a.get(&server.url("/3")).unwrap();
        assert_eq!(server.connections(), 1, "tls {tls}");
        server.client().get(&server.url("/4")).unwrap();
        assert_eq!(server.connections(), 2, "tls {tls}");
        // closing the idle connections of one clone empties the pool of all of them
        b.close_idle_connections();
        assert_eq!(a.idle_connections(), 0);
        a.get(&server.url("/5")).unwrap();
        assert_eq!(server.connections(), 3, "tls {tls}");
    });
}

#[test]
fn another_host_name_or_port_is_another_origin_with_its_own_connection() {
    // the same server under another name for the same address is another origin
    let a = TestServer::start_tls(hello);
    let client = a.client();
    client.get(&a.url("/")).unwrap();
    client.get(&a.url("/")).unwrap();
    assert_eq!(a.connections(), 1);
    client.get(&format!("https://localhost:{}/", a.port)).unwrap();
    assert_eq!(a.connections(), 2);
    client.get(&format!("https://localhost:{}/", a.port)).unwrap();
    client.get(&a.url("/")).unwrap();
    assert_eq!(a.connections(), 2, "both origins keep a connection");
    assert_eq!(client.idle_connections(), 2);

    // another port is another origin
    let (b, c) = (TestServer::start(hello), TestServer::start(hello));
    let client = b.client();
    for _ in 0..3 {
        client.get(&b.url("/")).unwrap();
        client.get(&c.url("/")).unwrap();
    }
    assert_eq!((b.connections(), c.connections()), (1, 1));
    assert_eq!(client.idle_connections(), 2);
}

#[test]
fn a_response_that_says_close_is_the_last_on_its_connection() {
    each_transport(
        |s| Reply::SendAndClose(response(200, &["Connection: close"], format!("n{}", s.path()).as_bytes())),
        |server, tls| {
            let client = server.client();
            for i in 0..3 {
                let r = client.get(&server.url(&format!("/{i}"))).unwrap();
                assert_eq!(r.text(), format!("n/{i}"));
                assert_eq!(client.idle_connections(), 0, "tls {tls}");
            }
            assert_eq!(server.connections(), 3, "tls {tls}");
        },
    );
}

#[test]
fn responses_that_cannot_be_followed_by_another_are_not_kept() {
    // HTTP/1.0 without keep-alive, a body that runs to the end of the connection, two framings at once
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("HTTP/1.0", b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()),
        ("until close", b"HTTP/1.1 200 OK\r\n\r\nok".to_vec()),
        ("both framings", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".to_vec()),
    ];
    for (name, bytes) in cases {
        let bytes2 = bytes.clone();
        each_transport(move |_| Reply::SendAndClose(bytes2.clone()), |server, tls| {
            let client = server.client();
            client.get(&server.url("/")).unwrap_or_else(|e| panic!("{name} tls {tls}: {e}"));
            assert_eq!(client.idle_connections(), 0, "{name} tls {tls}");
        });
        let _ = bytes;
    }
    // HTTP/1.0 that asks for keep-alive is kept
    each_transport(|_| Reply::Send(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok".to_vec()), |server, tls| {
        let client = server.client();
        client.get(&server.url("/")).unwrap();
        client.get(&server.url("/")).unwrap();
        assert_eq!((client.idle_connections(), server.connections()), (1, 1), "tls {tls}");
    });
}

#[test]
fn every_kind_of_framing_leaves_the_connection_usable() {
    each_transport(
        |s| match s.path() {
            "/chunked" => Reply::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec()),
            "/trailers" => Reply::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n".to_vec()),
            "/empty" => Reply::Send(response(200, &[], b"")),
            "/no-content" => Reply::Send(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
            "/not-modified" => Reply::Send(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n".to_vec()),
            "/head" => Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec()),
            _ => ok("fine"),
        },
        |server, tls| {
            let client = server.client();
            assert_eq!(client.get(&server.url("/chunked")).unwrap().text(), "hello world");
            assert_eq!(client.get(&server.url("/trailers")).unwrap().text(), "abc");
            assert_eq!(client.get(&server.url("/empty")).unwrap().body, b"");
            assert_eq!(client.get(&server.url("/no-content")).unwrap().status, 204);
            let nm = client.get(&server.url("/not-modified")).unwrap();
            assert_eq!((nm.status, nm.body.len()), (304, 0));
            let head = client.head(&server.url("/head")).unwrap();
            assert_eq!((head.status, head.body.len()), (200, 0));
            assert_eq!(client.get(&server.url("/after")).unwrap().text(), "fine");
            assert_eq!(server.connections(), 1, "tls {tls}: all of these on one connection");
        },
    );
}

#[test]
fn a_redirect_chain_stays_on_one_connection_unless_a_body_is_large() {
    each_transport(
        |s| match s.path() {
            "/a" => Reply::Send(response(302, &["Location: /b"], b"see /b")),
            "/b" => Reply::Send(response(301, &["Location: /c"], b"")),
            "/c" => ok("done"),
            "/big" => Reply::Send(response(302, &["Location: /c"], &vec![b'x'; 100_000])),
            _ => ok("other"),
        },
        |server, tls| {
            let client = server.client();
            let r = client.get(&server.url("/a")).unwrap();
            assert_eq!((r.status, r.text().as_str(), r.url.path_and_query.as_str()), (200, "done", "/c"));
            assert_eq!(server.connections(), 1, "tls {tls}: three requests, one connection");
            // a redirect with a body larger than is worth reading is not read: its connection is closed
            let r = client.get(&server.url("/big")).unwrap();
            assert_eq!(r.text(), "done");
            assert_eq!(server.connections(), 2, "tls {tls}");
            assert_eq!(client.idle_connections(), 1);
        },
    );
}

#[test]
fn a_redirect_to_another_origin_uses_that_origins_connection() {
    let target = TestServer::start(|_| ok("target"));
    let target_url = target.url("/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {target_url}")], b"")));
    let client = origin.client();
    assert_eq!(client.get(&origin.url("/")).unwrap().text(), "target");
    assert_eq!(client.get(&origin.url("/")).unwrap().text(), "target");
    assert_eq!((origin.connections(), target.connections()), (1, 1));
    assert_eq!(client.idle_connections(), 2);
}

// ------------------------------------------------------------------------------------------------ connections that die

#[test]
fn a_connection_the_server_closed_while_it_waited_is_replaced() {
    each_transport(hello, |server, tls| {
        let client = server.client();
        client.get(&server.url("/1")).unwrap();
        server.close_all(); // the server's idle timeout, as far as the client can tell
        thread::sleep(Duration::from_millis(50)); // the FIN has arrived
        // a POST may not be repeated, so this is the check at the pool, not the retry, that saves it
        let r = client.post(&server.url("/2"), "x").unwrap();
        assert_eq!(r.text(), "hello /2", "tls {tls}");
        assert_eq!(server.connections(), 2, "tls {tls}");
        assert_eq!(client.idle_connections(), 1);
    });
}

#[test]
fn a_get_survives_a_connection_that_died_in_the_same_instant() {
    // without waiting for the close to arrive, the check at the pool may not see it, and the retry must
    each_transport(hello, |server, tls| {
        let client = server.client();
        for i in 0..30 {
            client.get(&server.url("/")).unwrap_or_else(|e| panic!("tls {tls} round {i}: {e}"));
            server.close_all();
        }
        assert!(server.connections() >= 2);
    });
}

#[test]
fn a_reused_connection_that_dies_silently_is_retried_for_get_and_not_for_post() {
    // the server takes the second request on a connection and hangs up without answering
    for close in [Reply::Close, Reply::Cut] {
        let kind = if matches!(close, Reply::Close) { "close" } else { "cut" };
        let reply = Mutex::new(Some(close));
        each_transport_with_state(&reply, |server, tls, reply_for| {
            let _ = reply_for;
            let client = server.client();
            // GET, DELETE and PUT may be sent again; so may a POST that carries an Idempotency-Key
            for (method, headers) in [("GET", vec![]), ("DELETE", vec![]), ("PUT", vec![]), ("POST", vec![("Idempotency-Key", "k1")])] {
                let before = server.requests().len();
                client.get(&server.url("/warm")).unwrap();
                let mut req = client.request(method, &server.url("/die"));
                for (k, v) in &headers {
                    req = req.header(k, v);
                }
                let r = req.send().unwrap_or_else(|e| panic!("{kind} tls {tls} {method}: {e}"));
                assert_eq!(r.text(), "second try", "{kind} tls {tls} {method}");
                let seen = server.requests();
                let mine: Vec<_> = seen[before..].iter().map(|s| (s.conn, s.nth, s.path().to_string())).collect();
                assert_eq!(mine.len(), 3, "{kind} tls {tls} {method}: warm-up, the request that died, the repeat: {mine:?}");
                assert_eq!(mine[1].2, "/die");
                assert_eq!(mine[2].2, "/die");
                assert_ne!(mine[1].0, mine[2].0, "the repeat is on another connection");
                assert_eq!(mine[2].1, 0, "and it is the first request on that connection");
                server.close_all();
                thread::sleep(Duration::from_millis(30));
            }
            // a plain POST is not repeated: the caller gets the error, the server saw it once
            client.get(&server.url("/warm")).unwrap();
            let before = server.requests().len();
            let err = client.post(&server.url("/die"), "data").err().unwrap_or_else(|| panic!("{kind} tls {tls}: a POST was answered"));
            assert!(matches!(err, Error::Io(_)), "{kind} tls {tls}: {err}");
            assert_eq!(server.requests().len() - before, 1, "{kind} tls {tls}: the POST reached the server once");
        });
    }
}

/// `each_transport` for a handler whose behaviour for "/die" depends on whether the connection is a fresh
/// one: the first request on a connection to "/die" is hung up on only if it is not the first on its
/// connection (so a repeat on a new connection succeeds).
fn each_transport_with_state(close: &Mutex<Option<Reply>>, test: impl Fn(&TestServer, bool, &Mutex<Option<Reply>>)) {
    let hang_up_with_close = matches!(close.lock().unwrap().as_ref(), Some(Reply::Close));
    for tls in [false, true] {
        let handler = move |s: &Seen| {
            if s.path() == "/die" && s.nth > 0 {
                if hang_up_with_close {
                    Reply::Close
                } else {
                    Reply::Cut
                }
            } else if s.path() == "/die" {
                ok("second try")
            } else {
                ok("warm")
            }
        };
        let server = if tls { TestServer::start_tls(handler) } else { TestServer::start(handler) };
        test(&server, tls, close);
    }
}

#[test]
fn a_new_connection_that_dies_is_an_error_and_not_a_retry() {
    for close in [true, false] {
        each_transport(
            move |_| if close { Reply::Close } else { Reply::Cut },
            |server, tls| {
                let client = server.client();
                assert!(client.get(&server.url("/")).is_err(), "close {close} tls {tls}");
                assert_eq!(server.requests().len(), 1, "close {close} tls {tls}: nothing is sent twice on a new connection");
            },
        );
    }
}

#[test]
fn a_connection_cut_in_the_middle_of_a_body_is_an_error_and_is_not_kept() {
    each_transport(
        |s| {
            if s.path() == "/cut" {
                Reply::Run(Box::new(|w| {
                    w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
                    w.write_all(&[b'a'; 40]).unwrap();
                    w.flush().unwrap();
                    false
                }))
            } else {
                ok("fine")
            }
        },
        |server, tls| {
            let client = server.client();
            assert!(client.get(&server.url("/cut")).is_err(), "tls {tls}");
            assert_eq!(client.idle_connections(), 0, "tls {tls}");
            // as a stream: the first 40 bytes arrive, then the error
            let mut stream = client.get_stream(&server.url("/cut")).unwrap();
            let mut buf = Vec::new();
            let err = stream.read_to_end(&mut buf).err().expect("the body is short");
            assert_eq!(buf.len(), 40, "tls {tls}");
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "tls {tls}: {err}");
            drop(stream);
            assert_eq!(client.idle_connections(), 0);
            assert_eq!(client.get(&server.url("/ok")).unwrap().text(), "fine");
        },
    );
}

#[test]
fn idle_connections_expire_and_the_limits_hold() {
    // bodies too big to arrive with the head, so that several connections can be in use at once
    each_transport(|_| Reply::Send(response(200, &[], &big_body(200_000))), |server, tls| {
        // too old
        let client = server.client().pool_idle_timeout(Duration::from_millis(120));
        client.get(&server.url("/1")).unwrap();
        client.get(&server.url("/2")).unwrap();
        assert_eq!(server.connections(), 1, "tls {tls}");
        thread::sleep(Duration::from_millis(250));
        client.get(&server.url("/3")).unwrap();
        assert_eq!(server.connections(), 2, "tls {tls}: the old connection was not used");

        // too many: three connections in use at once, two kept
        let client = server.client().pool_max_idle_per_host(2);
        let mut streams: Vec<_> = (0..3).map(|i| client.get_stream(&server.url(&format!("/s{i}"))).unwrap()).collect();
        assert_eq!(client.idle_connections(), 0, "tls {tls}: all three are busy");
        for s in &mut streams {
            assert_eq!(read_all(s).unwrap().len(), 200_000);
        }
        assert_eq!(client.idle_connections(), 2, "tls {tls}");

        // none at all
        let client = server.client().pool_max_idle_per_host(0);
        client.get(&server.url("/n")).unwrap();
        assert_eq!(client.idle_connections(), 0);
    });
}

#[test]
fn a_server_that_says_how_long_it_waits_is_believed() {
    // Keep-Alive: timeout=0 means the server closes at once: do not keep the connection
    each_transport(|_| Reply::Send(response(200, &["Keep-Alive: timeout=0"], b"ok")), |server, tls| {
        let client = server.client();
        client.get(&server.url("/")).unwrap();
        client.get(&server.url("/")).unwrap();
        assert_eq!(server.connections(), 2, "tls {tls}");
    });
}

#[test]
fn the_timeout_applies_to_the_request_that_uses_a_connection() {
    each_transport(
        |s| {
            if s.path() == "/slow" {
                Reply::Run(Box::new(|w| {
                    thread::sleep(Duration::from_millis(1500));
                    let _ = w.write_all(&response(200, &[], b"late"));
                    true
                }))
            } else {
                ok("fast")
            }
        },
        |server, tls| {
            let client = server.client().timeout(Duration::from_millis(500));
            client.get(&server.url("/1")).unwrap();
            // longer idle than the timeout: the new request gets a new allowance
            thread::sleep(Duration::from_millis(700));
            assert_eq!(client.get(&server.url("/2")).unwrap().text(), "fast", "tls {tls}");
            assert_eq!(server.connections(), 1, "tls {tls}");
            // and a response that is slower than that allowance is a timeout, on a reused connection, at once
            let start = Instant::now();
            let err = client.get(&server.url("/slow")).err().expect("timed out");
            assert!(start.elapsed() < Duration::from_millis(1400), "tls {tls}: {:?} {err}", start.elapsed());
            assert!(matches!(err, Error::Io(_)), "{err}");
            // a timeout is not a stale connection: no retry
            assert_eq!(server.requests().iter().filter(|s| s.path() == "/slow").count(), 1, "tls {tls}");
        },
    );
}

// ------------------------------------------------------------------------------------------------ bodies as streams

fn big_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

#[test]
fn a_stream_gives_the_head_before_the_body_and_the_body_as_it_arrives() {
    let gates: Arc<Mutex<Vec<mpsc::Sender<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let g = gates.clone();
    each_transport(
        move |s| {
            if s.path() == "/pause" {
                let (tx, rx) = mpsc::channel();
                g.lock().unwrap().push(tx);
                Reply::Run(Box::new(move |w| {
                    w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
                    w.write_all(&[b'a'; 10]).unwrap();
                    w.flush().unwrap();
                    rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    w.write_all(&[b'b'; 90]).unwrap();
                    true
                }))
            } else if s.path() == "/pause-chunked" {
                let (tx, rx) = mpsc::channel();
                g.lock().unwrap().push(tx);
                Reply::Run(Box::new(move |w| {
                    w.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n").unwrap();
                    w.flush().unwrap();
                    rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    w.write_all(b"3\r\nefg\r\n0\r\n\r\n").unwrap();
                    true
                }))
            } else {
                ok("fine")
            }
        },
        |server, tls| {
            let client = server.client();
            gates.lock().unwrap().clear();
            // sized body: 10 bytes now, 90 when the server is told to go on
            let mut stream = client.get_stream(&server.url("/pause")).unwrap();
            assert_eq!((stream.status, stream.content_length), (200, Some(100)), "tls {tls}");
            let mut first = [0u8; 10];
            stream.read_exact(&mut first).unwrap();
            assert_eq!(&first, b"aaaaaaaaaa");
            assert_eq!(client.idle_connections(), 0, "the connection is in use until the body is read");
            gates.lock().unwrap()[0].send(()).unwrap();
            assert_eq!(read_all(&mut stream).unwrap(), vec![b'b'; 90]);
            // reading it all put the connection back
            assert_eq!(client.idle_connections(), 1, "tls {tls}");
            drop(stream);

            // chunked: a chunk now, the rest later
            let mut stream = client.get_stream(&server.url("/pause-chunked")).unwrap();
            assert_eq!(stream.content_length, None);
            let mut first = [0u8; 4];
            stream.read_exact(&mut first).unwrap();
            assert_eq!(&first, b"abcd");
            gates.lock().unwrap()[1].send(()).unwrap();
            assert_eq!(read_all(&mut stream).unwrap(), b"efg");
            assert_eq!(client.idle_connections(), 1, "tls {tls}");
            assert_eq!(server.connections(), 1, "tls {tls}: all on one connection");
        },
    );
}

#[test]
fn a_stream_read_to_its_last_byte_returns_its_connection_before_it_is_dropped() {
    each_transport(|_| Reply::Send(response(200, &[], &big_body(5000))), |server, tls| {
        let client = server.client();
        let mut stream = client.get_stream(&server.url("/")).unwrap();
        let mut body = vec![0u8; 5000];
        stream.read_exact(&mut body).unwrap(); // not even asking for the end of the stream
        assert_eq!(body, big_body(5000));
        assert_eq!(client.idle_connections(), 1, "tls {tls}");
        // and it is used by the next request while the stream is still alive
        assert_eq!(client.get(&server.url("/")).unwrap().body.len(), 5000);
        assert_eq!(server.connections(), 1, "tls {tls}");
        assert_eq!(stream.read(&mut body).unwrap(), 0);
    });
}

#[test]
fn a_stream_dropped_early_does_not_poison_the_pool() {
    each_transport(|_| Reply::Send(response(200, &[], &big_body(50_000))), |server, tls| {
        let client = server.client();
        let mut stream = client.get_stream(&server.url("/")).unwrap();
        let mut some = [0u8; 10];
        stream.read_exact(&mut some).unwrap();
        drop(stream);
        assert_eq!(client.idle_connections(), 0, "tls {tls}: a half-read body leaves a connection that cannot be used");
        // without reading anything at all
        drop(client.get_stream(&server.url("/")).unwrap());
        assert_eq!(client.idle_connections(), 0);
        let r = client.get(&server.url("/")).unwrap();
        assert_eq!(r.body, big_body(50_000));
        assert_eq!(server.connections(), 3, "tls {tls}");
    });
}

#[test]
fn a_big_body_is_copied_through_without_being_held() {
    // 20 MiB, produced by the server in pieces; the client counts what comes out of `copy_to`
    let total: u64 = 20 << 20;
    each_transport(
        move |_| {
            Reply::Run(Box::new(move |w| {
                w.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n").as_bytes()).unwrap();
                let piece = big_body(64 * 1024);
                let mut left = total as usize;
                while left > 0 {
                    let n = left.min(piece.len());
                    if w.write_all(&piece[..n]).is_err() {
                        return false;
                    }
                    left -= n;
                }
                true
            }))
        },
        |server, tls| {
            let client = server.client();
            let mut stream = client.get_stream(&server.url("/")).unwrap();
            let mut sink = Counting { n: 0, sum: 0 };
            assert_eq!(stream.copy_to(&mut sink).unwrap(), total, "tls {tls}");
            assert_eq!(sink.n, total);
            // the bytes were the right bytes
            let piece = big_body(64 * 1024);
            let expected: u64 = (0..total as usize).map(|i| piece[i % piece.len()] as u64).sum();
            assert_eq!(sink.sum, expected, "tls {tls}");
            assert_eq!(client.idle_connections(), 1);
        },
    );
}

struct Counting {
    n: u64,
    sum: u64,
}

impl std::io::Write for Counting {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.n += buf.len() as u64;
        self.sum += buf.iter().map(|&b| b as u64).sum::<u64>();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What a request for `url` does about a body over the limit: the error, from the request or from reading
/// the body (which of the two depends on how the bytes arrived).
fn limit_error(client: &crate::Client, url: &str) -> String {
    let error = match client.get_stream(url) {
        Err(e) => e.to_string(),
        Ok(mut stream) => read_all(&mut stream).err().expect("the body is over the limit").to_string(),
    };
    assert!(error.to_ascii_lowercase().contains("size limit"), "{error}");
    error
}

#[test]
fn the_size_limit_applies_to_streams_too() {
    each_transport(
        |s| match s.path() {
            "/sized" => Reply::Send(response(200, &[], &[b'x'; 500])),
            _ => Reply::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1f4\r\n".iter().copied().chain(vec![b'x'; 500]).chain(*b"\r\n0\r\n\r\n").collect()),
        },
        |server, tls| {
            let client = server.client().max_body_bytes(100);
            limit_error(&client, &server.url("/sized"));
            assert!(client.get(&server.url("/sized")).is_err(), "tls {tls}");
            // a chunked body is known only as it arrives
            limit_error(&client, &server.url("/chunked"));
            assert_eq!(client.idle_connections(), 0, "tls {tls}: a connection that broke is not kept");
            // one request may ask for more than the client's default
            let r = client.request("GET", &server.url("/sized")).max_body_bytes(1000).send().unwrap();
            assert_eq!(r.body.len(), 500, "tls {tls}");
            // and for less
            let big = server.client();
            assert!(big.request("GET", &server.url("/sized")).max_body_bytes(10).send().is_err());
            assert_eq!(big.request("GET", &server.url("/sized")).send().unwrap().body.len(), 500);
        },
    );
}

#[test]
fn a_stream_turned_into_a_response_has_the_whole_body() {
    each_transport(|_| Reply::Send(response(200, &["X-One: 1", "X-Two: 2"], &big_body(70_000))), |server, tls| {
        let client = server.client();
        let mut stream = client.get_stream(&server.url("/")).unwrap();
        assert_eq!((stream.header("x-one"), stream.header("X-TWO"), stream.is_success()), (Some("1"), Some("2"), true));
        let mut head = [0u8; 100];
        stream.read_exact(&mut head).unwrap(); // some of it is already read
        let r = stream.into_response().unwrap();
        assert_eq!(r.body, big_body(70_000)[100..], "tls {tls}: what is left");
        assert_eq!(client.idle_connections(), 1);
    });
}

// ------------------------------------------------------------------------------------------------ TLS only

#[test]
fn session_tickets_and_key_updates_do_not_get_in_the_way_of_reuse() {
    for (tickets, late) in [(0usize, false), (1, false), (4, false), (2, true)] {
        let server = TestServer::start_tls_with(hello, move |mut c| {
            c.tickets = tickets;
            c.tickets_after_first_write = late;
            c.with_rekey_after_records(3)
        });
        let client = server.client();
        for i in 0..25 {
            let r = client.get(&server.url(&format!("/{i}"))).unwrap();
            assert_eq!(r.text(), format!("hello /{i}"), "tickets {tickets} late {late}");
        }
        assert_eq!(server.connections(), 1, "tickets {tickets} late {late}: 25 requests, keys rotated many times, one connection");
    }
}

#[test]
fn a_key_update_that_arrives_with_the_end_of_a_response_is_answered_and_the_connection_kept() {
    for request_peer in [false, true] {
        let server = TestServer::start_tls(move |s| {
            let body = format!("n{}", s.path());
            let bytes = response(200, &[], body.as_bytes());
            Reply::Run(Box::new(move |w| {
                w.write_then_key_update(&bytes, request_peer);
                true
            }))
        });
        let client = server.client();
        for i in 0..8 {
            assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("n/{i}"), "request_peer {request_peer}");
        }
        assert_eq!(server.connections(), 1, "request_peer {request_peer}");
    }
}

#[test]
fn session_tickets_that_arrive_with_the_end_of_a_response_are_digested() {
    let server = TestServer::start_tls(|s| {
        let bytes = response(200, &[], s.path().as_bytes());
        Reply::Run(Box::new(move |w| {
            w.write_then_tickets(&bytes, 2);
            true
        }))
    });
    let client = server.client();
    for i in 0..6 {
        assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("/{i}"));
    }
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_connection_with_something_unread_on_it_is_not_reused() {
    // What the server sends after the response was complete and the connection parked (session tickets, a
    // KeyUpdate) is waiting on the socket, so the connection is not "quiet" and a new one is opened: that costs
    // a handshake, and is correct.
    type Late = fn(&mut dyn Wire);
    let kinds: [(&str, Late); 2] = [("tickets", |w| w.tickets(1)), ("key update", |w| w.key_update(true))];
    for (name, late) in kinds {
        let server = TestServer::start_tls(move |s| {
            let bytes = response(200, &[], s.path().as_bytes());
            let first = s.nth == 0;
            Reply::Run(Box::new(move |w| {
                w.write_all(&bytes).unwrap();
                w.flush().unwrap();
                if first {
                    thread::sleep(Duration::from_millis(150));
                    late(w);
                }
                true
            }))
        });
        let client = server.client();
        assert_eq!(client.get(&server.url("/a")).unwrap().text(), "/a", "{name}");
        thread::sleep(Duration::from_millis(400));
        assert_eq!(client.get(&server.url("/b")).unwrap().text(), "/b", "{name}");
        assert_eq!(server.connections(), 2, "{name}");
    }
}

#[test]
fn a_close_notify_that_arrived_while_it_waited_ends_the_connection() {
    // the server answers and then closes the polite way (close_notify, then TCP close), as a server does that
    // has had enough of a connection
    let server = TestServer::start_tls(|s| Reply::SendAndClose(response(200, &[], s.path().as_bytes())));
    let client = server.client();
    for i in 0..4 {
        assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("/{i}"));
        // the client cannot know the server closed until it looks: next time it looks
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(server.connections(), 4);
}

// ------------------------------------------------------------------------------------------------ the async client

mod asynchronous {
    use super::*;
    use crate::asyncio::{block_on, AsyncReadExt, ThreadedStream};
    use crate::http::async_client::Connect;
    use crate::http::{AsyncClient, ConnectOptions};
    use std::future::Future;
    use std::pin::Pin;

    fn async_client(server: &TestServer) -> AsyncClient {
        server.client().into_async()
    }

    #[test]
    fn async_requests_share_a_connection_over_both_transports() {
        each_transport(hello, |server, tls| {
            let client = async_client(server);
            for i in 0..5 {
                let r = block_on(client.get(&server.url(&format!("/{i}")))).unwrap();
                assert_eq!(r.text(), format!("hello /{i}"), "tls {tls}");
                assert_eq!(client.idle_connections(), 1);
            }
            assert_eq!(server.connections(), 1, "tls {tls}");
            // clones share what the client keeps
            let c2 = client.clone();
            block_on(c2.get(&server.url("/x"))).unwrap();
            assert_eq!(server.connections(), 1, "tls {tls}");
            c2.close_idle_connections();
            assert_eq!(client.idle_connections(), 0);
        });
    }

    #[test]
    fn async_keep_alive_off_and_close_responses() {
        each_transport(hello, |server, tls| {
            let client = server.client().keep_alive(false).into_async();
            for i in 0..3 {
                block_on(client.get(&server.url(&format!("/{i}")))).unwrap();
            }
            assert_eq!((server.connections(), client.idle_connections()), (3, 0), "tls {tls}");
        });
        each_transport(|_| Reply::SendAndClose(response(200, &["Connection: close"], b"x")), |server, tls| {
            let client = async_client(server);
            for _ in 0..3 {
                block_on(client.get(&server.url("/"))).unwrap();
            }
            assert_eq!((server.connections(), client.idle_connections()), (3, 0), "tls {tls}");
        });
    }

    #[test]
    fn an_async_stream_is_read_as_it_arrives_and_returns_its_connection() {
        let gate: Arc<Mutex<Option<mpsc::Sender<()>>>> = Arc::new(Mutex::new(None));
        let g = gate.clone();
        each_transport(
            move |s| {
                if s.path() == "/pause" {
                    let (tx, rx) = mpsc::channel();
                    *g.lock().unwrap() = Some(tx);
                    Reply::Run(Box::new(move |w| {
                        w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
                        w.write_all(&[b'a'; 10]).unwrap();
                        w.flush().unwrap();
                        rx.recv_timeout(Duration::from_secs(10)).unwrap();
                        w.write_all(&[b'b'; 90]).unwrap();
                        true
                    }))
                } else if s.path() == "/huge" {
                    Reply::Send(response(200, &[], &big_body(300_000)))
                } else {
                    Reply::Send(response(200, &[], &big_body(5000)))
                }
            },
            |server, tls| {
                let client = async_client(server);
                block_on(async {
                    let mut stream = client.get_stream(&server.url("/pause")).await.unwrap();
                    assert_eq!((stream.status, stream.content_length), (200, Some(100)));
                    let mut first = [0u8; 10];
                    stream.read_exact(&mut first).await.unwrap();
                    assert_eq!(&first, b"aaaaaaaaaa");
                    assert_eq!(client.idle_connections(), 0);
                    gate.lock().unwrap().take().unwrap().send(()).unwrap();
                    // the last byte returns the connection, before the end of the body is asked for
                    let mut rest = vec![0u8; 90];
                    stream.read_exact(&mut rest).await.unwrap();
                    assert_eq!(rest, vec![b'b'; 90], "tls {tls}");
                    assert_eq!(client.idle_connections(), 1, "tls {tls}");
                    let mut end = [0u8; 1];
                    assert_eq!(stream.read(&mut end).await.unwrap(), 0);
                    drop(stream);

                    // a short body that came with the head: the connection was parked before the stream was returned
                    let stream = client.get_stream(&server.url("/big")).await.unwrap();
                    assert_eq!(client.idle_connections(), 1, "tls {tls}");
                    drop(stream);
                    // a stream dropped half-read does not return its connection
                    let mut stream = client.get_stream(&server.url("/huge")).await.unwrap();
                    let mut some = [0u8; 10];
                    stream.read_exact(&mut some).await.unwrap();
                    assert_eq!(client.idle_connections(), 0, "tls {tls}");
                    drop(stream);
                    assert_eq!(client.idle_connections(), 0, "tls {tls}");
                    // copy_to and into_response
                    let mut stream = client.get_stream(&server.url("/big")).await.unwrap();
                    let mut sink = Vec::new();
                    let mut cursor = VecSink(&mut sink);
                    assert_eq!(stream.copy_to(&mut cursor).await.unwrap(), 5000);
                    assert_eq!(sink, big_body(5000));
                    let stream = client.get_stream(&server.url("/big")).await.unwrap();
                    assert_eq!(stream.into_response().await.unwrap().body, big_body(5000));
                });
                // /pause, /big and the abandoned /huge shared one connection; copy_to and into_response the next
                assert_eq!(server.connections(), 2, "tls {tls}");
            },
        );
    }

    /// An `AsyncWrite` into a Vec.
    struct VecSink<'a>(&'a mut Vec<u8>);

    impl crate::asyncio::AsyncWrite for VecSink<'_> {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn async_stale_connections_are_replaced_and_only_replayable_requests_repeated() {
        each_transport(
            |s| if s.path() == "/die" && s.nth > 0 { Reply::Cut } else if s.path() == "/die" { ok("second try") } else { ok("warm") },
            |server, tls| {
                let client = async_client(server);
                // closed while waiting, noticed at the pool
                block_on(client.get(&server.url("/warm"))).unwrap();
                server.close_all();
                thread::sleep(Duration::from_millis(50));
                assert_eq!(block_on(client.request("POST", &server.url("/warm")).body("x").send()).unwrap().text(), "warm", "tls {tls}");
                // closed in the middle of a request: a GET goes again, a POST does not
                block_on(client.get(&server.url("/warm"))).unwrap();
                let before = server.requests().len();
                assert_eq!(block_on(client.get(&server.url("/die"))).unwrap().text(), "second try", "tls {tls}");
                assert_eq!(server.requests().len() - before, 2, "tls {tls}");
                block_on(client.get(&server.url("/warm"))).unwrap();
                let before = server.requests().len();
                assert!(block_on(client.request("POST", &server.url("/die")).body("x").send()).is_err(), "tls {tls}");
                assert_eq!(server.requests().len() - before, 1, "tls {tls}");
                // with an Idempotency-Key, it does
                block_on(client.get(&server.url("/warm"))).unwrap();
                let r = block_on(client.request("POST", &server.url("/die")).header("Idempotency-Key", "k").body("x").send()).unwrap();
                assert_eq!(r.text(), "second try", "tls {tls}");
            },
        );
    }

    #[test]
    fn async_redirects_and_limits() {
        each_transport(
            |s| match s.path() {
                "/a" => Reply::Send(response(302, &["Location: /b"], b"see /b")),
                "/b" => Reply::Send(response(200, &[], &[b'y'; 500])),
                _ => ok("x"),
            },
            |server, tls| {
                let client = async_client(server);
                let r = block_on(client.get(&server.url("/a"))).unwrap();
                assert_eq!((r.status, r.body.len()), (200, 500));
                assert_eq!(server.connections(), 1, "tls {tls}");
                assert!(block_on(client.request("GET", &server.url("/b")).max_body_bytes(100).send()).is_err());
                assert_eq!(block_on(client.request("GET", &server.url("/b")).max_body_bytes(1000).send()).unwrap().body.len(), 500);
            },
        );
    }

    /// A connector that does not say a connection may be reused: its connections are not.
    #[derive(Clone)]
    struct NoReuse(crate::http::async_client::ThreadConnector);

    impl Connect for NoReuse {
        type Stream = ThreadedStream;

        fn connect<'a>(&'a self, host: &'a str, port: u16, opts: ConnectOptions) -> Pin<Box<dyn Future<Output = std::io::Result<ThreadedStream>> + Send + 'a>> {
            self.0.connect(host, port, opts)
        }
    }

    #[test]
    fn a_connector_that_does_not_opt_in_gets_no_reuse() {
        each_transport(hello, |server, tls| {
            let connector = NoReuse(crate::http::async_client::ThreadConnector::new(crate::asyncio::Pool::global()));
            let client = AsyncClient::with_connector(server.client(), connector);
            for i in 0..3 {
                assert_eq!(block_on(client.get(&server.url(&format!("/{i}")))).unwrap().text(), format!("hello /{i}"));
            }
            assert_eq!(server.connections(), 3, "tls {tls}: each request had to open its own connection");
            // and what it parked was not handed out again, and is not leaked
            client.close_idle_connections();
            assert_eq!(client.idle_connections(), 0);
        });
    }

    #[test]
    fn async_session_tickets_and_key_updates() {
        let server = TestServer::start_tls_with(
            |s| {
                let bytes = response(200, &[], s.path().as_bytes());
                Reply::Run(Box::new(move |w| {
                    w.write_then_key_update(&bytes, true);
                    true
                }))
            },
            |c| c.with_tickets(3).with_rekey_after_records(4),
        );
        let client = async_client(&server);
        for i in 0..12 {
            assert_eq!(block_on(client.get(&server.url(&format!("/{i}")))).unwrap().text(), format!("/{i}"));
        }
        assert_eq!(server.connections(), 1, "12 requests, keys rotated both ways, one connection");
    }
}

/// TLS 1.3 session resumption (B-35) through the client: a request that needs a new connection to a server it has spoken to
/// resumes the session of the connection before, with the client's own store (shared by its clones), and a separate
/// client does not.
#[test]
fn a_new_connection_to_the_same_server_resumes_the_tls_session() {
    let sessions = Arc::new(Mutex::new(crate::tls::server::ServerSessions::default()));
    let s = sessions.clone();
    // the server closes every connection after its response, so each request makes a new one
    let server = TestServer::start_tls_with(|_| Reply::SendAndClose(response(200, &[], b"ok")), move |c| crate::tls::server::ServerConfig { sessions: Some(s), ..c });
    let client = server.client();
    for i in 0..3 {
        let resp = client.get(&server.url("/")).unwrap();
        assert_eq!(resp.body, b"ok", "request {i}");
    }
    assert_eq!(server.connections(), 3);
    assert_eq!(sessions.lock().unwrap().resumed, 2, "the second and third connections resumed");
    let clone = client.clone();
    clone.get(&server.url("/")).unwrap();
    assert_eq!(sessions.lock().unwrap().resumed, 3, "a clone shares the sessions");
    server.client().get(&server.url("/")).unwrap();
    assert_eq!(sessions.lock().unwrap().resumed, 3, "another client has none");
}
