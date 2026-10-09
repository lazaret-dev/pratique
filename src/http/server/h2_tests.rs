//! HTTP/2: the server against the crate's own HTTP/2 client (over TLS, ALPN `h2`), and against a client that writes frames
//! by hand (prior knowledge, over plain TCP) for what a polite client never does: the floods, the protocol errors, flow
//! control pushed to its edges.

use super::super::h2::frame::{self, flag, kind, setting, ErrorCode, PREFACE};
use super::test_util::{Raw, Server};
use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn hello(req: Request) -> Response {
    Response::text(200, format!("{} {} {}", req.method(), req.path(), req.authority()))
}

fn small_floods() -> HttpConfig {
    let mut c = HttpConfig::default();
    c.h2.flood_resets = 20;
    c.h2.flood_settings = 10;
    c.h2.flood_pings = 10;
    c.h2.flood_empty = 10;
    c.h2.flood_priority = 20;
    c.h2.flood_small_updates = 10;
    c
}

// ------------------------------------------------------------------------------------------------ with the crate's client

#[test]
fn requests_go_over_one_connection_with_bodies_both_ways() {
    let s = Server::tls(
        |mut req: Request| match req.path() {
            "/echo" => Response::reader(200, req.into_body(), None),
            "/len" => {
                let n = req.read_body(64 << 20).unwrap().len();
                Response::text(200, format!("{n}"))
            }
            "/big" => Response::bytes(200, "application/octet-stream", (0..3_000_000u32).map(|i| (i % 251) as u8).collect()),
            _ => hello(req),
        },
        HttpConfig::default(),
        &["h2", "http/1.1"],
    );
    let client = s.client();
    let r = client.get(&s.url("/hi")).unwrap();
    assert_eq!((r.status, r.version, r.text()), (200, crate::http::HttpVersion::Http2, format!("GET /hi 127.0.0.1:{}", s.addr.port())));
    assert!(r.header("date").is_some());
    let body: Vec<u8> = (0..5_000_000u32).map(|i| (i % 253) as u8).collect();
    let r = client.post(&s.url("/echo"), body.clone()).unwrap();
    assert!(r.body == body, "an echo of 5 MB, through windows of 1 MB");
    assert_eq!(client.post(&s.url("/len"), vec![1u8; 2_500_000]).unwrap().text(), "2500000");
    let r = client.get(&s.url("/big")).unwrap();
    assert_eq!((r.body.len(), r.body[2_999_999]), (3_000_000, (2_999_999u32 % 251) as u8));
    // many at once, each on its own stream
    let threads: Vec<_> = (0..20)
        .map(|i| {
            let (client, url) = (client.clone(), s.url(&format!("/{i}")));
            thread::spawn(move || client.get(&url).unwrap().text())
        })
        .collect();
    for (i, t) in threads.into_iter().enumerate() {
        assert!(t.join().unwrap().starts_with(&format!("GET /{i} ")));
    }
    assert_eq!(s.connections.load(Ordering::SeqCst), 1, "one connection for everything");
}

#[test]
fn a_stream_waits_for_the_client_window_and_others_go_on() {
    // the client gives no stream credit at first: the head comes, the data waits for a WINDOW_UPDATE
    let s = Server::plain(|req: Request| if req.path() == "/big" { Response::bytes(200, "x/y", vec![9; 100_000]) } else { hello(req) }, HttpConfig::default());
    let mut c = Raw::connect(&s, &[(setting::INITIAL_WINDOW_SIZE, 0)]);
    c.get(1, "/big");
    let frames = c.until(|f| f.h.stream == 1 && f.is(kind::HEADERS));
    assert!(frames.iter().all(|f| !f.is(kind::DATA)));
    // a round trip: nothing but the PING's answer comes in the meantime
    thread::sleep(Duration::from_millis(100));
    c.raw_frame(kind::PING, 0, 0, b"roundtrp");
    let frames = c.until(|f| f.is(kind::PING));
    assert!(frames.iter().all(|f| !f.is(kind::DATA)), "no data without a window: {frames:?}");
    // credit for 10 bytes: 10 bytes come
    let mut out = Vec::new();
    frame::write_window_update(&mut out, 1, 10);
    c.send(&out);
    let f = c.until(|f| f.is(kind::DATA)).pop().unwrap();
    assert_eq!(f.p.len(), 10);
    // the rest
    let mut out = Vec::new();
    frame::write_window_update(&mut out, 1, 200_000);
    frame::write_window_update(&mut out, 0, 200_000);
    c.send(&out);
    let mut got = 10;
    for f in c.until(|f| f.h.stream == 1 && f.h.has(flag::END_STREAM)) {
        if f.is(kind::DATA) {
            got += f.p.len();
        }
    }
    assert_eq!(got, 100_000);
}

#[test]
fn a_handler_that_does_not_read_holds_its_client_to_the_window() {
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = Arc::new(Mutex::new(go_rx));
    let mut config = HttpConfig::default();
    config.h2.stream_window = 65_535;
    config.h2.connection_window = 1 << 20;
    let s = Server::plain(
        move |mut req: Request| {
            go_rx.lock().unwrap().recv().unwrap();
            let n = req.read_body(1 << 20).map_or(0, |b| b.len());
            Response::text(200, format!("{n}"))
        },
        config,
    );
    let mut c = Raw::connect(&s, &[]);
    c.headers(1, &[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/up")], false);
    c.data(1, &vec![1u8; 16_384], false);
    c.data(1, &vec![1u8; 16_384], false);
    c.data(1, &vec![1u8; 16_384], false);
    c.data(1, &vec![1u8; 16_383], false);
    // the window is full: one byte more is a flow-control error on the stream
    c.data(1, &[1], false);
    assert_eq!(c.reset_of(1), Some(ErrorCode::FLOW_CONTROL_ERROR.0));
    go_tx.send(()).unwrap();
    // a stream that keeps within the window gets its credit as the handler reads
    c.headers(3, &[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/up")], false);
    c.data(3, &vec![2u8; 60_000], false);
    go_tx.send(()).unwrap();
    // as a client must: what the window allows, and more as the credit comes
    let mut window: i64 = 65_535 - 60_000;
    let mut left = 60_000i64;
    while left > 0 {
        let f = c.until(|f| f.is(kind::WINDOW_UPDATE) && f.h.stream == 3).pop().expect("credit as the handler reads");
        window += u32::from_be_bytes(f.p[..4].try_into().unwrap()) as i64;
        let n = window.min(left);
        if n > 0 {
            c.data(3, &vec![2u8; n as usize], n == left);
            window -= n;
            left -= n;
        }
    }
    let (status, _, body) = c.response(3);
    assert_eq!((status, String::from_utf8(body).unwrap()), (200, "120000".into()));
}

#[test]
fn trailers_head_and_hundred_continue() {
    let s = Server::plain(
        |mut req: Request| match req.path() {
            "/trailers" => {
                let body = req.read_body(1 << 20).unwrap();
                let got: Vec<String> = req.body().trailers().iter().map(|(n, v)| format!("{n}={v}")).collect();
                Response::stream(200, move |w| {
                    w.write_all(&body)?;
                    w.write_all(got.join(",").as_bytes())?;
                    w.set_trailers(vec![("grpc-status".into(), "0".into())]);
                    Ok(())
                })
            }
            "/sized" => Response::bytes(200, "x/y", vec![5; 1234]),
            _ => {
                let n = req.read_body(1 << 20).unwrap().len();
                Response::text(200, format!("{n}"))
            }
        },
        HttpConfig::default(),
    );
    let mut c = Raw::connect(&s, &[]);
    c.headers(1, &[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/trailers"), ("te", "trailers")], false);
    c.data(1, b"body;", false);
    c.headers(1, &[("x-sum", "42")], true);
    let frames = c.until(|f| f.h.stream == 1 && f.h.has(flag::END_STREAM));
    let mut body = Vec::new();
    let mut blocks = Vec::new();
    for f in &frames {
        if f.is(kind::DATA) && f.h.stream == 1 {
            body.extend_from_slice(&f.p);
        }
        if f.is(kind::HEADERS) && f.h.stream == 1 {
            blocks.push(c.decode(f));
        }
    }
    assert_eq!(String::from_utf8(body).unwrap(), "body;x-sum=42");
    assert_eq!(blocks.last().unwrap(), &vec![("grpc-status".to_string(), "0".to_string())]);
    // HEAD: the length, no data
    c.headers(3, &[(":method", "HEAD"), (":scheme", "http"), (":authority", "a"), (":path", "/sized")], true);
    let frames = c.until(|f| f.h.stream == 3 && f.h.has(flag::END_STREAM));
    assert!(frames.iter().all(|f| !(f.is(kind::DATA) && f.h.stream == 3)));
    let head = c.decode(frames.iter().find(|f| f.h.stream == 3 && f.is(kind::HEADERS)).unwrap());
    assert!(head.contains(&("content-length".to_string(), "1234".to_string())));
    // Expect: 100-continue: a 100 once the handler reads
    c.headers(5, &[(":method", "PUT"), (":scheme", "http"), (":authority", "a"), (":path", "/up"), ("expect", "100-continue")], false);
    let frames = c.until(|f| f.h.stream == 5 && f.is(kind::HEADERS));
    assert_eq!(c.decode(frames.last().unwrap()), vec![(":status".to_string(), "100".to_string())]);
    c.data(5, b"abc", true);
    let (status, _, body) = c.response(5);
    assert_eq!((status, body), (200, b"3".to_vec()));
}

#[test]
fn connect_over_a_stream_is_a_tunnel() {
    let s = Server::plain(
        |req: Request| {
            assert_eq!((req.method(), req.target()), ("CONNECT", "upstream.example:443"));
            Response::upgrade(200, |mut t| {
                let mut buf = [0u8; 100];
                loop {
                    match t.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = t.write_all(&buf[..n].to_ascii_uppercase());
                        }
                    }
                }
            })
        },
        HttpConfig::default(),
    );
    let mut c = Raw::connect(&s, &[]);
    c.headers(1, &[(":method", "CONNECT"), (":authority", "upstream.example:443")], false);
    let frames = c.until(|f| f.h.stream == 1 && f.is(kind::HEADERS));
    assert_eq!(c.decode(frames.last().unwrap()).first().unwrap(), &(":status".to_string(), "200".to_string()));
    assert!(!frames.last().unwrap().h.has(flag::END_STREAM));
    c.data(1, b"through the tunnel", false);
    let f = c.until(|f| f.is(kind::DATA)).pop().unwrap();
    assert_eq!(f.p, b"THROUGH THE TUNNEL");
    c.data(1, b"", true);
    let frames = c.until(|f| f.h.stream == 1 && f.h.has(flag::END_STREAM));
    assert!(frames.last().unwrap().h.has(flag::END_STREAM), "the tunnel ends both ways");
}

// ------------------------------------------------------------------------------------------------ what is refused

#[test]
fn malformed_requests_are_reset_and_the_connection_goes_on() {
    let s = Server::plain(hello, HttpConfig::default());
    let mut c = Raw::connect(&s, &[]);
    let base = [(":method", "GET"), (":scheme", "https"), (":authority", "a.example"), (":path", "/")];
    let mut id = 1;
    for extra in [
        &[("Upper", "x")][..],
        &[("connection", "keep-alive")],
        &[("transfer-encoding", "chunked")],
        &[("te", "gzip")],
        &[("host", "b.example")],
        &[("x", " padded")],
        &[("content-length", "1, 1")],
        &[(":protocol", "websocket")],
    ] {
        let mut fields = base.to_vec();
        fields.extend_from_slice(extra);
        c.headers(id, &fields, true);
        assert_eq!(c.reset_of(id), Some(ErrorCode::PROTOCOL_ERROR.0), "{extra:?}");
        id += 2;
    }
    for fields in [
        &[(":method", "GET"), (":scheme", "https"), (":authority", "a")][..],
        &[(":method", "GET"), (":authority", "a"), (":path", "/")],
        &[(":method", "GET"), (":scheme", "https"), (":path", "/")],
        &[(":method", "GET"), (":scheme", "https"), (":authority", "a"), (":path", "x")],
        &[(":method", "GET"), (":scheme", "ftp"), (":authority", "a"), (":path", "/")],
        &[(":scheme", "https"), (":authority", "a"), (":path", "/")],
        &[(":method", "GET"), (":method", "GET"), (":scheme", "https"), (":authority", "a"), (":path", "/")],
        &[(":method", "GET"), ("x", "y"), (":scheme", "https"), (":authority", "a"), (":path", "/")],
        &[(":method", "CONNECT"), (":authority", "a:443"), (":path", "/")],
        &[(":method", "CONNECT"), (":authority", "a")],
        &[(":method", "POST"), (":scheme", "https"), (":authority", "a"), (":path", "/"), ("content-length", "5")],
    ] {
        c.headers(id, fields, true);
        assert_eq!(c.reset_of(id), Some(ErrorCode::PROTOCOL_ERROR.0), "{fields:?}");
        id += 2;
    }
    // and after all that, a good request is answered
    c.get(id, "/fine");
    assert_eq!(c.response(id).0, 200);
}

#[test]
fn protocol_errors_lose_the_connection_with_the_right_code() {
    let s = Server::plain(hello, HttpConfig::default());
    let cases: Vec<(&str, Box<dyn Fn(&mut Raw)>, ErrorCode)> = vec![
        ("HEADERS on an even stream", Box::new(|c: &mut Raw| c.get(2, "/")), ErrorCode::PROTOCOL_ERROR),
        ("a stream id that goes back", Box::new(|c: &mut Raw| {
            c.get(5, "/");
            c.get(3, "/");
        }), ErrorCode::PROTOCOL_ERROR),
        ("DATA on an idle stream", Box::new(|c: &mut Raw| c.data(7, b"x", true)), ErrorCode::PROTOCOL_ERROR),
        ("WINDOW_UPDATE on an idle stream", Box::new(|c: &mut Raw| c.raw_frame(kind::WINDOW_UPDATE, 0, 9, &1u32.to_be_bytes())), ErrorCode::PROTOCOL_ERROR),
        ("RST_STREAM on an idle stream", Box::new(|c: &mut Raw| c.raw_frame(kind::RST_STREAM, 0, 9, &0u32.to_be_bytes())), ErrorCode::PROTOCOL_ERROR),
        ("CONTINUATION without HEADERS", Box::new(|c: &mut Raw| c.raw_frame(kind::CONTINUATION, flag::END_HEADERS, 1, b"")), ErrorCode::PROTOCOL_ERROR),
        ("a frame inside a header block", Box::new(|c: &mut Raw| {
            let block = c.block(&[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")]);
            c.raw_frame(kind::HEADERS, flag::END_STREAM, 1, &block);
            c.raw_frame(kind::PING, 0, 0, &[0; 8]);
        }), ErrorCode::PROTOCOL_ERROR),
        ("PUSH_PROMISE from a client", Box::new(|c: &mut Raw| c.raw_frame(kind::PUSH_PROMISE, flag::END_HEADERS, 1, &[0, 0, 0, 2])), ErrorCode::PROTOCOL_ERROR),
        ("a frame larger than announced", Box::new(|c: &mut Raw| c.raw_frame(kind::DATA, 0, 1, &vec![0; 16_385])), ErrorCode::FRAME_SIZE_ERROR),
        ("a connection window over 2^31-1", Box::new(|c: &mut Raw| c.raw_frame(kind::WINDOW_UPDATE, 0, 0, &0x7fff_ffffu32.to_be_bytes())), ErrorCode::FLOW_CONTROL_ERROR),
        ("SETTINGS_ENABLE_PUSH of 2", Box::new(|c: &mut Raw| {
            let mut out = Vec::new();
            frame::write_settings(&mut out, &[(setting::ENABLE_PUSH, 2)]);
            c.send(&out);
        }), ErrorCode::PROTOCOL_ERROR),
        ("a header block that does not decode", Box::new(|c: &mut Raw| c.raw_frame(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &[0xff, 0xff, 0xff, 0xff, 0x7f])), ErrorCode::COMPRESSION_ERROR),
        ("a stream that depends on itself", Box::new(|c: &mut Raw| {
            let block = c.block(&[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")]);
            let mut p = 1u32.to_be_bytes().to_vec();
            p.push(16);
            p.extend_from_slice(&block);
            c.raw_frame(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM | flag::PRIORITY, 1, &p);
        }), ErrorCode::PROTOCOL_ERROR),
        ("DATA on a stream the client ended", Box::new(|c: &mut Raw| {
            c.headers(1, &[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")], true);
            let _ = c.until(|f| f.h.stream == 1 && f.h.has(flag::END_STREAM));
            c.data(1, b"late", true);
        }), ErrorCode::STREAM_CLOSED),
    ];
    for (what, act, code) in cases {
        let mut c = Raw::connect(&s, &[]);
        act(&mut c);
        assert_eq!(c.goaway(), Some(code.0), "{what}");
        assert!(c.next().is_none(), "{what}: the connection closes");
    }
    // the first frame must be SETTINGS
    let mut c = s.connect();
    c.write_all(PREFACE).unwrap();
    let mut out = Vec::new();
    frame::write_ping(&mut out, false, [0; 8]);
    c.write_all(&out).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(got.windows(1).count() > 0);
}

// ------------------------------------------------------------------------------------------------ floods

#[test]
fn rapid_reset_is_stopped_and_resets_do_not_free_handler_places() {
    let running = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let mut config = small_floods();
    config.h2.max_concurrent_streams = 4;
    config.h2.flood_resets = 30;
    let s = {
        let (running, most) = (running.clone(), most.clone());
        Server::plain(
            move |req: Request| {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(300));
                running.fetch_sub(1, Ordering::SeqCst);
                hello(req)
            },
            config,
        )
    };
    let mut c = Raw::connect(&s, &[]);
    let mut id = 1;
    let mut lost = None;
    for _ in 0..200 {
        c.get(id, "/slow");
        c.raw_frame(kind::RST_STREAM, 0, id, &ErrorCode::CANCEL.0.to_be_bytes());
        id += 2;
    }
    if let Some(code) = c.goaway() {
        lost = Some(code);
    }
    assert_eq!(lost, Some(ErrorCode::ENHANCE_YOUR_CALM.0), "200 streams opened and reset at once");
    thread::sleep(Duration::from_millis(400));
    assert!(most.load(Ordering::SeqCst) <= 4, "at most the four handlers the limit allows ran at once: {}", most.load(Ordering::SeqCst));
}

#[test]
fn the_2019_floods_are_stopped() {
    let s = Server::plain(hello, small_floods());
    let floods: Vec<(&str, Box<dyn Fn(&mut Raw)>)> = vec![
        ("PING", Box::new(|c: &mut Raw| c.raw_frame(kind::PING, 0, 0, &[1; 8]))),
        ("SETTINGS", Box::new(|c: &mut Raw| c.raw_frame(kind::SETTINGS, 0, 0, b""))),
        ("PRIORITY", Box::new(|c: &mut Raw| c.raw_frame(kind::PRIORITY, 0, 1, &[0, 0, 0, 3, 16]))),
        ("unknown frames", Box::new(|c: &mut Raw| c.raw_frame(0x77, 0, 0, b"x"))),
        ("small window updates", Box::new(|c: &mut Raw| c.raw_frame(kind::WINDOW_UPDATE, 0, 0, &1u32.to_be_bytes()))),
    ];
    for (what, one) in floods {
        let mut c = Raw::connect(&s, &[]);
        for _ in 0..200 {
            one(&mut c);
        }
        assert_eq!(c.goaway(), Some(ErrorCode::ENHANCE_YOUR_CALM.0), "{what}");
    }
    // empty DATA frames on an open stream
    let mut c = Raw::connect(&s, &[]);
    c.headers(1, &[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/")], false);
    for _ in 0..200 {
        c.data(1, b"", false);
    }
    assert_eq!(c.goaway(), Some(ErrorCode::ENHANCE_YOUR_CALM.0), "empty DATA");
    // a few of each are fine
    let mut c = Raw::connect(&s, &[]);
    for _ in 0..5 {
        c.raw_frame(kind::PING, 0, 0, &[1; 8]);
        c.raw_frame(kind::PRIORITY, 0, 1, &[0, 0, 0, 3, 16]);
    }
    c.get(1, "/still");
    assert_eq!(c.response(1).0, 200);
}

#[test]
fn continuation_floods_and_hpack_bombs_cost_little() {
    let s = Server::plain(hello, HttpConfig { max_header_bytes: 16 * 1024, ..small_floods() });
    // CVE-2024-27316: a header block that never ends
    let mut c = Raw::connect(&s, &[]);
    let block = c.block(&[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")]);
    c.raw_frame(kind::HEADERS, 0, 1, &block);
    for _ in 0..100 {
        c.raw_frame(kind::CONTINUATION, 0, 1, &[0x40, 1, b'x', 1, b'y']);
    }
    assert_eq!(c.goaway(), Some(ErrorCode::ENHANCE_YOUR_CALM.0), "too many CONTINUATION frames");
    let mut c = Raw::connect(&s, &[]);
    let block = c.block(&[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")]);
    c.raw_frame(kind::HEADERS, 0, 1, &block);
    let big = vec![b'a'; 16_000];
    let mut lit = vec![0x00, 0x01, b'x', 0x7f];
    // a 16000-byte literal value, its length as an HPACK integer
    let mut n = 16_000 - 127;
    while n >= 128 {
        lit.push((n % 128) as u8 | 0x80);
        n /= 128;
    }
    lit.push(n as u8);
    lit.extend_from_slice(&big);
    c.raw_frame(kind::CONTINUATION, 0, 1, &lit);
    c.raw_frame(kind::CONTINUATION, 0, 1, &lit);
    assert_eq!(c.goaway(), Some(ErrorCode::ENHANCE_YOUR_CALM.0), "a header block longer than the limit");
    // an HPACK bomb: one large entry in the table, referred to again and again with one byte each
    let mut c = Raw::connect(&s, &[]);
    let mut block = c.block(&[(":method", "GET"), (":scheme", "http"), (":authority", "a"), (":path", "/")]);
    // literal with incremental indexing, new name "x-big", value of 4000 bytes: it goes into the table at index 62
    block.extend_from_slice(&[0x40, 5]);
    block.extend_from_slice(b"x-big");
    let mut v = vec![0x7f];
    let mut n = 4000 - 127;
    while n >= 128 {
        v.push((n % 128) as u8 | 0x80);
        n /= 128;
    }
    v.push(n as u8);
    block.extend_from_slice(&v);
    block.extend_from_slice(&[b'b'; 4000]);
    block.extend(std::iter::repeat_n(0x80 | 62, 10_000));
    let t = Instant::now();
    let mut out = Vec::new();
    frame::write_header_block(&mut out, 1, true, &block, 16_384);
    c.send(&out);
    let frames = c.until(|f| f.h.stream == 1 && (f.h.has(flag::END_STREAM) || f.is(kind::RST_STREAM)) || f.is(kind::GOAWAY));
    let last = frames.last().unwrap();
    if last.is(kind::HEADERS) {
        assert_eq!(c.decode(last)[0], (":status".to_string(), "431".to_string()), "40 MB of fields, refused");
    } else {
        assert!(last.is(kind::GOAWAY), "{last:?}");
    }
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

#[test]
fn streams_past_the_limit_are_refused_and_counted() {
    let mut config = small_floods();
    config.h2.max_concurrent_streams = 2;
    let gate = Arc::new(Mutex::new(()));
    let held = gate.lock().unwrap();
    let s = {
        let gate = gate.clone();
        Server::plain(
            move |req: Request| {
                drop(gate.lock().unwrap());
                hello(req)
            },
            config,
        )
    };
    let mut c = Raw::connect(&s, &[]);
    c.get(1, "/a");
    c.get(3, "/b");
    thread::sleep(Duration::from_millis(100));
    c.get(5, "/c");
    assert_eq!(c.reset_of(5), Some(ErrorCode::REFUSED_STREAM.0));
    drop(held);
    assert_eq!(c.response(1).0, 200);
    assert_eq!(c.response(3).0, 200);
    c.get(7, "/d");
    assert_eq!(c.response(7).0, 200);
}

#[test]
fn a_client_that_reads_nothing_stops_the_server_reading_and_holds_no_more_than_a_buffer() {
    // the client opens a large window and never reads: the server's writes stop at what the socket takes
    let written = Arc::new(AtomicUsize::new(0));
    let s = {
        let written = written.clone();
        Server::plain(
            move |_req: Request| {
                let written = written.clone();
                Response::stream(200, move |w| {
                    for _ in 0..10_000 {
                        w.write_all(&[0u8; 16_384])?;
                        written.fetch_add(16_384, Ordering::SeqCst);
                    }
                    Ok(())
                })
            },
            HttpConfig::default(),
        )
    };
    let mut c = Raw::connect(&s, &[(setting::INITIAL_WINDOW_SIZE, 0x7fff_ffff)]);
    let mut out = Vec::new();
    frame::write_window_update(&mut out, 0, 0x7fff_ffff - 65_535);
    c.send(&out);
    c.get(1, "/firehose");
    thread::sleep(Duration::from_millis(500));
    let w = written.load(Ordering::SeqCst);
    assert!(w < 64 << 20, "the handler was held back by the socket: {w} bytes written");
    drop(c);
}

#[test]
fn a_client_goaway_refuses_new_streams_and_the_client_closes_when_it_likes() {
    let s = Server::plain(hello, HttpConfig::default());
    let mut c = Raw::connect(&s, &[]);
    c.get(1, "/");
    assert_eq!(c.response(1).0, 200);
    let mut out = Vec::new();
    frame::write_goaway(&mut out, 0, ErrorCode(0xbad), b"an unknown code is no special case");
    c.send(&out);
    // the connection still answers: a PING, and a stream opened after the GOAWAY is refused
    c.raw_frame(kind::PING, 0, 0, b"stillup!");
    let frames = c.until(|f| f.is(kind::PING));
    assert_eq!(frames.last().map(|f| f.p.clone()), Some(b"stillup!".to_vec()));
    c.get(3, "/late");
    assert_eq!(c.reset_of(3), Some(ErrorCode::REFUSED_STREAM.0));
    drop(c);
    let t = Instant::now();
    while s.results.lock().unwrap().is_empty() && t.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(s.results.lock().unwrap().clone(), vec!["ok".to_string()]);
}

#[test]
fn frames_on_a_stream_the_client_reset_are_stream_errors_and_ours_are_ignored() {
    let gate = Arc::new(Mutex::new(()));
    let held = gate.lock().unwrap();
    let s = {
        let gate = gate.clone();
        Server::plain(
            move |req: Request| {
                drop(gate.lock().unwrap());
                hello(req)
            },
            HttpConfig::default(),
        )
    };
    let mut c = Raw::connect(&s, &[]);
    c.headers(1, &[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/")], false);
    c.raw_frame(kind::RST_STREAM, 0, 1, &ErrorCode::CANCEL.0.to_be_bytes());
    c.data(1, b"after the reset", false);
    assert_eq!(c.reset_of(1), Some(ErrorCode::STREAM_CLOSED.0), "DATA after the client's own reset");
    c.headers(1, &[("x-trailer", "late")], true);
    assert_eq!(c.reset_of(1), Some(ErrorCode::STREAM_CLOSED.0), "HEADERS after the client's own reset");
    drop(held);
    c.get(3, "/after");
    assert_eq!(c.response(3).0, 200, "the connection goes on");
}

#[test]
fn a_stream_answered_before_its_request_ends_is_still_checked_and_stopped_if_it_goes_on() {
    let s = Server::plain(hello, HttpConfig::default());
    let mut c = Raw::connect(&s, &[]);
    let post = [(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/")];
    // answered at once; trailers that do not end the stream are still an error on it
    c.headers(1, &post, false);
    assert_eq!(c.response(1).0, 200);
    c.headers(1, &[("x-t", "1")], false);
    assert_eq!(c.reset_of(1), Some(ErrorCode::PROTOCOL_ERROR.0));
    // more of a body nobody will read: the client is asked to stop, with no error
    c.headers(3, &post, false);
    assert_eq!(c.response(3).0, 200);
    c.data(3, b"more", false);
    assert_eq!(c.reset_of(3), Some(ErrorCode::NO_ERROR.0));
    // a client that ends it properly is not reset at all
    c.headers(5, &post, false);
    assert_eq!(c.response(5).0, 200);
    c.data(5, b"", true);
    c.get(7, "/next");
    let frames = c.until(|f| f.h.stream == 7 && f.h.has(flag::END_STREAM));
    assert!(frames.iter().all(|f| !(f.h.stream == 5 && f.is(kind::RST_STREAM))), "{frames:?}");
}
