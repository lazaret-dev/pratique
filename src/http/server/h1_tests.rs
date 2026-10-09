//! HTTP/1.1: what the server refuses (the request-smuggling cases of published research, and the rest of RFC 9112's
//! musts), and what it does with what it takes (keep-alive, pipelining, bodies both ways, 100-continue, upgrades).

use super::h1::{check, chunk_size, field_line, request_line};
use super::test_util::{responses, Server};
use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// A handler that says what it got: method, target, authority and the body (its length and the body itself).
fn echo(mut req: Request) -> Response {
    let body = req.read_body(1 << 24);
    let trailers: Vec<String> = req.body().trailers().iter().map(|(n, v)| format!("{n}={v}")).collect();
    match body {
        Ok(b) => Response::text(200, format!("{} {} {} {} {}|{}", req.method(), req.target(), req.authority(), b.len(), String::from_utf8_lossy(&b), trailers.join(","))),
        Err(e) => Response::text(400, format!("body: {e}")),
    }
}

fn statuses(server: &Server, raw: &str) -> Vec<u16> {
    responses(&server.exchange(raw.as_bytes()), &[]).iter().map(|r| r.status).collect()
}

// ------------------------------------------------------------------------------------------------ the parts

#[test]
fn request_lines_are_three_parts_and_nothing_else() {
    let ok = |l: &str| request_line(l.as_bytes()).map(|(m, t, v)| format!("{m} {t} {v}")).map_err(|b| b.status);
    assert_eq!(ok("GET / HTTP/1.1"), Ok("GET / HTTP/1.1".into()));
    assert_eq!(ok("POST /a?b=c HTTP/1.0"), Ok("POST /a?b=c HTTP/1.0".into()));
    assert_eq!(ok("GET / HTTP/1.2"), Ok("GET / HTTP/1.1".into()), "a later 1.x is answered as 1.1");
    for (line, status) in [
        ("GET  / HTTP/1.1", 400),
        ("GET / HTTP/1.1 ", 400),
        ("GET\t/ HTTP/1.1", 400),
        ("GET / http/1.1", 400),
        ("GET / HTTP/1.1x", 400),
        ("GET /\x7f HTTP/1.1", 400),
        ("GET /é HTTP/1.1", 400),
        ("G(T / HTTP/1.1", 400),
        ("GET / HTTP/2.0", 505),
        ("GET / HTTP/0.9", 505),
        ("GET /", 400),
        ("", 400),
    ] {
        assert_eq!(ok(line), Err(status), "{line:?}");
    }
}

#[test]
fn field_lines_are_a_name_a_colon_and_a_clean_value() {
    let f = |l: &[u8]| field_line(l).map_err(|b| b.why);
    assert_eq!(f(b"Host: example.com").unwrap(), ("host".into(), "example.com".into()));
    assert_eq!(f(b"X-A:\t a b \t").unwrap(), ("x-a".into(), "a b".into()));
    assert_eq!(f(b"X-Empty:").unwrap(), ("x-empty".into(), "".into()));
    assert_eq!(f("X-U: caf\u{e9}".as_bytes()).unwrap().1, "caf\u{e9}");
    for (line, why) in [
        (&b" folded: x"[..], "obsolete line folding"),
        (b"\tfolded: x", "obsolete line folding"),
        (b"Transfer-Encoding : chunked", "followed by something other than a colon"),
        (b"Transfer-Encoding\t: chunked", "followed by something other than a colon"),
        (b": x", "without a name"),
        (b"X-A: a\x00b", "control character"),
        (b"X-A: a\x7fb", "control character"),
        (b"X-A: a\x0bb", "control character"),
        (b"X-A: \xff", "not UTF-8"),
        (b"X(A): b", "followed by something other than a colon"),
    ] {
        let e = f(line).unwrap_err();
        assert!(e.contains(why), "{:?}: {e}", String::from_utf8_lossy(line));
    }
}

#[test]
fn chunk_sizes_are_plain_hexadecimal_and_extensions_well_formed() {
    assert_eq!(chunk_size(b"0"), Ok(0));
    assert_eq!(chunk_size(b"1A"), Ok(26));
    assert_eq!(chunk_size(b"ffffffffffffffff"), Ok(u64::MAX));
    assert_eq!(chunk_size(b"5;name"), Ok(5));
    assert_eq!(chunk_size(b"5 ; name = value ; other=\"a \\\" b\""), Ok(5));
    for line in [&b"0x5"[..], b"-5", b" 5", b"+5", b"5 ", b"5;", b"5;=x", b"5;a=", b"5;a=\"x", b"5;a=\"x\x01\"", b"5\tx", b"10000000000000000", b"5;a b", b"", b"g"] {
        assert!(chunk_size(line).is_err(), "{:?}", String::from_utf8_lossy(line));
    }
}

/// The framing cases of the HTTP request smuggling research (Linhart et al. 2005; Kettle, "HTTP Desync Attacks", 2019,
/// and "HTTP/1.1 must die", 2025; the HTTP Garden; "funky chunks", 2025): each is refused, with the status RFC 9112 asks
/// for, before any handler sees it.
#[test]
fn every_ambiguous_framing_is_refused() {
    let config = HttpConfig::default();
    let h = |extra: &[(&str, &str)], version: Version| {
        let mut headers = vec![("host".to_string(), "example.com".to_string())];
        headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.to_string())));
        check("POST".into(), "/".into(), version, headers, &config).map(|c| c.method).map_err(|b| b.status)
    };
    use Version::*;
    for (fields, version, status) in [
        (&[("content-length", "6"), ("transfer-encoding", "chunked")][..], Http11, 400),
        (&[("transfer-encoding", "chunked"), ("content-length", "6")], Http11, 400),
        (&[("transfer-encoding", "chunked"), ("transfer-encoding", "x")], Http11, 400),
        (&[("transfer-encoding", "xchunked")], Http11, 400),
        (&[("transfer-encoding", "chunked, chunked")], Http11, 400),
        (&[("transfer-encoding", "chunked, identity")], Http11, 400),
        (&[("transfer-encoding", "\"chunked\"")], Http11, 400),
        (&[("transfer-encoding", ",chunked")], Http11, 400),
        (&[("transfer-encoding", "chunked,")], Http11, 400),
        (&[("transfer-encoding", "identity")], Http11, 400),
        (&[("transfer-encoding", "")], Http11, 400),
        (&[("transfer-encoding", "gzip, chunked")], Http11, 501),
        (&[("transfer-encoding", "chunked")], Http10, 400),
        (&[("content-length", "5"), ("content-length", "5")], Http11, 400),
        (&[("content-length", "5, 5")], Http11, 400),
        (&[("content-length", "+5")], Http11, 400),
        (&[("content-length", "-1")], Http11, 400),
        (&[("content-length", "0x5")], Http11, 400),
        (&[("content-length", "5 5")], Http11, 400),
        (&[("content-length", "1e3")], Http11, 400),
        (&[("content-length", "")], Http11, 400),
        (&[("content-length", "1234567890123456789")], Http11, 400),
        (&[("content-length", "100000000000")], Http11, 413),
        (&[("expect", "200-ok")], Http11, 417),
    ] {
        assert_eq!(h(fields, version), Err(status), "{fields:?} {version}");
    }
    for (fields, version) in [
        (&[("transfer-encoding", "chunked")][..], Http11),
        (&[("transfer-encoding", "Chunked")], Http11),
        (&[("transfer-encoding", " chunked\t")], Http11),
        (&[("content-length", "007")], Http11),
        (&[("content-length", "5")], Http10),
        (&[("expect", "100-Continue")], Http11),
        (&[("expect", "anything")], Http10),
    ] {
        assert!(h(fields, version).is_ok(), "{fields:?} {version}");
    }
}

#[test]
fn targets_and_hosts_are_checked() {
    let config = HttpConfig::default();
    let c = |method: &str, target: &str, hosts: &[&str], version: Version| {
        let headers = hosts.iter().map(|h| ("host".to_string(), h.to_string())).collect();
        check(method.into(), target.into(), version, headers, &config).map(|c| c.authority).map_err(|b| b.status)
    };
    use Version::*;
    assert_eq!(c("GET", "/a", &["example.com:8080"], Http11), Ok("example.com:8080".into()));
    assert_eq!(c("GET", "http://other.example/x", &["example.com"], Http11), Ok("other.example".into()), "a URL's authority, not Host's");
    assert_eq!(c("GET", "https://user@other.example:8443?q", &["example.com"], Http11), Ok("other.example:8443".into()));
    assert_eq!(c("CONNECT", "example.com:443", &["example.com:443"], Http11), Ok("example.com:443".into()));
    assert_eq!(c("CONNECT", "[2001:db8::1]:443", &["x"], Http11), Ok("[2001:db8::1]:443".into()));
    assert_eq!(c("OPTIONS", "*", &["example.com"], Http11), Ok("example.com".into()));
    assert_eq!(c("GET", "/", &[], Http10), Ok("".into()), "HTTP/1.0 needs no Host");
    for (method, target, hosts) in [
        ("GET", "/", &[][..]),
        ("GET", "/", &["a.example", "b.example"]),
        ("GET", "/", &["a.example/b"]),
        ("GET", "/", &["a example"]),
        ("GET", "/", &["a@b"]),
        ("GET", "/#frag", &["a"]),
        ("GET", "*", &["a"]),
        ("GET", "a/b", &["a"]),
        ("GET", "ftp://a/b", &["a"]),
        ("GET", "http:///x", &["a"]),
        ("CONNECT", "example.com", &["a"]),
        ("CONNECT", "/x", &["a"]),
        ("CONNECT", "example.com:", &["a"]),
        ("CONNECT", ":443", &["a"]),
    ] {
        assert_eq!(c(method, target, hosts, Http11), Err(400), "{method} {target} {hosts:?}");
    }
}

// ------------------------------------------------------------------------------------------------ on the wire

#[test]
fn smuggling_attempts_on_the_wire_get_one_refusal_and_the_connection_closes() {
    let seen = Arc::new(AtomicUsize::new(0));
    let s = {
        let seen = seen.clone();
        Server::plain(
            move |req: Request| {
                seen.fetch_add(1, Ordering::SeqCst);
                echo(req)
            },
            HttpConfig::default(),
        )
    };
    // each: what follows the refused request would be a second request to a server that framed it differently
    let smuggled = "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n";
    for (raw, status) in [
        (format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nX: y\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nX: y\rTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nX: y\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 30\r\n\r\nhello{smuggled}"), 400),
        (format!("POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"), 400),
        (format!("GET / HTTP/1.1\nHost: x\n\n{smuggled}"), 400),
    ] {
        let before = seen.load(Ordering::SeqCst);
        assert_eq!(statuses(&s, &raw), vec![status], "{raw:?}");
        assert_eq!(seen.load(Ordering::SeqCst), before, "no handler saw it: {raw:?}");
    }
    // bodies that go wrong in the middle: the handler sees an error, the client its answer, and the connection closes
    for raw in [
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n{smuggled}"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n{smuggled}"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;a=\"b\nc\"\r\nhello\r\n0\r\n\r\n{smuggled}"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n{smuggled}"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\nhello\r\n0\r\n\r\n{smuggled}"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\nZ: w\r\n\r\n{smuggled}"),
    ] {
        let rs = responses(&s.exchange(raw.as_bytes()), &[]);
        assert_eq!(rs.len(), 1, "{raw:?}: {rs:?}");
        assert_eq!(rs[0].status, 400, "{raw:?}");
        assert!(rs[0].text().starts_with("body: "), "{raw:?}: {}", rs[0].text());
    }
}

#[test]
fn keep_alive_and_pipelining_answer_in_order_on_one_connection() {
    let s = Server::plain(echo, HttpConfig::default());
    let raw = "GET /one HTTP/1.1\r\nHost: a\r\n\r\n\
               POST /two HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello\
               POST /three HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT-One: 1\r\nT-Two: 2\r\n\r\n\
               \r\nGET /four HTTP/1.1\r\nHost: a\r\n\r\n";
    let rs = responses(&s.exchange(raw.as_bytes()), &[]);
    let texts: Vec<String> = rs.iter().map(|r| r.text()).collect();
    assert_eq!(texts, ["GET /one a 0 |", "POST /two a 5 hello|", "POST /three a 5 abcde|t-one=1,t-two=2", "GET /four a 0 |"]);
    assert!(rs.iter().all(|r| r.header("connection").is_none() && r.header("date").is_some()));
    assert_eq!(s.connections.load(Ordering::SeqCst), 1);
    // HTTP/1.0 closes unless asked not to; Connection: close is honoured
    let rs = responses(&s.exchange(b"GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.0\r\n\r\n"), &[]);
    assert_eq!((rs.len(), rs[0].header("connection")), (1, Some("close")));
    let rs = responses(&s.exchange(b"GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.0\r\n\r\n"), &[]);
    assert_eq!((rs.len(), rs[0].header("connection"), rs[1].header("connection")), (2, Some("keep-alive"), Some("close")));
    let rs = responses(&s.exchange(b"GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n"), &[]);
    assert_eq!((rs.len(), rs[0].header("connection")), (1, Some("close")));
}

#[test]
fn a_head_arriving_a_byte_at_a_time_is_read_as_one() {
    let s = Server::plain(echo, HttpConfig::default());
    let mut c = s.connect();
    for b in b"POST /drip HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nxyz" {
        c.write_all(&[*b]).unwrap();
        thread::sleep(Duration::from_micros(200));
    }
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).unwrap();
    assert_eq!(responses(&out, &[])[0].text(), "POST /drip a 3 xyz|");
}

#[test]
fn limits_on_the_head_and_the_body_have_their_statuses() {
    let config = HttpConfig { max_request_line: 100, max_header_bytes: 200, max_headers: 5, max_body: Some(10), ..HttpConfig::default() };
    let calls = Arc::new(AtomicUsize::new(0));
    let s = {
        let calls = calls.clone();
        Server::plain(
            move |req: Request| {
                calls.fetch_add(1, Ordering::SeqCst);
                echo(req)
            },
            config,
        )
    };
    let long = "a".repeat(120);
    assert_eq!(statuses(&s, &format!("GET /{long} HTTP/1.1\r\nHost: a\r\n\r\n")), [414]);
    assert_eq!(statuses(&s, &format!("GET / HTTP/1.1\r\nHost: a\r\nX: {long}{long}\r\n\r\n")), [431]);
    assert_eq!(statuses(&s, "GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\n\r\n"), [431]);
    assert_eq!(statuses(&s, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nhello world"), [413]);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // a chunked body that grows past the limit fails to read
    let rs = responses(&s.exchange(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n"), &[]);
    assert_eq!((rs[0].status, rs[0].text().contains("larger than this server takes")), (400, true));
    // the request after a limited one is never read
    assert_eq!(statuses(&s, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n0123456789GET / HTTP/1.1\r\nHost: a\r\n\r\n"), [200, 200]);
}

#[test]
fn responses_are_framed_by_what_the_server_knows_of_their_length() {
    let s = Server::plain(
        |req: Request| match req.path() {
            "/bytes" => Response::bytes(200, "application/octet-stream", vec![7; 100_000]),
            "/reader" => Response::reader(200, std::io::Cursor::new(vec![1u8; 70_000]), None),
            "/sized" => Response::reader(200, std::io::Cursor::new(vec![2u8; 70_000]), Some(50_000)),
            "/short" => Response::reader(200, std::io::Cursor::new(vec![2u8; 10]), Some(50)),
            "/stream" => Response::stream(200, |w| {
                for i in 0..100u8 {
                    w.write_all(&[i; 1000])?;
                }
                w.set_trailers(vec![("x-checksum".into(), "abc".into())]);
                Ok(())
            }),
            "/nothing" => Response::new(204).with_header("content-length", "99"),
            "/notmod" => Response::new(304).with_header("content-length", "1234"),
            "/head" => Response::new(200).with_header("content-length", "42"),
            _ => Response::text(404, "no\n"),
        },
        HttpConfig::default(),
    );
    let get = |path: &str| responses(&s.exchange(format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes()), &[]).remove(0);
    let r = get("/bytes");
    assert_eq!((r.body.len(), r.header("content-length"), r.chunked), (100_000, Some("100000"), false));
    let r = get("/reader");
    assert_eq!((r.body.len(), r.chunked), (70_000, true));
    let r = get("/sized");
    assert_eq!((r.body.len(), r.header("content-length")), (50_000, Some("50000")));
    let r = get("/stream");
    assert_eq!((r.body.len(), r.chunked, r.trailers.clone()), (100_000, true, vec![("x-checksum".to_string(), "abc".to_string())]));
    assert_eq!(r.body[99_999], 99);
    let r = get("/nothing");
    assert_eq!((r.status, r.header("content-length"), r.body.len()), (204, None, 0));
    let r = get("/notmod");
    assert_eq!((r.status, r.header("content-length")), (304, Some("1234")));
    // a reader shorter than its length: the body is cut and the connection closed, so the client sees it is short
    let out = s.exchange(b"GET /short HTTP/1.1\r\nHost: a\r\n\r\nGET /bytes HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(responses(&out, &[]).is_empty(), "the cut response is not a whole one");
    assert!(out.len() < 200);
    // HEAD: the length it would have, no body; the next response on the connection is whole
    let raw = "HEAD /bytes HTTP/1.1\r\nHost: a\r\n\r\nHEAD /stream HTTP/1.1\r\nHost: a\r\n\r\nHEAD /head HTTP/1.1\r\nHost: a\r\n\r\nGET /sized HTTP/1.1\r\nHost: a\r\n\r\n";
    let rs = responses(&s.exchange(raw.as_bytes()), &[true, true, true, false]);
    assert_eq!(rs.len(), 4);
    assert_eq!((rs[0].header("content-length"), rs[0].body.len()), (Some("100000"), 0));
    assert_eq!((rs[1].header("content-length"), rs[1].header("transfer-encoding")), (None, None));
    assert_eq!(rs[2].header("content-length"), Some("42"));
    assert_eq!(rs[3].body.len(), 50_000);
    // HTTP/1.0 gets no chunks: the body runs to the close
    let out = s.exchange(b"GET /stream HTTP/1.0\r\n\r\n");
    let r = responses(&out, &[]).remove(0);
    assert_eq!((r.body.len(), r.chunked, r.header("connection")), (100_000, false, Some("close")));
}

#[test]
fn bodies_are_streamed_both_ways_at_once() {
    // the response reads the request body as it goes, a chunk at a time
    let s = Server::plain(|req: Request| Response::reader(200, req.into_body(), None), HttpConfig::default());
    let mut c = s.connect();
    c.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 65536];
    for i in 0..20u8 {
        let piece = vec![i; 10_000];
        c.write_all(format!("{:x}\r\n", piece.len()).as_bytes()).unwrap();
        c.write_all(&piece).unwrap();
        c.write_all(b"\r\n").unwrap();
        // the server answers as the body comes: the echo of what was sent arrives before the body ends
        while got.len() < 60 + (i as usize) * 10_000 {
            let n = c.read(&mut buf).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
    }
    c.write_all(b"0\r\n\r\n").unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    c.read_to_end(&mut got).unwrap();
    let r = responses(&got, &[]).remove(0);
    assert_eq!(r.body.len(), 200_000);
    assert_eq!(r.body[199_999], 19);
}

#[test]
fn hundred_continue_is_sent_when_the_body_is_read_and_not_otherwise() {
    let s = Server::plain(
        |mut req: Request| {
            if req.path() == "/refuse" {
                return Response::text(401, "who are you\n");
            }
            let n = req.read_body(1 << 20).unwrap().len();
            Response::text(200, format!("{n}"))
        },
        HttpConfig::default(),
    );
    let head = |path: &str| format!("POST {path} HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
    // the client waits for the go-ahead before it sends the body
    let mut c = s.connect();
    c.write_all(head("/take").as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    let n = c.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    c.write_all(b"hello").unwrap();
    let n = c.read(&mut buf).unwrap();
    let r = responses(&buf[..n], &[]).remove(0);
    assert_eq!((r.status, r.text()), (200, "5".into()));
    // a handler that answers without the body: no 100, and the connection closes (the body may or may not come)
    let mut c = s.connect();
    c.write_all(head("/refuse").as_bytes()).unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).unwrap();
    let rs = responses(&out, &[]);
    assert_eq!((rs.len(), rs[0].status, rs[0].header("connection")), (1, 401, Some("close")));
    assert!(!String::from_utf8_lossy(&out).contains("100 Continue"));
}

#[test]
fn a_body_the_handler_leaves_is_read_past_if_it_is_small_and_closes_the_connection_if_not() {
    let config = HttpConfig { drain_limit: 1000, ..HttpConfig::default() };
    let s = Server::plain(|_req: Request| Response::text(200, "ignored your body\n"), config);
    let small = format!("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 500\r\n\r\n{}GET /b HTTP/1.1\r\nHost: a\r\n\r\n", "x".repeat(500));
    assert_eq!(statuses(&s, &small), [200, 200]);
    let large = format!("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n{}GET /b HTTP/1.1\r\nHost: a\r\n\r\n", "x".repeat(5000));
    assert_eq!(statuses(&s, &large), [200]);
}

#[test]
fn a_bad_handler_gets_the_client_a_500_and_the_connection_closed() {
    let s = Server::plain(
        |req: Request| match req.path() {
            "/panic" => panic!("the handler fails"),
            "/badheader" => Response::text(200, "x").with_header("x-evil", "a\r\nset-cookie: b"),
            "/badname" => Response::text(200, "x").with_header("x evil", "a"),
            "/interim" => Response::new(103),
            "/upgrade-without" => Response::upgrade(200, |_| {}),
            _ => Response::text(200, "fine"),
        },
        HttpConfig::default(),
    );
    for path in ["/panic", "/badheader", "/badname", "/interim", "/upgrade-without"] {
        let rs = responses(&s.exchange(format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes()), &[]);
        assert_eq!(rs.len(), 1, "{path}: closed after the 500");
        assert_eq!((rs[0].status, rs[0].header("connection"), rs[0].header("x-evil")), (500, Some("close"), None), "{path}");
    }
}

#[test]
fn a_connection_answers_so_many_requests_and_then_says_close() {
    let s = Server::plain(echo, HttpConfig { max_requests_per_connection: 3, ..HttpConfig::default() });
    let raw = "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n".repeat(5);
    let rs = responses(&s.exchange(raw.as_bytes()), &[]);
    assert_eq!(rs.len(), 3);
    assert_eq!(rs[2].header("connection"), Some("close"));
}

#[test]
fn connect_hands_over_the_connection_with_what_came_after_the_head() {
    let s = Server::plain(
        |req: Request| {
            if req.method() != "CONNECT" {
                return Response::text(405, "only CONNECT\n");
            }
            let target = req.target().to_string();
            Response::upgrade(200, move |mut tunnel| {
                // an echo, upper-cased, that says where it was meant to go first
                let _ = tunnel.write_all(format!("to {target}\n").as_bytes());
                let mut buf = [0u8; 1024];
                while let Ok(n) = tunnel.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let up: Vec<u8> = buf[..n].to_ascii_uppercase();
                    if tunnel.write_all(&up).is_err() {
                        break;
                    }
                }
            })
        },
        HttpConfig::default(),
    );
    let mut c = s.connect();
    // the first bytes for the tunnel come in the same write as the CONNECT
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly ").unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&got).contains("EARLY ") {
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0, "{:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    c.write_all(b"later").unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    c.read_to_end(&mut got).unwrap();
    let text = String::from_utf8_lossy(&got).into_owned();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n") && !head.to_ascii_lowercase().contains("content-length") && !head.to_ascii_lowercase().contains("transfer-encoding"), "{head}");
    assert_eq!(rest, "to example.com:443\nEARLY LATER");
    // a refused CONNECT closes, so that tunnel bytes sent too early are never read as a request
    let rs = responses(&s.exchange(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), &[]);
    assert_eq!(rs[0].status, 405);
}

#[test]
fn switching_protocols_hands_over_the_connection_after_the_101() {
    let s = Server::plain(
        |req: Request| {
            if req.header("upgrade") != Some("echo") {
                return Response::text(426, "upgrade to echo\n");
            }
            Response::upgrade(101, |mut io| {
                let mut buf = [0u8; 64];
                let n = io.read(&mut buf).unwrap_or(0);
                let _ = io.write_all(&buf[..n]);
            })
            .with_header("upgrade", "echo")
            .with_header("connection", "upgrade")
        },
        HttpConfig::default(),
    );
    let out = s.exchange(b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: echo\r\nConnection: upgrade\r\n\r\nping");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{text}");
    assert!(text.to_ascii_lowercase().contains("upgrade: echo"), "{text}");
    assert!(text.ends_with("\r\n\r\nping"), "{text}");
}

#[test]
fn a_body_kept_past_its_request_reads_nothing_more() {
    let kept: Arc<std::sync::Mutex<Option<Body>>> = Arc::new(std::sync::Mutex::new(None));
    let s = {
        let kept = kept.clone();
        Server::plain(
            move |req: Request| {
                if req.path() == "/keep" {
                    *kept.lock().unwrap() = Some(req.into_body());
                    return Response::text(200, "kept\n");
                }
                echo(req)
            },
            HttpConfig::default(),
        )
    };
    let raw = "POST /keep HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcPOST /next HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nxyz";
    let t = std::time::Instant::now();
    let rs = responses(&s.exchange(raw.as_bytes()), &[]);
    assert!(t.elapsed() < Duration::from_secs(2), "the kept body did not keep the connection open: {:?}", t.elapsed());
    assert_eq!(rs[1].text(), "POST /next a 3 xyz|");
    let mut body = kept.lock().unwrap().take().unwrap();
    let mut buf = [0u8; 8];
    assert!(body.read(&mut buf).is_err(), "the next request's body is not this one's");
}

#[test]
fn the_tls_connection_carries_http1_when_alpn_says_so() {
    let s = Server::tls(echo, HttpConfig::default(), &["http/1.1"]);
    let client = s.client();
    let r = client.post(&s.url("/over-tls"), b"secret".to_vec()).unwrap();
    assert_eq!(r.text(), format!("POST /over-tls 127.0.0.1:{} 6 secret|", s.addr.port()));
    assert_eq!(r.version, crate::http::HttpVersion::Http11);
    for i in 0..5 {
        assert_eq!(client.get(&s.url(&format!("/{i}"))).unwrap().status, 200);
    }
    assert_eq!(s.connections.load(Ordering::SeqCst), 1, "kept alive");
}
