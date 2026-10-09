//! Tests of `Content-Encoding` in the clients ([`Client::decompress`]) against the scripted servers: what is asked for, what is
//! decoded and what is left alone, over HTTP/1.1 (whole, streamed, chunked, through a redirect), HTTP/2 and the async client,
//! and what bombs, broken streams and bytes after the stream do to the request and to its connection.

use super::h2_server::response as h2_response;
use super::h2_testserver::H2Server;
use super::testserver::{response, Reply, Seen, TestServer};
use crate::asyncio::block_on;
use crate::error::Error;
use crate::inflate::{adler32, crc32, Error as InflateError};
use std::io::Read;
use std::sync::Arc;

// ------------------------------------------------------------------------------------------------ making compressed bodies

/// Bare DEFLATE in stored blocks: valid, and as long as the data.
fn stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunks = data.chunks(65535).peekable();
    if chunks.peek().is_none() {
        return vec![0x01, 0x00, 0x00, 0xff, 0xff];
    }
    while let Some(c) = chunks.next() {
        out.push(if chunks.peek().is_none() { 1 } else { 0 });
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

fn gzip_of(deflate: &[u8], data: &[u8]) -> Vec<u8> {
    let mut g = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
    g.extend_from_slice(deflate);
    g.extend_from_slice(&crc32(0, data).to_le_bytes());
    g.extend_from_slice(&(data.len() as u32).to_le_bytes());
    g
}

fn gzip(data: &[u8]) -> Vec<u8> {
    gzip_of(&stored(data), data)
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut z = vec![0x78, 0x01];
    z.extend_from_slice(&stored(data));
    z.extend_from_slice(&adler32(1, data).to_be_bytes());
    z
}

/// Bits, least significant first, as DEFLATE packs them.
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, value: u64, n: u32) {
        self.acc |= value << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// A Huffman code, which DEFLATE sends most significant bit first.
    fn code(&mut self, code: u64, len: u32) {
        let reversed = (0..len).fold(0, |r, i| r | ((code >> i) & 1) << (len - 1 - i));
        self.put(reversed, len);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// The classic bomb: `1 + 258 * matches` zeros in one dynamic block whose code gives the length 258 one bit and the distance 1
/// one bit, so that each match of 258 bytes takes two bits: 1,032 to 1, as far as DEFLATE goes.
fn bomb(matches: u64) -> (Vec<u8>, u64) {
    let mut b = Bits { out: Vec::new(), acc: 0, n: 0 };
    b.put(1, 1); // the last block
    b.put(2, 2); // a dynamic code
    b.put(29, 5); // 286 literal/length codes
    b.put(0, 5); // 1 distance code
    b.put(14, 4); // 18 code length codes
    // the lengths of the code length code, in the order of the RFC (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1):
    // 18 gets 1 bit, 1 and 2 get 2 bits (a complete code)
    for len in [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2] {
        b.put(len, 3);
    }
    // canonical codes of that code: 18 is 0, 1 is 10, 2 is 11
    let (c18, c1, c2) = ((0, 1), (0b10, 2), (0b11, 2));
    // literal/length lengths: 0 gets 2, 1 to 255 none, 256 gets 2, 257 to 284 none, 285 gets 1
    b.code(c2.0, c2.1);
    b.code(c18.0, c18.1);
    b.put(138 - 11, 7);
    b.code(c18.0, c18.1);
    b.put(117 - 11, 7);
    b.code(c2.0, c2.1);
    b.code(c18.0, c18.1);
    b.put(28 - 11, 7);
    b.code(c1.0, c1.1);
    // the one distance code, 0 (distance 1), of length 1
    b.code(c1.0, c1.1);
    // the data: literal 0 is 10, length 258 is 0, distance 1 is 0, the end of the block is 11
    b.code(0b10, 2);
    for _ in 0..matches {
        b.code(0, 1);
        b.code(0, 1);
    }
    b.code(0b11, 2);
    (b.finish(), 1 + 258 * matches)
}

fn zeros_crc(n: u64) -> u32 {
    let block = vec![0u8; 1 << 16];
    let (mut crc, mut left) = (0, n);
    while left > 0 {
        let k = left.min(block.len() as u64) as usize;
        crc = crc32(crc, &block[..k]);
        left -= k as u64;
    }
    crc
}

/// A gzip bomb that is valid all the way to its trailer.
fn gzip_bomb(matches: u64) -> (Vec<u8>, u64) {
    let (deflate, n) = bomb(matches);
    let mut g = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
    g.extend_from_slice(&deflate);
    g.extend_from_slice(&zeros_crc(n).to_le_bytes());
    g.extend_from_slice(&(n as u32).to_le_bytes());
    (g, n)
}

const TEXT: &[u8] = b"the same words, again and again: the same words, again and again.\n";

fn text(n: usize) -> Vec<u8> {
    TEXT.iter().copied().cycle().take(n).collect()
}

/// A server that answers every request with `body` and these headers (a Content-Length added).
fn serving(headers: &'static [&'static str], body: Vec<u8>) -> TestServer {
    let body = Arc::new(body);
    TestServer::start(move |_| Reply::Send(response(200, headers, &body)))
}

fn decode_error(e: &Error) -> Option<&InflateError> {
    match e {
        Error::Decode(d) => Some(d),
        _ => None,
    }
}

/// The decode error inside an `io::Error` from a stream's `read`.
fn decode_error_io(e: &std::io::Error) -> Option<InflateError> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<Error>()).and_then(decode_error).cloned()
}

// ------------------------------------------------------------------------------------------------ HTTP/1.1

#[test]
fn off_by_default_the_client_asks_for_identity_and_gets_the_bytes_as_they_came() {
    let data = text(5000);
    let server = serving(&["Content-Encoding: gzip"], gzip(&data));
    let r = server.client().get(&server.url("/")).unwrap();
    assert_eq!(r.body, gzip(&data));
    assert!(!r.uncompressed);
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(server.requests()[0].header("accept-encoding"), Some("identity"));
}

#[test]
fn gzip_and_both_forms_of_deflate_are_decoded_and_the_wire_headers_dropped() {
    let data = text(100_000);
    for (coding, body) in [("gzip", gzip(&data)), ("x-gzip", gzip(&data)), ("GZip", gzip(&data)), ("deflate", zlib(&data)), ("deflate", stored(&data))] {
        let header: &'static str = Box::leak(format!("Content-Encoding: {coding}").into_boxed_str());
        let headers: &'static [&'static str] = Box::leak(vec![header, "Content-Type: text/plain", "Vary: Accept-Encoding"].into_boxed_slice());
        let server = serving(headers, body.clone());
        let client = server.client().decompress(true);
        for _ in 0..2 {
            let r = client.get(&server.url("/")).unwrap();
            assert_eq!(r.body, data, "{coding}");
            assert!(r.uncompressed, "{coding}");
            assert_eq!(r.header("content-encoding"), None, "{coding}");
            assert_eq!(r.header("content-length"), None, "{coding}");
            assert_eq!(r.header("content-type"), Some("text/plain"));
            assert_eq!(r.header("vary"), Some("Accept-Encoding"));
        }
        assert_eq!(server.requests()[0].header("accept-encoding"), Some("gzip, deflate"), "{coding}");
        // a decoded body read to its end leaves its connection fit for the next request
        assert_eq!(server.connections(), 1, "{coding}");
    }
}

#[test]
fn a_streamed_body_is_decoded_as_it_is_read_in_pieces_of_any_size() {
    let data = text(300_000);
    let server = serving(&["Content-Encoding: gzip"], gzip(&data));
    let client = server.client().decompress(true);
    for piece in [1usize, 7, 4096, 1 << 20] {
        let mut s = client.get_stream(&server.url("/")).unwrap();
        assert!(s.uncompressed);
        assert_eq!(s.content_length, None);
        let mut got = Vec::new();
        let mut buf = vec![0u8; piece];
        // (a byte at a time for the first part only: the rest in big reads)
        loop {
            let want = if got.len() < 5000 { piece } else { buf.len().max(65536) };
            if buf.len() < want {
                buf.resize(want, 0);
            }
            match s.read(&mut buf[..want]).unwrap() {
                0 => break,
                n => got.extend_from_slice(&buf[..n]),
            }
        }
        assert_eq!(got, data, "reads of {piece}");
        // and the end stays the end
        assert_eq!(s.read(&mut buf).unwrap(), 0);
    }
    assert_eq!(server.connections(), 1);
    // copy_to decodes too
    let mut s = client.get_stream(&server.url("/")).unwrap();
    let mut sink = Vec::new();
    assert_eq!(s.copy_to(&mut sink).unwrap(), data.len() as u64);
    assert_eq!(sink, data);
}

#[test]
fn a_chunked_body_is_decoded_across_chunks_of_odd_sizes() {
    let data = text(70_000);
    let wire = gzip(&data);
    let wire = Arc::new(wire);
    let server = TestServer::start(move |_| {
        let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        for c in wire.chunks(997) {
            out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        Reply::Send(out)
    });
    let client = server.client().decompress(true);
    assert_eq!(client.get(&server.url("/")).unwrap().body, data);
    assert_eq!(client.get(&server.url("/")).unwrap().body, data);
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_request_can_say_otherwise_than_the_client() {
    let data = text(2000);
    let server = serving(&["Content-Encoding: gzip"], gzip(&data));
    // on for one request of a client that has it off
    let r = server.client().request("GET", &server.url("/a")).decompress(true).send().unwrap();
    assert_eq!((r.body.as_slice(), r.uncompressed), (data.as_slice(), true));
    // off for one request of a client that has it on: it asks for identity and gets what came
    let r = server.client().decompress(true).request("GET", &server.url("/b")).decompress(false).send().unwrap();
    assert_eq!((r.body, r.uncompressed), (gzip(&data), false));
    let seen = server.requests();
    assert_eq!(seen[0].header("accept-encoding"), Some("gzip, deflate"));
    assert_eq!(seen[1].header("accept-encoding"), Some("identity"));
}

#[test]
fn the_callers_accept_encoding_is_sent_as_it_is_and_a_range_does_not_ask() {
    let data = text(2000);
    let server = serving(&["Content-Encoding: gzip"], gzip(&data));
    let client = server.client().decompress(true);
    // the caller's own header goes out unchanged, and a known coding that comes back is decoded all the same
    let r = client.request("GET", &server.url("/own")).header("Accept-Encoding", "br, gzip").send().unwrap();
    assert_eq!(r.body, data);
    // a range is a range of the encoded body: the client asks for identity
    let _ = client.request("GET", &server.url("/range")).header("Range", "bytes=0-99").send().unwrap();
    let seen = server.requests();
    assert_eq!(seen[0].header("accept-encoding"), Some("br, gzip"));
    assert_eq!(seen[1].header("accept-encoding"), Some("identity"));
}

#[test]
fn what_is_not_a_single_known_coding_comes_as_it_is() {
    let data = text(3000);
    for (headers, body) in [
        (&["Content-Encoding: br"][..], b"not brotli at all".to_vec()),
        (&["Content-Encoding: gzip, gzip"][..], gzip(&gzip(&data))),
        (&["Content-Encoding: gzip", "Content-Encoding: deflate"][..], b"two layers".to_vec()),
        (&["Content-Encoding: compress"][..], b"lzw".to_vec()),
    ] {
        let headers: &'static [&'static str] = Box::leak(headers.to_vec().into_boxed_slice());
        let server = serving(headers, body.clone());
        let r = server.client().decompress(true).get(&server.url("/")).unwrap();
        assert_eq!(r.body, body, "{headers:?}");
        assert!(!r.uncompressed);
        assert!(r.header("content-encoding").is_some());
        assert_eq!(r.header("content-length"), Some(body.len().to_string().as_str()));
    }
}

#[test]
fn bodiless_responses_and_ranges_are_not_touched() {
    let server = TestServer::start(|seen: &Seen| {
        let path = seen.path().to_string();
        Reply::Send(match path.as_str() {
            "/204" => b"HTTP/1.1 204 No Content\r\nContent-Encoding: gzip\r\n\r\n".to_vec(),
            "/304" => b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\n\r\n".to_vec(),
            "/206" => response(206, &["Content-Encoding: gzip", "Content-Range: bytes 0-3/40"], b"\x1f\x8b\x08\x00"),
            _ if seen.method() == "HEAD" => format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gzip(b"hello").len()).into_bytes(),
            _ => response(200, &["Content-Encoding: gzip"], &gzip(b"hello")),
        })
    });
    let client = server.client().decompress(true);
    let head = client.head(&server.url("/")).unwrap();
    assert!(head.body.is_empty() && !head.uncompressed);
    assert_eq!(head.header("content-encoding"), Some("gzip"));
    for path in ["/204", "/304"] {
        let r = client.get(&server.url(path)).unwrap();
        assert!(r.body.is_empty() && !r.uncompressed, "{path}");
    }
    let r = client.get(&server.url("/206")).unwrap();
    assert_eq!((r.status, r.body.as_slice(), r.uncompressed), (206, &b"\x1f\x8b\x08\x00"[..], false));
    // and the connection was fine all along
    assert_eq!(client.get(&server.url("/")).unwrap().body, b"hello");
    assert_eq!(server.connections(), 1);
}

#[test]
fn an_empty_body_is_empty_whatever_its_coding_says() {
    let server = serving(&["Content-Encoding: gzip"], Vec::new());
    let client = server.client().decompress(true);
    let r = client.get(&server.url("/")).unwrap();
    assert!(r.body.is_empty() && r.uncompressed);
    let r = client.get(&server.url("/")).unwrap();
    assert!(r.body.is_empty());
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_broken_stream_fails_the_request_and_its_connection_is_not_used_again() {
    let data = text(20_000);
    let good = gzip(&data);
    let mut bad_crc = good.clone();
    let at = bad_crc.len() - 6;
    bad_crc[at] ^= 1;
    let cut = good[..good.len() - 3].to_vec();
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"\0\0");
    let not_gzip = text(100_000);
    // (whether the whole body had arrived when the decoder failed: if it had, its HTTP framing was sound and the connection is
    // as good as any; if not, the rest is never read and the connection is closed)
    for (what, body, want, all_there) in [
        ("a bad CRC", bad_crc, InflateError::Checksum("crc32"), true),
        ("a cut stream", cut, InflateError::Truncated, true),
        ("bytes after the stream", trailing, InflateError::Corrupt(""), true),
        ("text that says it is gzip", not_gzip, InflateError::Corrupt(""), false),
    ] {
        let server = serving(&["Content-Encoding: gzip"], body.clone());
        let client = server.client().decompress(true);
        let e = client.get(&server.url("/")).unwrap_err();
        let got = decode_error(&e).unwrap_or_else(|| panic!("{what}: {e}"));
        match (&want, got) {
            (InflateError::Corrupt(_), InflateError::Corrupt(_)) => {}
            _ => assert_eq!(got, &want, "{what}"),
        }
        assert!(e.to_string().starts_with("response body could not be decoded"), "{what}: {e}");
        // the same through a stream: the error comes from a read, and stays
        let mut s = client.get_stream(&server.url("/")).unwrap();
        let mut sink = Vec::new();
        let e = s.read_to_end(&mut sink).unwrap_err();
        assert!(decode_error_io(&e).is_some(), "{what}: {e}");
        assert!(s.read(&mut [0u8; 16]).is_err(), "{what}: the failure is kept");
        drop(s);
        // a body that failed before it was all there leaves its connection closed, never handed to the next request
        let _ = client.get(&server.url("/"));
        assert_eq!(server.connections(), if all_there { 1 } else { 3 }, "{what}");
    }
}

#[test]
fn a_bomb_stops_at_the_limit_on_the_decoded_size() {
    // 70 MB of zeros in 68 KB
    let (bomb, size) = gzip_bomb(270_000);
    assert!(size > 64 << 20 && bomb.len() < 70_000, "{} bytes for {size}", bomb.len());
    let server = serving(&["Content-Encoding: gzip"], bomb);
    // by default the decoded body is held to the body limit (64 MiB)
    let e = server.client().decompress(true).get(&server.url("/")).unwrap_err();
    assert_eq!(decode_error(&e), Some(&InflateError::OutputLimit { limit: 64 << 20 }), "{e}");
    // a lower limit, whole and streamed: nothing past it is ever handed out
    let client = server.client().decompress(true).max_decoded_bytes(1 << 20);
    let e = client.get(&server.url("/")).unwrap_err();
    assert_eq!(decode_error(&e), Some(&InflateError::OutputLimit { limit: 1 << 20 }));
    let mut s = client.get_stream(&server.url("/")).unwrap();
    let (mut total, mut buf) = (0u64, vec![0u8; 100_000]);
    let e = loop {
        match s.read(&mut buf) {
            Ok(0) => panic!("the bomb ended"),
            Ok(n) => total += n as u64,
            Err(e) => break e,
        }
    };
    assert!(total <= 1 << 20, "{total} bytes were handed out");
    assert_eq!(decode_error_io(&e), Some(InflateError::OutputLimit { limit: 1 << 20 }));
    // the request's own limit, higher, lets it through, all of it
    let r = client.request("GET", &server.url("/")).max_decoded_bytes(size).send().unwrap();
    assert_eq!(r.body.len() as u64, size);
    assert!(r.body.iter().all(|&b| b == 0));
    // and a ratio limit refuses it whatever the size limit says
    let e = server.client().decompress(true).max_decoded_bytes(u64::MAX).max_decode_ratio(100, 1 << 16).get(&server.url("/")).unwrap_err();
    assert!(matches!(decode_error(&e), Some(InflateError::RatioLimit { ratio: 100 })), "{e}");
}

#[test]
fn the_wire_limit_still_holds_for_the_compressed_bytes() {
    let data = text(50_000);
    let server = serving(&["Content-Encoding: gzip"], gzip(&data));
    // the compressed body (stored, so a bit longer than the data) is over the body limit; the decoded one would be under its own
    let e = server.client().decompress(true).max_body_bytes(10_000).max_decoded_bytes(1 << 20).get(&server.url("/")).unwrap_err();
    assert!(decode_error(&e).is_none() && e.to_string().contains("limit"), "{e}");
}

#[test]
fn a_redirect_is_not_decoded_and_the_response_it_leads_to_is() {
    let data = text(9000);
    let server = TestServer::start(move |seen: &Seen| {
        if seen.path() == "/old" {
            Reply::Send(response(302, &["Location: /new", "Content-Encoding: gzip"], b"this is no gzip, and nobody reads it"))
        } else {
            Reply::Send(response(200, &["Content-Encoding: deflate"], &zlib(&text(9000))))
        }
    });
    let r = server.client().decompress(true).get(&server.url("/old")).unwrap();
    assert_eq!(r.body, data);
    assert!(r.uncompressed);
    // both hops asked for it
    assert!(server.requests().iter().all(|s| s.header("accept-encoding") == Some("gzip, deflate")));
    assert_eq!(server.connections(), 1);
}

#[test]
fn an_error_page_is_decoded_like_any_other_body() {
    let server = TestServer::start(|_: &Seen| Reply::Send(response(404, &["Content-Encoding: gzip"], &gzip(b"not found here"))));
    let r = server.client().decompress(true).get(&server.url("/")).unwrap();
    assert_eq!((r.status, r.body.as_slice(), r.uncompressed), (404, &b"not found here"[..], true));
}

#[test]
fn over_tls_too() {
    let data = text(40_000);
    let body = Arc::new(gzip(&data));
    let server = TestServer::start_tls(move |_| Reply::Send(response(200, &["Content-Encoding: gzip"], &body)));
    let client = server.client().decompress(true);
    assert_eq!(client.get(&server.url("/")).unwrap().body, data);
    assert_eq!(client.get(&server.url("/")).unwrap().body, data);
    assert_eq!(server.connections(), 1);
}

// ------------------------------------------------------------------------------------------------ HTTP/2

#[test]
fn over_http2_whole_and_streamed() {
    let data = text(200_000);
    let body = Arc::new(gzip(&data));
    let (bomb, _) = gzip_bomb(40_000);
    let bomb = Arc::new(bomb);
    let length = body.len().to_string();
    let server = H2Server::start(move |seen| match seen.path() {
        "/bomb" => h2_response(200, &[("content-encoding", "gzip")], &bomb),
        "/plain" => h2_response(200, &[("content-encoding", "gzip"), ("content-length", &length)], &body),
        _ => h2_response(200, &[("content-encoding", "gzip")], &body),
    });
    let client = server.client().decompress(true);
    let r = client.get(&server.url("/")).unwrap();
    assert_eq!((r.body.as_slice(), r.uncompressed), (data.as_slice(), true));
    assert_eq!(r.version, super::HttpVersion::Http2);
    let r = client.get(&server.url("/plain")).unwrap();
    assert_eq!(r.body, data);
    assert_eq!(r.header("content-length"), None);
    let mut s = client.get_stream(&server.url("/")).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert_eq!(got, data);
    let e = client.request("GET", &server.url("/bomb")).max_decoded_bytes(1 << 20).send().unwrap_err();
    assert_eq!(decode_error(&e), Some(&InflateError::OutputLimit { limit: 1 << 20 }));
    // the failed stream is given up; the connection goes on serving others
    assert_eq!(client.get(&server.url("/")).unwrap().body, data);
    assert_eq!(server.requests()[0].header("accept-encoding"), Some("gzip, deflate"));
    assert_eq!(server.connections(), 1);
    assert_eq!(server.end_and_complaints(), Vec::<String>::new());
}

// ------------------------------------------------------------------------------------------------ the async client

#[test]
fn the_async_client_decodes_the_same_way() {
    let data = text(120_000);
    let (bomb, _) = gzip_bomb(10_000);
    let (body, bomb) = (Arc::new(gzip(&data)), Arc::new(bomb));
    let server = TestServer::start(move |seen: &Seen| match seen.path() {
        "/bomb" => Reply::Send(response(200, &["Content-Encoding: gzip"], &bomb)),
        "/raw" => Reply::Send(response(200, &["Content-Encoding: br"], b"raw")),
        _ => Reply::Send(response(200, &["Content-Encoding: gzip"], &body)),
    });
    let client = server.client().decompress(true).into_async();
    let r = block_on(client.get(&server.url("/"))).unwrap();
    assert_eq!((r.body.as_slice(), r.uncompressed), (data.as_slice(), true));
    assert_eq!(r.header("content-encoding"), None);
    let mut s = block_on(client.get_stream(&server.url("/"))).unwrap();
    assert!(s.uncompressed && s.content_length.is_none());
    let mut sink = Vec::new();
    assert_eq!(block_on(s.copy_to(&mut sink)).unwrap(), data.len() as u64);
    assert_eq!(sink, data);
    let r = block_on(client.get(&server.url("/raw"))).unwrap();
    assert_eq!((r.body.as_slice(), r.uncompressed), (&b"raw"[..], false));
    let e = block_on(client.request("GET", &server.url("/bomb")).max_decoded_bytes(100_000).send()).unwrap_err();
    assert_eq!(decode_error(&e), Some(&InflateError::OutputLimit { limit: 100_000 }));
    let r = block_on(client.request("GET", &server.url("/")).decompress(false).send()).unwrap();
    assert_eq!(r.body, gzip(&data));
    assert_eq!(server.requests().last().unwrap().header("accept-encoding"), Some("identity"));
}

// ------------------------------------------------------------------------------------------------ the helpers

#[test]
fn the_bodies_made_here_are_what_they_say() {
    use crate::inflate::{decode_all, Format, Limits};
    let data = text(200_000);
    assert_eq!(decode_all(Format::Gzip, &gzip(&data), Limits::unlimited()).unwrap(), data);
    assert_eq!(decode_all(Format::Zlib, &zlib(&data), Limits::unlimited()).unwrap(), data);
    assert_eq!(decode_all(Format::Deflate, &stored(&data), Limits::unlimited()).unwrap(), data);
    assert_eq!(decode_all(Format::Gzip, &gzip(b""), Limits::unlimited()).unwrap(), b"");
    let (g, n) = gzip_bomb(1000);
    let out = decode_all(Format::Gzip, &g, Limits::unlimited()).unwrap();
    assert_eq!(out.len() as u64, n);
    assert!(out.iter().all(|&b| b == 0));
}
