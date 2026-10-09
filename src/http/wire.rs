//! HTTP/1.1 message framing: request serialization and the limits on responses. The response
//! parser itself is in `parser`; `read_response` here reads a whole response through it (for tests: the
//! client reads responses through `stream`, which hands the body on as it comes).

#[cfg(test)]
use super::parser::Buffered;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use std::io::{self, Read};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum size of the status line plus all header lines.
    pub max_header_bytes: usize,
    /// Maximum size of a response body.
    pub max_body_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_header_bytes: 64 * 1024, max_body_bytes: 64 * 1024 * 1024 }
    }
}

/// A whole response, as the tests and the fuzzer look at it (the fuzzer reads the status and the body only).
#[cfg(any(test, pratique_fuzzing))]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_char)
}

pub fn is_valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Serializes a request head (request line, headers and the blank line). Caller supplies
/// already-validated headers.
pub fn write_request_head(method: &str, target: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, target).as_bytes());
    for (n, v) in headers {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Serializes a request head + body into one buffer (for small bodies).
#[cfg(test)]
pub fn write_request(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = write_request_head(method, target, headers);
    out.reserve(body.len());
    out.extend_from_slice(body);
    out
}

/// Size of the buffer responses are read through.
#[cfg(test)]
const READ_CHUNK: usize = 32 * 1024;

/// Reads one complete response (skipping 1xx interim responses) from a blocking reader.
#[cfg(test)]
pub fn read_response<R: Read>(reader: &mut R, request_method: &str, limits: Limits) -> Result<RawResponse> {
    let mut parser = Buffered::new(request_method, limits);
    let mut scratch = vec![0u8; READ_CHUNK];
    while !parser.is_done() {
        // a sized body never asks for more than is left of it, so nothing past the message is read
        let want = parser.max_read().min(scratch.len());
        match reader.read(&mut scratch[..want]) {
            Ok(0) => parser.finish_eof()?,
            Ok(n) => parser.feed(&scratch[..n])?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(parser.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &[u8], method: &str) -> Result<RawResponse> {
        read_response(&mut Cursor::new(raw.to_vec()), method, Limits::default())
    }

    #[test]
    fn content_length_body() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A:  v \r\n\r\nhelloEXTRA", "GET").unwrap();
        assert_eq!((r.status, r.reason.as_str()), (200, "OK"));
        assert_eq!(r.body, b"hello");
        assert_eq!(r.headers[1], ("X-A".to_string(), "v".to_string()));
    }

    #[test]
    fn chunked_body_with_extensions_and_trailers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(parse(raw, "GET").unwrap().body, b"hello world");
    }

    #[test]
    fn read_until_close() {
        let r = parse(b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\nall of it", "GET").unwrap();
        assert_eq!(r.body, b"all of it");
    }

    #[test]
    fn no_body_cases() {
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", "HEAD").unwrap().body.is_empty());
        assert!(parse(b"HTTP/1.1 204 No Content\r\n\r\n", "GET").unwrap().body.is_empty());
        assert!(parse(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4\r\n\r\n", "GET").unwrap().body.is_empty());
    }

    #[test]
    fn skips_interim_100_continue() {
        let r = parse(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok", "POST").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (201, &b"ok"[..]));
    }

    #[test]
    fn tolerates_bare_lf() {
        assert_eq!(parse(b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi", "GET").unwrap().body, b"hi");
    }

    #[test]
    fn rejects_malformed_and_smuggling_shapes() {
        let bad: Vec<&[u8]> = vec![
            b"garbage\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi", // truncated
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ];
        for raw in bad {
            assert!(parse(raw, "GET").is_err(), "should reject {:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn enforces_limits() {
        let tiny = Limits { max_header_bytes: 64, max_body_bytes: 8 };
        let big_header = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(200));
        assert!(read_response(&mut Cursor::new(big_header.into_bytes()), "GET", tiny).is_err());
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789".to_vec();
        assert!(read_response(&mut Cursor::new(r), "GET", tiny).is_err());
        let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n".to_vec();
        assert!(read_response(&mut Cursor::new(r), "GET", tiny).is_err());
        let r = b"HTTP/1.1 200 OK\r\n\r\n123456789".to_vec();
        assert!(read_response(&mut Cursor::new(r), "GET", tiny).is_err());
    }

    /// A reader that returns at most `step` bytes per call.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        step: usize,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.step).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn big_body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn bodies_survive_any_read_pattern() {
        let body = big_body(100_000);
        let mut cl = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        cl.extend_from_slice(&body);
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for piece in body.chunks(7777) {
            chunked.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            chunked.extend_from_slice(piece);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\nX-Trailer: t\r\n\r\n");
        let mut until_close = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        until_close.extend_from_slice(&body);

        for step in [1usize, 2, 3, 100, 4096, 16 * 1024, 16 * 1024 + 1, 1 << 20] {
            for raw in [&cl, &chunked, &until_close] {
                let mut r = Trickle { data: raw.clone(), pos: 0, step };
                let resp = read_response(&mut r, "GET", Limits::default()).unwrap();
                assert!(resp.body == body, "step {step}");
            }
        }
    }

    #[test]
    fn leaves_following_bytes_unread_for_content_length() {
        // Bytes after the body belong to the next message and must not be consumed from the reader
        // beyond what the buffer already holds; here everything arrives in one read, so just check
        // the body is cut at the right place.
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcNEXT", "GET").unwrap();
        assert_eq!(r.body, b"abc");
        let mut t = Trickle { data: b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcNEXT".to_vec(), pos: 0, step: 1 };
        let r = read_response(&mut t, "GET", Limits::default()).unwrap();
        assert_eq!(r.body, b"abc");
        assert_eq!(&t.data[t.pos..], b"NEXT", "reader must not be drained past the body");
    }

    #[test]
    fn very_long_header_line_grows_the_buffer() {
        let value = "v".repeat(40_000);
        let raw = format!("HTTP/1.1 200 OK\r\nX-Long: {value}\r\nContent-Length: 2\r\n\r\nok");
        for step in [1usize << 20, 5000, 1] {
            let mut r = Trickle { data: raw.clone().into_bytes(), pos: 0, step };
            let resp = read_response(&mut r, "GET", Limits::default()).unwrap();
            assert_eq!(resp.headers[0].1.len(), 40_000);
            assert_eq!(resp.body, b"ok");
        }
        // ... but the limit still applies.
        let limits = Limits { max_header_bytes: 30_000, max_body_bytes: 100 };
        assert!(read_response(&mut Cursor::new(raw.into_bytes()), "GET", limits).is_err());
    }

    #[test]
    fn body_limit_is_exact_for_read_until_close() {
        let body = big_body(5000);
        let mut raw = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        raw.extend_from_slice(&body);
        let at_limit = Limits { max_header_bytes: 4096, max_body_bytes: 5000 };
        let under = Limits { max_header_bytes: 4096, max_body_bytes: 4999 };
        for step in [1usize << 20, 777] {
            let mut r = Trickle { data: raw.clone(), pos: 0, step };
            assert_eq!(read_response(&mut r, "GET", at_limit).unwrap().body.len(), 5000);
            let mut r = Trickle { data: raw.clone(), pos: 0, step };
            assert!(read_response(&mut r, "GET", under).is_err());
        }
    }

    #[test]
    fn truncation_is_an_error_not_a_short_body() {
        let body = big_body(50_000);
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\n".to_vec();
        raw.extend_from_slice(&body[..49_999]);
        for step in [1usize << 20, 1000] {
            let mut r = Trickle { data: raw.clone(), pos: 0, step };
            assert!(read_response(&mut r, "GET", Limits::default()).is_err());
        }
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nonly-eight".to_vec();
        assert!(read_response(&mut Cursor::new(chunked), "GET", Limits::default()).is_err());
    }

    #[test]
    fn request_serialization() {
        let req = write_request("POST", "/x?y=1", &[("Host".into(), "h".into()), ("Content-Length".into(), "2".into())], b"hi");
        assert_eq!(req, b"POST /x?y=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi");
    }

    #[test]
    fn header_validation() {
        assert!(is_valid_header_name("Content-Type"));
        assert!(!is_valid_header_name("Bad Name"));
        assert!(!is_valid_header_name(""));
        assert!(!is_valid_header_name("X:y"));
        assert!(is_valid_header_value("text/plain; charset=utf-8"));
        assert!(!is_valid_header_value("a\r\nInjected: 1"));
    }
}
