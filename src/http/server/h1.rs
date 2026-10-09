//! HTTP/1.1 for the server (RFC 9112): the request head, the framing of the body, the response, and the connection loop
//! with keep-alive and pipelining.
//!
//! Lines are read as they come, each new byte looked at once (a client that sends a head a byte at a time costs no more
//! than one that sends it at once), and every line must end with CRLF: a bare CR or LF anywhere in the head, a chunk
//! line or the trailers is refused. See the module above for what else is refused, and why.

use super::runtime::{Ctl, Pending, Timer};
use super::{call, reason, response_head, Body, BodySink, BodySource, BodyWriter, ConnInfo, Handler, HttpConfig, Request, Response, ResponseBody, Transport, Upgraded, Version};
use std::time::{Duration, Instant};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

/// The longest chunk line (the size and its extensions).
const MAX_CHUNK_LINE: usize = 4096;
/// Empty lines taken before a request line (RFC 9112 section 2.2 says at least one).
const MAX_EMPTY_LINES: usize = 8;
/// Bytes read from the transport at a time.
const READ_SIZE: usize = 16 * 1024;
/// Response bytes gathered before they are written.
const WRITE_SIZE: usize = 16 * 1024;

/// Something wrong with a request, which is answered with this status and closes the connection.
#[derive(Debug)]
pub(super) struct Bad {
    pub(super) status: u16,
    pub(super) why: String,
}

fn bad(status: u16, why: impl Into<String>) -> Bad {
    Bad { status, why: why.into() }
}

/// Why a line could not be read.
enum LineError {
    /// The transport ended (`true` if it ended with part of a line read).
    Eof(bool),
    TooLong,
    Bad(&'static str),
    Io(io::Error),
}

#[derive(Debug)]
enum Framing {
    /// No body (or what was left of one has been read).
    Done,
    Length(u64),
    Chunked(Chunk),
}

#[derive(Debug, Clone, Copy)]
enum Chunk {
    /// The next thing is a chunk-size line.
    Size,
    /// This much of the chunk's data is left.
    Data(u64),
    /// The CRLF after a chunk's data.
    DataEnd,
}

/// The state of the request body being read.
struct BodyState {
    framing: Framing,
    /// `Expect: 100-continue` was sent and the 100 is still owed.
    continue_pending: bool,
    /// The final response head has gone, so a 100 may no longer be sent.
    responded: bool,
    read: u64,
    max: Option<u64>,
    trailers: Vec<(String, String)>,
    /// A framing error, which every later read repeats.
    error: Option<String>,
    /// The minimum rate is being kept (from the first read of the body).
    timed: bool,
}

/// The connection, shared by the loop and the body of the request being handled.
struct Conn {
    io: Option<Box<dyn Transport>>,
    rbuf: Vec<u8>,
    rpos: usize,
    /// How far into `rbuf[rpos..]` the line being read has been looked at.
    scan: usize,
    body: BodyState,
    /// The request the body belongs to; a body kept past its request reads nothing.
    generation: u64,
    max_header_bytes: usize,
    max_headers: usize,
    timer: Option<Arc<Timer>>,
    body_grace: Duration,
    body_min_rate: u64,
}

impl Conn {
    fn io(&mut self) -> io::Result<&mut Box<dyn Transport>> {
        self.io.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "the connection was upgraded"))
    }

    /// Reads once more from the transport; 0 at its end.
    fn fill(&mut self) -> io::Result<usize> {
        if self.rpos > 0 && self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        } else if self.rpos >= READ_SIZE {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }
        let old = self.rbuf.len();
        self.rbuf.resize(old + READ_SIZE, 0);
        let got = loop {
            let io = match self.io.as_mut() {
                Some(io) => io,
                None => break Err(io::Error::new(io::ErrorKind::NotConnected, "the connection was upgraded")),
            };
            match io.read(&mut self.rbuf[old..]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        self.rbuf.truncate(old + *got.as_ref().unwrap_or(&0));
        got
    }

    fn buffered(&self) -> &[u8] {
        &self.rbuf[self.rpos..]
    }

    /// The next line, without its CRLF, if it is at most `limit` bytes; waits for it.
    fn read_line(&mut self, limit: usize) -> Result<Vec<u8>, LineError> {
        loop {
            let avail = &self.rbuf[self.rpos..];
            let mut i = self.scan;
            while i < avail.len() {
                match avail[i] {
                    b'\n' => return Err(LineError::Bad("a bare LF")),
                    b'\r' => {
                        if i + 1 == avail.len() {
                            break;
                        }
                        if avail[i + 1] != b'\n' {
                            return Err(LineError::Bad("a bare CR"));
                        }
                        if i > limit {
                            return Err(LineError::TooLong);
                        }
                        let line = avail[..i].to_vec();
                        self.rpos += i + 2;
                        self.scan = 0;
                        return Ok(line);
                    }
                    _ => i += 1,
                }
            }
            self.scan = i;
            if i > limit {
                return Err(LineError::TooLong);
            }
            match self.fill() {
                Ok(0) => return Err(LineError::Eof(!self.buffered().is_empty())),
                Ok(_) => {}
                Err(e) => return Err(LineError::Io(e)),
            }
        }
    }

    fn write_out(&mut self, bytes: &[u8]) -> io::Result<()> {
        let io = self.io()?;
        io.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io()?.flush()
    }

    /// Reads some of the request body.
    fn read_body(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.body.error {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.clone()));
        }
        if matches!(self.body.framing, Framing::Done) || buf.is_empty() {
            return Ok(0);
        }
        if !self.body.timed {
            // the body keeps to a minimum rate from when it is first read (a handler may think before it reads)
            self.body.timed = true;
            if let Some(t) = &self.timer {
                t.rate(self.body_grace, self.body_min_rate);
            }
        }
        if self.body.continue_pending && !self.body.responded {
            self.body.continue_pending = false;
            self.write_out(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            self.flush()?;
        }
        match self.read_body_inner(buf) {
            Ok(n) => {
                self.body.read += n as u64;
                if self.body.max.is_some_and(|max| self.body.read > max) {
                    return Err(self.body_error("the request body is larger than this server takes".into()));
                }
                Ok(n)
            }
            Err(e) => {
                if self.body.error.is_none() {
                    self.body.error = Some(e.to_string());
                }
                Err(e)
            }
        }
    }

    fn body_error(&mut self, why: String) -> io::Error {
        self.body.error = Some(why.clone());
        io::Error::new(io::ErrorKind::InvalidData, why)
    }

    fn read_body_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.body.framing {
                Framing::Done => return Ok(0),
                Framing::Length(0) => {
                    self.body.framing = Framing::Done;
                    return Ok(0);
                }
                Framing::Length(left) => {
                    let n = self.copy_data(buf, left)?;
                    self.body.framing = if left == n as u64 { Framing::Done } else { Framing::Length(left - n as u64) };
                    return Ok(n);
                }
                Framing::Chunked(Chunk::Data(left)) => {
                    let n = self.copy_data(buf, left)?;
                    self.body.framing = Framing::Chunked(if left == n as u64 { Chunk::DataEnd } else { Chunk::Data(left - n as u64) });
                    return Ok(n);
                }
                Framing::Chunked(Chunk::DataEnd) => {
                    let line = self.read_line(0).map_err(|e| self.line_error(e, "chunk data not followed by CRLF"))?;
                    if !line.is_empty() {
                        return Err(self.body_error("chunk data not followed by CRLF".into()));
                    }
                    self.body.framing = Framing::Chunked(Chunk::Size);
                }
                Framing::Chunked(Chunk::Size) => {
                    let line = self.read_line(MAX_CHUNK_LINE).map_err(|e| self.line_error(e, "a chunk line longer than this server takes"))?;
                    let size = chunk_size(&line).map_err(|why| self.body_error(why.into()))?;
                    if size == 0 {
                        self.read_trailers()?;
                        self.body.framing = Framing::Done;
                        return Ok(0);
                    }
                    if self.body.max.is_some_and(|max| self.body.read.saturating_add(size) > max) {
                        return Err(self.body_error("the request body is larger than this server takes".into()));
                    }
                    self.body.framing = Framing::Chunked(Chunk::Data(size));
                }
            }
        }
    }

    /// Copies up to `left` bytes of body data into `buf`: what is buffered, or one read of the transport.
    fn copy_data(&mut self, buf: &mut [u8], left: u64) -> io::Result<usize> {
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        if self.buffered().is_empty() {
            // straight into the caller's buffer when there is nothing buffered
            let io = self.io()?;
            let n = loop {
                match io.read(&mut buf[..want]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    other => break other?,
                }
            };
            if n == 0 {
                return Err(self.body_error("the connection ended in the middle of the request body".into()));
            }
            return Ok(n);
        }
        let n = want.min(self.buffered().len());
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        self.scan = 0;
        Ok(n)
    }

    fn line_error(&mut self, e: LineError, too_long: &str) -> io::Error {
        match e {
            LineError::Io(e) => e,
            LineError::Eof(_) => self.body_error("the connection ended in the middle of the request body".into()),
            LineError::TooLong => self.body_error(too_long.into()),
            LineError::Bad(why) => self.body_error(format!("{why} in the chunked body")),
        }
    }

    fn read_trailers(&mut self) -> io::Result<()> {
        let mut used = 0usize;
        let mut trailers = Vec::new();
        loop {
            let budget = self.max_header_bytes.saturating_sub(used);
            let line = self.read_line(budget).map_err(|e| self.line_error(e, "trailers longer than this server takes"))?;
            if line.is_empty() {
                break;
            }
            used += line.len() + 2;
            if trailers.len() == self.max_headers {
                return Err(self.body_error("more trailers than this server takes".into()));
            }
            let (name, value) = field_line(&line).map_err(|b| self.body_error(format!("a trailer: {}", b.why)))?;
            trailers.push((name, value));
        }
        self.body.trailers = trailers;
        Ok(())
    }
}

/// The size of a chunk from its line: plain hexadecimal of at most 16 digits, then well-formed extensions (which are
/// ignored).
pub(super) fn chunk_size(line: &[u8]) -> Result<u64, &'static str> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return Err("a chunk line that does not begin with its size in hexadecimal");
    }
    if digits > 16 {
        return Err("a chunk size of more than 16 hexadecimal digits");
    }
    let size = u64::from_str_radix(std::str::from_utf8(&line[..digits]).expect("hex digits"), 16).map_err(|_| "a chunk size that does not fit 64 bits")?;
    chunk_extensions(&line[digits..])?;
    Ok(size)
}

/// `*( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] )` (RFC 9112 section 7.1.1), and nothing else.
fn chunk_extensions(mut s: &[u8]) -> Result<(), &'static str> {
    let ws = |s: &[u8]| -> usize { s.iter().take_while(|&&b| b == b' ' || b == b'\t').count() };
    let token = |s: &[u8]| -> usize { s.iter().take_while(|&&b| super::is_tchar(b)).count() };
    loop {
        let w = ws(s);
        if w == s.len() {
            return if w == 0 { Ok(()) } else { Err("white space after a chunk size with no extension") };
        }
        s = &s[w..];
        if s[0] != b';' {
            return Err("a chunk extension that is not well formed");
        }
        s = &s[1..];
        s = &s[ws(s)..];
        let n = token(s);
        if n == 0 {
            return Err("a chunk extension without a name");
        }
        s = &s[n..];
        let w = ws(s);
        if s.get(w) == Some(&b'=') {
            s = &s[w + 1..];
            s = &s[ws(s)..];
            if s.first() == Some(&b'"') {
                let mut i = 1;
                loop {
                    match s.get(i) {
                        None => return Err("a quoted chunk extension that does not end"),
                        Some(b'"') => break,
                        Some(b'\\') => {
                            match s.get(i + 1) {
                                Some(&b) if b == b'\t' || (b >= 0x20 && b != 0x7f) => i += 2,
                                _ => return Err("a quoted chunk extension that is not well formed"),
                            }
                        }
                        Some(&b) if b == b'\t' || (b >= 0x20 && b != 0x7f) => i += 1,
                        Some(_) => return Err("a control character in a chunk extension"),
                    }
                }
                s = &s[i + 1..];
            } else {
                let n = token(s);
                if n == 0 {
                    return Err("a chunk extension without a value after its =");
                }
                s = &s[n..];
            }
        }
    }
}

/// A header field line: `name ":" OWS value OWS`, the name a token directly followed by the colon (no obsolete line
/// folding, no white space before the colon), the value without control characters, and UTF-8.
pub(super) fn field_line(line: &[u8]) -> Result<(String, String), Bad> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(bad(400, "obsolete line folding"));
    }
    let n = line.iter().take_while(|&&b| super::is_tchar(b)).count();
    if n == 0 {
        return Err(bad(400, "a header field without a name"));
    }
    if line.get(n) != Some(&b':') {
        return Err(bad(400, "a header field name followed by something other than a colon"));
    }
    let value = &line[n + 1..];
    if let Some(b) = value.iter().find(|&&b| !(b == b'\t' || (b >= 0x20 && b != 0x7f))) {
        return Err(bad(400, format!("a control character ({b:#04x}) in a header field value")));
    }
    let value = std::str::from_utf8(value).map_err(|_| bad(400, "a header field value that is not UTF-8"))?;
    let name = std::str::from_utf8(&line[..n]).expect("token characters").to_ascii_lowercase();
    Ok((name, value.trim_matches([' ', '\t']).to_string()))
}

/// The request line: `method SP request-target SP HTTP-version`, each part what its grammar allows and a single space
/// between them.
pub(super) fn request_line(line: &[u8]) -> Result<(String, String, Version), Bad> {
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad(400, "a request line that is not three parts with a space between each"));
    };
    if method.is_empty() || !method.iter().all(|&b| super::is_tchar(b)) {
        return Err(bad(400, "a method that is not a token"));
    }
    if target.is_empty() || !target.iter().all(|&b| (0x21..0x7f).contains(&b)) {
        return Err(bad(400, "a request target with a character it may not have"));
    }
    let version = match version {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
            if *major == b'1' {
                Version::Http11 // a later 1.x is answered as 1.1 (RFC 9110 section 2.5)
            } else {
                return Err(bad(505, "a version of HTTP other than 1.x"));
            }
        }
        _ => return Err(bad(400, "a request line whose version is not HTTP/x.y")),
    };
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).expect("ASCII");
    Ok((s(method), s(target), version))
}

/// Whether `host` may be a Host field value or the authority of a target: a host name, an IPv4 address or a bracketed IP
/// literal, and an optional port.
pub(super) fn valid_authority(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 1024
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=%:[]".contains(&b))
        && host.bytes().filter(|&b| b == b'[').count() <= 1
}

/// What the head of a request says about the request: checked, with the framing of its body.
pub(super) struct Checked {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) authority: String,
    pub(super) version: Version,
    pub(super) headers: Vec<(String, String)>,
    framing: Framing,
    pub(super) expect_continue: bool,
    pub(super) close: bool,
}

/// Checks a request's head: the target's form, Host, the framing of the body (RFC 9112 section 6), Expect and
/// Connection.
pub(super) fn check(method: String, target: String, version: Version, headers: Vec<(String, String)>, config: &HttpConfig) -> Result<Checked, Bad> {
    if target.contains('#') {
        return Err(bad(400, "a fragment in the request target"));
    }
    // the target's form (RFC 9112 section 3.2) and the authority
    let hosts: Vec<&str> = headers.iter().filter(|(n, _)| n == "host").map(|(_, v)| v.as_str()).collect();
    if version == Version::Http11 && hosts.len() != 1 {
        return Err(bad(400, if hosts.is_empty() { "no Host field" } else { "more than one Host field" }));
    }
    if hosts.len() > 1 {
        return Err(bad(400, "more than one Host field"));
    }
    if let Some(h) = hosts.first() {
        if !h.is_empty() && !valid_authority(h) {
            return Err(bad(400, "a Host field that is not a host and port"));
        }
    }
    let authority = if method == "CONNECT" {
        // authority-form: host:port, nothing else
        let ok = valid_authority(&target) && target.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            return Err(bad(400, "a CONNECT target that is not host:port"));
        }
        target.clone()
    } else if target.starts_with('/') {
        hosts.first().unwrap_or(&"").to_string()
    } else if target == "*" {
        if method != "OPTIONS" {
            return Err(bad(400, "the target * with a method other than OPTIONS"));
        }
        hosts.first().unwrap_or(&"").to_string()
    } else {
        // absolute-form: its authority, not Host's (RFC 9112 section 3.2.2)
        let lower = target.to_ascii_lowercase();
        let rest = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")).ok_or_else(|| bad(400, "a request target that is not a path, a URL, host:port or *"))?;
        let start = target.len() - rest.len();
        let end = target[start..].find(['/', '?']).map_or(target.len(), |i| start + i);
        let authority = &target[start..end];
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        if !valid_authority(authority) {
            return Err(bad(400, "a URL target without a host"));
        }
        authority.to_string()
    };
    // the body's framing
    let te: Vec<&str> = headers.iter().filter(|(n, _)| n == "transfer-encoding").map(|(_, v)| v.as_str()).collect();
    let cl: Vec<&str> = headers.iter().filter(|(n, _)| n == "content-length").map(|(_, v)| v.as_str()).collect();
    let framing = if !te.is_empty() {
        if version == Version::Http10 {
            return Err(bad(400, "Transfer-Encoding in an HTTP/1.0 request"));
        }
        if !cl.is_empty() {
            return Err(bad(400, "both Transfer-Encoding and Content-Length"));
        }
        let codings: Vec<&str> = te.iter().flat_map(|v| v.split(',')).map(|c| c.trim_matches([' ', '\t'])).collect();
        let chunked = |c: &str| c.eq_ignore_ascii_case("chunked");
        if codings.iter().any(|c| c.is_empty()) {
            return Err(bad(400, "an empty transfer coding"));
        }
        if codings.len() == 1 && chunked(codings[0]) {
            Framing::Chunked(Chunk::Size)
        } else if codings.iter().filter(|c| chunked(c)).count() == 1 && chunked(codings[codings.len() - 1]) && codings.iter().all(|c| c.bytes().all(super::is_tchar)) {
            return Err(bad(501, "a transfer coding other than chunked"));
        } else {
            return Err(bad(400, "a Transfer-Encoding that does not end with chunked, once"));
        }
    } else if !cl.is_empty() {
        if cl.len() > 1 {
            return Err(bad(400, "more than one Content-Length"));
        }
        let v = cl[0];
        if v.is_empty() || v.len() > 18 || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad(400, "a Content-Length that is not one number"));
        }
        let n: u64 = v.parse().expect("digits");
        if config.max_body.is_some_and(|max| n > max) {
            return Err(bad(413, "a body larger than this server takes"));
        }
        if n == 0 { Framing::Done } else { Framing::Length(n) }
    } else {
        Framing::Done
    };
    // Expect (RFC 9110 section 10.1.1): only 100-continue, and only in HTTP/1.1
    let mut expect_continue = false;
    if version == Version::Http11 {
        for (_, v) in headers.iter().filter(|(n, _)| n == "expect") {
            if v.eq_ignore_ascii_case("100-continue") {
                expect_continue = true;
            } else {
                return Err(bad(417, "an expectation other than 100-continue"));
            }
        }
    }
    let tokens: Vec<String> = headers.iter().filter(|(n, _)| n == "connection").flat_map(|(_, v)| v.split(',')).map(|t| t.trim_matches([' ', '\t']).to_ascii_lowercase()).collect();
    let close = tokens.iter().any(|t| t == "close") || (version == Version::Http10 && !tokens.iter().any(|t| t == "keep-alive"));
    Ok(Checked { method, target, authority, version, headers, expect_continue: expect_continue && !matches!(framing, Framing::Done), framing, close })
}

/// The body of the request being handled, as the handler reads it.
struct Source {
    conn: Arc<Mutex<Conn>>,
    generation: u64,
}

fn lock(conn: &Mutex<Conn>) -> MutexGuard<'_, Conn> {
    conn.lock().unwrap_or_else(|e| e.into_inner())
}

impl BodySource for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut c = lock(&self.conn);
        if c.generation != self.generation {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the request this body belongs to is over"));
        }
        c.read_body(buf)
    }

    fn trailers(&self) -> Vec<(String, String)> {
        let c = lock(&self.conn);
        if c.generation != self.generation {
            return Vec::new();
        }
        c.body.trailers.clone()
    }
}

/// Serves an HTTP/1.1 connection until it ends.
pub(super) fn serve(io: Box<dyn Transport>, info: Arc<ConnInfo>, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<Ctl>) -> io::Result<()> {
    serve_with(io, Vec::new(), info, handler, config, ctl)
}

/// [`serve`], with bytes already read from the connection.
pub(super) fn serve_with(io: Box<dyn Transport>, already: Vec<u8>, info: Arc<ConnInfo>, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<Ctl>) -> io::Result<()> {
    let conn = Arc::new(Mutex::new(Conn {
        io: Some(io),
        rbuf: already,
        rpos: 0,
        scan: 0,
        body: BodyState { framing: Framing::Done, continue_pending: false, responded: true, read: 0, max: None, trailers: Vec::new(), error: None, timed: true },
        generation: 0,
        max_header_bytes: config.max_header_bytes,
        max_headers: config.max_headers,
        timer: ctl.timer.clone(),
        body_grace: ctl.limits.body_grace,
        body_min_rate: ctl.limits.body_min_rate,
    }));
    // however the loop ends, the transport goes with it: a body a handler kept must not keep the connection open
    struct Closer(Arc<Mutex<Conn>>);
    impl Drop for Closer {
        fn drop(&mut self) {
            let io = lock(&self.0).io.take();
            drop(io);
        }
    }
    let _closer = Closer(conn.clone());
    let scheme = if info.tls.is_some() { "https" } else { "http" };
    let mut served = 0usize;
    loop {
        if ctl.is_closing() {
            return Ok(());
        }
        let head = {
            let mut c = lock(&conn);
            // idle until the first byte of the next request (the server's shutdown ends this wait at once), then the
            // whole head within its time
            if c.buffered().is_empty() {
                if let Some(t) = &ctl.timer {
                    t.until(Instant::now() + ctl.limits.idle_timeout);
                }
                ctl.idle.store(true, std::sync::atomic::Ordering::SeqCst);
                let waited = if ctl.is_closing() { Ok(0) } else { c.fill() };
                ctl.idle.store(false, std::sync::atomic::Ordering::SeqCst);
                match waited {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            if let Some(t) = &ctl.timer {
                t.until(Instant::now() + ctl.limits.head_timeout);
            }
            match read_head(&mut c, config) {
                Ok(Some(head)) => head,
                Ok(None) => return Ok(()),
                Err(HeadError::Io(e)) => return Err(e),
                Err(HeadError::Bad(b)) => {
                    refuse(&mut c, &b, config);
                    return Ok(());
                }
            }
        };
        let (method, target, version, headers) = head;
        let Checked { method, target, authority, version, headers, framing, expect_continue, close } = match check(method, target, version, headers, config) {
            Ok(c) => c,
            Err(b) => {
                refuse(&mut lock(&conn), &b, config);
                return Ok(());
            }
        };
        served += 1;
        let has_body = !matches!(framing, Framing::Done);
        let generation = {
            let mut c = lock(&conn);
            c.generation += 1;
            c.body = BodyState {
                framing,
                continue_pending: expect_continue,
                responded: false,
                read: 0,
                max: config.max_body,
                trailers: Vec::new(),
                error: None,
                timed: false,
            };
            c.generation
        };
        let body = if has_body { Body::new(Some(Box::new(Source { conn: conn.clone(), generation }))) } else { Body::new(None) };
        let mut ctx = Ctx { version, head: method == "HEAD", connect: method == "CONNECT", close: close || served >= config.max_requests_per_connection, upgraded_idle: ctl.limits.upgraded_idle_timeout };
        let interim: Option<super::Interim> = (version == Version::Http11).then(|| {
            let conn = conn.clone();
            Arc::new(move |status: u16, fields: &[(String, String)]| {
                let mut c = lock(&conn);
                if c.generation != generation || c.body.responded {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the final response has begun"));
                }
                let mut text = format!("HTTP/1.1 {status} {}\r\n", reason(status));
                for (n, v) in fields {
                    text.push_str(&format!("{n}: {v}\r\n"));
                }
                text.push_str("\r\n");
                c.write_out(text.as_bytes())?;
                c.flush()
            }) as super::Interim
        });
        let request = Request { method, target, authority, scheme: scheme.into(), version, headers, body, info: info.clone(), interim, ctl: Some(ctl.clone()) };
        let pending = Pending::of(&ctl, &request);
        let (response, panicked) = call(&*handler, request);
        // a server that began to shut down while the handler ran closes after this response
        ctx.close |= ctl.is_closing();
        let (after, status, bytes) = send_response(&conn, response, &ctx, panicked, config)?;
        if let Some(p) = pending {
            p.done(&ctl, status, bytes);
        }
        let mut c = lock(&conn);
        match after {
            After::Upgraded => return Ok(()),
            After::Close => return Ok(()),
            After::KeepAlive => {}
        }
        // what the handler left of the body: read past it, a little, or close
        if !matches!(c.body.framing, Framing::Done) || c.body.error.is_some() {
            if c.body.continue_pending || c.body.error.is_some() {
                return Ok(());
            }
            let mut sink = [0u8; 8192];
            let mut drained = 0u64;
            loop {
                match c.read_body(&mut sink) {
                    Ok(0) => break,
                    Ok(n) => {
                        drained += n as u64;
                        if drained > config.drain_limit {
                            return Ok(());
                        }
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
        c.generation += 1;
    }
}

enum HeadError {
    Io(io::Error),
    Bad(Bad),
}

type Head = (String, String, Version, Vec<(String, String)>);

/// Reads the next request head. `None` if the connection ended cleanly before one began.
fn read_head(c: &mut Conn, config: &HttpConfig) -> Result<Option<Head>, HeadError> {
    let line_err = |e: LineError, too_long: Bad| match e {
        LineError::Io(e) => HeadError::Io(e),
        LineError::Eof(partial) => HeadError::Bad(bad(400, if partial { "the connection ended in the middle of a request head" } else { "" })),
        LineError::TooLong => HeadError::Bad(too_long),
        LineError::Bad(why) => HeadError::Bad(bad(400, why)),
    };
    let mut line = match c.read_line(config.max_request_line) {
        Ok(l) => l,
        Err(LineError::Eof(false)) => return Ok(None),
        Err(e) => return Err(line_err(e, bad(414, "a request line longer than this server takes"))),
    };
    let mut empty = 0;
    while line.is_empty() {
        empty += 1;
        if empty > MAX_EMPTY_LINES {
            return Err(HeadError::Bad(bad(400, "empty lines where a request line should be")));
        }
        line = match c.read_line(config.max_request_line) {
            Ok(l) => l,
            Err(LineError::Eof(false)) => return Ok(None),
            Err(e) => return Err(line_err(e, bad(414, "a request line longer than this server takes"))),
        };
    }
    let (method, target, version) = request_line(&line).map_err(HeadError::Bad)?;
    let mut headers = Vec::new();
    let mut used = 0usize;
    loop {
        let budget = config.max_header_bytes.saturating_sub(used);
        let line = c.read_line(budget).map_err(|e| line_err(e, bad(431, "header fields longer than this server takes")))?;
        if line.is_empty() {
            break;
        }
        used += line.len() + 2;
        if used > config.max_header_bytes {
            return Err(HeadError::Bad(bad(431, "header fields longer than this server takes")));
        }
        if headers.len() == config.max_headers {
            return Err(HeadError::Bad(bad(431, "more header fields than this server takes")));
        }
        headers.push(field_line(&line).map_err(HeadError::Bad)?);
    }
    Ok(Some((method, target, version, headers)))
}

/// Answers a request the server refuses, and lingers a little before the connection is closed.
fn refuse(c: &mut Conn, b: &Bad, config: &HttpConfig) {
    if write_refusal(c, b, config).is_ok() && !b.why.is_empty() {
        if let Some(t) = &c.timer {
            t.each(Duration::from_millis(200));
        }
        if let Some(io) = c.io.as_mut() {
            io.linger();
        }
    }
}

/// Answers a request the server refuses, and closes.
fn write_refusal(c: &mut Conn, b: &Bad, config: &HttpConfig) -> io::Result<()> {
    if b.why.is_empty() {
        return Ok(()); // the connection ended: nobody to answer
    }
    let body = format!("{}\n", b.why);
    let mut out = format!("HTTP/1.1 {} {}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\ndate: {}\r\n", b.status, reason(b.status), body.len(), super::date::now());
    if let Some(server) = &config.server_header {
        out.push_str(&format!("server: {server}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(&body);
    c.write_out(out.as_bytes())?;
    c.flush()
}

#[derive(Clone, Copy)]
struct Ctx {
    version: Version,
    head: bool,
    connect: bool,
    close: bool,
    upgraded_idle: Duration,
}

enum After {
    KeepAlive,
    Close,
    Upgraded,
}

/// How the response body is framed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Out {
    None,
    Length(u64),
    Chunked,
    /// To the end of the connection (HTTP/1.0, length unknown).
    UntilClose,
}

/// Sends a response; says what is to become of the connection, and the status and body bytes sent (for the access log).
fn send_response(conn: &Arc<Mutex<Conn>>, response: Response, ctx: &Ctx, panicked: bool, config: &HttpConfig) -> io::Result<(After, u16, u64)> {
    let Response { status, headers, body } = response;
    let head = match response_head(&headers, config) {
        Ok(h) if (100..=999).contains(&status) => h,
        _ => return send_response(conn, Response::text(500, "internal server error\n"), &Ctx { close: true, ..*ctx }, true, config),
    };
    let upgrade = matches!(body, ResponseBody::Upgrade(_));
    let valid = match status {
        101 => upgrade,
        100..=199 => false,
        200..=299 if ctx.connect => true,
        _ => !upgrade,
    };
    if !valid {
        return send_response(conn, Response::text(500, "internal server error\n"), &Ctx { close: true, ..*ctx }, true, config);
    }
    let no_body = matches!(status, 100..=199 | 204 | 304) || (ctx.connect && (200..300).contains(&status));
    let out = if no_body {
        Out::None
    } else {
        match &body {
            ResponseBody::Empty => Out::Length(if ctx.head { head.content_length.unwrap_or(0) } else { 0 }),
            ResponseBody::Bytes(b) => Out::Length(b.len() as u64),
            ResponseBody::Reader { length: Some(n), .. } => Out::Length(*n),
            ResponseBody::Reader { length: None, .. } | ResponseBody::Stream(_) => {
                if ctx.head {
                    Out::None
                } else if ctx.version == Version::Http11 {
                    Out::Chunked
                } else {
                    Out::UntilClose
                }
            }
            ResponseBody::Upgrade(_) => Out::None,
        }
    };
    // what of the request body will be left when the response is done, and whether it is too much to read past: a body
    // the client is still waiting for a 100 to send, or more than the drain limit (if its length is known)
    let streams = matches!(body, ResponseBody::Reader { .. } | ResponseBody::Stream(_)) && !ctx.head;
    let abandon = {
        let c = lock(conn);
        let left = match c.body.framing {
            Framing::Done => Some(0),
            Framing::Length(n) => Some(n),
            Framing::Chunked(_) => None,
        };
        c.body.error.is_some() || (!streams && left != Some(0) && (c.body.continue_pending || left.is_some_and(|n| n > config.drain_limit)))
    };
    // after a CONNECT that is not a tunnel the client may already have sent what was meant for the tunnel: close
    let close = (ctx.close || head.close || panicked || abandon || out == Out::UntilClose || ctx.connect) && !upgrade;
    let mut text = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (n, v) in &head.fields {
        text.push_str(n);
        text.push_str(": ");
        text.push_str(v);
        text.push_str("\r\n");
    }
    match out {
        Out::Length(n) => text.push_str(&format!("content-length: {n}\r\n")),
        Out::Chunked => text.push_str("transfer-encoding: chunked\r\n"),
        Out::None if status == 304 => {
            if let Some(n) = head.content_length {
                text.push_str(&format!("content-length: {n}\r\n"));
            }
        }
        _ => {}
    }
    if close {
        text.push_str("connection: close\r\n");
    } else if ctx.version == Version::Http10 && !upgrade {
        text.push_str("connection: keep-alive\r\n");
    }
    text.push_str("\r\n");
    let mut head_bytes = text.into_bytes();
    {
        let mut c = lock(conn);
        // a streamed response may read the request body as it goes: the 100 it may be waiting for goes first
        if c.body.continue_pending && matches!(body, ResponseBody::Reader { .. } | ResponseBody::Stream(_)) && !ctx.head {
            c.body.continue_pending = false;
            let mut with = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
            with.append(&mut head_bytes);
            head_bytes = with;
        }
        c.body.responded = true;
    }
    let send_body = !ctx.head && !no_body;
    let mut sent = 0u64;
    match body {
        ResponseBody::Empty => {
            let mut c = lock(conn);
            c.write_out(&head_bytes)?;
            c.flush()?;
        }
        ResponseBody::Bytes(b) => {
            let mut c = lock(conn);
            if send_body {
                sent = b.len() as u64;
            }
            if send_body && b.len() <= WRITE_SIZE * 4 {
                head_bytes.extend_from_slice(&b);
                c.write_out(&head_bytes)?;
            } else {
                c.write_out(&head_bytes)?;
                if send_body {
                    c.write_out(&b)?;
                }
            }
            c.flush()?;
        }
        ResponseBody::Reader { mut reader, length } => {
            lock(conn).write_out(&head_bytes)?;
            if send_body {
                let mut sink = Sink { conn, framing: out, buf: Vec::new() };
                let mut left = length;
                let mut chunk = vec![0u8; WRITE_SIZE];
                loop {
                    let want = left.map_or(chunk.len(), |l| chunk.len().min(usize::try_from(l).unwrap_or(usize::MAX)));
                    if want == 0 {
                        break;
                    }
                    // the handler's reader is read with no lock held: it may be reading the request body
                    let n = match reader.read(&mut chunk[..want]) {
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return Ok((After::Close, status, sent)),
                    };
                    if n == 0 {
                        if left.is_some_and(|l| l > 0) {
                            // shorter than the length it promised: the client must see that the body is cut
                            let _ = sink.flush_body();
                            return Ok((After::Close, status, sent));
                        }
                        break;
                    }
                    sent += n as u64;
                    // what the reader gives goes out as it comes: a reader that trickles (events, a proxied stream) is not held
                    sink.write_body(&chunk[..n])?;
                    sink.emit()?;
                    if let Some(l) = left.as_mut() {
                        *l -= n as u64;
                    }
                }
                sink.finish(&[])?;
            }
            lock(conn).flush()?;
        }
        ResponseBody::Stream(write) => {
            lock(conn).write_out(&head_bytes)?;
            if send_body {
                let mut sink = Sink { conn, framing: out, buf: Vec::new() };
                let mut writer = BodyWriter { sink: &mut sink, trailers: Vec::new(), written: 0 };
                let res = write(&mut writer);
                let trailers = std::mem::take(&mut writer.trailers);
                sent = writer.written;
                if res.is_err() {
                    let _ = sink.flush_body();
                    return Ok((After::Close, status, sent));
                }
                sink.finish(&trailers)?;
            }
            lock(conn).flush()?;
        }
        ResponseBody::Upgrade(then) => {
            let (io, leftover) = {
                let mut c = lock(conn);
                c.write_out(&head_bytes)?;
                c.flush()?;
                let leftover = c.buffered().to_vec();
                c.rbuf.clear();
                c.rpos = 0;
                c.generation += 1;
                (c.io.take(), leftover)
            };
            let Some(io) = io else { return Ok((After::Close, status, 0)) };
            // an upgraded connection may be quiet for long (a tunnel): each read waits up to its own limit
            if let Some(t) = lock(conn).timer.as_ref() {
                t.each(ctx.upgraded_idle);
            }
            let (r, w) = io.split()?;
            then(Upgraded { reader: Box::new(io::Cursor::new(leftover).chain(r)), writer: w });
            return Ok((After::Upgraded, status, 0));
        }
    }
    Ok((if close { After::Close } else { After::KeepAlive }, status, sent))
}

/// Writes a response body, framed, gathering small writes.
struct Sink<'a> {
    conn: &'a Arc<Mutex<Conn>>,
    framing: Out,
    buf: Vec<u8>,
}

impl Sink<'_> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut c = lock(self.conn);
        if self.framing == Out::Chunked {
            c.write_out(format!("{:x}\r\n", self.buf.len()).as_bytes())?;
            self.buf.extend_from_slice(b"\r\n");
        }
        c.write_out(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// The end of the body: the last chunk and the trailers.
    fn finish(&mut self, trailers: &[(String, String)]) -> io::Result<()> {
        self.emit()?;
        if self.framing == Out::Chunked {
            let mut end = b"0\r\n".to_vec();
            for (n, v) in trailers {
                if !n.is_empty() && n.bytes().all(super::is_tchar) && super::is_field_value(v) {
                    end.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
                }
            }
            end.extend_from_slice(b"\r\n");
            lock(self.conn).write_out(&end)?;
        }
        Ok(())
    }
}

impl BodySink for Sink<'_> {
    fn write_body(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() >= WRITE_SIZE {
            self.emit()?;
        }
        Ok(())
    }

    fn flush_body(&mut self) -> io::Result<()> {
        self.emit()?;
        lock(self.conn).flush()
    }
}
