//! An incremental HTTP/1.1 response parser that does no I/O (sans-IO).
//!
//! Feed it the bytes as they arrive, in pieces of any size, and it frames the response: status
//! line, headers (1xx interim responses are skipped), then the body by Content-Length, chunked
//! encoding or read-until-close. The blocking reader, the streaming readers and the async client
//! all drive it.
//!
//! The parser keeps no body. The decoded body bytes are appended to a `Vec` the caller passes to
//! [`feed`](ResponseParser::feed), so the caller may collect them, pass them on or hash them as
//! they come, and while the transport's next bytes are all body (a sized body, or the data of a
//! chunk) the caller can read them straight into its own buffer
//! ([`direct_window`](ResponseParser::direct_window)) and tell the parser how many arrived.
//!
//! When the message is complete the parser also knows whether the connection can carry another
//! request ([`reusable`](ResponseParser::reusable)): the body was framed (not "until close"), the
//! server did not ask to close and speaks HTTP/1.1 (or HTTP/1.0 with keep-alive), the message
//! does not carry both a Content-Length and a Transfer-Encoding, and nothing arrived after it.

use super::wire::{is_valid_header_name, Limits};
use crate::error::{Error, Result};
use std::io;
use std::time::Duration;

fn http_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Http(msg.into()))
}

fn eof(msg: &str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, msg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    StatusLine,
    Headers,
    /// Content-Length body, bytes still to come.
    Sized(u64),
    ChunkSize,
    /// Chunk data, bytes still to come.
    ChunkData(u64),
    /// The CRLF after chunk data.
    ChunkEnd,
    /// Trailer lines up to the blank line; bytes seen so far.
    Trailers(usize),
    UntilClose,
    Done,
}

/// The status line and headers of the final response (the one after any 1xx interim responses).
#[derive(Debug, Clone)]
pub(crate) struct Head {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
    /// The Content-Length the server declared, if it declared one and the response is not
    /// chunked. A response to HEAD declares the length a GET would have, though no body follows.
    pub(crate) content_length: Option<u64>,
}

pub(crate) struct ResponseParser {
    head_request: bool,
    limits: Limits,
    state: State,
    /// Bytes received but not yet consumed by a line state or a body state: `buf[pos..]`.
    buf: Vec<u8>,
    pos: usize,
    header_bytes: usize,
    blank_lines: usize,
    /// Any byte has been fed (a request whose connection fails before this is true never got an answer).
    seen: bool,
    /// The minor version of the response's `HTTP/1.x`.
    minor: u8,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    /// Set when the headers are complete, until [`take_head`](ResponseParser::take_head).
    head: Option<Head>,
    head_complete: bool,
    /// Body bytes produced so far, counted against the limit.
    body_bytes: u64,
    /// The headers and the framing allow another request on this connection.
    persistent: bool,
    /// Bytes arrived after the end of the message.
    extra: bool,
    /// A `100 Continue` interim response has been read (see [`continued`](ResponseParser::continued)).
    continued: bool,
}

impl ResponseParser {
    pub(crate) fn new(request_method: &str, limits: Limits) -> ResponseParser {
        ResponseParser {
            head_request: request_method.eq_ignore_ascii_case("HEAD"),
            limits,
            state: State::StatusLine,
            buf: Vec::new(),
            pos: 0,
            header_bytes: 0,
            blank_lines: 0,
            seen: false,
            minor: 1,
            status: 0,
            reason: String::new(),
            headers: Vec::new(),
            head: None,
            head_complete: false,
            body_bytes: 0,
            persistent: false,
            extra: false,
            continued: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// True once any byte of the response has been fed.
    pub(crate) fn started(&self) -> bool {
        self.seen
    }

    /// True once the status line and headers of the final response have been read.
    pub(crate) fn head_complete(&self) -> bool {
        self.head_complete
    }

    /// True once a `100 Continue` has been read: the go-ahead that a request with `Expect: 100-continue` waits for before it sends
    /// its body. (The interim response is otherwise skipped, like every 1xx.)
    pub(crate) fn continued(&self) -> bool {
        self.continued
    }

    /// The final response's head, once, after [`head_complete`](ResponseParser::head_complete).
    pub(crate) fn take_head(&mut self) -> Option<Head> {
        self.head.take()
    }

    /// True when the message is complete and the connection can carry another request: see the
    /// module documentation.
    pub(crate) fn reusable(&self) -> bool {
        self.state == State::Done && self.persistent && !self.extra
    }

    /// The most bytes worth reading from the transport next: a sized body never asks for more
    /// than is left of it, so nothing past the end of the message is consumed.
    pub(crate) fn max_read(&self) -> usize {
        let left = |n: u64| (n.saturating_sub((self.buf.len() - self.pos) as u64)).min(usize::MAX as u64) as usize;
        match self.state {
            State::Sized(n) | State::ChunkData(n) => left(n).max(1),
            State::Done => 0,
            _ => usize::MAX,
        }
    }

    /// How many of the transport's next bytes are body bytes that need no parsing: the rest of a
    /// sized body, the rest of a chunk's data, or everything of a body that runs to the end of the
    /// connection; 0 when the parser has to look at the next bytes itself (or holds bytes it has
    /// not consumed yet). Read up to this many straight into the destination and report them with
    /// [`consume_direct`](ResponseParser::consume_direct).
    pub(crate) fn direct_window(&self) -> usize {
        if self.buf.len() > self.pos {
            return 0;
        }
        match self.state {
            State::Sized(n) | State::ChunkData(n) => n.min(usize::MAX as u64) as usize,
            State::UntilClose => usize::MAX,
            _ => 0,
        }
    }

    /// Accounts for `n` body bytes read straight from the transport (see
    /// [`direct_window`](ResponseParser::direct_window)).
    pub(crate) fn consume_direct(&mut self, n: usize) -> Result<()> {
        let n = n as u64;
        match self.state {
            State::Sized(left) | State::ChunkData(left) if n <= left && self.buf.len() == self.pos => {
                let sized = matches!(self.state, State::Sized(_));
                self.body_bytes += n;
                let left = left - n;
                self.state = match (left > 0, sized) {
                    (true, true) => State::Sized(left),
                    (true, false) => State::ChunkData(left),
                    (false, true) => State::Done,
                    (false, false) => State::ChunkEnd,
                };
                Ok(())
            }
            State::UntilClose if self.buf.len() == self.pos => self.count_until_close(n),
            _ => http_err("body bytes were read directly while the parser was not expecting body data"),
        }
    }

    fn count_until_close(&mut self, n: u64) -> Result<()> {
        match self.body_bytes.checked_add(n) {
            Some(total) if total <= self.limits.max_body_bytes => {
                self.body_bytes = total;
                Ok(())
            }
            _ => http_err("response body exceeds the configured size limit"),
        }
    }

    /// Consumes `data`, which may hold any part of the response, and appends the body bytes it
    /// holds to `out`. Bytes after the end of the message are not consumed (and make the
    /// connection unfit for another request).
    pub(crate) fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if !data.is_empty() {
            self.seen = true;
        }
        let mut data = data;
        loop {
            match self.state {
                State::Done => {
                    if !data.is_empty() || self.buf.len() > self.pos {
                        self.extra = true;
                    }
                    return Ok(());
                }
                State::StatusLine | State::Headers | State::ChunkSize | State::ChunkEnd | State::Trailers(_) => {
                    // line states need contiguous bytes: everything goes through `buf`
                    self.buf.extend_from_slice(data);
                    data = &[];
                    if !self.step_line()? {
                        return Ok(());
                    }
                }
                State::Sized(n) | State::ChunkData(n) => {
                    let sized = matches!(self.state, State::Sized(_));
                    // leftover bytes in `buf` first, then the new data
                    let from_buf = ((self.buf.len() - self.pos) as u64).min(n) as usize;
                    out.extend_from_slice(&self.buf[self.pos..self.pos + from_buf]);
                    self.pos += from_buf;
                    let mut left = n - from_buf as u64;
                    let from_data = (data.len() as u64).min(left) as usize;
                    out.extend_from_slice(&data[..from_data]);
                    data = &data[from_data..];
                    left -= from_data as u64;
                    self.body_bytes += n - left;
                    if left > 0 {
                        self.state = if sized { State::Sized(left) } else { State::ChunkData(left) };
                        return Ok(());
                    }
                    if sized {
                        self.state = State::Done;
                        self.extra = !data.is_empty() || self.buf.len() > self.pos;
                        return Ok(());
                    }
                    self.state = State::ChunkEnd;
                    // bytes of `data` not consumed so far belong to what follows: put them in `buf`
                    // (the line state's branch above does it on the next turn)
                }
                State::UntilClose => {
                    let buffered = (self.buf.len() - self.pos) as u64;
                    self.count_until_close(buffered.saturating_add(data.len() as u64))?;
                    out.extend_from_slice(&self.buf[self.pos..]);
                    self.buf.clear();
                    self.pos = 0;
                    out.extend_from_slice(data);
                    return Ok(());
                }
            }
        }
    }

    /// The transport reached end of file. Fine for a read-until-close body or a finished
    /// message; an error anywhere else.
    pub(crate) fn finish_eof(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let partial = self.buf.len() > self.pos;
        let in_line = |closed: &str| if partial { eof("connection closed in the middle of a line") } else { eof(closed) };
        match self.state {
            State::Done => Ok(()),
            State::UntilClose => {
                let buffered = (self.buf.len() - self.pos) as u64;
                self.count_until_close(buffered)?;
                out.extend_from_slice(&self.buf[self.pos..]);
                self.buf.clear();
                self.pos = 0;
                self.state = State::Done;
                Ok(())
            }
            State::StatusLine => Err(in_line("connection closed before a response arrived")),
            State::Headers => Err(in_line("connection closed inside the response headers")),
            State::ChunkSize => Err(in_line("connection closed inside a chunked body")),
            State::Trailers(_) => Err(in_line("connection closed inside chunked trailers")),
            State::ChunkEnd => {
                if partial {
                    Err(eof("connection closed in the middle of a line"))
                } else {
                    http_err("missing CRLF after chunk data")
                }
            }
            State::Sized(_) | State::ChunkData(_) => Err(eof("connection closed before the full body arrived")),
        }
    }

    /// Takes one line (LF terminated, CR removed) from `buf`, if a whole one is there. A line
    /// longer than `max` is an error, complete or not.
    fn take_line(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        let rest = &self.buf[self.pos..];
        match rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let mut line = rest[..i].to_vec();
                self.pos += i + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > max {
                    return http_err("header line too long");
                }
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                Ok(Some(line))
            }
            None => {
                // a trailing CR is not part of the line (it is dropped once the LF arrives), so a
                // line of exactly `max` bytes must not be refused just because it is being read in
                // pieces and only its CR is here so far
                let content = if rest.last() == Some(&b'\r') { rest.len() - 1 } else { rest.len() };
                if content > max {
                    return http_err("header line too long");
                }
                if self.pos > 0 && self.pos >= self.buf.len() / 2 {
                    self.buf.drain(..self.pos);
                    self.pos = 0;
                }
                Ok(None)
            }
        }
    }

    /// Runs the current line state as far as the buffered bytes allow. Returns true if the state
    /// is now one that consumes bytes differently (so the caller should loop), false if more
    /// input is needed.
    fn step_line(&mut self) -> Result<bool> {
        let limits = self.limits;
        loop {
            match self.state {
                State::StatusLine => {
                    let Some(line) = self.take_line(limits.max_header_bytes)? else { return Ok(false) };
                    if line.is_empty() {
                        // tolerate a few leading blank lines
                        self.blank_lines += 1;
                        if self.blank_lines >= 4 {
                            return http_err("malformed response: no status line");
                        }
                        continue;
                    }
                    self.header_bytes += line.len();
                    let text = String::from_utf8_lossy(&line).into_owned();
                    let mut parts = text.splitn(3, ' ');
                    let version = parts.next().unwrap_or("");
                    if !version.starts_with("HTTP/1.") || version.len() != 8 || !version.as_bytes()[7].is_ascii_digit() {
                        // `take(60)` counts characters, so the cut can never fall inside a multi-byte sequence.
                        return http_err(format!("malformed status line: {:?}", text.chars().take(60).collect::<String>()));
                    }
                    self.minor = version.as_bytes()[7] - b'0';
                    let code = parts.next().unwrap_or("");
                    if code.len() != 3 || !code.bytes().all(|c| c.is_ascii_digit()) {
                        return http_err("malformed status code");
                    }
                    self.status = code.parse().unwrap_or(0);
                    self.reason = parts.next().unwrap_or("").to_string();
                    self.headers.clear();
                    self.state = State::Headers;
                }
                State::Headers => {
                    let Some(line) = self.take_line(limits.max_header_bytes)? else { return Ok(false) };
                    if line.is_empty() {
                        if (100..200).contains(&self.status) {
                            if self.status == 101 {
                                return http_err("unexpected protocol switch (101)");
                            }
                            // an interim response: the real one follows
                            self.continued |= self.status == 100;
                            self.blank_lines = 0;
                            self.state = State::StatusLine;
                            continue;
                        }
                        self.begin_body()?;
                        return Ok(true);
                    }
                    self.header_bytes += line.len() + 2;
                    if self.header_bytes > limits.max_header_bytes {
                        return http_err("response headers too large");
                    }
                    if line[0] == b' ' || line[0] == b'\t' {
                        return http_err("obsolete header line folding is not accepted");
                    }
                    let Some(colon) = line.iter().position(|&c| c == b':') else {
                        return http_err("malformed header line");
                    };
                    let name = std::str::from_utf8(&line[..colon]).map_err(|_| Error::Http("non-ASCII header name".into()))?;
                    if !is_valid_header_name(name) {
                        return http_err("invalid header name");
                    }
                    if line[colon + 1..].contains(&0) {
                        return http_err("NUL byte in header value");
                    }
                    let value = String::from_utf8_lossy(&line[colon + 1..]).trim_matches(|c| c == ' ' || c == '\t').to_string();
                    self.headers.push((name.to_string(), value));
                }
                State::ChunkSize => {
                    let Some(line) = self.take_line(4096)? else { return Ok(false) };
                    let size_part = line.split(|&c| c == b';').next().unwrap_or(&[]);
                    let size_str = std::str::from_utf8(size_part).map_err(|_| Error::Http("bad chunk size".into()))?.trim();
                    if size_str.is_empty() || size_str.len() > 16 || !size_str.bytes().all(|c| c.is_ascii_hexdigit()) {
                        return http_err("bad chunk size");
                    }
                    let size = u64::from_str_radix(size_str, 16).map_err(|_| Error::Http("bad chunk size".into()))?;
                    if size == 0 {
                        self.state = State::Trailers(0);
                    } else {
                        // checked: a size near u64::MAX must not wrap around to "fits" and let the
                        // body grow past the limit (chunk data is not checked again as it arrives)
                        if self.body_bytes.checked_add(size).map_or(true, |total| total > limits.max_body_bytes) {
                            return http_err("response body exceeds the configured size limit");
                        }
                        self.state = State::ChunkData(size);
                        return Ok(true);
                    }
                }
                State::Trailers(seen) => {
                    let Some(t) = self.take_line(limits.max_header_bytes)? else { return Ok(false) };
                    if t.is_empty() {
                        self.state = State::Done;
                        return Ok(true);
                    }
                    let seen = seen + t.len();
                    if seen > limits.max_header_bytes {
                        return http_err("chunked trailers too large");
                    }
                    self.state = State::Trailers(seen);
                }
                State::ChunkEnd => {
                    let Some(l) = self.take_line(8)? else { return Ok(false) };
                    if !l.is_empty() {
                        return http_err("missing CRLF after chunk data");
                    }
                    self.state = State::ChunkSize;
                }
                _ => return Ok(true),
            }
        }
    }

    /// The headers are complete: decide how the body is framed and whether the connection can be
    /// used again, and make the head available.
    fn begin_body(&mut self) -> Result<()> {
        let connection: Vec<String> =
            header_values(&self.headers, "connection").flat_map(|v| v.split(',')).map(|t| t.trim().to_ascii_lowercase()).collect();
        let close = connection.iter().any(|t| t == "close");
        let keep_alive = connection.iter().any(|t| t == "keep-alive");
        self.persistent = !close && (self.minor >= 1 || keep_alive);

        let no_body = self.head_request || self.status == 204 || self.status == 304;
        let te: Vec<&str> = header_values(&self.headers, "transfer-encoding").collect();
        let mut content_length = None;
        if no_body {
            // the declared length is only information here: it is not what frames the message
            content_length = parse_content_length(&self.headers).ok().flatten();
            self.state = State::Done;
        } else if !te.is_empty() {
            let encodings: Vec<String> =
                te.iter().flat_map(|v| v.split(',')).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
            if encodings.last().map(String::as_str) != Some("chunked") || encodings.iter().any(|e| e != "chunked" && e != "identity") {
                return http_err(format!("unsupported Transfer-Encoding: {}", te.join(", ")));
            }
            // a message with both framings is what request smuggling is made of: it is read, but
            // the connection is not trusted with another request
            if header_values(&self.headers, "content-length").next().is_some() {
                self.persistent = false;
            }
            self.state = State::ChunkSize;
        } else if let Some(len) = parse_content_length(&self.headers)? {
            if len > self.limits.max_body_bytes {
                return http_err("response body exceeds the configured size limit");
            }
            content_length = Some(len);
            self.state = if len == 0 { State::Done } else { State::Sized(len) };
        } else {
            let buffered = (self.buf.len() - self.pos) as u64;
            if buffered > self.limits.max_body_bytes {
                return http_err("response body exceeds the configured size limit");
            }
            self.persistent = false;
            self.state = State::UntilClose;
        }
        self.head = Some(Head {
            status: self.status,
            reason: std::mem::take(&mut self.reason),
            headers: std::mem::take(&mut self.headers),
            content_length,
        });
        self.head_complete = true;
        Ok(())
    }
}

fn header_values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn parse_content_length(headers: &[(String, String)]) -> Result<Option<u64>> {
    let mut found: Option<u64> = None;
    for v in header_values(headers, "content-length") {
        for part in v.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return http_err("invalid Content-Length");
            }
            let n: u64 = part.parse().map_err(|_| Error::Http("invalid Content-Length".into()))?;
            match found {
                Some(prev) if prev != n => return http_err("conflicting Content-Length values"),
                _ => found = Some(n),
            }
        }
    }
    Ok(found)
}

/// The `timeout` the server announced in a `Keep-Alive: timeout=5, max=1000` header: how long it
/// will keep an idle connection open.
pub(crate) fn keep_alive_timeout(headers: &[(String, String)]) -> Option<Duration> {
    header_values(headers, "keep-alive")
        .flat_map(|v| v.split(','))
        .filter_map(|p| p.trim().strip_prefix("timeout=").map(str::trim).and_then(|n| n.parse::<u64>().ok()))
        .min()
        .map(Duration::from_secs)
}

/// A parser that collects the whole response: the head, then every body byte in one `Vec`.
/// What the tests and the fuzzer use to look at a message as a whole.
#[cfg(any(test, pratique_fuzzing))]
pub(crate) struct Buffered {
    pub(crate) parser: ResponseParser,
    pub(crate) body: Vec<u8>,
    head: Option<Head>,
}

#[cfg(any(test, pratique_fuzzing))]
impl Buffered {
    pub(crate) fn new(request_method: &str, limits: Limits) -> Buffered {
        Buffered { parser: ResponseParser::new(request_method, limits), body: Vec::new(), head: None }
    }

    fn collect_head(&mut self) {
        if self.head.is_none() {
            self.head = self.parser.take_head();
        }
    }

    pub(crate) fn feed(&mut self, data: &[u8]) -> Result<()> {
        let r = self.parser.feed(data, &mut self.body);
        self.collect_head();
        r
    }

    pub(crate) fn finish_eof(&mut self) -> Result<()> {
        let r = self.parser.finish_eof(&mut self.body);
        self.collect_head();
        r
    }

    pub(crate) fn is_done(&self) -> bool {
        self.parser.is_done()
    }

    pub(crate) fn max_read(&self) -> usize {
        self.parser.max_read()
    }

    /// The finished response. Panics if the headers were never completed.
    pub(crate) fn into_response(mut self) -> super::wire::RawResponse {
        self.collect_head();
        let head = self.head.expect("a response whose headers were never completed");
        super::wire::RawResponse { status: head.status, reason: head.reason, headers: head.headers, body: self.body }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::wire::RawResponse;

    fn parse_in_pieces(raw: &[u8], method: &str, piece: usize) -> Result<RawResponse> {
        let mut p = Buffered::new(method, Limits::default());
        for chunk in raw.chunks(piece) {
            p.feed(chunk)?;
            if p.is_done() {
                return Ok(p.into_response());
            }
        }
        p.finish_eof()?;
        Ok(p.into_response())
    }

    #[test]
    fn any_piece_size_gives_the_same_response() {
        let chunked = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n5;ext=1\r\nhello\r\n0\r\nTrailer: x\r\n\r\n";
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
        let closed = b"HTTP/1.0 200 OK\r\n\r\nuntil the end";
        for (raw, body) in [(&chunked[..], &b"hello"[..]), (&sized[..], b"hello world"), (&closed[..], b"until the end")] {
            for piece in [1, 2, 3, 5, 7, 64, 10_000] {
                let r = parse_in_pieces(raw, "GET", piece).unwrap();
                assert_eq!((r.status, r.body.as_slice()), (200, body), "piece size {piece}");
            }
        }
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_accepted_however_it_is_read() {
        // found by the fuzzer: the CR of a line of exactly `max` bytes counted against it while
        // the line was incomplete, so reading byte by byte refused what reading at once accepted
        let limits = Limits { max_header_bytes: 64, max_body_bytes: 100 };
        let status = format!("HTTP/1.1 204 {}", "x".repeat(64 - 13));
        assert_eq!(status.len(), 64);
        let raw = format!("{status}\r\n\r\n");
        let too_long = raw.replacen("xx", "xxx", 1);
        for piece in [1, 2, 3, 63, 64, 65, 66, 1000] {
            let run = |text: &str| {
                let mut p = Buffered::new("GET", limits);
                text.as_bytes().chunks(piece).try_for_each(|c| p.feed(c)).and_then(|_| p.finish_eof()).map(|_| p.into_response().status)
            };
            assert_eq!(run(&raw).unwrap(), 204, "piece size {piece}");
            assert!(run(&too_long).is_err(), "a 65-byte line was accepted with piece size {piece}");
        }
    }

    #[test]
    fn a_huge_chunk_size_cannot_wrap_around_the_body_limit() {
        // found by the fuzzer: `body.len() + size` overflowed, which panics in a debug build and
        // wraps to a small number (so the limit was skipped) in a release build
        let limits = Limits { max_header_bytes: 1024, max_body_bytes: 100 };
        for size in ["ffffffffffffffff", "fffffffffffffffe", "8000000000000000", "ffffffffffffff9b", "65"] {
            let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n{size}\r\n");
            let mut p = Buffered::new("GET", limits);
            let r = raw.as_bytes().chunks(7).try_for_each(|c| p.feed(c));
            assert!(r.is_err(), "a second chunk of {size} bytes after 1 byte was accepted under a limit of 100");
        }
        // the limit itself is still reachable
        let ok = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n63\r\n".to_string() + &"b".repeat(99) + "\r\n0\r\n\r\n";
        let mut p = Buffered::new("GET", limits);
        p.feed(ok.as_bytes()).unwrap();
        assert!(p.is_done());
        assert_eq!(p.into_response().body.len(), 100);
    }

    #[test]
    fn truncation_is_an_error_in_every_framing_except_read_until_close() {
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert!(parse_in_pieces(sized, "GET", 4).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n";
        assert!(parse_in_pieces(chunked, "GET", 4).is_err());
        assert!(parse_in_pieces(b"HTTP/1.1 200 OK\r\nX: y\r\n", "GET", 4).is_err());
        assert!(parse_in_pieces(b"", "GET", 4).is_err());
        assert_eq!(parse_in_pieces(b"HTTP/1.0 200 OK\r\n\r\npartial", "GET", 4).unwrap().body, b"partial");
    }

    #[test]
    fn a_sized_body_never_asks_for_bytes_past_its_end() {
        let mut p = Buffered::new("GET", Limits::default());
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").unwrap();
        assert_eq!(p.max_read(), 7);
        p.feed(b"defghijEXTRA").unwrap();
        assert!(p.is_done() && p.max_read() == 0);
        assert_eq!(p.into_response().body, b"abcdefghij");
    }

    // ---------------------------------------------------------------------------- reuse of the connection

    /// Feeds `raw` in pieces of `piece` bytes and returns (done, reusable) after the last one.
    fn reusable_after(raw: &[u8], method: &str, piece: usize) -> (bool, bool) {
        let mut p = Buffered::new(method, Limits::default());
        for chunk in raw.chunks(piece) {
            p.feed(chunk).unwrap();
        }
        if !p.is_done() {
            let _ = p.finish_eof();
        }
        (p.is_done(), p.parser.reusable())
    }

    #[test]
    fn what_may_carry_another_request() {
        let cases: &[(&str, &[u8], &str, bool)] = &[
            ("http/1.1 sized", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", "GET", true),
            ("http/1.1 chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", "GET", true),
            ("http/1.1 chunked with trailers", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nT: v\r\n\r\n", "GET", true),
            ("no body: 204", b"HTTP/1.1 204 No Content\r\n\r\n", "GET", true),
            ("no body: 304", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n", "GET", true),
            ("no body: HEAD", b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", "HEAD", true),
            ("empty body", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "GET", true),
            ("after an interim response", b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", "POST", true),
            ("connection: close", b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi", "GET", false),
            ("connection: Close, TE", b"HTTP/1.1 200 OK\r\nConnection: TE, Close\r\nContent-Length: 2\r\n\r\nhi", "GET", false),
            ("connection: keep-alive", b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nhi", "GET", true),
            ("http/1.0", b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi", "GET", false),
            ("http/1.0 keep-alive", b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 2\r\n\r\nhi", "GET", true),
            ("http/1.0 keep-alive then close", b"HTTP/1.0 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 2\r\n\r\nhi", "GET", false),
            ("until close", b"HTTP/1.1 200 OK\r\n\r\nall of it", "GET", false),
            ("both framings", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", "GET", false),
            ("bytes after a sized body", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA", "GET", false),
            ("bytes after a chunked body", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\nEXTRA", "GET", false),
            ("bytes after no body", b"HTTP/1.1 204 No Content\r\n\r\nEXTRA", "GET", false),
            ("bytes after an empty body", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nEXTRA", "GET", false),
        ];
        for (name, raw, method, want) in cases {
            for piece in [1usize, 3, 1000] {
                let (done, reusable) = reusable_after(raw, method, piece);
                assert!(done, "{name}: not complete (piece {piece})");
                // the pieces that stop exactly at the end of the message cannot see the extra bytes, so
                // only whole-message and every-piece-size runs that contain them are compared
                assert_eq!(reusable, *want, "{name} (piece {piece})");
            }
        }
    }

    #[test]
    fn a_message_is_not_reusable_before_it_is_complete() {
        let mut p = Buffered::new("GET", Limits::default());
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab").unwrap();
        assert!(!p.parser.reusable() && p.parser.head_complete());
        p.feed(b"cd").unwrap();
        assert!(p.parser.reusable());
    }

    #[test]
    fn the_head_is_available_before_the_body_and_only_once() {
        let mut p = ResponseParser::new("GET", Limits::default());
        let mut body = Vec::new();
        assert!(!p.started() && !p.head_complete());
        p.feed(b"HTTP/1.1 200 OK\r\nX-A: b\r\nContent-Length: 6\r\n\r\nab", &mut body).unwrap();
        assert!(p.started() && p.head_complete() && !p.is_done());
        let head = p.take_head().unwrap();
        assert_eq!((head.status, head.reason.as_str(), head.content_length), (200, "OK", Some(6)));
        assert_eq!(head.headers[0], ("X-A".to_string(), "b".to_string()));
        assert_eq!(body, b"ab");
        assert!(p.take_head().is_none());
    }

    #[test]
    fn the_declared_length_of_a_head_response_is_reported_but_frames_nothing() {
        let mut p = ResponseParser::new("HEAD", Limits::default());
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", &mut Vec::new()).unwrap();
        assert!(p.is_done());
        let head = p.take_head().unwrap();
        assert_eq!(head.content_length, Some(1234));
        // a chunked response declares no length, and neither does one with nothing declared
        for raw in ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"] {
            let mut p = ResponseParser::new("GET", Limits::default());
            p.feed(raw.as_bytes(), &mut Vec::new()).unwrap();
            assert_eq!(p.take_head().unwrap().content_length, None);
        }
    }

    #[test]
    fn bytes_read_straight_from_the_transport_are_counted_like_fed_ones() {
        // sized: the head and a first piece through `feed`, the rest directly, then another message's bytes are extra
        let mut p = ResponseParser::new("GET", Limits::default());
        let mut body = Vec::new();
        assert_eq!(p.direct_window(), 0);
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", &mut body).unwrap();
        assert_eq!(p.direct_window(), 7);
        p.consume_direct(4).unwrap();
        assert_eq!(p.direct_window(), 3);
        p.consume_direct(3).unwrap();
        assert!(p.is_done() && p.reusable());
        assert_eq!(p.direct_window(), 0);
        assert_eq!(body, b"abc", "directly read bytes are the caller's, not the parser's");
        // more than is left is a misuse, never a panic or a wrong state
        let mut p = ResponseParser::new("GET", Limits::default());
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", &mut body).unwrap();
        assert!(p.consume_direct(3).is_err());
        assert!(p.consume_direct(2).is_ok() && p.is_done());
        assert!(p.consume_direct(1).is_err());
    }

    #[test]
    fn a_chunked_body_can_be_read_directly_inside_a_chunk_only() {
        let mut p = ResponseParser::new("GET", Limits::default());
        let mut body = Vec::new();
        p.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", &mut body).unwrap();
        assert_eq!(p.direct_window(), 0, "a chunk size line comes next");
        p.feed(b"6\r\nabc", &mut body).unwrap();
        assert_eq!(p.direct_window(), 3);
        p.consume_direct(3).unwrap();
        assert_eq!(p.direct_window(), 0, "the CRLF after the chunk comes next");
        p.feed(b"\r\n0\r\n\r\n", &mut body).unwrap();
        assert!(p.is_done() && p.reusable());
        assert_eq!(body, b"abc");
    }

    #[test]
    fn a_body_that_runs_to_the_close_is_limited_when_read_directly() {
        let limits = Limits { max_header_bytes: 1024, max_body_bytes: 10 };
        let mut p = ResponseParser::new("GET", limits);
        let mut body = Vec::new();
        p.feed(b"HTTP/1.0 200 OK\r\n\r\n", &mut body).unwrap();
        assert_eq!(p.direct_window(), usize::MAX);
        p.consume_direct(10).unwrap();
        assert!(p.consume_direct(1).is_err());
        assert!(!p.reusable());
        p.finish_eof(&mut body).unwrap();
        assert!(p.is_done() && !p.reusable());
    }

    #[test]
    fn the_direct_window_is_closed_while_the_parser_holds_unread_bytes() {
        let mut p = ResponseParser::new("GET", Limits::default());
        let mut body = Vec::new();
        // the headers end the buffer's content exactly: nothing is held
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", &mut body).unwrap();
        assert_eq!(p.direct_window(), 4);
        // a parser given more than it can use in one go keeps no body bytes either
        let mut p = ResponseParser::new("GET", Limits::default());
        p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab", &mut body).unwrap();
        assert_eq!(p.direct_window(), 2);
    }

    #[test]
    fn the_keep_alive_header_says_how_long_the_server_waits() {
        let h = |v: &str| vec![("Keep-Alive".to_string(), v.to_string())];
        assert_eq!(keep_alive_timeout(&h("timeout=5, max=1000")), Some(Duration::from_secs(5)));
        assert_eq!(keep_alive_timeout(&h("max=1000,timeout=60")), Some(Duration::from_secs(60)));
        assert_eq!(keep_alive_timeout(&h("max=1000")), None);
        assert_eq!(keep_alive_timeout(&h("timeout=abc")), None);
        assert_eq!(keep_alive_timeout(&h("timeout=-1")), None);
        assert_eq!(keep_alive_timeout(&[]), None);
        // the smallest announcement wins when there are several
        let two = vec![("Keep-Alive".to_string(), "timeout=30".to_string()), ("keep-alive".to_string(), "timeout=7".to_string())];
        assert_eq!(keep_alive_timeout(&two), Some(Duration::from_secs(7)));
    }

    #[test]
    fn the_http_version_must_be_a_digit() {
        for line in ["HTTP/1.x 200 OK", "HTTP/1.  200 OK", "HTTP/1.10 200 OK", "HTTP/2.0 200 OK"] {
            let raw = format!("{line}\r\nContent-Length: 0\r\n\r\n");
            assert!(parse_in_pieces(raw.as_bytes(), "GET", 100).is_err(), "{line}");
        }
    }
}
