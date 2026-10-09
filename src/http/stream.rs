//! Streaming responses for the blocking client: the connection, the parser and the pool a finished
//! connection goes back to.
//!
//! [`ResponseStream`] is what `send_stream` returns: the head of the response (status, headers and
//! declared length) is there to read as soon as it has arrived, and the body is read from it as a
//! [`Read`]. While the transport's next bytes are all body (a sized body, the data of a chunk, a
//! body that runs to the end of the connection) they are read straight into the caller's buffer;
//! only chunk framing passes through a scratch buffer. When the body has been read to its end and
//! the connection is fit for another request, the connection goes back to the client's pool.

use super::decode::{BodyDecoder, Next};
use super::h2_transport::{Failure as MuxFailure, H2Stream, Waits};
use super::h3_transport::H3Stream;
use super::idle::{IdlePool, Key, Policy};
use super::parser::{keep_alive_timeout, Head, ResponseParser};
use super::wire::Limits;
use super::{HttpVersion, Response, Url};
use crate::asyncio::net::Io;
use crate::asyncio::slots::Slots;
use crate::error::{Error, Result};
use crate::inflate::{Format, Limits as InflateLimits};
use crate::tls::{TlsStream, TlsVersion};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Size of the buffer that chunk framing and the headers pass through.
const SCRATCH: usize = 32 * 1024;

thread_local! {
    /// The buffer of a response that was finished on this thread, for the next one: a new buffer is zeroed (32 KiB), which
    /// for a small response on a connection that is used again was a good part of the work (BACKLOG B-90). What it holds
    /// from before is never looked at: only what a read writes into it is.
    static SPARE_SCRATCH: Cell<Option<Vec<u8>>> = const { Cell::new(None) };
}

/// A buffer of `SCRATCH` bytes: the spare one, if this thread has it.
fn scratch_buffer() -> Vec<u8> {
    SPARE_SCRATCH.with(Cell::take).filter(|b| b.len() == SCRATCH).unwrap_or_else(|| vec![0u8; SCRATCH])
}

/// Where this thread's spare buffer is, if it has one (tests).
#[cfg(test)]
pub(super) fn spare_scratch() -> Option<usize> {
    SPARE_SCRATCH.with(|s| {
        let b = s.take();
        let at = b.as_ref().map(|b| b.as_ptr() as usize);
        s.set(b);
        at
    })
}

/// Plain or TLS, so the request code does not care which.
pub(super) enum Conn {
    Plain(Io),
    Tls(Box<TlsStream<Io>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

impl Conn {
    /// The version of TLS spoken, if any.
    pub(super) fn tls_version(&self) -> Option<TlsVersion> {
        match self {
            Conn::Plain(_) => None,
            Conn::Tls(s) => s.protocol_version(),
        }
    }

    pub(super) fn io_mut(&mut self) -> &mut Io {
        match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => s.get_mut(),
        }
    }

    /// Digests what arrived along with the end of the last response and says whether the
    /// connection is fit to wait for another request.
    fn settle(&mut self) -> bool {
        match self {
            Conn::Plain(_) => true,
            Conn::Tls(s) => s.settle(),
        }
    }
}

/// Where a finished connection goes if it can be used again.
pub(super) struct Home {
    pub(super) pool: Arc<IdlePool<Conn>>,
    pub(super) key: Key,
    pub(super) policy: Policy,
    /// The client's per-host connection limit, whose waiters are told when a connection is parked.
    pub(super) slots: Option<std::sync::Arc<Slots>>,
}

/// Why a request got no response, and whether trying again on a new connection is sound.
pub(super) struct Failure {
    pub(super) error: Error,
    /// The connection was closed by the peer before any byte of the response arrived. On a
    /// connection that had been idle this is what a server that closed it in the meantime looks like.
    pub(super) peer_closed: bool,
}

/// An error that says the peer is gone rather than slow or unhappy.
pub(super) fn is_peer_close(e: &Error) -> bool {
    use io::ErrorKind::*;
    matches!(e, Error::Io(e) if matches!(e.kind(), UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected))
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// The connection, the parser and the not-yet-delivered body bytes of one response.
pub(super) struct BodyReader {
    conn: Option<Conn>,
    parser: ResponseParser,
    home: Option<Home>,
    /// Body bytes the parser produced that have not been handed out: `pending[pos..]`.
    pending: Vec<u8>,
    pos: usize,
    scratch: Vec<u8>,
    failed: bool,
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        if self.scratch.len() == SCRATCH {
            let spare = std::mem::take(&mut self.scratch);
            SPARE_SCRATCH.with(|s| s.set(Some(spare)));
        }
    }
}

impl BodyReader {
    pub(super) fn new(conn: Conn, method: &str, limits: Limits, home: Option<Home>) -> BodyReader {
        BodyReader { conn: Some(conn), parser: ResponseParser::new(method, limits), home, pending: Vec::new(), pos: 0, scratch: Vec::new(), failed: false }
    }

    /// Sends the request on the connection and waits for the head of the response.
    pub(super) fn send_request(&mut self, head: &[u8], body: &[u8], small: bool) -> std::result::Result<(), Failure> {
        let conn = self.conn.as_mut().expect("a connection");
        let sent = if small {
            let mut one = Vec::with_capacity(head.len() + body.len());
            one.extend_from_slice(head);
            one.extend_from_slice(body);
            conn.write_all(&one)
        } else {
            // a large upload goes from the caller's slice, not through a second copy of it
            conn.write_all(head).and_then(|_| conn.write_all(body))
        };
        sent.and_then(|_| conn.flush()).map_err(|e| {
            let error = Error::Io(e);
            Failure { peer_closed: is_peer_close(&error), error }
        })
    }

    /// Sends a request that says `Expect: 100-continue`: the head, then a wait of up to `wait` for the server's word on it, then the
    /// body. A `100 Continue` ends the wait at once; so does the final response, if the server answers before the body (a refusal, a
    /// redirect, a demand for credentials, a 417), and then the body is never sent and the connection, on which the server may
    /// still be expecting it, is not used again. A server that says nothing in time gets the body all the same (RFC 9110, 10.1.1).
    pub(super) fn send_request_expecting_continue(&mut self, head: &[u8], body: &[u8], wait: Duration) -> std::result::Result<(), Failure> {
        fn failure(e: io::Error) -> Failure {
            let error = Error::Io(e);
            Failure { peer_closed: is_peer_close(&error), error }
        }
        if self.scratch.is_empty() {
            self.scratch = scratch_buffer();
        }
        let conn = self.conn.as_mut().expect("a connection");
        conn.write_all(head).and_then(|_| conn.flush()).map_err(failure)?;
        // the wait: a shorter timeout on the socket for as long as it lasts (never past the request's deadline)
        let (timeout, deadline) = (conn.io_mut().timeout, conn.io_mut().deadline);
        let left = deadline.map_or(wait, |d| wait.min(d.saturating_duration_since(Instant::now())));
        let short = left.max(Duration::from_millis(1));
        conn.io_mut().rearm(short, deadline).map_err(failure)?;
        let mut outcome = Ok(());
        while !self.parser.continued() && !self.parser.head_complete() {
            let want = self.parser.max_read().min(self.scratch.len());
            let read = match conn.read(&mut self.scratch[..want]) {
                Ok(0) => match self.parser.finish_eof(&mut self.pending) {
                    Err(e) => Err(e),
                    Ok(()) => Err(Error::Http("the connection was closed before the response".into())),
                },
                Ok(n) => self.parser.feed(&self.scratch[..n], &mut self.pending),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                // no word in time (and the request's own time is not up): the body goes
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) && !deadline.is_some_and(|d| Instant::now() >= d) => break,
                Err(e) => Err(Error::Io(e)),
            };
            if let Err(error) = read {
                outcome = Err(Failure { peer_closed: !self.parser.started() && is_peer_close(&error), error });
                break;
            }
        }
        let restored = conn.io_mut().rearm(timeout, deadline);
        if let Err(f) = outcome {
            self.conn = None;
            self.failed = true;
            return Err(f);
        }
        restored.map_err(failure)?;
        if self.parser.head_complete() {
            // the answer came before the body: it is the response, and the body stays here
            self.home = None;
            return Ok(());
        }
        conn.write_all(body).and_then(|_| conn.flush()).map_err(failure)
    }

    /// Reads until the headers of the final response are complete and returns them. The pool
    /// takes the connection back at once if the response has no body to read.
    pub(super) fn receive_head(&mut self) -> std::result::Result<Head, Failure> {
        if self.scratch.is_empty() {
            self.scratch = scratch_buffer();
        }
        while !self.parser.head_complete() {
            let want = self.parser.max_read().min(self.scratch.len());
            let conn = self.conn.as_mut().expect("a connection");
            let outcome = match conn.read(&mut self.scratch[..want]) {
                Ok(0) => match self.parser.finish_eof(&mut self.pending) {
                    Err(e) => Err(e),
                    Ok(()) => Err(Error::Http("the response ended before its headers were complete".into())),
                },
                Ok(n) => self.parser.feed(&self.scratch[..n], &mut self.pending),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                Err(e) => Err(Error::Io(e)),
            };
            if let Err(error) = outcome {
                let peer_closed = !self.parser.started() && is_peer_close(&error);
                self.conn = None;
                self.failed = true;
                return Err(Failure { error, peer_closed });
            }
        }
        let head = self.parser.take_head().expect("the head was complete");
        if let Some(home) = &mut self.home {
            // the server says how long it will wait: never wait longer than that for it
            if let Some(t) = keep_alive_timeout(&head.headers) {
                home.policy.idle_timeout = home.policy.idle_timeout.min(t);
            }
        }
        if self.parser.is_done() {
            self.complete();
        }
        Ok(head)
    }

    /// The message has been read to its end: the connection goes back to the pool if it can be used
    /// again and is closed otherwise.
    fn complete(&mut self) {
        let (Some(mut conn), Some(home)) = (self.conn.take(), self.home.take()) else { return };
        if self.parser.reusable() && home.policy.parks() && conn.settle() {
            home.pool.put(home.key, conn, home.policy.idle_timeout, &home.policy, Instant::now());
            if let Some(slots) = &home.slots {
                slots.poke();
            }
        }
    }

    fn broken(&mut self, e: Error) -> Error {
        self.conn = None;
        self.home = None;
        self.failed = true;
        e
    }

    /// Reads body bytes into `out`; 0 is the end of the body. The size limit, the framing and the
    /// timeouts are enforced here.
    pub(super) fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(Error::Http("the response failed earlier and cannot be read further".into()));
        }
        loop {
            if self.pos < self.pending.len() {
                let n = (self.pending.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            self.pending.clear();
            self.pos = 0;
            if self.parser.is_done() {
                self.complete();
                return Ok(0);
            }
            let Some(conn) = self.conn.as_mut() else { return Ok(0) };
            let window = self.parser.direct_window();
            if window > 0 {
                // body bytes that need no parsing go straight to the caller
                let want = window.min(out.len());
                match conn.read(&mut out[..want]) {
                    Ok(0) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Err(self.broken(e));
                        }
                    }
                    Ok(n) => {
                        if let Err(e) = self.parser.consume_direct(n) {
                            return Err(self.broken(e));
                        }
                        if self.parser.is_done() {
                            self.complete();
                        }
                        return Ok(n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(self.broken(Error::Io(e))),
                }
            } else {
                if self.scratch.is_empty() {
                    self.scratch = scratch_buffer();
                }
                let want = self.parser.max_read().min(self.scratch.len());
                match conn.read(&mut self.scratch[..want]) {
                    Ok(0) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Err(self.broken(e));
                        }
                    }
                    Ok(n) => {
                        if let Err(e) = self.parser.feed(&self.scratch[..n], &mut self.pending) {
                            return Err(self.broken(e));
                        }
                        if self.parser.is_done() {
                            self.complete();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(self.broken(Error::Io(e))),
                }
            }
        }
    }

    /// Reads and drops up to `limit` bytes of what is left of the body, so that a connection whose
    /// response nobody wants (a redirect's) can be used again. Gives up, and closes the connection,
    /// beyond that.
    pub(super) fn discard(&mut self, limit: u64) {
        let mut sink = [0u8; 8192];
        let mut seen = 0u64;
        while seen < limit {
            match self.read_body(&mut sink) {
                Ok(0) => return,
                Ok(n) => seen += n as u64,
                Err(_) => return,
            }
        }
        // too much to be worth it
        self.conn = None;
        self.home = None;
    }
}

/// A stream on a connection that other requests share: HTTP/2's or HTTP/3's.
pub(super) enum MuxStream {
    H2(H2Stream),
    H3(H3Stream),
}

impl MuxStream {
    fn read(&mut self, out: &mut [u8], waits: Waits) -> std::result::Result<usize, MuxFailure> {
        match self {
            MuxStream::H2(s) => s.read(out, waits),
            MuxStream::H3(s) => s.read(out, waits),
        }
    }

    fn collect(&mut self, limit: u64, waits: Waits) -> std::result::Result<Vec<u8>, MuxFailure> {
        match self {
            MuxStream::H2(s) => s.collect(limit, waits),
            MuxStream::H3(s) => s.collect(limit, waits),
        }
    }
}

/// The body of an HTTP/2 or HTTP/3 response: a stream on a connection that other requests share.
pub(super) struct MuxBody {
    /// Gone once the body has been read to its end, has failed, or has been given up.
    stream: Option<MuxStream>,
    waits: Waits,
    max: u64,
    seen: u64,
    ended: bool,
    failed: bool,
    /// The whole body, if it was waited for along with the head (see [`H2Stream::response`]): `whole[whole_pos..]` is
    /// what has not been read.
    whole: Vec<u8>,
    whole_pos: usize,
}

impl MuxBody {
    pub(super) fn new(stream: H2Stream, waits: Waits, limits: Limits) -> MuxBody {
        MuxBody { stream: Some(MuxStream::H2(stream)), waits, max: limits.max_body_bytes, seen: 0, ended: false, failed: false, whole: Vec::new(), whole_pos: 0 }
    }

    /// The body of a response that came over HTTP/3.
    pub(super) fn new_h3(stream: H3Stream, waits: Waits, limits: Limits) -> MuxBody {
        MuxBody { stream: Some(MuxStream::H3(stream)), waits, max: limits.max_body_bytes, seen: 0, ended: false, failed: false, whole: Vec::new(), whole_pos: 0 }
    }

    /// A body that is all here already.
    pub(super) fn complete(body: Vec<u8>, waits: Waits, limits: Limits) -> MuxBody {
        MuxBody { stream: None, waits, max: limits.max_body_bytes, seen: 0, ended: false, failed: false, whole: body, whole_pos: 0 }
    }

    fn limit(&self) -> u64 {
        self.max
    }

    fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() || self.ended {
            return Ok(0);
        }
        if self.failed {
            return Err(Error::Http("the response failed earlier and cannot be read further".into()));
        }
        if self.whole_pos < self.whole.len() {
            let n = (self.whole.len() - self.whole_pos).min(out.len());
            out[..n].copy_from_slice(&self.whole[self.whole_pos..self.whole_pos + n]);
            self.whole_pos += n;
            self.seen += n as u64;
            return Ok(n);
        }
        let Some(stream) = self.stream.as_mut() else { return Ok(0) };
        match stream.read(out, self.waits) {
            Ok(0) => {
                self.ended = true;
                self.stream = None;
                Ok(0)
            }
            Ok(n) => {
                self.seen += n as u64;
                if self.seen > self.max {
                    self.failed = true;
                    self.stream = None;
                    return Err(Error::Http("response body exceeds the configured size limit".into()));
                }
                Ok(n)
            }
            Err(f) => {
                self.failed = true;
                self.stream = None;
                Err(f.error)
            }
        }
    }

    /// What is left of the body, all of it, as one buffer: the connection keeps the body in one as it comes, and
    /// hands it over (see [`H2Stream::collect`]).
    fn collect(&mut self) -> Result<Vec<u8>> {
        if self.ended {
            return Ok(Vec::new());
        }
        if self.failed {
            return Err(Error::Http("the response failed earlier and cannot be read further".into()));
        }
        if !self.whole.is_empty() || self.stream.is_none() {
            // it is all here (the part of it that was not read)
            let mut body = std::mem::take(&mut self.whole);
            body.drain(..self.whole_pos.min(body.len()));
            self.whole_pos = 0;
            self.ended = true;
            return Ok(body);
        }
        let Some(stream) = self.stream.as_mut() else { return Ok(Vec::new()) };
        match stream.collect(self.max, self.waits) {
            Ok(body) => {
                self.seen += body.len() as u64;
                self.ended = true;
                self.stream = None;
                Ok(body)
            }
            Err(f) => {
                self.failed = true;
                self.stream = None;
                Err(f.error)
            }
        }
    }

    /// Reads and drops up to `limit` bytes of what is left; a larger rest is cancelled (the connection is not
    /// affected, other requests go on).
    fn discard(&mut self, limit: u64) {
        let mut sink = [0u8; 8192];
        let mut seen = 0u64;
        while seen < limit {
            match self.read_body(&mut sink) {
                Ok(0) | Err(_) => return,
                Ok(n) => seen += n as u64,
            }
        }
        self.stream = None;
    }
}

/// Where a response's body comes from.
pub(super) enum Body {
    H1(BodyReader),
    Mux(MuxBody),
}

impl Body {
    fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Body::H1(b) => b.read_body(out),
            Body::Mux(b) => b.read_body(out),
        }
    }

    fn discard(&mut self, limit: u64) {
        match self {
            Body::H1(b) => b.discard(limit),
            Body::Mux(b) => b.discard(limit),
        }
    }

    /// True if there is nothing more to read from the transport.
    fn is_done(&self) -> bool {
        match self {
            Body::H1(b) => b.parser.is_done(),
            Body::Mux(b) => b.ended,
        }
    }
}

/// A response whose head has arrived and whose body is read as it comes.
///
/// `status`, `headers` and `content_length` are known when this is returned; the body is read with
/// [`Read`] (or [`into_response`](ResponseStream::into_response) buffers what is left). The body is
/// limited by the client's [`max_body_bytes`](super::Client::max_body_bytes) (or the request's own)
/// and by the client's timeouts, including the total time limit. A body over the limit is an error,
/// and when it is reported depends on what the server sent: the request itself fails if the head
/// declares a length over the limit or if the first read already holds more than the limit, and a
/// later read fails otherwise. A connection whose body was read to its end may be reused; dropping
/// the stream earlier closes it.
///
/// If the client decodes compressed bodies ([`Client::decompress`](super::Client::decompress)) and this one came as `gzip` or
/// `deflate`, what is read is the decoded body, [`uncompressed`](ResponseStream::uncompressed) is true, `content_length` is `None`
/// and the headers have no `Content-Encoding` and no `Content-Length`. The decoder fails a read with
/// [`Error::Decode`] when the stream is not valid, is cut short or passes a limit on the decoded size; nothing more is read after that.
pub struct ResponseStream {
    pub status: u16,
    /// The reason phrase of the status line; empty over HTTP/2 and HTTP/3, which have none.
    pub reason: String,
    /// The protocol the response came over.
    pub version: HttpVersion,
    pub headers: Vec<(String, String)>,
    /// The URL that produced this response (after redirects).
    pub url: Url,
    /// The Content-Length the server declared, if it declared one and the body is not chunked.
    /// Known before the body is read. For a response to HEAD, the length a GET would have.
    pub content_length: Option<u64>,
    /// The version of TLS the response came over (`None` over plain http; HTTP/3 is always TLS 1.3).
    pub tls_version: Option<TlsVersion>,
    /// True if the body came compressed and the client is decoding it as it is read (see [`Client::decompress`](super::Client::decompress)).
    pub uncompressed: bool,
    body: Body,
    decoder: Option<Box<BodyDecoder>>,
    /// What the request holds while it is in flight (its scheduler's place, its batch's), given back when the body is over.
    in_flight: Option<super::InFlight>,
}

impl ResponseStream {
    pub(super) fn new(head: Head, url: Url, body: BodyReader, tls_version: Option<TlsVersion>) -> ResponseStream {
        ResponseStream {
            status: head.status,
            reason: head.reason,
            version: HttpVersion::Http11,
            headers: head.headers,
            url,
            content_length: head.content_length,
            tls_version,
            uncompressed: false,
            body: Body::H1(body),
            decoder: None,
            in_flight: None,
        }
    }

    /// The same response, holding what its request holds in flight until its body is over (or it is dropped).
    pub(super) fn in_flight(mut self, in_flight: Option<super::InFlight>) -> ResponseStream {
        let Some(mut f) = in_flight else { return self };
        if self.body.is_done() {
            // nothing more to come: over now
            return self;
        }
        f.length(self.content_length);
        self.in_flight = Some(f);
        self
    }

    /// What became of a read, for what the request holds in flight: given back at the end of the body or on an error
    /// (which is a cancel if its batch was cancelled).
    fn account(&mut self, r: Result<usize>) -> Result<usize> {
        let Some(f) = self.in_flight.as_mut() else { return r };
        match r {
            Ok(0) => {
                self.in_flight = None;
                Ok(0)
            }
            Ok(n) => {
                f.received(n, self.content_length);
                Ok(n)
            }
            Err(e) => {
                let cancelled = f.cancelled();
                self.in_flight = None;
                Err(if cancelled { Error::Cancelled } else { e })
            }
        }
    }

    /// The same response with its body decoded as it is read: the headers that describe the encoded body are gone and so is the length.
    pub(super) fn with_decoder(mut self, format: Format, limits: InflateLimits) -> ResponseStream {
        super::decode::strip_encoding_headers(&mut self.headers);
        self.content_length = None;
        self.uncompressed = true;
        self.decoder = Some(Box::new(BodyDecoder::new(format, limits)));
        self
    }

    /// Reads up to `out.len()` bytes of the body as the caller gets it (decoded, if it is): 0 is the end.
    fn read_some(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.in_flight.is_none() {
            return self.read_plain(out);
        }
        if self.in_flight.as_ref().is_some_and(|f| f.cancelled()) {
            return self.account(Err(Error::Cancelled));
        }
        let r = self.read_plain(out);
        self.account(r)
    }

    fn read_plain(&mut self, out: &mut [u8]) -> Result<usize> {
        let Some(decoder) = self.decoder.as_mut() else { return self.body.read_body(out) };
        loop {
            match decoder.next(out).map_err(Error::Decode)? {
                Next::Data(n) => return Ok(n),
                Next::End => return Ok(0),
                Next::Wire => {
                    let n = self.body.read_body(decoder.wire_buf())?;
                    decoder.wire(n).map_err(Error::Decode)?;
                }
            }
        }
    }

    /// A response that came over HTTP/2: there is no reason phrase, and the length is the Content-Length field's.
    /// A body that is declared larger than the limit fails the request, as it does over HTTP/1.1 (unless there is
    /// no body: a response to HEAD, a 204 or a 304).
    pub(super) fn from_h2(status: u16, headers: Vec<(String, String)>, url: Url, body: MuxBody, bodiless: bool, tls_version: Option<TlsVersion>) -> Result<ResponseStream> {
        ResponseStream::from_mux(HttpVersion::Http2, status, headers, url, body, bodiless, tls_version)
    }

    /// A response that came over HTTP/3 (the same as one over HTTP/2 but for the protocol it says it came over).
    pub(super) fn from_h3(status: u16, headers: Vec<(String, String)>, url: Url, body: MuxBody, bodiless: bool) -> Result<ResponseStream> {
        ResponseStream::from_mux(HttpVersion::Http3, status, headers, url, body, bodiless, Some(TlsVersion::Tls13))
    }

    fn from_mux(version: HttpVersion, status: u16, headers: Vec<(String, String)>, url: Url, body: MuxBody, bodiless: bool, tls_version: Option<TlsVersion>) -> Result<ResponseStream> {
        let content_length = headers.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse::<u64>().ok());
        if !bodiless && content_length.is_some_and(|n| n > body.limit()) {
            return Err(Error::Http("response body exceeds the configured size limit".into()));
        }
        Ok(ResponseStream { status, reason: String::new(), version, headers, url, content_length, tls_version, uncompressed: false, body: Body::Mux(body), decoder: None, in_flight: None })
    }

    /// First header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// All headers with this (case-insensitive) name.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Reads the rest of the body into memory and returns the whole [`Response`].
    pub fn into_response(mut self) -> Result<Response> {
        // over HTTP/2 the connection keeps the body in one buffer as it comes, and gives that buffer over
        if let (Body::Mux(b), None) = (&mut self.body, &self.decoder) {
            let collected = b.collect();
            let body = match self.in_flight.take() {
                Some(f) if collected.is_err() && f.cancelled() => return Err(Error::Cancelled),
                _ => collected?,
            };
            return Ok(Response { status: self.status, reason: self.reason, version: self.version, headers: self.headers, body, url: self.url, tls_version: self.tls_version, uncompressed: false });
        }
        // `body[..filled]` is what has been read; the rest of `body` is zeros waiting to be read into (the safe way to
        // hand out a `&mut [u8]`).
        let mut body: Vec<u8> = Vec::new();
        let mut filled = 0usize;
        // What the server says is coming is a hint, not a promise: a body that says it is large gets room for that much
        // (up to PRESIZE_MAX), but as zeroed memory straight from the allocator, which for a large block is pages the
        // system has not even mapped yet: nothing is written to them until the body is. Nothing is reserved for a server
        // that says nothing, and what is reserved up front beyond PRESIZE_MAX is a megabyte.
        const PRESIZE_MAX: u64 = 256 << 20;
        let mut presized = false;
        if !self.body.is_done() {
            let hint = self.content_length.unwrap_or(0);
            if hint >= 1 << 20 {
                // (and the room for one more read, which is how the end of the body is found out)
                body = vec![0u8; hint.min(PRESIZE_MAX) as usize + 4096];
                presized = true;
            } else if self.content_length.is_some() && !self.uncompressed {
                // a small body of a known length: room for it and that one more read, and no more zeroed than that (where
                // 32 KiB were, for a body of 1 KB: BACKLOG B-90); one that is longer than it said grows as below
                body = vec![0u8; hint as usize + 4096];
                presized = true;
            } else {
                body.reserve(hint as usize);
            }
        }
        // Growing past what was zeroed means zeroing more, so what is offered to each read there is kept to about twice
        // what the last read returned: a read that gives 16 KiB must not make the next one pay for zeroing a megabyte.
        let mut offer = 32 * 1024;
        loop {
            if body.len() - filled < 4096 {
                let more = body.len().max(32 * 1024);
                body.resize(body.len() + more, 0);
                presized = false;
            }
            let room = if presized { body.len() - filled } else { (body.len() - filled).min(offer) };
            match self.read_some(&mut body[filled..filled + room]) {
                Ok(0) => break,
                Ok(n) => {
                    filled += n;
                    offer = (n * 2).clamp(32 * 1024, 1 << 20);
                }
                Err(e) => return Err(e),
            }
        }
        body.truncate(filled);
        // a body that was shorter than the room made for it does not keep the room
        if body.capacity() > filled + filled / 4 + 4096 {
            body.shrink_to_fit();
        }
        Ok(Response { status: self.status, reason: self.reason, version: self.version, headers: self.headers, body, url: self.url, tls_version: self.tls_version, uncompressed: self.uncompressed })
    }

    /// Reads the rest of the body into `sink`; returns how many bytes it was.
    pub fn copy_to<W: Write>(&mut self, sink: &mut W) -> Result<u64> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            match self.read_some(&mut buf)? {
                0 => return Ok(total),
                n => {
                    sink.write_all(&buf[..n])?;
                    total += n as u64;
                }
            }
        }
    }

    /// Reads and drops up to `limit` bytes of what is left of the body; see `BodyReader::discard`.
    pub(super) fn discard(&mut self, limit: u64) {
        self.body.discard(limit);
    }
}

impl Read for ResponseStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_some(out).map_err(to_io)
    }
}

impl std::fmt::Debug for ResponseStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseStream").field("status", &self.status).field("url", &self.url.to_string()).field("content_length", &self.content_length).finish_non_exhaustive()
    }
}
