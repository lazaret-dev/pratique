//! The client side of an HTTP/3 connection (RFC 9114) as a state machine that does no I/O and reads no clock: it works on the streams of a
//! transport (the QUIC connection, or in the tests and the fuzzer a stand-in) through the [`Transport`] trait, and the application
//! drives it with calls like those of the HTTP/2 connection (open a stream, send a body, ask what a stream has).
//!
//! What it takes care of: the three streams a client opens (control, with our SETTINGS, and the two of QPACK) and the ones the server
//! opens (read for what they are, and the ones of unknown types turned away); the server's SETTINGS (what the QPACK encoder may do, the
//! largest field section it takes); the request streams: a request is a HEADERS frame, DATA frames and the end of the stream, a response
//! is read as HEADERS (any number of 1xx before the final one), DATA and trailers, checked as the HTTP/2 connection checks one (the
//! pseudo-headers, connection-specific fields, Content-Length against the data); QPACK, both ways, including a response whose
//! field section waits for entries of the table that have not come yet; GOAWAY; and the errors, a stream's and the connection's, with
//! the codes of RFC 9114 section 8.1 and of RFC 9204 section 6.
//!
//! What it guards against, as it reads what a server sent: frames out of order or of types a stream may not carry (the frame reader says
//! which), a second control stream, the closing of a stream the connection cannot do without, push (we never allow it), field sections
//! that are larger than we said we would take or that make no sense, a body larger than its Content-Length, and a response that is read
//! more slowly than it comes (the body that is held unread is bounded, and the stream is not read further until the application has
//! taken some, so that the transport's flow control holds the server back).
//!
//! Push is off: no MAX_PUSH_ID is sent, so a push stream, PUSH_PROMISE and CANCEL_PUSH are errors.

use super::frame::{self, code, stream_type, Event, FrameError, FrameReader, Kind, PeerSettings};
use super::qpack::{Decoded, Decoder, Encoder, EncoderConfig};
use crate::http::h2::connection::{lower_names, parse_response, parse_trailers, request_fields, Fields, Head, Request, MAX_INTERIM};
use crate::http::h2::hpack::Field;
use crate::quic::streams::{StreamError as TransportError, StreamEvent as TransportEvent};
use crate::quic::wire;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

/// The streams of the connection under this one, as the HTTP/3 connection needs them (the QUIC connection has all of it: see
/// [`QuicTransport`]).
pub(crate) trait Transport {
    /// A new stream of ours, and its id. [`TransportError::Blocked`] if the peer's limit is reached or not known yet.
    fn open_stream(&mut self, bidirectional: bool) -> Result<u64, TransportError>;
    /// Writes; the number of bytes taken (the end is marked only if all were taken). [`TransportError::Blocked`] if none.
    fn write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, TransportError>;
    /// Reads: the bytes, and whether the stream ends with them. [`TransportError::Blocked`] if there is nothing now.
    fn read(&mut self, id: u64, buf: &mut [u8]) -> Result<(usize, bool), TransportError>;
    fn reset(&mut self, id: u64, error: u64) -> Result<(), TransportError>;
    fn stop_sending(&mut self, id: u64, error: u64) -> Result<(), TransportError>;
    fn poll_event(&mut self) -> Option<TransportEvent>;
    /// Ends the connection with an application error.
    fn close(&mut self, error: u64, reason: &[u8]);
}

/// What this endpoint announces and how much it holds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    /// SETTINGS_MAX_FIELD_SECTION_SIZE: the largest header list we take (and the most that an encoded field section may be).
    pub(crate) max_header_list: usize,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY: how much the server's encoder may keep in the table it makes for us.
    pub(crate) qpack_table_capacity: usize,
    /// SETTINGS_QPACK_BLOCKED_STREAMS: how many streams may wait for the table at once.
    pub(crate) qpack_blocked_streams: usize,
    /// How our encoder behaves.
    pub(crate) encoder: EncoderConfig,
    /// The most body that a stream holds unread before it is not read further.
    pub(crate) body_buffer: usize,
    /// The most that a stream holds that is written and not yet taken by the transport.
    pub(crate) send_buffer: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_header_list: 64 << 10,
            qpack_table_capacity: 4096,
            qpack_blocked_streams: 16,
            encoder: EncoderConfig { table_capacity: 4096, blocked_streams: 0, only_safe_names: true },
            body_buffer: 1 << 20,
            send_buffer: 256 << 10,
        }
    }
}

/// How much is read from a stream at a time.
const READ_CHUNK: usize = 64 << 10;

/// The connection is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionError {
    pub(crate) code: u64,
    pub(crate) reason: String,
    /// True if this endpoint found the fault (and closed the connection saying so), false if the connection was closed from outside.
    pub(crate) local: bool,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/3 connection {}: {} (error {:#x})", if self.local { "failed" } else { "closed" }, self.reason, self.code)
    }
}

/// A stream is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamError {
    pub(crate) code: u64,
    pub(crate) reason: String,
    /// True if the request cannot have been acted on (the server rejected it, or said in a GOAWAY that it did not get that far), so that
    /// sending it again on another connection is safe whatever the method.
    pub(crate) retry_safe: bool,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/3 stream failed: {} (error {:#x})", self.reason, self.code)
    }
}

/// Why a stream could not be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// The server's limit on the streams we open is reached (or not known yet); try again when one has ended.
    Full,
    /// The connection is going away or is lost: use another.
    Unavailable,
    /// The request cannot be sent (a bad header, a header list over the server's limit).
    Invalid(String),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Full => f.write_str("the HTTP/3 connection has as many streams as the server allows"),
            OpenError::Unavailable => f.write_str("the HTTP/3 connection cannot take another request"),
            OpenError::Invalid(why) => write!(f, "the request cannot be sent over HTTP/3: {why}"),
        }
    }
}

/// What happened on a stream, as [`Connection::poll_stream`] gives it, in this order: the head, any number of pieces of body, perhaps
/// trailers, the end; or a failure at any point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StreamEvent {
    /// Nothing new yet.
    Pending,
    Head(Head),
    /// This many bytes of the body were copied into the buffer.
    Data(usize),
    Trailers(Fields),
    /// The response is complete (and so it stays: this is returned again if asked again).
    End,
    Failed(StreamError),
}

/// The most that [`Connection::take_stream_data`] moves in one go.
pub(crate) const TAKE_MAX: usize = 1 << 20;

// ------------------------------------------------------------------------------------------------ what a stream of ours has to send

/// What is to be written on a stream of ours: bytes, and then perhaps the end.
#[derive(Debug, Default)]
struct Outbox {
    /// None until the stream is open.
    id: Option<u64>,
    buf: Vec<u8>,
    pos: usize,
    /// The end of the stream follows the bytes.
    fin: bool,
    /// The end has been written.
    finished: bool,
}

impl Outbox {
    fn with(buf: Vec<u8>) -> Outbox {
        Outbox { buf, ..Outbox::default() }
    }

    fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether there is anything to write (bytes, or an end that has not been).
    fn wants_write(&self) -> bool {
        self.id.is_some() && !self.finished && (self.pending() > 0 || self.fin)
    }

    /// Writes what the transport takes. Not an error that it takes less than all (the rest waits for a Writable event).
    fn flush<T: Transport>(&mut self, t: &mut T) -> Result<(), TransportError> {
        let Some(id) = self.id else { return Ok(()) };
        while self.wants_write() {
            let all = self.pending();
            match t.write(id, &self.buf[self.pos..], self.fin) {
                Ok(n) => {
                    self.pos += n;
                    if n == all {
                        self.buf.clear();
                        self.pos = 0;
                        if self.fin {
                            self.finished = true;
                        }
                    } else {
                        break;
                    }
                }
                Err(TransportError::Blocked) => break,
                Err(e) => return Err(e),
            }
        }
        if self.pos > 0 && self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        Ok(())
    }

    /// Nothing more is to be written.
    fn abandon(&mut self) {
        self.buf = Vec::new();
        self.pos = 0;
        self.fin = false;
        self.finished = true;
    }
}

// ------------------------------------------------------------------------------------------------ the streams of the server

/// A unidirectional stream of the server: what it is, once its first bytes say.
#[derive(Clone, Copy, Debug)]
enum UniKind {
    /// The type is a variable-length integer, not all here yet.
    Type { bytes: [u8; 8], have: usize },
    Control,
    QpackEncoder,
    QpackDecoder,
}

// ------------------------------------------------------------------------------------------------ the request streams

/// A piece of what was read from a request stream, in the order it came.
enum Item<'a> {
    Headers(Vec<u8>),
    Data(&'a [u8]),
    /// The frame reader found an error after the frames before this.
    Error(FrameError),
    /// The end of the stream.
    Fin,
}

/// A piece that is held back while an earlier field section waits for the table.
#[derive(Debug)]
enum Held {
    Headers(Vec<u8>),
    Data(Vec<u8>),
    Error(FrameError),
    Fin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    /// A field section is waiting for the table: what follows it is held.
    Blocked,
    /// Nothing more is read from the stream (it ended or failed).
    Stop,
}

#[derive(Debug)]
struct Stream {
    reader: FrameReader,
    out: Outbox,
    /// The server asked us to stop sending (the code it gave).
    send_stopped: Option<u64>,
    /// The response is to a HEAD request: no body comes whatever Content-Length says.
    head_request: bool,
    /// The response (a 204 or 304, or one to HEAD) has no body.
    bodiless: bool,
    /// How many 1xx responses came before the final one.
    interim: u32,
    head: Option<Head>,
    got_head: bool,
    trailers: Option<Fields>,
    /// The trailers came: nothing may follow them.
    trailers_seen: bool,
    body: Vec<u8>,
    body_pos: usize,
    expected: Option<u64>,
    received: u64,
    remote_ended: bool,
    failure: Option<StreamError>,
    /// A field section that waits for entries of the table, and how many have to have come.
    blocked: Option<(Vec<u8>, u64)>,
    /// What was read after it.
    held: VecDeque<Held>,
    /// Reading stopped because the body held is as much as is allowed.
    stalled: bool,
}

impl Stream {
    fn new(max_headers: usize, out: Outbox, head_request: bool) -> Stream {
        Stream {
            reader: FrameReader::new(Kind::Request, max_headers),
            out,
            send_stopped: None,
            head_request,
            bodiless: false,
            interim: 0,
            head: None,
            got_head: false,
            trailers: None,
            trailers_seen: false,
            body: Vec::new(),
            body_pos: 0,
            expected: None,
            received: 0,
            remote_ended: false,
            failure: None,
            blocked: None,
            held: VecDeque::new(),
            stalled: false,
        }
    }

    fn unread(&self) -> usize {
        self.body.len() - self.body_pos
    }
}

// ------------------------------------------------------------------------------------------------ the connection

pub(crate) struct Connection {
    cfg: Config,
    decoder: Decoder,
    encoder: Encoder,
    control_out: Outbox,
    encoder_out: Outbox,
    decoder_out: Outbox,
    /// The unidirectional streams of the server that are known (read, or being read, for their type).
    uni: HashMap<u64, UniKind>,
    /// Streams of types we do not know, which we have asked the server to stop sending (what still comes is thrown away).
    ignored: HashSet<u64>,
    control_reader: FrameReader,
    control_in: Option<u64>,
    encoder_in: Option<u64>,
    decoder_in: Option<u64>,
    peer: Option<PeerSettings>,
    /// The id of the first request the server did not take, from its GOAWAY.
    goaway: Option<u64>,
    streams: HashMap<u64, Stream>,
    /// Streams that may have something to read.
    readable: BTreeSet<u64>,
    /// Request streams that have something to write.
    dirty: BTreeSet<u64>,
    /// The encoder stream brought entries: a field section may be waiting for them.
    table_grew: bool,
    error: Option<ConnectionError>,
    scratch: Vec<u8>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("h3::Connection").field("streams", &self.streams.len()).field("error", &self.error).finish()
    }
}

impl Connection {
    pub(crate) fn new(cfg: Config) -> Connection {
        let announce = frame::Settings {
            qpack_max_table_capacity: cfg.qpack_table_capacity as u64,
            qpack_blocked_streams: cfg.qpack_blocked_streams as u64,
            max_field_section_size: cfg.max_header_list as u64,
        };
        Connection {
            decoder: Decoder::new(cfg.qpack_table_capacity, cfg.qpack_blocked_streams, cfg.max_header_list),
            encoder: Encoder::new(cfg.encoder),
            control_out: Outbox::with(frame::control_stream_start(&announce)),
            encoder_out: Outbox::with(vec![stream_type::QPACK_ENCODER as u8]),
            decoder_out: Outbox::with(vec![stream_type::QPACK_DECODER as u8]),
            uni: HashMap::new(),
            ignored: HashSet::new(),
            control_reader: FrameReader::new(Kind::Control, 0),
            control_in: None,
            encoder_in: None,
            decoder_in: None,
            peer: None,
            goaway: None,
            streams: HashMap::new(),
            readable: BTreeSet::new(),
            dirty: BTreeSet::new(),
            table_grew: false,
            error: None,
            scratch: vec![0; READ_CHUNK],
            cfg,
        }
    }

    // -------------------------------------------------------------------------------------------- what the application asks

    /// The connection is lost: why (None while it is not).
    pub(crate) fn error(&self) -> Option<&ConnectionError> {
        self.error.as_ref()
    }

    /// Whether another request may be sent on it: it is not lost, and the server has not said it is going away.
    pub(crate) fn usable(&self) -> bool {
        self.error.is_none() && self.goaway.is_none()
    }

    pub(crate) fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// What the server announced in its SETTINGS (none until they come).
    pub(crate) fn peer_settings(&self) -> Option<&PeerSettings> {
        self.peer.as_ref()
    }

    /// Whether [`process`](Connection::process) has something to do that no event of the transport is going to say: a stream that was not
    /// read further because its body was held back, and has room again.
    pub(crate) fn needs_processing(&self) -> bool {
        !self.readable.is_empty() || self.table_grew
    }

    /// Opens a stream for a request: the HEADERS frame is queued and, as far as the transport takes it, written. `end_stream` says there
    /// is no body.
    pub(crate) fn open_stream<T: Transport>(&mut self, t: &mut T, request: &Request<'_>, end_stream: bool) -> Result<u64, OpenError> {
        if !self.usable() {
            return Err(OpenError::Unavailable);
        }
        let lowered = lower_names(request.headers);
        let fields = request_fields(request, &lowered).map_err(|e| match e {
            crate::http::h2::connection::OpenError::Invalid(why) => OpenError::Invalid(why),
            other => OpenError::Invalid(other.to_string()),
        })?;
        if let Some(limit) = self.peer.and_then(|p| p.max_field_section_size) {
            let size: u64 = fields.iter().map(|f| (f.name.len() + f.value.len() + 32) as u64).sum();
            if size > limit {
                return Err(OpenError::Invalid(format!("the header list is {size} bytes and the server takes {limit}")));
            }
        }
        self.open_critical(t);
        let id = match t.open_stream(true) {
            Ok(id) => id,
            Err(TransportError::Blocked) => return Err(OpenError::Full),
            Err(_) => return Err(OpenError::Unavailable),
        };
        let mut block = Vec::new();
        self.encoder.encode(id, &fields, &mut block);
        let mut out = Outbox::default();
        out.id = Some(id);
        frame::put_headers(&mut out.buf, &block);
        out.fin = end_stream;
        let head_request = request.method == "HEAD";
        self.streams.insert(id, Stream::new(self.cfg.max_header_list, out, head_request));
        self.dirty.insert(id);
        self.pump(t);
        Ok(id)
    }

    /// How much more of a body [`send_data`](Connection::send_data) takes now.
    pub(crate) fn send_capacity(&self, id: u64) -> usize {
        match self.streams.get(&id) {
            Some(s) if s.failure.is_none() && s.send_stopped.is_none() && !s.out.fin => self.cfg.send_buffer.saturating_sub(s.out.pending()),
            _ => 0,
        }
    }

    /// Sends body: how many bytes of `data` were taken (as many as [`send_capacity`](Connection::send_capacity) allows); the end follows
    /// if `end_stream` and all were taken.
    pub(crate) fn send_data<T: Transport>(&mut self, t: &mut T, id: u64, data: &[u8], end_stream: bool) -> Result<usize, StreamError> {
        let Some(s) = self.streams.get_mut(&id) else { return Err(local_error("there is no such stream")) };
        if let Some(f) = &s.failure {
            return Err(f.clone());
        }
        if let Some(c) = s.send_stopped {
            return Err(StreamError { code: c, reason: "the server asked us to stop sending the request".into(), retry_safe: c == code::H3_REQUEST_REJECTED });
        }
        if s.out.fin {
            return Err(local_error("the request is already complete"));
        }
        let n = data.len().min(self.cfg.send_buffer.saturating_sub(s.out.pending()));
        if n > 0 {
            frame::put_frame_header(&mut s.out.buf, frame::ty::DATA, n as u64);
            s.out.buf.extend_from_slice(&data[..n]);
        }
        if end_stream && n == data.len() {
            s.out.fin = true;
        }
        self.dirty.insert(id);
        self.pump(t);
        Ok(n)
    }

    /// Whether [`poll_stream`](Connection::poll_stream) (with room to put body in) has something to give: a head, body, trailers, the end
    /// or a failure (a stream that is not known fails). What an application that waits for news has to ask after the connection has taken
    /// in more.
    pub(crate) fn ready(&self, id: u64) -> bool {
        match self.streams.get(&id) {
            None => true,
            Some(s) => s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,
        }
    }

    /// Whether a writer that waits for room has something to do: there is room for body (see [`send_capacity`](Connection::send_capacity)),
    /// or the stream can take none any more (it failed, the server asked to stop, the request is complete, it is not known).
    pub(crate) fn writable(&self, id: u64) -> bool {
        match self.streams.get(&id) {
            None => true,
            Some(s) => s.failure.is_some() || s.send_stopped.is_some() || s.out.fin || self.send_capacity(id) > 0,
        }
    }

    /// What the stream has for the application: see [`StreamEvent`]. Reading body bytes makes room for the server to send more.
    pub(crate) fn poll_stream(&mut self, id: u64, buf: &mut [u8]) -> StreamEvent {
        self.poll(id, Sink::Copy(buf))
    }

    /// Like [`poll_stream`](Connection::poll_stream), but the body bytes are moved into `into` (emptied first) and not copied into a
    /// buffer: up to [`TAKE_MAX`] of what is waiting. When all that is waiting is taken the buffers are swapped.
    pub(crate) fn take_stream_data(&mut self, id: u64, into: &mut Vec<u8>) -> StreamEvent {
        into.clear();
        self.poll(id, Sink::Take(into))
    }

    fn poll(&mut self, id: u64, sink: Sink<'_>) -> StreamEvent {
        let Some(s) = self.streams.get_mut(&id) else { return StreamEvent::Failed(local_error("there is no such stream")) };
        let wants_body = match &sink {
            Sink::Copy(buf) => !buf.is_empty(),
            Sink::Take(_) => true,
        };
        // what arrived before a failure is for the application to see first, then the failure
        if let Some(head) = s.head.take() {
            return StreamEvent::Head(head);
        }
        if s.unread() > 0 && wants_body {
            let n = match sink {
                Sink::Copy(buf) => {
                    let n = s.unread().min(buf.len());
                    buf[..n].copy_from_slice(&s.body[s.body_pos..s.body_pos + n]);
                    s.body_pos += n;
                    n
                }
                Sink::Take(into) => {
                    let n = s.unread().min(TAKE_MAX);
                    if s.body_pos == 0 && n == s.body.len() {
                        std::mem::swap(&mut s.body, into);
                    } else {
                        into.extend_from_slice(&s.body[s.body_pos..s.body_pos + n]);
                        s.body_pos += n;
                    }
                    n
                }
            };
            if s.body_pos >= s.body.len() {
                s.body.clear();
                s.body_pos = 0;
            }
            if s.stalled && s.unread() < self.cfg.body_buffer {
                s.stalled = false;
                self.readable.insert(id);
            }
            return StreamEvent::Data(n);
        }
        if let Some(f) = &s.failure {
            if s.unread() == 0 || !wants_body {
                return StreamEvent::Failed(f.clone());
            }
        }
        if s.unread() == 0 {
            if let Some(tr) = s.trailers.take() {
                return StreamEvent::Trailers(tr);
            }
            if s.remote_ended {
                return StreamEvent::End;
            }
        }
        StreamEvent::Pending
    }

    /// The application is done with the stream: what is still unread is dropped, and if the exchange was not finished the server is told
    /// to stop.
    pub(crate) fn release_stream<T: Transport>(&mut self, t: &mut T, id: u64) {
        let Some(s) = self.streams.remove(&id) else { return };
        self.readable.remove(&id);
        self.dirty.remove(&id);
        if s.failure.is_none() && self.error.is_none() && !(s.remote_ended && (s.out.finished || s.send_stopped.is_some())) {
            // (the end of a response that has been read is all there is to a stream that was finished; anything else is cancelled)
            if !s.remote_ended {
                let _ = t.stop_sending(id, code::H3_REQUEST_CANCELLED);
                self.decoder.cancel_stream(id);
            }
            if !s.out.finished {
                let _ = t.reset(id, code::H3_REQUEST_CANCELLED);
            }
            self.pump(t);
        }
    }

    /// The application is done with the connection: it is closed (with no error), and what is not complete fails.
    pub(crate) fn close<T: Transport>(&mut self, t: &mut T) {
        if self.error.is_some() {
            return;
        }
        t.close(code::H3_NO_ERROR, b"");
        self.fail_streams(code::H3_NO_ERROR, "the connection was closed");
        self.error = Some(ConnectionError { code: code::H3_NO_ERROR, reason: "closed by the application".into(), local: true });
    }

    /// The transport under the connection is gone (closed by the peer, timed out, or failed): every stream that is not complete fails
    /// with `code` and `reason`.
    pub(crate) fn transport_closed(&mut self, code: u64, reason: &str) {
        if self.error.is_none() {
            self.error = Some(ConnectionError { code, reason: reason.to_string(), local: false });
        }
        self.fail_streams(code, reason);
    }

    // -------------------------------------------------------------------------------------------- driving it

    /// Takes in what the transport has (events, bytes of streams) and writes what is due. Returns the error that has made the
    /// connection unusable, if one has.
    pub(crate) fn process<T: Transport>(&mut self, t: &mut T) -> Result<(), ConnectionError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        self.open_critical(t);
        loop {
            while let Some(ev) = t.poll_event() {
                self.on_event(t, ev);
            }
            while let Some(id) = self.readable.pop_first() {
                if self.error.is_some() {
                    break;
                }
                self.read(t, id);
            }
            if self.error.is_none() && self.table_grew {
                self.table_grew = false;
                self.retry_blocked(t);
            }
            if self.error.is_some() || (self.readable.is_empty() && !self.table_grew) {
                break;
            }
        }
        self.pump(t);
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn open_critical<T: Transport>(&mut self, t: &mut T) {
        for out in [&mut self.control_out, &mut self.encoder_out, &mut self.decoder_out] {
            if out.id.is_none() {
                match t.open_stream(false) {
                    Ok(id) => out.id = Some(id),
                    // (not yet: the peer's limits are not known, or are reached; the next call tries again)
                    Err(_) => break,
                }
            }
        }
    }

    fn on_event<T: Transport>(&mut self, t: &mut T, ev: TransportEvent) {
        match ev {
            TransportEvent::Readable(id) => match id & 3 {
                // a unidirectional stream of the server
                3 => {
                    self.readable.insert(id);
                }
                // a stream of ours
                0 => {
                    if self.streams.contains_key(&id) {
                        self.readable.insert(id);
                    }
                }
                // a bidirectional stream of the server: we allow none
                1 => self.fail(t, code::H3_STREAM_CREATION_ERROR, "the server opened a bidirectional stream"),
                _ => {}
            },
            TransportEvent::Writable(id) => {
                if self.streams.contains_key(&id) {
                    self.dirty.insert(id);
                }
            }
            TransportEvent::Stopped(id, c) => {
                if [self.control_out.id, self.encoder_out.id, self.decoder_out.id].contains(&Some(id)) {
                    self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, "the server stopped a stream the connection cannot do without");
                } else if let Some(s) = self.streams.get_mut(&id) {
                    s.send_stopped = Some(c);
                    s.out.abandon();
                    self.dirty.remove(&id);
                }
            }
            TransportEvent::Available { .. } => {}
        }
    }

    /// Writes what is due on the streams that are ours: the QPACK instructions, the control stream, the requests.
    fn pump<T: Transport>(&mut self, t: &mut T) {
        let d = self.decoder.take_output();
        self.decoder_out.buf.extend_from_slice(&d);
        let e = self.encoder.take_output();
        self.encoder_out.buf.extend_from_slice(&e);
        let mut lost = false;
        for out in [&mut self.control_out, &mut self.encoder_out, &mut self.decoder_out] {
            // (a stream the server stopped, or that is gone: the connection cannot do without it)
            lost |= out.flush(t).is_err_and(|e| !matches!(e, TransportError::Closed));
        }
        if lost {
            self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, "a stream the connection cannot do without cannot be written");
        }
        let ids: Vec<u64> = self.dirty.iter().copied().collect();
        for id in ids {
            let Some(s) = self.streams.get_mut(&id) else {
                self.dirty.remove(&id);
                continue;
            };
            match s.out.flush(t) {
                Ok(()) => {
                    if !s.out.wants_write() {
                        self.dirty.remove(&id);
                    }
                }
                Err(TransportError::Stopped(c)) => {
                    s.send_stopped = Some(c);
                    s.out.abandon();
                    self.dirty.remove(&id);
                }
                Err(_) => {
                    s.out.abandon();
                    self.dirty.remove(&id);
                }
            }
        }
    }

    // -------------------------------------------------------------------------------------------- errors

    /// The connection is lost by our finding: it is closed with the code, and every stream that is not complete fails.
    fn fail<T: Transport>(&mut self, t: &mut T, code: u64, reason: impl Into<String>) {
        if self.error.is_some() {
            return;
        }
        let reason = reason.into();
        t.close(code, reason.as_bytes());
        self.fail_streams(code, &reason);
        self.error = Some(ConnectionError { code, reason, local: true });
    }

    fn fail_streams(&mut self, code: u64, reason: &str) {
        for s in self.streams.values_mut() {
            if s.failure.is_none() && !s.remote_ended {
                s.failure = Some(StreamError { code, reason: reason.to_string(), retry_safe: false });
            }
            s.blocked = None;
            s.held.clear();
            s.out.abandon();
        }
        self.readable.clear();
        self.dirty.clear();
    }

    /// A stream is lost: the server is told to stop sending and we stop, and the stream's failure is what the application sees after what
    /// it has already been given.
    fn fail_stream<T: Transport>(&mut self, t: &mut T, id: u64, code: u64, reason: &str, retry_safe: bool) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        if s.failure.is_some() || s.remote_ended {
            return;
        }
        s.failure = Some(StreamError { code, reason: reason.to_string(), retry_safe });
        s.blocked = None;
        s.held.clear();
        s.out.abandon();
        self.dirty.remove(&id);
        self.readable.remove(&id);
        // (what the encoder counted on from this stream is released)
        self.decoder.cancel_stream(id);
        let _ = t.stop_sending(id, code);
        let _ = t.reset(id, code);
    }

    // -------------------------------------------------------------------------------------------- reading

    fn read<T: Transport>(&mut self, t: &mut T, id: u64) {
        let mut buf = std::mem::take(&mut self.scratch);
        if id & 3 == 3 {
            self.read_uni(t, id, &mut buf);
        } else {
            self.read_request(t, id, &mut buf);
        }
        self.scratch = buf;
    }

    /// A unidirectional stream of the server.
    fn read_uni<T: Transport>(&mut self, t: &mut T, id: u64, buf: &mut [u8]) {
        loop {
            if self.error.is_some() {
                return;
            }
            if self.ignored.contains(&id) {
                match t.read(id, buf) {
                    Ok((_, false)) => continue,
                    Err(TransportError::Blocked) => return,
                    Ok((_, true)) | Err(_) => {
                        self.ignored.remove(&id);
                        return;
                    }
                }
            }
            let kind = self.uni.get(&id).copied().unwrap_or(UniKind::Type { bytes: [0; 8], have: 0 });
            match kind {
                UniKind::Type { mut bytes, mut have } => {
                    let want = if have == 0 { 1 } else { (1usize << (bytes[0] >> 6)) - have };
                    match t.read(id, &mut bytes[have..have + want]) {
                        Ok((n, fin)) => {
                            have += n;
                            if have == 0 || have < 1usize << (bytes[0] >> 6) {
                                if fin {
                                    // (the stream ended before it said what it was: nothing to do for it)
                                    self.uni.remove(&id);
                                    return;
                                }
                                self.uni.insert(id, UniKind::Type { bytes, have });
                                if n == 0 {
                                    return;
                                }
                                continue;
                            }
                            let (ty, _) = wire::get_varint(&bytes[..have]).expect("a whole variable-length integer");
                            if !self.on_stream_type(t, id, ty) {
                                return;
                            }
                            if fin {
                                // (a stream that is critical ends before anything was said on it; one that is not wanted is over)
                                if self.uni.contains_key(&id) {
                                    self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, "a stream the connection cannot do without was closed");
                                }
                                self.ignored.remove(&id);
                                return;
                            }
                        }
                        Err(_) => {
                            return;
                        }
                    }
                }
                UniKind::Control | UniKind::QpackEncoder | UniKind::QpackDecoder => match t.read(id, buf) {
                    Ok((n, fin)) => {
                        self.on_uni_bytes(t, kind, &buf[..n]);
                        if self.error.is_some() {
                            return;
                        }
                        if fin {
                            self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, "a stream the connection cannot do without was closed");
                            return;
                        }
                        if n == 0 {
                            return;
                        }
                    }
                    Err(TransportError::Blocked) => return,
                    Err(TransportError::Reset(_)) => {
                        self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, "a stream the connection cannot do without was reset");
                        return;
                    }
                    Err(_) => return,
                },
            }
        }
    }

    /// The type of a stream of the server is known. Returns false if nothing more is to be read from it now.
    fn on_stream_type<T: Transport>(&mut self, t: &mut T, id: u64, ty: u64) -> bool {
        let (slot, kind, what) = match ty {
            stream_type::CONTROL => (&mut self.control_in, UniKind::Control, "control"),
            stream_type::QPACK_ENCODER => (&mut self.encoder_in, UniKind::QpackEncoder, "QPACK encoder"),
            stream_type::QPACK_DECODER => (&mut self.decoder_in, UniKind::QpackDecoder, "QPACK decoder"),
            stream_type::PUSH => {
                self.fail(t, code::H3_ID_ERROR, "a push stream, though push was not allowed");
                return false;
            }
            _ => {
                // not a type we know: the rest cannot be read, so the server is asked not to send it
                self.uni.remove(&id);
                self.ignored.insert(id);
                let _ = t.stop_sending(id, code::H3_STREAM_CREATION_ERROR);
                return true;
            }
        };
        if slot.is_some() {
            let reason = format!("a second {what} stream");
            self.fail(t, code::H3_STREAM_CREATION_ERROR, reason);
            return false;
        }
        *slot = Some(id);
        self.uni.insert(id, kind);
        true
    }

    fn on_uni_bytes<T: Transport>(&mut self, t: &mut T, kind: UniKind, bytes: &[u8]) {
        match kind {
            UniKind::Control => {
                let mut events = Vec::new();
                let r = self.control_reader.feed(bytes, &mut events);
                for ev in events {
                    self.on_control_frame(t, ev);
                    if self.error.is_some() {
                        return;
                    }
                }
                if let Err(e) = r {
                    match e {
                        FrameError::Connection(c, why) => self.fail(t, c, why),
                        FrameError::HeadersTooLarge => self.fail(t, code::H3_INTERNAL_ERROR, "a HEADERS frame on the control stream"),
                    }
                }
            }
            UniKind::QpackEncoder => match self.decoder.encoder_stream(bytes) {
                Ok(()) => self.table_grew = true,
                Err(e) => self.fail(t, e.code(), e.to_string()),
            },
            UniKind::QpackDecoder => {
                if let Err(e) = self.encoder.decoder_stream(bytes) {
                    self.fail(t, e.code(), e.to_string());
                }
            }
            UniKind::Type { .. } => {}
        }
    }

    fn on_control_frame<T: Transport>(&mut self, t: &mut T, ev: Event) {
        match ev {
            Event::Settings(pairs) => match PeerSettings::from_pairs(&pairs) {
                Ok(s) => {
                    self.encoder.set_peer_settings(s.qpack_max_table_capacity, s.qpack_blocked_streams);
                    self.peer = Some(s);
                }
                Err(FrameError::Connection(c, why)) => self.fail(t, c, why),
                Err(FrameError::HeadersTooLarge) => unreachable!("settings are not field sections"),
            },
            Event::GoAway(id) => {
                if id % 4 != 0 {
                    self.fail(t, code::H3_ID_ERROR, "a GOAWAY that does not name a request stream of the client");
                    return;
                }
                if self.goaway.is_some_and(|before| id > before) {
                    self.fail(t, code::H3_ID_ERROR, "a GOAWAY that is greater than the one before");
                    return;
                }
                self.goaway = Some(id);
                let lost: Vec<u64> = self.streams.keys().copied().filter(|&s| s >= id).collect();
                for s in lost {
                    self.fail_stream(t, s, code::H3_REQUEST_REJECTED, "the server did not take the request (GOAWAY)", true);
                }
            }
            Event::CancelPush(_) | Event::MaxPushId(_) => self.fail(t, code::H3_ID_ERROR, "a push that was never allowed"),
            Event::Data(_) | Event::Headers(_) => self.fail(t, code::H3_FRAME_UNEXPECTED, "a frame of a request stream on the control stream"),
        }
    }

    /// A request stream: what the server sent on it.
    fn read_request<T: Transport>(&mut self, t: &mut T, id: u64, buf: &mut [u8]) {
        loop {
            if self.error.is_some() {
                return;
            }
            let Some(s) = self.streams.get_mut(&id) else { return };
            if s.failure.is_some() || s.remote_ended || s.blocked.is_some() {
                return;
            }
            if s.unread() >= self.cfg.body_buffer {
                s.stalled = true;
                return;
            }
            let (n, fin) = match t.read(id, buf) {
                Ok((0, false)) => return,
                Ok(r) => r,
                Err(TransportError::Blocked) => return,
                Err(TransportError::Reset(c)) => {
                    self.fail_stream(t, id, c, "the server reset the stream", c == code::H3_REQUEST_REJECTED);
                    return;
                }
                Err(_) => return,
            };
            let mut events = Vec::new();
            let result = s.reader.feed(&buf[..n], &mut events);
            let mut items: Vec<Item<'_>> = Vec::with_capacity(events.len() + 1);
            for ev in events {
                match ev {
                    Event::Headers(block) => items.push(Item::Headers(block)),
                    Event::Data(r) => items.push(Item::Data(&buf[r])),
                    _ => unreachable!("a request stream's reader gives only headers and data"),
                }
            }
            match result {
                Err(e) => items.push(Item::Error(e)),
                Ok(()) if fin => items.push(Item::Fin),
                Ok(()) => {}
            }
            let mut items = items.into_iter();
            while let Some(item) = items.next() {
                match self.apply(t, id, item) {
                    Flow::Continue => {}
                    Flow::Stop => return,
                    Flow::Blocked => {
                        // what follows waits with the field section
                        let held: Vec<Held> = items
                            .map(|i| match i {
                                Item::Headers(b) => Held::Headers(b),
                                Item::Data(d) => Held::Data(d.to_vec()),
                                Item::Error(e) => Held::Error(e),
                                Item::Fin => Held::Fin,
                            })
                            .collect();
                        if let Some(s) = self.streams.get_mut(&id) {
                            s.held.extend(held);
                        }
                        return;
                    }
                }
            }
            if fin {
                return;
            }
        }
    }

    /// A field section that was waiting may be decoded now: the ones that can are, and what was held back behind them is taken in.
    fn retry_blocked<T: Transport>(&mut self, t: &mut T) {
        let have = self.decoder.insert_count();
        let ready: Vec<u64> = self.streams.iter().filter(|(_, s)| s.blocked.as_ref().is_some_and(|(_, need)| *need <= have)).map(|(id, _)| *id).collect();
        for id in ready {
            let Some((block, _)) = self.streams.get_mut(&id).and_then(|s| s.blocked.take()) else { continue };
            let mut flow = self.apply(t, id, Item::Headers(block));
            // what was held behind it, until another field section waits or the stream is over
            while flow == Flow::Continue {
                let Some(held) = self.streams.get_mut(&id).and_then(|s| s.held.pop_front()) else { break };
                flow = match held {
                    Held::Headers(b) => self.apply(t, id, Item::Headers(b)),
                    Held::Data(d) => self.apply(t, id, Item::Data(&d)),
                    Held::Error(e) => self.apply(t, id, Item::Error(e)),
                    Held::Fin => self.apply(t, id, Item::Fin),
                };
            }
            if flow == Flow::Continue {
                // (all that was held is taken in: reading goes on)
                self.readable.insert(id);
            }
        }
    }

    fn apply<T: Transport>(&mut self, t: &mut T, id: u64, item: Item<'_>) -> Flow {
        match item {
            Item::Error(FrameError::Connection(c, why)) => {
                self.fail(t, c, why);
                Flow::Stop
            }
            Item::Error(FrameError::HeadersTooLarge) => {
                self.fail_stream(t, id, code::H3_EXCESSIVE_LOAD, "a field section larger than the limit", false);
                Flow::Stop
            }
            Item::Data(bytes) => self.on_data(t, id, bytes),
            Item::Headers(block) => self.on_headers(t, id, block),
            Item::Fin => self.on_fin(t, id),
        }
    }

    fn on_data<T: Transport>(&mut self, t: &mut T, id: u64, bytes: &[u8]) -> Flow {
        let Some(s) = self.streams.get_mut(&id) else { return Flow::Stop };
        let bad: Result<(), (bool, &str)> = if s.trailers_seen {
            Err((true, "DATA after the trailers"))
        } else if !s.got_head {
            Err((true, "DATA before the response headers"))
        } else if s.bodiless {
            Err((false, "DATA in a response that has no body"))
        } else if s.expected.is_some_and(|n| s.received + bytes.len() as u64 > n) {
            Err((false, "more DATA than the Content-Length says"))
        } else {
            Ok(())
        };
        match bad {
            Ok(()) => {
                s.received += bytes.len() as u64;
                s.body.extend_from_slice(bytes);
                Flow::Continue
            }
            // (a frame where it may not be is the connection's fault; a body that is not what the head said is the stream's)
            Err((true, why)) => {
                self.fail(t, code::H3_FRAME_UNEXPECTED, why);
                Flow::Stop
            }
            Err((false, why)) => {
                self.fail_stream(t, id, code::H3_MESSAGE_ERROR, why, false);
                Flow::Stop
            }
        }
    }

    fn on_headers<T: Transport>(&mut self, t: &mut T, id: u64, block: Vec<u8>) -> Flow {
        let Some(s) = self.streams.get_mut(&id) else { return Flow::Stop };
        if s.trailers_seen {
            self.fail(t, code::H3_FRAME_UNEXPECTED, "HEADERS after the trailers");
            return Flow::Stop;
        }
        let mut fields: Vec<Field> = Vec::new();
        match self.decoder.decode(id, &block, &mut fields) {
            Err(e) => {
                self.fail(t, e.code(), e.to_string());
                Flow::Stop
            }
            Ok(Decoded::Blocked { required_insert_count }) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.blocked = Some((block, required_insert_count));
                }
                Flow::Blocked
            }
            Ok(Decoded::Done { within_limit: false }) => {
                self.fail_stream(t, id, code::H3_EXCESSIVE_LOAD, "a field section larger than the limit", false);
                Flow::Stop
            }
            Ok(Decoded::Done { within_limit: true }) => self.on_fields(t, id, fields),
        }
    }

    /// The fields of a section that is decoded: the response's head, an interim response's, or the trailers.
    fn on_fields<T: Transport>(&mut self, t: &mut T, id: u64, fields: Vec<Field>) -> Flow {
        let Some(s) = self.streams.get_mut(&id) else { return Flow::Stop };
        if s.got_head {
            return match parse_trailers(&fields) {
                Ok(trailers) => {
                    s.trailers = Some(trailers);
                    s.trailers_seen = true;
                    Flow::Continue
                }
                Err(why) => {
                    self.fail_stream(t, id, code::H3_MESSAGE_ERROR, why, false);
                    Flow::Stop
                }
            };
        }
        let (status, headers, length) = match parse_response(&fields) {
            Ok(r) => r,
            Err(why) => {
                self.fail_stream(t, id, code::H3_MESSAGE_ERROR, why, false);
                return Flow::Stop;
            }
        };
        if (100..200).contains(&status) {
            // an interim response: nothing for the application, and the final one is still to come (RFC 9114 section 4.1; a 101 has
            // no place in HTTP/3)
            s.interim += 1;
            if status == 101 || s.interim > MAX_INTERIM {
                self.fail_stream(t, id, code::H3_MESSAGE_ERROR, "a 101, or too many 1xx responses", false);
                return Flow::Stop;
            }
            return Flow::Continue;
        }
        s.got_head = true;
        s.bodiless = s.head_request || status == 204 || status == 304;
        s.expected = if s.bodiless { None } else { length };
        s.head = Some(Head { status, headers });
        Flow::Continue
    }

    fn on_fin<T: Transport>(&mut self, t: &mut T, id: u64) -> Flow {
        let Some(s) = self.streams.get_mut(&id) else { return Flow::Stop };
        if !s.reader.at_frame_boundary() {
            self.fail(t, code::H3_FRAME_ERROR, "the stream ended inside a frame");
            return Flow::Stop;
        }
        if !s.got_head {
            self.fail_stream(t, id, code::H3_REQUEST_INCOMPLETE, "the response ended before its headers", false);
            return Flow::Stop;
        }
        if s.expected.is_some_and(|n| s.received != n) {
            self.fail_stream(t, id, code::H3_MESSAGE_ERROR, "less DATA than the Content-Length says", false);
            return Flow::Stop;
        }
        s.remote_ended = true;
        Flow::Stop
    }

    /// For the tests and the fuzzer: the books must add up. Panics if they do not.
    #[cfg(any(test, pratique_fuzzing))]
    pub(crate) fn assert_books(&self) {
        let blocked = self.streams.values().filter(|s| s.blocked.is_some()).count();
        assert!(blocked <= self.cfg.qpack_blocked_streams, "{blocked} streams wait for the table, {} are allowed", self.cfg.qpack_blocked_streams);
        if self.error.is_none() {
            assert_eq!(self.decoder.blocked_streams(), blocked, "the decoder and the connection disagree on which streams wait");
        }
        for (id, s) in &self.streams {
            assert_eq!(id & 3, 0, "a request stream that is not a client's bidirectional one");
            assert!(s.unread() <= self.cfg.body_buffer + READ_CHUNK, "{} bytes of body are held unread on stream {id}", s.unread());
            assert!(s.body_pos <= s.body.len());
            if s.blocked.is_none() {
                assert!(s.held.is_empty(), "something is held back behind no field section");
            }
            if let Some((block, _)) = &s.blocked {
                assert!(block.len() <= self.cfg.max_header_list, "a waiting field section larger than the limit");
            }
            let held: usize = s.held.iter().map(|h| if let Held::Data(d) = h { d.len() } else { 0 }).sum();
            assert!(held <= READ_CHUNK, "{held} bytes held back behind a field section");
            if s.failure.is_some() {
                assert!(s.blocked.is_none() && s.held.is_empty(), "a failed stream holds on to what it was waiting with");
            }
        }
        assert!(self.ignored.len() <= 1 << 16);
        assert!(self.uni.len() <= 1 << 16);
        for id in &self.readable {
            assert!(self.streams.contains_key(id) || id & 3 == 3, "a stream to read that is not known");
        }
    }
}

enum Sink<'a> {
    Copy(&'a mut [u8]),
    Take(&'a mut Vec<u8>),
}

fn local_error(reason: &str) -> StreamError {
    StreamError { code: code::H3_REQUEST_CANCELLED, reason: reason.to_string(), retry_safe: false }
}

// ------------------------------------------------------------------------------------------------ the QUIC connection as a transport

/// A QUIC connection, and the time it is to be used at (the connection reads no clock).
pub(crate) struct QuicTransport<'a> {
    pub(crate) conn: &'a mut crate::quic::connection::Connection,
    pub(crate) now: std::time::Instant,
}

impl Transport for QuicTransport<'_> {
    fn open_stream(&mut self, bidirectional: bool) -> Result<u64, TransportError> {
        self.conn.open_stream(bidirectional)
    }
    fn write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, TransportError> {
        self.conn.stream_write(id, data, fin)
    }
    fn read(&mut self, id: u64, buf: &mut [u8]) -> Result<(usize, bool), TransportError> {
        self.conn.stream_read(id, buf)
    }
    fn reset(&mut self, id: u64, error: u64) -> Result<(), TransportError> {
        self.conn.stream_reset(id, error)
    }
    fn stop_sending(&mut self, id: u64, error: u64) -> Result<(), TransportError> {
        self.conn.stream_stop_sending(id, error)
    }
    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.conn.poll_stream_event()
    }
    fn close(&mut self, error: u64, reason: &[u8]) {
        self.conn.close(self.now, error, reason);
    }
}

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
#[cfg(any(test, pratique_fuzzing))]
#[path = "connection_harness.rs"]
pub(crate) mod harness;
