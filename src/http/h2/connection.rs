//! The client side of an HTTP/2 connection (RFC 9113) as a state machine that does no I/O: bytes the peer sent go in
//! through [`Connection::receive`] and [`Connection::process`], bytes to send come out of [`Connection::output`],
//! and what the application does (open a stream, send a body, read a response) are calls on it.
//!
//! What it takes care of: the connection preface and SETTINGS in both directions; HPACK; header blocks in several
//! frames; flow control, both ways, at the stream and the connection (credit goes back to the peer as the
//! application reads, so a stream that nobody reads holds the peer back instead of piling up in memory);
//! PING and GOAWAY; stream and connection errors, with the right RST_STREAM and GOAWAY; and the checks RFC 9113
//! section 8 asks of a response (the pseudo-headers, connection-specific fields, Content-Length against the data).
//! Push is switched off, and a PUSH_PROMISE is a connection error. Priorities are not sent and are ignored.
//!
//! What it guards against, as it reads what a server sent: frames larger than it allows or out of order, header
//! blocks that go on and on, windows that overflow or are overrun, floods of frames that need answers or of
//! frames that carry nothing, and requests it could not have made. A connection error queues a GOAWAY, fails every
//! stream and makes the connection unusable; the application sees it from [`Connection::process`] and from each
//! stream's next [`Connection::poll_stream`].

use super::frame::{self, flag, kind, setting, ErrorCode, Frame, FrameError, Header, DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW, HEADER_LEN, MAX_FRAME_SIZE_LIMIT, MAX_WINDOW, PREFACE};
use super::hpack::{self, Decoder, Encoder, FieldRef};
use std::collections::HashMap;
use std::fmt;

/// What this endpoint asks of the peer and allows it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    /// SETTINGS_INITIAL_WINDOW_SIZE: how much of a response the peer may send on a stream before we read some.
    pub(crate) stream_window: u32,
    /// How much the peer may send on all streams together before we read some.
    pub(crate) connection_window: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE: the largest response header list we take (and the most that one header
    /// block, compressed, may be).
    pub(crate) max_header_list: u32,
}

impl Default for Config {
    fn default() -> Config {
        // Big enough that a fast path with a long delay is not held up by waiting for credit: a window has to cover
        // the bandwidth-delay product (100 MB/s at 80 ms is 8 MB). The memory this can cost is bounded by the
        // connection window, and only for a response the application is slow to read.
        Config { stream_window: 8 << 20, connection_window: 32 << 20, max_header_list: 64 << 10 }
    }
}

/// How much credit may build up (bytes the application has read, and the peer has not been told it can send again)
/// before it is announced: half the window, but never more than this, so that a large window does not mean
/// WINDOW_UPDATEs that come late. (Waiting for half of 8 MiB would hold a fast sender back for a whole round trip's
/// worth, again and again; with this much, a window of 8 MiB is never less than 7 MiB open, so a path with a round trip
/// of 70 ms is kept full at 100 MB/s.) It is not much less either: every update costs a frame, a TLS record, a system
/// call and the wake-up of the writer, and at 128 KiB that was one for every read on a fast download.
pub(crate) const REFRESH_CAP: i64 = 1 << 20;

/// The most that [`Connection::take_stream_data`] moves in one go: what is waiting beyond this stays, so that what an
/// application holds that the connection has already given credit for is bounded (by this, on top of the window).
pub(crate) const TAKE_MAX: usize = 1 << 20;

/// The most room made for a body that is collected (see [`Connection::collect_stream`]) before it comes: what the
/// response says its length is, up to this. (Room that is not written to costs no memory.)
pub(crate) const COLLECT_ROOM_MAX: u64 = 256 << 20;

/// Why a collected response that goes past its limit loses its stream.
pub(crate) const BODY_TOO_BIG: &str = "response body exceeds the configured size limit";

/// Where the body bytes of a poll go.
enum Sink<'a> {
    /// Copied into the buffer.
    Copy(&'a mut [u8]),
    /// Moved into the vector.
    Take(&'a mut Vec<u8>),
}

/// The buffer of the application that reads one stream, when the application is also the one feeding the connection the
/// server's bytes (see [`Connection::feed_direct`]): the body of that stream is written straight into it as it is taken
/// in, instead of being kept in the stream's own buffer to be copied out by a poll (BACKLOG B-87).
pub(crate) struct Direct<'a> {
    stream: u32,
    out: &'a mut [u8],
    written: usize,
}

impl<'a> Direct<'a> {
    pub(crate) fn new(stream: u32, out: &'a mut [u8]) -> Direct<'a> {
        Direct { stream, out, written: 0 }
    }

    /// How many bytes of the body were written into the buffer (from its start), all of which count as read.
    pub(crate) fn written(&self) -> usize {
        self.written
    }

    /// The buffer has no room left.
    pub(crate) fn full(&self) -> bool {
        self.written == self.out.len()
    }
}

/// The credit at which a window of this size is refreshed.
pub(crate) fn refresh_threshold(window: u32) -> i64 {
    (window as i64 / 2).min(REFRESH_CAP)
}

/// The HPACK table size this endpoint announces.
const HEADER_TABLE_SIZE: u32 = hpack::DEFAULT_TABLE_SIZE as u32;

/// The most frames one header block may be made of.
const MAX_BLOCK_FRAMES: u32 = 256;

/// The most 1xx responses one stream may get before its final one.
pub(crate) const MAX_INTERIM: u32 = 32;

/// How much output may wait to be sent before [`Connection::send_data`] takes no more.
const OUTPUT_HIGH_WATER: usize = 256 << 10;

/// How much output the peer may make us queue by asking for answers (PING, SETTINGS) before it is too much.
const CONTROL_BACKLOG: usize = 1 << 20;

/// How many frames in a row that carry nothing (empty DATA without END_STREAM) are too many.
const EMPTY_FRAMES: u32 = 10_000;

/// The largest stream id.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;

pub(crate) type Fields = Vec<(String, String)>;

/// The head of a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) status: u16,
    pub(crate) headers: Fields,
}

/// The connection is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionError {
    pub(crate) code: ErrorCode,
    pub(crate) reason: String,
    /// True if this endpoint found the fault (and sent a GOAWAY saying so), false if the peer said it was going
    /// away with an error.
    pub(crate) local: bool,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/2 connection {}: {} ({})", if self.local { "failed" } else { "closed by the server" }, self.reason, self.code)
    }
}

/// A stream is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamError {
    pub(crate) code: ErrorCode,
    pub(crate) reason: String,
    /// True if the request cannot have been acted on (the server refused the stream, or said in a GOAWAY that it
    /// did not get that far), so that sending it again on another connection is safe whatever the method.
    pub(crate) retry_safe: bool,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/2 stream failed: {} ({})", self.reason, self.code)
    }
}

/// Why a stream could not be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// The peer's limit on concurrent streams is reached; try again when one has ended.
    Full,
    /// The connection is going away or is lost, or has no stream ids left: use another.
    Unavailable,
    /// The request cannot be sent as HTTP/2 (a bad header, a header list over the peer's limit).
    Invalid(String),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Full => f.write_str("the HTTP/2 connection has as many streams as the server allows"),
            OpenError::Unavailable => f.write_str("the HTTP/2 connection cannot take another request"),
            OpenError::Invalid(why) => write!(f, "the request cannot be sent over HTTP/2: {why}"),
        }
    }
}

/// A request to send.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) scheme: &'a str,
    /// The host and, unless it is the default, the port: what `Host` would have been.
    pub(crate) authority: &'a str,
    /// The path and query.
    pub(crate) path: &'a str,
    /// The header fields other than the pseudo-headers. Names may have capitals (they are lowered); `Host`,
    /// `Connection` and the other connection-specific fields are dropped, as RFC 9113 section 8.2.2 requires.
    pub(crate) headers: &'a [(String, String)],
    /// Names (lower case) of the fields of `headers` whose values are secrets, besides the ones that always are (`SENSITIVE`): they are
    /// written so that a compression table does not keep them (HPACK's and QPACK's "never indexed"). A caller that gives each hop its own
    /// credentials names them here.
    pub(crate) secret: &'a [String],
}

/// What happened on a stream, as [`Connection::poll_stream`] gives it, in this order: the head, any number of
/// pieces of body, perhaps trailers, the end; or a failure at any point.
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

/// What a stream that is collecting has: see [`Connection::collected`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Collected {
    /// The response is not complete. The number grows as it comes (the head, then the bytes of the body), so that whether it
    /// is going on can be told.
    Pending(u64),
    /// The whole body was moved into the vector; and the head, if the application has not taken it.
    Done(Option<Head>),
    /// The stream failed (after its head came, or before).
    Failed { error: StreamError, got_head: bool },
}

#[derive(Debug)]
struct Stream {
    /// How much DATA we may still send on it.
    send_window: i64,
    /// How much the peer may still send on it.
    recv_window: i64,
    /// Body bytes the application has read and for which the peer has not yet been given the credit.
    unannounced: u32,
    local_ended: bool,
    remote_ended: bool,
    /// The response is to a HEAD request: no body comes whatever Content-Length says.
    head_request: bool,
    /// The response (a 204 or 304, or one to HEAD) has no body, whatever Content-Length says.
    bodiless: bool,
    /// How many 1xx responses came before the final one.
    interim: u32,
    head: Option<Head>,
    got_head: bool,
    trailers: Option<Fields>,
    body: Vec<u8>,
    body_pos: usize,
    expected: Option<u64>,
    received: u64,
    failure: Option<StreamError>,
    /// The application has said it will take the whole body at once (see [`Connection::collect_stream`]): the body is
    /// kept as it comes, the peer has credit for it as it comes, and nothing in `body` counts as unread.
    collecting: bool,
    /// How much body a collecting stream may take, all told.
    collect_limit: u64,
}

impl Stream {
    fn active(&self) -> bool {
        self.failure.is_none() && !(self.local_ended && self.remote_ended)
    }

    fn unread(&self) -> usize {
        if self.collecting {
            0
        } else {
            self.body.len() - self.body_pos
        }
    }

    /// Makes room in the body of a stream that is collecting, for as much as the response says is coming (up to
    /// [`COLLECT_ROOM_MAX`], and the limit). False if the response says it is more than the limit: it is too big.
    fn make_room(&mut self) -> bool {
        if !self.collecting || !self.got_head {
            return true;
        }
        let left = self.expected.map_or(0, |n| n.saturating_sub(self.received));
        if self.expected.is_some_and(|n| n > self.collect_limit) {
            return false;
        }
        let room = left.min(self.collect_limit.saturating_sub(self.received)).min(COLLECT_ROOM_MAX);
        self.body.reserve_exact(room as usize);
        true
    }

    /// Drops the part of the body buffer that has been read, once that is a good part of it (so a reader that never
    /// quite empties the buffer does not make it as big as the whole response). The cost of the move is paid for by
    /// the reading it follows.
    fn compact(&mut self) {
        if self.body_pos >= 32 * 1024 && self.body_pos * 2 >= self.body.len() {
            self.body.drain(..self.body_pos);
            self.body_pos = 0;
        }
    }
}

/// A header block being received.
#[derive(Debug)]
struct Block {
    stream: u32,
    end_stream: bool,
    bytes: Vec<u8>,
    frames: u32,
}

/// A DATA frame whose payload is still arriving. A frame is usually cut by the record boundaries of the transport, and
/// collecting the pieces to handle it whole would copy every byte once more; so the payload of a frame that is not
/// complete goes where it belongs as it comes (see [`Connection::run`]).
#[derive(Debug)]
struct Incoming {
    stream: u32,
    /// Bytes of the payload still to come.
    remaining: usize,
    end_stream: bool,
    /// True if the bytes are the stream's body; false if they are thrown away (the stream is gone, or this frame lost it).
    keep: bool,
}

/// Which waiters the frames just handled can have news for: the streams they were about, and whether any was about
/// the connection as a whole (SETTINGS, GOAWAY, a window for the connection, or the connection's end), which can
/// matter to every stream. It is always a superset of what changed: a stream in the list may have nothing new, and
/// when the list would be long it is replaced by "everyone". See [`Connection::take_news`].
#[derive(Debug, Default)]
pub(crate) struct News {
    streams: Vec<u32>,
    everyone: bool,
}

impl News {
    /// The most streams listed by name: beyond this the news is for everyone.
    const MOST: usize = 256;

    fn touch(&mut self, id: u32) {
        if self.everyone || self.streams.last() == Some(&id) {
            return;
        }
        if self.streams.len() >= News::MOST {
            self.everyone();
        } else {
            self.streams.push(id);
        }
    }

    fn everyone(&mut self) {
        self.everyone = true;
        self.streams.clear();
    }

    /// The streams with news (not meaningful if [`News::everyone`] is true).
    pub(crate) fn streams(&self) -> &[u32] {
        &self.streams
    }

    /// True if the news is for every stream.
    pub(crate) fn is_for_everyone(&self) -> bool {
        self.everyone
    }

    pub(crate) fn clear(&mut self) {
        self.streams.clear();
        self.everyone = false;
    }
}

pub(crate) struct Connection {
    config: Config,
    decoder: Decoder,
    encoder: Encoder,
    inbound: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    streams: HashMap<u32, Stream>,
    next_stream_id: u32,
    /// How much DATA we may still send, over all streams.
    send_window: i64,
    /// How much the peer may still send, over all streams.
    recv_window: i64,
    /// Credit for the connection that the application has earned and the peer has not been given.
    unannounced: u32,
    // what the peer's SETTINGS say
    peer_initial_window: i64,
    peer_max_frame: usize,
    peer_max_concurrent: u32,
    peer_max_header_list: u32,
    got_peer_settings: bool,
    block: Option<Block>,
    /// The DATA frame whose payload is arriving, if one is. While it is, `inbound` is empty (unless a test has put
    /// bytes in it with `receive`, which `process` takes in order).
    incoming: Option<Incoming>,
    empty_frames: u32,
    goaway: Option<(u32, ErrorCode)>,
    error: Option<ConnectionError>,
    news: News,
}

impl Connection {
    /// A client connection whose preface and SETTINGS are waiting in the output.
    pub(crate) fn new(config: Config) -> Connection {
        let mut c = Connection {
            config,
            decoder: Decoder::new(HEADER_TABLE_SIZE as usize, config.max_header_list as usize),
            encoder: Encoder::new(),
            inbound: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            streams: HashMap::new(),
            next_stream_id: 1,
            send_window: DEFAULT_WINDOW as i64,
            recv_window: config.connection_window.max(DEFAULT_WINDOW) as i64,
            unannounced: 0,
            peer_initial_window: DEFAULT_WINDOW as i64,
            peer_max_frame: DEFAULT_MAX_FRAME_SIZE as usize,
            peer_max_concurrent: u32::MAX,
            peer_max_header_list: u32::MAX,
            got_peer_settings: false,
            block: None,
            incoming: None,
            empty_frames: 0,
            goaway: None,
            error: None,
            news: News::default(),
        };
        c.out.extend_from_slice(PREFACE);
        frame::write_settings(
            &mut c.out,
            &[
                (setting::HEADER_TABLE_SIZE, HEADER_TABLE_SIZE),
                (setting::ENABLE_PUSH, 0),
                (setting::INITIAL_WINDOW_SIZE, config.stream_window),
                (setting::MAX_HEADER_LIST_SIZE, config.max_header_list),
            ],
        );
        if config.connection_window > DEFAULT_WINDOW {
            frame::write_window_update(&mut c.out, 0, config.connection_window - DEFAULT_WINDOW);
        }
        c
    }

    // -------------------------------------------------------------------------------------------- the wire

    /// Takes bytes the peer sent. Nothing is looked at until [`process`](Connection::process). (The transport uses
    /// [`feed`](Connection::feed), which does both without copying what it can handle where it is.)
    #[cfg(test)]
    pub(crate) fn receive(&mut self, data: &[u8]) {
        if self.error.is_none() {
            self.inbound.extend_from_slice(data);
        }
    }

    /// The bytes waiting to be sent.
    pub(crate) fn output(&self) -> &[u8] {
        &self.out[self.out_pos..]
    }

    pub(crate) fn wants_write(&self) -> bool {
        self.out_pos < self.out.len()
    }

    /// `n` bytes of [`output`](Connection::output) have been sent.
    pub(crate) fn consume_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out.len());
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
    }

    /// Hands over what the frames handled since the last call have news for (see [`News`]): `into` is replaced by it,
    /// and the connection starts a new list.
    pub(crate) fn take_news(&mut self, into: &mut News) {
        into.clear();
        std::mem::swap(&mut self.news, into);
    }

    /// Handles every complete frame received so far. An error means the connection is lost (the GOAWAY is in the
    /// output); streams that were still going have failed.
    pub(crate) fn process(&mut self) -> Result<(), ConnectionError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let buf = std::mem::take(&mut self.inbound);
        let (used, result) = self.run(&buf, None);
        self.inbound = buf;
        self.inbound.drain(..used); // what is left is a part of a frame; the allocation stays
        self.finish(result)
    }

    /// Takes bytes the peer sent and handles every complete frame in them (and in what was left before). Nothing is
    /// copied that need not be: frames in `data` are handled where they are; the start of a frame that was left
    /// from before is completed with just the bytes it needs; the payload of a DATA frame that is cut off is passed
    /// on as it comes, and only a part of any other frame at the end is kept for the next call. Same errors as
    /// [`process`](Connection::process). (The transport feeds with [`feed_direct`](Connection::feed_direct), this with no
    /// reader's buffer.)
    #[cfg(any(test, pratique_fuzzing))]
    pub(crate) fn feed(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        self.feed_direct(data, None)
    }

    /// [`feed`](Connection::feed), by the application that reads `direct`'s stream: the body of that stream is written
    /// into `direct`'s buffer as it is taken in, as far as the buffer has room, and those bytes are read (the peer gets
    /// credit for them as for bytes a poll returns, and they are not news for the stream). Only bytes that a poll would
    /// return next go there: none while the stream holds bytes that were not read, or a head that was not taken, or is
    /// collecting; what does not fit is kept for a poll as usual, and so is everything after it. So a reader that feeds
    /// with an empty buffer, or whose stream has something waiting, sees exactly what [`feed`](Connection::feed) would
    /// have done.
    pub(crate) fn feed_direct(&mut self, mut data: &[u8], mut direct: Option<&mut Direct<'_>>) -> Result<(), ConnectionError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.incoming.is_some() && !self.inbound.is_empty() {
            // (only the tests, with `receive`, make this happen)
            self.inbound.extend_from_slice(data);
            return self.process();
        }
        // what was kept is the start of one frame: finish it with the bytes it lacks, no more
        while !self.inbound.is_empty() {
            let need = self.inbound_lacks();
            let take = need.min(data.len());
            self.inbound.extend_from_slice(&data[..take]);
            data = &data[take..];
            let buf = std::mem::take(&mut self.inbound);
            let (used, result) = self.run(&buf, direct.as_deref_mut());
            self.inbound = buf;
            self.inbound.drain(..used);
            if result.is_err() {
                return self.finish(result);
            }
            if take < need || (take == 0 && used == 0) {
                return Ok(()); // all of `data` is in `inbound`, and it is still not a whole frame
            }
        }
        let (used, result) = self.run(data, direct);
        if result.is_ok() {
            self.inbound.extend_from_slice(&data[used..]);
        }
        self.finish(result)
    }

    /// How many bytes the frame at the start of `inbound` still lacks: of its header, or of the frame as a whole.
    fn inbound_lacks(&self) -> usize {
        if self.inbound.len() < HEADER_LEN {
            return HEADER_LEN - self.inbound.len();
        }
        let header = Header::parse(self.inbound[..HEADER_LEN].try_into().expect("nine bytes"));
        (HEADER_LEN + header.length.min(DEFAULT_MAX_FRAME_SIZE) as usize).saturating_sub(self.inbound.len())
    }

    /// Handles the complete frames at the start of `buf`, and passes on the payload of a DATA frame that is cut off
    /// at its end (when it can be told what to do with the bytes from the header alone: the frame is not padded,
    /// and nothing else is in the way): how many bytes of `buf` that was, and how it went. A frame that is not
    /// complete and is not one of those is left, and not counted.
    fn run(&mut self, buf: &[u8], mut direct: Option<&mut Direct<'_>>) -> (usize, Result<(), ConnectionError>) {
        let mut pos = 0;
        let result = loop {
            if self.incoming.is_some() {
                pos += self.pass_on(&buf[pos..], direct.as_deref_mut());
                if self.incoming.is_some() {
                    break Ok(()); // all of `buf` went to it
                }
                continue;
            }
            if buf.len() - pos < HEADER_LEN {
                break Ok(());
            }
            let header = Header::parse(buf[pos..pos + HEADER_LEN].try_into().expect("nine bytes"));
            if header.length > DEFAULT_MAX_FRAME_SIZE {
                break Err(connection_error(ErrorCode::FRAME_SIZE_ERROR, "a frame larger than the frame size this endpoint allows"));
            }
            let end = pos + HEADER_LEN + header.length as usize;
            if buf.len() < end {
                let streamable = header.kind == kind::DATA && header.flags & flag::PADDED == 0 && header.stream != 0 && self.got_peer_settings && self.block.is_none();
                if !streamable {
                    break Ok(());
                }
                pos += HEADER_LEN;
                match self.begin_data(&header) {
                    Ok(()) => continue,
                    Err(e) => break Err(e),
                }
            }
            if !self.got_peer_settings && !(header.kind == kind::SETTINGS && header.flags & flag::ACK == 0) {
                break Err(connection_error(ErrorCode::PROTOCOL_ERROR, "the server's first frame is not SETTINGS"));
            }
            let step = match frame::parse(&header, &buf[pos + HEADER_LEN..end]) {
                Ok(f) => self.handle(f, direct.as_deref_mut()),
                Err(FrameError { code, stream: None, reason }) => Err(connection_error(code, reason)),
                Err(FrameError { code, stream: Some(id), reason }) => {
                    self.stream_error(id, code, reason);
                    Ok(())
                }
            };
            pos = end;
            if let Err(e) = step {
                break Err(e);
            }
        };
        (pos, result)
    }

    /// The end of [`process`](Connection::process) and [`feed`](Connection::feed): a connection error ends the
    /// connection.
    fn finish(&mut self, result: Result<(), ConnectionError>) -> Result<(), ConnectionError> {
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                self.inbound.clear();
                if e.local {
                    frame::write_goaway(&mut self.out, 0, e.code, e.reason.as_bytes());
                }
                self.die(e.clone());
                Err(e)
            }
        }
    }

    /// The connection is lost: every stream whose response is not complete fails (one whose response is complete
    /// can still be read).
    fn die(&mut self, error: ConnectionError) {
        self.news.everyone();
        self.incoming = None;
        for s in self.streams.values_mut() {
            if s.failure.is_none() && !s.remote_ended {
                s.failure = Some(StreamError { code: error.code, reason: error.to_string(), retry_safe: false });
                if s.collecting {
                    // a body that is wanted whole is of no use in part (and may be a great deal)
                    s.body = Vec::new();
                }
            }
        }
        self.error = Some(error);
    }

    /// The transport was closed by the peer (or broke): what was not finished is lost. Streams the server said in
    /// a GOAWAY it had not got to are marked as safe to retry already.
    pub(crate) fn peer_closed(&mut self) {
        if self.error.is_none() {
            let error = match self.goaway {
                Some((_, code)) if code != ErrorCode::NO_ERROR => ConnectionError { code, reason: "the server said it was going away and closed the connection".into(), local: false },
                _ => ConnectionError { code: ErrorCode::NO_ERROR, reason: "the server closed the connection".into(), local: false },
            };
            self.die(error);
        }
    }

    /// Panics unless the books balance: for the connection and for every stream that has not failed, what the peer
    /// may still send, what it has not been told it may send again and what is held unread add up to the window; and
    /// the window for what we send is within bounds. (For the tests and the fuzzer: whatever the peer sends, this
    /// must hold.)
    #[cfg(any(test, pratique_fuzzing))]
    pub(crate) fn assert_books(&self) {
        if self.error.is_some() {
            return;
        }
        let held: i64 = self.streams.values().map(|s| s.unread() as i64).sum();
        let initial = self.config.connection_window.max(DEFAULT_WINDOW) as i64;
        assert_eq!(self.recv_window + self.unannounced as i64 + held, initial, "the connection window");
        assert!(self.recv_window >= 0);
        for (id, s) in self.streams.iter().filter(|(_, s)| s.failure.is_none()) {
            assert_eq!(s.recv_window + s.unannounced as i64 + s.unread() as i64, self.config.stream_window as i64, "the window of stream {id}");
        }
        assert!((0..=MAX_WINDOW as i64).contains(&self.send_window));
    }

    /// Why the connection is lost, if it is.
    #[cfg(test)]
    pub(crate) fn error(&self) -> Option<&ConnectionError> {
        self.error.as_ref()
    }

    /// Asks the peer to stop opening streams and finish up: a GOAWAY with no error. (The connection has no streams
    /// of the peer's, so the last stream id in it is 0.)
    /// Queues a PING (its answer is taken and dropped): something for the server to answer at once, which wakes whoever
    /// is waiting for the socket to be readable.
    pub(crate) fn ping(&mut self, data: [u8; 8]) {
        if self.error.is_none() {
            frame::write_ping(&mut self.out, false, data);
        }
    }

    pub(crate) fn close(&mut self) {
        if self.error.is_none() {
            frame::write_goaway(&mut self.out, 0, ErrorCode::NO_ERROR, b"");
            let error = ConnectionError { code: ErrorCode::NO_ERROR, reason: "closed by this endpoint".into(), local: true };
            self.die(error);
        }
    }

    // -------------------------------------------------------------------------------------------- requests

    /// The number of streams that are not finished.
    pub(crate) fn active_streams(&self) -> usize {
        self.streams.values().filter(|s| s.active()).count()
    }

    /// True if the connection may be given another request now.
    pub(crate) fn can_open_stream(&self) -> bool {
        self.usable() && (self.active_streams() as u64) < self.peer_max_concurrent as u64
    }

    /// False once the connection is lost, has been told to go away, or has used all its stream ids.
    pub(crate) fn usable(&self) -> bool {
        self.error.is_none() && self.goaway.is_none() && self.next_stream_id <= MAX_STREAM_ID
    }

    /// Sends the head of a request on a new stream. With `end_stream` the request has no body and the stream is
    /// half closed already; without, the body goes by [`send_data`](Connection::send_data).
    pub(crate) fn open_stream(&mut self, request: &Request<'_>, end_stream: bool) -> Result<u32, OpenError> {
        if !self.usable() {
            return Err(OpenError::Unavailable);
        }
        if !self.can_open_stream() {
            return Err(OpenError::Full);
        }
        let lowered = lower_names(request.headers);
        let list = request_fields(request, &lowered)?;
        let size: usize = list.iter().map(|f| f.name.len() + f.value.len() + 32).sum();
        if size as u64 > self.peer_max_header_list as u64 {
            return Err(OpenError::Invalid(format!("the header list is {size} bytes and the server takes {}", self.peer_max_header_list)));
        }
        let mut block = Vec::new();
        self.encoder.encode(&list, &mut block);
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        frame::write_header_block(&mut self.out, id, end_stream, &block, self.peer_max_frame);
        self.streams.insert(
            id,
            Stream {
                send_window: self.peer_initial_window,
                recv_window: self.config.stream_window as i64,
                unannounced: 0,
                local_ended: end_stream,
                remote_ended: false,
                head_request: request.method.eq_ignore_ascii_case("HEAD"),
                bodiless: false,
                interim: 0,
                head: None,
                got_head: false,
                trailers: None,
                body: Vec::new(),
                body_pos: 0,
                expected: None,
                received: 0,
                failure: None,
                collecting: false,
                collect_limit: u64::MAX,
            },
        );
        Ok(id)
    }

    /// How many bytes of body [`send_data`](Connection::send_data) would take now on this stream.
    pub(crate) fn send_capacity(&self, id: u32) -> usize {
        let Some(s) = self.streams.get(&id) else { return 0 };
        if s.failure.is_some() || s.local_ended || self.error.is_some() {
            return 0;
        }
        let room = OUTPUT_HIGH_WATER.saturating_sub(self.out.len() - self.out_pos);
        s.send_window.min(self.send_window).max(0).min(room as i64) as usize
    }

    /// Sends as much of `data` as the windows and the output backlog allow, as DATA frames, and says how much.
    /// With `end_stream` the stream is closed on this side once all of `data` has gone; the end is not sent if
    /// less than all of it did, so the caller calls again with the rest. An empty `data` with `end_stream` always
    /// goes. An error if the stream has failed or was already ended by this side.
    pub(crate) fn send_data(&mut self, id: u32, data: &[u8], end_stream: bool) -> Result<usize, StreamError> {
        let n = self.send_capacity(id).min(data.len());
        let Some(s) = self.streams.get_mut(&id) else {
            return Err(local_error("there is no such stream"));
        };
        if let Some(f) = &s.failure {
            return Err(f.clone());
        }
        if s.local_ended {
            return Err(local_error("the request body was already ended"));
        }
        if self.error.is_some() {
            return Err(local_error("the connection is lost"));
        }
        let finish = end_stream && n == data.len();
        if n == 0 && !finish {
            return Ok(0);
        }
        let mut rest = &data[..n];
        loop {
            let piece = rest.len().min(self.peer_max_frame);
            let last = piece == rest.len();
            frame::write_data(&mut self.out, id, finish && last, &rest[..piece]);
            rest = &rest[piece..];
            if last {
                break;
            }
        }
        s.send_window -= n as i64;
        self.send_window -= n as i64;
        if finish {
            s.local_ended = true;
        }
        Ok(n)
    }

    /// What the stream has for the application: see [`StreamEvent`]. Reading body bytes gives the peer credit to
    /// send more.
    pub(crate) fn poll_stream(&mut self, id: u32, buf: &mut [u8]) -> StreamEvent {
        self.poll(id, Sink::Copy(buf))
    }

    /// Like [`poll_stream`](Connection::poll_stream), but the body bytes are not copied into a buffer of the caller's: up to
    /// [`TAKE_MAX`] of what is waiting is moved into `into` (which is emptied first), and [`StreamEvent::Data`] says how
    /// many bytes that is. When everything that is waiting is taken the buffers are swapped, so that this costs no
    /// copy and no allocation (the connection goes on with the allocation `into` had); the caller copies the bytes out
    /// where it likes, without holding whatever lock this connection is behind. The peer is given credit as for
    /// bytes that were read.
    pub(crate) fn take_stream_data(&mut self, id: u32, into: &mut Vec<u8>) -> StreamEvent {
        into.clear();
        self.poll(id, Sink::Take(into))
    }

    /// The application will read the rest of the response whole, into memory, and not piece by piece: from now on the
    /// body is kept as it comes in one buffer (made `room` bytes big, if it is known what is coming), and the peer is
    /// given the credit for it as it arrives, not as it is read, since nobody will read it so. [`collected`](Connection::collected)
    /// hands the buffer over once the response is complete; nothing is copied on the way. What is kept is bounded by
    /// `limit` (the body, all told, from its first byte): a response that goes past it loses its stream.
    pub(crate) fn collect_stream(&mut self, id: u32, limit: u64) {
        // the rest of a DATA frame that is arriving for the stream counts as received: it was let in as it began, when there
        // was no limit to check it against (found by fuzzing on the Mac: collecting begun in the middle of a frame took
        // the rest of it past the limit)
        let arriving = self.incoming.as_ref().filter(|i| i.stream == id && i.keep).map_or(0, |i| i.remaining as u64);
        let Some(s) = self.streams.get_mut(&id) else { return };
        if s.collecting || s.failure.is_some() {
            return;
        }
        // what is held unread is the start of what is collected, and as good as read
        if s.body_pos > 0 {
            s.body.drain(..s.body_pos);
            s.body_pos = 0;
        }
        let held = s.body.len();
        s.collecting = true;
        s.collect_limit = limit;
        let too_big = s.received + arriving > limit || !s.make_room();
        s.unannounced += held as u32;
        self.announce_stream(id);
        self.credit_connection(held as u32);
        if too_big {
            self.stream_error(id, ErrorCode::CANCEL, BODY_TOO_BIG);
        }
    }

    /// The body of a stream that is collecting: if its response is complete, all of it is moved into `into` (which is
    /// emptied first; it is the stream's own buffer, swapped for `into`, so this costs no copy) and the answer is
    /// [`Collected::Done`], with the head if it has not been taken yet; if the stream failed, the failure; else how far it
    /// has come, to tell whether it is going on. (A stream that collects is not news until it is done or has failed: the
    /// application that has asked for the whole response is not woken for the head, or for pieces of the body.)
    pub(crate) fn collected(&mut self, id: u32, into: &mut Vec<u8>) -> Collected {
        let Some(s) = self.streams.get_mut(&id) else {
            return Collected::Failed { error: local_error("there is no such stream"), got_head: false };
        };
        if let Some(f) = &s.failure {
            return Collected::Failed { error: f.clone(), got_head: s.got_head };
        }
        if !s.collecting {
            return Collected::Failed { error: local_error("the stream is not collecting"), got_head: s.got_head };
        }
        if s.remote_ended {
            into.clear();
            std::mem::swap(&mut s.body, into);
            return Collected::Done(s.head.take());
        }
        Collected::Pending(s.received + u64::from(s.got_head))
    }

    fn poll(&mut self, id: u32, sink: Sink<'_>) -> StreamEvent {
        let Some(s) = self.streams.get_mut(&id) else {
            return StreamEvent::Failed(local_error("there is no such stream"));
        };
        let wants_body = match &sink {
            Sink::Copy(buf) => !buf.is_empty(),
            Sink::Take(_) => true,
        };
        // what arrived before a failure is for the application to see first, then the failure: whether a response's
        // head and the start of its body are seen must not depend on whether the reset came in the same read
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
            s.unannounced += n as u32;
            self.announce_stream(id);
            self.credit_connection(n as u32);
            return StreamEvent::Data(n);
        }
        if let Some(f) = &s.failure {
            if s.unread() == 0 || !wants_body {
                return StreamEvent::Failed(f.clone());
            }
        }
        if s.unread() == 0 {
            if let Some(t) = s.trailers.take() {
                return StreamEvent::Trailers(t);
            }
            if s.remote_ended {
                return StreamEvent::End;
            }
        }
        StreamEvent::Pending
    }

    /// Tells the peer it may send more on the stream, once the application has read (or padding has used) half of
    /// the window (or [`REFRESH_CAP`], if that is less). (A stream whose response is complete is sent nothing more.)
    fn announce_stream(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        if s.remote_ended || s.failure.is_some() || self.error.is_some() || s.unannounced == 0 || (s.unannounced as i64) < refresh_threshold(self.config.stream_window) {
            return;
        }
        let credit = std::mem::take(&mut s.unannounced);
        s.recv_window += credit as i64;
        frame::write_window_update(&mut self.out, id, credit);
    }

    /// Gives the peer credit for `n` bytes of DATA that are no longer held here (read, or thrown away), in a
    /// WINDOW_UPDATE once enough has built up.
    fn credit_connection(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.unannounced += n;
        if self.unannounced as i64 >= refresh_threshold(self.config.connection_window.max(DEFAULT_WINDOW)) && self.error.is_none() {
            let credit = std::mem::take(&mut self.unannounced);
            self.recv_window += credit as i64;
            frame::write_window_update(&mut self.out, 0, credit);
        }
    }

    /// The application is done with the stream: what is still unread is dropped, and if the exchange was not
    /// finished the server is told to stop (RST_STREAM CANCEL).
    pub(crate) fn release_stream(&mut self, id: u32) {
        let Some(s) = self.streams.remove(&id) else { return };
        let unread = s.unread() as u32;
        if s.failure.is_none() && !(s.local_ended && s.remote_ended) && self.error.is_none() {
            frame::write_rst_stream(&mut self.out, id, ErrorCode::CANCEL);
        }
        if unread > 0 {
            self.credit_connection(unread);
        }
    }

    // -------------------------------------------------------------------------------------------- frames

    fn handle(&mut self, f: Frame<'_>, direct: Option<&mut Direct<'_>>) -> Result<(), ConnectionError> {
        // a header block in progress is followed by its CONTINUATION frames and nothing else (RFC 9113 section 4.3)
        if let Some(block) = &self.block {
            match &f {
                Frame::Continuation { stream, .. } if *stream == block.stream => {}
                _ => return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "a frame in the middle of a header block")),
            }
        }
        if !matches!(f, Frame::Data { data: [], end_stream: false, .. }) {
            self.empty_frames = 0;
        }
        // who may be waiting for what this frame brings
        match &f {
            // (HEADERS and DATA are news as they are taken in, which is when it is known whether a stream that collects is
            // to be told: only when its response is complete)
            Frame::RstStream { stream, .. } => self.news.touch(*stream),
            Frame::WindowUpdate { stream, .. } if *stream != 0 => self.news.touch(*stream),
            Frame::WindowUpdate { .. } | Frame::Settings { .. } | Frame::GoAway { .. } | Frame::PushPromise { .. } => self.news.everyone(),
            Frame::Data { .. } | Frame::Headers { .. } | Frame::Continuation { .. } | Frame::Ping { .. } | Frame::Priority { .. } | Frame::Unknown { .. } => {}
        }
        match f {
            Frame::Data { stream, end_stream, data, flow_len } => self.on_data(stream, end_stream, data, flow_len, direct),
            Frame::Headers { stream, end_stream, end_headers, fragment } => {
                self.require_server_stream_known(stream)?;
                self.block = Some(Block { stream, end_stream, bytes: Vec::new(), frames: 0 });
                self.on_fragment(end_headers, fragment)
            }
            Frame::Continuation { end_headers, fragment, .. } => {
                if self.block.is_none() {
                    return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "CONTINUATION with no header block to continue"));
                }
                self.on_fragment(end_headers, fragment)
            }
            Frame::Priority { .. } | Frame::Unknown { .. } => Ok(()),
            Frame::RstStream { stream, code } => self.on_reset(stream, code),
            Frame::Settings { ack, values } => self.on_settings(ack, &values),
            Frame::PushPromise { .. } => Err(connection_error(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE, though push is switched off")),
            Frame::Ping { ack, data } => {
                if !ack {
                    self.control_backlog()?;
                    frame::write_ping(&mut self.out, true, data);
                }
                Ok(())
            }
            Frame::GoAway { last_stream, code, debug } => self.on_goaway(last_stream, code, debug),
            Frame::WindowUpdate { stream, increment } => self.on_window_update(stream, increment),
        }
    }

    /// A frame for a stream of the server's own (even numbered) or one that was never opened is a connection error;
    /// one for a stream that has been opened and is gone is for the caller to ignore.
    fn require_server_stream_known(&self, stream: u32) -> Result<(), ConnectionError> {
        if stream % 2 == 0 {
            return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "a frame on a stream the server would have to start, though push is switched off"));
        }
        if stream >= self.next_stream_id {
            return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "a frame on a stream that was never opened"));
        }
        Ok(())
    }

    fn control_backlog(&self) -> Result<(), ConnectionError> {
        if self.out.len() - self.out_pos > CONTROL_BACKLOG {
            Err(connection_error(ErrorCode::ENHANCE_YOUR_CALM, "more frames needing an answer than can be answered"))
        } else {
            Ok(())
        }
    }

    /// A DATA frame that is all here.
    fn on_data(&mut self, id: u32, end_stream: bool, data: &[u8], flow_len: u32, direct: Option<&mut Direct<'_>>) -> Result<(), ConnectionError> {
        let keep = self.check_data(id, end_stream, data.len(), flow_len)?;
        self.data_bytes(id, keep, data, direct);
        self.data_end(id, keep, end_stream, flow_len - data.len() as u32);
        Ok(())
    }

    /// The start of a DATA frame that is not all here (see [`Connection::run`]): what its payload will be passed on to.
    fn begin_data(&mut self, h: &Header) -> Result<(), ConnectionError> {
        // as `handle` does for a frame that is all here (the payload is not empty: it is not all here)
        self.empty_frames = 0;
        let end_stream = h.has(flag::END_STREAM);
        let keep = self.check_data(h.stream, end_stream, h.length as usize, h.length)?;
        self.incoming = Some(Incoming { stream: h.stream, remaining: h.length as usize, end_stream, keep });
        Ok(())
    }

    /// Passes on the payload of the DATA frame that is arriving: what of `bytes` it needs, which is how many bytes
    /// that is.
    fn pass_on(&mut self, bytes: &[u8], direct: Option<&mut Direct<'_>>) -> usize {
        let Some(incoming) = self.incoming.as_mut() else { return 0 };
        let n = bytes.len().min(incoming.remaining);
        incoming.remaining -= n;
        let (id, keep, end_stream, done) = (incoming.stream, incoming.keep, incoming.end_stream, incoming.remaining == 0);
        if done {
            self.incoming = None;
        }
        self.data_bytes(id, keep, &bytes[..n], direct);
        if done {
            self.data_end(id, keep, end_stream, 0);
        }
        n
    }

    /// What can be said of a DATA frame from its header alone, which is all that is checked of it: the stream must be
    /// one that was opened, and the windows must have room for the frame (`flow_len` is all of it, padding too);
    /// then whether the bytes are kept. They are not if nobody wants them (the stream is gone or has failed) or the
    /// frame is wrong for the stream (it loses the stream, and the peer is told).
    fn check_data(&mut self, id: u32, end_stream: bool, len: usize, flow_len: u32) -> Result<bool, ConnectionError> {
        self.require_server_stream_known(id)?;
        if flow_len as i64 > self.recv_window {
            return Err(connection_error(ErrorCode::FLOW_CONTROL_ERROR, "the server sent more than the connection window allows"));
        }
        if len == 0 && !end_stream {
            self.empty_frames += 1;
            if self.empty_frames > EMPTY_FRAMES {
                return Err(connection_error(ErrorCode::ENHANCE_YOUR_CALM, "a flood of empty DATA frames"));
            }
        }
        let bad = match self.streams.get(&id) {
            None => return Ok(false),
            Some(s) if s.failure.is_some() => return Ok(false),
            Some(s) => {
                if s.remote_ended {
                    Some((ErrorCode::STREAM_CLOSED, "DATA after the end of the response"))
                } else if !s.got_head {
                    Some((ErrorCode::PROTOCOL_ERROR, "DATA before the response headers"))
                } else if flow_len as i64 > s.recv_window {
                    Some((ErrorCode::FLOW_CONTROL_ERROR, "the server sent more than the stream window allows"))
                } else if s.bodiless && len > 0 {
                    Some((ErrorCode::PROTOCOL_ERROR, "DATA in a response that has no body"))
                } else if s.collecting && s.received + len as u64 > s.collect_limit {
                    Some((ErrorCode::CANCEL, BODY_TOO_BIG))
                } else if s.expected.is_some_and(|n| s.received + len as u64 > n) {
                    Some((ErrorCode::PROTOCOL_ERROR, "more DATA than the Content-Length says"))
                } else if end_stream && s.expected.is_some_and(|n| s.received + len as u64 != n) {
                    Some((ErrorCode::PROTOCOL_ERROR, "less DATA than the Content-Length says"))
                } else {
                    None
                }
            }
        };
        match bad {
            None => Ok(true),
            Some((code, reason)) => {
                self.stream_error(id, code, reason);
                Ok(false)
            }
        }
    }

    /// Some of the payload of a DATA frame: it counts against the windows as it comes, so that the books balance at
    /// every point, and it is the stream's body or thrown away (and credited at once). A stream that is collecting
    /// has the credit for it at once too, and its reader is not woken for it. Bytes that go straight to the reader (see
    /// [`Connection::feed_direct`]) are read as they come, with the credit a poll would give.
    fn data_bytes(&mut self, id: u32, keep: bool, bytes: &[u8], direct: Option<&mut Direct<'_>>) {
        let n = bytes.len();
        self.recv_window -= n as i64;
        if keep {
            // (the stream may have been let go since the frame began)
            let kept = match self.streams.get_mut(&id).filter(|s| s.failure.is_none()) {
                Some(s) => {
                    s.recv_window -= n as i64;
                    s.received += n as u64;
                    // the reader of the stream is the one feeding, and these are the bytes it would read next: they go to it
                    let mut read = 0;
                    if let Some(d) = direct.filter(|d| d.stream == id) {
                        if !s.collecting && s.head.is_none() && s.unread() == 0 {
                            read = n.min(d.out.len() - d.written);
                            d.out[d.written..d.written + read].copy_from_slice(&bytes[..read]);
                            d.written += read;
                        }
                    }
                    if read < n {
                        s.compact();
                        s.body.extend_from_slice(&bytes[read..]);
                    }
                    if s.collecting {
                        s.unannounced += n as u32;
                    } else {
                        s.unannounced += read as u32;
                    }
                    Some((s.collecting, read))
                }
                None => None,
            };
            match kept {
                Some((false, read)) => {
                    if read < n {
                        self.news.touch(id);
                    }
                    if read > 0 {
                        self.announce_stream(id);
                        self.credit_connection(read as u32);
                    }
                    return;
                }
                Some((true, _)) => {
                    self.credit_connection(n as u32);
                    return;
                }
                None => {}
            }
        }
        self.credit_connection(n as u32);
    }

    /// The end of a DATA frame, whose payload has been passed on: the padding, which nobody reads and whose credit
    /// goes back at once, and the end of the response if the frame was its last (which is news for the stream whatever
    /// else is).
    fn data_end(&mut self, id: u32, keep: bool, end_stream: bool, padding: u32) {
        self.recv_window -= padding as i64;
        if keep {
            if let Some(s) = self.streams.get_mut(&id).filter(|s| s.failure.is_none()) {
                s.recv_window -= padding as i64;
                s.unannounced += padding;
                if end_stream {
                    s.remote_ended = true;
                    self.news.touch(id);
                }
                self.credit_connection(padding);
                self.announce_stream(id);
                return;
            }
        }
        self.credit_connection(padding);
    }

    fn on_fragment(&mut self, end_headers: bool, fragment: &[u8]) -> Result<(), ConnectionError> {
        let limit = self.config.max_header_list as usize + 1024;
        let block = self.block.as_mut().expect("a block in progress");
        block.frames += 1;
        if block.frames > MAX_BLOCK_FRAMES || block.bytes.len() + fragment.len() > limit {
            return Err(connection_error(ErrorCode::ENHANCE_YOUR_CALM, "a header block that goes on too long"));
        }
        block.bytes.extend_from_slice(fragment);
        if !end_headers {
            return Ok(());
        }
        let Block { stream, end_stream, bytes, .. } = self.block.take().expect("a block in progress");
        let mut fields = Vec::new();
        // the block is decoded whatever stream it is for and whatever comes of it: the table must go on in step
        let within = self.decoder.decode(&bytes, &mut fields).map_err(|e| connection_error(ErrorCode::COMPRESSION_ERROR, e.to_string()))?;
        if !within {
            self.stream_error(stream, ErrorCode::PROTOCOL_ERROR, "the response header list is larger than this client takes");
            return Ok(());
        }
        self.on_headers(stream, end_stream, fields)
    }

    fn on_headers(&mut self, id: u32, end_stream: bool, fields: Vec<hpack::Field>) -> Result<(), ConnectionError> {
        let (outcome, news) = match self.streams.get_mut(&id) {
            None => return Ok(()),
            Some(s) if s.failure.is_some() => return Ok(()),
            Some(s) => (headers_for(s, end_stream, &fields), !s.collecting || s.remote_ended),
        };
        match outcome {
            Err((code, why)) => self.stream_error(id, code, why),
            Ok(()) if news => self.news.touch(id),
            Ok(()) => {}
        }
        Ok(())
    }

    fn on_reset(&mut self, id: u32, code: ErrorCode) -> Result<(), ConnectionError> {
        if id % 2 == 0 || id >= self.next_stream_id {
            return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "RST_STREAM on a stream that was never opened"));
        }
        let Some(s) = self.streams.get_mut(&id) else { return Ok(()) };
        // a server may say it is done with a stream whose response is complete (it has not read all the request)
        if s.remote_ended && s.failure.is_none() {
            s.local_ended = true;
            return Ok(());
        }
        // what arrived before the reset stays for the application to read; the failure comes after it
        if s.failure.is_none() {
            s.failure = Some(StreamError { code, reason: format!("the server reset the stream: {code}"), retry_safe: code == ErrorCode::REFUSED_STREAM });
        }
        Ok(())
    }

    fn on_settings(&mut self, ack: bool, values: &[(u16, u32)]) -> Result<(), ConnectionError> {
        if ack {
            return Ok(());
        }
        self.got_peer_settings = true;
        for &(id, value) in values {
            match id {
                setting::HEADER_TABLE_SIZE => self.encoder.set_peer_table_size(value as usize),
                setting::ENABLE_PUSH => {
                    if value > 1 {
                        return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH is neither 0 nor 1"));
                    }
                }
                setting::MAX_CONCURRENT_STREAMS => self.peer_max_concurrent = value,
                setting::INITIAL_WINDOW_SIZE => {
                    if value > MAX_WINDOW {
                        return Err(connection_error(ErrorCode::FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE is over 2^31 - 1"));
                    }
                    let delta = value as i64 - self.peer_initial_window;
                    self.peer_initial_window = value as i64;
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                        if s.send_window > MAX_WINDOW as i64 {
                            return Err(connection_error(ErrorCode::FLOW_CONTROL_ERROR, "a new SETTINGS_INITIAL_WINDOW_SIZE makes a stream window too large"));
                        }
                    }
                }
                setting::MAX_FRAME_SIZE => {
                    if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&value) {
                        return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE out of range"));
                    }
                    self.peer_max_frame = value as usize;
                }
                setting::MAX_HEADER_LIST_SIZE => self.peer_max_header_list = value,
                _ => {} // settings this crate does not know are to be ignored
            }
        }
        self.control_backlog()?;
        frame::write_settings_ack(&mut self.out);
        Ok(())
    }

    fn on_goaway(&mut self, last_stream: u32, code: ErrorCode, debug: &[u8]) -> Result<(), ConnectionError> {
        // a later GOAWAY may only lower the last stream id
        let last = self.goaway.map_or(last_stream, |(l, _)| l.min(last_stream));
        self.goaway = Some((last, code));
        let note = String::from_utf8_lossy(&debug[..debug.len().min(200)]).into_owned();
        let refused: Vec<u32> = self.streams.iter().filter(|(&id, s)| id > last && s.failure.is_none() && !s.remote_ended).map(|(&id, _)| id).collect();
        for id in refused {
            self.fail_stream(id, StreamError { code, reason: format!("the server is going away ({code}) and did not take this request: {note}"), retry_safe: true });
        }
        if code == ErrorCode::NO_ERROR {
            // a graceful shutdown: what the server did take is finished, and nothing new is started
            Ok(())
        } else {
            // the server gave up on the connection: what it did not finish is lost
            Err(ConnectionError { code, reason: format!("the server sent GOAWAY: {note}"), local: false })
        }
    }

    fn on_window_update(&mut self, id: u32, increment: u32) -> Result<(), ConnectionError> {
        if id == 0 {
            self.send_window += increment as i64;
            if self.send_window > MAX_WINDOW as i64 {
                return Err(connection_error(ErrorCode::FLOW_CONTROL_ERROR, "the connection window went over 2^31 - 1"));
            }
            return Ok(());
        }
        if id % 2 == 0 || id >= self.next_stream_id {
            return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE on a stream that was never opened"));
        }
        if let Some(s) = self.streams.get_mut(&id) {
            s.send_window += increment as i64;
            if s.send_window > MAX_WINDOW as i64 {
                self.stream_error(id, ErrorCode::FLOW_CONTROL_ERROR, "the stream window went over 2^31 - 1");
            }
        }
        Ok(())
    }

    /// The stream is lost, and the peer is told. (Frames that were in flight when the peer reads that are ignored
    /// by it.)
    fn stream_error(&mut self, id: u32, code: ErrorCode, reason: &str) {
        if self.streams.get(&id).is_some_and(|s| s.failure.is_none()) {
            self.fail_stream(id, StreamError { code, reason: reason.to_string(), retry_safe: false });
            frame::write_rst_stream(&mut self.out, id, code);
        }
    }

    /// The stream has failed: what it held unread is dropped and the peer is given the credit for it.
    fn fail_stream(&mut self, id: u32, failure: StreamError) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        if s.failure.is_some() {
            return;
        }
        self.news.touch(id);
        let unread = s.unread() as u32;
        s.body = Vec::new(); // (what was collected may be a great deal)
        s.body_pos = 0;
        s.failure = Some(failure);
        self.credit_connection(unread);
    }
}

fn connection_error(code: ErrorCode, reason: impl Into<String>) -> ConnectionError {
    ConnectionError { code, reason: reason.into(), local: true }
}

fn local_error(reason: &str) -> StreamError {
    StreamError { code: ErrorCode::CANCEL, reason: reason.to_string(), retry_safe: false }
}

// ------------------------------------------------------------------------------------------------ fields

/// Fields that belong to one HTTP/1.1 connection, which HTTP/2 does not have (RFC 9113 section 8.2.2).
const CONNECTION_SPECIFIC: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// Header names whose values are secrets.
const SENSITIVE: [&str; 3] = ["authorization", "cookie", "proxy-authorization"];

/// A name that HTTP/2 allows: lower case token characters (a pseudo-header's colon is checked by the caller).
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn valid_value(value: &[u8]) -> bool {
    !value.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n')
}

/// The header list of a request: the pseudo-headers, then the other fields with lower case names and without the
/// connection-specific ones.
pub(crate) fn request_fields<'a>(r: &'a Request<'_>, lowered: &'a [(String, String)]) -> Result<Vec<FieldRef<'a>>, OpenError> {
    let mut list = vec![
        FieldRef { name: b":method", value: r.method.as_bytes(), sensitive: false },
        FieldRef { name: b":scheme", value: r.scheme.as_bytes(), sensitive: false },
        FieldRef { name: b":authority", value: r.authority.as_bytes(), sensitive: false },
        FieldRef { name: b":path", value: r.path.as_bytes(), sensitive: false },
    ];
    if r.method.is_empty() || r.path.is_empty() || r.authority.is_empty() || r.scheme.is_empty() || !list.iter().all(|f| valid_value(f.value)) {
        return Err(OpenError::Invalid("an empty or damaged method, scheme, path or authority".into()));
    }
    if !r.method.bytes().all(is_token_byte) {
        return Err(OpenError::Invalid(format!("{:?} is not a method", r.method)));
    }
    for (name, value) in lowered {
        if !valid_name(name) {
            return Err(OpenError::Invalid(format!("{name:?} is not a header name")));
        }
        if !valid_value(value.as_bytes()) {
            return Err(OpenError::Invalid(format!("the value of {name} has a NUL, CR or LF")));
        }
        // `te: trailers` is the one connection-specific field HTTP/2 allows in a request
        // (`host` goes too: the authority says what it did)
        if CONNECTION_SPECIFIC.contains(&name.as_str()) || name == "host" || (name == "te" && !value.trim().eq_ignore_ascii_case("trailers")) {
            continue;
        }
        list.push(FieldRef { name: name.as_bytes(), value: value.as_bytes(), sensitive: SENSITIVE.contains(&name.as_str()) || r.secret.iter().any(|s| s == name) });
    }
    Ok(list)
}

/// The names of a request's fields in lower case, as HTTP/2 wants them.
pub(crate) fn lower_names(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.clone())).collect()
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Checks and takes apart the header list of a response: the status, the fields, and the Content-Length if there is
/// one (RFC 9113 section 8.3).
pub(crate) fn parse_response(fields: &[hpack::Field]) -> Result<(u16, Fields, Option<u64>), &'static str> {
    let mut status = None;
    let mut seen_regular = false;
    let mut out = Vec::new();
    let mut length: Option<u64> = None;
    for f in fields {
        if f.name.first() == Some(&b':') {
            if seen_regular {
                return Err("a pseudo-header after a regular header field");
            }
            if f.name != b":status" {
                return Err("a pseudo-header that a response may not have");
            }
            if status.is_some() {
                return Err("more than one :status");
            }
            status = Some(parse_status(&f.value)?);
            continue;
        }
        seen_regular = true;
        let (name, value) = regular_field(f)?;
        if name == "content-length" {
            let n = parse_length(&value)?;
            if length.is_some_and(|l| l != n) {
                return Err("Content-Length twice, with different values");
            }
            length = Some(n);
        }
        out.push((name, value));
    }
    match status {
        Some(code) => Ok((code, out, length)),
        None => Err("a response without :status"),
    }
}

/// Checks and takes apart a trailer section: no pseudo-headers.
pub(crate) fn parse_trailers(fields: &[hpack::Field]) -> Result<Fields, &'static str> {
    let mut out = Vec::new();
    for f in fields {
        if f.name.first() == Some(&b':') {
            return Err("a pseudo-header in trailers");
        }
        out.push(regular_field(f)?);
    }
    Ok(out)
}

/// A regular field of a response: the name lower case and a token, and not one that is connection-specific; the
/// value without NUL, CR or LF (and without the spaces around it).
fn regular_field(f: &hpack::Field) -> Result<(String, String), &'static str> {
    if !f.name.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)) || f.name.is_empty() {
        return Err("a header field name that is not lower case token characters");
    }
    // all ASCII by the check above
    let name = String::from_utf8_lossy(&f.name).into_owned();
    if CONNECTION_SPECIFIC.contains(&name.as_str()) {
        return Err("a connection-specific header field in a response");
    }
    if !valid_value(&f.value) {
        return Err("a header field value with a NUL, CR or LF");
    }
    let value = String::from_utf8_lossy(&f.value).trim_matches(|c| c == ' ' || c == '\t').to_string();
    Ok((name, value))
}

fn parse_status(value: &[u8]) -> Result<u16, &'static str> {
    if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return Err(":status is not three digits");
    }
    let code = (value[0] - b'0') as u16 * 100 + (value[1] - b'0') as u16 * 10 + (value[2] - b'0') as u16;
    if code < 100 {
        return Err(":status is below 100");
    }
    Ok(code)
}

fn parse_length(value: &str) -> Result<u64, &'static str> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("a Content-Length that is not a number");
    }
    value.parse().map_err(|_| "a Content-Length that is too large")
}

/// What a header block does for a stream: the response head (an interim one is noted and dropped), or the
/// trailers. The error is the stream's.
fn headers_for(s: &mut Stream, end_stream: bool, fields: &[hpack::Field]) -> Result<(), (ErrorCode, &'static str)> {
    use ErrorCode as E;
    if s.remote_ended {
        return Err((E::STREAM_CLOSED, "HEADERS after the end of the response"));
    }
    if s.got_head {
        // trailers
        if !end_stream {
            return Err((E::PROTOCOL_ERROR, "a second HEADERS that does not end the stream"));
        }
        let trailers = parse_trailers(fields).map_err(|why| (E::PROTOCOL_ERROR, why))?;
        s.remote_ended = true;
        if s.expected.is_some_and(|n| s.received != n) {
            return Err((E::PROTOCOL_ERROR, "less DATA than the Content-Length says"));
        }
        s.trailers = Some(trailers);
        return Ok(());
    }
    let (status, headers, length) = parse_response(fields).map_err(|why| (E::PROTOCOL_ERROR, why))?;
    if (100..200).contains(&status) {
        // an interim response: nothing for the application, and the final one is still to come (RFC 9113 section
        // 8.1.1; a 101 has no place in HTTP/2, section 8.6)
        s.interim += 1;
        if end_stream || status == 101 || s.interim > MAX_INTERIM {
            return Err((E::PROTOCOL_ERROR, "a 1xx response that ends the stream, a 101, or too many 1xx"));
        }
        return Ok(());
    }
    s.got_head = true;
    s.bodiless = s.head_request || status == 204 || status == 304;
    s.expected = if s.bodiless { None } else { length };
    s.head = Some(Head { status, headers });
    if !s.make_room() {
        // (a stream that collects, with a limit lower than what the response says is coming)
        return Err((E::CANCEL, BODY_TOO_BIG));
    }
    if end_stream {
        s.remote_ended = true;
        if s.expected.is_some_and(|n| n != 0) {
            return Err((E::PROTOCOL_ERROR, "the response ends without the DATA its Content-Length promised"));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    type Outcome = std::result::Result<(), ConnectionError>;

    /// A frame the client wrote.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Sent {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    }

    impl Sent {
        fn end_stream(&self) -> bool {
            self.flags & flag::END_STREAM != 0
        }

        /// The (setting, value) pairs of a SETTINGS frame.
        fn settings(&self) -> Vec<(u16, u32)> {
            assert_eq!(self.kind, kind::SETTINGS);
            self.payload.chunks(6).map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]]))).collect()
        }

        /// The number in a WINDOW_UPDATE, RST_STREAM or GOAWAY (the error code).
        fn number(&self) -> u32 {
            match self.kind {
                kind::WINDOW_UPDATE | kind::RST_STREAM => u32::from_be_bytes(self.payload[..4].try_into().unwrap()),
                kind::GOAWAY => u32::from_be_bytes(self.payload[4..8].try_into().unwrap()),
                other => panic!("no number in a frame of kind {other}"),
            }
        }
    }

    fn raw(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Header { length: payload.len() as u32, kind, flags, stream }.write(&mut out);
        out.extend_from_slice(payload);
        out
    }

    fn parse_sent(mut bytes: &[u8]) -> Vec<Sent> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= HEADER_LEN, "a partial frame header in the output");
            let h = Header::parse(bytes[..HEADER_LEN].try_into().unwrap());
            let end = HEADER_LEN + h.length as usize;
            assert!(bytes.len() >= end, "a partial frame in the output");
            out.push(Sent { kind: h.kind, flags: h.flags, stream: h.stream, payload: bytes[HEADER_LEN..end].to_vec() });
            bytes = &bytes[end..];
        }
        out
    }

    fn settings_ack() -> Sent {
        Sent { kind: kind::SETTINGS, flags: flag::ACK, stream: 0, payload: vec![] }
    }

    /// What one stream has delivered.
    #[derive(Debug, Default, PartialEq)]
    struct Got {
        head: Option<Head>,
        body: Vec<u8>,
        trailers: Option<Fields>,
        ended: bool,
        failed: Option<StreamError>,
    }

    /// A client connection and the server it talks to, as far as the tests need one: the server's HPACK encoder
    /// and the decoder for what the client sends, and what the client has written.
    struct Harness {
        c: Connection,
        enc: Encoder,
        dec: Decoder,
        prefaced: bool,
        all: Vec<Sent>,
    }

    impl Harness {
        /// A connection that has not heard from the server.
        fn unsettled(config: Config) -> Harness {
            Harness { c: Connection::new(config), enc: Encoder::new(), dec: Decoder::new(4096, 1 << 20), prefaced: false, all: Vec::new() }
        }

        /// A connection past the exchange of SETTINGS, the server's being these.
        fn with_settings(config: Config, settings: &[(u16, u32)]) -> Harness {
            let mut h = Harness::unsettled(config);
            let first = h.take();
            assert_eq!(first[0].kind, kind::SETTINGS);
            let mut s = Vec::new();
            frame::write_settings(&mut s, settings);
            h.feed(&s).unwrap();
            assert_eq!(h.take(), vec![settings_ack()]);
            h.feed(&raw(kind::SETTINGS, flag::ACK, 0, &[])).unwrap();
            assert_eq!(h.take(), vec![]);
            h
        }

        fn with(config: Config) -> Harness {
            Harness::with_settings(config, &[])
        }

        fn new() -> Harness {
            Harness::with(Config::default())
        }

        /// The frames the client has written since the last call.
        fn take(&mut self) -> Vec<Sent> {
            let mut out = self.c.output().to_vec();
            self.c.consume_output(out.len());
            if !self.prefaced {
                assert!(out.starts_with(PREFACE), "the connection does not begin with the preface");
                out.drain(..PREFACE.len());
                self.prefaced = true;
            }
            let frames = parse_sent(&out);
            self.all.extend(frames.iter().cloned());
            frames
        }

        fn feed(&mut self, bytes: &[u8]) -> Outcome {
            self.c.receive(bytes);
            self.c.process()
        }

        fn feed_frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Outcome {
            self.feed(&raw(kind, flags, stream, payload))
        }

        /// A header block from the server's encoder.
        fn block(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
            let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
            let mut out = Vec::new();
            self.enc.encode(&refs, &mut out);
            out
        }

        /// The server sends a HEADERS frame (and CONTINUATIONs if the block needs them) with `fields` as they are.
        fn send_fields(&mut self, stream: u32, fields: &[(&str, &str)], end_stream: bool) -> Outcome {
            let block = self.block(fields);
            let mut out = Vec::new();
            frame::write_header_block(&mut out, stream, end_stream, &block, 16384);
            self.feed(&out)
        }

        /// The server sends the head of a response.
        fn respond(&mut self, stream: u32, status: &str, extra: &[(&str, &str)], end_stream: bool) -> Outcome {
            let mut fields = vec![(":status", status)];
            fields.extend_from_slice(extra);
            self.send_fields(stream, &fields, end_stream)
        }

        /// The server sends body, in frames of at most 16384 bytes.
        fn data(&mut self, stream: u32, body: &[u8], end_stream: bool) -> Outcome {
            let mut out = Vec::new();
            if body.is_empty() {
                frame::write_data(&mut out, stream, end_stream, b"");
            }
            let mut chunks = body.chunks(16384).peekable();
            while let Some(chunk) = chunks.next() {
                frame::write_data(&mut out, stream, end_stream && chunks.peek().is_none(), chunk);
            }
            self.feed(&out)
        }

        fn open(&mut self, method: &str, path: &str) -> u32 {
            self.open_with(method, path, &[], true)
        }

        fn open_with(&mut self, method: &str, path: &str, headers: &[(&str, &str)], end_stream: bool) -> u32 {
            let headers: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
            self.c.open_stream(&Request { method, scheme: "https", authority: "example.com", path, headers: &headers, secret: &[] }, end_stream).unwrap()
        }

        /// The header list a HEADERS frame of the client carried.
        fn request_of(&mut self, f: &Sent) -> Vec<(String, String)> {
            assert_eq!(f.kind, kind::HEADERS);
            let mut fields = Vec::new();
            assert!(self.dec.decode(&f.payload, &mut fields).unwrap());
            fields.into_iter().map(|f| (String::from_utf8(f.name).unwrap(), String::from_utf8(f.value).unwrap())).collect()
        }

        /// Everything the stream has for the application now, reading with a buffer of `size` bytes.
        fn got_with(&mut self, id: u32, size: usize) -> Got {
            let mut got = Got::default();
            let mut buf = vec![0u8; size];
            loop {
                match self.c.poll_stream(id, &mut buf) {
                    StreamEvent::Pending => return got,
                    StreamEvent::Head(h) => {
                        assert!(got.head.is_none(), "two heads");
                        got.head = Some(h);
                    }
                    StreamEvent::Data(n) => got.body.extend_from_slice(&buf[..n]),
                    StreamEvent::Trailers(t) => got.trailers = Some(t),
                    StreamEvent::End => {
                        got.ended = true;
                        return got;
                    }
                    StreamEvent::Failed(e) => {
                        got.failed = Some(e);
                        return got;
                    }
                }
            }
        }

        fn got(&mut self, id: u32) -> Got {
            self.got_with(id, 1 << 20)
        }
    }

    fn header_pairs(pairs: &[(&str, &str)]) -> Fields {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    // ---------------------------------------------------------------------------------------- start

    #[test]
    fn the_connection_begins_with_the_preface_and_its_settings() {
        let c = Connection::new(Config::default());
        assert!(c.wants_write());
        assert!(c.output().starts_with(PREFACE));
        let frames = parse_sent(&c.output()[PREFACE.len()..]);
        assert_eq!(frames.len(), 2);
        assert_eq!((frames[0].kind, frames[0].stream), (kind::SETTINGS, 0));
        assert_eq!(
            frames[0].settings(),
            vec![(setting::HEADER_TABLE_SIZE, 4096), (setting::ENABLE_PUSH, 0), (setting::INITIAL_WINDOW_SIZE, 8 << 20), (setting::MAX_HEADER_LIST_SIZE, 64 << 10)]
        );
        assert_eq!((frames[1].kind, frames[1].stream, frames[1].number()), (kind::WINDOW_UPDATE, 0, (32 << 20) - 65_535));
        // a connection window that is the default needs no update
        let c = Connection::new(Config { connection_window: 65_535, ..Config::default() });
        assert_eq!(parse_sent(&c.output()[PREFACE.len()..]).len(), 1);
    }

    #[test]
    fn output_is_consumed_in_pieces() {
        let mut c = Connection::new(Config::default());
        let all = c.output().to_vec();
        c.consume_output(10);
        assert_eq!(c.output(), &all[10..]);
        assert!(c.wants_write());
        c.consume_output(all.len() - 10);
        assert!(!c.wants_write());
        assert!(c.output().is_empty());
        c.consume_output(5); // more than there is: nothing happens
        assert!(c.output().is_empty());
    }

    #[test]
    fn the_servers_settings_are_acknowledged_and_its_acknowledgement_is_welcome() {
        let mut h = Harness::unsettled(Config::default());
        h.take();
        let mut s = Vec::new();
        frame::write_settings(&mut s, &[(setting::MAX_CONCURRENT_STREAMS, 7), (0x77, 1234)]);
        h.feed(&s).unwrap();
        assert_eq!(h.take(), vec![settings_ack()]);
        h.feed(&raw(kind::SETTINGS, flag::ACK, 0, &[])).unwrap();
        assert!(h.take().is_empty());
    }

    #[test]
    fn the_servers_first_frame_must_be_settings() {
        for first in [raw(kind::PING, 0, 0, &[0; 8]), raw(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]), raw(kind::SETTINGS, flag::ACK, 0, &[]), raw(kind::GOAWAY, 0, 0, &[0; 8])] {
            let mut h = Harness::unsettled(Config::default());
            h.take();
            let e = h.feed(&first).unwrap_err();
            assert_eq!(e.code, ErrorCode::PROTOCOL_ERROR);
            assert!(e.local);
            let out = h.take();
            assert_eq!(out.len(), 1);
            assert_eq!((out[0].kind, out[0].number()), (kind::GOAWAY, ErrorCode::PROTOCOL_ERROR.0));
        }
    }

    #[test]
    fn nothing_works_before_the_settings_arrive_but_requests_may_be_sent() {
        // a client may send requests at once (RFC 9113 section 3.4): the server's SETTINGS can only widen what they may do
        let mut h = Harness::unsettled(Config::default());
        let id = h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &[], secret: &[] }, true).unwrap();
        assert_eq!(id, 1);
        let out = h.take();
        assert_eq!(out.last().map(|f| (f.kind, f.stream)), Some((kind::HEADERS, 1)));
    }

    #[test]
    fn a_partial_frame_waits_for_the_rest() {
        let mut h = Harness::new();
        let mut ping = Vec::new();
        frame::write_ping(&mut ping, false, *b"abcdefgh");
        for byte in &ping[..ping.len() - 1] {
            h.feed(&[*byte]).unwrap();
            assert!(h.take().is_empty());
        }
        h.feed(&ping[ping.len() - 1..]).unwrap();
        let out = h.take();
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].kind, out[0].flags, out[0].payload.as_slice()), (kind::PING, flag::ACK, b"abcdefgh".as_slice()));
    }

    // ---------------------------------------------------------------------------------------- requests

    #[test]
    fn a_request_is_pseudo_headers_then_lower_case_fields() {
        let mut h = Harness::new();
        let id = h.open_with(
            "GET",
            "/a?b=c",
            &[("Host", "example.com"), ("User-Agent", "tiny"), ("Accept", "*/*"), ("X-Mixed-Case", "Value"), ("Connection", "close"), ("Keep-Alive", "5"), ("Transfer-Encoding", "chunked"), ("Upgrade", "x"), ("Proxy-Connection", "x"), ("TE", "gzip"), ("TE", "trailers")],
            true,
        );
        assert_eq!(id, 1);
        let out = h.take();
        assert_eq!(out.len(), 1);
        assert!(out[0].end_stream());
        assert!(out[0].flags & flag::END_HEADERS != 0);
        let fields = h.request_of(&out[0]);
        assert_eq!(
            fields,
            header_pairs(&[(":method", "GET"), (":scheme", "https"), (":authority", "example.com"), (":path", "/a?b=c"), ("user-agent", "tiny"), ("accept", "*/*"), ("x-mixed-case", "Value"), ("te", "trailers")])
        );
        assert_eq!(h.open("GET", "/"), 3);
        assert_eq!(h.open("GET", "/"), 5);
    }

    #[test]
    fn secrets_are_never_indexed() {
        let headers = vec![("authorization".to_string(), "Bearer x".to_string()), ("cookie".to_string(), "a=b".to_string()), ("accept".to_string(), "*/*".to_string())];
        let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
        let lowered = lower_names(r.headers);
        let list = request_fields(&r, &lowered).unwrap();
        let sensitive: Vec<(&[u8], bool)> = list.iter().map(|f| (f.name, f.sensitive)).collect();
        assert_eq!(
            sensitive,
            vec![(b":method".as_slice(), false), (b":scheme".as_slice(), false), (b":authority".as_slice(), false), (b":path".as_slice(), false), (b"authorization".as_slice(), true), (b"cookie".as_slice(), true), (b"accept".as_slice(), false)]
        );
    }

    #[test]
    fn the_names_a_caller_says_are_secret_are_never_indexed_either() {
        // (a hop's own credentials: any name, in any case, given as the lower case name; the others stay as they were)
        let headers = vec![("Private-Token".to_string(), "t0k3n".to_string()), ("X-Api-Key".to_string(), "k".to_string()), ("accept".to_string(), "*/*".to_string())];
        let secret = vec!["private-token".to_string(), "x-api-key".to_string()];
        let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &secret };
        let lowered = lower_names(r.headers);
        let list = request_fields(&r, &lowered).unwrap();
        let sensitive: Vec<(&[u8], bool)> = list.iter().skip(4).map(|f| (f.name, f.sensitive)).collect();
        assert_eq!(sensitive, vec![(b"private-token".as_slice(), true), (b"x-api-key".as_slice(), true), (b"accept".as_slice(), false)]);
        // and what is written does not let a table keep them: the second of two identical requests on one connection is a few bytes when a table
        // holds the credentials, and carries them in full when it does not
        let second_block = |secret: &[String]| {
            let mut h = Harness::new();
            let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret };
            h.c.open_stream(&r, true).unwrap();
            h.c.open_stream(&r, true).unwrap();
            h.take().into_iter().filter(|f| f.kind == kind::HEADERS).map(|f| f.payload.len()).last().unwrap()
        };
        assert!(second_block(&secret) > second_block(&[]) + 10, "{} against {}", second_block(&secret), second_block(&[]));
    }

    #[test]
    fn requests_that_cannot_be_sent_are_refused_before_anything_is_written() {
        let mut h = Harness::new();
        let try_open = |h: &mut Harness, method: &str, path: &str, authority: &str, headers: &[(&str, &str)]| {
            let headers: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
            h.c.open_stream(&Request { method, scheme: "https", authority, path, headers: &headers, secret: &[] }, true)
        };
        for (method, path, authority, headers) in [
            ("", "/", "example.com", vec![]),
            ("GET", "", "example.com", vec![]),
            ("GET", "/", "", vec![]),
            ("GE T", "/", "example.com", vec![]),
            ("GET", "/\r\nX: y", "example.com", vec![]),
            ("GET", "/", "example.com", vec![("bad name", "x")]),
            ("GET", "/", "example.com", vec![("", "x")]),
            ("GET", "/", "example.com", vec![("x", "a\nb")]),
            ("GET", "/", "example.com", vec![("x", "a\0b")]),
            ("GET", "/", "example.com", vec![(":path", "/other")]),
        ] {
            assert!(matches!(try_open(&mut h, method, path, authority, &headers), Err(OpenError::Invalid(_))), "{method:?} {path:?} {authority:?} {headers:?}");
        }
        assert!(h.take().is_empty(), "nothing was written");
        // and the stream ids were not used up
        assert_eq!(h.open("GET", "/"), 1);
    }

    #[test]
    fn a_header_list_over_what_the_server_takes_is_refused() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::MAX_HEADER_LIST_SIZE, 200)]);
        let headers = vec![("x-big".to_string(), "v".repeat(300))];
        let big = h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] }, true);
        assert!(matches!(big, Err(OpenError::Invalid(_))), "{big:?}");
        assert_eq!(h.open("GET", "/"), 1);
    }

    #[test]
    fn a_header_block_too_big_for_one_frame_continues_in_the_next() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::MAX_HEADER_LIST_SIZE, 1 << 20)]);
        // values that do not repeat, so that Huffman and the table cannot make them small
        let value: String = (0..60_000u32).map(|i| char::from(b'a' + ((i * 7 + i / 13) % 26) as u8)).collect();
        let headers = vec![("x-big".to_string(), value.clone())];
        h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] }, true).unwrap();
        let out = h.take();
        assert!(out.len() >= 3, "{} frames", out.len());
        assert_eq!((out[0].kind, out[0].flags & flag::END_HEADERS), (kind::HEADERS, 0));
        assert!(out[0].end_stream());
        for f in &out[1..out.len() - 1] {
            assert_eq!((f.kind, f.stream, f.flags), (kind::CONTINUATION, 1, 0));
        }
        let last = out.last().unwrap();
        assert_eq!((last.kind, last.flags), (kind::CONTINUATION, flag::END_HEADERS));
        assert!(out.iter().all(|f| f.payload.len() <= 16_384));
        let joined = Sent { kind: kind::HEADERS, flags: 0, stream: 1, payload: out.iter().flat_map(|f| f.payload.clone()).collect() };
        let fields = h.request_of(&joined);
        assert_eq!(fields.last().unwrap(), &("x-big".to_string(), value));
    }

    #[test]
    fn a_request_body_goes_in_data_frames_within_the_windows() {
        let mut h = Harness::new();
        let id = h.open_with("POST", "/up", &[("content-length", "100000")], false);
        let out = h.take();
        assert!(!out[0].end_stream(), "the body is still to come");
        // the initial window is 65535: that much goes, in frames of 16384
        assert_eq!(h.c.send_capacity(id), 65_535);
        let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let sent = h.c.send_data(id, &body, true).unwrap();
        assert_eq!(sent, 65_535);
        let frames = h.take();
        assert_eq!(frames.iter().map(|f| f.payload.len()).collect::<Vec<_>>(), vec![16_384, 16_384, 16_384, 16_383]);
        assert!(frames.iter().all(|f| f.kind == kind::DATA && f.stream == 1 && !f.end_stream()), "the end waits for the rest");
        assert_eq!(frames.iter().flat_map(|f| f.payload.clone()).collect::<Vec<u8>>(), body[..65_535]);
        assert_eq!(h.c.send_capacity(id), 0);
        assert_eq!(h.c.send_data(id, &body[65_535..], true).unwrap(), 0);
        assert!(h.take().is_empty());
        // the server makes room: for the stream, and for the connection
        h.feed_frame(kind::WINDOW_UPDATE, 0, 1, &50_000u32.to_be_bytes()).unwrap();
        assert_eq!(h.c.send_capacity(id), 0, "the connection window is still spent");
        h.feed_frame(kind::WINDOW_UPDATE, 0, 0, &40_000u32.to_be_bytes()).unwrap();
        assert_eq!(h.c.send_capacity(id), 40_000, "the smaller of the two windows");
        let rest = &body[65_535..];
        assert_eq!(h.c.send_data(id, rest, true).unwrap(), 34_465);
        let frames = h.take();
        assert_eq!(frames.iter().map(|f| f.payload.len()).sum::<usize>(), 34_465);
        assert!(frames.last().unwrap().end_stream(), "all of the body went, so the end goes with it");
        assert_eq!(h.c.send_capacity(id), 0, "the stream is ended");
    }

    #[test]
    fn the_end_of_a_body_is_sent_with_its_last_frame_or_alone() {
        let mut h = Harness::new();
        let id = h.open_with("POST", "/", &[], false);
        h.take();
        assert_eq!(h.c.send_data(id, b"hello", true).unwrap(), 5);
        let out = h.take();
        assert_eq!(out.len(), 1);
        assert!(out[0].end_stream());
        assert_eq!(out[0].payload, b"hello");
        assert!(h.c.send_data(id, b"more", false).is_err(), "the body was ended");
        // an empty DATA frame ends a body that was sent without its end
        let id2 = h.open_with("POST", "/", &[], false);
        h.take();
        assert_eq!(h.c.send_data(id2, b"abc", false).unwrap(), 3);
        assert_eq!(h.c.send_data(id2, b"", true).unwrap(), 0);
        let out = h.take();
        assert_eq!(out.len(), 2);
        assert!(!out[0].end_stream() && out[1].end_stream() && out[1].payload.is_empty());
        // no window at all: the end still goes
        let id3 = h.open_with("POST", "/", &[], false);
        h.take();
        h.c.streams.get_mut(&id3).unwrap().send_window = 0;
        assert_eq!(h.c.send_data(id3, b"", true).unwrap(), 0);
        assert!(h.take()[0].end_stream());
    }

    #[test]
    fn a_larger_frame_size_from_the_server_makes_larger_frames() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::MAX_FRAME_SIZE, 40_000), (setting::INITIAL_WINDOW_SIZE, 1 << 20)]);
        h.feed_frame(kind::WINDOW_UPDATE, 0, 0, &(1u32 << 20).to_be_bytes()).unwrap();
        let id = h.open_with("POST", "/", &[], false);
        h.take();
        assert_eq!(h.c.send_data(id, &vec![7u8; 100_000], true).unwrap(), 100_000);
        let sizes: Vec<usize> = h.take().iter().map(|f| f.payload.len()).collect();
        assert_eq!(sizes, vec![40_000, 40_000, 20_000]);
    }

    #[test]
    fn the_output_backlog_limits_what_send_data_takes() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::INITIAL_WINDOW_SIZE, 10 << 20)]);
        h.feed_frame(kind::WINDOW_UPDATE, 0, 0, &(10u32 << 20).to_be_bytes()).unwrap();
        let id = h.open_with("POST", "/", &[], false);
        h.take();
        let body = vec![1u8; 2 << 20];
        let first = h.c.send_data(id, &body, false).unwrap();
        assert_eq!(first, OUTPUT_HIGH_WATER);
        assert_eq!(h.c.send_data(id, &body, false).unwrap(), 0, "nothing more until the output is sent");
        let out = h.c.output().len();
        h.c.consume_output(out / 2);
        assert_eq!(h.c.send_capacity(id), OUTPUT_HIGH_WATER - (out - out / 2));
        h.c.consume_output(out - out / 2);
        assert_eq!(h.c.send_capacity(id), OUTPUT_HIGH_WATER);
    }

    #[test]
    fn a_new_initial_window_from_the_server_moves_the_windows_of_open_streams() {
        let mut h = Harness::new();
        let id = h.open_with("POST", "/", &[], false);
        h.take();
        assert_eq!(h.c.send_data(id, &vec![0; 60_000], false).unwrap(), 60_000);
        // 65535 - 60000 = 5535 left; a window of 1000 makes it 1000 - 60000 = -59000
        let mut s = Vec::new();
        frame::write_settings(&mut s, &[(setting::INITIAL_WINDOW_SIZE, 1000)]);
        h.feed(&s).unwrap();
        assert_eq!(h.c.streams[&id].send_window, -59_000);
        assert_eq!(h.c.send_capacity(id), 0);
        h.feed_frame(kind::WINDOW_UPDATE, 0, 1, &60_000u32.to_be_bytes()).unwrap();
        assert_eq!(h.c.streams[&id].send_window, 1000);
        // and streams opened later start with the new one
        let id2 = h.open_with("POST", "/", &[], false);
        assert_eq!(h.c.streams[&id2].send_window, 1000);
    }

    // ---------------------------------------------------------------------------------------- responses

    #[test]
    fn a_response_is_a_head_then_body_then_the_end() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        assert_eq!(h.got(id).head, None);
        h.respond(1, "200", &[("content-type", "text/plain"), ("content-length", "11"), ("x-n", " padded ")], false).unwrap();
        let got = h.got(id);
        assert_eq!(got.head, Some(Head { status: 200, headers: header_pairs(&[("content-type", "text/plain"), ("content-length", "11"), ("x-n", "padded")]) }));
        assert!(!got.ended);
        h.data(1, b"hello ", false).unwrap();
        assert_eq!(h.got(id).body, b"hello ");
        h.data(1, b"world", true).unwrap();
        let got = h.got(id);
        assert_eq!(got.body, b"world");
        assert!(got.ended);
        // the end stays
        assert!(h.got(id).ended);
        assert_eq!(h.c.active_streams(), 0);
    }

    #[test]
    fn a_response_may_be_read_in_small_pieces() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[], false).unwrap();
        h.data(1, &(0..1000u32).map(|i| i as u8).collect::<Vec<u8>>(), true).unwrap();
        let got = h.got_with(id, 7);
        assert_eq!(got.body, (0..1000u32).map(|i| i as u8).collect::<Vec<u8>>());
        assert!(got.ended);
        // an empty buffer gets nothing but does not lose anything
        let id2 = h.open("GET", "/");
        h.respond(id2, "200", &[], false).unwrap();
        h.data(id2, b"xyz", true).unwrap();
        assert!(matches!(h.c.poll_stream(id2, &mut []), StreamEvent::Head(_)));
        assert_eq!(h.c.poll_stream(id2, &mut []), StreamEvent::Pending);
        assert_eq!(h.got(id2).body, b"xyz");
    }

    #[test]
    fn trailers_come_after_the_body() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[("trailer", "x-sum")], false).unwrap();
        h.data(1, b"body", false).unwrap();
        h.send_fields(1, &[("x-sum", "42"), ("x-other", "o")], true).unwrap();
        let got = h.got(id);
        assert_eq!(got.body, b"body");
        assert_eq!(got.trailers, Some(header_pairs(&[("x-sum", "42"), ("x-other", "o")])));
        assert!(got.ended);
    }

    #[test]
    fn trailers_are_checked_too() {
        for bad in [vec![(":status", "200")], vec![("X-Upper", "1")], vec![("connection", "close")], vec![("x", "a\nb")]] {
            let mut h = Harness::new();
            let id = h.open("GET", "/");
            h.respond(1, "200", &[], false).unwrap();
            h.send_fields(1, &bad, true).unwrap();
            h.take();
            let got = h.got(id);
            assert_eq!(got.failed.as_ref().map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR), "{bad:?}");
        }
        // trailers that do not end the stream
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[], false).unwrap();
        h.send_fields(1, &[("x", "1")], false).unwrap();
        assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR));
    }

    #[test]
    fn a_header_block_in_several_frames_is_put_together() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        let long = "v".repeat(3000);
        let block = h.block(&[(":status", "200"), ("x-a", "1"), ("x-long", &long), ("x-z", "last")]);
        // HEADERS with a third of it, a CONTINUATION with another third, and the rest
        let third = block.len() / 3;
        let mut wire = raw(kind::HEADERS, flag::END_STREAM, 1, &block[..third]);
        wire.extend(raw(kind::CONTINUATION, 0, 1, &block[third..2 * third]));
        wire.extend(raw(kind::CONTINUATION, flag::END_HEADERS, 1, &block[2 * third..]));
        h.feed(&wire).unwrap();
        let got = h.got(id);
        assert_eq!(got.head.unwrap().headers, header_pairs(&[("x-a", "1"), ("x-long", &long), ("x-z", "last")]));
        assert!(got.ended);
    }

    #[test]
    fn interim_responses_are_set_aside() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "100", &[], false).unwrap();
        h.respond(1, "103", &[("link", "</a>; rel=preload")], false).unwrap();
        assert_eq!(h.got(id).head, None);
        h.respond(1, "200", &[("content-length", "2")], false).unwrap();
        h.data(1, b"ok", true).unwrap();
        let got = h.got(id);
        assert_eq!(got.head.unwrap().status, 200);
        assert_eq!(got.body, b"ok");
        // a 1xx that ends the stream, a 101, and too many are errors
        for status in ["101", "100"] {
            let mut h = Harness::new();
            let id = h.open("GET", "/");
            h.respond(1, status, &[], status == "100").unwrap();
            assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR));
        }
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        for _ in 0..MAX_INTERIM {
            h.respond(1, "102", &[], false).unwrap();
        }
        assert_eq!(h.got(id).failed, None);
        h.respond(1, "102", &[], false).unwrap();
        assert!(h.got(id).failed.is_some());
    }

    #[test]
    fn responses_without_a_body() {
        let mut h = Harness::new();
        // HEAD: Content-Length is the length a GET would have, and there is no DATA
        let id = h.open("HEAD", "/");
        h.respond(1, "200", &[("content-length", "5000")], true).unwrap();
        let got = h.got(id);
        assert_eq!(got.head.unwrap().headers, header_pairs(&[("content-length", "5000")]));
        assert!(got.ended && got.body.is_empty() && got.failed.is_none());
        // 204 and 304 the same, and an empty body that was promised empty
        for (status, length) in [("204", None), ("304", Some("100")), ("200", Some("0"))] {
            let id = h.open("GET", "/");
            let extra: Vec<(&str, &str)> = length.map(|l| ("content-length", l)).into_iter().collect();
            h.respond(id, status, &extra, true).unwrap();
            let got = h.got(id);
            assert!(got.ended && got.failed.is_none(), "{status}");
        }
        // DATA that a HEAD response, a 204 or a 304 may not have
        for (method, status) in [("HEAD", "200"), ("GET", "204"), ("GET", "304")] {
            let id = h.open(method, "/");
            h.respond(id, status, &[], false).unwrap();
            h.data(id, b"x", true).unwrap();
            assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR), "{method} {status}");
        }
    }

    #[test]
    fn content_length_is_held_to() {
        // more than it says
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[("content-length", "3")], false).unwrap();
        h.data(1, b"abcd", false).unwrap();
        assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR));
        // less than it says, with the end in DATA, in an empty DATA and in trailers
        for how in 0..3 {
            let mut h = Harness::new();
            let id = h.open("GET", "/");
            h.respond(1, "200", &[("content-length", "10")], false).unwrap();
            h.data(1, b"abc", how == 0).unwrap();
            match how {
                1 => h.data(1, b"", true).unwrap(),
                2 => h.send_fields(1, &[("x", "y")], true).unwrap(),
                _ => {}
            }
            let got = h.got(id);
            assert_eq!(got.failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR), "{how}");
        }
        // headers that end the stream without the promised body
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[("content-length", "10")], true).unwrap();
        assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR));
        // exactly right
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[("content-length", "10")], false).unwrap();
        h.data(1, b"abcde", false).unwrap();
        h.data(1, b"fghij", true).unwrap();
        let got = h.got(id);
        assert!(got.ended && got.failed.is_none());
        assert_eq!(got.body, b"abcdefghij");
    }

    // ---------------------------------------------------------------------------------------- malformed responses

    /// The bookkeeping that must hold whatever the server sends: every byte of DATA is either held for the
    /// application or has been given back as credit (or is waiting to be).
    fn check_windows(c: &Connection) {
        c.assert_books();
    }

    #[test]
    fn malformed_responses_lose_their_stream_and_nothing_else() {
        let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
            ("no status", vec![("content-type", "x")]),
            ("two statuses", vec![(":status", "200"), (":status", "200")]),
            ("status after a field", vec![("x", "y"), (":status", "200")]),
            ("a request pseudo-header", vec![(":status", "200"), (":path", "/")]),
            ("an unknown pseudo-header", vec![(":status", "200"), (":nope", "1")]),
            ("a pseudo-header after a field", vec![(":status", "200"), ("x", "y"), (":scheme", "https")]),
            ("status of two digits", vec![(":status", "20")]),
            ("status of four digits", vec![(":status", "2000")]),
            ("status with a letter", vec![(":status", "2x0")]),
            ("status below 100", vec![(":status", "099")]),
            ("status with a sign", vec![(":status", "+20")]),
            ("a capital in a name", vec![(":status", "200"), ("Content-Type", "x")]),
            ("a space in a name", vec![(":status", "200"), ("a b", "c")]),
            ("a colon in a name", vec![(":status", "200"), ("a:b", "c")]),
            ("an empty name", vec![(":status", "200"), ("", "c")]),
            ("connection", vec![(":status", "200"), ("connection", "close")]),
            ("keep-alive", vec![(":status", "200"), ("keep-alive", "timeout=5")]),
            ("proxy-connection", vec![(":status", "200"), ("proxy-connection", "x")]),
            ("transfer-encoding", vec![(":status", "200"), ("transfer-encoding", "chunked")]),
            ("upgrade", vec![(":status", "200"), ("upgrade", "h2c")]),
            ("a CR in a value", vec![(":status", "200"), ("x", "a\rb")]),
            ("an LF in a value", vec![(":status", "200"), ("x", "a\nb")]),
            ("a NUL in a value", vec![(":status", "200"), ("x", "a\0b")]),
            ("a Content-Length that is not a number", vec![(":status", "200"), ("content-length", "abc")]),
            ("a negative Content-Length", vec![(":status", "200"), ("content-length", "-1")]),
            ("an empty Content-Length", vec![(":status", "200"), ("content-length", "")]),
            ("a list as Content-Length", vec![(":status", "200"), ("content-length", "1, 1")]),
            ("a Content-Length too large", vec![(":status", "200"), ("content-length", "99999999999999999999999")]),
            ("two different Content-Lengths", vec![(":status", "200"), ("content-length", "1"), ("content-length", "2")]),
        ];
        for (what, mut bad) in cases {
            let mut h = Harness::new();
            let first = h.open("GET", "/first");
            let second = h.open("GET", "/second");
            h.take();
            // the last field of the block goes into the table, and the next response uses it
            bad.push(("x-keep", "kept value"));
            h.send_fields(first, &bad, false).unwrap();
            let sent = h.take();
            assert_eq!(sent.len(), 1, "{what}: {sent:?}");
            assert_eq!((sent[0].kind, sent[0].stream, sent[0].number()), (kind::RST_STREAM, first, ErrorCode::PROTOCOL_ERROR.0), "{what}");
            let got = h.got(first);
            let failed = got.failed.unwrap_or_else(|| panic!("{what}: the stream did not fail"));
            assert_eq!(failed.code, ErrorCode::PROTOCOL_ERROR, "{what}");
            assert!(!failed.retry_safe);
            assert!(h.c.error().is_none(), "{what}");
            // the other stream, and the table, are fine
            h.respond(second, "200", &[("x-keep", "kept value")], true).unwrap();
            let got = h.got(second);
            assert_eq!(got.head.unwrap().headers, header_pairs(&[("x-keep", "kept value")]), "{what}");
            // and what the server sends for the lost stream afterwards is thrown away
            h.data(first, b"late", false).unwrap();
            check_windows(&h.c);
        }
    }

    #[test]
    fn a_response_for_a_stream_that_was_never_opened_is_a_connection_error() {
        for (stream, what) in [(2, "an even stream"), (5, "a stream that was never opened"), (1, "a stream that was never opened")] {
            let mut h = Harness::new();
            if stream == 5 {
                h.open("GET", "/");
            }
            let e = h.respond(stream, "200", &[], true).unwrap_err();
            assert_eq!(e.code, ErrorCode::PROTOCOL_ERROR, "{what}");
            let sent = h.take();
            let last = sent.last().unwrap();
            assert_eq!((last.kind, last.number()), (kind::GOAWAY, ErrorCode::PROTOCOL_ERROR.0), "{what}");
        }
    }

    #[test]
    fn a_header_list_larger_than_this_client_takes_loses_the_stream_and_the_table_goes_on() {
        let mut h = Harness::new();
        let first = h.open("GET", "/");
        let second = h.open("GET", "/");
        h.take();
        // one field is indexed, and then sent again and again: a small block that makes a long list
        let big = "b".repeat(2000);
        let mut fields = vec![(":status", "200")];
        for _ in 0..40 {
            fields.push(("x-big", big.as_str()));
        }
        h.send_fields(first, &fields, true).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream)).collect::<Vec<_>>(), vec![(kind::RST_STREAM, first)]);
        assert_eq!(h.got(first).failed.map(|e| e.code), Some(ErrorCode::PROTOCOL_ERROR));
        // the entry that block added is there for the next one
        h.respond(second, "200", &[("x-big", big.as_str())], true).unwrap();
        assert_eq!(h.got(second).head.unwrap().headers, header_pairs(&[("x-big", big.as_str())]));
    }

    #[test]
    fn a_header_block_that_goes_on_too_long_is_a_connection_error() {
        // too many frames
        let mut h = Harness::new();
        h.open("GET", "/");
        let mut wire = raw(kind::HEADERS, 0, 1, &[0x88]);
        for _ in 0..MAX_BLOCK_FRAMES {
            wire.extend(raw(kind::CONTINUATION, 0, 1, &[0x88]));
        }
        wire.extend(raw(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x88]));
        assert_eq!(h.feed(&wire).unwrap_err().code, ErrorCode::ENHANCE_YOUR_CALM);
        // too many bytes
        let mut h = Harness::new();
        h.open("GET", "/");
        let mut wire = raw(kind::HEADERS, 0, 1, &[0x88; 16_384]);
        for _ in 0..5 {
            wire.extend(raw(kind::CONTINUATION, 0, 1, &[0x88; 16_384]));
        }
        assert_eq!(h.feed(&wire).unwrap_err().code, ErrorCode::ENHANCE_YOUR_CALM);
    }

    #[test]
    fn a_header_block_must_be_followed_by_its_continuations() {
        let first_half = |h: &mut Harness| {
            h.open("GET", "/");
            h.open("GET", "/");
            let block = h.block(&[(":status", "200"), ("x", "y")]);
            h.feed(&raw(kind::HEADERS, 0, 1, &block[..2])).unwrap();
            block
        };
        // another kind of frame, or another stream's CONTINUATION, in the middle
        for (kind, stream, payload) in [(kind::DATA, 1, vec![1]), (kind::PING, 0, vec![0; 8]), (kind::SETTINGS, 0, vec![]), (kind::WINDOW_UPDATE, 1, vec![0, 0, 0, 1]), (kind::CONTINUATION, 3, vec![0x88]), (kind::HEADERS, 3, vec![0x88]), (kind::RST_STREAM, 1, vec![0; 4])] {
            let mut h = Harness::new();
            first_half(&mut h);
            let e = h.feed_frame(kind, 0, stream, &payload).unwrap_err();
            assert_eq!(e.code, ErrorCode::PROTOCOL_ERROR, "kind {kind} on {stream}");
        }
        // CONTINUATION with nothing to continue, and after a block that has ended
        let mut h = Harness::new();
        h.open("GET", "/");
        assert_eq!(h.feed_frame(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x88]).unwrap_err().code, ErrorCode::PROTOCOL_ERROR);
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(1, "200", &[], false).unwrap();
        assert_eq!(h.feed_frame(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x88]).unwrap_err().code, ErrorCode::PROTOCOL_ERROR);
        let _ = id;
        // and the continuation completes it
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.open("GET", "/");
        let block = h.block(&[(":status", "200"), ("x", "y")]);
        h.feed(&raw(kind::HEADERS, flag::END_STREAM, 1, &block[..2])).unwrap();
        assert_eq!(h.got(id).head, None);
        h.feed(&raw(kind::CONTINUATION, flag::END_HEADERS, 1, &block[2..])).unwrap();
        assert_eq!(h.got(id).head.unwrap().headers, header_pairs(&[("x", "y")]));
    }

    #[test]
    fn a_header_block_that_does_not_decode_is_a_compression_error() {
        for block in [vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], vec![0x80 | 62], vec![0x80], vec![0x40, 0x05, b'a'], vec![0x88, 0x20 | 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f]] {
            let mut h = Harness::new();
            h.open("GET", "/");
            let e = h.feed_frame(kind::HEADERS, flag::END_HEADERS, 1, &block).unwrap_err();
            assert_eq!(e.code, ErrorCode::COMPRESSION_ERROR, "{block:?}");
            assert!(h.take().iter().any(|f| f.kind == kind::GOAWAY && f.number() == ErrorCode::COMPRESSION_ERROR.0));
        }
    }

    #[test]
    fn headers_for_a_stream_that_was_let_go_are_decoded_and_dropped() {
        let mut h = Harness::new();
        let first = h.open("GET", "/");
        let second = h.open("GET", "/");
        h.take();
        h.c.release_stream(first);
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, first, ErrorCode::CANCEL.0)]);
        h.respond(first, "200", &[("x-late", "in the table now")], false).unwrap();
        h.data(first, b"nobody wants this", true).unwrap();
        h.respond(second, "200", &[("x-late", "in the table now")], true).unwrap();
        assert_eq!(h.got(second).head.unwrap().headers, header_pairs(&[("x-late", "in the table now")]));
        assert!(h.take().is_empty());
        check_windows(&h.c);
    }

    // ---------------------------------------------------------------------------------------- flow control, in

    fn small_windows() -> Config {
        Config { stream_window: 1000, connection_window: 65_535, max_header_list: 64 << 10 }
    }

    #[test]
    fn credit_goes_back_as_the_application_reads() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(1, "200", &[], false).unwrap();
        h.data(1, &[7u8; 900], false).unwrap();
        assert!(h.take().is_empty(), "nothing has been read, so nothing is given back");
        check_windows(&h.c);
        // reading 600 is past half of the window of 1000: the stream gets it back at once
        let mut buf = [0u8; 300];
        assert!(matches!(h.c.poll_stream(id, &mut buf), StreamEvent::Head(_)));
        assert_eq!(h.c.poll_stream(id, &mut buf), StreamEvent::Data(300));
        assert!(h.take().is_empty(), "300 is less than half");
        assert_eq!(h.c.poll_stream(id, &mut buf), StreamEvent::Data(300));
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, 1, 600)]);
        assert_eq!(h.c.poll_stream(id, &mut buf), StreamEvent::Data(300));
        assert!(h.take().is_empty());
        check_windows(&h.c);
        // the connection gets its credit when 32767 (half of 65535) has been read, however many streams that took
        assert_eq!(h.c.unannounced, 900);
    }

    #[test]
    fn the_connection_window_is_given_back_in_halves() {
        let config = Config { stream_window: 1 << 20, connection_window: 65_535, max_header_list: 64 << 10 };
        let mut h = Harness::with(config);
        let id = h.open("GET", "/");
        let other = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        h.respond(other, "200", &[], false).unwrap();
        h.data(id, &vec![1u8; 30_000], false).unwrap();
        h.data(other, &vec![2u8; 30_000], false).unwrap();
        // 60000 of 65535 used and none read: another 5536 would be too many
        let e = h.data(id, &vec![1u8; 5_536], false).unwrap_err();
        assert_eq!(e.code, ErrorCode::FLOW_CONTROL_ERROR);
        let mut h = Harness::with(config);
        let id = h.open("GET", "/");
        let other = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        h.respond(other, "200", &[], false).unwrap();
        h.data(id, &vec![1u8; 30_000], false).unwrap();
        h.data(other, &vec![2u8; 30_000], false).unwrap();
        // reading 30000 is under the half
        assert_eq!(h.got(id).body.len(), 30_000);
        assert!(h.take().is_empty());
        // 30000 more is over it: the connection gets 60000 back in one update
        assert_eq!(h.got(other).body.len(), 30_000);
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, 0, 60_000)]);
        check_windows(&h.c);
        // and the server may send again
        h.data(id, &vec![3u8; 40_000], false).unwrap();
        assert_eq!(h.got(id).body.len(), 40_000);
    }

    #[test]
    fn a_big_window_is_refreshed_every_megabyte_not_every_half() {
        // the default windows are 8 MiB and 32 MiB: waiting for half of them to be read would leave a fast sender idle
        // for a round trip, again and again
        assert_eq!(refresh_threshold(8 << 20), 1 << 20);
        assert_eq!(refresh_threshold(32 << 20), 1 << 20);
        assert_eq!(refresh_threshold(65_535), 32_767);
        let mut h = Harness::with(Config::default());
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        let mut read = 0usize;
        let mut updates = Vec::new();
        while read < 3_100_000 {
            h.data(id, &[5u8; 16_000], false).unwrap();
            read += h.got(id).body.len();
            updates.extend(h.take().iter().map(|f| (f.kind, f.stream, f.number())));
        }
        // each window (the stream's and the connection's) was given back as soon as a megabyte or more was read
        let credit = |stream: u32| updates.iter().filter(|u| u.0 == kind::WINDOW_UPDATE && u.1 == stream).map(|u| u.2 as usize).collect::<Vec<_>>();
        for given in [credit(id), credit(0)] {
            assert_eq!(given.len(), 2, "{given:?}");
            assert!(given.iter().all(|g| *g >= 1 << 20 && *g < (1 << 20) + 16_000), "{given:?}");
        }
        assert_eq!(credit(id).iter().sum::<usize>() + h.c.streams[&id].unannounced as usize, read);
        assert_eq!(credit(0).iter().sum::<usize>() + h.c.unannounced as usize, read);
        check_windows(&h.c);
    }

    /// What the connection says has news since the last time, as (streams, for everyone).
    fn news_of(h: &mut Harness) -> (Vec<u32>, bool) {
        let mut n = News::default();
        h.c.take_news(&mut n);
        (n.streams().to_vec(), n.is_for_everyone())
    }

    #[test]
    fn news_says_which_streams_a_frame_was_about_and_what_is_for_everyone() {
        let mut h = Harness::new();
        let a = h.open("GET", "/a");
        let b = h.open("GET", "/b");
        let c = h.open("GET", "/c");
        h.take();
        // the exchange of SETTINGS that opened the connection was news for everyone
        assert_eq!(news_of(&mut h), (vec![], true));
        assert_eq!(news_of(&mut h), (vec![], false));
        // heads and data for two streams, in the order they came, each stream once in a row
        h.respond(b, "200", &[], false).unwrap();
        h.data(b, b"x", false).unwrap();
        h.data(a, b"y", false).unwrap(); // DATA before the head is an error for the stream `a` only: it is news for `a`
        assert_eq!(news_of(&mut h), (vec![b, a], false));
        assert_eq!(news_of(&mut h), (vec![], false), "taken news is gone");
        // a stream reset, a window for one stream, a window for the connection
        h.feed_frame(kind::RST_STREAM, 0, c, &ErrorCode::CANCEL.0.to_be_bytes()).unwrap();
        assert_eq!(news_of(&mut h), (vec![c], false));
        h.feed_frame(kind::WINDOW_UPDATE, 0, b, &1000u32.to_be_bytes()).unwrap();
        assert_eq!(news_of(&mut h), (vec![b], false));
        h.feed_frame(kind::WINDOW_UPDATE, 0, 0, &1000u32.to_be_bytes()).unwrap();
        assert_eq!(news_of(&mut h), (vec![], true));
        // SETTINGS and GOAWAY are for everyone, PING for nobody
        let mut settings = Vec::new();
        frame::write_settings(&mut settings, &[(0x4, 70_000)]);
        h.feed(&settings).unwrap();
        assert_eq!(news_of(&mut h), (vec![], true));
        h.feed_frame(kind::PING, 0, 0, &[0; 8]).unwrap();
        assert_eq!(news_of(&mut h), (vec![], false));
        h.take();
        let mut goaway = Vec::new();
        frame::write_goaway(&mut goaway, 1, ErrorCode::NO_ERROR, b"");
        h.feed(&goaway).unwrap();
        assert_eq!(news_of(&mut h), (vec![], true));
        // the end of the connection is news for everyone
        let mut h = Harness::new();
        let _ = h.open("GET", "/");
        h.take();
        let _ = news_of(&mut h);
        h.c.peer_closed();
        assert_eq!(news_of(&mut h), (vec![], true));
    }

    #[test]
    fn news_about_very_many_streams_becomes_news_for_everyone() {
        let mut h = Harness::new();
        let ids: Vec<u32> = (0..300).map(|i| h.open("GET", &format!("/{i}"))).collect();
        h.take();
        let _ = news_of(&mut h);
        // a few streams: kept by name
        for id in &ids[..5] {
            h.respond(*id, "200", &[], true).unwrap();
        }
        assert_eq!(news_of(&mut h), (ids[..5].to_vec(), false));
        // 295 more different streams without anyone taking the news: it is not kept by name
        for id in &ids[5..] {
            h.respond(*id, "200", &[], true).unwrap();
        }
        let (listed, everyone) = news_of(&mut h);
        assert!(everyone && listed.is_empty());
    }

    #[test]
    fn taking_the_body_swaps_buffers_and_gives_the_same_credit_as_reading_it() {
        // the same traffic read the two ways: the bytes, the credit and the books are the same
        let run = |take: bool| {
            let mut h = Harness::with(Config::default());
            let id = h.open("GET", "/");
            h.take();
            h.respond(id, "200", &[], false).unwrap();
            assert!(matches!(h.c.poll_stream(id, &mut []), StreamEvent::Head(_)));
            let mut got = Vec::new();
            let mut buf = vec![0u8; 50_000];
            let mut carry: Vec<u8> = Vec::new();
            let mut updates = Vec::new();
            let mut sent = 0usize;
            while sent < 700_000 {
                for _ in 0..3 {
                    let piece: Vec<u8> = (sent..sent + 16_000).map(|i| (i % 251) as u8).collect();
                    h.data(id, &piece, false).unwrap();
                    sent += piece.len();
                }
                loop {
                    let event = if take { h.c.take_stream_data(id, &mut carry) } else { h.c.poll_stream(id, &mut buf) };
                    match event {
                        StreamEvent::Data(n) if take => {
                            assert_eq!(carry.len(), n);
                            got.extend_from_slice(&carry);
                        }
                        StreamEvent::Data(n) => got.extend_from_slice(&buf[..n]),
                        StreamEvent::Pending => break,
                        other => panic!("{other:?}"),
                    }
                }
                updates.extend(h.take().iter().map(|f| (f.kind, f.stream, f.number())));
                check_windows(&h.c);
            }
            assert_eq!(got.len(), sent);
            assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
            (updates, h.c.streams[&id].unannounced, h.c.unannounced, sent)
        };
        // reading 50 000 at a time takes 3 pieces of 16 000 in two or three reads; taking takes them in one: the credit
        // given and not yet given add up to the same
        let (read_updates, read_s, read_c, sent) = run(false);
        let (take_updates, take_s, take_c, _) = run(true);
        let total = |u: &[(u8, u32, u32)], stream: u32, rest: u32| u.iter().filter(|x| x.0 == kind::WINDOW_UPDATE && x.1 == stream).map(|x| x.2 as u64).sum::<u64>() + rest as u64;
        assert_eq!(total(&read_updates, 1, read_s), sent as u64);
        assert_eq!(total(&read_updates, 0, read_c), sent as u64);
        assert_eq!(total(&take_updates, 1, take_s), total(&read_updates, 1, read_s));
        assert_eq!(total(&take_updates, 0, take_c), total(&read_updates, 0, read_c));
    }

    #[test]
    fn taking_the_body_moves_at_most_take_max_and_the_rest_stays() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        assert!(matches!(h.c.poll_stream(id, &mut []), StreamEvent::Head(_)));
        let total = TAKE_MAX + TAKE_MAX / 2 + 5;
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(16_000);
            let piece: Vec<u8> = (sent..sent + n).map(|i| (i % 253) as u8).collect();
            h.data(id, &piece, false).unwrap();
            sent += n;
        }
        let mut carry = vec![9u8; 10]; // not empty: it is emptied first
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::Data(TAKE_MAX));
        assert_eq!(carry.len(), TAKE_MAX);
        assert!(carry.iter().enumerate().all(|(i, b)| *b == (i % 253) as u8));
        check_windows(&h.c);
        let mut got = std::mem::take(&mut carry);
        // what is left comes in the next take
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::Data(total - TAKE_MAX));
        got.extend_from_slice(&carry);
        assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 253) as u8));
        assert_eq!(got.len(), total);
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::Pending);
        assert!(carry.is_empty());
        // and all of what is waiting, when it all starts at the start of the buffer, is taken by swapping
        h.data(id, &[1, 2, 3], true).unwrap();
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::Data(3));
        assert_eq!(carry, [1, 2, 3]);
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::End);
        check_windows(&h.c);
    }

    #[test]
    fn taking_the_body_of_a_failed_stream_gives_what_came_first_then_the_failure() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        h.data(id, b"partial", false).unwrap();
        h.feed_frame(kind::RST_STREAM, 0, id, &ErrorCode::INTERNAL_ERROR.0.to_be_bytes()).unwrap();
        let mut carry = Vec::new();
        assert!(matches!(h.c.take_stream_data(id, &mut carry), StreamEvent::Head(_)));
        assert_eq!(h.c.take_stream_data(id, &mut carry), StreamEvent::Data(7));
        assert_eq!(carry, b"partial");
        assert!(matches!(h.c.take_stream_data(id, &mut carry), StreamEvent::Failed(_)));
        assert!(carry.is_empty());
    }

    #[test]
    fn the_part_of_the_buffer_that_was_read_does_not_pile_up() {
        // a reader that is always a little behind never empties the buffer; what it has read must still go
        let mut h = Harness::with(Config::default());
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        let mut sent = 0usize;
        let mut got = Vec::new();
        let mut buf = vec![0u8; 12_000];
        let mut biggest = 0usize;
        for _ in 0..300 {
            let piece: Vec<u8> = (sent..sent + 16_000).map(|i| (i % 251) as u8).collect();
            h.data(id, &piece, false).unwrap();
            sent += piece.len();
            if let StreamEvent::Data(n) = h.c.poll_stream(id, &mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
            let s = &h.c.streams[&id];
            biggest = biggest.max(s.body.len());
            assert!(s.body.len() <= 2 * s.unread() + 64 * 1024, "{} bytes held for {} unread", s.body.len(), s.unread());
        }
        // 4.8 MB were sent in the 300 rounds and 3.6 MB read, so 1.2 MB were unread at the end: the buffer never held much
        // more than twice that, nowhere near the 4.8 MB that went through it
        assert!(biggest < 3_000_000, "{biggest}");
        // and nothing was lost or reordered
        while let StreamEvent::Data(n) = h.c.poll_stream(id, &mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), sent);
        assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
        check_windows(&h.c);
    }

    #[test]
    fn a_response_that_has_ended_gets_no_more_stream_credit() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(1, "200", &[], false).unwrap();
        h.data(1, &[1u8; 900], true).unwrap();
        assert_eq!(h.got(id).body.len(), 900);
        assert!(h.take().is_empty());
    }

    #[test]
    fn a_server_that_sends_more_than_the_stream_window_loses_the_stream() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(1, "200", &[], false).unwrap();
        h.data(1, &[1u8; 600], false).unwrap();
        h.data(1, &[1u8; 401], false).unwrap();
        assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::FLOW_CONTROL_ERROR));
        let out = h.take();
        assert_eq!(out.iter().filter(|f| f.kind == kind::RST_STREAM).map(|f| f.number()).collect::<Vec<_>>(), vec![ErrorCode::FLOW_CONTROL_ERROR.0]);
        assert!(h.c.error().is_none());
        // what it held was given back, and so was the frame that did it
        check_windows(&h.c);
        assert_eq!(h.c.recv_window + h.c.unannounced as i64, 65_535);
    }

    #[test]
    fn a_server_that_sends_more_than_the_connection_window_loses_the_connection() {
        let mut h = Harness::with(Config { stream_window: 1 << 20, connection_window: 65_535, max_header_list: 64 << 10 });
        h.open("GET", "/");
        h.respond(1, "200", &[], false).unwrap();
        for _ in 0..3 {
            h.data(1, &[0u8; 16_384], false).unwrap();
        }
        assert_eq!(h.data(1, &[0u8; 16_384], false).unwrap_err().code, ErrorCode::FLOW_CONTROL_ERROR);
    }

    #[test]
    fn padding_is_credited_at_once() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(1, "200", &[], false).unwrap();
        // 10 bytes of data and 20 of padding: 31 with the Pad Length byte
        let mut payload = vec![20u8];
        payload.extend_from_slice(b"0123456789");
        payload.extend_from_slice(&[0u8; 20]);
        h.feed_frame(kind::DATA, flag::PADDED, 1, &payload).unwrap();
        assert_eq!(h.c.recv_window, 65_535 - 31);
        assert_eq!(h.c.unannounced, 21);
        assert_eq!(h.c.streams[&id].recv_window, 1000 - 31);
        assert_eq!(h.c.streams[&id].unannounced, 21);
        check_windows(&h.c);
        let got = h.got(id);
        assert_eq!(got.body, b"0123456789");
        assert_eq!(h.c.unannounced, 31);
        check_windows(&h.c);
        // enough padding makes the stream announce without a byte being read
        let mut payload = vec![255u8];
        payload.extend_from_slice(&[0u8; 255]);
        for _ in 0..2 {
            h.feed_frame(kind::DATA, flag::PADDED, 1, &payload).unwrap();
        }
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, 1, 31 + 256 + 256)]);
        check_windows(&h.c);
    }

    #[test]
    fn letting_go_of_a_stream_gives_back_what_it_held() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(1, "200", &[], false).unwrap();
        h.data(1, &[1u8; 700], false).unwrap();
        check_windows(&h.c);
        h.c.release_stream(id);
        assert_eq!(h.c.unannounced, 700);
        assert_eq!(h.c.active_streams(), 0);
        // the server was told to stop; and what it sends before it hears is dropped, but credited
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, 1, ErrorCode::CANCEL.0)]);
        h.data(1, &[1u8; 200], false).unwrap();
        assert_eq!(h.c.unannounced, 900);
        check_windows(&h.c);
        // a stream whose exchange was complete needs no RST_STREAM
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], true).unwrap();
        h.take();
        assert_eq!(h.got(id).ended, true);
        h.c.release_stream(id);
        assert!(h.take().is_empty());
        // and nothing happens for one that is not there
        h.c.release_stream(id);
        h.c.release_stream(999);
        assert!(h.take().is_empty());
    }

    // ---------------------------------------------------------------------------------------- RST_STREAM

    #[test]
    fn a_reset_stream_fails_and_a_refused_one_may_be_tried_again() {
        let mut h = Harness::new();
        let a = h.open("GET", "/");
        let b = h.open("GET", "/");
        let c = h.open("GET", "/");
        h.respond(a, "200", &[], false).unwrap();
        h.data(a, b"partly", false).unwrap();
        h.feed_frame(kind::RST_STREAM, 0, a, &ErrorCode::INTERNAL_ERROR.0.to_be_bytes()).unwrap();
        h.feed_frame(kind::RST_STREAM, 0, b, &ErrorCode::REFUSED_STREAM.0.to_be_bytes()).unwrap();
        let got = h.got(a);
        let failed = got.failed.unwrap();
        assert_eq!((failed.code, failed.retry_safe), (ErrorCode::INTERNAL_ERROR, false));
        // what arrived before the reset is there to read, and the failure comes after it
        assert_eq!(got.head.unwrap().status, 200);
        assert_eq!(got.body, b"partly");
        let failed = h.got(b).failed.unwrap();
        assert_eq!((failed.code, failed.retry_safe), (ErrorCode::REFUSED_STREAM, true));
        assert_eq!(h.got(c).failed, None);
        assert_eq!(h.c.active_streams(), 1);
        check_windows(&h.c);
        // a reset for a stream that is gone is nothing
        h.c.release_stream(a);
        h.feed_frame(kind::RST_STREAM, 0, a, &ErrorCode::CANCEL.0.to_be_bytes()).unwrap();
    }

    #[test]
    fn a_reset_after_the_whole_response_leaves_the_response_readable() {
        // a server that answered before it had the whole request may say it wants no more of it
        let mut h = Harness::new();
        let id = h.open_with("POST", "/", &[], false);
        h.respond(id, "413", &[], false).unwrap();
        h.data(id, b"too big", true).unwrap();
        h.feed_frame(kind::RST_STREAM, 0, id, &ErrorCode::NO_ERROR.0.to_be_bytes()).unwrap();
        let got = h.got(id);
        assert_eq!(got.head.unwrap().status, 413);
        assert_eq!(got.body, b"too big");
        assert!(got.ended && got.failed.is_none());
        // and the body is no longer to be sent
        assert!(h.c.send_data(id, b"x", false).is_err() || h.c.send_capacity(id) == 0);
    }

    #[test]
    fn a_reset_of_a_stream_that_never_was_is_a_connection_error() {
        for stream in [2, 3, 99] {
            let mut h = Harness::new();
            h.open("GET", "/");
            let e = h.feed_frame(kind::RST_STREAM, 0, stream, &[0; 4]).unwrap_err();
            assert_eq!(e.code, ErrorCode::PROTOCOL_ERROR, "stream {stream}");
        }
    }

    // ---------------------------------------------------------------------------------------- GOAWAY and the end

    #[test]
    fn a_graceful_goaway_lets_the_streams_it_took_finish() {
        let mut h = Harness::new();
        let s1 = h.open("GET", "/");
        let s3 = h.open("GET", "/");
        let s5 = h.open("GET", "/");
        h.take();
        assert!(h.c.usable());
        let mut goaway = Vec::new();
        frame::write_goaway(&mut goaway, 3, ErrorCode::NO_ERROR, b"bye");
        h.feed(&goaway).unwrap();
        assert!(!h.c.usable());
        assert!(!h.c.can_open_stream());
        assert_eq!(h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "a", path: "/", headers: &[], secret: &[] }, true), Err(OpenError::Unavailable));
        let failed = h.got(s5).failed.unwrap();
        assert!(failed.retry_safe, "the server did not get to it");
        assert_eq!(h.got(s1).failed, None);
        h.respond(s1, "200", &[], true).unwrap();
        h.respond(s3, "200", &[], true).unwrap();
        assert!(h.got(s1).ended);
        assert!(h.got(s3).ended);
        assert_eq!(h.c.active_streams(), 0);
        assert!(h.c.error().is_none(), "the connection is not broken, only finishing");
    }

    #[test]
    fn a_goaway_with_an_error_loses_the_connection() {
        let mut h = Harness::new();
        let s1 = h.open("GET", "/");
        let s3 = h.open("GET", "/");
        h.take();
        let mut goaway = Vec::new();
        frame::write_goaway(&mut goaway, 1, ErrorCode::ENHANCE_YOUR_CALM, b"slow down");
        let e = h.feed(&goaway).unwrap_err();
        assert_eq!((e.code, e.local), (ErrorCode::ENHANCE_YOUR_CALM, false));
        assert!(e.reason.contains("slow down"));
        assert!(h.take().is_empty(), "no GOAWAY in answer to one");
        let failed = h.got(s1).failed.unwrap();
        assert!(!failed.retry_safe, "the server may have acted on it");
        let failed = h.got(s3).failed.unwrap();
        assert!(failed.retry_safe, "but not on this one");
        assert!(h.c.error().is_some());
        assert_eq!(h.feed(b"more").unwrap_err().code, ErrorCode::ENHANCE_YOUR_CALM, "the error stays");
    }

    #[test]
    fn a_later_goaway_cannot_raise_the_last_stream() {
        let mut h = Harness::new();
        let s1 = h.open("GET", "/");
        let s3 = h.open("GET", "/");
        let mut wire = Vec::new();
        frame::write_goaway(&mut wire, 1, ErrorCode::NO_ERROR, b"");
        frame::write_goaway(&mut wire, 3, ErrorCode::NO_ERROR, b"");
        h.feed(&wire).unwrap();
        assert!(h.got(s3).failed.unwrap().retry_safe);
        assert_eq!(h.got(s1).failed, None);
        // a server that starts with the largest id and then says where it really is
        let mut h = Harness::new();
        let s1 = h.open("GET", "/");
        let s3 = h.open("GET", "/");
        let mut wire = Vec::new();
        frame::write_goaway(&mut wire, 0x7fff_ffff, ErrorCode::NO_ERROR, b"");
        h.feed(&wire).unwrap();
        assert!(!h.c.usable());
        assert_eq!((h.got(s1).failed, h.got(s3).failed), (None, None));
        let mut wire = Vec::new();
        frame::write_goaway(&mut wire, 1, ErrorCode::NO_ERROR, b"");
        h.feed(&wire).unwrap();
        assert_eq!(h.got(s1).failed, None);
        assert!(h.got(s3).failed.unwrap().retry_safe);
    }

    #[test]
    fn closing_the_transport_fails_what_was_not_finished() {
        let mut h = Harness::new();
        let done = h.open("GET", "/");
        let open = h.open("GET", "/");
        h.respond(done, "200", &[], false).unwrap();
        h.data(done, b"complete", true).unwrap();
        h.respond(open, "200", &[], false).unwrap();
        h.data(open, b"partial", false).unwrap();
        h.c.peer_closed();
        assert!(!h.c.usable());
        let got = h.got(done);
        assert_eq!(got.body, b"complete", "a finished response can still be read");
        assert!(got.ended);
        let failed = h.got(open).failed.unwrap();
        assert!(!failed.retry_safe);
        assert!(h.c.error().is_some());
        // asking again changes nothing
        h.c.peer_closed();
        assert_eq!(h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "a", path: "/", headers: &[], secret: &[] }, true), Err(OpenError::Unavailable));
    }

    #[test]
    fn closing_the_connection_says_goodbye() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.c.close();
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.number())).collect::<Vec<_>>(), vec![(kind::GOAWAY, 0)]);
        assert!(!h.c.usable());
        assert!(h.got(id).failed.is_some());
        h.c.close();
        assert!(h.take().is_empty(), "once is enough");
        assert!(h.c.process().is_err(), "and nothing is read any more");
    }

    // ---------------------------------------------------------------------------------------- connection frames

    #[test]
    fn pings_are_answered_in_kind() {
        let mut h = Harness::new();
        let mut wire = Vec::new();
        frame::write_ping(&mut wire, false, [1, 2, 3, 4, 5, 6, 7, 8]);
        frame::write_ping(&mut wire, true, [9; 8]);
        frame::write_ping(&mut wire, false, [8, 7, 6, 5, 4, 3, 2, 1]);
        h.feed(&wire).unwrap();
        let out = h.take();
        assert_eq!(out.len(), 2, "an acknowledgement is not acknowledged");
        assert_eq!((out[0].flags, out[0].payload.clone()), (flag::ACK, vec![1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!((out[1].flags, out[1].payload.clone()), (flag::ACK, vec![8, 7, 6, 5, 4, 3, 2, 1]));
    }

    #[test]
    fn a_flood_of_frames_that_need_answers_is_stopped() {
        // 17 bytes of answer for each ping, and nobody takes the output
        let mut ping = Vec::new();
        frame::write_ping(&mut ping, false, [0; 8]);
        let mut h = Harness::new();
        let e = h.feed(&ping.repeat(70_000)).unwrap_err();
        assert_eq!(e.code, ErrorCode::ENHANCE_YOUR_CALM);
        // the same number, with the answers sent as they come, is nothing
        let mut h = Harness::new();
        for _ in 0..70 {
            h.feed(&ping.repeat(1000)).unwrap();
            h.take();
        }
        // SETTINGS the same
        let mut settings = Vec::new();
        frame::write_settings(&mut settings, &[]);
        let mut h = Harness::new();
        assert_eq!(h.feed(&settings.repeat(130_000)).unwrap_err().code, ErrorCode::ENHANCE_YOUR_CALM);
    }

    #[test]
    fn a_flood_of_empty_data_frames_is_stopped() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        let empty = raw(kind::DATA, 0, 1, &[]);
        h.feed(&empty.repeat(EMPTY_FRAMES as usize)).unwrap();
        // a frame of another kind starts the count again
        h.feed(&raw(kind::PING, 0, 0, &[0; 8])).unwrap();
        h.feed(&empty.repeat(EMPTY_FRAMES as usize)).unwrap();
        assert_eq!(h.feed(&empty.repeat(2)).unwrap_err().code, ErrorCode::ENHANCE_YOUR_CALM);
        // an empty frame that ends the stream is not part of a flood
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.feed(&raw(kind::DATA, flag::END_STREAM, 1, &[])).unwrap();
        assert!(h.got(id).ended);
    }

    #[test]
    fn frames_a_client_has_no_use_for_are_connection_errors() {
        let cases: Vec<(&str, u8, u8, u32, Vec<u8>, ErrorCode)> = vec![
            ("PUSH_PROMISE", kind::PUSH_PROMISE, flag::END_HEADERS, 1, vec![0, 0, 0, 2, 0x88], ErrorCode::PROTOCOL_ERROR),
            ("DATA on a stream never opened", kind::DATA, 0, 7, vec![1], ErrorCode::PROTOCOL_ERROR),
            ("DATA on an even stream", kind::DATA, 0, 2, vec![1], ErrorCode::PROTOCOL_ERROR),
            ("HEADERS on an even stream", kind::HEADERS, flag::END_HEADERS, 2, vec![0x88], ErrorCode::PROTOCOL_ERROR),
            ("WINDOW_UPDATE on a stream never opened", kind::WINDOW_UPDATE, 0, 7, vec![0, 0, 0, 1], ErrorCode::PROTOCOL_ERROR),
            ("a frame larger than the size allowed", kind::DATA, 0, 1, vec![0; 16_385], ErrorCode::FRAME_SIZE_ERROR),
            ("a window update of nothing for the connection", kind::WINDOW_UPDATE, 0, 0, vec![0, 0, 0, 0], ErrorCode::PROTOCOL_ERROR),
            ("a connection window past the limit", kind::WINDOW_UPDATE, 0, 0, vec![0x7f, 0xff, 0xff, 0xff], ErrorCode::FLOW_CONTROL_ERROR),
            ("PING of the wrong length", kind::PING, 0, 0, vec![0; 7], ErrorCode::FRAME_SIZE_ERROR),
            ("SETTINGS on a stream", kind::SETTINGS, 0, 1, vec![], ErrorCode::PROTOCOL_ERROR),
            ("SETTINGS of the wrong length", kind::SETTINGS, 0, 0, vec![0; 5], ErrorCode::FRAME_SIZE_ERROR),
            ("GOAWAY on a stream", kind::GOAWAY, 0, 1, vec![0; 8], ErrorCode::PROTOCOL_ERROR),
            ("padding as long as the frame", kind::DATA, flag::PADDED, 1, vec![5, 0, 0, 0, 0], ErrorCode::PROTOCOL_ERROR),
        ];
        for (what, kind, flags, stream, payload, code) in cases {
            let mut h = Harness::new();
            h.open("GET", "/");
            h.respond(1, "200", &[], false).unwrap();
            h.take();
            let e = h.feed(&raw(kind, flags, stream, &payload[..payload.len().min(16_385)])).unwrap_err();
            assert_eq!(e.code, code, "{what}");
            assert!(e.local);
            let out = h.take();
            assert_eq!(out.len(), 1, "{what}");
            assert_eq!((out[0].kind, out[0].number()), (kind::GOAWAY, code.0), "{what}");
            // everything is lost with it
            assert!(h.got(1).failed.is_some(), "{what}");
        }
    }

    #[test]
    fn frames_for_one_stream_that_are_wrong_lose_only_that_stream() {
        let mut h = Harness::new();
        let a = h.open("GET", "/");
        let b = h.open("GET", "/");
        h.take();
        // WINDOW_UPDATE of nothing, on a stream; a PRIORITY of the wrong length
        h.feed_frame(kind::WINDOW_UPDATE, 0, a, &[0; 4]).unwrap();
        h.feed_frame(kind::PRIORITY, 0, b, &[0; 4]).unwrap();
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream)).collect::<Vec<_>>(), vec![(kind::RST_STREAM, a), (kind::RST_STREAM, b)]);
        assert_eq!(out[0].number(), ErrorCode::PROTOCOL_ERROR.0);
        assert_eq!(out[1].number(), ErrorCode::FRAME_SIZE_ERROR.0);
        assert!(h.got(a).failed.is_some() && h.got(b).failed.is_some());
        assert!(h.c.error().is_none());
        // a stream window pushed past the limit
        let c = h.open("GET", "/");
        h.take();
        h.feed_frame(kind::WINDOW_UPDATE, 0, c, &0x7fff_ffffu32.to_be_bytes()).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, ErrorCode::FLOW_CONTROL_ERROR.0)]);
        // unknown frames and priorities are ignored
        h.feed_frame(0x42, 0xff, 0, b"whatever").unwrap();
        h.feed_frame(0x42, 0, 3, b"").unwrap();
        h.feed_frame(kind::PRIORITY, 0, 1, &[0; 5]).unwrap();
        assert!(h.take().is_empty());
    }

    #[test]
    fn bad_settings_are_connection_errors() {
        for (what, id, value, code) in [
            ("ENABLE_PUSH of 2", setting::ENABLE_PUSH, 2, ErrorCode::PROTOCOL_ERROR),
            ("an initial window over 2^31 - 1", setting::INITIAL_WINDOW_SIZE, 0x8000_0000, ErrorCode::FLOW_CONTROL_ERROR),
            ("a frame size under 16384", setting::MAX_FRAME_SIZE, 16_383, ErrorCode::PROTOCOL_ERROR),
            ("a frame size over 2^24 - 1", setting::MAX_FRAME_SIZE, 1 << 24, ErrorCode::PROTOCOL_ERROR),
        ] {
            let mut h = Harness::unsettled(Config::default());
            h.take();
            let mut wire = Vec::new();
            frame::write_settings(&mut wire, &[(id, value)]);
            assert_eq!(h.feed(&wire).unwrap_err().code, code, "{what}");
        }
        // an initial window that takes a stream window past the limit
        let mut h = Harness::new();
        let id = h.open_with("POST", "/", &[], false);
        h.feed_frame(kind::WINDOW_UPDATE, 0, id, &0x7fff_0000u32.to_be_bytes()).unwrap();
        let mut wire = Vec::new();
        frame::write_settings(&mut wire, &[(setting::INITIAL_WINDOW_SIZE, 0x7fff_ffff)]);
        assert_eq!(h.feed(&wire).unwrap_err().code, ErrorCode::FLOW_CONTROL_ERROR);
        // values at the edges are fine
        let mut h = Harness::unsettled(Config::default());
        h.take();
        let mut wire = Vec::new();
        frame::write_settings(&mut wire, &[(setting::ENABLE_PUSH, 1), (setting::MAX_FRAME_SIZE, 16_777_215), (setting::INITIAL_WINDOW_SIZE, 0x7fff_ffff), (setting::MAX_CONCURRENT_STREAMS, 0), (setting::HEADER_TABLE_SIZE, 0)]);
        h.feed(&wire).unwrap();
    }

    #[test]
    fn the_servers_table_size_goes_to_the_encoder() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::HEADER_TABLE_SIZE, 0)]);
        h.open_with("GET", "/", &[("x-one", "1")], true);
        h.open_with("GET", "/", &[("x-one", "1")], true);
        let out = h.take();
        assert_eq!(out.len(), 2);
        // the first block starts with the update to 0 (0b001 followed by 5 bits of size)
        assert_eq!(out[0].payload[0], 0x20);
        // and with no table nothing could be an index into it: the same field costs the same the second time
        assert_ne!(out[1].payload[0], 0x20);
        assert_eq!(out[0].payload.len() - 1, out[1].payload.len());
    }

    // ---------------------------------------------------------------------------------------- streams

    #[test]
    fn no_more_streams_than_the_server_allows() {
        let mut h = Harness::with_settings(Config::default(), &[(setting::MAX_CONCURRENT_STREAMS, 2)]);
        let a = h.open("GET", "/");
        let b = h.open("GET", "/");
        assert!(!h.c.can_open_stream());
        assert_eq!(h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "a", path: "/", headers: &[], secret: &[] }, true), Err(OpenError::Full));
        // a stream whose exchange is over makes room, read or not, let go of or not
        h.respond(a, "200", &[], true).unwrap();
        assert!(h.c.can_open_stream());
        let c = h.open("GET", "/");
        assert_eq!(c, 5);
        assert!(!h.c.can_open_stream());
        h.c.release_stream(b);
        assert!(h.c.can_open_stream());
        // a failed stream too
        let d = h.open("GET", "/");
        assert!(!h.c.can_open_stream());
        h.feed_frame(kind::RST_STREAM, 0, d, &ErrorCode::CANCEL.0.to_be_bytes()).unwrap();
        assert!(h.c.can_open_stream());
        let _ = c;
    }

    #[test]
    fn stream_ids_run_out() {
        let mut h = Harness::new();
        h.c.next_stream_id = MAX_STREAM_ID;
        assert!(h.c.usable());
        assert_eq!(h.open("GET", "/"), MAX_STREAM_ID);
        assert!(!h.c.usable());
        assert_eq!(h.c.open_stream(&Request { method: "GET", scheme: "https", authority: "a", path: "/", headers: &[], secret: &[] }, true), Err(OpenError::Unavailable));
    }

    #[test]
    fn sending_on_streams_that_cannot_take_it() {
        let mut h = Harness::new();
        assert!(h.c.send_data(99, b"x", false).is_err(), "no such stream");
        assert_eq!(h.c.send_capacity(99), 0);
        let id = h.open_with("POST", "/", &[], false);
        h.feed_frame(kind::RST_STREAM, 0, id, &ErrorCode::CANCEL.0.to_be_bytes()).unwrap();
        assert_eq!(h.c.send_capacity(id), 0);
        assert_eq!(h.c.send_data(id, b"x", false).unwrap_err().code, ErrorCode::CANCEL);
        let id = h.open_with("POST", "/", &[], false);
        h.c.peer_closed();
        assert!(h.c.send_data(id, b"x", false).is_err());
        assert!(h.c.poll_stream(1234, &mut [0; 4]) != StreamEvent::Pending, "a stream that is not there is an error, not a wait");
    }

    #[test]
    fn many_streams_at_once_with_their_data_interleaved() {
        let mut h = Harness::new();
        let ids: Vec<u32> = (0..50).map(|_| h.open("GET", "/")).collect();
        for &id in &ids {
            h.respond(id, "200", &[("x-id", &id.to_string())], false).unwrap();
        }
        // the data of all of them in small pieces, round and round
        let body = |id: u32| -> Vec<u8> { (0..5000u32).map(|i| (i as u8) ^ (id as u8)).collect() };
        for round in 0..5 {
            for &id in &ids {
                let b = body(id);
                h.data(id, &b[round * 1000..(round + 1) * 1000], round == 4).unwrap();
            }
        }
        for &id in &ids {
            let got = h.got(id);
            assert_eq!(got.head.unwrap().headers, header_pairs(&[("x-id", &id.to_string())]));
            assert_eq!(got.body, body(id), "stream {id}");
            assert!(got.ended);
            check_windows(&h.c);
        }
    }

    // ---------------------------------------------------------------------------------------- DATA frames in pieces

    /// What the transport does: the server's bytes go in with `feed`, `n` at a time, and the books balance after every piece.
    fn feed_in_pieces(h: &mut Harness, bytes: &[u8], n: usize) -> Outcome {
        for piece in bytes.chunks(n) {
            h.c.feed(piece)?;
            h.c.assert_books();
        }
        Ok(())
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn the_payload_of_a_frame_that_is_cut_off_is_the_body_as_it_comes() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[("content-length", "3000")], false).unwrap();
        h.take();
        let body = pattern(3000);
        let wire = raw(kind::DATA, flag::END_STREAM, id, &body);
        let mut news = News::default();
        h.c.take_news(&mut news);

        // the header and 100 bytes of the payload: the 100 bytes are there to read
        h.c.feed(&wire[..HEADER_LEN + 100]).unwrap();
        h.c.assert_books();
        let first = h.got(id);
        assert!(first.head.is_some());
        assert_eq!(first.body, body[..100]);
        assert!(!first.ended);
        h.c.take_news(&mut news);
        assert!(news.streams().contains(&id) || news.is_for_everyone(), "the reader is told there is something to read");
        assert!(h.c.inbound.is_empty(), "nothing is kept: it has gone where it belongs");

        // more, and the frame is still not complete
        h.c.feed(&wire[HEADER_LEN + 100..HEADER_LEN + 1100]).unwrap();
        h.c.assert_books();
        let second = h.got(id);
        assert_eq!(second.body, body[100..1100]);
        assert!(!second.ended, "the end of the response is not the end of a frame that has not ended");

        // the rest: the response ends with the frame
        h.c.feed(&wire[HEADER_LEN + 1100..]).unwrap();
        h.c.assert_books();
        let third = h.got(id);
        assert_eq!(third.body, body[1100..]);
        assert!(third.ended);
        assert!(h.c.inbound.is_empty());
        assert!(h.c.incoming.is_none());
    }

    #[test]
    fn pieces_make_no_difference_to_what_the_connection_makes_of_the_bytes() {
        // three streams, frames of every kind between the pieces of body, padding, an empty frame, and the end
        let build = || {
            let mut h = Harness::new();
            let ids: Vec<u32> = (0..3).map(|_| h.open("GET", "/")).collect();
            h.take();
            (h, ids)
        };
        let (mut whole, ids) = build();
        let (mut srv, _) = build();
        let mut wire = Vec::new();
        for (i, &id) in ids.iter().enumerate() {
            let length = if i == 2 { vec![("content-length", "5000")] } else { vec![] };
            let block = srv.block(&[(":status", "200")].into_iter().chain(length).collect::<Vec<_>>());
            wire.extend(raw(kind::HEADERS, flag::END_HEADERS, id, &block));
        }
        let mut padded = vec![40u8];
        padded.extend(pattern(700));
        padded.extend([0u8; 40]);
        wire.extend(raw(kind::DATA, 0, ids[0], &pattern(1000)));
        wire.extend(raw(kind::DATA, 0, ids[1], &pattern(16_384)));
        wire.extend(raw(kind::PING, 0, 0, b"12345678"));
        wire.extend(raw(kind::DATA, flag::PADDED, ids[0], &padded));
        wire.extend(raw(kind::DATA, 0, ids[2], &pattern(2000)));
        wire.extend(raw(kind::DATA, 0, ids[2], &[]));
        wire.extend(raw(kind::DATA, 0, ids[1], &pattern(9)));
        wire.extend(raw(kind::WINDOW_UPDATE, 0, ids[0], &[0, 0, 1, 0]));
        wire.extend(raw(kind::DATA, flag::END_STREAM, ids[2], &pattern(3000)));
        wire.extend(raw(kind::DATA, flag::END_STREAM, ids[0], &pattern(1)));
        wire.extend(raw(kind::DATA, flag::END_STREAM, ids[1], &[]));
        feed_in_pieces(&mut whole, &wire, wire.len()).unwrap();
        let (expected_out, expected_in): (Vec<Sent>, Vec<Got>) = (whole.take(), ids.iter().map(|&id| whole.got(id)).collect());
        assert!(expected_in.iter().all(|g| g.ended && g.failed.is_none()), "{expected_in:?}");
        assert_eq!(expected_in[0].body.len(), 1000 + 700 + 1);
        assert_eq!(expected_in[1].body.len(), 16_384 + 9);
        assert_eq!(expected_in[2].body.len(), 5000);
        for n in [1, 2, 3, 8, 9, 10, 17, 100, 999, 1000, 1009, 1010, 5000, 16_393] {
            let (mut h, ids) = build();
            // (the server's encoder is the same, so the blocks are the same: only the pieces differ)
            feed_in_pieces(&mut h, &wire, n).unwrap();
            assert!(h.c.inbound.len() < HEADER_LEN + 1, "{n}: only the start of a frame that is not DATA, or its header, may be kept");
            assert_eq!(h.take(), expected_out, "pieces of {n}");
            let got: Vec<Got> = ids.iter().map(|&id| h.got(id)).collect();
            assert_eq!(got, expected_in, "pieces of {n}");
            assert_eq!(h.c.recv_window, whole.c.recv_window, "pieces of {n}");
            assert_eq!(h.c.unannounced, whole.c.unannounced, "pieces of {n}");
            assert_eq!(h.take(), whole.take(), "pieces of {n}");
        }
    }

    #[test]
    fn a_frame_cut_off_after_part_of_its_header_waits_for_the_rest_of_the_header() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        let wire = raw(kind::DATA, 0, id, &pattern(500));
        for cut in 1..=HEADER_LEN + 1 {
            h.c.feed(&wire[..cut]).unwrap();
            h.c.assert_books();
            h.c.feed(&wire[cut..]).unwrap();
            h.c.assert_books();
        }
        let got = h.got(id);
        assert_eq!(got.body.len(), 500 * (HEADER_LEN + 1));
        assert!(got.body.chunks(500).all(|c| c == &pattern(500)[..]));
    }

    #[test]
    fn a_frame_whose_start_was_kept_is_completed_with_only_the_bytes_it_needs() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        // half a PING is kept (it is not DATA); the next call has the rest of it and a DATA frame, both handled in
        // place, without the DATA frame going through `inbound`
        let ping = raw(kind::PING, 0, 0, b"abcdefgh");
        let mut next = ping[10..].to_vec();
        next.extend(raw(kind::DATA, 0, id, &pattern(2000)));
        h.c.feed(&ping[..10]).unwrap();
        assert_eq!(h.c.inbound.len(), 10);
        let capacity = h.c.inbound.capacity();
        h.c.feed(&next).unwrap();
        assert!(h.c.inbound.is_empty());
        assert_eq!(h.c.inbound.capacity(), capacity, "no more room was needed");
        assert_eq!(h.take(), vec![Sent { kind: kind::PING, flags: flag::ACK, stream: 0, payload: b"abcdefgh".to_vec() }]);
        assert_eq!(h.got(id).body, pattern(2000));
    }

    #[test]
    fn the_rest_of_a_frame_for_a_stream_that_was_let_go_is_credited_at_once() {
        let mut h = Harness::with(Config { stream_window: 1 << 20, connection_window: 65_535, max_header_list: 64 << 10 });
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        let wire = raw(kind::DATA, 0, id, &pattern(16_384));
        h.c.feed(&wire[..HEADER_LEN + 4000]).unwrap();
        h.c.assert_books();
        h.c.release_stream(id);
        h.c.assert_books();
        assert_eq!(h.c.unannounced, 4000 + 0);
        h.c.feed(&wire[HEADER_LEN + 4000..HEADER_LEN + 10_000]).unwrap();
        h.c.assert_books();
        assert_eq!(h.c.unannounced, 10_000);
        h.c.feed(&wire[HEADER_LEN + 10_000..]).unwrap();
        h.c.assert_books();
        // all 16384 bytes are credited, though nobody read them: the window does not shrink for good
        assert_eq!(h.c.recv_window as u32 + h.c.unannounced, 65_535);
        // and more frames for the stream are no more than that
        h.data(id, &pattern(100), false).unwrap();
        h.c.assert_books();
    }

    #[test]
    fn a_frame_that_is_wrong_for_its_stream_loses_the_stream_when_its_header_comes() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        // b has its head; a has not: DATA for a is wrong, and is known to be as soon as its header is here
        h.respond(b, "200", &[("content-length", "100")], false).unwrap();
        let mut wire = raw(kind::DATA, 0, a, &pattern(5000));
        wire.extend(raw(kind::DATA, 0, b, &pattern(100)));
        feed_in_pieces(&mut h, &wire[..HEADER_LEN + 7], 3).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, a, ErrorCode::PROTOCOL_ERROR.0)]);
        feed_in_pieces(&mut h, &wire[HEADER_LEN + 7..], 700).unwrap();
        assert!(h.take().is_empty(), "nothing more is said about it");
        assert_eq!(h.got(a).failed.unwrap().reason, "DATA before the response headers");
        let got = h.got(b);
        assert_eq!(got.body, pattern(100));
        assert!(!got.ended);
        // the 5000 bytes were thrown away and are credited, not held (and the 100 that were read)
        assert_eq!(h.c.unannounced, 5000 + 100);
    }

    #[test]
    fn more_than_the_content_length_says_is_known_when_the_frame_begins() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[("content-length", "1000")], false).unwrap();
        h.take();
        let wire = raw(kind::DATA, flag::END_STREAM, id, &pattern(1500));
        // 1500 bytes of a body that is to be 1000: the stream is lost with the frame's header, not at its end
        h.c.feed(&wire[..HEADER_LEN + 10]).unwrap();
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, id, ErrorCode::PROTOCOL_ERROR.0)]);
        h.c.feed(&wire[HEADER_LEN + 10..]).unwrap();
        h.c.assert_books();
        let got = h.got(id);
        assert!(got.body.is_empty() && got.failed.unwrap().reason.contains("Content-Length"));
        // and a last frame that is short of it
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[("content-length", "1000")], false).unwrap();
        let wire = raw(kind::DATA, flag::END_STREAM, id, &pattern(900));
        h.c.feed(&wire[..HEADER_LEN + 10]).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream)).collect::<Vec<_>>(), vec![(kind::RST_STREAM, id)]);
    }

    #[test]
    fn a_frame_that_does_not_fit_the_connection_window_is_refused_when_its_header_comes() {
        let mut h = Harness::with(Config { stream_window: 1 << 20, connection_window: 65_535, max_header_list: 64 << 10 });
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        for _ in 0..3 {
            h.data(id, &[0u8; 16_384], false).unwrap();
        }
        // 16383 bytes are left of the window: a frame of 16384 breaks it, and the header says so
        let wire = raw(kind::DATA, 0, id, &[0u8; 16_384]);
        let e = h.c.feed(&wire[..HEADER_LEN + 1]).unwrap_err();
        assert_eq!(e.code, ErrorCode::FLOW_CONTROL_ERROR);
        // a frame of 16383 is within it
        let mut h = Harness::with(Config { stream_window: 1 << 20, connection_window: 65_535, max_header_list: 64 << 10 });
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        for _ in 0..3 {
            h.data(id, &[0u8; 16_384], false).unwrap();
        }
        let wire = raw(kind::DATA, 0, id, &[0u8; 16_383]);
        feed_in_pieces(&mut h, &wire, 1000).unwrap();
        assert_eq!(h.c.recv_window, 0);
    }

    #[test]
    fn a_padded_frame_waits_until_it_is_all_here() {
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        // (what is padding is not known until the Pad Length byte, and the end of the data is where the padding begins)
        let mut payload = vec![100u8];
        payload.extend(pattern(400));
        payload.extend([0u8; 100]);
        let wire = raw(kind::DATA, flag::PADDED, id, &payload);
        let half = HEADER_LEN + 250;
        h.c.feed(&wire[..half]).unwrap();
        h.c.assert_books();
        assert_eq!(h.c.inbound.len(), half, "kept, not passed on");
        assert!(h.got(id).body.is_empty());
        h.c.feed(&wire[half..]).unwrap();
        h.c.assert_books();
        assert_eq!(h.got(id).body, pattern(400));
        assert!(h.c.inbound.is_empty());
    }

    #[test]
    fn a_connection_lost_in_the_middle_of_a_frame_leaves_what_arrived_and_then_the_failure() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        let wire = raw(kind::DATA, 0, id, &pattern(3000));
        h.c.feed(&wire[..HEADER_LEN + 1234]).unwrap();
        h.c.peer_closed();
        let got = h.got(id);
        assert_eq!(got.body, pattern(1234));
        assert!(got.failed.is_some() && !got.ended);
        h.c.assert_books();
        // and the connection that is lost stays lost, whatever else is fed
        assert!(h.c.feed(&wire[HEADER_LEN + 1234..]).is_err());
        assert!(h.c.incoming.is_none());
    }

    #[test]
    fn the_frames_after_one_that_is_cut_off_are_handled_in_the_same_call() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        h.respond(a, "200", &[], false).unwrap();
        let first = raw(kind::DATA, 0, a, &pattern(2000));
        h.c.feed(&first[..HEADER_LEN + 1500]).unwrap();
        // the rest of it, a PING, a response for b with its body and end
        let mut next = first[HEADER_LEN + 1500..].to_vec();
        next.extend(raw(kind::PING, 0, 0, b"ABCDEFGH"));
        let block = h.block(&[(":status", "200")]);
        next.extend(raw(kind::HEADERS, flag::END_HEADERS, b, &block));
        next.extend(raw(kind::DATA, flag::END_STREAM, b, b"hello"));
        h.c.feed(&next).unwrap();
        h.c.assert_books();
        assert_eq!(h.take().iter().map(|f| f.kind).collect::<Vec<_>>(), vec![kind::PING]);
        assert_eq!(h.got(a).body, pattern(2000));
        let got = h.got(b);
        assert_eq!(got.body, b"hello");
        assert!(got.ended);
    }

    #[test]
    fn bytes_put_in_with_receive_are_taken_in_order_with_a_frame_that_is_cut_off() {
        // (what the tests' harness does, and what `process` is for: the transport never mixes the two)
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.respond(id, "200", &[], false).unwrap();
        h.take();
        let wire = raw(kind::DATA, 0, id, &pattern(3000));
        h.c.feed(&wire[..HEADER_LEN + 100]).unwrap();
        h.c.receive(&wire[HEADER_LEN + 100..HEADER_LEN + 2000]);
        h.c.feed(&wire[HEADER_LEN + 2000..]).unwrap();
        h.c.process().unwrap();
        h.c.assert_books();
        assert_eq!(h.got(id).body, pattern(3000));
    }

    // ---------------------------------------------------------------------------------------- straight into the reader's buffer

    /// DATA frames of at most 16384 bytes with `body`, the last one ending the stream if `end`.
    fn data_frames(id: u32, body: &[u8], end: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunks = body.chunks(16384).peekable();
        while let Some(chunk) = chunks.next() {
            frame::write_data(&mut out, id, end && chunks.peek().is_none(), chunk);
        }
        out
    }

    /// A stream with its head taken, as a reader has it when it asks for body.
    fn reading(h: &mut Harness, extra: &[(&str, &str)]) -> u32 {
        let id = h.open("GET", "/");
        h.respond(id, "200", extra, false).unwrap();
        assert!(h.got(id).head.is_some());
        h.take();
        id
    }

    /// Feeds `bytes` in pieces of `n` as the reader of `id` does when it reads the socket itself, with a buffer of `size`
    /// bytes (B-87), and after each piece polls with a buffer as big; the books must balance after every step. The body in
    /// the order the reader got it, how much of it went straight into the buffer, and the last event of the polls.
    fn read_straight(h: &mut Harness, id: u32, bytes: &[u8], n: usize, size: usize) -> (Vec<u8>, usize, StreamEvent) {
        let mut body = Vec::new();
        let mut straight = 0;
        let mut buf = vec![0u8; size];
        let mut last = StreamEvent::Pending;
        for piece in bytes.chunks(n) {
            let mut direct = Direct::new(id, &mut buf);
            let fed = h.c.feed_direct(piece, Some(&mut direct));
            let w = direct.written();
            body.extend_from_slice(&buf[..w]);
            straight += w;
            h.c.assert_books();
            loop {
                match h.c.poll_stream(id, &mut buf) {
                    StreamEvent::Data(k) => body.extend_from_slice(&buf[..k]),
                    StreamEvent::Head(_) | StreamEvent::Trailers(_) => {}
                    other => {
                        last = other;
                        break;
                    }
                }
            }
            h.c.assert_books();
            if fed.is_err() {
                break;
            }
        }
        (body, straight, last)
    }

    #[test]
    fn a_reader_that_feeds_gets_the_body_straight_into_its_buffer() {
        let body = pattern(100_000);
        let wire = data_frames(1, &body, true);
        // (pieces that cut frames anywhere, buffers smaller and larger than a frame and than a piece)
        for (n, size) in [(1, 7), (100, 1000), (777, 300), (16_393, 16_384), (5000, 65_536), (wire.len(), 1 << 20)] {
            let mut h = Harness::new();
            let id = reading(&mut h, &[("content-length", "100000")]);
            let (got, straight, last) = read_straight(&mut h, id, &wire, n, size);
            assert!(got == body, "pieces of {n}, a buffer of {size}");
            assert_eq!(last, StreamEvent::End);
            assert!(straight > 0);
            if n <= size {
                assert_eq!(straight, body.len(), "pieces of {n} fit a buffer of {size}");
                assert_eq!(h.c.streams[&id].body.capacity(), 0, "the stream's own buffer was used");
            }
        }
    }

    #[test]
    fn bytes_read_straight_are_not_news_and_what_is_kept_is() {
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        news_of(&mut h);
        let mut buf = [0u8; 4000];
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, 0, id, &pattern(3000)), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 3000);
        assert_eq!(news_of(&mut h), (vec![], false), "the reader has what came: nobody is to be woken for it");
        let mut direct = Direct::new(id, &mut buf[..1000]);
        h.c.feed_direct(&raw(kind::DATA, 0, id, &pattern(3000)), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 1000);
        assert_eq!(news_of(&mut h), (vec![id], false), "what did not fit is waiting for a read");
    }

    #[test]
    fn what_does_not_fit_is_kept_and_read_next_and_nothing_goes_past_it() {
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        let body = pattern(6000);
        let mut buf = [0u8; 1000];
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, 0, id, &body[..3000]), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 1000);
        assert_eq!(buf[..], body[..1000]);
        assert_eq!(h.c.streams[&id].unread(), 2000);
        h.c.assert_books();
        // the stream holds bytes that were not read: the next ones go behind them, not to the reader
        let mut buf = [0u8; 1000];
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, 0, id, &body[3000..]), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 0);
        h.c.assert_books();
        assert!(h.got(id).body == body[1000..]);
        // and once they are read, the reader gets the next straight again
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, 0, id, b"more"), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 4);
        h.c.assert_books();
    }

    #[test]
    fn only_the_readers_stream_goes_to_its_buffer() {
        let mut h = Harness::new();
        let a = reading(&mut h, &[]);
        let b = reading(&mut h, &[]);
        news_of(&mut h);
        let mut wire = raw(kind::DATA, 0, b, &pattern(500));
        wire.extend(raw(kind::DATA, 0, a, b"for a"));
        wire.extend(raw(kind::DATA, 0, b, &pattern(700)[500..]));
        let mut buf = [0u8; 4000];
        let mut direct = Direct::new(a, &mut buf);
        h.c.feed_direct(&wire, Some(&mut direct)).unwrap();
        let w = direct.written();
        assert_eq!(&buf[..w], b"for a");
        assert_eq!(news_of(&mut h), (vec![b], false));
        assert_eq!(h.got(b).body, pattern(700));
        assert!(h.got(a).body.is_empty());
        h.c.assert_books();
    }

    #[test]
    fn nothing_goes_straight_before_the_head_is_taken_or_to_a_stream_that_collects() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        let mut wire = Vec::new();
        let block = h.block(&[(":status", "200")]);
        frame::write_header_block(&mut wire, id, false, &block, 16384);
        wire.extend(raw(kind::DATA, 0, id, b"body"));
        let mut buf = [0u8; 100];
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&wire, Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 0, "the head comes first");
        let got = h.got(id);
        assert!(got.head.is_some());
        assert_eq!(got.body, b"body");

        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        h.c.collect_stream(id, 1 << 20);
        let mut wire = raw(kind::DATA, 0, id, b"all ");
        wire.extend(raw(kind::DATA, flag::END_STREAM, id, b"of it"));
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&wire, Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 0);
        h.c.assert_books();
        let mut body = Vec::new();
        assert_eq!(h.c.collected(id, &mut body), Collected::Done(None));
        assert_eq!(body, b"all of it");
    }

    #[test]
    fn credit_for_bytes_read_straight_is_what_a_poll_would_give() {
        // as in `credit_goes_back_as_the_application_reads`, with the reads made as the bytes come
        let mut h = Harness::with(small_windows());
        let id = reading(&mut h, &[]);
        let mut buf = [0u8; 300];
        let mut feed = |h: &mut Harness| {
            let mut direct = Direct::new(id, &mut buf);
            h.c.feed_direct(&raw(kind::DATA, 0, id, &[7u8; 300]), Some(&mut direct)).unwrap();
            assert_eq!(direct.written(), 300);
            h.c.assert_books();
        };
        feed(&mut h);
        assert!(h.take().is_empty(), "300 is less than half");
        feed(&mut h);
        let out = h.take();
        assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, 1, 600)]);
        feed(&mut h);
        assert!(h.take().is_empty());
        assert_eq!(h.c.unannounced, 900);
        // the window is as the reads left it: 1000 - 900 + 600 is room for 700 more, and no more (fed with no room to read)
        let mut direct = Direct::new(id, &mut []);
        h.c.feed_direct(&raw(kind::DATA, 0, id, &[7u8; 700]), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 0);
        h.c.assert_books();
        assert_eq!(h.c.streams[&id].recv_window, 0);
        h.c.feed(&raw(kind::DATA, 0, id, &[7u8; 1])).unwrap();
        assert_eq!(h.got(id).failed.map(|e| e.code), Some(ErrorCode::FLOW_CONTROL_ERROR));
    }

    #[test]
    fn bytes_read_straight_come_before_the_end_the_trailers_or_the_failure() {
        let mut buf = [0u8; 1000];
        // the end
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        news_of(&mut h);
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, flag::END_STREAM, id, &pattern(500)), Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 500);
        assert_eq!(news_of(&mut h), (vec![id], false), "the end is news");
        assert_eq!(h.got(id), Got { ended: true, ..Got::default() });
        // trailers
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        let mut wire = raw(kind::DATA, 0, id, &pattern(500));
        let block = h.block(&[("x-check", "1")]);
        wire.extend(raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, id, &block));
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&wire, Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 500);
        assert_eq!(h.got(id), Got { trailers: Some(header_pairs(&[("x-check", "1")])), ended: true, ..Got::default() });
        // a reset
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        let mut wire = raw(kind::DATA, 0, id, &pattern(500));
        wire.extend(raw(kind::RST_STREAM, 0, id, &ErrorCode::INTERNAL_ERROR.0.to_be_bytes()));
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&wire, Some(&mut direct)).unwrap();
        assert_eq!(direct.written(), 500);
        let got = h.got(id);
        assert!(got.body.is_empty() && got.failed.is_some());
        h.c.assert_books();
        // a padded frame: the data is read, the padding given back
        let mut h = Harness::new();
        let id = reading(&mut h, &[]);
        let mut payload = vec![200u8];
        payload.extend(pattern(500));
        payload.extend([0u8; 200]);
        let mut direct = Direct::new(id, &mut buf);
        h.c.feed_direct(&raw(kind::DATA, flag::PADDED, id, &payload), Some(&mut direct)).unwrap();
        let w = direct.written();
        assert_eq!(&buf[..w], &pattern(500)[..]);
        h.c.assert_books();
        assert_eq!(h.c.unannounced, 701);
    }

    // ---------------------------------------------------------------------------------------- collecting a body

    #[test]
    fn a_stream_that_collects_has_its_credit_as_the_body_comes() {
        // (a stream window of 1000 and a connection window of 65535: halves are 500 and 32767)
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], false).unwrap();
        assert!(matches!(h.c.poll_stream(id, &mut []), StreamEvent::Head(_)));
        h.c.collect_stream(id, u64::MAX);
        let mut body = Vec::new();
        assert_eq!(h.c.collected(id, &mut body), Collected::Pending(1)); // (the head, and no body)
        let mut sent = Vec::new();
        for round in 0..30u8 {
            // 900 of the window of 1000 at a time: more than half, so the stream is given it back at once
            let chunk = vec![round; 900];
            h.data(id, &chunk, false).unwrap();
            sent.extend(chunk);
            h.c.assert_books();
            let out = h.take();
            assert_eq!(out.iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, id, 900)], "round {round}");
            assert_eq!(h.c.collected(id, &mut body), Collected::Pending(sent.len() as u64 + 1));
        }
        // 27000 bytes have come and nobody has read any: the connection has been given back what is past half of its window
        assert!(h.c.unannounced < 32_767);
        h.data(id, b"end", true).unwrap();
        sent.extend(b"end");
        assert_eq!(h.c.collected(id, &mut body), Collected::Done(None));
        assert_eq!(body, sent);
        h.c.assert_books();
        // and nothing is left in the stream
        assert_eq!(h.c.collected(id, &mut body), Collected::Done(None));
        h.c.release_stream(id);
        h.c.assert_books();
    }

    #[test]
    fn collecting_takes_what_is_unread_first_and_credits_it() {
        // (a stream window of 1000, so the stream is given credit back when 500 are to be)
        let mut h = Harness::with(small_windows());
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[("content-length", "1000")], false).unwrap();
        h.data(id, &pattern(1000)[..400], false).unwrap();
        let mut buf = [0u8; 100];
        assert!(matches!(h.c.poll_stream(id, &mut buf), StreamEvent::Head(_)));
        assert_eq!(h.c.poll_stream(id, &mut buf), StreamEvent::Data(100));
        assert!(h.take().is_empty());
        // 300 are unread: they are the start of what is collected, and as good as read: with the 100 that were, the stream
        // has 400 to be given back, which is not half yet
        h.c.collect_stream(id, u64::MAX);
        h.c.assert_books();
        assert!(h.take().is_empty());
        assert_eq!(h.c.streams[&id].unannounced, 400);
        let mut body = vec![9u8; 5];
        assert_eq!(h.c.collected(id, &mut body), Collected::Pending(401));
        // 300 more come, and are as good as read at once: 700 are given back
        h.data(id, &pattern(1000)[400..700], false).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::WINDOW_UPDATE, id, 700)]);
        h.data(id, &pattern(1000)[700..], true).unwrap();
        assert_eq!(h.c.collected(id, &mut body), Collected::Done(None));
        assert_eq!(body, &pattern(1000)[100..], "what was read is not in it, the rest is, whole");
        h.c.assert_books();
    }

    #[test]
    fn a_stream_that_collects_makes_room_for_the_length_it_was_told() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[("content-length", "5000")], false).unwrap();
        h.c.collect_stream(id, u64::MAX);
        assert!(h.c.streams[&id].body.capacity() >= 5000);
        // collecting began before the head came: the room is made when it does
        let id = h.open("GET", "/");
        h.take();
        h.c.collect_stream(id, 8000);
        assert_eq!(h.c.streams[&id].body.capacity(), 0);
        h.respond(id, "200", &[("content-length", "6000")], false).unwrap();
        assert!(h.c.streams[&id].body.capacity() >= 6000);
        let mut body = Vec::new();
        assert_eq!(h.c.collected(id, &mut body), Collected::Pending(1));
        assert_eq!(h.c.streams[&id].head.is_some(), true, "the head is for whoever collects");
    }

    #[test]
    fn a_response_that_says_it_is_more_than_the_limit_loses_its_stream_at_its_head() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        // the head comes after collecting began
        h.c.collect_stream(a, 3000);
        h.respond(a, "200", &[("content-length", "9000")], false).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, a, ErrorCode::CANCEL.0)]);
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(a, &mut body), Collected::Failed { error, got_head: true } if error.reason == BODY_TOO_BIG));
        // the head comes before
        h.respond(b, "200", &[("content-length", "9000")], false).unwrap();
        h.c.collect_stream(b, 3000);
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, b, ErrorCode::CANCEL.0)]);
        assert!(matches!(h.c.collected(b, &mut body), Collected::Failed { error, .. } if error.reason == BODY_TOO_BIG));
        // a response to HEAD says what a GET would have: it has no body, and is not too big
        let c = h.open("HEAD", "/c");
        h.take();
        h.c.collect_stream(c, 3000);
        h.respond(c, "200", &[("content-length", "9000")], true).unwrap();
        assert!(matches!(h.c.collected(c, &mut body), Collected::Done(Some(_))));
        assert!(h.c.error().is_none());
        h.c.assert_books();
    }

    #[test]
    fn a_collected_body_past_its_limit_loses_its_stream_and_nothing_else() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        h.respond(a, "200", &[], false).unwrap();
        h.respond(b, "200", &[], false).unwrap();
        h.c.collect_stream(a, 1000);
        let mut body = Vec::new();
        h.data(a, &pattern(600), false).unwrap();
        assert_eq!(h.c.collected(a, &mut body), Collected::Pending(601));
        // the frame that takes it past the limit is refused as it begins, and what it brings is thrown away
        let wire = raw(kind::DATA, 0, a, &pattern(600));
        feed_in_pieces(&mut h, &wire[..HEADER_LEN + 10], 4).unwrap();
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, a, ErrorCode::CANCEL.0)]);
        feed_in_pieces(&mut h, &wire[HEADER_LEN + 10..], 100).unwrap();
        match h.c.collected(a, &mut body) {
            Collected::Failed { error, got_head } => assert_eq!((error.reason.as_str(), got_head), (BODY_TOO_BIG, true)),
            other => panic!("{other:?}"),
        }
        h.c.assert_books();
        // the other stream and the connection are as they were
        h.data(b, b"fine", true).unwrap();
        assert_eq!(h.got(b).body, b"fine");
        assert!(h.c.error().is_none());
        // (a limit that is already passed when collecting begins)
        let c = h.open("GET", "/c");
        h.take();
        h.respond(c, "200", &[], false).unwrap();
        h.data(c, &pattern(300), false).unwrap();
        h.c.collect_stream(c, 200);
        assert!(matches!(h.c.collected(c, &mut body), Collected::Failed { .. }));
        h.c.assert_books();
    }

    #[test]
    fn collecting_begun_in_the_middle_of_a_data_frame_counts_the_rest_of_it() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        h.respond(a, "200", &[], false).unwrap();
        h.respond(b, "200", &[], false).unwrap();
        // a frame of 600 bytes, of which 100 have come when collecting begins with a limit of 400: the stream is lost at once,
        // and the rest of the frame is thrown away
        let wire = raw(kind::DATA, 0, a, &pattern(600));
        feed_in_pieces(&mut h, &wire[..HEADER_LEN + 100], 50).unwrap();
        h.c.collect_stream(a, 400);
        assert_eq!(h.take().iter().map(|f| (f.kind, f.stream, f.number())).collect::<Vec<_>>(), vec![(kind::RST_STREAM, a, ErrorCode::CANCEL.0)]);
        feed_in_pieces(&mut h, &wire[HEADER_LEN + 100..], 100).unwrap();
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(a, &mut body), Collected::Failed { error, .. } if error.reason == BODY_TOO_BIG));
        h.c.assert_books();
        // with a limit the whole frame fits in, it is collected whole
        let wire = raw(kind::DATA, flag::END_STREAM, b, &pattern(600));
        feed_in_pieces(&mut h, &wire[..HEADER_LEN + 100], 50).unwrap();
        h.c.collect_stream(b, 600);
        feed_in_pieces(&mut h, &wire[HEADER_LEN + 100..], 100).unwrap();
        assert!(matches!(h.c.collected(b, &mut body), Collected::Done(_)));
        assert_eq!(body, pattern(600));
        assert!(h.c.error().is_none());
        h.c.assert_books();
    }

    #[test]
    fn a_stream_that_collects_is_news_only_when_it_is_done_or_has_failed() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        h.respond(a, "200", &[], false).unwrap();
        h.respond(b, "200", &[], false).unwrap();
        h.c.collect_stream(a, u64::MAX);
        let mut news = News::default();
        h.c.take_news(&mut news);
        // a's frames, some of them cut off: no news. b's are news, as they always were
        let wire = raw(kind::DATA, 0, a, &pattern(2000));
        h.c.feed(&wire[..HEADER_LEN + 500]).unwrap();
        h.c.feed(&wire[HEADER_LEN + 500..]).unwrap();
        h.c.feed(&raw(kind::DATA, 0, b, b"x")).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[b]);
        // the end of a is news
        h.c.feed(&raw(kind::DATA, flag::END_STREAM, a, b"last")).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[a]);
        // and so is a failure
        let c = h.open("GET", "/c");
        h.take();
        h.respond(c, "200", &[], false).unwrap();
        h.c.collect_stream(c, u64::MAX);
        h.c.take_news(&mut news);
        h.c.feed(&raw(kind::RST_STREAM, 0, c, &ErrorCode::CANCEL.0.to_be_bytes())).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[c]);
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(c, &mut body), Collected::Failed { .. }));
    }

    #[test]
    fn a_stream_that_collects_is_not_woken_for_its_head() {
        let mut h = Harness::new();
        let (a, b) = (h.open("GET", "/a"), h.open("GET", "/b"));
        h.take();
        h.c.collect_stream(a, u64::MAX);
        let mut news = News::default();
        h.c.take_news(&mut news);
        // an interim response and the head, in pieces, and a stream that does not collect for comparison
        h.send_fields(a, &[(":status", "103"), ("link", "x")], false).unwrap();
        h.respond(a, "200", &[("content-length", "4")], false).unwrap();
        h.respond(b, "200", &[], false).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[b], "the head of a stream that does not collect is news");
        // the whole of the response, in a head with its end, is news at once
        let c = h.open("GET", "/c");
        h.take();
        h.c.collect_stream(c, u64::MAX);
        h.respond(c, "204", &[], true).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[c]);
        // and the end of a, with a trailer, after the body
        h.data(a, b"body", false).unwrap();
        h.c.take_news(&mut news);
        assert!(news.streams().is_empty(), "{:?}", news.streams());
        h.send_fields(a, &[("x-sum", "1")], true).unwrap();
        h.c.take_news(&mut news);
        assert_eq!(news.streams(), &[a]);
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(a, &mut body), Collected::Done(Some(_))));
        assert_eq!(body, b"body");
    }

    #[test]
    fn a_connection_lost_while_a_body_is_collected_fails_it_and_frees_what_it_held() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[("content-length", "100000")], false).unwrap();
        h.c.collect_stream(id, u64::MAX);
        h.data(id, &pattern(5000), false).unwrap();
        h.c.peer_closed();
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(id, &mut body), Collected::Failed { .. }));
        assert!(h.c.streams[&id].body.capacity() < 100_000, "the room made for a body that will not come is given up");
        h.c.release_stream(id);
        assert_eq!(h.c.active_streams(), 0);
    }

    #[test]
    fn a_stream_that_does_not_collect_is_not_collected() {
        let mut h = Harness::new();
        let id = h.open("GET", "/");
        h.take();
        h.respond(id, "200", &[], true).unwrap();
        let mut body = Vec::new();
        assert!(matches!(h.c.collected(id, &mut body), Collected::Failed { .. }));
        assert!(matches!(h.c.collected(99, &mut body), Collected::Failed { .. }));
        // (and collecting twice does no harm)
        h.c.collect_stream(id, 10);
        h.c.collect_stream(id, 10);
        // (the head, which nobody has taken, is with it)
        assert!(matches!(h.c.collected(id, &mut body), Collected::Done(Some(_))));
        assert!(body.is_empty());
    }

    // ---------------------------------------------------------------------------------------- whatever the wire brings

    #[test]
    fn feeding_a_byte_at_a_time_changes_nothing() {
        let build = || {
            let mut h = Harness::new();
            let ids: Vec<u32> = (0..4).map(|i| if i == 3 { h.open_with("POST", "/up", &[], false) } else { h.open("GET", "/") }).collect();
            h.take();
            (h, ids)
        };
        let (mut a, ids) = build();
        let (mut b, _) = build();
        // the server's side of it, from a throwaway harness whose encoder produces the blocks
        let mut srv = Harness::new();
        let mut wire = Vec::new();
        let mut add = |bytes: Vec<u8>| wire.extend(bytes);
        let long = "x".repeat(5000);
        for (i, &id) in ids.iter().enumerate() {
            let block = srv.block(&[(":status", "200"), ("x-n", &i.to_string()), ("x-long", &long), ("content-length", "3000")]);
            // the block in frames of 100 bytes
            let mut pieces = block.chunks(100).peekable();
            let mut first = true;
            while let Some(piece) = pieces.next() {
                let end = if pieces.peek().is_none() { flag::END_HEADERS } else { 0 };
                add(raw(if first { kind::HEADERS } else { kind::CONTINUATION }, end, id, piece));
                first = false;
            }
        }
        add(raw(kind::PING, 0, 0, b"12345678"));
        add(raw(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 9]));
        for round in 0..3 {
            for &id in &ids {
                add(raw(kind::DATA, 0, id, &[round as u8; 1000]));
            }
        }
        add(raw(kind::WINDOW_UPDATE, 0, 7 - 4, &[0, 0, 1, 0]));
        add(raw(kind::RST_STREAM, 0, ids[1], &ErrorCode::CANCEL.0.to_be_bytes()));
        add(raw(kind::GOAWAY, 0, 0, &[0, 0, 0, 5, 0, 0, 0, 0]));
        a.feed(&wire).unwrap();
        for byte in &wire {
            b.feed(&[*byte]).unwrap();
        }
        assert_eq!(a.take(), b.take());
        for &id in &ids {
            let (ga, gb) = (a.got(id), b.got(id));
            assert_eq!(ga, gb, "stream {id}");
        }
        assert_eq!(a.take(), b.take());
        assert_eq!(a.c.recv_window, b.c.recv_window);
        assert_eq!(a.c.unannounced, b.c.unannounced);
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len() as u64) as usize]
        }
    }

    fn padded(rng: &mut Rng, body: &[u8]) -> Vec<u8> {
        let pad = rng.below(10) as usize;
        let mut out = vec![pad as u8];
        out.extend_from_slice(body);
        out.extend(std::iter::repeat(0).take(pad));
        out
    }

    /// A frame the server might send, well formed or not, for a stream that is probably one of `ids`.
    fn random_frame(rng: &mut Rng, h: &mut Harness, ids: &[u32]) -> Vec<u8> {
        let stream = if ids.is_empty() || rng.below(10) == 0 { rng.below(10) as u32 } else { rng.pick(ids) };
        match rng.below(16) {
            0..=2 => {
                let status = rng.pick(&["200", "200", "204", "304", "404", "100", "103", "101", "20x"]);
                let mut owned: Vec<(String, String)> = vec![(":status".into(), status.into())];
                if rng.below(3) == 0 {
                    owned.push(("content-length".into(), rng.pick(&["0", "5", "300", "x"]).into()));
                }
                if rng.below(3) == 0 {
                    owned.push(("x-v".into(), "value".repeat(rng.below(5) as usize + 1)));
                }
                if rng.below(12) == 0 {
                    owned.push(("connection".into(), "close".into()));
                }
                let pairs: Vec<(&str, &str)> = owned.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
                let block = h.block(&pairs);
                let mut flags = 0;
                if rng.below(6) != 0 {
                    flags |= flag::END_HEADERS;
                }
                if rng.below(3) == 0 {
                    flags |= flag::END_STREAM;
                }
                let payload = if rng.below(6) == 0 {
                    flags |= flag::PADDED;
                    padded(rng, &block)
                } else {
                    block
                };
                raw(kind::HEADERS, flags, stream, &payload)
            }
            3..=6 => {
                let len = if rng.below(4) == 0 { 0 } else { rng.below(3000) as usize };
                let mut flags = 0;
                if rng.below(6) == 0 {
                    flags |= flag::END_STREAM;
                }
                let body = vec![0xab; len];
                let payload = if rng.below(6) == 0 {
                    flags |= flag::PADDED;
                    padded(rng, &body)
                } else {
                    body
                };
                raw(kind::DATA, flags, stream, &payload)
            }
            7 => raw(kind::RST_STREAM, 0, stream, &(rng.below(15) as u32).to_be_bytes()),
            8 => {
                let stream = if rng.below(3) == 0 { 0 } else { stream };
                raw(kind::WINDOW_UPDATE, 0, stream, &rng.pick(&[1u32, 100, 65_535, 0, 0x7fff_ffff]).to_be_bytes())
            }
            9 => raw(kind::PING, rng.pick(&[0, 0, flag::ACK]), 0, &[0; 8]),
            10 => {
                if rng.below(5) == 0 {
                    return raw(kind::SETTINGS, flag::ACK, 0, &[]);
                }
                let mut payload = Vec::new();
                for _ in 0..rng.below(4) {
                    let (id, value) = match rng.below(5) {
                        0 => (setting::MAX_CONCURRENT_STREAMS, rng.below(100) as u32),
                        1 => (setting::INITIAL_WINDOW_SIZE, rng.below(200_000) as u32),
                        2 => (setting::MAX_FRAME_SIZE, 16_384 + rng.below(24_000) as u32),
                        3 => (setting::HEADER_TABLE_SIZE, rng.below(4097) as u32),
                        _ => (0x99, 1),
                    };
                    payload.extend_from_slice(&id.to_be_bytes());
                    payload.extend_from_slice(&value.to_be_bytes());
                }
                // the identifiers are 16 bits: drop the top two bytes of what to_be_bytes gave
                let mut fixed = Vec::new();
                for c in payload.chunks(8) {
                    fixed.extend_from_slice(&c[2..]);
                }
                raw(kind::SETTINGS, 0, 0, &fixed)
            }
            11 => {
                let (last, code) = if rng.below(3) == 0 { (rng.below(8) as u32, rng.pick(&[0u32, 0, 2, 11])) } else { return raw(kind::PING, 0, 0, &[1; 8]) };
                let mut payload = last.to_be_bytes().to_vec();
                payload.extend_from_slice(&code.to_be_bytes());
                raw(kind::GOAWAY, 0, 0, &payload)
            }
            12 => raw(kind::CONTINUATION, if rng.below(2) == 0 { flag::END_HEADERS } else { 0 }, stream, &[0x88, 0x40, 0x01, b'a', 0x01, b'b']),
            13 => {
                if rng.below(4) == 0 {
                    raw(kind::PUSH_PROMISE, flag::END_HEADERS, stream, &[0, 0, 0, 2, 0x88])
                } else {
                    raw(kind::PRIORITY, 0, stream, &[0; 5])
                }
            }
            14 => raw(0x20 + rng.below(100) as u8, rng.below(256) as u8, stream, &vec![1; rng.below(20) as usize]),
            _ => (0..rng.below(30)).map(|_| rng.below(256) as u8).collect(),
        }
    }

    /// DATA that fits the windows.
    fn polite_data(rng: &mut Rng, h: &mut Harness, stream: u32) -> Vec<u8> {
        let conn = h.c.recv_window;
        let room = h.c.streams.get(&stream).map_or(conn, |s| s.recv_window.min(conn)).clamp(0, 3000) as u64;
        let padded_frame = rng.below(8) == 0 && room > 12;
        let len = if padded_frame { rng.below(room - 11) as usize } else { rng.below(room + 1) as usize };
        let mut flags = if rng.below(8) == 0 { flag::END_STREAM } else { 0 };
        let body = vec![0xcd; len];
        let payload = if padded_frame {
            flags |= flag::PADDED;
            padded(rng, &body)
        } else {
            body
        };
        raw(kind::DATA, flags, stream, &payload)
    }

    /// A frame a server that behaves might send: about streams that exist, and within the windows. (Now and then it
    /// still gets a response wrong, as a server can.)
    fn polite_frame(rng: &mut Rng, h: &mut Harness, known: &[u32]) -> Vec<u8> {
        if known.is_empty() {
            return raw(kind::PING, 0, 0, &[3; 8]);
        }
        let stream = rng.pick(known);
        // where the exchange on that stream is: the head still to come, the body going, or over (or the stream gone)
        let state = h.c.streams.get(&stream).map(|s| (s.got_head, s.remote_ended || s.failure.is_some()));
        match (rng.below(12), state) {
            (0..=2, Some((true, false))) => {
                if rng.below(6) == 0 {
                    // trailers
                    let block = h.block(&[("x-trailer", "t")]);
                    raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, stream, &block)
                } else {
                    polite_data(rng, h, stream)
                }
            }
            (0..=2, Some((false, false)) | None | Some((_, true))) => {
                let status = rng.pick(&["200", "200", "200", "204", "304", "404", "100", "103"]);
                let mut owned: Vec<(String, String)> = vec![(":status".into(), status.into())];
                if rng.below(10) == 0 {
                    owned.push(("content-length".into(), rng.pick(&["0", "5", "300"]).into()));
                }
                if rng.below(3) == 0 {
                    owned.push(("x-v".into(), "value".repeat(rng.below(5) as usize + 1)));
                }
                let pairs: Vec<(&str, &str)> = owned.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
                let block = h.block(&pairs);
                let flags = flag::END_HEADERS | if rng.below(6) == 0 { flag::END_STREAM } else { 0 };
                raw(kind::HEADERS, flags, stream, &block)
            }
            (3..=7, Some((true, false)) | None) => polite_data(rng, h, stream),
            (8, _) => {
                if rng.below(8) == 0 {
                    raw(kind::RST_STREAM, 0, stream, &ErrorCode::CANCEL.0.to_be_bytes())
                } else {
                    raw(kind::PING, 0, 0, &[4; 8])
                }
            }
            (9 | 10, _) => {
                let stream = if rng.below(2) == 0 { 0 } else { stream };
                raw(kind::WINDOW_UPDATE, 0, stream, &(rng.below(70_000) as u32 + 1).to_be_bytes())
            }
            (11, _) => {
                if rng.below(30) == 0 {
                    let mut payload = rng.pick(known).to_be_bytes().to_vec();
                    payload.extend_from_slice(&0u32.to_be_bytes());
                    raw(kind::GOAWAY, 0, 0, &payload)
                } else {
                    raw(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, rng.below(50) as u8 + 1])
                }
            }
            _ => raw(kind::PING, 0, 0, &[5; 8]),
        }
    }

    /// Every frame the client wrote must be one a peer would accept.
    fn check_output(h: &mut Harness) {
        for f in h.take() {
            let header = Header { length: f.payload.len() as u32, kind: f.kind, flags: f.flags, stream: f.stream };
            if let Err(e) = frame::parse(&header, &f.payload) {
                panic!("the client wrote a frame that does not parse ({e}): {f:?}");
            }
            assert!(f.payload.len() <= 40_000 || f.kind == kind::GOAWAY, "a frame of {} bytes", f.payload.len());
        }
    }

    /// What the fuzzing got to see, so that it is known not to have been idle.
    #[derive(Default, Debug)]
    struct Seen {
        heads: usize,
        body_bytes: usize,
        ends: usize,
        failures: usize,
        lost_connections: usize,
        sent_bytes: usize,
    }

    fn fuzz_session(seed: u64, steps: usize, seen: &mut Seen) {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let config = match rng.below(3) {
            0 => Config::default(),
            1 => Config { stream_window: 3000, connection_window: 65_535, max_header_list: 4096 },
            _ => Config { stream_window: 70_000, connection_window: 200_000, max_header_list: 64 << 10 },
        };
        let mut h = Harness::with(config);
        // most sessions have a server that behaves, so that they get somewhere; some have one that does not
        let polite = seed % 4 != 0;
        let mut ids: Vec<u32> = Vec::new();
        let mut known: Vec<u32> = Vec::new();
        let mut lost = None;
        for step in 0..steps {
            match rng.below(12) {
                0..=4 => {
                    let mut wire = Vec::new();
                    for _ in 0..rng.below(3) + 1 {
                        wire.extend(if polite && rng.below(100) != 0 { polite_frame(&mut rng, &mut h, &known) } else { random_frame(&mut rng, &mut h, &known) });
                    }
                    // in pieces of whatever size
                    let mut rest = &wire[..];
                    while !rest.is_empty() {
                        let n = (rng.below(40) as usize + 1).min(rest.len());
                        if let Err(e) = h.feed(&rest[..n]) {
                            lost.get_or_insert(e);
                        }
                        rest = &rest[n..];
                    }
                }
                5 | 6 => {
                    let method = rng.pick(&["GET", "POST", "HEAD"]);
                    let end = method != "POST" || rng.below(3) == 0;
                    let headers = vec![("x-n".to_string(), step.to_string())];
                    if let Ok(id) = h.c.open_stream(&Request { method, scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] }, end) {
                        ids.push(id);
                        known.push(id);
                    }
                }
                7 => {
                    if !ids.is_empty() {
                        let id = rng.pick(&ids);
                        let data = vec![5u8; rng.below(30_000) as usize];
                        let _ = h.c.send_data(id, &data, rng.below(3) == 0);
                    }
                }
                8 | 9 => {
                    if !ids.is_empty() {
                        let id = rng.pick(&ids);
                        let size = rng.pick(&[1usize, 7, 100, 5000, 70_000]);
                        let got = h.got_with(id, size);
                        seen.heads += got.head.is_some() as usize;
                        seen.body_bytes += got.body.len();
                        seen.ends += got.ended as usize;
                        seen.failures += got.failed.is_some() as usize;
                    }
                }
                10 => {
                    if !ids.is_empty() {
                        let i = rng.below(ids.len() as u64) as usize;
                        h.c.release_stream(ids.swap_remove(i));
                    }
                }
                _ => check_output(&mut h),
            }
            check_windows(&h.c);
            if h.c.error().is_some() {
                // a lost connection stays lost
                assert!(!h.c.usable());
                if let Some(first) = &lost {
                    assert_eq!(h.c.process().unwrap_err().code, first.code);
                }
            }
        }
        seen.lost_connections += h.c.error().is_some() as usize;
        seen.sent_bytes += h.all.iter().filter(|f| f.kind == kind::DATA).map(|f| f.payload.len()).sum::<usize>();
        check_output(&mut h);
    }

    #[test]
    fn whatever_the_server_sends_the_books_balance_and_nothing_panics() {
        let mut seen = Seen::default();
        for seed in 1..=400 {
            fuzz_session(seed, 300, &mut seen);
        }
        // the fuzzing got somewhere: responses came, were read to the end, and streams and connections were lost
        assert!(seen.heads > 500 && seen.body_bytes > 100_000 && seen.ends > 100, "{seen:?}");
        assert!(seen.failures > 100 && seen.lost_connections > 20 && seen.lost_connections < 380, "{seen:?}");
        assert!(seen.sent_bytes > 100_000, "{seen:?}");
    }

    #[test]
    fn garbage_on_the_wire_never_panics() {
        for seed in 1..=300u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
            let mut h = if seed % 2 == 0 { Harness::new() } else { Harness::unsettled(Config::default()) };
            h.open("GET", "/");
            for _ in 0..100 {
                let n = rng.below(60) as usize;
                // runs of plausible frame headers and runs of noise
                let chunk: Vec<u8> = if rng.below(2) == 0 {
                    (0..n).map(|_| rng.below(256) as u8).collect()
                } else {
                    let mut c = Vec::new();
                    Header { length: rng.below(40) as u32, kind: rng.below(11) as u8, flags: rng.below(256) as u8, stream: rng.below(6) as u32 }.write(&mut c);
                    c.extend((0..rng.below(40)).map(|_| rng.below(256) as u8));
                    c
                };
                let _ = h.feed(&chunk);
                check_windows(&h.c);
            }
            h.take();
        }
    }
}
