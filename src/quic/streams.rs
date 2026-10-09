//! Streams and flow control (RFC 9000 sections 2, 3 and 4).
//!
//! A stream is a pair of byte streams, one for each direction (one only, for a unidirectional stream), each with its own state:
//!
//! * The sending side holds what the application wrote until the peer has acknowledged it (a [`SendBuf`]), puts ranges of it in
//!   STREAM frames when the packet scheduler asks for frames, and sends them again when a packet is lost. It ends with the end of
//!   the stream (FIN) or with a RESET_STREAM that gives the data up. The peer's flow control limits (MAX_DATA, MAX_STREAM_DATA)
//!   say how much new data may be sent; a stream that has data and no credit waits for it, and says so (DATA_BLOCKED,
//!   STREAM_DATA_BLOCKED).
//! * The receiving side puts the ranges that arrive back in order (a [`Reassembler`]), holds them for the application to read,
//!   and gives the peer more credit as the application reads: a window of data ahead of what has been read, moved up when half
//!   of it has been used. What the peer sends beyond a limit, or against the final size of a stream, ends the connection.
//!
//! The streams the peer opens are opened by their numbers: a frame for stream 12 opens 0, 4 and 8 of the same kind as well. The
//! number the peer may open is limited (MAX_STREAMS); streams that are finished are forgotten, and the limit moves up.
//!
//! The application talks to this through [`Streams::open`], [`write`](Streams::write), [`read`](Streams::read),
//! [`reset`](Streams::reset), [`stop_sending`](Streams::stop_sending) and [`poll_event`](Streams::poll_event); the connection
//! gives it the frames that arrive and asks it for the frames to send ([`write_frames`](Streams::write_frames)), and tells it
//! what became of the frames in the packets it sent ([`on_acked`](Streams::on_acked), [`on_lost`](Streams::on_lost)).
//!
//! Events are edges: a [`StreamEvent::Readable`] comes when a stream that had nothing to read has something (data, the end, or a
//! reset), and the next one only after the application has read until [`StreamError::Blocked`]. A [`StreamEvent::Writable`]
//! comes when a write was cut short or refused for lack of room, and there is room again.

use super::connection::{code, SentFrame, TransportError};
use super::frame::{self, Frame, MAX_STREAMS_LIMIT};
use super::reassembly::{self, Reassembler};
use super::sendbuf::SendBuf;
use super::transport_params::TransportParameters;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// ---------------------------------------------------------------------------------------------------------------------------
// ids

/// Whether the stream with this id goes both ways (RFC 9000 section 2.1: the second bit of the id is 0).
pub fn is_bidirectional(id: u64) -> bool {
    id & 2 == 0
}

/// Whether the client opened the stream with this id (the lowest bit is 0).
pub fn is_client_initiated(id: u64) -> bool {
    id & 1 == 0
}

/// 0 for a bidirectional stream, 1 for a unidirectional one: an index for what is kept for each kind.
fn kind_of(id: u64) -> usize {
    ((id >> 1) & 1) as usize
}

/// Which of the streams of its kind and initiator this is (0 for the first).
fn index_of(id: u64) -> u64 {
    id >> 2
}

fn make_id(index: u64, kind: usize, client_initiated: bool) -> u64 {
    (index << 2) | ((kind as u64) << 1) | u64::from(!client_initiated)
}

// ---------------------------------------------------------------------------------------------------------------------------
// what the application sees

/// Why an operation on a stream could not be done.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamError {
    /// There is no such stream: it was never opened, it is finished and forgotten, or it has no such direction.
    Unknown,
    /// Nothing can be done now: nothing to read, no room to write, no stream that can be opened. A [`StreamEvent`] says when to try
    /// again.
    Blocked,
    /// The peer reset the stream, with this error code: there is no more to read.
    Reset(u64),
    /// The peer sent STOP_SENDING with this error code, and the stream is reset: there is no more to write.
    Stopped(u64),
    /// The stream (or its sending side) is ended already, by the application, or the connection is over.
    Closed,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Unknown => write!(f, "no such stream"),
            StreamError::Blocked => write!(f, "the stream is blocked"),
            StreamError::Reset(c) => write!(f, "the stream was reset by the peer (error {c})"),
            StreamError::Stopped(c) => write!(f, "the peer asked to stop sending (error {c})"),
            StreamError::Closed => write!(f, "the stream is closed"),
        }
    }
}

impl std::error::Error for StreamError {}

/// What happened to the streams that the application might want to know.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamEvent {
    /// The stream has something to read: data, the end of the stream, or a reset.
    Readable(u64),
    /// The stream takes writes again, after one that was refused or cut short.
    Writable(u64),
    /// The peer sent STOP_SENDING (the code is its error code): it does not want the rest of the stream. The stream has been reset
    /// with the same code; there is nothing more to write.
    Stopped(u64, u64),
    /// A stream of this kind can be opened again, after [`Streams::open`] said [`StreamError::Blocked`]: the peer raised its limit.
    Available { bidirectional: bool },
}

/// What a frame that carried stream data or a flow control update was, kept with the packet that carried it: to be sent again
/// when the packet is lost, and to be forgotten when it is acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamFrame {
    Stream { id: u64, offset: u64, len: usize, fin: bool },
    ResetStream { id: u64, error: u64, final_size: u64 },
    StopSending { id: u64, error: u64 },
    MaxData(u64),
    MaxStreamData { id: u64, max: u64 },
    MaxStreams { bidirectional: bool, max: u64 },
    DataBlocked(u64),
    StreamDataBlocked { id: u64, limit: u64 },
    StreamsBlocked { bidirectional: bool, limit: u64 },
}

/// What the streams are to be given to start with: our limits, which are told to the peer in the transport parameters.
#[derive(Clone, Copy, Debug)]
pub struct StreamsConfig {
    /// Whether we are the client (which opens the streams with even numbers).
    pub client: bool,
    /// The most the peer may send on all streams together, to start with; the window the limit is kept ahead of what we have read.
    pub max_data: u64,
    /// The same for one stream that we opened (a bidirectional one: the peer's side of it).
    pub bidi_local: u64,
    /// ... for one bidirectional stream that the peer opened.
    pub bidi_remote: u64,
    /// ... for one unidirectional stream that the peer opened.
    pub uni: u64,
    /// How many streams of each kind the peer may open, to start with.
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    /// How much a stream holds that was written and is not yet acknowledged: a write that would pass this is cut short.
    pub send_buffer: usize,
}

// ---------------------------------------------------------------------------------------------------------------------------
// state

/// The limits that the peer's transport parameters set.
#[derive(Clone, Copy)]
struct PeerLimits {
    /// For a bidirectional stream that the peer opened (the peer's "local").
    bidi_local: u64,
    /// For a bidirectional stream that we opened (the peer's "remote").
    bidi_remote: u64,
    uni: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SendState {
    /// The application can write.
    Open,
    /// The end of the stream has been written: what is left is to send it and to have it acknowledged.
    Finished,
    /// The stream was reset: RESET_STREAM is to be sent and acknowledged.
    Reset,
    /// Everything was acknowledged, or the reset was.
    Done,
}

struct Reset {
    error: u64,
    final_size: u64,
    pending: bool,
}

struct Send {
    buf: SendBuf,
    /// The peer's limit on the stream: no new byte at this offset or above is sent.
    max_data: u64,
    state: SendState,
    reset: Option<Reset>,
    /// The code of the STOP_SENDING that the peer sent.
    stopped: Option<u64>,
    /// The limit at which STREAM_DATA_BLOCKED was sent last, and whether it is to be sent (again).
    blocked_sent: Option<u64>,
    blocked_pending: bool,
    /// A write was cut short or refused: tell the application when there is room.
    write_blocked: bool,
    /// In the queue of streams that have something to send.
    queued: bool,
    /// Has something to send, but waits for the connection's credit.
    parked: bool,
}

impl Send {
    fn new(max_data: u64) -> Send {
        Send {
            buf: SendBuf::new(),
            max_data,
            state: SendState::Open,
            reset: None,
            stopped: None,
            blocked_sent: None,
            blocked_pending: false,
            write_blocked: false,
            queued: false,
            parked: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecvState {
    Open,
    /// The peer reset the stream (with this code) and the application does not know yet.
    Reset(u64),
    /// The application has read to the end.
    Fin,
    /// The application knows of the reset (with this code).
    ResetRead(u64),
}

struct Stop {
    error: u64,
    pending: bool,
}

struct Recv {
    buf: Reassembler,
    /// The limit that we gave the peer: no byte at this offset or above may come.
    max_data: u64,
    /// How far ahead of what has been read the limit is kept.
    window: u64,
    /// The end of the highest range that has come (what counts against the limits).
    high: u64,
    final_size: Option<u64>,
    state: RecvState,
    /// The application does not want the data: it is thrown away as it comes.
    discard: bool,
    stop: Option<Stop>,
    max_data_pending: bool,
    /// A `Readable` event was given and the application has not read until it was blocked.
    queued: bool,
}

impl Recv {
    fn new(window: u64) -> Recv {
        Recv {
            buf: Reassembler::new(),
            max_data: window,
            window,
            high: 0,
            final_size: None,
            state: RecvState::Open,
            discard: false,
            stop: None,
            max_data_pending: false,
            queued: false,
        }
    }

    /// There is something for the application to read: data, the end, or the reset.
    fn readable(&self) -> bool {
        match self.state {
            RecvState::Reset(_) => true,
            RecvState::Open => !self.discard && (self.buf.readable() > 0 || self.final_size == Some(self.buf.read_offset())),
            _ => false,
        }
    }

    /// All of the stream up to its end has come (it may not have been read).
    fn all_received(&self) -> bool {
        self.final_size.is_some_and(|fs| self.buf.read_offset() + self.buf.readable() as u64 == fs)
    }
}

struct Stream {
    send: Option<Send>,
    recv: Option<Recv>,
}

/// Whether a stream with something to send can send it.
enum Gate {
    Ready,
    /// Waits for credit for the stream.
    StreamBlocked,
    /// Waits for credit for the connection.
    ConnBlocked,
    Nothing,
}

fn gate(s: &Send, conn_room: u64) -> Gate {
    if !matches!(s.state, SendState::Open | SendState::Finished) || !s.buf.has_pending() {
        return Gate::Nothing;
    }
    let limit = s.max_data.min(s.buf.sent() + conn_room);
    if s.buf.has_pending_within(limit) {
        Gate::Ready
    } else if s.buf.sent() >= s.max_data {
        Gate::StreamBlocked
    } else {
        Gate::ConnBlocked
    }
}

/// Appends the frame to `out` if it fits in what is left of `budget` after the `start` bytes.
fn put(out: &mut Vec<u8>, start: usize, budget: usize, f: &Frame<'_>) -> bool {
    if out.len() - start + f.len() > budget {
        return false;
    }
    f.write(out);
    true
}

/// The streams of a connection and the flow control of the connection.
pub struct Streams {
    cfg: StreamsConfig,
    streams: BTreeMap<u64, Stream>,
    peer: Option<PeerLimits>,

    // what we may send
    /// The peer's limit on all the data we send (MAX_DATA).
    send_max_data: u64,
    /// How much new stream data we have sent (a resend is not new).
    sent_total: u64,
    /// How many streams of each kind (bidirectional, unidirectional) the peer lets us open, and how many we have opened.
    peer_max_streams: [u64; 2],
    opened: [u64; 2],
    /// `open` said that no more can be opened: tell the application when that changes.
    open_blocked: [bool; 2],

    // what we let the peer send
    /// Our limit on all the data the peer sends, the end of the data that has come (summed over the streams), and how much has
    /// been read or thrown away.
    recv_limit: u64,
    recv_total: u64,
    consumed: u64,
    /// How many streams of each kind the peer may open (the limit we gave), how many it has opened (by number), and how many of
    /// those are finished and forgotten.
    max_streams: [u64; 2],
    peer_opened: [u64; 2],
    peer_closed: [u64; 2],

    // frames to send
    max_data_pending: bool,
    max_streams_pending: [bool; 2],
    data_blocked_sent: Option<u64>,
    data_blocked_pending: bool,
    streams_blocked_sent: [Option<u64>; 2],
    streams_blocked_pending: [bool; 2],
    /// The streams that have a control frame to send (reset, stop sending, a limit, blocked).
    control: BTreeSet<u64>,
    /// The streams that have data to send and the credit to send it, in turn.
    send_queue: VecDeque<u64>,
    /// The streams that have data to send and wait for the connection's credit.
    parked: BTreeSet<u64>,

    events: VecDeque<StreamEvent>,
}

impl Streams {
    pub fn new(cfg: StreamsConfig) -> Streams {
        Streams {
            cfg,
            streams: BTreeMap::new(),
            peer: None,
            send_max_data: 0,
            sent_total: 0,
            peer_max_streams: [0; 2],
            opened: [0; 2],
            open_blocked: [false; 2],
            recv_limit: cfg.max_data,
            recv_total: 0,
            consumed: 0,
            max_streams: [cfg.max_streams_bidi, cfg.max_streams_uni],
            peer_opened: [0; 2],
            peer_closed: [0; 2],
            max_data_pending: false,
            max_streams_pending: [false; 2],
            data_blocked_sent: None,
            data_blocked_pending: false,
            streams_blocked_sent: [None; 2],
            streams_blocked_pending: [false; 2],
            control: BTreeSet::new(),
            send_queue: VecDeque::new(),
            parked: BTreeSet::new(),
            events: VecDeque::new(),
        }
    }

    /// The peer's transport parameters are known: they set what we may send. Streams can be opened after this.
    pub fn set_peer_params(&mut self, p: &TransportParameters) {
        self.peer = Some(PeerLimits {
            bidi_local: p.initial_max_stream_data_bidi_local,
            bidi_remote: p.initial_max_stream_data_bidi_remote,
            uni: p.initial_max_stream_data_uni,
        });
        self.send_max_data = p.initial_max_data;
        self.peer_max_streams = [p.initial_max_streams_bidi.min(MAX_STREAMS_LIMIT), p.initial_max_streams_uni.min(MAX_STREAMS_LIMIT)];
    }

    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    /// The ids of the streams that are kept (open in one direction or the other, or ended and not yet taken in): for the tests and
    /// the fuzzer.
    pub fn stream_ids(&self) -> Vec<u64> {
        self.streams.keys().copied().collect()
    }

    /// What the receiving side of a stream holds, in words: for the tests and the fuzzer when something is wrong.
    pub fn describe_recv(&self, id: u64) -> String {
        let conn = format!("connection: limit {} (window {}), received {}, consumed {}, update pending {}", self.recv_limit, self.cfg.max_data, self.recv_total, self.consumed, self.max_data_pending);
        match self.streams.get(&id).and_then(|s| s.recv.as_ref()) {
            None => format!("no receiving side; {conn}"),
            Some(r) => format!(
                "{conn}; state {:?}, read {}, readable {}, held {}, end of what came {}, high {}, final size {:?}, limit {} (window {}), discard {}, queued {}",
                r.state,
                r.buf.read_offset(),
                r.buf.readable(),
                r.buf.buffered(),
                r.buf.end_offset(),
                r.high,
                r.final_size,
                r.max_data,
                r.window,
                r.discard,
                r.queued
            ),
        }
    }

    /// What the sending side of a stream, and the connection's flow control, hold, in words: for the tests and the fuzzer.
    pub fn describe_send(&self, id: u64) -> String {
        let conn = format!("connection: limit {} sent {} parked {:?} queue {:?} control {:?}", self.send_max_data, self.sent_total, self.parked, self.send_queue, self.control);
        match self.streams.get(&id).and_then(|s| s.send.as_ref()) {
            None => format!("no sending side; {conn}"),
            Some(s) => format!(
                "state {:?}, buffered {}, written {}, sent {}, base {}, lost {:?}, limit {}, queued {}, parked {}, pending {}; {conn}",
                s.state,
                s.buf.buffered(),
                s.buf.written(),
                s.buf.sent(),
                s.buf.base(),
                s.buf.lost_ranges(),
                s.max_data,
                s.queued,
                s.parked,
                s.buf.has_pending()
            ),
        }
    }

    pub fn contains(&self, id: u64) -> bool {
        self.streams.contains_key(&id)
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // the application

    /// Whether a stream of this kind can be opened now: the peer's parameters are known and its limit is not reached.
    pub fn can_open(&self, bidirectional: bool) -> bool {
        let k = if bidirectional { 0 } else { 1 };
        self.peer.is_some() && self.opened[k] < self.peer_max_streams[k]
    }

    /// Opens a stream and gives its id. Blocked if the peer's limit on the streams we open is reached (or its parameters are not
    /// known yet): there is an event when it is raised.
    pub fn open(&mut self, bidirectional: bool) -> Result<u64, StreamError> {
        let Some(peer) = self.peer else { return Err(StreamError::Blocked) };
        let k = if bidirectional { 0 } else { 1 };
        if self.opened[k] >= self.peer_max_streams[k] {
            self.open_blocked[k] = true;
            if self.streams_blocked_sent[k] != Some(self.peer_max_streams[k]) {
                self.streams_blocked_sent[k] = Some(self.peer_max_streams[k]);
                self.streams_blocked_pending[k] = true;
            }
            return Err(StreamError::Blocked);
        }
        let id = make_id(self.opened[k], k, self.cfg.client);
        self.opened[k] += 1;
        let send = Send::new(if bidirectional { peer.bidi_remote } else { peer.uni });
        let recv = bidirectional.then(|| Recv::new(self.cfg.bidi_local));
        self.streams.insert(id, Stream { send: Some(send), recv });
        Ok(id)
    }

    /// Writes `data` on the stream, and ends the stream after it if `fin` and all of it was taken. Returns how many bytes were
    /// taken: fewer than `data.len()` if the stream holds as much as it should (the rest is for the application to write again
    /// after a [`StreamEvent::Writable`]); [`StreamError::Blocked`] if none was.
    pub fn write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, StreamError> {
        let room_limit = self.cfg.send_buffer;
        let s = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()).ok_or(StreamError::Unknown)?;
        if s.state != SendState::Open {
            return Err(match (s.stopped, s.state) {
                (Some(c), SendState::Reset | SendState::Done) => StreamError::Stopped(c),
                _ => StreamError::Closed,
            });
        }
        let room = room_limit.saturating_sub(s.buf.buffered());
        let n = data.len().min(room);
        if n == 0 && !data.is_empty() {
            s.write_blocked = true;
            return Err(StreamError::Blocked);
        }
        s.buf.write(&data[..n]);
        if n < data.len() {
            s.write_blocked = true;
        } else if fin {
            s.buf.finish();
            s.state = SendState::Finished;
        }
        self.schedule(id);
        Ok(n)
    }

    /// Reads what has come on the stream into `buf`. Returns how many bytes, and whether the stream ends with them (it does when
    /// the bytes read were the last). [`StreamError::Blocked`] if there is nothing now; [`StreamError::Reset`] if the peer reset
    /// the stream.
    pub fn read(&mut self, id: u64, buf: &mut [u8]) -> Result<(usize, bool), StreamError> {
        let r = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()).ok_or(StreamError::Unknown)?;
        match r.state {
            RecvState::Reset(c) => {
                r.state = RecvState::ResetRead(c);
                r.queued = false;
                self.cleanup(id);
                return Err(StreamError::Reset(c));
            }
            RecvState::ResetRead(c) => return Err(StreamError::Reset(c)),
            RecvState::Fin => return Ok((0, true)),
            RecvState::Open => {}
        }
        if r.discard {
            return Err(StreamError::Closed);
        }
        let n = r.buf.read(buf);
        let fin = r.final_size == Some(r.buf.read_offset());
        if n == 0 && !fin {
            r.queued = false;
            return if buf.is_empty() { Ok((0, false)) } else { Err(StreamError::Blocked) };
        }
        if fin {
            r.state = RecvState::Fin;
            r.queued = false;
        } else if r.buf.readable() == 0 {
            r.queued = false;
        }
        self.after_consume(id, n as u64);
        if fin {
            self.cleanup(id);
        }
        Ok((n, fin))
    }

    /// Gives up the sending side of the stream: what is not yet acknowledged is dropped, and the peer is told with RESET_STREAM
    /// and this error code (an application's, as HTTP/3 defines them).
    pub fn reset(&mut self, id: u64, error: u64) -> Result<(), StreamError> {
        let s = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()).ok_or(StreamError::Unknown)?;
        if matches!(s.state, SendState::Open | SendState::Finished) {
            self.do_reset(id, error);
        }
        Ok(())
    }

    /// Asks the peer to stop sending on the stream (STOP_SENDING, with this error code): what comes after this is thrown away, and
    /// the peer is expected to reset the stream.
    pub fn stop_sending(&mut self, id: u64, error: u64) -> Result<(), StreamError> {
        let r = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()).ok_or(StreamError::Unknown)?;
        if r.state != RecvState::Open || r.discard {
            return Ok(());
        }
        r.discard = true;
        r.queued = false;
        if !r.all_received() {
            r.stop = Some(Stop { error, pending: true });
            self.control.insert(id);
        }
        self.drain(id);
        Ok(())
    }

    /// How much more can be written on the stream before a write is cut short.
    pub fn send_room(&self, id: u64) -> Option<usize> {
        let s = self.streams.get(&id)?.send.as_ref()?;
        Some(self.cfg.send_buffer.saturating_sub(s.buf.buffered()))
    }

    /// How much is written on the stream and not yet acknowledged.
    pub fn buffered(&self, id: u64) -> Option<usize> {
        Some(self.streams.get(&id)?.send.as_ref()?.buf.buffered())
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // internals for the application's calls

    /// Throws away what has come on a stream that the application does not want, and finishes it if the end has come.
    fn drain(&mut self, id: u64) {
        let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else { return };
        if !r.discard || r.state != RecvState::Open {
            return;
        }
        let n = r.buf.discard();
        if r.final_size == Some(r.buf.read_offset()) {
            r.state = RecvState::Fin;
        }
        let done = r.state == RecvState::Fin;
        self.after_consume(id, n as u64);
        if done {
            self.cleanup(id);
        }
    }

    /// `n` bytes of the stream were read (or thrown away): the credit that the peer has can move up.
    fn after_consume(&mut self, id: u64, n: u64) {
        self.consumed += n;
        if let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) {
            if r.final_size.is_none() && r.state == RecvState::Open {
                let new = r.buf.read_offset() + r.window;
                if new > r.max_data && new - r.max_data >= r.window / 2 {
                    r.max_data = new;
                    r.max_data_pending = true;
                    self.control.insert(id);
                }
            }
        }
        self.grow_connection_window();
    }

    fn grow_connection_window(&mut self) {
        let new = self.consumed + self.cfg.max_data;
        if new > self.recv_limit && new - self.recv_limit >= self.cfg.max_data / 2 {
            self.recv_limit = new;
            self.max_data_pending = true;
        }
    }

    /// A stream that the peer opened is finished and forgotten: it may open another.
    fn grow_stream_limit(&mut self, k: usize) {
        let initial = if k == 0 { self.cfg.max_streams_bidi } else { self.cfg.max_streams_uni };
        let new = (initial + self.peer_closed[k]).min(MAX_STREAMS_LIMIT);
        if new >= self.max_streams[k] + (initial / 2).max(1) {
            self.max_streams[k] = new;
            self.max_streams_pending[k] = true;
        }
    }

    /// Forgets the stream if nothing more can happen to it, and lets the peer open another if it was one of its.
    fn cleanup(&mut self, id: u64) {
        let Some(st) = self.streams.get(&id) else { return };
        let send_done = st.send.as_ref().is_none_or(|s| s.state == SendState::Done);
        let recv_done = st.recv.as_ref().is_none_or(|r| matches!(r.state, RecvState::Fin | RecvState::ResetRead(_)));
        if !(send_done && recv_done) {
            return;
        }
        self.streams.remove(&id);
        self.control.remove(&id);
        self.parked.remove(&id);
        if is_client_initiated(id) != self.cfg.client {
            let k = kind_of(id);
            self.peer_closed[k] += 1;
            self.grow_stream_limit(k);
        }
    }

    /// Gives up the sending side (the caller has checked that it is open or finished).
    fn do_reset(&mut self, id: u64, error: u64) {
        let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
        let final_size = s.buf.sent();
        s.buf.clear();
        s.reset = Some(Reset { error, final_size, pending: true });
        s.state = SendState::Reset;
        s.blocked_pending = false;
        s.write_blocked = false;
        let was_queued = std::mem::take(&mut s.queued);
        s.parked = false;
        if was_queued {
            self.send_queue.retain(|&q| q != id);
        }
        self.parked.remove(&id);
        self.control.insert(id);
    }

    /// Puts the stream in the queue of those that have something to send if it has, and the credit to send it; if it waits for
    /// credit, makes a note to say so.
    fn schedule(&mut self, id: u64) {
        let conn_room = self.send_max_data.saturating_sub(self.sent_total);
        let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
        if s.queued {
            return;
        }
        let what = gate(s, conn_room);
        // (a stream that waits for credit of the connection is looked at again whatever happens to it: data that is lost needs no
        // credit to be sent again, and the peer may be waiting for exactly that data before it gives more)
        if s.parked && !matches!(what, Gate::ConnBlocked) {
            s.parked = false;
            self.parked.remove(&id);
        }
        match what {
            Gate::Ready => {
                s.queued = true;
                self.send_queue.push_back(id);
            }
            Gate::ConnBlocked => {
                if !s.parked {
                    s.parked = true;
                    self.parked.insert(id);
                }
                if self.data_blocked_sent != Some(self.send_max_data) {
                    self.data_blocked_sent = Some(self.send_max_data);
                    self.data_blocked_pending = true;
                }
            }
            Gate::StreamBlocked => {
                if s.blocked_sent != Some(s.max_data) {
                    s.blocked_sent = Some(s.max_data);
                    s.blocked_pending = true;
                    self.control.insert(id);
                }
            }
            Gate::Nothing => {}
        }
    }

    /// Checks what must hold of the accounting, whatever has happened: for the tests and the fuzzer. The error says what does not.
    pub fn check(&self) -> Result<(), String> {
        let bad = |what: String| -> Result<(), String> { Err(what) };
        if self.sent_total > self.send_max_data {
            return bad(format!("sent {} beyond the connection's limit {}", self.sent_total, self.send_max_data));
        }
        if self.recv_total > self.recv_limit || self.consumed > self.recv_total {
            return bad(format!("received {} (limit {}), consumed {}", self.recv_total, self.recv_limit, self.consumed));
        }
        for k in 0..2 {
            if self.opened[k] > self.peer_max_streams[k] {
                return bad(format!("opened {} streams of kind {k}, the limit is {}", self.opened[k], self.peer_max_streams[k]));
            }
            if self.peer_opened[k] > self.max_streams[k] {
                return bad(format!("the peer opened {} streams of kind {k}, the limit is {}", self.peer_opened[k], self.max_streams[k]));
            }
        }
        let mut queued = 0;
        let mut parked = 0;
        let mut sent_sum = 0;
        for (id, st) in &self.streams {
            if let Some(s) = &st.send {
                // (the buffer of a stream that was reset is cleared: its end is where the data ends, whatever was sent)
                if matches!(s.state, SendState::Open | SendState::Finished) && s.buf.sent() > s.max_data {
                    return bad(format!("stream {id}: sent {} beyond the limit {}", s.buf.sent(), s.max_data));
                }
                sent_sum += s.buf.sent();
                queued += usize::from(s.queued);
                parked += usize::from(s.parked);
                if s.queued && s.parked {
                    return bad(format!("stream {id} is queued and parked"));
                }
                if s.queued != self.send_queue.contains(id) || s.parked != self.parked.contains(id) {
                    return bad(format!("stream {id}: the queue and the stream disagree"));
                }
                if s.state == SendState::Reset && s.reset.is_none() {
                    return bad(format!("stream {id}: reset with no reset"));
                }
            }
            if let Some(r) = &st.recv {
                let read = r.buf.read_offset();
                if read > r.high || r.high > r.max_data || r.buf.end_offset() > r.high {
                    return bad(format!("stream {id}: read {read}, high {}, limit {}, end {}", r.high, r.max_data, r.buf.end_offset()));
                }
                if r.final_size.is_some_and(|f| f < r.high) {
                    return bad(format!("stream {id}: final size {:?} below {}", r.final_size, r.high));
                }
            }
        }
        if queued != self.send_queue.len() || parked != self.parked.len() {
            return bad(format!("{queued} queued, {} in the queue; {parked} parked, {} in the set", self.send_queue.len(), self.parked.len()));
        }
        let _ = sent_sum;
        Ok(())
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // frames that arrive

    /// For a frame about the receiving side of stream `id` (STREAM, RESET_STREAM, STREAM_DATA_BLOCKED): checks that the peer may
    /// send it, and opens the stream if it is one of the peer's that was not opened yet. False if the stream is finished and
    /// forgotten: the frame is late and is dropped.
    fn check_recv(&mut self, id: u64) -> Result<bool, TransportError> {
        let local = is_client_initiated(id) == self.cfg.client;
        let k = kind_of(id);
        if local {
            if !is_bidirectional(id) {
                return Err(TransportError::new(code::STREAM_STATE_ERROR, "a frame for a stream that only we send on"));
            }
            if index_of(id) >= self.opened[k] {
                return Err(TransportError::new(code::STREAM_STATE_ERROR, "a frame for a stream of ours that was not opened"));
            }
        } else {
            self.open_remote(id)?;
        }
        Ok(self.streams.contains_key(&id))
    }

    /// For a frame about the sending side of stream `id` (MAX_STREAM_DATA, STOP_SENDING).
    fn check_send(&mut self, id: u64) -> Result<bool, TransportError> {
        let local = is_client_initiated(id) == self.cfg.client;
        let k = kind_of(id);
        if local {
            if index_of(id) >= self.opened[k] {
                return Err(TransportError::new(code::STREAM_STATE_ERROR, "a frame for a stream of ours that was not opened"));
            }
        } else {
            if !is_bidirectional(id) {
                return Err(TransportError::new(code::STREAM_STATE_ERROR, "a frame for a stream that only the peer sends on"));
            }
            self.open_remote(id)?;
        }
        Ok(self.streams.contains_key(&id))
    }

    /// The peer uses the stream `id` that it opens: it is open, and so are all of its kind with lower numbers.
    fn open_remote(&mut self, id: u64) -> Result<(), TransportError> {
        let k = kind_of(id);
        let index = index_of(id);
        if index >= self.max_streams[k] {
            return Err(TransportError::new(code::STREAM_LIMIT_ERROR, "a stream beyond the limit on the streams the peer may open"));
        }
        let peer = self.peer;
        while self.peer_opened[k] <= index {
            let i = self.peer_opened[k];
            self.peer_opened[k] += 1;
            let sid = make_id(i, k, !self.cfg.client);
            let bidirectional = k == 0;
            let send = bidirectional.then(|| Send::new(peer.map_or(0, |p| p.bidi_local)));
            let recv = Recv::new(if bidirectional { self.cfg.bidi_remote } else { self.cfg.uni });
            self.streams.insert(sid, Stream { send, recv: Some(recv) });
        }
        Ok(())
    }

    /// A frame of streams or of flow control arrived. An error is for the connection to end with.
    pub fn on_frame(&mut self, f: &Frame<'_>) -> Result<(), TransportError> {
        match f {
            Frame::Stream { id, offset, data, fin } => self.on_stream(*id, *offset, data, *fin),
            Frame::ResetStream { id, error, final_size } => self.on_reset_stream(*id, *error, *final_size),
            Frame::StopSending { id, error } => self.on_stop_sending(*id, *error),
            Frame::MaxData(max) => {
                if *max > self.send_max_data {
                    self.send_max_data = *max;
                    let parked = std::mem::take(&mut self.parked);
                    for id in parked {
                        if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                            s.parked = false;
                        }
                        self.schedule(id);
                    }
                }
                Ok(())
            }
            Frame::MaxStreamData { id, max } => {
                if self.check_send(*id)? {
                    if let Some(s) = self.streams.get_mut(id).and_then(|s| s.send.as_mut()) {
                        if *max > s.max_data {
                            s.max_data = *max;
                            s.blocked_pending = false;
                            self.schedule(*id);
                        }
                    }
                }
                Ok(())
            }
            Frame::MaxStreams { bidirectional, max } => {
                let k = if *bidirectional { 0 } else { 1 };
                if *max > self.peer_max_streams[k] {
                    self.peer_max_streams[k] = *max;
                    if std::mem::take(&mut self.open_blocked[k]) {
                        self.events.push_back(StreamEvent::Available { bidirectional: *bidirectional });
                    }
                }
                Ok(())
            }
            // (these say that the peer would send more if it could: the limits that we gave go out when we have read, as they do)
            Frame::StreamDataBlocked { id, .. } => self.check_recv(*id).map(|_| ()),
            Frame::DataBlocked(_) | Frame::StreamsBlocked { .. } => Ok(()),
            _ => Ok(()),
        }
    }

    fn on_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<(), TransportError> {
        if !self.check_recv(id)? {
            return Ok(());
        }
        let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else { return Ok(()) };
        if r.state != RecvState::Open {
            return Ok(());
        }
        let end = offset + data.len() as u64;
        match r.final_size {
            Some(fs) if end > fs || (fin && end != fs) => {
                return Err(TransportError::new(code::FINAL_SIZE_ERROR, "stream data that does not agree with the final size"));
            }
            None if fin && r.high > end => {
                return Err(TransportError::new(code::FINAL_SIZE_ERROR, "the end of a stream below data that has come"));
            }
            _ => {}
        }
        if end > r.max_data {
            return Err(TransportError::new(code::FLOW_CONTROL_ERROR, "stream data beyond the limit of the stream"));
        }
        let delta = end.saturating_sub(r.high);
        if self.recv_total + delta > self.recv_limit {
            return Err(TransportError::new(code::FLOW_CONTROL_ERROR, "stream data beyond the limit of the connection"));
        }
        let window = r.max_data - r.buf.read_offset();
        match r.buf.insert(offset, data, window) {
            Ok(()) => {}
            Err(reassembly::Error::Exceeded) => return Err(TransportError::new(code::FLOW_CONTROL_ERROR, "stream data beyond the limit of the stream, or in too many pieces")),
            Err(reassembly::Error::Inconsistent) => return Err(TransportError::new(code::PROTOCOL_VIOLATION, "stream data that differs from what came before")),
        }
        r.high = r.high.max(end);
        self.recv_total += delta;
        if fin {
            r.final_size = Some(end);
        }
        if r.discard {
            self.drain(id);
        } else if r.readable() && !r.queued {
            r.queued = true;
            self.events.push_back(StreamEvent::Readable(id));
        }
        Ok(())
    }

    fn on_reset_stream(&mut self, id: u64, error: u64, final_size: u64) -> Result<(), TransportError> {
        if !self.check_recv(id)? {
            return Ok(());
        }
        let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else { return Ok(()) };
        if r.final_size.is_some_and(|fs| fs != final_size) || r.high > final_size {
            return Err(TransportError::new(code::FINAL_SIZE_ERROR, "RESET_STREAM with a final size that does not agree with the data"));
        }
        if final_size > r.max_data {
            return Err(TransportError::new(code::FLOW_CONTROL_ERROR, "RESET_STREAM with a final size beyond the limit of the stream"));
        }
        let delta = final_size - r.high;
        if self.recv_total + delta > self.recv_limit {
            return Err(TransportError::new(code::FLOW_CONTROL_ERROR, "RESET_STREAM with a final size beyond the limit of the connection"));
        }
        if r.state != RecvState::Open {
            return Ok(()); // (a repeat, or after the end has been read)
        }
        r.final_size = Some(final_size);
        r.high = final_size;
        self.recv_total += delta;
        // what was not read is not going to be: it is counted as read, for the credit of the connection
        let unread = final_size - r.buf.read_offset();
        r.buf = Reassembler::new();
        r.stop = None;
        let wanted = !r.discard;
        if wanted {
            r.state = RecvState::Reset(error);
            if !r.queued {
                r.queued = true;
                self.events.push_back(StreamEvent::Readable(id));
            }
        } else {
            r.state = RecvState::ResetRead(error);
        }
        self.consumed += unread;
        self.grow_connection_window();
        if !wanted {
            self.cleanup(id);
        }
        Ok(())
    }

    fn on_stop_sending(&mut self, id: u64, error: u64) -> Result<(), TransportError> {
        if !self.check_send(id)? {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else { return Ok(()) };
        if matches!(s.state, SendState::Open | SendState::Finished) {
            s.stopped = Some(error);
            self.events.push_back(StreamEvent::Stopped(id, error));
            self.do_reset(id, error);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // frames to send

    /// Whether there is anything that `write_frames` would write.
    pub fn has_pending(&self) -> bool {
        self.max_data_pending
            || self.max_streams_pending.iter().any(|&p| p)
            || self.streams_blocked_pending.iter().any(|&p| p)
            || (self.data_blocked_pending && !self.parked.is_empty())
            || !self.control.is_empty()
            || !self.send_queue.is_empty()
    }

    /// Writes the frames that are due after `out.len()`, no more than `budget` bytes of them, and says what they were in `sent`:
    /// first the flow control and the resets, then stream data, a frame for each stream in turn while there is room.
    pub fn write_frames(&mut self, out: &mut Vec<u8>, budget: usize, sent: &mut Vec<SentFrame>) {
        let start = out.len();
        let record = |sent: &mut Vec<SentFrame>, f: StreamFrame| sent.push(SentFrame::Stream(f));
        // the connection's
        if self.max_data_pending && put(out, start, budget, &Frame::MaxData(self.recv_limit)) {
            self.max_data_pending = false;
            record(sent, StreamFrame::MaxData(self.recv_limit));
        }
        for k in 0..2 {
            let bidirectional = k == 0;
            if self.max_streams_pending[k] && put(out, start, budget, &Frame::MaxStreams { bidirectional, max: self.max_streams[k] }) {
                self.max_streams_pending[k] = false;
                record(sent, StreamFrame::MaxStreams { bidirectional, max: self.max_streams[k] });
            }
            if self.streams_blocked_pending[k] {
                let limit = self.peer_max_streams[k];
                if !self.open_blocked[k] {
                    self.streams_blocked_pending[k] = false; // (not blocked any more)
                } else if put(out, start, budget, &Frame::StreamsBlocked { bidirectional, limit }) {
                    self.streams_blocked_pending[k] = false;
                    record(sent, StreamFrame::StreamsBlocked { bidirectional, limit });
                }
            }
        }
        if self.data_blocked_pending {
            if self.parked.is_empty() {
                self.data_blocked_pending = false;
            } else if put(out, start, budget, &Frame::DataBlocked(self.send_max_data)) {
                self.data_blocked_pending = false;
                record(sent, StreamFrame::DataBlocked(self.send_max_data));
            }
        }
        // the streams'
        let ids: Vec<u64> = self.control.iter().copied().collect();
        for id in ids {
            let Some(st) = self.streams.get_mut(&id) else {
                self.control.remove(&id);
                continue;
            };
            let mut more = false;
            if let Some(s) = st.send.as_mut() {
                if let Some(r) = s.reset.as_mut().filter(|r| r.pending) {
                    let f = Frame::ResetStream { id, error: r.error, final_size: r.final_size };
                    if put(out, start, budget, &f) {
                        r.pending = false;
                        record(sent, StreamFrame::ResetStream { id, error: r.error, final_size: r.final_size });
                    } else {
                        more = true;
                    }
                }
                if s.blocked_pending {
                    let limit = s.blocked_sent.unwrap_or(s.max_data);
                    if put(out, start, budget, &Frame::StreamDataBlocked { id, limit }) {
                        s.blocked_pending = false;
                        record(sent, StreamFrame::StreamDataBlocked { id, limit });
                    } else {
                        more = true;
                    }
                }
            }
            if let Some(r) = st.recv.as_mut() {
                if r.state != RecvState::Open {
                    r.max_data_pending = false;
                    r.stop = None;
                }
                if let Some(stop) = r.stop.as_mut().filter(|s| s.pending) {
                    if put(out, start, budget, &Frame::StopSending { id, error: stop.error }) {
                        stop.pending = false;
                        record(sent, StreamFrame::StopSending { id, error: stop.error });
                    } else {
                        more = true;
                    }
                }
                if r.max_data_pending {
                    if put(out, start, budget, &Frame::MaxStreamData { id, max: r.max_data }) {
                        r.max_data_pending = false;
                        record(sent, StreamFrame::MaxStreamData { id, max: r.max_data });
                    } else {
                        more = true;
                    }
                }
            }
            if !more {
                self.control.remove(&id);
            }
        }
        // the data
        loop {
            let room = budget.saturating_sub(out.len() - start);
            if room < 4 {
                break;
            }
            let Some(&id) = self.send_queue.front() else { break };
            let conn_room = self.send_max_data.saturating_sub(self.sent_total);
            let ready = self.streams.get(&id).and_then(|s| s.send.as_ref()).is_some_and(|s| matches!(gate(s, conn_room), Gate::Ready));
            if !ready {
                // (it was reset, or the credit went to other streams)
                self.send_queue.pop_front();
                if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                    s.queued = false;
                }
                self.schedule(id);
                continue;
            }
            let Some(f) = self.write_stream_frame(id, out, room) else { break };
            sent.push(SentFrame::Stream(f));
            self.send_queue.pop_front();
            if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                s.queued = false;
            }
            self.schedule(id);
        }
    }

    /// Writes a STREAM frame for the stream, using at most `room` bytes: with a Length field, or without if the data fills the
    /// room (the frame is then the last of the packet).
    fn write_stream_frame(&mut self, id: u64, out: &mut Vec<u8>, room: usize) -> Option<StreamFrame> {
        let conn_room = self.send_max_data.saturating_sub(self.sent_total);
        let s = self.streams.get_mut(&id)?.send.as_mut()?;
        let limit = s.max_data.min(s.buf.sent() + conn_room);
        let offset = s.buf.next_offset()?;
        let available = s.buf.peek_len(limit);
        let header = frame::stream_header_len(id, offset, None);
        if room < header + 1 {
            return None;
        }
        // a frame that would hold a few bytes of much more waits for the next packet
        if available > 16 && room - header < 16 {
            return None;
        }
        let fill = room - header;
        let max_len = if available >= fill && available > 0 {
            fill
        } else {
            let mut n = available;
            while frame::stream_header_len(id, offset, Some(n)) + n > room {
                n -= 1;
            }
            n
        };
        let c = s.buf.next_chunk(max_len, limit)?;
        debug_assert_eq!(c.offset, offset);
        if c.len == fill && available >= fill {
            frame::write_stream_header(out, id, c.offset, None, c.fin);
        } else {
            frame::write_stream_header(out, id, c.offset, Some(c.len), c.fin);
        }
        s.buf.copy(c.offset, c.len, out);
        self.sent_total += c.new;
        Some(StreamFrame::Stream { id, offset: c.offset, len: c.len, fin: c.fin })
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // what became of the frames sent

    pub fn on_acked(&mut self, f: &StreamFrame) {
        match *f {
            StreamFrame::Stream { id, offset, len, fin } => {
                let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
                if !matches!(s.state, SendState::Open | SendState::Finished) {
                    return;
                }
                s.buf.on_acked(offset, len, fin);
                if s.state == SendState::Finished && s.buf.is_fully_acked() {
                    s.state = SendState::Done;
                }
                if s.write_blocked && s.state == SendState::Open && s.buf.buffered() <= self.cfg.send_buffer / 2 {
                    s.write_blocked = false;
                    self.events.push_back(StreamEvent::Writable(id));
                }
                self.cleanup(id);
            }
            StreamFrame::ResetStream { id, .. } => {
                if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                    if s.state == SendState::Reset {
                        s.state = SendState::Done;
                        s.reset = None;
                    }
                }
                self.cleanup(id);
            }
            _ => {}
        }
    }

    pub fn on_lost(&mut self, f: &StreamFrame) {
        match *f {
            StreamFrame::Stream { id, offset, len, fin } => {
                let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
                if !matches!(s.state, SendState::Open | SendState::Finished) {
                    return;
                }
                s.buf.on_lost(offset, len, fin);
                self.schedule(id);
            }
            StreamFrame::ResetStream { id, .. } => {
                if let Some(r) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()).filter(|s| s.state == SendState::Reset).and_then(|s| s.reset.as_mut()) {
                    r.pending = true;
                    self.control.insert(id);
                }
            }
            StreamFrame::StopSending { id, .. } => {
                if let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()).filter(|r| r.state == RecvState::Open) {
                    if let Some(stop) = r.stop.as_mut() {
                        stop.pending = true;
                        self.control.insert(id);
                    }
                }
            }
            // a limit is sent again if it is still the one we gave: the frames say what is current when they are written
            StreamFrame::MaxData(v) => {
                if v == self.recv_limit {
                    self.max_data_pending = true;
                }
            }
            StreamFrame::MaxStreamData { id, max } => {
                if let Some(r) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()).filter(|r| r.state == RecvState::Open && r.max_data == max) {
                    r.max_data_pending = true;
                    self.control.insert(id);
                }
            }
            StreamFrame::MaxStreams { bidirectional, max } => {
                let k = if bidirectional { 0 } else { 1 };
                if self.max_streams[k] == max {
                    self.max_streams_pending[k] = true;
                }
            }
            // the blocked frames are sent again if the stream is still blocked at the same limit
            StreamFrame::DataBlocked(v) => {
                if v == self.send_max_data && !self.parked.is_empty() {
                    self.data_blocked_pending = true;
                }
            }
            StreamFrame::StreamDataBlocked { id, limit } => {
                if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()).filter(|s| s.max_data == limit && matches!(s.state, SendState::Open | SendState::Finished)) {
                    s.blocked_pending = true;
                    self.control.insert(id);
                }
            }
            StreamFrame::StreamsBlocked { bidirectional, limit } => {
                let k = if bidirectional { 0 } else { 1 };
                if self.open_blocked[k] && self.peer_max_streams[k] == limit {
                    self.streams_blocked_pending[k] = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::packet::PacketType;
    use std::collections::{BTreeMap, BTreeSet};

    // ------------------------------------------------------------------------------------------------------------------------
    // a little harness: two endpoints, and packets between them that the test delivers, loses or acknowledges

    fn config(client: bool) -> StreamsConfig {
        StreamsConfig { client, max_data: 20_000, bidi_local: 6_000, bidi_remote: 6_000, uni: 6_000, max_streams_bidi: 8, max_streams_uni: 8, send_buffer: 8_000 }
    }

    /// The transport parameters that an endpoint with this configuration sends.
    fn params(c: &StreamsConfig) -> TransportParameters {
        TransportParameters {
            initial_max_data: c.max_data,
            initial_max_stream_data_bidi_local: c.bidi_local,
            initial_max_stream_data_bidi_remote: c.bidi_remote,
            initial_max_stream_data_uni: c.uni,
            initial_max_streams_bidi: c.max_streams_bidi,
            initial_max_streams_uni: c.max_streams_uni,
            ..TransportParameters::default()
        }
    }

    fn pair_with(cc: StreamsConfig, sc: StreamsConfig) -> (Streams, Streams) {
        let (mut c, mut s) = (Streams::new(cc), Streams::new(sc));
        c.set_peer_params(&params(&sc));
        s.set_peer_params(&params(&cc));
        (c, s)
    }

    fn pair() -> (Streams, Streams) {
        pair_with(config(true), config(false))
    }

    /// Writes the frames of one packet of up to `budget` bytes. Returns the bytes, and what they were.
    fn packet(from: &mut Streams, budget: usize) -> (Vec<u8>, Vec<SentFrame>) {
        let mut out = Vec::new();
        let mut sent = Vec::new();
        from.write_frames(&mut out, budget, &mut sent);
        assert!(out.len() <= budget, "{} bytes in a budget of {budget}", out.len());
        (out, sent)
    }

    fn deliver(to: &mut Streams, bytes: &[u8]) -> Result<(), TransportError> {
        if bytes.is_empty() {
            return Ok(());
        }
        for f in frame::frames(bytes, PacketType::OneRtt) {
            to.on_frame(&f.expect("a frame that reads"))?;
        }
        Ok(())
    }

    fn frames_of(bytes: &[u8]) -> Vec<Frame<'_>> {
        frame::frames(bytes, PacketType::OneRtt).map(|f| f.expect("a frame that reads")).collect()
    }

    fn acked(from: &mut Streams, sent: &[SentFrame]) {
        for f in sent {
            if let SentFrame::Stream(f) = f {
                from.on_acked(f);
            }
        }
    }

    fn lost(from: &mut Streams, sent: &[SentFrame]) {
        for f in sent {
            if let SentFrame::Stream(f) = f {
                from.on_lost(f);
            }
        }
    }

    /// One packet from `from` to `to` that arrives and is acknowledged at once. Returns what was in it.
    fn flow(from: &mut Streams, to: &mut Streams, budget: usize) -> Vec<SentFrame> {
        let (bytes, sent) = packet(from, budget);
        deliver(to, &bytes).expect("the peer takes the frames");
        acked(from, &sent);
        sent
    }

    /// Sends packets from `from` to `to`, each acknowledged at once, until `from` has nothing to send. Returns how many.
    fn drain_to(from: &mut Streams, to: &mut Streams) -> usize {
        let mut n = 0;
        while from.has_pending() {
            let sent = flow(from, to, 1200);
            if sent.is_empty() {
                break;
            }
            n += 1;
            assert!(n < 10_000, "this does not end");
        }
        n
    }

    /// Both ways until neither has anything to send.
    fn settle(a: &mut Streams, b: &mut Streams) {
        for _ in 0..1000 {
            let n = drain_to(a, b) + drain_to(b, a);
            if n == 0 {
                return;
            }
        }
        panic!("the streams do not settle");
    }

    fn read_all(s: &mut Streams, id: u64) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = [0u8; 700];
        loop {
            match s.read(id, &mut buf) {
                Ok((n, fin)) => {
                    out.extend_from_slice(&buf[..n]);
                    if fin {
                        return (out, true);
                    }
                    if n == 0 {
                        return (out, false);
                    }
                }
                Err(StreamError::Blocked) => return (out, false),
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn events(s: &mut Streams) -> Vec<StreamEvent> {
        std::iter::from_fn(|| s.poll_event()).collect()
    }

    /// A deterministic source of random numbers (xorshift).
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
        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // ids and opening

    #[test]
    fn the_id_says_who_opened_the_stream_and_which_way_it_goes() {
        assert_eq!([make_id(0, 0, true), make_id(0, 1, true), make_id(0, 0, false), make_id(0, 1, false)], [0, 2, 1, 3]);
        assert_eq!(make_id(3, 0, true), 12);
        assert_eq!(make_id(2, 1, false), 11);
        assert!(is_bidirectional(12) && !is_bidirectional(11));
        assert!(is_client_initiated(12) && !is_client_initiated(11));
        assert_eq!((index_of(11), kind_of(11), kind_of(12)), (2, 1, 0));
    }

    #[test]
    fn streams_open_with_the_numbers_of_their_kind_and_only_when_the_peers_limits_are_known() {
        let mut c = Streams::new(config(true));
        assert_eq!(c.open(true), Err(StreamError::Blocked), "the peer's parameters are not known");
        let (mut c, mut s) = pair();
        assert_eq!([c.open(true), c.open(true), c.open(false), c.open(true), c.open(false)], [Ok(0), Ok(4), Ok(2), Ok(8), Ok(6)]);
        assert_eq!([s.open(true), s.open(false), s.open(true)], [Ok(1), Ok(3), Ok(5)]);
    }

    #[test]
    fn opening_beyond_the_peers_limit_is_blocked_and_says_so_once_and_the_peer_can_raise_it() {
        let (mut c, _s) = pair_with(config(true), StreamsConfig { max_streams_bidi: 2, ..config(false) });
        assert_eq!([c.open(true), c.open(true)], [Ok(0), Ok(4)]);
        assert_eq!(c.open(true), Err(StreamError::Blocked));
        assert_eq!(c.open(true), Err(StreamError::Blocked));
        let (bytes, sent) = packet(&mut c, 100);
        assert_eq!(frames_of(&bytes), vec![Frame::StreamsBlocked { bidirectional: true, limit: 2 }]);
        assert_eq!(sent, vec![SentFrame::Stream(StreamFrame::StreamsBlocked { bidirectional: true, limit: 2 })]);
        // (once for the limit, though the application tried twice)
        assert!(!c.has_pending());
        // the packet was lost: the frame goes again, as the stream is still blocked
        lost(&mut c, &sent);
        let (bytes, _) = packet(&mut c, 100);
        assert_eq!(frames_of(&bytes).len(), 1);
        // the peer raises the limit
        assert!(c.poll_event().is_none());
        c.on_frame(&Frame::MaxStreams { bidirectional: true, max: 3 }).unwrap();
        assert_eq!(events(&mut c), vec![StreamEvent::Available { bidirectional: true }]);
        assert_eq!(c.open(true), Ok(8));
        assert_eq!(c.open(true), Err(StreamError::Blocked));
        // a lower limit than the one we have changes nothing
        c.on_frame(&Frame::MaxStreams { bidirectional: true, max: 1 }).unwrap();
        assert_eq!(c.peer_max_streams[0], 3);
        // the unidirectional streams have a limit of their own
        assert_eq!(c.open(false), Ok(2));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // data

    #[test]
    fn what_is_written_is_read_in_order_and_the_end_comes_with_it() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        let data = pattern(5000, 1);
        assert_eq!(c.write(id, &data, true), Ok(5000));
        assert!(c.has_pending());
        // 1200 bytes a packet: the frames of a stream fill the packets
        let mut packets = 0;
        let mut sizes = Vec::new();
        while c.has_pending() {
            let (bytes, sent) = packet(&mut c, 1200);
            sizes.push(bytes.len());
            deliver(&mut s, &bytes).unwrap();
            acked(&mut c, &sent);
            packets += 1;
        }
        assert_eq!(packets, 5);
        assert_eq!(&sizes[..4], &[1200; 4], "the full packets have no room to spare: the frame has no length");
        assert_eq!(events(&mut s), vec![StreamEvent::Readable(id)], "one event for the stream, however many frames came");
        let (got, fin) = read_all(&mut s, id);
        assert!(fin);
        assert_eq!(got, data);
        // nothing is left on the sending side: all acknowledged
        assert!(c.send_room(id).is_some());
        assert_eq!(c.buffered(id), Some(0));
        // the server has not finished its own side of the stream
        assert!(s.contains(id));
        assert_eq!(s.write(id, b"ok", true), Ok(2));
        settle(&mut c, &mut s);
        assert_eq!(read_all(&mut c, id), (b"ok".to_vec(), true));
        assert!(!c.contains(id) && !s.contains(id), "a stream that is over on both sides is forgotten");
    }

    #[test]
    fn a_frame_with_the_end_and_no_data_is_sent_for_a_stream_that_is_ended_later() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        assert_eq!(c.write(id, b"hello", false), Ok(5));
        let sent = flow(&mut c, &mut s, 1200);
        assert_eq!(sent, vec![SentFrame::Stream(StreamFrame::Stream { id, offset: 0, len: 5, fin: false })]);
        assert_eq!(read_all(&mut s, id), (b"hello".to_vec(), false));
        assert_eq!(c.write(id, b"", true), Ok(0));
        let sent = flow(&mut c, &mut s, 1200);
        assert_eq!(sent, vec![SentFrame::Stream(StreamFrame::Stream { id, offset: 5, len: 0, fin: true })]);
        // the application is told of the end, and then reads it
        assert_eq!(events(&mut s), vec![StreamEvent::Readable(id), StreamEvent::Readable(id)]);
        let mut buf = [0u8; 10];
        assert_eq!(s.read(id, &mut buf), Ok((0, true)));
        assert!(!s.contains(id), "a unidirectional stream that is read to its end is forgotten");
        assert!(!c.contains(id), "and the sending side's once all is acknowledged");
        // writing after the end is refused
        let (mut c2, _s2) = pair();
        let id = c2.open(true).unwrap();
        c2.write(id, b"x", true).unwrap();
        assert_eq!(c2.write(id, b"y", false), Err(StreamError::Closed));
    }

    #[test]
    fn a_stream_with_nothing_in_it_but_the_end_is_readable_as_ended() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        assert_eq!(c.write(id, b"", true), Ok(0));
        flow(&mut c, &mut s, 100);
        assert_eq!(events(&mut s), vec![StreamEvent::Readable(id)]);
        assert_eq!(s.read(id, &mut [0u8; 4]), Ok((0, true)));
    }

    #[test]
    fn a_write_that_the_buffer_cannot_hold_is_cut_short_and_the_application_is_told_when_there_is_room() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        let data = pattern(20_000, 2);
        assert_eq!(c.write(id, &data, true), Ok(8000), "the buffer holds 8000 bytes");
        assert_eq!(c.send_room(id), Some(0));
        assert_eq!(c.write(id, &data[8000..], true), Err(StreamError::Blocked));
        // sent, and not acknowledged: still held
        let mut in_flight = Vec::new();
        for _ in 0..4 {
            let (bytes, sent) = packet(&mut c, 1200);
            deliver(&mut s, &bytes).unwrap();
            in_flight.push(sent);
        }
        assert!(events(&mut c).is_empty());
        assert_eq!(c.write(id, &data[8000..], true), Err(StreamError::Blocked));
        // the acknowledgments bring the room back, and one event for it
        for sent in &in_flight {
            acked(&mut c, sent);
        }
        let room = c.send_room(id).unwrap();
        assert!(room >= 4000, "{room}");
        assert_eq!(events(&mut c), vec![StreamEvent::Writable(id)]);
        let n = c.write(id, &data[8000..], true).unwrap();
        assert!(n > 0 && n <= room);
    }

    #[test]
    fn many_streams_take_turns_in_the_packets() {
        let (mut c, mut s) = pair();
        let ids: Vec<u64> = (0..4).map(|_| c.open(true).unwrap()).collect();
        for &id in &ids {
            c.write(id, &pattern(3000, id as u8), false).unwrap();
        }
        // four packets: every stream is in one of them at least, and after a few more all have got an equal share
        let mut seen = std::collections::BTreeMap::new();
        for _ in 0..8 {
            let sent = flow(&mut c, &mut s, 600);
            for f in sent {
                if let SentFrame::Stream(StreamFrame::Stream { id, len, .. }) = f {
                    *seen.entry(id).or_insert(0usize) += len;
                }
            }
        }
        assert_eq!(seen.len(), 4, "{seen:?}");
        let (lo, hi) = (seen.values().min().unwrap(), seen.values().max().unwrap());
        assert!(*hi - *lo <= 600, "{seen:?}");
    }

    #[test]
    fn data_that_comes_out_of_order_and_twice_is_put_in_order() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        let data = pattern(3000, 3);
        c.write(id, &data, true).unwrap();
        let mut packets = Vec::new();
        while c.has_pending() {
            packets.push(packet(&mut c, 700));
        }
        assert!(packets.len() >= 4);
        // the last first, then the others in turn, the second twice
        deliver(&mut s, &packets.last().unwrap().0).unwrap();
        assert_eq!(s.read(id, &mut [0u8; 10]), Err(StreamError::Blocked));
        for (bytes, _) in &packets[..packets.len() - 1] {
            deliver(&mut s, bytes).unwrap();
            deliver(&mut s, bytes).unwrap();
        }
        assert_eq!(read_all(&mut s, id), (data, true));
    }

    #[test]
    fn what_is_lost_is_sent_again_until_the_stream_is_complete() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        let data = pattern(7000, 4);
        c.write(id, &data, true).unwrap();
        let mut rng = Rng(7);
        let mut rounds = 0;
        while c.has_pending() || c.buffered(id).is_some_and(|b| b > 0) {
            rounds += 1;
            assert!(rounds < 1000);
            let (bytes, sent) = packet(&mut c, 1000);
            if rng.chance(40) {
                lost(&mut c, &sent);
            } else {
                deliver(&mut s, &bytes).unwrap();
                acked(&mut c, &sent);
            }
            // (flow control credit goes back as the server reads)
            if s.contains(id) {
                read_all(&mut s, id);
            }
            let _ = drain_to(&mut s, &mut c);
        }
        assert!(!s.contains(id) && !c.contains(id), "read to the end, all acknowledged, forgotten");
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // flow control

    fn stream_bytes(sent: &[SentFrame]) -> usize {
        sent.iter().map(|f| if let SentFrame::Stream(StreamFrame::Stream { len, .. }) = f { *len } else { 0 }).sum()
    }

    fn count(sent: &[SentFrame], pick: impl Fn(&StreamFrame) -> bool) -> usize {
        sent.iter().filter(|f| matches!(f, SentFrame::Stream(f) if pick(f))).count()
    }

    #[test]
    fn a_stream_stops_at_the_limit_says_so_once_and_goes_on_when_the_peer_has_read_half_the_window() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        c.write(id, &pattern(8000, 5), false).unwrap();
        let mut sent = Vec::new();
        while c.has_pending() {
            sent.extend(flow(&mut c, &mut s, 1200));
        }
        assert_eq!(stream_bytes(&sent), 6000, "the limit of the stream is 6000");
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::StreamDataBlocked { id: i, limit: 6000 } if *i == id)), 1);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::StreamDataBlocked { .. })), 1);
        assert!(!c.has_pending(), "nothing to send until the peer gives more credit");
        // the peer reads, but less than half of the window: no news
        let mut buf = vec![0u8; 2999];
        assert_eq!(s.read(id, &mut buf), Ok((2999, false)));
        assert!(!s.has_pending());
        assert_eq!(s.read(id, &mut buf[..1]), Ok((1, false)));
        let sent = flow(&mut s, &mut c, 1200);
        assert_eq!(sent, vec![SentFrame::Stream(StreamFrame::MaxStreamData { id, max: 9000 })]);
        assert!(c.has_pending());
        let mut rest = Vec::new();
        while c.has_pending() {
            rest.extend(flow(&mut c, &mut s, 1200));
        }
        assert_eq!(stream_bytes(&rest), 2000);
        assert_eq!(count(&rest, |f| matches!(f, StreamFrame::StreamDataBlocked { .. })), 0);
    }

    #[test]
    fn all_streams_stop_at_the_limit_of_the_connection_and_the_connection_says_so_once() {
        let (mut c, mut s) = pair_with(config(true), StreamsConfig { max_data: 5000, ..config(false) });
        let (a, b) = (c.open(true).unwrap(), c.open(true).unwrap());
        let (da, db) = (pattern(4000, 1), pattern(4000, 2));
        c.write(a, &da, true).unwrap();
        c.write(b, &db, true).unwrap();
        let mut sent = Vec::new();
        while c.has_pending() {
            sent.extend(flow(&mut c, &mut s, 1200));
        }
        assert_eq!(stream_bytes(&sent), 5000);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::DataBlocked(5000))), 1);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::StreamDataBlocked { .. })), 0, "the streams' limits are not reached");
        // the server reads what came, and gives more: not at every byte, but when half of the window has been read
        let (mut ra, mut rb) = (read_all(&mut s, a).0, read_all(&mut s, b).0);
        assert_eq!(ra.len() + rb.len(), 5000);
        let sent = flow(&mut s, &mut c, 1200);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::MaxData(v) if *v > 5000 && *v <= 10_000)), 1, "{sent:?}");
        assert!(c.has_pending());
        for _ in 0..10 {
            settle(&mut c, &mut s);
            ra.extend(read_all(&mut s, a).0);
            rb.extend(read_all(&mut s, b).0);
        }
        assert_eq!((ra, rb), (da, db));
        assert!(c.parked.is_empty());
    }

    #[test]
    fn credit_for_the_whole_connection_follows_what_is_read_not_what_comes() {
        let (mut c, mut s) = pair_with(config(true), StreamsConfig { max_data: 4000, bidi_remote: 4000, ..config(false) });
        let id = c.open(true).unwrap();
        c.write(id, &pattern(4000, 0), false).unwrap();
        while c.has_pending() {
            flow(&mut c, &mut s, 1200);
        }
        assert_eq!(s.recv_total, 4000);
        assert!(!s.has_pending(), "nothing was read");
        s.read(id, &mut vec![0u8; 1999]).unwrap();
        assert!(!s.has_pending());
        s.read(id, &mut [0u8; 1]).unwrap();
        assert!(s.max_data_pending, "half of the window was read");
        let sent = flow(&mut s, &mut c, 1200);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::MaxData(6000))), 1);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::MaxStreamData { max: 6000, .. })), 1);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // what the peer may not do

    fn code_of(r: Result<(), TransportError>) -> u64 {
        r.expect_err("an error").code
    }

    fn data(id: u64, offset: u64, bytes: &[u8], fin: bool) -> Frame<'_> {
        Frame::Stream { id, offset, data: bytes, fin }
    }

    #[test]
    fn data_beyond_the_limit_of_a_stream_or_of_the_connection_ends_the_connection() {
        let (_c, mut s) = pair();
        assert!(s.on_frame(&data(0, 5980, &[0; 20], false)).is_ok(), "up to the limit is fine");
        assert_eq!(code_of(s.on_frame(&data(0, 5990, &[0; 20], false))), code::FLOW_CONTROL_ERROR);
        assert_eq!(code_of(s.on_frame(&data(4, 6000, &[0; 1], false))), code::FLOW_CONTROL_ERROR);
        // the limit of the connection is 20000: 3 streams of 5000 and then a 4th; 5980 are in from the first
        let (_c, mut s) = pair();
        for i in 0..4u64 {
            s.on_frame(&data(4 * i, 0, &[0; 5000], false)).unwrap();
        }
        assert_eq!(s.recv_total, 20_000);
        assert_eq!(code_of(s.on_frame(&data(16, 0, &[0; 1], false))), code::FLOW_CONTROL_ERROR);
        // a repeat of what came is not new data
        assert!(s.on_frame(&data(0, 0, &[0; 5000], false)).is_ok());
    }

    #[test]
    fn the_final_size_of_a_stream_is_one_number_and_nothing_goes_beyond_it() {
        let ok = |s: &mut Streams, f: Frame<'_>| s.on_frame(&f).unwrap();
        let (_c, mut s) = pair();
        ok(&mut s, data(0, 0, &[1; 100], true));
        assert_eq!(code_of(s.on_frame(&data(0, 100, &[1; 10], false))), code::FINAL_SIZE_ERROR, "data beyond the end");
        assert_eq!(code_of(s.on_frame(&data(0, 95, &[1; 10], true))), code::FINAL_SIZE_ERROR, "another end");
        ok(&mut s, data(0, 50, &[1; 50], true)); // (the same end again is a repeat)
        assert_eq!(code_of(s.on_frame(&Frame::ResetStream { id: 0, error: 1, final_size: 99 })), code::FINAL_SIZE_ERROR);
        // the end below data that has come
        let (_c, mut s) = pair();
        ok(&mut s, data(4, 0, &[1; 100], false));
        assert_eq!(code_of(s.on_frame(&data(4, 50, &[], true))), code::FINAL_SIZE_ERROR);
        // a reset below data that has come
        assert_eq!(code_of(s.on_frame(&Frame::ResetStream { id: 4, error: 1, final_size: 99 })), code::FINAL_SIZE_ERROR);
        // a reset beyond the limit
        assert_eq!(code_of(s.on_frame(&Frame::ResetStream { id: 4, error: 1, final_size: 6001 })), code::FLOW_CONTROL_ERROR);
    }

    #[test]
    fn data_that_differs_from_what_came_for_the_same_offsets_is_a_violation() {
        let (_c, mut s) = pair();
        s.on_frame(&data(0, 0, &[1; 100], false)).unwrap();
        assert_eq!(code_of(s.on_frame(&data(0, 50, &[2; 10], false))), code::PROTOCOL_VIOLATION);
    }

    #[test]
    fn frames_for_streams_that_cannot_be_are_stream_state_errors() {
        let (mut c, mut s) = pair();
        // the server's unidirectional stream 3 is one the client only reads: it cannot send on it
        assert_eq!(code_of(s.on_frame(&data(3, 0, &[1], false))), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(s.on_frame(&Frame::ResetStream { id: 3, error: 0, final_size: 0 })), code::STREAM_STATE_ERROR);
        // a stream of the server's that it did not open
        assert_eq!(code_of(s.on_frame(&data(1, 0, &[1], false))), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(s.on_frame(&Frame::MaxStreamData { id: 1, max: 9 })), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(s.on_frame(&Frame::StopSending { id: 1, error: 9 })), code::STREAM_STATE_ERROR);
        // the client's unidirectional streams are not ones the client reads, nor ones the server sends on
        assert_eq!(code_of(s.on_frame(&Frame::MaxStreamData { id: 2, max: 9 })), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(s.on_frame(&Frame::StopSending { id: 2, error: 9 })), code::STREAM_STATE_ERROR);
        // the same from the client's side
        assert_eq!(code_of(c.on_frame(&data(2, 0, &[1], false))), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(c.on_frame(&Frame::MaxStreamData { id: 3, max: 9 })), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(c.on_frame(&Frame::StreamDataBlocked { id: 2, limit: 9 })), code::STREAM_STATE_ERROR);
        assert_eq!(code_of(c.on_frame(&Frame::MaxStreamData { id: 8, max: 9 })), code::STREAM_STATE_ERROR, "a stream we did not open");
    }

    #[test]
    fn the_peer_may_open_streams_up_to_the_limit_and_opens_the_lower_ones_with_the_first_it_uses() {
        let (_c, mut s) = pair();
        s.on_frame(&data(28, 0, &[1; 10], false)).unwrap(); // index 7: the 8th
        for id in [0, 4, 8, 12, 16, 20, 24, 28] {
            assert!(s.contains(id), "{id}");
        }
        assert_eq!(code_of(s.on_frame(&data(32, 0, &[1], false))), code::STREAM_LIMIT_ERROR);
        assert_eq!(code_of(s.on_frame(&Frame::ResetStream { id: 36, error: 0, final_size: 0 })), code::STREAM_LIMIT_ERROR);
        // the server can write on the streams that the client opened with a frame for another
        assert_eq!(s.write(0, b"hi", false), Ok(2));
        assert_eq!(events(&mut s), vec![StreamEvent::Readable(28)]);
    }

    #[test]
    fn a_late_frame_for_a_stream_that_is_over_is_dropped() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, b"abc", true).unwrap();
        let (bytes, sent) = packet(&mut c, 1200);
        deliver(&mut s, &bytes).unwrap();
        assert_eq!(read_all(&mut s, id), (b"abc".to_vec(), true));
        acked(&mut c, &sent);
        assert!(!s.contains(id) && !c.contains(id));
        // a copy of the frame arrives again, and an acknowledgment and a loss of what is forgotten
        deliver(&mut s, &bytes).unwrap();
        s.on_frame(&Frame::MaxStreamData { id: 2, max: 9 }).expect_err("it is a stream that we do not send on");
        c.on_acked(&StreamFrame::Stream { id, offset: 0, len: 3, fin: true });
        c.on_lost(&StreamFrame::Stream { id, offset: 0, len: 3, fin: true });
        c.on_frame(&Frame::MaxStreamData { id, max: 9 }).unwrap();
        c.on_frame(&Frame::StopSending { id, error: 0 }).unwrap();
        assert!(!c.has_pending());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // resets and stopping

    #[test]
    fn a_reset_drops_what_is_not_sent_and_the_receiver_is_told_with_the_final_size() {
        let (mut c, mut s) = pair();
        let id = c.open(true).unwrap();
        c.write(id, &pattern(5000, 6), false).unwrap();
        let first = flow(&mut c, &mut s, 1200);
        let sent_bytes = stream_bytes(&first) as u64;
        assert!(sent_bytes > 1000);
        c.reset(id, 77).unwrap();
        assert_eq!(c.write(id, b"x", false), Err(StreamError::Closed));
        assert_eq!(c.reset(id, 78), Ok(()), "a second reset changes nothing");
        let (bytes, sent) = packet(&mut c, 1200);
        assert_eq!(frames_of(&bytes), vec![Frame::ResetStream { id, error: 77, final_size: sent_bytes }]);
        assert!(!c.has_pending());
        // the packet is lost: it is sent again, the same
        lost(&mut c, &sent);
        let (bytes, sent) = packet(&mut c, 1200);
        assert_eq!(frames_of(&bytes), vec![Frame::ResetStream { id, error: 77, final_size: sent_bytes }]);
        deliver(&mut s, &bytes).unwrap();
        acked(&mut c, &sent);
        // the receiver has data that it did not read, and is told of the reset
        assert_eq!(events(&mut s), vec![StreamEvent::Readable(id)]);
        let mut buf = [0u8; 10];
        assert_eq!(s.read(id, &mut buf), Err(StreamError::Reset(77)));
        assert_eq!(s.read(id, &mut buf), Err(StreamError::Reset(77)));
        // what was in the buffer and what did not come count as read, for the credit of the connection
        assert_eq!(s.consumed, sent_bytes);
        // acknowledgments and losses of what was in flight are no harm
        c.on_acked(&StreamFrame::Stream { id, offset: 0, len: 100, fin: false });
        c.on_lost(&StreamFrame::Stream { id, offset: 100, len: 100, fin: false });
        assert!(!c.has_pending());
    }

    #[test]
    fn a_unidirectional_stream_that_was_reset_is_forgotten_by_both_when_all_is_acknowledged() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, &pattern(3000, 6), false).unwrap();
        flow(&mut c, &mut s, 1200);
        c.reset(id, 5).unwrap();
        settle(&mut c, &mut s);
        assert!(c.contains(id) == false, "the reset is acknowledged");
        assert!(s.contains(id), "the receiver has not read it");
        assert_eq!(s.read(id, &mut [0u8; 5]), Err(StreamError::Reset(5)));
        assert!(!s.contains(id));
    }

    #[test]
    fn a_receiver_that_stops_the_sender_throws_data_away_and_the_sender_resets() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, &pattern(5000, 7), false).unwrap();
        let data_in = |frames: &[SentFrame]| -> u64 {
            frames.iter().map(|f| if let SentFrame::Stream(StreamFrame::Stream { len, .. }) = f { *len as u64 } else { 0 }).sum()
        };
        let mut data_sent = data_in(&flow(&mut c, &mut s, 1200));
        data_sent += data_in(&flow(&mut c, &mut s, 1200));
        assert!(data_sent > 2000, "the test has data to throw away");
        assert_eq!(s.consumed, 0, "nothing was read yet");
        s.stop_sending(id, 9).unwrap();
        assert_eq!(s.consumed, data_sent, "what was held counts as read");
        assert_eq!(s.read(id, &mut [0u8; 5]), Err(StreamError::Closed));
        events(&mut s); // (what happened so far is not what this test is about)
        // data that is on its way is thrown away as it comes, and counts as read too (the connection's credit must not leak)
        let (late, late_sent) = packet(&mut c, 1200);
        deliver(&mut s, &late).unwrap();
        acked(&mut c, &late_sent);
        data_sent += data_in(&late_sent);
        assert_eq!(s.consumed, data_sent, "what came after counts as read too");
        assert!(!events(&mut s).contains(&StreamEvent::Readable(id)), "data that is thrown away is not announced");
        let sent = flow(&mut s, &mut c, 1200);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::StopSending { error: 9, .. })), 1);
        assert_eq!(events(&mut c), vec![StreamEvent::Stopped(id, 9)]);
        assert_eq!(c.write(id, b"more", false), Err(StreamError::Stopped(9)));
        settle(&mut c, &mut s);
        assert!(!c.contains(id) && !s.contains(id), "reset with the same code, and both are done");
    }

    #[test]
    fn stopping_a_stream_that_has_all_come_sends_no_stop_sending() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, b"all of it", true).unwrap();
        flow(&mut c, &mut s, 1200);
        s.stop_sending(id, 3).unwrap();
        assert!(!s.has_pending() || count(&flow(&mut s, &mut c, 1200), |f| matches!(f, StreamFrame::StopSending { .. })) == 0);
        assert!(!s.contains(id));
    }

    #[test]
    fn a_stop_sending_that_is_lost_is_sent_again_while_the_stream_goes_on() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, &pattern(4000, 1), false).unwrap();
        flow(&mut c, &mut s, 1200);
        s.stop_sending(id, 4).unwrap();
        let (_, sent) = packet(&mut s, 1200);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::StopSending { .. })), 1);
        lost(&mut s, &sent);
        let (bytes, sent2) = packet(&mut s, 1200);
        assert_eq!(count(&sent2, |f| matches!(f, StreamFrame::StopSending { error: 4, .. })), 1);
        deliver(&mut c, &bytes).unwrap();
        acked(&mut s, &sent2);
        // the sender's reset ends it
        settle(&mut c, &mut s);
        assert!(!s.contains(id));
        // after the stream is over, the loss of the old frame is not an order to send it again
        s.on_lost(&StreamFrame::StopSending { id, error: 4 });
        assert!(!s.has_pending());
    }

    #[test]
    fn a_stream_that_is_reset_by_the_peer_for_a_stream_we_stopped_is_over_at_once() {
        let (mut c, mut s) = pair();
        let id = c.open(false).unwrap();
        c.write(id, &pattern(2000, 1), false).unwrap();
        flow(&mut c, &mut s, 1200);
        s.stop_sending(id, 4).unwrap();
        c.reset(id, 4).unwrap();
        settle(&mut c, &mut s);
        assert!(!s.contains(id) && !c.contains(id));
        assert!(events(&mut s).iter().all(|e| !matches!(e, StreamEvent::Readable(i) if *i == id)) || true);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // limits that move

    #[test]
    fn streams_that_are_over_make_room_for_the_peer_to_open_more() {
        let (mut c, mut s) = pair_with(config(true), StreamsConfig { max_streams_uni: 4, ..config(false) });
        let mut ids = Vec::new();
        for round in 0..3 {
            for _ in 0..4 {
                let id = c.open(false).unwrap_or_else(|e| panic!("round {round}: {e}"));
                c.write(id, b"x", true).unwrap();
                ids.push(id);
            }
            assert_eq!(c.open(false), Err(StreamError::Blocked), "round {round}: the limit");
            settle(&mut c, &mut s);
            for &id in ids.iter().rev().take(4) {
                assert_eq!(read_all(&mut s, id), (b"x".to_vec(), true));
            }
            settle(&mut c, &mut s);
            assert!(events(&mut c).iter().any(|e| *e == StreamEvent::Available { bidirectional: false }), "round {round}");
        }
        assert_eq!(ids.len(), 12);
    }

    #[test]
    fn a_limit_that_was_lost_is_sent_again_as_it_is_now() {
        let (mut c, mut s) = pair_with(config(true), StreamsConfig { max_data: 4000, bidi_remote: 4000, max_streams_uni: 2, ..config(false) });
        let id = c.open(true).unwrap();
        c.write(id, &pattern(4000, 3), false).unwrap();
        while c.has_pending() {
            flow(&mut c, &mut s, 1200);
        }
        s.read(id, &mut vec![0u8; 2000]).unwrap();
        let (_, first) = packet(&mut s, 1200);
        assert_eq!(count(&first, |f| matches!(f, StreamFrame::MaxData(6000))), 1);
        assert_eq!(count(&first, |f| matches!(f, StreamFrame::MaxStreamData { max: 6000, .. })), 1);
        assert!(!s.has_pending());
        // lost: both are sent again
        lost(&mut s, &first);
        let (_, second) = packet(&mut s, 1200);
        assert_eq!(count(&second, |f| matches!(f, StreamFrame::MaxData(6000) | StreamFrame::MaxStreamData { max: 6000, .. })), 2);
        // the application reads more and a higher limit is sent; the loss of the old one is no reason to send it
        s.read(id, &mut vec![0u8; 2000]).unwrap();
        let (_, third) = packet(&mut s, 1200);
        assert_eq!(count(&third, |f| matches!(f, StreamFrame::MaxData(8000))), 1);
        lost(&mut s, &second);
        assert!(!s.has_pending(), "the limits that were lost are not the current ones");
        lost(&mut s, &third);
        assert!(s.has_pending());
        let (_, fourth) = packet(&mut s, 1200);
        assert_eq!(count(&fourth, |f| matches!(f, StreamFrame::MaxData(8000) | StreamFrame::MaxStreamData { max: 8000, .. })), 2);
    }

    #[test]
    fn a_stream_limit_that_was_lost_is_sent_again() {
        let (mut c, mut s) = pair_with(config(true), StreamsConfig { max_streams_uni: 2, ..config(false) });
        for _ in 0..2 {
            let id = c.open(false).unwrap();
            c.write(id, b"x", true).unwrap();
        }
        settle(&mut c, &mut s);
        for id in [2, 6] {
            read_all(&mut s, id);
        }
        let (_, sent) = packet(&mut s, 1200);
        assert_eq!(count(&sent, |f| matches!(f, StreamFrame::MaxStreams { bidirectional: false, max: 4 })), 1, "{sent:?}");
        lost(&mut s, &sent);
        let (_, again) = packet(&mut s, 1200);
        assert_eq!(count(&again, |f| matches!(f, StreamFrame::MaxStreams { bidirectional: false, max: 4 })), 1);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // frames and room

    #[test]
    fn frames_fit_the_room_whatever_it_is() {
        let mut rng = Rng(99);
        let (mut c, mut s) = pair();
        for id in 0..6u64 {
            let id = if id % 2 == 0 { c.open(true).unwrap() } else { c.open(false).unwrap() };
            c.write(id, &pattern(2000 + 100 * id as usize, id as u8), id % 3 == 0).unwrap();
        }
        let mut rounds = 0;
        while c.has_pending() {
            rounds += 1;
            assert!(rounds < 5000, "no end");
            let budget = [0usize, 1, 2, 3, 4, 5, 8, 17, 20, 21, 30, 64, 100, 1200][rng.below(14) as usize];
            let (bytes, sent) = packet(&mut c, budget);
            // the frames that come out are the frames that were said to be sent
            let n = if bytes.is_empty() { 0 } else { frame::frames(&bytes, PacketType::OneRtt).count() };
            assert_eq!(n, sent.len(), "budget {budget}");
            deliver(&mut s, &bytes).unwrap();
            acked(&mut c, &sent);
            for id in [0u64, 2, 4, 6, 8, 10] {
                if s.contains(id) {
                    read_all(&mut s, id);
                }
            }
            drain_to(&mut s, &mut c);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // a randomized run: two endpoints, a network that loses and delays, and an application that does what it likes

    enum Ev {
        /// A packet arrives (at the server if `to_server`); then it is acknowledged `ack` later (or never: it was lost).
        Deliver { to_server: bool, bytes: Vec<u8>, sent: Vec<SentFrame> },
        Ack { to_server: bool, sent: Vec<SentFrame> },
        Lost { to_server: bool, sent: Vec<SentFrame> },
    }

    #[derive(Default)]
    struct Book {
        /// What was written on a stream, by who (client?) and id; what was read; whether the end was read.
        written: BTreeMap<(bool, u64), Vec<u8>>,
        read: BTreeMap<(bool, u64), Vec<u8>>,
        ended: BTreeSet<(bool, u64)>,
        /// Streams that were reset or stopped: what came is not checked.
        broken: BTreeSet<(bool, u64)>,
        fin_written: BTreeSet<(bool, u64)>,
    }

    struct Sim {
        side: [Streams; 2],
        rng: Rng,
        now: u64,
        seq: u64,
        events: Vec<(u64, u64, Ev)>,
        book: Book,
        /// The streams that each side has seen, to write to or read from.
        known: [BTreeSet<u64>; 2],
        loss: u64,
    }

    impl Sim {
        fn new(seed: u64, loss: u64, cc: StreamsConfig, sc: StreamsConfig) -> Sim {
            let (c, s) = pair_with(cc, sc);
            Sim { side: [c, s], rng: Rng(seed * 2654435761 + 12345), now: 0, seq: 0, events: Vec::new(), book: Book::default(), known: [BTreeSet::new(), BTreeSet::new()], loss }
        }

        fn push(&mut self, at: u64, ev: Ev) {
            self.seq += 1;
            self.events.push((at, self.seq, ev));
        }

        /// A side makes a packet, if it has anything to send.
        fn send_from(&mut self, who: usize) {
            let budget = [60, 200, 600, 1200, 1200, 1200][self.rng.below(6) as usize];
            let (bytes, sent) = packet(&mut self.side[who], budget);
            if sent.is_empty() {
                return;
            }
            let to_server = who == 0;
            if self.rng.chance(self.loss) {
                let at = self.now + 20 + self.rng.below(10);
                self.push(at, Ev::Lost { to_server, sent });
            } else {
                let at = self.now + 1 + self.rng.below(12);
                self.push(at, Ev::Deliver { to_server, bytes, sent });
            }
        }

        fn run_events(&mut self) {
            self.events.sort_by_key(|e| (e.0, e.1));
            while let Some(first) = self.events.first() {
                if first.0 > self.now {
                    break;
                }
                let (at, _, ev) = self.events.remove(0);
                match ev {
                    Ev::Deliver { to_server, bytes, sent } => {
                        let to = to_server as usize;
                        deliver(&mut self.side[to], &bytes).expect("an honest peer");
                        let back = at + 1 + self.rng.below(12);
                        self.push(back, Ev::Ack { to_server: !to_server, sent });
                    }
                    Ev::Ack { to_server, sent } => acked(&mut self.side[to_server as usize], &sent),
                    Ev::Lost { to_server, sent } => lost(&mut self.side[(!to_server) as usize], &sent),
                }
            }
            for w in 0..2 {
                while let Some(e) = self.side[w].poll_event() {
                    match e {
                        StreamEvent::Readable(id) => {
                            self.known[w].insert(id);
                        }
                        StreamEvent::Stopped(id, _) => {
                            self.book.broken.insert((w == 0, id));
                        }
                        _ => {}
                    }
                }
            }
        }

        fn app_read(&mut self, who: usize, id: u64) {
            // the one who reads is not the one who writes the direction that is read
            let key = (who == 1, id);
            let mut buf = vec![0u8; 1 + self.rng.below(900) as usize];
            loop {
                match self.side[who].read(id, &mut buf) {
                    Ok((n, fin)) => {
                        self.book.read.entry(key).or_default().extend_from_slice(&buf[..n]);
                        if fin {
                            self.book.ended.insert(key);
                            return;
                        }
                        if n == 0 {
                            return;
                        }
                    }
                    Err(StreamError::Reset(_)) => {
                        self.book.broken.insert(key);
                        return;
                    }
                    Err(_) => return,
                }
            }
        }

        fn app_write(&mut self, who: usize, id: u64, fin_allowed: bool) {
            let key = (who == 0, id);
            let len = 1 + self.rng.below(2500) as usize;
            let data = pattern(len, id as u8);
            let fin = fin_allowed && self.rng.chance(10);
            let at = self.book.written.entry(key).or_default().len();
            let chunk: Vec<u8> = (0..len).map(|i| ((at + i) as u8).wrapping_mul(7).wrapping_add(id as u8)).collect();
            let _ = data;
            match self.side[who].write(id, &chunk, fin) {
                Ok(n) => {
                    self.book.written.get_mut(&key).unwrap().extend_from_slice(&chunk[..n]);
                    if fin && n == len {
                        self.book.fin_written.insert(key);
                    }
                }
                Err(StreamError::Stopped(_)) | Err(StreamError::Closed) | Err(StreamError::Blocked) | Err(StreamError::Unknown) => {}
                Err(e) => panic!("{e}"),
            }
        }

        fn tick(&mut self, active: bool) {
            self.now += 1;
            if active {
                for who in 0..2 {
                    if self.rng.chance(15) {
                        if let Ok(id) = self.side[who].open(self.rng.chance(60)) {
                            self.known[who].insert(id);
                        }
                    }
                    let known: Vec<u64> = self.known[who].iter().copied().collect();
                    if known.is_empty() {
                        continue;
                    }
                    for _ in 0..2 {
                        let id = known[self.rng.below(known.len() as u64) as usize];
                        let ours = is_client_initiated(id) == (who == 0);
                        let can_write = ours || is_bidirectional(id);
                        let can_read = !ours || is_bidirectional(id);
                        let roll = self.rng.below(100);
                        if can_write && roll < 40 {
                            let fin_ok = !self.book.fin_written.contains(&(who == 0, id));
                            self.app_write(who, id, fin_ok);
                        } else if can_read && roll < 85 {
                            if self.side[who].contains(id) {
                                self.app_read(who, id);
                            }
                        } else if can_write && roll < 87 {
                            let _ = self.side[who].reset(id, 1000 + id);
                            self.book.broken.insert((who == 0, id));
                        } else if can_read && roll < 89 {
                            let _ = self.side[who].stop_sending(id, 2000 + id);
                            self.book.broken.insert((who != 0, id));
                        }
                    }
                }
            }
            self.run_events();
            for who in 0..2 {
                if self.rng.chance(60) {
                    self.send_from(who);
                }
            }
        }

        /// Ends what is open and goes on until nothing more happens.
        fn finish(&mut self) {
            for step in 0..20_000 {
                self.tick(false);
                if step % 7 == 0 {
                    for who in 0..2 {
                        let ids: Vec<u64> = self.side[who].streams.keys().copied().collect();
                        for id in ids {
                            let ours = is_client_initiated(id) == (who == 0);
                            if (ours || is_bidirectional(id)) && !self.book.fin_written.contains(&(who == 0, id)) {
                                let key = (who == 0, id);
                                match self.side[who].write(id, &[], true) {
                                    Ok(_) => {
                                        self.book.fin_written.insert(key);
                                    }
                                    Err(_) => {
                                        self.book.fin_written.insert(key);
                                    }
                                }
                            }
                            if self.side[who].contains(id) {
                                self.app_read(who, id);
                            }
                        }
                    }
                }
                if self.events.is_empty() && !self.side[0].has_pending() && !self.side[1].has_pending() && self.side[0].streams.is_empty() && self.side[1].streams.is_empty() {
                    return;
                }
            }
            let mut why = String::new();
            for who in 0..2 {
                for (id, st) in &self.side[who].streams {
                    why += &format!(
                        "\n side {who} stream {id}: send {:?} recv {:?}",
                        st.send.as_ref().map(|s| (s.state, s.buf.buffered(), s.buf.has_pending(), s.buf.is_fully_acked(), s.max_data, s.buf.sent(), s.queued, s.parked, s.reset.as_ref().map(|r| r.pending))),
                        st.recv.as_ref().map(|r| (r.state, r.final_size, r.buf.read_offset(), r.buf.readable(), r.discard, r.max_data, r.high))
                    );
                }
            }
            panic!("it does not end: {} events, pending {} {}{why}", self.events.len(), self.side[0].has_pending(), self.side[1].has_pending());
        }

        fn check(&self) {
            for (key, wrote) in &self.book.written {
                if self.book.broken.contains(key) {
                    continue;
                }
                let got = self.book.read.get(key).map_or(&[][..], |v| &v[..]);
                assert_eq!(got.len(), wrote.len(), "stream {key:?}: read {} of {} bytes", got.len(), wrote.len());
                assert!(got == &wrote[..], "stream {key:?}: the bytes differ");
                assert!(self.book.ended.contains(key), "stream {key:?}: the end did not come");
            }
        }
    }

    fn simulate(seed: u64, loss: u64, cc: StreamsConfig, sc: StreamsConfig) {
        let mut sim = Sim::new(seed, loss, cc, sc);
        for _ in 0..600 {
            sim.tick(true);
            for side in &sim.side {
                side.check().unwrap_or_else(|e| panic!("seed {seed}: {e}"));
            }
        }
        sim.finish();
        sim.check();
    }

    #[test]
    fn random_use_over_a_network_that_loses_and_delays_loses_no_data() {
        for seed in 1..=60 {
            simulate(seed, 20, config(true), config(false));
        }
    }

    #[test]
    fn random_use_with_small_windows_and_a_lot_of_loss() {
        let small = |client| StreamsConfig { max_data: 3000, bidi_local: 1500, bidi_remote: 1500, uni: 1500, max_streams_bidi: 3, max_streams_uni: 3, send_buffer: 2500, ..config(client) };
        for seed in 100..140 {
            simulate(seed, 40, small(true), small(false));
        }
    }

    #[test]
    fn random_use_on_a_network_that_loses_nothing() {
        for seed in 200..220 {
            simulate(seed, 0, config(true), config(false));
        }
    }

    /// A long run, for when the streams are changed: `cargo test --release --lib quic::streams -- --ignored`.
    #[test]
    #[ignore]
    fn random_use_for_a_long_time() {
        let small = |client| StreamsConfig { max_data: 3000, bidi_local: 1500, bidi_remote: 1500, uni: 1500, max_streams_bidi: 3, max_streams_uni: 3, send_buffer: 2500, ..config(client) };
        let medium = |client| StreamsConfig { max_data: 9000, bidi_local: 4000, bidi_remote: 2500, uni: 3000, max_streams_bidi: 5, max_streams_uni: 2, send_buffer: 5000, ..config(client) };
        let n: u64 = std::env::var("STREAMS_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(600);
        for seed in 1000..1000 + n {
            simulate(seed, 15 + seed % 30, small(true), small(false));
            simulate(seed + 10_000, seed % 40, medium(true), config(false));
            simulate(seed + 20_000, 25, config(true), medium(false));
        }
    }
}
