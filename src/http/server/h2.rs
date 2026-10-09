//! HTTP/2 for the server (RFC 9113): the protocol as a state machine with no I/O ([`Engine`]), and a driver that reads the
//! client's frames on the connection's thread and runs each request's handler on a thread of its own.
//!
//! The engine and everything the threads share are under one lock that is never held across I/O. Request bodies wait in
//! a buffer per stream that the windows the server announced bound: the client is given credit back only as the handler
//! reads, so a handler that does not read stops its client rather than filling memory. Response data waits in a buffer
//! per stream (`H2Config::stream_send_buffer`; a handler's writes wait when it is full) and is framed as the client's
//! windows allow, a frame per stream in turn. Whoever has frames to send sends them under a second lock, as the TLS split
//! does: the reading thread only if nobody else is sending (unless what is waiting is past a high-water mark: then it
//! waits, and so stops reading a client that sends faster than it reads).
//!
//! The limits on what a client can make the server do are in [`H2Config`].

use super::super::h2::frame::{self, flag, kind, setting, ErrorCode, Frame, FrameError, Header, DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW, HEADER_LEN, MAX_FRAME_SIZE_LIMIT, MAX_WINDOW};
use super::super::h2::hpack::{Decoder, Encoder, FieldRef};
use super::h1::valid_authority;
use super::runtime::{Ctl, GoAway, Pending};
use super::{call, response_head, Body, BodySink, BodySource, BodyWriter, ConnInfo, H2Config, Handler, HttpConfig, Request, Response, ResponseBody, Upgraded, Version};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

pub(super) const PREFACE: &[u8] = frame::PREFACE;

/// Unsent output past which the reading thread waits to send (and so stops reading).
const HIGH_WATER: usize = 256 * 1024;
/// Closed streams remembered, to tell a frame that was in flight from one that is wrong.
const REMEMBER_CLOSED: usize = 512;

// ------------------------------------------------------------------------------------------------ floods

/// A budget of frames of one kind: `cap`, refilled at a tenth of it per second.
#[derive(Debug)]
struct Budget {
    left: f64,
    cap: f64,
    at: Instant,
}

impl Budget {
    fn new(cap: u32) -> Budget {
        Budget { left: cap as f64, cap: cap as f64, at: Instant::now() }
    }

    /// Takes one; false when there is none left.
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.left = (self.left + now.duration_since(self.at).as_secs_f64() * self.cap / 10.0).min(self.cap);
        self.at = now;
        if self.left < 1.0 {
            return false;
        }
        self.left -= 1.0;
        true
    }
}

#[derive(Debug)]
struct Budgets {
    resets: Budget,
    settings: Budget,
    pings: Budget,
    empty: Budget,
    priority: Budget,
    small_updates: Budget,
}

// ------------------------------------------------------------------------------------------------ the engine

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closed {
    /// Both sides ended it.
    Ended,
    /// The client reset it.
    ClientReset,
    /// We reset it: frames the client sent before it knew are ignored.
    WeReset,
}

struct Stream {
    // the request
    recv: VecDeque<u8>,
    recv_window: i64,
    /// Body bytes the handler has read and the client has not been given credit for.
    unacked: u32,
    remote_ended: bool,
    trailers: Vec<(String, String)>,
    expected: Option<u64>,
    received: u64,
    /// Why the body cannot be read any further, if it cannot.
    body_error: Option<String>,
    /// `Expect: 100-continue`, and the 100 not sent yet.
    continue_pending: bool,
    // the response
    send_window: i64,
    pending: Vec<u8>,
    pending_pos: usize,
    end_pending: bool,
    trailers_pending: Option<Vec<(String, String)>>,
    head_sent: bool,
    local_ended: bool,
    /// Reset, by either side: reads and writes fail.
    reset: bool,
    /// The client reset it: what it sends on the stream after that is a stream error (STREAM_CLOSED), where what was in
    /// flight when we reset it is ignored.
    reset_by_client: bool,
    /// The handler has returned (or there is none).
    handler_done: bool,
    /// The request body is no longer wanted: what comes is credited back and dropped.
    discard: bool,
    /// The handler said `Connection: close`: GOAWAY once this response has ended.
    goaway_after: bool,
    /// Since when response data has been waiting with no window to send it in.
    stalled_since: Option<Instant>,
    /// The response is whole and the handler done, but the client has not ended the request: the stream is kept a
    /// while, so that what the client sends on it is still checked (and a body it goes on sending is stopped).
    lingering_since: Option<Instant>,
}

impl Stream {
    fn queued(&self) -> usize {
        self.pending.len() - self.pending_pos
    }
}

struct Block {
    stream: u32,
    end_stream: bool,
    bytes: Vec<u8>,
    continuations: u32,
}

/// A new request, for a handler.
pub(super) struct NewStream {
    id: u32,
    method: String,
    scheme: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    end_stream: bool,
}

impl NewStream {
    #[cfg(pratique_fuzzing)]
    pub(super) fn id(&self) -> u32 {
        self.id
    }
}

/// The connection was lost.
#[derive(Debug)]
pub(super) struct Lost {
    pub(super) code: u32,
    pub(super) reason: String,
}

/// The server side of an HTTP/2 connection, with no I/O.
pub(super) struct Engine {
    cfg: H2Config,
    max_header_bytes: usize,
    max_headers: usize,
    max_body: Option<u64>,
    decoder: Decoder,
    encoder: Encoder,
    inbound: Vec<u8>,
    pub(super) out: Vec<u8>,
    got_settings: bool,
    /// Our SETTINGS were acknowledged: the stream window is the one announced, not the default.
    settings_acked: bool,
    streams: HashMap<u32, Stream>,
    closed: HashMap<u32, Closed>,
    closed_order: VecDeque<u32>,
    highest: u32,
    send_window: i64,
    recv_window: i64,
    conn_unacked: u32,
    peer_initial_window: i64,
    peer_max_frame: usize,
    block: Option<Block>,
    peer_goaway: bool,
    /// We said GOAWAY with no error: no new streams, and the connection ends when those under way are done.
    going_away: bool,
    /// Since when no stream has been open (frames that are not requests do not end the idle time).
    idle_since: Option<Instant>,
    dead: bool,
    budgets: Budgets,
    /// The stream after the one last given a frame, for turns.
    turn: u32,
}

impl Engine {
    pub(super) fn new(config: &HttpConfig) -> Engine {
        let cfg = config.h2.clone();
        let mut e = Engine {
            decoder: Decoder::new(cfg.header_table_size as usize, config.max_header_bytes),
            encoder: Encoder::new(),
            inbound: Vec::new(),
            out: Vec::new(),
            got_settings: false,
            settings_acked: false,
            streams: HashMap::new(),
            closed: HashMap::new(),
            closed_order: VecDeque::new(),
            highest: 0,
            send_window: DEFAULT_WINDOW as i64,
            recv_window: cfg.connection_window.max(DEFAULT_WINDOW) as i64,
            conn_unacked: 0,
            peer_initial_window: DEFAULT_WINDOW as i64,
            peer_max_frame: DEFAULT_MAX_FRAME_SIZE as usize,
            block: None,
            peer_goaway: false,
            going_away: false,
            idle_since: Some(Instant::now()),
            dead: false,
            budgets: Budgets {
                resets: Budget::new(cfg.flood_resets),
                settings: Budget::new(cfg.flood_settings),
                pings: Budget::new(cfg.flood_pings),
                empty: Budget::new(cfg.flood_empty),
                priority: Budget::new(cfg.flood_priority),
                small_updates: Budget::new(cfg.flood_small_updates),
            },
            turn: 0,
            max_header_bytes: config.max_header_bytes,
            max_headers: config.max_headers,
            max_body: config.max_body,
            cfg,
        };
        let c = &e.cfg;
        let settings = [
            (setting::HEADER_TABLE_SIZE, c.header_table_size),
            (setting::MAX_CONCURRENT_STREAMS, c.max_concurrent_streams),
            (setting::INITIAL_WINDOW_SIZE, c.stream_window.min(MAX_WINDOW)),
            (setting::MAX_FRAME_SIZE, c.max_frame_size.clamp(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT)),
            (setting::MAX_HEADER_LIST_SIZE, config.max_header_bytes as u32),
        ];
        frame::write_settings(&mut e.out, &settings);
        if c.connection_window > DEFAULT_WINDOW {
            let more = c.connection_window.min(MAX_WINDOW) - DEFAULT_WINDOW;
            frame::write_window_update(&mut e.out, 0, more);
        }
        e
    }

    fn max_frame(&self) -> u32 {
        self.cfg.max_frame_size.clamp(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT)
    }

    /// The window a new stream starts with on our side: until our SETTINGS are acknowledged the client may go by the
    /// default.
    fn initial_recv_window(&self) -> i64 {
        let announced = self.cfg.stream_window.min(MAX_WINDOW) as i64;
        if self.settings_acked { announced } else { announced.max(DEFAULT_WINDOW as i64) }
    }

    pub(super) fn is_dead(&self) -> bool {
        self.dead
    }

    /// Since when the connection has had nothing under way (no stream, or only streams whose responses are whole), if it
    /// has nothing.
    pub(super) fn idle_since(&self) -> Option<Instant> {
        let mut since = self.idle_since;
        for s in self.streams.values() {
            let t = s.lingering_since?;
            since = Some(since.map_or(t, |x| x.max(t)));
        }
        since.or(Some(Instant::now()))
    }

    /// The earliest time a stream began to wait for a window, if one is waiting.
    pub(super) fn stalled_since(&self) -> Option<Instant> {
        self.streams.values().filter(|s| !s.reset && !s.local_ended).filter_map(|s| s.stalled_since).min()
    }

    /// Resets the streams that have waited for a window since before `before`; how many.
    pub(super) fn reset_stalled(&mut self, before: Instant) -> usize {
        let stalled: Vec<u32> = self.streams.iter().filter(|(_, s)| !s.reset && !s.local_ended && s.stalled_since.is_some_and(|t| t <= before)).map(|(&id, _)| id).collect();
        for &id in &stalled {
            self.reset(id, ErrorCode::CANCEL);
        }
        stalled.len()
    }

    /// Refuses a stream that was taken but cannot be run (the server has no place for its handler).
    pub(super) fn refuse(&mut self, id: u32) {
        frame::write_rst_stream(&mut self.out, id, ErrorCode::REFUSED_STREAM);
        self.streams.remove(&id);
        self.remember(id, Closed::WeReset);
        if self.streams.is_empty() {
            self.idle_since = Some(Instant::now());
        }
    }

    /// The largest frame the client takes.
    #[cfg(pratique_fuzzing)]
    pub(super) fn peer_max_frame_for_fuzz(&self) -> usize {
        self.peer_max_frame
    }

    /// Whether the connection has nothing left to do: we said GOAWAY and every stream is over. (A client's GOAWAY only
    /// says it opens no more streams: it closes the connection when it is done with it.)
    pub(super) fn is_finished(&self) -> bool {
        self.going_away && self.streams.is_empty()
    }

    /// Says GOAWAY with no error (the streams opened so far are answered, no others), once.
    pub(super) fn go_away(&mut self) {
        if !self.going_away && !self.dead {
            self.going_away = true;
            frame::write_goaway(&mut self.out, self.highest, ErrorCode::NO_ERROR, b"");
            let lingering: Vec<u32> = self.streams.iter().filter(|(_, s)| s.lingering_since.is_some()).map(|(&id, _)| id).collect();
            for id in lingering {
                self.stop_lingering(id);
            }
        }
    }

    fn lose(&mut self, code: ErrorCode, reason: impl Into<String>) -> Lost {
        let reason = reason.into();
        if !self.dead {
            frame::write_goaway(&mut self.out, self.highest, code, reason.as_bytes());
            self.dead = true;
        }
        for s in self.streams.values_mut() {
            s.reset = true;
        }
        Lost { code: code.0, reason }
    }

    fn remember(&mut self, id: u32, how: Closed) {
        if self.closed.insert(id, how).is_none() {
            self.closed_order.push_back(id);
            if self.closed_order.len() > REMEMBER_CLOSED {
                if let Some(old) = self.closed_order.pop_front() {
                    self.closed.remove(&old);
                }
            }
        }
    }

    /// Resets a stream (a stream error, or the handler failed).
    fn reset(&mut self, id: u32, code: ErrorCode) {
        frame::write_rst_stream(&mut self.out, id, code);
        if let Some(s) = self.streams.get_mut(&id) {
            s.reset = true;
            s.discard = true;
            let credit = s.recv.len() as u32 + s.unacked;
            s.recv.clear();
            s.unacked = 0;
            self.credit_connection(credit);
        }
        self.remember(id, Closed::WeReset);
        self.maybe_remove(id);
    }

    /// Takes a stream off once its handler is done and both sides are over with it.
    fn maybe_remove(&mut self, id: u32) {
        self.remove_if_done(id);
        if self.streams.is_empty() && self.idle_since.is_none() {
            self.idle_since = Some(Instant::now());
        }
    }

    fn remove_if_done(&mut self, id: u32) {
        if self.streams.get(&id).is_some_and(|s| s.goaway_after && (s.local_ended || s.reset)) {
            // after the response's end, not before it: a client that takes GOAWAY as the end (python-h2) must have it all
            self.go_away();
        }
        let Some(s) = self.streams.get(&id) else { return };
        if !s.handler_done {
            return;
        }
        if s.reset {
            self.streams.remove(&id);
            return;
        }
        if !s.local_ended {
            return;
        }
        if !s.remote_ended {
            // a whole response before the whole request: the stream lingers, still checked, until the client ends it, or
            // sends more of a body nobody will read (then it is asked to stop: RFC 9113 section 8.1), or the connection
            // goes away
            if self.going_away {
                self.stop_lingering(id);
            } else if let Some(s) = self.streams.get_mut(&id) {
                s.lingering_since.get_or_insert_with(Instant::now);
            }
            return;
        }
        self.streams.remove(&id);
        self.remember(id, Closed::Ended);
    }

    /// Asks the client to stop sending on a stream whose response is whole (RST_STREAM with no error), and drops it.
    fn stop_lingering(&mut self, id: u32) {
        let Some(s) = self.streams.remove(&id) else { return };
        frame::write_rst_stream(&mut self.out, id, ErrorCode::NO_ERROR);
        self.credit_connection(s.recv.len() as u32 + s.unacked);
        self.remember(id, Closed::WeReset);
        if self.streams.is_empty() {
            self.idle_since = Some(Instant::now());
        }
    }

    /// Gives the client credit on the connection for `n` bytes taken off it (read, or dropped).
    fn credit_connection(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.conn_unacked += n;
        let window = self.cfg.connection_window.clamp(DEFAULT_WINDOW, MAX_WINDOW);
        if self.conn_unacked >= window / 2 {
            let credit = std::mem::take(&mut self.conn_unacked);
            self.recv_window += credit as i64;
            frame::write_window_update(&mut self.out, 0, credit);
        }
    }

    /// Hands bytes the client sent to the engine; returns the new requests. An error means the connection is lost (the
    /// GOAWAY is in the output).
    pub(super) fn receive(&mut self, data: &[u8]) -> Result<Vec<NewStream>, Lost> {
        let mut new = Vec::new();
        if self.dead {
            return Ok(new);
        }
        self.inbound.extend_from_slice(data);
        let buf = std::mem::take(&mut self.inbound);
        let mut pos = 0;
        let result = loop {
            if buf.len() - pos < HEADER_LEN {
                break Ok(());
            }
            let header = Header::parse(buf[pos..pos + HEADER_LEN].try_into().expect("nine bytes"));
            if header.length > self.max_frame() {
                break Err(self.lose(ErrorCode::FRAME_SIZE_ERROR, "a frame larger than the size this server announced"));
            }
            let end = pos + HEADER_LEN + header.length as usize;
            if buf.len() < end {
                break Ok(());
            }
            let payload = &buf[pos + HEADER_LEN..end];
            pos = end;
            if !self.got_settings && !(header.kind == kind::SETTINGS && !header.has(flag::ACK)) {
                break Err(self.lose(ErrorCode::PROTOCOL_ERROR, "the client's first frame is not SETTINGS"));
            }
            // a stream may not depend on itself (RFC 9113 section 5.3.1); the frame parser drops the priority fields
            if let Some(dep) = self_dependency(&header, payload) {
                if dep == header.stream {
                    if header.kind == kind::HEADERS {
                        break Err(self.lose(ErrorCode::PROTOCOL_ERROR, "a stream that depends on itself"));
                    }
                    self.reset(header.stream, ErrorCode::PROTOCOL_ERROR);
                    continue;
                }
            }
            let step = match frame::parse(&header, payload) {
                Ok(f) => self.handle(f, &mut new),
                Err(FrameError { code, stream: None, reason }) => Err(self.lose(code, reason)),
                Err(FrameError { code, stream: Some(id), reason }) => {
                    if id > self.highest {
                        // no RST_STREAM may be sent on a stream that is idle: the error is the connection's
                        Err(self.lose(code, reason))
                    } else {
                        self.reset(id, code);
                        Ok(())
                    }
                }
            };
            if let Err(e) = step {
                break Err(e);
            }
            if self.dead {
                break Ok(());
            }
        };
        self.inbound = buf[pos..].to_vec();
        result.map(|()| new)
    }

    fn handle(&mut self, f: Frame<'_>, new: &mut Vec<NewStream>) -> Result<(), Lost> {
        if let Some(block) = &self.block {
            match &f {
                Frame::Continuation { stream, .. } if *stream == block.stream => {}
                _ => return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "a frame in the middle of a header block")),
            }
        }
        match f {
            Frame::Data { stream, end_stream, data, flow_len } => self.on_data(stream, end_stream, data, flow_len),
            Frame::Headers { stream, end_stream, end_headers, fragment } => {
                if stream % 2 == 0 {
                    return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "HEADERS on an even stream"));
                }
                if fragment.is_empty() && !end_headers && !self.budgets.empty.take() {
                    return Err(self.calm("empty HEADERS frames"));
                }
                self.block = Some(Block { stream, end_stream, bytes: Vec::new(), continuations: 0 });
                self.on_fragment(end_headers, fragment, new)
            }
            Frame::Continuation { end_headers, fragment, .. } => {
                let Some(block) = self.block.as_mut() else {
                    return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "CONTINUATION with no header block"));
                };
                block.continuations += 1;
                if block.continuations > self.cfg.max_continuations {
                    return Err(self.calm("a header block in more CONTINUATION frames than this server takes"));
                }
                if fragment.is_empty() && !end_headers && !self.budgets.empty.take() {
                    return Err(self.calm("empty CONTINUATION frames"));
                }
                self.on_fragment(end_headers, fragment, new)
            }
            Frame::Priority { .. } | Frame::Unknown { .. } => {
                if !self.budgets.priority.take() {
                    return Err(self.calm("PRIORITY or unknown frames"));
                }
                Ok(())
            }
            Frame::RstStream { stream, .. } => {
                if stream > self.highest {
                    return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "RST_STREAM on a stream that is idle"));
                }
                if let Some(s) = self.streams.get_mut(&stream) {
                    let unfinished = !s.handler_done || !s.local_ended;
                    s.reset = true;
                    s.reset_by_client = true;
                    s.discard = true;
                    let credit = s.recv.len() as u32 + s.unacked;
                    s.recv.clear();
                    s.unacked = 0;
                    self.credit_connection(credit);
                    self.remember(stream, Closed::ClientReset);
                    self.maybe_remove(stream);
                    if unfinished && !self.budgets.resets.take() {
                        return Err(self.calm("streams reset by the client (CVE-2023-44487)"));
                    }
                } else if self.closed.get(&stream) != Some(&Closed::WeReset) {
                    self.remember(stream, Closed::ClientReset);
                }
                Ok(())
            }
            Frame::Settings { ack, values } => {
                if ack {
                    self.settings_acked = true;
                    return Ok(());
                }
                if !self.budgets.settings.take() {
                    return Err(self.calm("SETTINGS frames"));
                }
                self.on_settings(&values)
            }
            Frame::PushPromise { .. } => Err(self.lose(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE from a client")),
            Frame::Ping { ack, data } => {
                if !ack {
                    if !self.budgets.pings.take() {
                        return Err(self.calm("PING frames"));
                    }
                    frame::write_ping(&mut self.out, true, data);
                }
                Ok(())
            }
            Frame::GoAway { .. } => {
                self.peer_goaway = true;
                Ok(())
            }
            Frame::WindowUpdate { stream, increment } => {
                // a client that reads with a window of a few bytes makes the server frame its data a few bytes at a time
                // (CVE-2019-9511); small windows of a kilobyte or so are a client's choice (Go's MaxReceiveBufferPerStream)
                if increment < 128 && !self.budgets.small_updates.take() {
                    return Err(self.calm("window updates of a few bytes"));
                }
                if stream == 0 {
                    self.send_window += increment as i64;
                    if self.send_window > MAX_WINDOW as i64 {
                        return Err(self.lose(ErrorCode::FLOW_CONTROL_ERROR, "the connection window went over 2^31 - 1"));
                    }
                } else if stream > self.highest {
                    return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE on a stream that is idle"));
                } else if let Some(s) = self.streams.get_mut(&stream) {
                    s.send_window += increment as i64;
                    if s.send_window > MAX_WINDOW as i64 {
                        self.reset(stream, ErrorCode::FLOW_CONTROL_ERROR);
                    }
                }
                self.pump();
                Ok(())
            }
        }
    }

    fn calm(&mut self, what: &str) -> Lost {
        self.lose(ErrorCode::ENHANCE_YOUR_CALM, format!("too many {what}"))
    }

    fn on_settings(&mut self, values: &[(u16, u32)]) -> Result<(), Lost> {
        self.got_settings = true;
        for &(id, value) in values {
            match id {
                setting::HEADER_TABLE_SIZE => self.encoder.set_peer_table_size(value as usize),
                setting::ENABLE_PUSH if value > 1 => return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH is neither 0 nor 1")),
                setting::INITIAL_WINDOW_SIZE => {
                    if value > MAX_WINDOW {
                        return Err(self.lose(ErrorCode::FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE over 2^31 - 1"));
                    }
                    let delta = value as i64 - self.peer_initial_window;
                    self.peer_initial_window = value as i64;
                    let mut over = Vec::new();
                    for (&id, s) in self.streams.iter_mut() {
                        s.send_window += delta;
                        if s.send_window > MAX_WINDOW as i64 {
                            over.push(id);
                        }
                    }
                    if !over.is_empty() {
                        return Err(self.lose(ErrorCode::FLOW_CONTROL_ERROR, "a stream window went over 2^31 - 1"));
                    }
                }
                setting::MAX_FRAME_SIZE => {
                    if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&value) {
                        return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE out of range"));
                    }
                    self.peer_max_frame = value as usize;
                }
                _ => {}
            }
        }
        frame::write_settings_ack(&mut self.out);
        self.pump();
        Ok(())
    }

    fn on_data(&mut self, id: u32, end_stream: bool, data: &[u8], flow_len: u32) -> Result<(), Lost> {
        if id > self.highest {
            return Err(self.lose(ErrorCode::PROTOCOL_ERROR, "DATA on a stream that is idle"));
        }
        if flow_len as i64 > self.recv_window {
            return Err(self.lose(ErrorCode::FLOW_CONTROL_ERROR, "the client sent more than the connection window allows"));
        }
        self.recv_window -= flow_len as i64;
        if data.is_empty() && !end_stream && !self.budgets.empty.take() {
            return Err(self.calm("empty DATA frames"));
        }
        let Some(s) = self.streams.get_mut(&id) else {
            self.credit_connection(flow_len);
            return match self.closed.get(&id) {
                Some(Closed::WeReset) => Ok(()),
                Some(Closed::ClientReset) => {
                    frame::write_rst_stream(&mut self.out, id, ErrorCode::STREAM_CLOSED);
                    Ok(())
                }
                _ => Err(self.lose(ErrorCode::STREAM_CLOSED, "DATA on a stream that is closed")),
            };
        };
        if s.lingering_since.is_some() && !data.is_empty() {
            // more of a body that nobody will read: the client is asked to stop
            self.credit_connection(flow_len);
            self.stop_lingering(id);
            return Ok(());
        }
        if s.reset {
            let by_client = s.reset_by_client;
            self.credit_connection(flow_len);
            if by_client {
                frame::write_rst_stream(&mut self.out, id, ErrorCode::STREAM_CLOSED);
            }
            return Ok(());
        }
        if s.remote_ended {
            // both ends done (only the handler's return is awaited): closed, as when it is gone
            let closed = s.local_ended;
            self.credit_connection(flow_len);
            if closed {
                return Err(self.lose(ErrorCode::STREAM_CLOSED, "DATA on a stream that is closed"));
            }
            self.reset(id, ErrorCode::STREAM_CLOSED);
            return Ok(());
        }
        if flow_len as i64 > s.recv_window {
            self.credit_connection(flow_len);
            self.reset(id, ErrorCode::FLOW_CONTROL_ERROR);
            return Ok(());
        }
        s.recv_window -= flow_len as i64;
        s.received += data.len() as u64;
        if s.expected.is_some_and(|n| s.received > n || (end_stream && s.received != n)) {
            self.credit_connection(flow_len);
            self.reset(id, ErrorCode::PROTOCOL_ERROR);
            return Ok(());
        }
        if self.max_body.is_some_and(|max| s.received > max) {
            s.body_error = Some("the request body is larger than this server takes".into());
            self.credit_connection(flow_len);
            self.reset(id, ErrorCode::CANCEL);
            return Ok(());
        }
        // padding is credited back at once; the data when it is read (or at once, if nobody will read it)
        let padding = flow_len - data.len() as u32;
        let s = self.streams.get_mut(&id).expect("the stream");
        if s.discard {
            s.recv_window += flow_len as i64;
            let stream_credit = flow_len;
            if !end_stream && stream_credit > 0 {
                frame::write_window_update(&mut self.out, id, stream_credit);
            }
            self.credit_connection(flow_len);
        } else {
            s.recv.extend(data);
            s.unacked += padding;
            self.credit_connection(padding);
        }
        let s = self.streams.get_mut(&id).expect("the stream");
        if end_stream {
            s.remote_ended = true;
        }
        self.maybe_remove(id);
        Ok(())
    }

    fn on_fragment(&mut self, end_headers: bool, fragment: &[u8], new: &mut Vec<NewStream>) -> Result<(), Lost> {
        let limit = self.max_header_bytes + 1024;
        let block = self.block.as_mut().expect("a block in progress");
        if block.bytes.len() + fragment.len() > limit {
            return Err(self.calm("bytes of header block (CVE-2024-27316)"));
        }
        block.bytes.extend_from_slice(fragment);
        if !end_headers {
            return Ok(());
        }
        let Block { stream, end_stream, bytes, .. } = self.block.take().expect("a block in progress");
        let mut decoded = Vec::new();
        // the block is decoded whatever becomes of the stream, so that the table stays the client's
        let within = match self.decoder.decode(&bytes, &mut decoded) {
            Ok(w) => w,
            Err(e) => return Err(self.lose(ErrorCode::COMPRESSION_ERROR, e.to_string())),
        };
        let mut fields = Vec::with_capacity(decoded.len());
        let mut utf8 = true;
        for f in decoded {
            match (String::from_utf8(f.name), String::from_utf8(f.value)) {
                (Ok(n), Ok(v)) => fields.push((n, v)),
                _ => utf8 = false,
            }
        }
        self.on_header_block(stream, end_stream, fields, within && utf8, utf8, new)
    }

    fn on_header_block(&mut self, id: u32, end_stream: bool, fields: Vec<(String, String)>, within: bool, utf8: bool, new: &mut Vec<NewStream>) -> Result<(), Lost> {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.reset {
                if s.reset_by_client {
                    frame::write_rst_stream(&mut self.out, id, ErrorCode::STREAM_CLOSED);
                }
                return Ok(());
            }
            // trailers
            if s.remote_ended {
                // both ends done (only the handler's return is awaited): closed, as when it is gone
                if s.local_ended {
                    return Err(self.lose(ErrorCode::STREAM_CLOSED, "HEADERS on a stream that is closed"));
                }
                self.reset(id, ErrorCode::STREAM_CLOSED);
                return Ok(());
            }
            if !end_stream || !within || trailer_fault(&fields).is_some() || s.expected.is_some_and(|n| s.received != n) {
                self.reset(id, ErrorCode::PROTOCOL_ERROR);
                return Ok(());
            }
            s.trailers = fields;
            s.remote_ended = true;
            self.maybe_remove(id);
            return Ok(());
        }
        if id <= self.highest {
            return match self.closed.get(&id) {
                Some(Closed::WeReset) => Ok(()),
                Some(Closed::ClientReset) => {
                    frame::write_rst_stream(&mut self.out, id, ErrorCode::STREAM_CLOSED);
                    Ok(())
                }
                Some(Closed::Ended) => Err(self.lose(ErrorCode::STREAM_CLOSED, "HEADERS on a stream that is closed")),
                None => Err(self.lose(ErrorCode::PROTOCOL_ERROR, "HEADERS on a stream id that is not new")),
            };
        }
        // a new stream
        self.highest = id;
        if self.peer_goaway || self.going_away {
            frame::write_rst_stream(&mut self.out, id, ErrorCode::REFUSED_STREAM);
            self.remember(id, Closed::WeReset);
            return Ok(());
        }
        if !utf8 {
            self.reset(id, ErrorCode::PROTOCOL_ERROR);
            return Ok(());
        }
        if !within || fields.len() > self.max_headers + 4 {
            self.answer_alone(id, end_stream, 431);
            return Ok(());
        }
        let checked = match check_request(fields) {
            Ok(c) => c,
            Err(_why) => {
                self.reset(id, ErrorCode::PROTOCOL_ERROR);
                return Ok(());
            }
        };
        // the streams open, as the protocol counts them, and the ones reset whose handlers have not returned yet (a stream
        // stays in the map until both are over), so that resets cannot make room for more handlers than the limit
        if self.streams.len() as u64 >= self.cfg.max_concurrent_streams as u64 {
            // refused, so that the client may try again; not the client's fault, but counted (resets are cheap to cause)
            frame::write_rst_stream(&mut self.out, id, ErrorCode::REFUSED_STREAM);
            self.remember(id, Closed::WeReset);
            if !self.budgets.resets.take() {
                return Err(self.calm("streams refused"));
            }
            return Ok(());
        }
        if checked.expected.is_some_and(|n| self.max_body.is_some_and(|max| n > max)) {
            self.answer_alone(id, end_stream, 413);
            return Ok(());
        }
        let recv_window = self.initial_recv_window();
        self.idle_since = None;
        self.streams.insert(
            id,
            Stream {
                recv: VecDeque::new(),
                recv_window,
                unacked: 0,
                remote_ended: end_stream,
                trailers: Vec::new(),
                expected: checked.expected,
                received: 0,
                body_error: None,
                continue_pending: checked.expect_continue && !end_stream,
                send_window: self.peer_initial_window,
                pending: Vec::new(),
                pending_pos: 0,
                end_pending: false,
                trailers_pending: None,
                head_sent: false,
                local_ended: false,
                reset: false,
                reset_by_client: false,
                handler_done: false,
                discard: false,
                goaway_after: false,
                stalled_since: None,
                lingering_since: None,
            },
        );
        if end_stream && checked.expected.is_some_and(|n| n != 0) {
            self.reset(id, ErrorCode::PROTOCOL_ERROR);
            return Ok(());
        }
        new.push(NewStream { id, method: checked.method, scheme: checked.scheme, authority: checked.authority, path: checked.path, headers: checked.headers, end_stream });
        Ok(())
    }

    /// Answers a request without a handler (413, 431), dropping its body.
    fn answer_alone(&mut self, id: u32, end_stream: bool, status: u16) {
        let block = self.encode(status, &[("content-length".into(), "0".into())]);
        frame::write_header_block(&mut self.out, id, true, &block, self.peer_max_frame);
        if end_stream {
            self.remember(id, Closed::Ended);
        } else {
            frame::write_rst_stream(&mut self.out, id, ErrorCode::NO_ERROR);
            self.remember(id, Closed::WeReset);
        }
    }

    fn encode(&mut self, status: u16, fields: &[(String, String)]) -> Vec<u8> {
        let status = status.to_string();
        let mut refs = Vec::with_capacity(fields.len() + 1);
        refs.push(FieldRef { name: b":status", value: status.as_bytes(), sensitive: false });
        for (n, v) in fields {
            refs.push(FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: n == "set-cookie" });
        }
        let mut block = Vec::new();
        self.encoder.encode(&refs, &mut block);
        block
    }

    // -------------------------------------------------------------------------------------------- the handlers' side

    /// Reads request body data for a handler: `Ok(Some(n))`, `Ok(None)` if it must wait, `Ok(Some(0))` at the end.
    pub(super) fn read_body(&mut self, id: u32, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(s) = self.streams.get_mut(&id) else {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the stream is over"));
        };
        if let Some(e) = &s.body_error {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.clone()));
        }
        if !s.recv.is_empty() {
            let n = buf.len().min(s.recv.len());
            for (dst, src) in buf[..n].iter_mut().zip(s.recv.drain(..n)) {
                *dst = src;
            }
            s.unacked += n as u32;
            let window = self.cfg.stream_window.clamp(1, MAX_WINDOW);
            if !s.remote_ended && s.unacked >= (window / 2).max(1) {
                let credit = std::mem::take(&mut s.unacked);
                s.recv_window += credit as i64;
                frame::write_window_update(&mut self.out, id, credit);
            }
            self.credit_connection(n as u32);
            return Ok(Some(n));
        }
        if s.remote_ended {
            return Ok(Some(0));
        }
        if s.reset || self.dead {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "the client reset the stream"));
        }
        if s.continue_pending && !s.head_sent {
            s.continue_pending = false;
            let block = self.encode(100, &[]);
            frame::write_header_block(&mut self.out, id, false, &block, self.peer_max_frame);
        }
        Ok(None)
    }

    fn send_interim(&mut self, id: u32, status: u16, fields: &[(String, String)]) -> io::Result<()> {
        let s = self.stream_for_writing(id)?;
        if s.head_sent {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the final response has begun"));
        }
        let block = self.encode(status, fields);
        frame::write_header_block(&mut self.out, id, false, &block, self.peer_max_frame);
        Ok(())
    }

    pub(super) fn send_head(&mut self, id: u32, status: u16, fields: &[(String, String)], end: bool) -> io::Result<()> {
        let s = self.stream_for_writing(id)?;
        s.head_sent = true;
        s.continue_pending = false;
        if end {
            s.local_ended = true;
        }
        let block = self.encode(status, fields);
        frame::write_header_block(&mut self.out, id, end, &block, self.peer_max_frame);
        if end {
            self.maybe_remove(id);
        }
        Ok(())
    }

    fn stream_for_writing(&mut self, id: u32) -> io::Result<&mut Stream> {
        let dead = self.dead;
        match self.streams.get_mut(&id) {
            Some(s) if !s.reset && !dead && !s.local_ended && !s.end_pending => Ok(s),
            _ => Err(io::Error::new(io::ErrorKind::BrokenPipe, "the client reset the stream, or the connection is over")),
        }
    }

    /// Queues response data; `Ok(0)` if the stream's buffer is full (wait and try again).
    pub(super) fn queue_data(&mut self, id: u32, data: &[u8]) -> io::Result<usize> {
        let room = self.cfg.stream_send_buffer.max(1);
        let s = self.stream_for_writing(id)?;
        let n = room.saturating_sub(s.queued()).min(data.len());
        if s.pending_pos > 0 && s.pending_pos == s.pending.len() {
            s.pending.clear();
            s.pending_pos = 0;
        }
        s.pending.extend_from_slice(&data[..n]);
        self.pump();
        Ok(n)
    }

    pub(super) fn end_stream(&mut self, id: u32, trailers: Vec<(String, String)>) -> io::Result<()> {
        let s = self.stream_for_writing(id)?;
        s.end_pending = true;
        if !trailers.is_empty() {
            s.trailers_pending = Some(trailers);
        }
        self.pump();
        Ok(())
    }

    pub(super) fn handler_returned(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        s.handler_done = true;
        if !s.reset && !s.end_pending && !s.local_ended {
            // the response was never finished: the client must not take it for a whole one
            self.reset(id, ErrorCode::INTERNAL_ERROR);
            return;
        }
        if !s.remote_ended {
            s.discard = true;
        }
        self.maybe_remove(id);
    }

    /// Frames the response data the windows allow, a frame per stream in turn, until the output is full.
    pub(super) fn pump(&mut self) {
        if self.dead {
            return;
        }
        let mut ids: Vec<u32> = self.streams.iter().filter(|(_, s)| !s.local_ended && !s.reset && s.head_sent && (s.queued() > 0 || s.end_pending)).map(|(&id, _)| id).collect();
        if ids.is_empty() {
            return;
        }
        ids.sort_unstable();
        // start after the stream served last, so that one stream cannot keep the others waiting
        let start = ids.iter().position(|&id| id >= self.turn).unwrap_or(0);
        ids.rotate_left(start);
        loop {
            let mut wrote = false;
            for &id in &ids {
                if self.out.len() >= HIGH_WATER {
                    return;
                }
                if self.pump_stream(id) {
                    wrote = true;
                    self.turn = id + 1;
                }
            }
            if !wrote {
                return;
            }
        }
    }

    fn pump_stream(&mut self, id: u32) -> bool {
        let peer_max_frame = self.peer_max_frame;
        let conn_window = self.send_window;
        let Some(s) = self.streams.get_mut(&id) else { return false };
        if s.local_ended || s.reset {
            return false;
        }
        let queued = s.queued();
        if queued == 0 {
            if !s.end_pending {
                return false;
            }
            s.local_ended = true;
            match s.trailers_pending.take() {
                Some(trailers) => {
                    let block = self.encode_trailers(&trailers);
                    frame::write_header_block(&mut self.out, id, true, &block, peer_max_frame);
                }
                None => frame::write_data(&mut self.out, id, true, b""),
            }
            self.maybe_remove(id);
            return true;
        }
        let room = s.send_window.min(conn_window).max(0) as usize;
        let n = queued.min(room).min(peer_max_frame);
        if n == 0 {
            s.stalled_since.get_or_insert_with(Instant::now);
            return false;
        }
        s.stalled_since = None;
        let end = n == queued && s.end_pending && s.trailers_pending.is_none();
        frame::write_data(&mut self.out, id, end, &s.pending[s.pending_pos..s.pending_pos + n]);
        s.pending_pos += n;
        if s.pending_pos == s.pending.len() {
            s.pending.clear();
            s.pending_pos = 0;
        }
        s.send_window -= n as i64;
        self.send_window -= n as i64;
        if end {
            s.local_ended = true;
            self.maybe_remove(id);
        }
        true
    }

    fn encode_trailers(&mut self, trailers: &[(String, String)]) -> Vec<u8> {
        let lower: Vec<(String, String)> = trailers.iter().filter(|(n, v)| !n.is_empty() && n.bytes().all(super::is_tchar) && super::is_field_value(v)).map(|(n, v)| (n.to_ascii_lowercase(), v.clone())).collect();
        let refs: Vec<FieldRef<'_>> = lower.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut block = Vec::new();
        self.encoder.encode(&refs, &mut block);
        block
    }

    /// The connection is over: every stream fails.
    fn close_all(&mut self) {
        self.dead = true;
        for s in self.streams.values_mut() {
            s.reset = true;
        }
    }
}

/// The stream a HEADERS or PRIORITY frame says it depends on, if the frame has priority fields.
fn self_dependency(h: &Header, payload: &[u8]) -> Option<u32> {
    if h.stream == 0 {
        return None; // the frame parser's error
    }
    let at = match h.kind {
        kind::PRIORITY if payload.len() == 5 => 0,
        kind::HEADERS if h.has(flag::PRIORITY) => usize::from(h.has(flag::PADDED)),
        _ => return None,
    };
    let b = payload.get(at..at + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff)
}

/// A request's header list, checked (RFC 9113 section 8.3).
struct CheckedRequest {
    method: String,
    scheme: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    expected: Option<u64>,
    expect_continue: bool,
}

fn check_request(fields: Vec<(String, String)>) -> Result<CheckedRequest, String> {
    let (mut method, mut scheme, mut path, mut authority) = (None, None, None, None);
    let mut regular = false;
    let mut headers = Vec::new();
    let mut expected: Option<u64> = None;
    let mut host: Option<String> = None;
    let mut expect_continue = false;
    for (name, value) in fields {
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(format!("the value of {name:?} has a NUL, CR or LF"));
        }
        if value != value.trim_matches([' ', '\t']) {
            return Err(format!("the value of {name:?} begins or ends with white space"));
        }
        if let Some(pseudo) = name.strip_prefix(':') {
            if regular {
                return Err(format!("the pseudo-header {name} after a regular field"));
            }
            let slot = match pseudo {
                "method" => &mut method,
                "scheme" => &mut scheme,
                "path" => &mut path,
                "authority" => &mut authority,
                _ => return Err(format!("{name} is not a request pseudo-header (extended CONNECT is not offered)")),
            };
            if slot.replace(value).is_some() {
                return Err(format!("{name} twice"));
            }
            continue;
        }
        regular = true;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || (super::is_tchar(b) && !b.is_ascii_uppercase())) {
            return Err(format!("the field name {name:?} is not lower case token characters"));
        }
        match name.as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => return Err(format!("the connection-specific field {name}")),
            "te" if value != "trailers" => return Err(format!("te: {value}")),
            "host" => {
                if host.replace(value.clone()).is_some() {
                    return Err("two Host fields".into());
                }
            }
            "content-length" => {
                if value.is_empty() || value.len() > 18 || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("Content-Length {value:?}"));
                }
                let n: u64 = value.parse().expect("digits");
                if expected.is_some_and(|l| l != n) {
                    return Err("two different Content-Lengths".into());
                }
                expected = Some(n);
            }
            "expect" => {
                if value.eq_ignore_ascii_case("100-continue") {
                    expect_continue = true;
                }
            }
            _ => {}
        }
        headers.push((name, value));
    }
    let method = method.ok_or("no :method")?;
    if method.is_empty() || !method.bytes().all(super::is_tchar) {
        return Err("a :method that is not a token".into());
    }
    if method == "CONNECT" {
        if scheme.is_some() || path.is_some() {
            return Err("CONNECT with :scheme or :path".into());
        }
        let a = authority.ok_or("CONNECT without :authority")?;
        if !valid_authority(&a) || !a.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
            return Err("a CONNECT :authority that is not host:port".into());
        }
        return Ok(CheckedRequest { method, scheme: String::new(), path: a.clone(), authority: a, headers, expected, expect_continue });
    }
    let scheme = scheme.ok_or("no :scheme")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Err(format!(":scheme {scheme}"));
    }
    let path = path.ok_or("no :path")?;
    let path_ok = (path.starts_with('/') || (path == "*" && method == "OPTIONS")) && !path.contains('#') && path.bytes().all(|b| (0x21..0x7f).contains(&b));
    if !path_ok {
        return Err(format!("the :path {path:?}"));
    }
    let authority = match (authority, host) {
        (Some(a), Some(h)) if !a.eq_ignore_ascii_case(&h) => return Err("a Host that is not :authority".into()),
        (Some(a), _) | (None, Some(a)) => a,
        (None, None) => return Err("neither :authority nor Host".into()),
    };
    if !valid_authority(&authority) {
        return Err("an :authority that is not a host and port".into());
    }
    Ok(CheckedRequest { method, scheme, authority, path, headers, expected, expect_continue })
}

fn trailer_fault(fields: &[(String, String)]) -> Option<&'static str> {
    for (name, value) in fields {
        if name.starts_with(':') {
            return Some("a pseudo-header in trailers");
        }
        if name.is_empty() || !name.bytes().all(|b| super::is_tchar(b) && !b.is_ascii_uppercase()) {
            return Some("a trailer name that is not lower case token characters");
        }
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Some("a trailer value with a NUL, CR or LF");
        }
    }
    None
}

// ------------------------------------------------------------------------------------------------ the driver

struct Shared {
    engine: Mutex<Engine>,
    /// Handlers wait here: for request data, for room to queue response data.
    changed: Condvar,
    /// The writing handle. Holding it is the right to send.
    out: Mutex<Option<Box<dyn Write + Send>>>,
    /// How long a handler waits for more of its body, and for room to send (none without the runtime).
    body_wait: Option<Duration>,
    write_wait: Option<Duration>,
}

impl GoAway for Shared {
    fn go_away(&self) -> bool {
        let finished = {
            let mut e = self.engine();
            e.go_away();
            e.is_finished()
        };
        let _ = self.send(false);
        finished
    }
}

impl Shared {
    /// Waits for a change, at most `limit`; false if the time ran out with nothing changed.
    fn wait<'a>(&self, e: MutexGuard<'a, Engine>, limit: Option<Duration>) -> (MutexGuard<'a, Engine>, bool) {
        match limit {
            None => (self.changed.wait(e).unwrap_or_else(|p| p.into_inner()), true),
            Some(d) => {
                let (e, r) = self.changed.wait_timeout(e, d).unwrap_or_else(|p| p.into_inner());
                (e, !r.timed_out())
            }
        }
    }
}

impl Shared {
    fn engine(&self) -> MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends what the engine has framed. With `wait`, waits for the right to send; without, sends only if nobody is
    /// sending (whoever is sends this too).
    fn send(&self, wait: bool) -> io::Result<()> {
        let mut wait = wait;
        let mut buf = Vec::new();
        loop {
            let mut guard = if wait {
                self.out.lock().unwrap_or_else(|e| e.into_inner())
            } else {
                match self.out.try_lock() {
                    Ok(g) => g,
                    Err(TryLockError::Poisoned(e)) => e.into_inner(),
                    Err(TryLockError::WouldBlock) => return Ok(()),
                }
            };
            loop {
                {
                    let mut e = self.engine();
                    e.pump();
                    if e.out.is_empty() {
                        break;
                    }
                    std::mem::swap(&mut buf, &mut e.out);
                    e.out.clear();
                }
                // room was made in the streams' buffers: the handlers waiting for it can go on
                self.changed.notify_all();
                let Some(w) = guard.as_mut() else {
                    // our side is closed (the connection went away gracefully): what is left is not sent
                    buf.clear();
                    continue;
                };
                let res = w.write_all(&buf).and_then(|()| w.flush());
                buf.clear();
                if let Err(e) = res {
                    self.engine().close_all();
                    self.changed.notify_all();
                    return Err(e);
                }
            }
            drop(guard);
            if self.engine().out.is_empty() {
                return Ok(());
            }
            wait = false;
        }
    }
}

/// A request body read from its stream.
struct StreamIn {
    shared: Arc<Shared>,
    id: u32,
}

impl BodySource for StreamIn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let mut e = self.shared.engine();
            loop {
                match e.read_body(self.id, buf)? {
                    Some(n) => break n,
                    None => {
                        let has_output = !e.out.is_empty();
                        if has_output {
                            drop(e);
                            self.shared.send(true)?;
                            e = self.shared.engine();
                            continue;
                        }
                        let (guard, changed) = self.shared.wait(e, self.shared.body_wait);
                        e = guard;
                        if !changed {
                            // the client sent nothing more of the body for too long: the stream is given up
                            e.reset(self.id, ErrorCode::CANCEL);
                            drop(e);
                            let _ = self.shared.send(true);
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "the client sent nothing more of the request body for too long"));
                        }
                    }
                }
            }
        };
        // the credit the reading may have queued
        self.shared.send(true)?;
        Ok(n)
    }

    fn trailers(&self) -> Vec<(String, String)> {
        self.shared.engine().streams.get(&self.id).map(|s| s.trailers.clone()).unwrap_or_default()
    }
}

/// Response data written to its stream.
struct StreamOut {
    shared: Arc<Shared>,
    id: u32,
}

impl StreamOut {
    fn write_all_data(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = {
                let mut e = self.shared.engine();
                loop {
                    let n = e.queue_data(self.id, data)?;
                    if n > 0 {
                        break n;
                    }
                    let (guard, changed) = self.shared.wait(e, self.shared.write_wait);
                    e = guard;
                    if !changed {
                        // the client opened no window for too long
                        e.reset(self.id, ErrorCode::CANCEL);
                        drop(e);
                        let _ = self.shared.send(true);
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "the client did not take the response in time"));
                    }
                }
            };
            data = &data[n..];
            self.shared.send(true)?;
        }
        Ok(())
    }

    fn end(&mut self, trailers: Vec<(String, String)>) -> io::Result<()> {
        self.shared.engine().end_stream(self.id, trailers)?;
        self.shared.send(true)
    }
}

impl BodySink for StreamOut {
    fn write_body(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_all_data(data)
    }

    fn flush_body(&mut self) -> io::Result<()> {
        self.shared.send(true)
    }
}

/// The writing half of a CONNECT tunnel over a stream: dropping it ends the stream.
struct TunnelOut(StreamOut);

impl Write for TunnelOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all_data(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush_body()
    }
}

impl Drop for TunnelOut {
    fn drop(&mut self) {
        let _ = self.0.end(Vec::new());
    }
}

/// Serves an HTTP/2 connection whose preface has not been read yet.
pub(super) fn serve(mut reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>, info: Arc<ConnInfo>, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<Ctl>) -> io::Result<()> {
    let mut preface = [0u8; 24];
    reader.read_exact(&mut preface)?;
    if preface != PREFACE {
        let mut writer = writer;
        let mut out = Vec::new();
        frame::write_goaway(&mut out, 0, ErrorCode::PROTOCOL_ERROR, b"the client did not begin with the connection preface");
        let _ = writer.write_all(&out);
        return Ok(());
    }
    serve_after_preface(reader, writer, info, handler, config, ctl)
}

/// Serves an HTTP/2 connection whose preface has been read.
pub(super) fn serve_after_preface(mut reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>, info: Arc<ConnInfo>, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<Ctl>) -> io::Result<()> {
    let runtime = ctl.timer.is_some();
    let shared = Arc::new(Shared {
        engine: Mutex::new(Engine::new(config)),
        changed: Condvar::new(),
        out: Mutex::new(Some(writer)),
        body_wait: runtime.then_some(ctl.limits.body_wait),
        write_wait: runtime.then_some(ctl.limits.write_timeout),
    });
    shared.send(true)?;
    let weak: std::sync::Weak<dyn GoAway> = Arc::downgrade(&shared) as std::sync::Weak<dyn GoAway>;
    ctl.set_h2(weak);
    let scheme_default = if info.tls.is_some() { "https" } else { "http" };
    let config = Arc::new(config.clone());
    // the handlers of this connection's streams that have not returned: the connection waits for them before it ends
    let running = Arc::new((Mutex::new(0usize), Condvar::new()));
    let result = (|| -> io::Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        let result = loop {
            // idle while no stream is open, from when the last one ended; while streams are open, the handlers' own
            // waits bound them, and the reading only waits for the client
            // and while response data waits for a window, until the client has had the write timeout to open one
            if let Some(t) = &ctl.timer {
                let (idle, stalled) = {
                    let e = shared.engine();
                    (e.idle_since(), e.stalled_since())
                };
                match (idle, stalled) {
                    (Some(since), _) => t.until(since + ctl.limits.idle_timeout),
                    (None, Some(since)) => t.until(since + ctl.limits.write_timeout),
                    (None, None) => t.none(),
                }
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                // (WouldBlock: a read with no deadline lets the loop look at the streams again)
                Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    // a stream that waited too long for a window is reset, and the connection goes on; an idle one ends
                    let reset = shared.engine().reset_stalled(Instant::now() - ctl.limits.write_timeout);
                    if reset == 0 {
                        break Err(e);
                    }
                    shared.changed.notify_all();
                    if let Err(e) = shared.send(true) {
                        break Err(e);
                    }
                    continue;
                }
                Err(e) => break Err(e),
            };
            let (new, backlog, done) = {
                let mut e = shared.engine();
                let new = e.receive(&buf[..n]);
                (new, e.out.len(), e.is_dead() || e.is_finished())
            };
            shared.changed.notify_all();
            let new = match new {
                Ok(new) => new,
                Err(lost) => {
                    let _ = shared.send(true);
                    break Err(io::Error::new(io::ErrorKind::InvalidData, format!("HTTP/2 connection closed with {}: {}", ErrorCode(lost.code), lost.reason)));
                }
            };
            for stream in new {
                if !ctl.take_handler() {
                    shared.engine().refuse(stream.id);
                    continue;
                }
                let shared = shared.clone();
                let handler = handler.clone();
                let info = info.clone();
                let ctl = ctl.clone();
                let config = config.clone();
                let running = running.clone();
                let scheme = if stream.scheme.is_empty() { scheme_default.to_string() } else { stream.scheme.to_ascii_lowercase() };
                *running.0.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                pool::run(Box::new(move || {
                    run_stream(shared, handler, info, stream, scheme, &config, &ctl);
                    ctl.give_handler();
                    let (count, done) = &*running;
                    *count.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
                    done.notify_all();
                }));
            }
            if let Err(e) = shared.send(backlog > HIGH_WATER) {
                break Err(e);
            }
            if done {
                let _ = shared.send(true);
                break Ok(());
            }
        };
        result
    })();
    // the connection is over (or the client is gone): every handler still waiting is woken to find so, and the
    // connection waits for them to return
    shared.engine().close_all();
    shared.changed.notify_all();
    {
        let (count, done) = &*running;
        let mut n = count.lock().unwrap_or_else(|e| e.into_inner());
        while *n > 0 {
            n = done.wait(n).unwrap_or_else(|e| e.into_inner());
        }
    }
    let _ = shared.send(true);
    if let Some(mut w) = shared.out.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = w.flush();
    }
    result
}

/// Runs one request's handler and sends its response.
fn run_stream(shared: Arc<Shared>, handler: Arc<dyn Handler>, info: Arc<ConnInfo>, s: NewStream, scheme: String, config: &HttpConfig, ctl: &Ctl) {
    let id = s.id;
    let is_head = s.method == "HEAD";
    let is_connect = s.method == "CONNECT";
    let body = if s.end_stream { Body::new(None) } else { Body::new(Some(Box::new(StreamIn { shared: shared.clone(), id }))) };
    let interim: super::Interim = {
        let shared = shared.clone();
        Arc::new(move |status: u16, fields: &[(String, String)]| {
            shared.engine().send_interim(id, status, fields)?;
            shared.send(true)
        })
    };
    let request = Request { method: s.method, target: s.path, authority: s.authority, scheme, version: Version::Http2, headers: s.headers, body, info, interim: Some(interim), ctl: None };
    let pending = Pending::of(ctl, &request);
    let (response, _panicked) = call(&*handler, request);
    let status = response.status;
    let sent = send_response(&shared, id, response, is_head, is_connect, config);
    if let Some(p) = pending {
        match sent {
            Ok((status, bytes)) => p.done(ctl, status, bytes),
            Err(_) => p.done(ctl, status, 0),
        }
    }
    let finished = {
        let mut e = shared.engine();
        e.handler_returned(id);
        e.is_finished()
    };
    shared.changed.notify_all();
    let _ = shared.send(true);
    if finished {
        // the GOAWAY has gone and nothing is left: end what we send (a TLS close_notify), and stop reading
        if let Some(mut w) = shared.out.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = w.flush();
        }
        ctl.stop();
    }
}

/// Sends a response; the status and the body bytes sent.
fn send_response(shared: &Arc<Shared>, id: u32, response: Response, is_head: bool, is_connect: bool, config: &HttpConfig) -> io::Result<(u16, u64)> {
    let Response { status, headers, body } = response;
    let upgrade = matches!(body, ResponseBody::Upgrade(_));
    let valid = (200..=999).contains(&status) && (upgrade == (is_connect && (200..300).contains(&status)) || (is_connect && !upgrade));
    let head = match response_head(&headers, config) {
        Ok(h) if valid => h,
        _ => return send_response(shared, id, Response::text(500, "internal server error\n"), is_head, false, config),
    };
    if head.close {
        // a handler's Connection: close is a GOAWAY once this response has ended: the connection ends with the others
        if let Some(s) = shared.engine().streams.get_mut(&id) {
            s.goaway_after = true;
        }
    }
    let mut fields: Vec<(String, String)> = head.fields.into_iter().filter(|(n, _)| n != "upgrade" && n != "te").collect();
    let no_body = matches!(status, 204 | 304) || (is_connect && (200..300).contains(&status));
    let length = match &body {
        _ if no_body && status != 304 => None,
        ResponseBody::Empty if status == 304 || is_head => head.content_length,
        ResponseBody::Empty => Some(0),
        ResponseBody::Bytes(b) => Some(b.len() as u64),
        ResponseBody::Reader { length, .. } => *length,
        ResponseBody::Stream(_) | ResponseBody::Upgrade(_) => None,
    };
    if let Some(n) = length {
        if !(no_body && status != 304) {
            fields.push(("content-length".into(), n.to_string()));
        }
    }
    let send_body = !is_head && !no_body;
    let empty = matches!(body, ResponseBody::Empty) || !send_body || matches!(&body, ResponseBody::Bytes(b) if b.is_empty()) || matches!(body, ResponseBody::Reader { length: Some(0), .. });
    if let ResponseBody::Bytes(b) = &body {
        if !empty && !upgrade && b.len() <= config.h2.stream_send_buffer {
            // a whole small response: the head, the body and its end framed under one lock and sent together
            {
                let mut e = shared.engine();
                e.send_head(id, status, &fields, false)?;
                e.queue_data(id, b)?;
                e.end_stream(id, Vec::new())?;
            }
            shared.send(true)?;
            return Ok((status, b.len() as u64));
        }
    }
    shared.engine().send_head(id, status, &fields, empty && !upgrade)?;
    shared.send(true)?;
    if empty && !upgrade {
        return Ok((status, 0));
    }
    let mut out = StreamOut { shared: shared.clone(), id };
    match body {
        ResponseBody::Empty => out.end(Vec::new()).map(|()| (status, 0)),
        ResponseBody::Bytes(b) => {
            out.write_all_data(&b)?;
            out.end(Vec::new()).map(|()| (status, b.len() as u64))
        }
        ResponseBody::Reader { mut reader, length } => {
            let mut left = length;
            let mut sent = 0u64;
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                let want = left.map_or(chunk.len(), |l| chunk.len().min(usize::try_from(l).unwrap_or(usize::MAX)));
                if want == 0 {
                    break;
                }
                let n = match reader.read(&mut chunk[..want]) {
                    Ok(0) if left.is_some_and(|l| l > 0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the handler's reader ended before its length")),
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                out.write_all_data(&chunk[..n])?;
                sent += n as u64;
                if let Some(l) = left.as_mut() {
                    *l -= n as u64;
                }
            }
            out.end(Vec::new()).map(|()| (status, sent))
        }
        ResponseBody::Stream(write) => {
            let mut writer = BodyWriter { sink: &mut out, trailers: Vec::new(), written: 0 };
            write(&mut writer)?;
            let trailers = std::mem::take(&mut writer.trailers);
            let sent = writer.written;
            out.end(trailers).map(|()| (status, sent))
        }
        ResponseBody::Upgrade(then) => {
            let reader = Body::new(Some(Box::new(StreamIn { shared: shared.clone(), id })));
            then(Upgraded { reader: Box::new(reader), writer: Box::new(TunnelOut(out)) });
            Ok((status, 0))
        }
    }
}

/// The threads the handlers of HTTP/2 streams run on, for all connections: a stream's handler takes an idle one or, if
/// none is idle, a new one, which waits for more work for ten seconds once its handler has returned (so that a busy
/// connection does not make and end a thread for each request). The number running is bounded by the runtime's
/// `Limits::max_h2_handlers`.
mod pool {
    use std::collections::VecDeque;
    use std::sync::{Condvar, Mutex, OnceLock};
    use std::time::Duration;

    type Job = Box<dyn FnOnce() + Send + 'static>;

    struct Pool {
        state: Mutex<State>,
        work: Condvar,
    }

    struct State {
        jobs: VecDeque<Job>,
        idle: usize,
    }

    fn pool() -> &'static Pool {
        static POOL: OnceLock<Pool> = OnceLock::new();
        POOL.get_or_init(|| Pool { state: Mutex::new(State { jobs: VecDeque::new(), idle: 0 }), work: Condvar::new() })
    }

    /// Runs `job` on a thread of the pool.
    pub(super) fn run(job: Job) {
        let p = pool();
        let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.idle > st.jobs.len() {
            st.jobs.push_back(job);
            drop(st);
            p.work.notify_one();
            return;
        }
        drop(st);
        let slot = std::sync::Arc::new(Mutex::new(Some(job)));
        let mine = slot.clone();
        let spawned = std::thread::Builder::new().name("pratique-h2".into()).spawn(move || {
            if let Some(job) = mine.lock().unwrap_or_else(|e| e.into_inner()).take() {
                job();
            }
            worker(p);
        });
        if spawned.is_err() {
            // no thread could be made (the system is out of them): the job runs here rather than not at all
            if let Some(job) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
                job();
            }
        }
    }

    fn worker(p: &'static Pool) {
        loop {
            let job = {
                let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
                st.idle += 1;
                loop {
                    if let Some(j) = st.jobs.pop_front() {
                        st.idle -= 1;
                        break Some(j);
                    }
                    let (next, timeout) = p.work.wait_timeout(st, Duration::from_secs(10)).unwrap_or_else(|e| e.into_inner());
                    st = next;
                    if timeout.timed_out() && st.jobs.is_empty() {
                        st.idle -= 1;
                        break None;
                    }
                }
            };
            match job {
                Some(j) => j(),
                None => return,
            }
        }
    }
}
