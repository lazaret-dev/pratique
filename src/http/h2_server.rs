//! A small HTTP/2 server (RFC 9113) for tests and tools: something real for the client's HTTP/2 to talk to, over
//! the crate's own TLS server (`tls::server`, ALPN `h2`) and in memory, and a peer that scripts what it does.
//!
//! **Experimental, and not for production** (behind the `server` feature, always built for this crate's own tests):
//! it keeps whole request bodies in memory, answers whatever the handler says, and takes every shortcut that keeps
//! a test simple. What it does do properly is read what the client sends the way a server must, because a test
//! server that accepts anything cannot find a client's mistakes: the preface, SETTINGS, frame sizes, stream ids,
//! the flow-control windows, header blocks and the pseudo-headers, lower case names and connection-specific fields
//! of a request (RFC 9113 section 8) are all checked. A request the server finds fault with is reset or the
//! connection is lost, and the finding is kept in [`ServerConn::complaints`] so that a test can say that none
//! were made.
//!
//! [`serve`] runs one connection: it reads requests, hands each complete one to the handler, and plays out the
//! handler's [`Step`]s (a head, data, trailers, a reset, a GOAWAY, raw bytes, and so on, each some time after the
//! last), sending response data as the client's windows allow. [`ServerConn`] is the protocol with no I/O.

use super::h2::frame::{self, flag, kind, setting, ErrorCode, Frame, FrameError, Header, DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW, HEADER_LEN, MAX_FRAME_SIZE_LIMIT, MAX_WINDOW, PREFACE};
use super::h2::hpack::{Decoder, Encoder, FieldRef};
use crate::tls::server::ServerStream;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// What the server tells the client about itself.
#[derive(Clone, Debug)]
pub struct Settings {
    /// SETTINGS_MAX_CONCURRENT_STREAMS. A stream opened past it is refused (RST_STREAM REFUSED_STREAM).
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE: what the client may send of a request body before the server has read some.
    pub initial_window: u32,
    /// The window for the connection as a whole (announced with a WINDOW_UPDATE).
    pub connection_window: u32,
    /// SETTINGS_MAX_FRAME_SIZE (16384 to 16777215).
    pub max_frame_size: u32,
    /// The largest header list taken, and SETTINGS_MAX_HEADER_LIST_SIZE.
    pub max_header_list: u32,
    /// SETTINGS_HEADER_TABLE_SIZE.
    pub header_table_size: u32,
    /// A request body larger than this is not taken: the stream is reset.
    pub max_body: usize,
    /// Give the client credit for request data as it is taken (the default). Without it the client's windows only
    /// open when a step says so ([`Action::WindowUpdate`]), which is how a test holds a request body back.
    pub auto_credit: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { max_concurrent_streams: 100, initial_window: 1 << 20, connection_window: 16 << 20, max_frame_size: DEFAULT_MAX_FRAME_SIZE, max_header_list: 64 << 10, header_table_size: 4096, max_body: 64 << 20, auto_credit: true }
    }
}

/// A request, whole.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub stream: u32,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    /// The header fields other than the pseudo-headers, as they came, names in lower case.
    pub headers: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header with this (lower case) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Something the server does on a stream (or on the connection).
#[derive(Clone, Debug)]
pub enum Action {
    /// A 1xx response.
    Interim { status: u16, headers: Vec<(String, String)> },
    /// The head of the response; with `end` there is no body and the stream is closed.
    Head { status: u16, headers: Vec<(String, String)>, end: bool },
    /// Body, sent as the windows allow.
    Data(Vec<u8>),
    /// Trailers, after the body that is queued; they end the stream.
    Trailers(Vec<(String, String)>),
    /// The end of the body.
    End,
    /// RST_STREAM with this error code, after whatever body the windows let through; the rest is dropped.
    Reset(u32),
    /// GOAWAY with this error code (after the data that the windows let through); the last stream is the highest
    /// the client has opened unless given.
    GoAway { code: u32, last_stream: Option<u32> },
    Ping,
    /// A SETTINGS frame with these (identifier, value) pairs.
    Settings(Vec<(u16, u32)>),
    /// A WINDOW_UPDATE of this many bytes for the stream (for the connection if the step is on stream 0).
    WindowUpdate(u32),
    /// PUSH_PROMISE on the stream, promising this (even) stream, with a request's header fields.
    PushPromise { promised: u32, headers: Vec<(String, String)> },
    /// These bytes on the connection, as they are.
    Raw(Vec<u8>),
    /// Stop serving: a close_notify, and the connection is closed.
    Close,
    /// Stop serving without a close_notify: the caller cuts the connection.
    Cut,
}

/// An action, `after` the one before it (or, for the first, after the request was complete).
#[derive(Clone, Debug)]
pub struct Step {
    pub after: Duration,
    pub action: Action,
}

impl Step {
    pub fn now(action: Action) -> Step {
        Step { after: Duration::ZERO, action }
    }

    pub fn later(after: Duration, action: Action) -> Step {
        Step { after, action }
    }
}

/// A complete response as steps: the head, the body, the end.
pub fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<Step> {
    let headers: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
    if body.is_empty() {
        vec![Step::now(Action::Head { status, headers, end: true })]
    } else {
        vec![Step::now(Action::Head { status, headers, end: false }), Step::now(Action::Data(body.to_vec())), Step::now(Action::End)]
    }
}

// ------------------------------------------------------------------------------------------------ the protocol

/// What the client did, for [`serve`] (or a test) to act on.
#[derive(Debug)]
pub enum Event {
    /// A request head or, on a stream that already has one, its trailers.
    Headers { stream: u32, fields: Vec<(String, String)>, end_stream: bool },
    Data { stream: u32, data: Vec<u8>, end_stream: bool },
    Reset { stream: u32, code: u32 },
    GoAway { code: u32 },
}

/// The connection is lost (and a GOAWAY says why).
#[derive(Debug)]
pub struct ConnError {
    pub code: u32,
    pub reason: String,
}

#[derive(Debug)]
struct SStream {
    recv_window: i64,
    unannounced: u32,
    send_window: i64,
    remote_ended: bool,
    local_ended: bool,
    expected: Option<u64>,
    received: u64,
    head_request: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    end_pending: bool,
    trailers: Option<Vec<(String, String)>>,
}

impl SStream {
    fn queued(&self) -> usize {
        self.pending.len() - self.pending_pos
    }

    fn has_output(&self) -> bool {
        !self.local_ended && (self.queued() > 0 || self.end_pending || self.trailers.is_some())
    }
}

struct Block {
    stream: u32,
    end_stream: bool,
    bytes: Vec<u8>,
}

/// The server side of one connection, with no I/O.
pub struct ServerConn {
    settings: Settings,
    decoder: Decoder,
    encoder: Encoder,
    inbound: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    got_preface: bool,
    got_settings: bool,
    streams: HashMap<u32, SStream>,
    highest_stream: u32,
    send_window: i64,
    recv_window: i64,
    unannounced: u32,
    peer_initial_window: i64,
    peer_max_frame: usize,
    block: Option<Block>,
    failed: bool,
    pings: u8,
    complaints: Vec<String>,
}

/// How much output may wait before response data is held back.
const OUTPUT_HIGH_WATER: usize = 512 << 10;

impl ServerConn {
    /// A server whose SETTINGS are waiting in the output.
    pub fn new(settings: Settings) -> ServerConn {
        let mut c = ServerConn {
            decoder: Decoder::new(settings.header_table_size as usize, settings.max_header_list as usize),
            encoder: Encoder::new(),
            inbound: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            got_preface: false,
            got_settings: false,
            streams: HashMap::new(),
            highest_stream: 0,
            send_window: DEFAULT_WINDOW as i64,
            recv_window: settings.connection_window.max(DEFAULT_WINDOW) as i64,
            unannounced: 0,
            peer_initial_window: DEFAULT_WINDOW as i64,
            peer_max_frame: DEFAULT_MAX_FRAME_SIZE as usize,
            block: None,
            failed: false,
            pings: 0,
            complaints: Vec::new(),
            settings,
        };
        let s = c.settings.clone();
        frame::write_settings(
            &mut c.out,
            &[
                (setting::HEADER_TABLE_SIZE, s.header_table_size),
                (setting::MAX_CONCURRENT_STREAMS, s.max_concurrent_streams),
                (setting::INITIAL_WINDOW_SIZE, s.initial_window),
                (setting::MAX_FRAME_SIZE, s.max_frame_size),
                (setting::MAX_HEADER_LIST_SIZE, s.max_header_list),
            ],
        );
        if s.connection_window > DEFAULT_WINDOW {
            frame::write_window_update(&mut c.out, 0, s.connection_window - DEFAULT_WINDOW);
        }
        c
    }

    pub fn receive(&mut self, data: &[u8]) {
        if !self.failed {
            self.inbound.extend_from_slice(data);
        }
    }

    pub fn output(&self) -> &[u8] {
        &self.out[self.out_pos..]
    }

    pub fn consume_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out.len());
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
    }

    pub fn wants_write(&self) -> bool {
        self.out_pos < self.out.len()
    }

    /// What the server found wrong with the client, in words.
    pub fn complaints(&self) -> &[String] {
        &self.complaints
    }

    /// The streams the client has opened (the highest id).
    pub fn highest_stream(&self) -> u32 {
        self.highest_stream
    }

    fn lost(&mut self, code: ErrorCode, reason: impl Into<String>) -> ConnError {
        let reason = reason.into();
        self.complaints.push(reason.clone());
        frame::write_goaway(&mut self.out, self.highest_stream, code, reason.as_bytes());
        self.failed = true;
        ConnError { code: code.0, reason }
    }

    fn stream_lost(&mut self, id: u32, code: ErrorCode, reason: &str) {
        self.complaints.push(format!("stream {id}: {reason}"));
        self.reset(id, code);
    }

    fn reset(&mut self, id: u32, code: ErrorCode) {
        self.streams.remove(&id);
        frame::write_rst_stream(&mut self.out, id, code);
    }

    /// Handles what has been received.
    pub fn process(&mut self) -> Result<Vec<Event>, ConnError> {
        let mut events = Vec::new();
        if self.failed {
            return Err(ConnError { code: ErrorCode::PROTOCOL_ERROR.0, reason: "the connection is lost".into() });
        }
        let buf = std::mem::take(&mut self.inbound);
        let mut pos = 0;
        if !self.got_preface {
            let n = buf.len().min(PREFACE.len());
            if buf[..n] != PREFACE[..n] {
                return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "the client did not begin with the connection preface"));
            }
            if buf.len() < PREFACE.len() {
                self.inbound = buf;
                return Ok(events);
            }
            pos = PREFACE.len();
            self.got_preface = true;
        }
        loop {
            if buf.len() - pos < HEADER_LEN {
                break;
            }
            let header = Header::parse(buf[pos..pos + HEADER_LEN].try_into().expect("nine bytes"));
            if header.length > self.settings.max_frame_size {
                return Err(self.lost(ErrorCode::FRAME_SIZE_ERROR, "a frame larger than the size this server announced"));
            }
            let end = pos + HEADER_LEN + header.length as usize;
            if buf.len() < end {
                break;
            }
            if !self.got_settings && !(header.kind == kind::SETTINGS && header.flags & flag::ACK == 0) {
                return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "the client's first frame is not SETTINGS"));
            }
            match frame::parse(&header, &buf[pos + HEADER_LEN..end]) {
                Ok(f) => self.handle(f, &mut events)?,
                Err(FrameError { code, stream: None, reason }) => return Err(self.lost(code, reason)),
                Err(FrameError { code, stream: Some(id), reason }) => self.stream_lost(id, code, reason),
            }
            pos = end;
        }
        self.inbound = buf[pos..].to_vec();
        Ok(events)
    }

    fn handle(&mut self, f: Frame<'_>, events: &mut Vec<Event>) -> Result<(), ConnError> {
        if let Some(block) = &self.block {
            match &f {
                Frame::Continuation { stream, .. } if *stream == block.stream => {}
                _ => return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "a frame in the middle of a header block")),
            }
        }
        match f {
            Frame::Data { stream, end_stream, data, flow_len } => self.on_data(stream, end_stream, data, flow_len, events),
            Frame::Headers { stream, end_stream, end_headers, fragment } => {
                if stream % 2 == 0 {
                    return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "HEADERS on an even stream"));
                }
                if stream <= self.highest_stream && !self.streams.contains_key(&stream) {
                    return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "HEADERS on a stream id that is not new"));
                }
                self.block = Some(Block { stream, end_stream, bytes: Vec::new() });
                self.on_fragment(end_headers, fragment, events)
            }
            Frame::Continuation { end_headers, fragment, .. } => {
                if self.block.is_none() {
                    return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "CONTINUATION with no header block"));
                }
                self.on_fragment(end_headers, fragment, events)
            }
            Frame::Priority { .. } | Frame::Unknown { .. } => Ok(()),
            Frame::RstStream { stream, code } => {
                if stream > self.highest_stream {
                    return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "RST_STREAM on a stream that was never opened"));
                }
                self.streams.remove(&stream);
                events.push(Event::Reset { stream, code: code.0 });
                Ok(())
            }
            Frame::Settings { ack, values } => self.on_settings(ack, &values),
            Frame::PushPromise { .. } => Err(self.lost(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE from a client")),
            Frame::Ping { ack, data } => {
                if !ack {
                    frame::write_ping(&mut self.out, true, data);
                }
                Ok(())
            }
            Frame::GoAway { code, .. } => {
                events.push(Event::GoAway { code: code.0 });
                Ok(())
            }
            Frame::WindowUpdate { stream, increment } => {
                if stream == 0 {
                    self.send_window += increment as i64;
                    if self.send_window > MAX_WINDOW as i64 {
                        return Err(self.lost(ErrorCode::FLOW_CONTROL_ERROR, "the connection window went over 2^31 - 1"));
                    }
                } else if stream > self.highest_stream {
                    return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE on a stream that was never opened"));
                } else if let Some(s) = self.streams.get_mut(&stream) {
                    s.send_window += increment as i64;
                    if s.send_window > MAX_WINDOW as i64 {
                        self.stream_lost(stream, ErrorCode::FLOW_CONTROL_ERROR, "the stream window went over 2^31 - 1");
                    }
                }
                Ok(())
            }
        }
    }

    fn on_settings(&mut self, ack: bool, values: &[(u16, u32)]) -> Result<(), ConnError> {
        if ack {
            return Ok(());
        }
        self.got_settings = true;
        for &(id, value) in values {
            match id {
                setting::HEADER_TABLE_SIZE => self.encoder.set_peer_table_size(value as usize),
                setting::ENABLE_PUSH if value > 1 => return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH is neither 0 nor 1")),
                setting::INITIAL_WINDOW_SIZE => {
                    if value > MAX_WINDOW {
                        return Err(self.lost(ErrorCode::FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE over 2^31 - 1"));
                    }
                    let delta = value as i64 - self.peer_initial_window;
                    self.peer_initial_window = value as i64;
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                    }
                }
                setting::MAX_FRAME_SIZE => {
                    if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&value) {
                        return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE out of range"));
                    }
                    self.peer_max_frame = value as usize;
                }
                _ => {}
            }
        }
        frame::write_settings_ack(&mut self.out);
        Ok(())
    }

    fn on_data(&mut self, id: u32, end_stream: bool, data: &[u8], flow_len: u32, events: &mut Vec<Event>) -> Result<(), ConnError> {
        if id % 2 == 0 || id > self.highest_stream {
            return Err(self.lost(ErrorCode::PROTOCOL_ERROR, "DATA on a stream that was never opened"));
        }
        if flow_len as i64 > self.recv_window {
            return Err(self.lost(ErrorCode::FLOW_CONTROL_ERROR, "the client sent more than the connection window allows"));
        }
        self.recv_window -= flow_len as i64;
        self.credit_connection(flow_len);
        let Some(s) = self.streams.get_mut(&id) else { return Ok(()) };
        if s.remote_ended {
            self.stream_lost(id, ErrorCode::STREAM_CLOSED, "DATA after the end of the request");
            return Ok(());
        }
        if flow_len as i64 > s.recv_window {
            self.stream_lost(id, ErrorCode::FLOW_CONTROL_ERROR, "the client sent more than the stream window allows");
            return Ok(());
        }
        s.recv_window -= flow_len as i64;
        s.unannounced += flow_len;
        s.received += data.len() as u64;
        let mut problem = None;
        if s.expected.is_some_and(|n| s.received > n) || (end_stream && s.expected.is_some_and(|n| s.received != n)) {
            problem = Some("the DATA does not match the Content-Length");
        }
        if s.received as usize > self.settings.max_body {
            problem = Some("a request body larger than this server keeps");
        }
        if let Some(why) = problem {
            self.stream_lost(id, ErrorCode::PROTOCOL_ERROR, why);
            return Ok(());
        }
        if end_stream {
            s.remote_ended = true;
        } else if self.settings.auto_credit && s.unannounced as i64 >= super::h2::connection::refresh_threshold(self.settings.initial_window) && s.unannounced > 0 {
            let credit = std::mem::take(&mut s.unannounced);
            s.recv_window += credit as i64;
            frame::write_window_update(&mut self.out, id, credit);
        }
        let closed = s.remote_ended && s.local_ended;
        events.push(Event::Data { stream: id, data: data.to_vec(), end_stream });
        if closed {
            self.streams.remove(&id);
        }
        Ok(())
    }

    fn credit_connection(&mut self, n: u32) {
        if n == 0 || !self.settings.auto_credit {
            return;
        }
        self.unannounced += n;
        if self.unannounced as i64 >= super::h2::connection::refresh_threshold(self.settings.connection_window.max(DEFAULT_WINDOW)) {
            let credit = std::mem::take(&mut self.unannounced);
            self.recv_window += credit as i64;
            frame::write_window_update(&mut self.out, 0, credit);
        }
    }

    fn on_fragment(&mut self, end_headers: bool, fragment: &[u8], events: &mut Vec<Event>) -> Result<(), ConnError> {
        let limit = self.settings.max_header_list as usize + 1024;
        let block = self.block.as_mut().expect("a block in progress");
        if block.bytes.len() + fragment.len() > limit {
            return Err(self.lost(ErrorCode::ENHANCE_YOUR_CALM, "a header block that goes on too long"));
        }
        block.bytes.extend_from_slice(fragment);
        if !end_headers {
            return Ok(());
        }
        let Block { stream, end_stream, bytes } = self.block.take().expect("a block in progress");
        let mut decoded = Vec::new();
        let within = match self.decoder.decode(&bytes, &mut decoded) {
            Ok(w) => w,
            Err(e) => return Err(self.lost(ErrorCode::COMPRESSION_ERROR, e.to_string())),
        };
        if !within {
            // the stream is lost, but a stream that would have been new is still opened as far as ids go
            self.highest_stream = self.highest_stream.max(stream);
            self.stream_lost(stream, ErrorCode::PROTOCOL_ERROR, "a header list larger than this server takes");
            return Ok(());
        }
        let fields: Vec<(String, String)> = decoded.into_iter().map(|f| (String::from_utf8_lossy(&f.name).into_owned(), String::from_utf8_lossy(&f.value).into_owned())).collect();
        self.on_headers(stream, end_stream, fields, events)
    }

    fn on_headers(&mut self, id: u32, end_stream: bool, fields: Vec<(String, String)>, events: &mut Vec<Event>) -> Result<(), ConnError> {
        if let Some(s) = self.streams.get_mut(&id) {
            // trailers
            if s.remote_ended {
                self.stream_lost(id, ErrorCode::STREAM_CLOSED, "HEADERS after the end of the request");
                return Ok(());
            }
            if !end_stream {
                self.stream_lost(id, ErrorCode::PROTOCOL_ERROR, "trailers that do not end the stream");
                return Ok(());
            }
            if let Some(why) = trailer_fault(&fields) {
                self.stream_lost(id, ErrorCode::PROTOCOL_ERROR, why);
                return Ok(());
            }
            if s.expected.is_some_and(|n| s.received != n) {
                self.stream_lost(id, ErrorCode::PROTOCOL_ERROR, "the DATA does not match the Content-Length");
                return Ok(());
            }
            s.remote_ended = true;
            let closed = s.local_ended;
            events.push(Event::Headers { stream: id, fields, end_stream });
            if closed {
                self.streams.remove(&id);
            }
            return Ok(());
        }
        // a new stream
        self.highest_stream = id;
        let (head_request, expected) = match request_fault(&fields) {
            Err(why) => {
                self.stream_lost(id, ErrorCode::PROTOCOL_ERROR, &why);
                return Ok(());
            }
            Ok(v) => v,
        };
        let active = self.streams.values().filter(|s| !(s.remote_ended && s.local_ended)).count();
        if active as u64 >= self.settings.max_concurrent_streams as u64 {
            // refused, so that the client may send it again elsewhere (RFC 9113 section 5.1.2); not the client's fault
            frame::write_rst_stream(&mut self.out, id, ErrorCode::REFUSED_STREAM);
            return Ok(());
        }
        self.streams.insert(
            id,
            SStream {
                recv_window: self.settings.initial_window as i64,
                unannounced: 0,
                send_window: self.peer_initial_window,
                remote_ended: end_stream,
                local_ended: false,
                expected,
                received: 0,
                head_request,
                pending: Vec::new(),
                pending_pos: 0,
                end_pending: false,
                trailers: None,
            },
        );
        events.push(Event::Headers { stream: id, fields, end_stream });
        Ok(())
    }

    // -------------------------------------------------------------------------------------------- sending

    fn block_of(&mut self, fields: &[(String, String)], first: Option<(&str, &str)>) -> Vec<u8> {
        let mut refs: Vec<FieldRef<'_>> = Vec::new();
        if let Some((n, v)) = first {
            refs.push(FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false });
        }
        for (n, v) in fields {
            refs.push(FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false });
        }
        let mut block = Vec::new();
        self.encoder.encode(&refs, &mut block);
        block
    }

    /// Does what the step says on the stream. `Some(how)` means the connection is to be closed.
    pub fn act(&mut self, stream: u32, action: Action) -> Option<Ended> {
        match action {
            Action::Interim { status, headers } => {
                if self.streams.contains_key(&stream) {
                    let block = self.block_of(&headers, Some((":status", &status.to_string())));
                    frame::write_header_block(&mut self.out, stream, false, &block, self.peer_max_frame);
                }
            }
            Action::Head { status, headers, end } => {
                if self.streams.contains_key(&stream) {
                    let block = self.block_of(&headers, Some((":status", &status.to_string())));
                    frame::write_header_block(&mut self.out, stream, end, &block, self.peer_max_frame);
                    if end {
                        self.finish_local(stream);
                    }
                }
            }
            Action::Data(bytes) => {
                if let Some(s) = self.streams.get_mut(&stream) {
                    s.pending.extend_from_slice(&bytes);
                }
            }
            Action::Trailers(fields) => {
                if let Some(s) = self.streams.get_mut(&stream) {
                    s.trailers = Some(fields);
                }
            }
            Action::End => {
                if let Some(s) = self.streams.get_mut(&stream) {
                    s.end_pending = true;
                }
            }
            Action::Reset(code) => {
                // what the windows let through goes before the reset, in the order of the steps
                self.pump_data();
                self.streams.remove(&stream);
                frame::write_rst_stream(&mut self.out, stream, ErrorCode(code));
            }
            Action::GoAway { code, last_stream } => {
                // the response that came before it is written first (as far as the windows allow): a client that
                // takes GOAWAY as the end of the connection (python-h2 does) must not see data after it
                self.pump_data();
                frame::write_goaway(&mut self.out, last_stream.unwrap_or(self.highest_stream), ErrorCode(code), b"");
            }
            Action::Ping => {
                self.pings = self.pings.wrapping_add(1);
                frame::write_ping(&mut self.out, false, [b'p', b'i', b'n', b'g', 0, 0, 0, self.pings]);
            }
            Action::Settings(values) => {
                for &(id, value) in &values {
                    if id == setting::INITIAL_WINDOW_SIZE {
                        let delta = value as i64 - self.settings.initial_window as i64;
                        self.settings.initial_window = value;
                        for s in self.streams.values_mut() {
                            s.recv_window += delta;
                        }
                    }
                }
                frame::write_settings(&mut self.out, &values);
            }
            Action::WindowUpdate(increment) => {
                if stream == 0 {
                    self.recv_window += increment as i64;
                    frame::write_window_update(&mut self.out, 0, increment);
                } else if let Some(s) = self.streams.get_mut(&stream) {
                    s.recv_window += increment as i64;
                    frame::write_window_update(&mut self.out, stream, increment);
                }
            }
            Action::PushPromise { promised, headers } => {
                let block = self.block_of(&headers, None);
                let mut payload = promised.to_be_bytes().to_vec();
                payload.extend_from_slice(&block);
                Header { length: payload.len() as u32, kind: kind::PUSH_PROMISE, flags: flag::END_HEADERS, stream }.write(&mut self.out);
                self.out.extend_from_slice(&payload);
            }
            Action::Raw(bytes) => self.out.extend_from_slice(&bytes),
            Action::Close => return Some(Ended::Closed),
            Action::Cut => return Some(Ended::Cut),
        }
        None
    }

    fn finish_local(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        s.local_ended = true;
        if s.remote_ended {
            self.streams.remove(&id);
        }
    }

    /// Writes the response data that the windows allow, a frame at a time to each stream in turn.
    pub fn pump_data(&mut self) {
        if self.failed {
            return;
        }
        let mut ids: Vec<u32> = self.streams.iter().filter(|(_, s)| s.has_output()).map(|(&id, _)| id).collect();
        ids.sort_unstable();
        loop {
            let mut wrote = false;
            for &id in &ids {
                if self.out.len() - self.out_pos >= OUTPUT_HIGH_WATER {
                    return;
                }
                wrote |= self.pump_stream(id);
            }
            if !wrote {
                return;
            }
        }
    }

    fn pump_stream(&mut self, id: u32) -> bool {
        let Some(s) = self.streams.get_mut(&id) else { return false };
        if s.local_ended {
            return false;
        }
        let queued = s.queued();
        if queued == 0 {
            // everything queued has gone: what ends the stream goes
            if let Some(trailers) = s.trailers.take() {
                let block = self.block_of(&trailers, None);
                frame::write_header_block(&mut self.out, id, true, &block, self.peer_max_frame);
                self.finish_local(id);
                return true;
            }
            if s.end_pending {
                frame::write_data(&mut self.out, id, true, b"");
                self.finish_local(id);
                return true;
            }
            return false;
        }
        let room = s.send_window.min(self.send_window).max(0) as usize;
        let n = queued.min(room).min(self.peer_max_frame);
        if n == 0 {
            return false;
        }
        let last = n == queued && s.trailers.is_none();
        let end = last && s.end_pending;
        frame::write_data(&mut self.out, id, end, &s.pending[s.pending_pos..s.pending_pos + n]);
        s.pending_pos += n;
        if s.pending_pos == s.pending.len() {
            s.pending.clear();
            s.pending_pos = 0;
        }
        s.send_window -= n as i64;
        self.send_window -= n as i64;
        if end {
            self.finish_local(id);
        }
        true
    }

    /// True if a HEAD request (whose response has no body) is on the stream.
    pub fn is_head_request(&self, stream: u32) -> bool {
        self.streams.get(&stream).is_some_and(|s| s.head_request)
    }
}

/// What is wrong with a request's header list, if anything; if not, whether it is a HEAD request and the
/// Content-Length (RFC 9113 sections 8.2 and 8.3.1).
fn request_fault(fields: &[(String, String)]) -> Result<(bool, Option<u64>), String> {
    let mut method = None;
    let mut scheme = false;
    let mut path = None;
    let mut authority = false;
    let mut host = false;
    let mut regular = false;
    let mut length: Option<u64> = None;
    for (name, value) in fields {
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(format!("the value of {name:?} has a NUL, CR or LF"));
        }
        if value != value.trim_matches(|c| c == ' ' || c == '\t') {
            return Err(format!("the value of {name:?} begins or ends with whitespace"));
        }
        if let Some(pseudo) = name.strip_prefix(':') {
            if regular {
                return Err(format!("the pseudo-header {name} comes after a regular field"));
            }
            let slot_taken = match pseudo {
                "method" => method.replace(value.as_str()).is_some(),
                "scheme" => std::mem::replace(&mut scheme, true),
                "path" => path.replace(value.as_str()).is_some(),
                "authority" => std::mem::replace(&mut authority, true),
                _ => return Err(format!("{name} is not a request pseudo-header")),
            };
            if slot_taken {
                return Err(format!("{name} twice"));
            }
            continue;
        }
        regular = true;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)) {
            return Err(format!("the field name {name:?} is not lower case token characters"));
        }
        match name.as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => return Err(format!("the connection-specific field {name}")),
            "te" if value != "trailers" => return Err(format!("te: {value}")),
            "host" => host = true,
            "content-length" => {
                let n: u64 = value.parse().map_err(|_| format!("Content-Length {value:?}"))?;
                if length.is_some_and(|l| l != n) {
                    return Err("two different Content-Lengths".into());
                }
                length = Some(n);
            }
            _ => {}
        }
    }
    let method = method.ok_or("no :method")?;
    if method != "CONNECT" {
        if !scheme {
            return Err("no :scheme".into());
        }
        match path {
            None | Some("") => return Err("no :path, or an empty one".into()),
            Some(_) => {}
        }
    }
    if !authority && !host {
        return Err("neither :authority nor Host".into());
    }
    Ok((method == "HEAD", length))
}

fn trailer_fault(fields: &[(String, String)]) -> Option<&'static str> {
    for (name, value) in fields {
        if name.starts_with(':') {
            return Some("a pseudo-header in trailers");
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)) {
            return Some("a trailer name that is not lower case token characters");
        }
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Some("a trailer value with a NUL, CR or LF");
        }
    }
    None
}

// ------------------------------------------------------------------------------------------------ the driver

/// How a connection came to an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The client closed the connection.
    PeerClosed,
    /// The client said GOAWAY with no error and the streams are done, or the handler's steps said `Close`.
    Closed,
    /// The handler's steps said `Cut`: the caller is to cut the transport without a close_notify.
    Cut,
    /// A connection error (the GOAWAY has been sent).
    Failed,
}

/// A transport that [`serve`] can read from with a timeout.
pub trait Transport: Read + Write {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl Transport for ServerStream<TcpStream> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.get_ref().set_read_timeout(timeout)
    }
}

struct Due {
    at: Instant,
    seq: u64,
    stream: u32,
    action: Action,
}

fn send_output<T: Transport>(io: &mut T, conn: &mut ServerConn) -> io::Result<()> {
    if conn.wants_write() {
        let n = conn.output().len();
        let res = io.write_all(conn.output());
        conn.consume_output(n);
        res?;
        io.flush()?;
    }
    Ok(())
}

fn request_of(stream: u32, fields: Vec<(String, String)>) -> Request {
    let mut r = Request { stream, ..Request::default() };
    for (name, value) in fields {
        match name.as_str() {
            ":method" => r.method = value,
            ":scheme" => r.scheme = value,
            ":authority" => r.authority = value,
            ":path" => r.path = value,
            _ => r.headers.push((name, value)),
        }
    }
    if r.authority.is_empty() {
        r.authority = r.header("host").unwrap_or("").to_string();
    }
    r
}

/// Serves one connection until it ends: reads requests, calls `handler` with each complete one, and plays out the
/// steps it returns.
pub fn serve<T: Transport>(io: &mut T, settings: &Settings, handler: &mut dyn FnMut(&Request) -> Vec<Step>) -> io::Result<Ended> {
    let mut conn = ServerConn::new(settings.clone());
    serve_with(io, &mut conn, handler)
}

/// [`serve`] with a connection the caller made (and keeps looking at afterwards: its complaints, for one).
pub fn serve_with<T: Transport>(io: &mut T, conn: &mut ServerConn, handler: &mut dyn FnMut(&Request) -> Vec<Step>) -> io::Result<Ended> {
    const IDLE: Duration = Duration::from_millis(50);
    let mut timers: Vec<Due> = Vec::new();
    let mut requests: HashMap<u32, Request> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut seq = 0u64;
    let mut asked_to_go = false;
    loop {
        // what is due
        timers.sort_by_key(|d| (d.at, d.seq));
        let now = Instant::now();
        let due = timers.iter().take_while(|d| d.at <= now).count();
        for d in timers.drain(..due).collect::<Vec<_>>() {
            if let Some(end) = conn.act(d.stream, d.action) {
                if end == Ended::Closed {
                    send_output(io, conn)?;
                }
                return Ok(end);
            }
        }
        conn.pump_data();
        send_output(io, conn)?;
        if asked_to_go && !conn.streams.values().any(|s| !s.local_ended) {
            return Ok(Ended::Closed);
        }
        let wait = timers.first().map_or(IDLE, |d| d.at.saturating_duration_since(Instant::now()).min(IDLE)).max(Duration::from_millis(1));
        io.set_read_timeout(Some(wait))?;
        match io.read(&mut buf) {
            Ok(0) => return Ok(Ended::PeerClosed),
            Ok(n) => conn.receive(&buf[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => continue,
            Err(e) => return Err(e),
        }
        let events = match conn.process() {
            Ok(events) => events,
            Err(_) => {
                let _ = send_output(io, conn);
                return Ok(Ended::Failed);
            }
        };
        for event in events {
            let finished = match event {
                Event::Headers { stream, fields, end_stream } => {
                    match requests.get_mut(&stream) {
                        Some(r) => r.trailers = fields,
                        None => {
                            requests.insert(stream, request_of(stream, fields));
                        }
                    }
                    end_stream.then_some(stream)
                }
                Event::Data { stream, data, end_stream } => {
                    if let Some(r) = requests.get_mut(&stream) {
                        r.body.extend_from_slice(&data);
                    }
                    end_stream.then_some(stream)
                }
                Event::Reset { stream, .. } => {
                    requests.remove(&stream);
                    timers.retain(|d| d.stream != stream);
                    None
                }
                Event::GoAway { .. } => {
                    asked_to_go = true;
                    None
                }
            };
            if let Some(stream) = finished {
                if let Some(request) = requests.remove(&stream) {
                    let mut at = Instant::now();
                    for step in handler(&request) {
                        at += step.after;
                        seq += 1;
                        timers.push(Due { at, seq, stream, action: step.action });
                    }
                }
            }
        }
    }
}
