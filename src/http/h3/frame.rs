//! HTTP/3 frames (RFC 9114 section 7): a reader that takes a stream's bytes in any pieces and says what frames they hold, and what
//! is needed to write the ones a client sends. No I/O. It checks what can be checked of a frame alone (which frames a stream may
//! carry, the size of the ones that are kept whole, the payloads that must be one integer, SETTINGS made of pairs) and leaves the
//! order of frames in a message to the connection, which knows what the stream is for.
//!
//! The bytes of a DATA frame are not copied: they are reported as ranges of the input that was given. Frames of types this client
//! does not know are skipped as they come, however long they are (RFC 9114 section 9: extension frames, and the reserved ones that
//! peers send to keep us honest), without being held.

use crate::quic::wire::{self, MAX_VARINT};
use std::ops::Range;

/// Frame types (RFC 9114 section 7.2).
pub(crate) mod ty {
    pub(crate) const DATA: u64 = 0x00;
    pub(crate) const HEADERS: u64 = 0x01;
    pub(crate) const CANCEL_PUSH: u64 = 0x03;
    pub(crate) const SETTINGS: u64 = 0x04;
    pub(crate) const PUSH_PROMISE: u64 = 0x05;
    pub(crate) const GOAWAY: u64 = 0x07;
    pub(crate) const MAX_PUSH_ID: u64 = 0x0d;
    /// The types of HTTP/2 frames that have no meaning in HTTP/3 (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION): receiving one is an error.
    pub(crate) fn is_http2_reserved(t: u64) -> bool {
        matches!(t, 0x02 | 0x06 | 0x08 | 0x09)
    }
}

/// Stream types of unidirectional streams (RFC 9114 section 6.2, RFC 9204 section 4.2).
pub(crate) mod stream_type {
    pub(crate) const CONTROL: u64 = 0x00;
    pub(crate) const PUSH: u64 = 0x01;
    pub(crate) const QPACK_ENCODER: u64 = 0x02;
    pub(crate) const QPACK_DECODER: u64 = 0x03;
}

/// Setting identifiers (RFC 9114 section 7.2.4.1, RFC 9204 section 5).
pub(crate) mod setting {
    pub(crate) const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub(crate) const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub(crate) const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// The ones of HTTP/2 that HTTP/3 does not have: receiving one is an error.
    pub(crate) fn is_http2_reserved(id: u64) -> bool {
        matches!(id, 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
    }
}

/// Error codes (RFC 9114 section 8.1).
pub(crate) mod code {
    pub(crate) const H3_NO_ERROR: u64 = 0x100;
    pub(crate) const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    pub(crate) const H3_INTERNAL_ERROR: u64 = 0x102;
    pub(crate) const H3_STREAM_CREATION_ERROR: u64 = 0x103;
    pub(crate) const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub(crate) const H3_FRAME_UNEXPECTED: u64 = 0x105;
    pub(crate) const H3_FRAME_ERROR: u64 = 0x106;
    pub(crate) const H3_EXCESSIVE_LOAD: u64 = 0x107;
    pub(crate) const H3_ID_ERROR: u64 = 0x108;
    pub(crate) const H3_SETTINGS_ERROR: u64 = 0x109;
    pub(crate) const H3_MISSING_SETTINGS: u64 = 0x10a;
    pub(crate) const H3_REQUEST_REJECTED: u64 = 0x10b;
    pub(crate) const H3_REQUEST_CANCELLED: u64 = 0x10c;
    pub(crate) const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
    pub(crate) const H3_MESSAGE_ERROR: u64 = 0x10e;
    pub(crate) const H3_CONNECT_ERROR: u64 = 0x10f;
    pub(crate) const H3_VERSION_FALLBACK: u64 = 0x110;
}

/// Why a stream's frames cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// The connection is at fault: this error code closes it.
    Connection(u64, &'static str),
    /// A HEADERS frame is longer than the reader keeps. The stream, not the connection, is lost.
    HeadersTooLarge,
}

impl FrameError {
    fn conn(code: u64, reason: &'static str) -> FrameError {
        FrameError::Connection(code, reason)
    }
}

/// What a stream may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A request stream (as a client reads it: the response): HEADERS and DATA.
    Request,
    /// The control stream (as a client reads the server's): SETTINGS first and once, then GOAWAY and CANCEL_PUSH.
    Control,
}

/// A frame, or a piece of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// Bytes of a DATA frame's payload: this range of the input given to [`FrameReader::feed`]. A frame may come in several.
    Data(Range<usize>),
    /// A whole HEADERS frame: the encoded field section.
    Headers(Vec<u8>),
    /// A whole SETTINGS frame: the identifiers and values, in order.
    Settings(Vec<(u64, u64)>),
    GoAway(u64),
    CancelPush(u64),
    MaxPushId(u64),
}

/// Where the reader is in a frame.
#[derive(Debug)]
enum State {
    /// Reading the type: the bytes so far.
    Type(Partial),
    /// Reading the length of a frame of this type.
    Length(u64, Partial),
    /// A DATA frame: this many bytes of payload to come.
    Data(u64),
    /// A frame that is kept whole: its type, the bytes still to come and what has come.
    Whole(u64, u64, Vec<u8>),
    /// A frame that is not wanted: this many bytes to skip.
    Skip(u64),
    /// An error was returned: nothing more is read.
    Failed,
}

/// A variable-length integer that is not all here yet.
#[derive(Debug, Default)]
struct Partial {
    bytes: [u8; 8],
    have: usize,
}

impl Partial {
    /// Takes bytes of `input` from `*pos` on until the integer is whole; returns it then.
    fn take(&mut self, input: &[u8], pos: &mut usize) -> Option<u64> {
        if self.have == 0 {
            let first = *input.get(*pos)?;
            self.bytes[0] = first;
            self.have = 1;
            *pos += 1;
        }
        let need = 1usize << (self.bytes[0] >> 6);
        while self.have < need {
            let b = *input.get(*pos)?;
            self.bytes[self.have] = b;
            self.have += 1;
            *pos += 1;
        }
        let (v, n) = wire::get_varint(&self.bytes[..need]).expect("a whole variable-length integer");
        debug_assert_eq!(n, need);
        *self = Partial::default();
        Some(v)
    }
}

/// Reads the frames of one stream.
#[derive(Debug)]
pub(crate) struct FrameReader {
    kind: Kind,
    state: State,
    /// The largest HEADERS frame kept (the encoded field section).
    max_headers: usize,
    /// The control stream has had its SETTINGS.
    settings_seen: bool,
    /// Whether any frame has been read.
    started: bool,
}

/// No frame that is kept whole besides HEADERS (SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID) is longer than this: SETTINGS carries a few
/// dozen pairs, at most, and the others one integer.
pub(crate) const MAX_WHOLE: u64 = 16 << 10;

impl FrameReader {
    pub(crate) fn new(kind: Kind, max_headers: usize) -> FrameReader {
        FrameReader { kind, state: State::Type(Partial::default()), max_headers, settings_seen: false, started: false }
    }

    /// Whether the stream is between frames (so that it may end here).
    pub(crate) fn at_frame_boundary(&self) -> bool {
        matches!(&self.state, State::Type(p) if p.have == 0)
    }

    /// Takes in `input` and appends what it holds to `out`. The input is consumed whole: what is cut off at its end waits for the
    /// next call. After an error nothing is read.
    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<Event>) -> Result<(), FrameError> {
        let mut pos = 0;
        loop {
            match &mut self.state {
                State::Failed => return Err(FrameError::conn(code::H3_INTERNAL_ERROR, "the stream is not read after an error")),
                State::Type(p) => {
                    let Some(t) = p.take(input, &mut pos) else { return Ok(()) };
                    if let Err(e) = self.check_type(t) {
                        self.state = State::Failed;
                        return Err(e);
                    }
                    self.started = true;
                    self.state = State::Length(t, Partial::default());
                }
                State::Length(t, p) => {
                    let t = *t;
                    let Some(len) = p.take(input, &mut pos) else { return Ok(()) };
                    match self.begin(t, len) {
                        Ok(state) => self.state = state,
                        Err(e) => {
                            self.state = State::Failed;
                            return Err(e);
                        }
                    }
                }
                State::Data(remaining) => {
                    if pos >= input.len() {
                        return Ok(());
                    }
                    let n = (*remaining).min((input.len() - pos) as u64) as usize;
                    out.push(Event::Data(pos..pos + n));
                    pos += n;
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        self.state = State::Type(Partial::default());
                    }
                }
                State::Skip(remaining) => {
                    let n = (*remaining).min((input.len() - pos) as u64) as usize;
                    pos += n;
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        self.state = State::Type(Partial::default());
                    } else {
                        return Ok(());
                    }
                }
                State::Whole(t, remaining, buf) => {
                    let n = (*remaining).min((input.len() - pos) as u64) as usize;
                    buf.extend_from_slice(&input[pos..pos + n]);
                    pos += n;
                    *remaining -= n as u64;
                    if *remaining > 0 {
                        return Ok(());
                    }
                    let (t, payload) = (*t, std::mem::take(buf));
                    self.state = State::Type(Partial::default());
                    if let Err(e) = self.complete(t, &payload, out) {
                        self.state = State::Failed;
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Whether a frame of this type may be here.
    fn check_type(&mut self, t: u64) -> Result<(), FrameError> {
        if ty::is_http2_reserved(t) {
            return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, "a frame type of HTTP/2 that HTTP/3 does not have"));
        }
        match self.kind {
            Kind::Request => match t {
                ty::DATA | ty::HEADERS => {}
                ty::PUSH_PROMISE => return Err(FrameError::conn(code::H3_ID_ERROR, "a push promise, when no push was allowed")),
                ty::SETTINGS | ty::GOAWAY | ty::CANCEL_PUSH | ty::MAX_PUSH_ID => return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, "a frame of the control stream on a request stream")),
                _ => {}
            },
            Kind::Control => {
                if !self.started && t != ty::SETTINGS {
                    return Err(FrameError::conn(code::H3_MISSING_SETTINGS, "the control stream does not begin with SETTINGS"));
                }
                match t {
                    ty::SETTINGS if self.settings_seen => return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, "a second SETTINGS frame")),
                    ty::DATA | ty::HEADERS | ty::PUSH_PROMISE => return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, "a frame of a request stream on the control stream")),
                    // a client does not accept MAX_PUSH_ID (RFC 9114 section 7.2.7)
                    ty::MAX_PUSH_ID => return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, "MAX_PUSH_ID sent to a client")),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// What follows the length of a frame.
    fn begin(&mut self, t: u64, len: u64) -> Result<State, FrameError> {
        Ok(match t {
            ty::DATA => {
                if len == 0 {
                    State::Type(Partial::default())
                } else {
                    State::Data(len)
                }
            }
            ty::HEADERS => {
                if len > self.max_headers as u64 {
                    return Err(FrameError::HeadersTooLarge);
                }
                State::Whole(t, len, Vec::with_capacity(len.min(4096) as usize))
            }
            ty::SETTINGS | ty::GOAWAY | ty::CANCEL_PUSH => {
                if len > MAX_WHOLE {
                    return Err(FrameError::conn(code::H3_EXCESSIVE_LOAD, "a control frame that is too long"));
                }
                State::Whole(t, len, Vec::with_capacity(len as usize))
            }
            _ => State::Skip(len),
        })
    }

    fn complete(&mut self, t: u64, payload: &[u8], out: &mut Vec<Event>) -> Result<(), FrameError> {
        match t {
            ty::HEADERS => out.push(Event::Headers(payload.to_vec())),
            ty::SETTINGS => {
                self.settings_seen = true;
                let mut pairs = vec![];
                let mut pos = 0;
                while pos < payload.len() {
                    let (id, n) = wire::get_varint(&payload[pos..]).ok_or(FrameError::conn(code::H3_FRAME_ERROR, "a SETTINGS frame that ends inside a setting"))?;
                    pos += n;
                    let (value, n) = wire::get_varint(&payload[pos..]).ok_or(FrameError::conn(code::H3_FRAME_ERROR, "a SETTINGS frame that ends inside a setting"))?;
                    pos += n;
                    pairs.push((id, value));
                }
                out.push(Event::Settings(pairs));
            }
            ty::GOAWAY | ty::CANCEL_PUSH => {
                let (v, n) = wire::get_varint(payload).ok_or(FrameError::conn(code::H3_FRAME_ERROR, "a frame that should hold one integer and does not"))?;
                if n != payload.len() {
                    return Err(FrameError::conn(code::H3_FRAME_ERROR, "a frame that should hold one integer and holds more"));
                }
                out.push(if t == ty::GOAWAY { Event::GoAway(v) } else { Event::CancelPush(v) });
            }
            _ => unreachable!("only the frames that are kept whole are completed"),
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------ writing

/// The header of a frame: its type and the length of its payload.
pub(crate) fn put_frame_header(out: &mut Vec<u8>, t: u64, len: u64) {
    debug_assert!(len <= MAX_VARINT);
    wire::put_varint(out, t);
    wire::put_varint(out, len);
}

/// A HEADERS frame holding the encoded field section.
pub(crate) fn put_headers(out: &mut Vec<u8>, block: &[u8]) {
    put_frame_header(out, ty::HEADERS, block.len() as u64);
    out.extend_from_slice(block);
}

/// A DATA frame holding `data`.
pub(crate) fn put_data(out: &mut Vec<u8>, data: &[u8]) {
    put_frame_header(out, ty::DATA, data.len() as u64);
    out.extend_from_slice(data);
}

/// What we announce: our QPACK limits and the largest field section we take, and one reserved setting of the form `0x1f * N + 0x21`
/// that peers must ignore (RFC 9114 section 7.2.4.1: so that they do).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) qpack_max_table_capacity: u64,
    pub(crate) qpack_blocked_streams: u64,
    pub(crate) max_field_section_size: u64,
}

/// The first bytes of our control stream: its type and the SETTINGS frame.
pub(crate) fn control_stream_start(s: &Settings) -> Vec<u8> {
    let mut payload = vec![];
    for (id, v) in [(setting::QPACK_MAX_TABLE_CAPACITY, s.qpack_max_table_capacity), (setting::QPACK_BLOCKED_STREAMS, s.qpack_blocked_streams), (setting::MAX_FIELD_SECTION_SIZE, s.max_field_section_size), (0x1f * 7 + 0x21, 0)] {
        wire::put_varint(&mut payload, id);
        wire::put_varint(&mut payload, v);
    }
    let mut out = vec![];
    wire::put_varint(&mut out, stream_type::CONTROL);
    put_frame_header(&mut out, ty::SETTINGS, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

/// What the peer announced, from the pairs of its SETTINGS frame. Settings that are not known are ignored; one that is given twice, or
/// that HTTP/2 had and HTTP/3 does not, is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerSettings {
    pub(crate) qpack_max_table_capacity: u64,
    pub(crate) qpack_blocked_streams: u64,
    /// The largest field section the peer takes (none: no limit announced).
    pub(crate) max_field_section_size: Option<u64>,
}

impl PeerSettings {
    pub(crate) fn from_pairs(pairs: &[(u64, u64)]) -> Result<PeerSettings, FrameError> {
        let mut s = PeerSettings { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: None };
        let mut seen: Vec<u64> = vec![];
        for &(id, v) in pairs {
            if setting::is_http2_reserved(id) {
                return Err(FrameError::conn(code::H3_SETTINGS_ERROR, "a setting of HTTP/2 that HTTP/3 does not have"));
            }
            if seen.contains(&id) {
                return Err(FrameError::conn(code::H3_SETTINGS_ERROR, "a setting that is given twice"));
            }
            seen.push(id);
            match id {
                setting::QPACK_MAX_TABLE_CAPACITY => s.qpack_max_table_capacity = v,
                setting::QPACK_BLOCKED_STREAMS => s.qpack_blocked_streams = v,
                setting::MAX_FIELD_SECTION_SIZE => s.max_field_section_size = Some(v),
                _ => {}
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
#[cfg(any(test, pratique_fuzzing))]
#[path = "frame_harness.rs"]
pub(crate) mod harness;
