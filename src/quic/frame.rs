//! QUIC frames (RFC 9000 section 19): reading the payload of a packet as the frames in it, and writing them.
//!
//! Reading is zero-copy and strict. Everything that a frame says about itself is checked while it is read (a length that goes
//! past the end of the packet, a connection id that is too long, a range of an ACK frame that reaches below packet number 0), and
//! what a frame says about the connection is left to the connection. A [`FrameError`] says which transport error the connection
//! is to be closed with. Frames of the DATAGRAM extension (RFC 9221) are not known, since nothing here negotiates it, so they are
//! unknown frame types.

use super::packet::PacketType;
use super::wire::{put_varint, varint_len, Reader, Truncated, MAX_VARINT};
use std::ops::RangeInclusive;

/// The transport error codes of RFC 9000 section 20.1 that reading frames can lead to.
pub const FRAME_ENCODING_ERROR: u64 = 0x07;
pub const PROTOCOL_VIOLATION: u64 = 0x0a;

/// The largest number of streams of one kind (RFC 9000 section 4.6): stream ids are 62 bits, two of which are the kind.
pub const MAX_STREAMS_LIMIT: u64 = 1 << 60;

/// The longest connection id a NEW_CONNECTION_ID frame may carry (RFC 9000 section 19.15), as a packet's.
const MAX_CID_LEN: usize = super::packet::MAX_CID_LEN;

/// What is wrong with the payload of a packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameErrorKind {
    /// The packet has no frames in it (PROTOCOL_VIOLATION, RFC 9000 section 12.4).
    Empty,
    /// The packet ends before a frame does (FRAME_ENCODING_ERROR).
    Truncated,
    /// A frame type that is not known (FRAME_ENCODING_ERROR).
    UnknownType,
    /// A frame type written in more bytes than it needs (PROTOCOL_VIOLATION).
    TypeNotMinimal,
    /// A frame that this kind of packet may not have (PROTOCOL_VIOLATION).
    NotAllowed,
    /// A field that has a value that it may not have (FRAME_ENCODING_ERROR).
    Invalid(&'static str),
}

/// A frame that could not be read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameError {
    pub kind: FrameErrorKind,
    /// The type of the frame, for the CONNECTION_CLOSE frame that says which frame it was that was wrong (0 if there was no frame,
    /// or no frame type that could be read).
    pub frame_type: u64,
}

impl FrameError {
    /// The transport error code to close the connection with.
    pub fn transport_error(&self) -> u64 {
        match self.kind {
            FrameErrorKind::Empty | FrameErrorKind::TypeNotMinimal | FrameErrorKind::NotAllowed => PROTOCOL_VIOLATION,
            FrameErrorKind::Truncated | FrameErrorKind::UnknownType | FrameErrorKind::Invalid(_) => FRAME_ENCODING_ERROR,
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            FrameErrorKind::Empty => write!(f, "a packet with no frames"),
            FrameErrorKind::Truncated => write!(f, "frame {:#x} is cut short", self.frame_type),
            FrameErrorKind::UnknownType => write!(f, "unknown frame type {:#x}", self.frame_type),
            FrameErrorKind::TypeNotMinimal => write!(f, "frame type {:#x} is not in the fewest bytes", self.frame_type),
            FrameErrorKind::NotAllowed => write!(f, "frame {:#x} may not be in this kind of packet", self.frame_type),
            FrameErrorKind::Invalid(what) => write!(f, "frame {:#x}: {what}", self.frame_type),
        }
    }
}

impl std::error::Error for FrameError {}

/// The ECN counts of an ACK frame of type 0x03.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// An ACK frame (RFC 9000 section 19.3). Its ranges were checked when it was read: none of them reaches below 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ack<'a> {
    /// The largest packet number acknowledged.
    pub largest: u64,
    /// The time since that packet was received, as sent: in units of 2^ack_delay_exponent microseconds (see [`Ack::delay_micros`]).
    pub delay: u64,
    /// How many packet numbers below `largest` the first range holds too.
    pub first_range: u64,
    range_count: u64,
    ranges: &'a [u8],
    pub ecn: Option<EcnCounts>,
}

impl<'a> Ack<'a> {
    /// The delay in microseconds, when the peer's `ack_delay_exponent` transport parameter is `exponent` (3 if it sent none).
    pub fn delay_micros(&self, exponent: u32) -> u64 {
        self.delay.saturating_mul(1u64 << exponent.min(20))
    }

    /// The packet numbers acknowledged as ranges, from the highest down. The first holds `largest`.
    pub fn ranges(&self) -> AckRanges<'a> {
        AckRanges { next: Some(self.largest - self.first_range..=self.largest), rest: Reader::new(self.ranges), left: self.range_count }
    }

    /// How many ranges there are after the first.
    pub fn additional_ranges(&self) -> u64 {
        self.range_count
    }

    /// Whether `pn` is acknowledged.
    pub fn acknowledges(&self, pn: u64) -> bool {
        for r in self.ranges() {
            if pn > *r.end() {
                return false;
            }
            if pn >= *r.start() {
                return true;
            }
        }
        false
    }
}

/// The ranges of an [`Ack`], the highest first, each as the packet numbers from the smallest to the largest.
#[derive(Clone, Debug)]
pub struct AckRanges<'a> {
    next: Option<RangeInclusive<u64>>,
    rest: Reader<'a>,
    left: u64,
}

impl Iterator for AckRanges<'_> {
    type Item = RangeInclusive<u64>;

    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        let this = self.next.take()?;
        if self.left > 0 {
            self.left -= 1;
            // a gap of `gap` packets not acknowledged, and one more than that, lie between the smallest of this one and the
            // largest of the next (RFC 9000 section 19.3.1)
            let following = (|| {
                let gap = self.rest.varint().ok()?;
                let len = self.rest.varint().ok()?;
                let largest = this.start().checked_sub(gap)?.checked_sub(2)?;
                Some(largest.checked_sub(len)?..=largest)
            })();
            self.next = following;
        }
        Some(this)
    }
}

/// A frame (RFC 9000 section 19). What is not a number borrows from the packet it was read from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame<'a> {
    /// A run of this many PADDING frames, which are a byte each.
    Padding(usize),
    Ping,
    Ack(Ack<'a>),
    ResetStream { id: u64, error: u64, final_size: u64 },
    StopSending { id: u64, error: u64 },
    Crypto { offset: u64, data: &'a [u8] },
    NewToken { token: &'a [u8] },
    Stream { id: u64, offset: u64, data: &'a [u8], fin: bool },
    MaxData(u64),
    MaxStreamData { id: u64, max: u64 },
    MaxStreams { bidirectional: bool, max: u64 },
    DataBlocked(u64),
    StreamDataBlocked { id: u64, limit: u64 },
    StreamsBlocked { bidirectional: bool, limit: u64 },
    NewConnectionId { sequence: u64, retire_prior_to: u64, cid: &'a [u8], reset_token: &'a [u8; 16] },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE: of the transport (type 0x1c, with the type of the frame that was at fault, 0 if none) or of the
    /// application (type 0x1d, with no frame type).
    ConnectionClose { code: u64, frame_type: Option<u64>, reason: &'a [u8] },
    HandshakeDone,
}

/// The frame types (RFC 9000 table 3).
pub mod types {
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    pub const CRYPTO: u64 = 0x06;
    pub const NEW_TOKEN: u64 = 0x07;
    /// STREAM frames are 0x08 to 0x0f: this with the bits below.
    pub const STREAM: u64 = 0x08;
    pub const STREAM_FIN: u64 = 0x01;
    pub const STREAM_LEN: u64 = 0x02;
    pub const STREAM_OFF: u64 = 0x04;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub const PATH_CHALLENGE: u64 = 0x1a;
    pub const PATH_RESPONSE: u64 = 0x1b;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    pub const HANDSHAKE_DONE: u64 = 0x1e;
}

use types::*;

/// Whether a frame of type `ft` may be in a packet of type `ty` (RFC 9000 table 3, the column of packet types). Of the frames,
/// those of streams and flow control are for 0-RTT and 1-RTT packets only, those of the handshake (ACK, CRYPTO) are for
/// everything but 0-RTT, and PADDING, PING and the CONNECTION_CLOSE frame of the transport are for all four; NEW_TOKEN,
/// PATH_RESPONSE and HANDSHAKE_DONE are for 1-RTT only.
pub fn allowed_in(ft: u64, ty: PacketType) -> bool {
    let initial = ty == PacketType::Initial;
    let handshake = ty == PacketType::Handshake;
    let zero_rtt = ty == PacketType::ZeroRtt;
    let one_rtt = ty == PacketType::OneRtt;
    match ft {
        PADDING | PING | CONNECTION_CLOSE => initial || handshake || zero_rtt || one_rtt,
        ACK | ACK_ECN | CRYPTO => initial || handshake || one_rtt,
        NEW_TOKEN | PATH_RESPONSE | HANDSHAKE_DONE => one_rtt,
        RESET_STREAM | STOP_SENDING | 0x08..=0x0f | MAX_DATA..=PATH_CHALLENGE | CONNECTION_CLOSE_APP => zero_rtt || one_rtt,
        _ => false,
    }
}

/// What a frame body could not be, before it is told what frame it was in.
enum Bad {
    Short,
    Invalid(&'static str),
}

impl From<Truncated> for Bad {
    fn from(_: Truncated) -> Bad {
        Bad::Short
    }
}

/// Reads the sum of an offset and a length that must stay in the range that offsets of a stream have (RFC 9000 section 19.8).
fn check_end(offset: u64, len: usize) -> Result<(), Bad> {
    if offset.checked_add(len as u64).is_none_or(|e| e > MAX_VARINT) {
        return Err(Bad::Invalid("offset and length go past 2^62 - 1"));
    }
    Ok(())
}

impl<'a> Frame<'a> {
    /// Reads one frame from the front of `r`, for a packet of type `ty`.
    pub fn read(r: &mut Reader<'a>, ty: PacketType) -> Result<Frame<'a>, FrameError> {
        let err = |kind, frame_type| FrameError { kind, frame_type };
        let (ft, minimal) = r.varint_minimal().map_err(|_| err(FrameErrorKind::Truncated, 0))?;
        if !minimal {
            return Err(err(FrameErrorKind::TypeNotMinimal, ft));
        }
        if ft > HANDSHAKE_DONE {
            return Err(err(FrameErrorKind::UnknownType, ft));
        }
        if !allowed_in(ft, ty) {
            return Err(err(FrameErrorKind::NotAllowed, ft));
        }
        Self::body(ft, r).map_err(|bad| match bad {
            Bad::Short => err(FrameErrorKind::Truncated, ft),
            Bad::Invalid(what) => err(FrameErrorKind::Invalid(what), ft),
        })
    }

    fn body(ft: u64, r: &mut Reader<'a>) -> Result<Frame<'a>, Bad> {
        Ok(match ft {
            PADDING => {
                // the type was the first byte of the run
                let mut n = 1;
                while r.rest().first() == Some(&0) {
                    r.u8()?;
                    n += 1;
                }
                Frame::Padding(n)
            }
            PING => Frame::Ping,
            ACK | ACK_ECN => {
                let largest = r.varint()?;
                let delay = r.varint()?;
                let range_count = r.varint()?;
                let first_range = r.varint()?;
                if first_range > largest {
                    return Err(Bad::Invalid("the first range of an ACK goes below packet number 0"));
                }
                // each range after the first is two numbers, a byte each at least: that bounds what is looked at below
                if range_count > (r.rest().len() / 2) as u64 {
                    return Err(Bad::Short);
                }
                let start = r.rest();
                let mut smallest = largest - first_range;
                for _ in 0..range_count {
                    let gap = r.varint()?;
                    let len = r.varint()?;
                    let next_largest = smallest.checked_sub(gap).and_then(|v| v.checked_sub(2));
                    let next_smallest = next_largest.and_then(|l| l.checked_sub(len));
                    smallest = next_smallest.ok_or(Bad::Invalid("a range of an ACK goes below packet number 0"))?;
                }
                let ranges = &start[..start.len() - r.rest().len()];
                let ecn = if ft == ACK_ECN { Some(EcnCounts { ect0: r.varint()?, ect1: r.varint()?, ce: r.varint()? }) } else { None };
                Frame::Ack(Ack { largest, delay, first_range, range_count, ranges, ecn })
            }
            RESET_STREAM => Frame::ResetStream { id: r.varint()?, error: r.varint()?, final_size: r.varint()? },
            STOP_SENDING => Frame::StopSending { id: r.varint()?, error: r.varint()? },
            CRYPTO => {
                let offset = r.varint()?;
                let data = r.length_prefixed()?;
                check_end(offset, data.len())?;
                Frame::Crypto { offset, data }
            }
            NEW_TOKEN => {
                let token = r.length_prefixed()?;
                if token.is_empty() {
                    return Err(Bad::Invalid("an empty token"));
                }
                Frame::NewToken { token }
            }
            0x08..=0x0f => {
                let id = r.varint()?;
                let offset = if ft & STREAM_OFF != 0 { r.varint()? } else { 0 };
                let data = if ft & STREAM_LEN != 0 { r.length_prefixed()? } else { r.bytes(r.rest().len())? };
                check_end(offset, data.len())?;
                Frame::Stream { id, offset, data, fin: ft & STREAM_FIN != 0 }
            }
            MAX_DATA => Frame::MaxData(r.varint()?),
            MAX_STREAM_DATA => Frame::MaxStreamData { id: r.varint()?, max: r.varint()? },
            MAX_STREAMS_BIDI | MAX_STREAMS_UNI => {
                let max = r.varint()?;
                if max > MAX_STREAMS_LIMIT {
                    return Err(Bad::Invalid("more than 2^60 streams"));
                }
                Frame::MaxStreams { bidirectional: ft == MAX_STREAMS_BIDI, max }
            }
            DATA_BLOCKED => Frame::DataBlocked(r.varint()?),
            STREAM_DATA_BLOCKED => Frame::StreamDataBlocked { id: r.varint()?, limit: r.varint()? },
            STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => {
                let limit = r.varint()?;
                if limit > MAX_STREAMS_LIMIT {
                    return Err(Bad::Invalid("more than 2^60 streams"));
                }
                Frame::StreamsBlocked { bidirectional: ft == STREAMS_BLOCKED_BIDI, limit }
            }
            NEW_CONNECTION_ID => {
                let sequence = r.varint()?;
                let retire_prior_to = r.varint()?;
                let len = r.u8()? as usize;
                if len == 0 || len > MAX_CID_LEN {
                    return Err(Bad::Invalid("a connection id that is not of 1 to 20 bytes"));
                }
                if retire_prior_to > sequence {
                    return Err(Bad::Invalid("retire_prior_to is more than the sequence number"));
                }
                let cid = r.bytes(len)?;
                let reset_token = r.bytes(16)?.try_into().map_err(|_| Bad::Short)?;
                Frame::NewConnectionId { sequence, retire_prior_to, cid, reset_token }
            }
            RETIRE_CONNECTION_ID => Frame::RetireConnectionId(r.varint()?),
            PATH_CHALLENGE => Frame::PathChallenge(r.bytes(8)?.try_into().map_err(|_| Bad::Short)?),
            PATH_RESPONSE => Frame::PathResponse(r.bytes(8)?.try_into().map_err(|_| Bad::Short)?),
            CONNECTION_CLOSE => {
                let code = r.varint()?;
                let frame_type = Some(r.varint()?);
                let reason = r.length_prefixed()?;
                Frame::ConnectionClose { code, frame_type, reason }
            }
            CONNECTION_CLOSE_APP => {
                let code = r.varint()?;
                let reason = r.length_prefixed()?;
                Frame::ConnectionClose { code, frame_type: None, reason }
            }
            HANDSHAKE_DONE => Frame::HandshakeDone,
            _ => unreachable!("the frame types that are known are handled"),
        })
    }

    /// Whether a packet that has this frame has to be acknowledged: all but ACK, PADDING and CONNECTION_CLOSE (RFC 9002 section 2).
    pub fn ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Padding(_) | Frame::Ack(_) | Frame::ConnectionClose { .. })
    }

    /// The frame type as it is written (for a STREAM frame, with the flags that [`Frame::write`] sets).
    pub fn frame_type(&self) -> u64 {
        match self {
            Frame::Padding(_) => PADDING,
            Frame::Ping => PING,
            Frame::Ack(a) => {
                if a.ecn.is_some() {
                    ACK_ECN
                } else {
                    ACK
                }
            }
            Frame::ResetStream { .. } => RESET_STREAM,
            Frame::StopSending { .. } => STOP_SENDING,
            Frame::Crypto { .. } => CRYPTO,
            Frame::NewToken { .. } => NEW_TOKEN,
            Frame::Stream { offset, fin, .. } => STREAM | STREAM_LEN | if *offset != 0 { STREAM_OFF } else { 0 } | u64::from(*fin),
            Frame::MaxData(_) => MAX_DATA,
            Frame::MaxStreamData { .. } => MAX_STREAM_DATA,
            Frame::MaxStreams { bidirectional, .. } => {
                if *bidirectional {
                    MAX_STREAMS_BIDI
                } else {
                    MAX_STREAMS_UNI
                }
            }
            Frame::DataBlocked(_) => DATA_BLOCKED,
            Frame::StreamDataBlocked { .. } => STREAM_DATA_BLOCKED,
            Frame::StreamsBlocked { bidirectional, .. } => {
                if *bidirectional {
                    STREAMS_BLOCKED_BIDI
                } else {
                    STREAMS_BLOCKED_UNI
                }
            }
            Frame::NewConnectionId { .. } => NEW_CONNECTION_ID,
            Frame::RetireConnectionId(_) => RETIRE_CONNECTION_ID,
            Frame::PathChallenge(_) => PATH_CHALLENGE,
            Frame::PathResponse(_) => PATH_RESPONSE,
            Frame::ConnectionClose { frame_type: Some(_), .. } => CONNECTION_CLOSE,
            Frame::ConnectionClose { frame_type: None, .. } => CONNECTION_CLOSE_APP,
            Frame::HandshakeDone => HANDSHAKE_DONE,
        }
    }

    /// How many bytes [`Frame::write`] appends.
    pub fn len(&self) -> usize {
        let v = varint_len;
        // (every frame type is a byte)
        1 + match self {
            Frame::Padding(n) => n - 1,
            Frame::Ping | Frame::HandshakeDone => 0,
            Frame::Ack(a) => {
                v(a.largest) + v(a.delay) + v(a.range_count) + v(a.first_range) + a.ranges.len() + a.ecn.map_or(0, |e| v(e.ect0) + v(e.ect1) + v(e.ce))
            }
            Frame::ResetStream { id, error, final_size } => v(*id) + v(*error) + v(*final_size),
            Frame::StopSending { id, error } => v(*id) + v(*error),
            Frame::Crypto { offset, data } => v(*offset) + v(data.len() as u64) + data.len(),
            Frame::NewToken { token } => v(token.len() as u64) + token.len(),
            Frame::Stream { id, offset, data, .. } => v(*id) + if *offset != 0 { v(*offset) } else { 0 } + v(data.len() as u64) + data.len(),
            Frame::MaxData(m) | Frame::DataBlocked(m) | Frame::RetireConnectionId(m) => v(*m),
            Frame::MaxStreamData { id, max: n } | Frame::StreamDataBlocked { id, limit: n } => v(*id) + v(*n),
            Frame::MaxStreams { max: n, .. } | Frame::StreamsBlocked { limit: n, .. } => v(*n),
            Frame::NewConnectionId { sequence, retire_prior_to, cid, .. } => v(*sequence) + v(*retire_prior_to) + 1 + cid.len() + 16,
            Frame::PathChallenge(_) | Frame::PathResponse(_) => 8,
            Frame::ConnectionClose { code, frame_type, reason } => v(*code) + frame_type.map_or(0, v) + v(reason.len() as u64) + reason.len(),
        }
    }

    /// Appends the frame. A STREAM frame is written with a Length field, and an Offset field if the offset is not 0 (see
    /// [`write_stream_to_end`] for the last frame of a packet, which can do without the length).
    pub fn write(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.push(self.frame_type() as u8);
        match self {
            Frame::Padding(n) => out.resize(start + n, 0),
            Frame::Ping | Frame::HandshakeDone => {}
            Frame::Ack(a) => {
                put_varint(out, a.largest);
                put_varint(out, a.delay);
                put_varint(out, a.range_count);
                put_varint(out, a.first_range);
                out.extend_from_slice(a.ranges);
                if let Some(e) = a.ecn {
                    put_varint(out, e.ect0);
                    put_varint(out, e.ect1);
                    put_varint(out, e.ce);
                }
            }
            Frame::ResetStream { id, error, final_size } => {
                put_varint(out, *id);
                put_varint(out, *error);
                put_varint(out, *final_size);
            }
            Frame::StopSending { id, error } => {
                put_varint(out, *id);
                put_varint(out, *error);
            }
            Frame::Crypto { offset, data } => {
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                put_varint(out, token.len() as u64);
                out.extend_from_slice(token);
            }
            Frame::Stream { id, offset, data, .. } => {
                put_varint(out, *id);
                if *offset != 0 {
                    put_varint(out, *offset);
                }
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData(m) | Frame::DataBlocked(m) | Frame::RetireConnectionId(m) => put_varint(out, *m),
            Frame::MaxStreamData { id, max: n } | Frame::StreamDataBlocked { id, limit: n } => {
                put_varint(out, *id);
                put_varint(out, *n);
            }
            Frame::MaxStreams { max: n, .. } | Frame::StreamsBlocked { limit: n, .. } => put_varint(out, *n),
            Frame::NewConnectionId { sequence, retire_prior_to, cid, reset_token } => {
                assert!((1..=MAX_CID_LEN).contains(&cid.len()) && retire_prior_to <= sequence);
                put_varint(out, *sequence);
                put_varint(out, *retire_prior_to);
                out.push(cid.len() as u8);
                out.extend_from_slice(cid);
                out.extend_from_slice(&reset_token[..]);
            }
            Frame::PathChallenge(d) | Frame::PathResponse(d) => out.extend_from_slice(d),
            Frame::ConnectionClose { code, frame_type, reason } => {
                put_varint(out, *code);
                if let Some(t) = frame_type {
                    put_varint(out, *t);
                }
                put_varint(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
        }
        debug_assert_eq!(out.len() - start, self.len());
    }
}

/// The frames of a payload, one after another. After the first error there are no more.
pub struct Frames<'a> {
    r: Reader<'a>,
    ty: PacketType,
    started: bool,
    failed: bool,
}

/// Reads the payload of a packet of type `ty` as frames.
pub fn frames(payload: &[u8], ty: PacketType) -> Frames<'_> {
    Frames { r: Reader::new(payload), ty, started: false, failed: false }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.r.is_empty() {
            if self.started {
                return None;
            }
            self.started = true;
            self.failed = true;
            return Some(Err(FrameError { kind: FrameErrorKind::Empty, frame_type: 0 }));
        }
        self.started = true;
        let f = Frame::read(&mut self.r, self.ty);
        self.failed = f.is_err();
        Some(f)
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// writing what the frame type does not say enough of

/// Appends an ACK frame for `ranges`: the packet numbers received, as ranges from the highest down, with at least one packet
/// number not received between one and the next. `delay` is as it is sent, in units of 2^ack_delay_exponent microseconds.
pub fn write_ack(out: &mut Vec<u8>, delay: u64, ranges: &[RangeInclusive<u64>], ecn: Option<EcnCounts>) {
    let first = ranges.first().expect("an ACK frame acknowledges something");
    out.push(if ecn.is_some() { ACK_ECN as u8 } else { ACK as u8 });
    put_varint(out, *first.end());
    put_varint(out, delay);
    put_varint(out, ranges.len() as u64 - 1);
    put_varint(out, first.end() - first.start());
    let mut smallest = *first.start();
    for r in &ranges[1..] {
        debug_assert!(r.start() <= r.end() && smallest >= r.end() + 2, "ranges are in order and apart");
        put_varint(out, smallest - r.end() - 2);
        put_varint(out, r.end() - r.start());
        smallest = *r.start();
    }
    if let Some(e) = ecn {
        put_varint(out, e.ect0);
        put_varint(out, e.ect1);
        put_varint(out, e.ce);
    }
}

/// Appends a STREAM frame without a Length field, whose data is the rest of the packet: the last frame of one, saving the bytes
/// of the length. An Offset field is written if `offset` is not 0.
pub fn write_stream_to_end(out: &mut Vec<u8>, id: u64, offset: u64, data: &[u8], fin: bool) {
    out.push((STREAM | if offset != 0 { STREAM_OFF } else { 0 } | u64::from(fin)) as u8);
    put_varint(out, id);
    if offset != 0 {
        put_varint(out, offset);
    }
    out.extend_from_slice(data);
}

/// Appends what comes before the data of a STREAM frame: its type, the stream id, the offset if it is not 0, and the length if one
/// is given (without one the data is the rest of the packet). The caller appends the data itself, so that it is copied once.
pub fn write_stream_header(out: &mut Vec<u8>, id: u64, offset: u64, len: Option<usize>, fin: bool) {
    out.push((STREAM | if offset != 0 { STREAM_OFF } else { 0 } | if len.is_some() { STREAM_LEN } else { 0 } | u64::from(fin)) as u8);
    put_varint(out, id);
    if offset != 0 {
        put_varint(out, offset);
    }
    if let Some(l) = len {
        put_varint(out, l as u64);
    }
}

/// How many bytes of a STREAM frame come before its data: with a Length field (for data of `len` bytes) if `len` is given, and
/// without if not. For fitting the data to the room that a packet has.
pub fn stream_header_len(id: u64, offset: u64, len: Option<usize>) -> usize {
    1 + varint_len(id) + if offset != 0 { varint_len(offset) } else { 0 } + len.map_or(0, |l| varint_len(l as u64))
}

/// How many bytes of a CRYPTO frame come before its data, which is `len` bytes.
pub fn crypto_header_len(offset: u64, len: usize) -> usize {
    1 + varint_len(offset) + varint_len(len as u64)
}

#[cfg(test)]
mod tests {
    use super::super::vectors::*;
    use super::*;
    use crate::util::{hex, unhex};

    const ALL_TYPES: [PacketType; 4] = [PacketType::Initial, PacketType::ZeroRtt, PacketType::Handshake, PacketType::OneRtt];

    fn read_all(bytes: &[u8], ty: PacketType) -> Result<Vec<Frame<'_>>, FrameError> {
        frames(bytes, ty).collect()
    }

    fn written(f: &Frame) -> Vec<u8> {
        let mut v = Vec::new();
        f.write(&mut v);
        assert_eq!(v.len(), f.len(), "{f:?}");
        v
    }

    #[test]
    fn the_frames_of_the_packets_of_the_rfc_are_read() {
        // RFC 9001 appendix A.2: a CRYPTO frame with the ClientHello, and then padding
        let mut p = unhex(CLIENT_INITIAL_CRYPTO);
        p.resize(p.len() + CLIENT_INITIAL_PADDING, 0);
        let fs = read_all(&p, PacketType::Initial).unwrap();
        assert_eq!(fs.len(), 2);
        let hello = unhex(CLIENT_INITIAL_CRYPTO);
        assert_eq!(fs[0], Frame::Crypto { offset: 0, data: &hello[4..] });
        assert_eq!(fs[1], Frame::Padding(CLIENT_INITIAL_PADDING));
        assert_eq!(hello[..4], [0x06, 0x00, 0x40, 0xf1]);

        // A.3: an ACK of packet 0, and a CRYPTO frame with the ServerHello
        let p = unhex(SERVER_INITIAL_PAYLOAD);
        let fs = read_all(&p, PacketType::Initial).unwrap();
        assert_eq!(fs.len(), 2);
        let Frame::Ack(a) = fs[0] else { panic!("{:?}", fs[0]) };
        assert_eq!((a.largest, a.delay, a.first_range, a.additional_ranges(), a.ecn), (0, 0, 0, 0, None));
        assert_eq!(a.ranges().collect::<Vec<_>>(), [0..=0]);
        let Frame::Crypto { offset: 0, data } = fs[1] else { panic!("{:?}", fs[1]) };
        assert_eq!(data.len(), 0x5a);
        assert_eq!(data[0], 0x02); // a ServerHello

        // A.5: a PING
        assert_eq!(read_all(&unhex(CHACHA_PAYLOAD), PacketType::OneRtt).unwrap(), [Frame::Ping]);
    }

    /// A frame of every type (STREAM in all its forms), with the numbers at the edges of the sizes of varints, for the tests that
    /// go through all of them. The returned frames borrow from `b`.
    fn samples<'a>(b: &'a Samples) -> Vec<Frame<'a>> {
        let mut v = vec![
            Frame::Padding(1),
            Frame::Padding(7),
            Frame::Ping,
            Frame::HandshakeDone,
            Frame::ResetStream { id: 4, error: 0x0100, final_size: MAX_VARINT },
            Frame::StopSending { id: 63, error: 64 },
            Frame::Crypto { offset: 0, data: &b.data[..10] },
            Frame::Crypto { offset: 16_383, data: &b.data[..200] },
            Frame::Crypto { offset: 16_384, data: &[] },
            Frame::NewToken { token: &b.data[..1] },
            Frame::NewToken { token: &b.data[..100] },
            Frame::MaxData(0),
            Frame::MaxData(MAX_VARINT),
            Frame::MaxStreamData { id: 1, max: 1_073_741_823 },
            Frame::MaxStreamData { id: 1_073_741_824, max: 2 },
            Frame::MaxStreams { bidirectional: true, max: 100 },
            Frame::MaxStreams { bidirectional: false, max: MAX_STREAMS_LIMIT },
            Frame::DataBlocked(12345),
            Frame::StreamDataBlocked { id: 8, limit: 9 },
            Frame::StreamsBlocked { bidirectional: true, limit: 0 },
            Frame::StreamsBlocked { bidirectional: false, limit: MAX_STREAMS_LIMIT },
            Frame::NewConnectionId { sequence: 3, retire_prior_to: 3, cid: &b.data[..8], reset_token: &b.token },
            Frame::NewConnectionId { sequence: 1 << 40, retire_prior_to: 0, cid: &b.data[..1], reset_token: &b.token },
            Frame::NewConnectionId { sequence: 9, retire_prior_to: 2, cid: &b.data[..20], reset_token: &b.token },
            Frame::RetireConnectionId(7),
            Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]),
            Frame::PathResponse([8, 7, 6, 5, 4, 3, 2, 1]),
            Frame::ConnectionClose { code: 0x0a, frame_type: Some(0x06), reason: b"" },
            Frame::ConnectionClose { code: 0x0100, frame_type: Some(0), reason: b"no good" },
            Frame::ConnectionClose { code: 0x0100, frame_type: None, reason: b"application says so" },
            Frame::ConnectionClose { code: MAX_VARINT, frame_type: None, reason: &b.data[..300] },
        ];
        for (id, offset, len, fin) in [(0, 0, 0, false), (0, 0, 5, true), (4, 1, 5, false), (63, 64, 70, true), (64, 16_384, 2, false), (1 << 40, MAX_VARINT - 100, 100, true)] {
            v.push(Frame::Stream { id, offset, data: &b.data[..len], fin });
        }
        v.push(Frame::Ack(b.acks[0]));
        v.push(Frame::Ack(b.acks[1]));
        v.push(Frame::Ack(b.acks[2]));
        v
    }

    /// What the sample frames borrow.
    struct Samples {
        data: Vec<u8>,
        token: [u8; 16],
        acks: Vec<Ack<'static>>,
    }

    fn samples_data() -> Samples {
        let data: Vec<u8> = (0..400u32).map(|i| (i * 7 + 3) as u8).collect();
        // the ACK frames come from what write_ack writes: read back, so that they hold their own ranges
        let mut acks = Vec::new();
        let sets: [(&[RangeInclusive<u64>], Option<EcnCounts>); 3] = [
            (&[0..=0], None),
            (&[1000..=2000, 900..=998, 10..=10, 0..=7], Some(EcnCounts { ect0: 1, ect1: 2, ce: 300 })),
            (&[MAX_VARINT - 5..=MAX_VARINT, 5..=6], None),
        ];
        for (ranges, ecn) in sets {
            let mut v = Vec::new();
            write_ack(&mut v, 25, ranges, ecn);
            let leaked: &'static [u8] = Box::leak(v.into_boxed_slice());
            let Frame::Ack(a) = Frame::read(&mut Reader::new(leaked), PacketType::OneRtt).unwrap() else { panic!() };
            acks.push(a);
        }
        Samples { data, token: [0xaa; 16], acks }
    }

    #[test]
    fn every_frame_is_read_as_it_is_written() {
        let b = samples_data();
        for f in samples(&b) {
            let bytes = written(&f);
            // in every kind of packet that may have it
            for ty in ALL_TYPES {
                let r = read_all(&bytes, ty);
                if allowed_in(f.frame_type(), ty) {
                    assert_eq!(r, Ok(vec![f]), "{f:?} in {ty:?}");
                } else {
                    assert_eq!(r.unwrap_err().kind, FrameErrorKind::NotAllowed, "{f:?} in {ty:?}");
                }
            }
            // and in a row, with others
            let mut row = written(&Frame::Ping);
            row.extend_from_slice(&bytes);
            row.extend_from_slice(&written(&Frame::MaxData(3)));
            let fs = read_all(&row, PacketType::OneRtt).unwrap();
            assert_eq!(fs.len(), 3, "{f:?}");
            assert_eq!(fs[0], Frame::Ping);
            assert_eq!(fs[1], f);
            assert_eq!(fs[2], Frame::MaxData(3));
        }
    }

    #[test]
    fn no_frame_is_read_from_less_than_all_of_it() {
        let b = samples_data();
        for f in samples(&b) {
            let bytes = written(&f);
            for cut in 1..bytes.len() {
                let r = read_all(&bytes[..cut], PacketType::OneRtt);
                // (a run of padding is as many frames as there are bytes of it, and a frame that is a type only has no shorter form)
                if let Frame::Padding(_) = f {
                    assert_eq!(r, Ok(vec![Frame::Padding(cut)]));
                    continue;
                }
                let e = r.unwrap_err();
                assert_eq!(e.kind, FrameErrorKind::Truncated, "{f:?} cut at {cut}");
                assert_eq!(e.frame_type, f.frame_type(), "{f:?} cut at {cut}");
                assert_eq!(e.transport_error(), FRAME_ENCODING_ERROR);
            }
        }
    }

    #[test]
    fn a_payload_with_no_frames_is_a_protocol_violation() {
        let mut it = frames(&[], PacketType::OneRtt);
        let e = it.next().unwrap().unwrap_err();
        assert_eq!(e.kind, FrameErrorKind::Empty);
        assert_eq!(e.transport_error(), PROTOCOL_VIOLATION);
        assert!(it.next().is_none());
        // and after the frames of a payload there are no more, and no error
        let mut it = frames(&[0x01], PacketType::OneRtt);
        assert_eq!(it.next(), Some(Ok(Frame::Ping)));
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn after_an_error_there_are_no_more_frames() {
        let mut it = frames(&[0x01, 0x1f, 0x01], PacketType::OneRtt);
        assert_eq!(it.next(), Some(Ok(Frame::Ping)));
        assert_eq!(it.next().unwrap().unwrap_err().kind, FrameErrorKind::UnknownType);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn frame_types_that_are_not_known_or_not_in_the_fewest_bytes_are_errors() {
        for ft in [0x1f_u8, 0x20, 0x30, 0x31, 0x3f] {
            let e = read_all(&[ft], PacketType::OneRtt).unwrap_err();
            assert_eq!((e.kind, e.frame_type, e.transport_error()), (FrameErrorKind::UnknownType, ft as u64, FRAME_ENCODING_ERROR));
        }
        // longer types, up to the largest
        for bytes in [&[0x40, 0x40][..], &[0x7f, 0xff][..], &[0x80, 0, 0x40, 0][..], &[0xff; 8][..]] {
            let e = read_all(bytes, PacketType::OneRtt).unwrap_err();
            assert_eq!(e.kind, FrameErrorKind::UnknownType, "{bytes:02x?}");
        }
        // the types that are known, in two bytes, in four, in eight
        for (bytes, ft) in [(&[0x40, 0x00][..], 0), (&[0x40, 0x01][..], 1), (&[0x40, 0x1e][..], 0x1e), (&[0x80, 0, 0, 0x06][..], 6), (&[0xc0, 0, 0, 0, 0, 0, 0, 0x01][..], 1)] {
            let e = read_all(bytes, PacketType::OneRtt).unwrap_err();
            assert_eq!((e.kind, e.frame_type, e.transport_error()), (FrameErrorKind::TypeNotMinimal, ft, PROTOCOL_VIOLATION), "{bytes:02x?}");
        }
        // a type that is cut off
        assert_eq!(read_all(&[0x40], PacketType::OneRtt).unwrap_err().kind, FrameErrorKind::Truncated);
        assert_eq!(read_all(&[0xc0, 0, 0], PacketType::OneRtt).unwrap_err().kind, FrameErrorKind::Truncated);
    }

    #[test]
    fn frames_are_allowed_in_the_packets_that_table_3_of_the_rfc_says() {
        // RFC 9000 table 3, "Pkts": which of Initial, Handshake, 0-RTT and 1-RTT, for each frame type
        let table: [(u64, &str); 31] = [
            (0x00, "IH01"), (0x01, "IH01"), (0x02, "IH1"), (0x03, "IH1"), (0x04, "01"), (0x05, "01"), (0x06, "IH1"), (0x07, "1"),
            (0x08, "01"), (0x09, "01"), (0x0a, "01"), (0x0b, "01"), (0x0c, "01"), (0x0d, "01"), (0x0e, "01"), (0x0f, "01"),
            (0x10, "01"), (0x11, "01"), (0x12, "01"), (0x13, "01"), (0x14, "01"), (0x15, "01"), (0x16, "01"), (0x17, "01"),
            (0x18, "01"), (0x19, "01"), (0x1a, "01"), (0x1b, "1"), (0x1c, "IH01"), (0x1d, "01"), (0x1e, "1"),
        ];
        for (ft, packets) in table {
            for (ty, letter) in [(PacketType::Initial, 'I'), (PacketType::Handshake, 'H'), (PacketType::ZeroRtt, '0'), (PacketType::OneRtt, '1')] {
                assert_eq!(allowed_in(ft, ty), packets.contains(letter), "frame {ft:#x} in {ty:?}");
            }
            for ty in [PacketType::Retry, PacketType::VersionNegotiation] {
                assert!(!allowed_in(ft, ty));
            }
        }
        assert!(!allowed_in(0x1f, PacketType::OneRtt));
        // and what comes of it when a frame is in a packet that may not have it
        let e = read_all(&[0x08, 0x00, 0x00], PacketType::Initial).unwrap_err();
        assert_eq!((e.kind, e.frame_type, e.transport_error()), (FrameErrorKind::NotAllowed, 0x08, PROTOCOL_VIOLATION));
        assert_eq!(read_all(&[0x1e], PacketType::Handshake).unwrap_err().kind, FrameErrorKind::NotAllowed);
        // (the type is looked at before the rest of the frame is: a frame in the wrong packet is that, not cut short)
        assert_eq!(read_all(&[0x07], PacketType::Initial).unwrap_err().kind, FrameErrorKind::NotAllowed);
    }

    #[test]
    fn what_a_frame_says_of_itself_is_checked() {
        let one = PacketType::OneRtt;
        let kind = |bytes: &[u8]| read_all(bytes, one).unwrap_err().kind;
        // ACK: the first range reaches below 0
        assert_eq!(kind(&[0x02, 5, 0, 0, 6]), FrameErrorKind::Invalid("the first range of an ACK goes below packet number 0"));
        assert!(read_all(&[0x02, 5, 0, 0, 5], one).is_ok());
        // a following range reaches below 0: largest 10, first range 2 (8 to 10), then a gap of 6 puts the next one's largest at 0
        assert!(read_all(&[0x02, 10, 0, 1, 2, 6, 0], one).is_ok());
        assert_eq!(kind(&[0x02, 10, 0, 1, 2, 7, 0]), FrameErrorKind::Invalid("a range of an ACK goes below packet number 0"));
        assert_eq!(kind(&[0x02, 10, 0, 1, 2, 6, 1]), FrameErrorKind::Invalid("a range of an ACK goes below packet number 0"));
        // more ranges than there is room for, whatever the count says
        assert_eq!(kind(&[0x02, 10, 0, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0, 0, 0, 0]), FrameErrorKind::Truncated);
        assert_eq!(kind(&[0x02, 10, 0, 3, 0, 0, 0, 0, 0]), FrameErrorKind::Truncated);
        assert!(read_all(&[0x02, 10, 0, 2, 0, 0, 0, 0, 0], one).is_ok());
        // an ACK with ECN counts has all three
        assert_eq!(kind(&[0x03, 10, 0, 0, 0, 1, 2]), FrameErrorKind::Truncated);
        assert!(read_all(&[0x03, 10, 0, 0, 0, 1, 2, 3], one).is_ok());
        // NEW_CONNECTION_ID: the id is 1 to 20 bytes; retire_prior_to is not past the sequence number
        let ncid = |len: u8, seq: u8, retire: u8| {
            let mut v = vec![0x18, seq, retire, len];
            v.extend(std::iter::repeat_n(7u8, len as usize + 16));
            v
        };
        assert!(read_all(&ncid(1, 1, 1), one).is_ok());
        assert!(read_all(&ncid(20, 5, 0), one).is_ok());
        assert_eq!(kind(&ncid(0, 1, 0)), FrameErrorKind::Invalid("a connection id that is not of 1 to 20 bytes"));
        assert_eq!(kind(&ncid(21, 1, 0)), FrameErrorKind::Invalid("a connection id that is not of 1 to 20 bytes"));
        assert_eq!(kind(&ncid(8, 1, 2)), FrameErrorKind::Invalid("retire_prior_to is more than the sequence number"));
        // and the reset token is all there
        let mut short = ncid(8, 1, 0);
        short.pop();
        assert_eq!(kind(&short), FrameErrorKind::Truncated);
        // NEW_TOKEN is not empty
        assert_eq!(kind(&[0x07, 0]), FrameErrorKind::Invalid("an empty token"));
        assert!(read_all(&[0x07, 1, 9], one).is_ok());
        // streams: at most 2^60
        let mut max_streams = vec![0x12, 0xd0, 0, 0, 0, 0, 0, 0, 0];
        assert!(read_all(&max_streams, one).is_ok());
        max_streams[8] = 1;
        assert_eq!(kind(&max_streams), FrameErrorKind::Invalid("more than 2^60 streams"));
        let mut blocked = vec![0x17, 0xd0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(kind(&blocked), FrameErrorKind::Invalid("more than 2^60 streams"));
        blocked[8] = 0;
        assert!(read_all(&blocked, one).is_ok());
        // the end of the data is a number that fits: CRYPTO and STREAM
        let mut crypto = vec![0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0];
        assert_eq!(kind(&crypto), FrameErrorKind::Invalid("offset and length go past 2^62 - 1"));
        crypto[8] = 0xfe; // an offset of 2^62 - 2 and a byte: the end is 2^62 - 1, as far as it may go
        assert!(read_all(&crypto, one).is_ok());
        let mut stream = vec![0x0e, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0];
        assert_eq!(kind(&stream), FrameErrorKind::Invalid("offset and length go past 2^62 - 1"));
        stream[9] = 0xfe; // offset 2^62 - 2, one byte: ends at 2^62 - 1
        assert!(read_all(&stream, one).is_ok());
        // a STREAM frame without a length takes the rest, and that can be nothing
        assert_eq!(read_all(&[0x08, 4], one), Ok(vec![Frame::Stream { id: 4, offset: 0, data: &[], fin: false }]));
        assert_eq!(read_all(&[0x09, 4, 1, 2, 3], one), Ok(vec![Frame::Stream { id: 4, offset: 0, data: &[1, 2, 3], fin: true }]));
        assert_eq!(read_all(&[0x0c, 4, 9, 1, 2], one), Ok(vec![Frame::Stream { id: 4, offset: 9, data: &[1, 2], fin: false }]));
        // a length that goes past the packet
        assert_eq!(kind(&[0x0a, 4, 5, 1, 2, 3]), FrameErrorKind::Truncated);
        assert_eq!(kind(&[0x06, 0, 0x7f, 0xff, 1]), FrameErrorKind::Truncated);
        assert_eq!(kind(&[0x1c, 0, 0, 5, b'a']), FrameErrorKind::Truncated);
    }

    #[test]
    fn padding_is_one_frame_for_a_run() {
        let one = PacketType::OneRtt;
        assert_eq!(read_all(&[0, 0, 0], one), Ok(vec![Frame::Padding(3)]));
        assert_eq!(read_all(&[0, 0, 1, 0, 0], one), Ok(vec![Frame::Padding(2), Frame::Ping, Frame::Padding(2)]));
        // frames that take a byte of 0 as data are not cut into padding
        assert_eq!(read_all(&[0x06, 0, 2, 0, 0, 0], one), Ok(vec![Frame::Crypto { offset: 0, data: &[0, 0] }, Frame::Padding(1)]));
    }

    #[test]
    fn ack_ranges_are_read_and_written() {
        let sets: [&[RangeInclusive<u64>]; 5] = [&[0..=0], &[5..=9], &[100..=200, 50..=98, 3..=3, 0..=0 + 0], &[1 << 40..=(1 << 40) + 1000, 7..=8], &[MAX_VARINT..=MAX_VARINT, 0..=MAX_VARINT - 2]];
        for ranges in sets {
            let mut v = Vec::new();
            write_ack(&mut v, 1234, ranges, None);
            let fs = read_all(&v, PacketType::Handshake).unwrap();
            let Frame::Ack(a) = fs[0] else { panic!() };
            assert_eq!(a.largest, *ranges[0].end());
            assert_eq!(a.delay, 1234);
            assert_eq!(a.ranges().collect::<Vec<_>>(), ranges);
            assert_eq!(a.additional_ranges() as usize, ranges.len() - 1);
            assert_eq!(a.ecn, None);
            for r in ranges {
                assert!(a.acknowledges(*r.start()) && a.acknowledges(*r.end()));
                if *r.start() > 0 {
                    // the packet number below a range is not acknowledged, unless the range below it has it
                    let below = r.start() - 1;
                    assert_eq!(a.acknowledges(below), ranges.iter().any(|o| o.contains(&below)));
                }
            }
            assert!(!a.acknowledges(*ranges[0].end() + 1) || *ranges[0].end() == MAX_VARINT);
            // and written again by the frame
            assert_eq!(written(&fs[0]), v);
        }
        // the delay in microseconds
        let mut v = Vec::new();
        write_ack(&mut v, 25, &[0..=0], None);
        let Frame::Ack(a) = read_all(&v, PacketType::OneRtt).unwrap()[0] else { panic!() };
        assert_eq!(a.delay_micros(3), 200);
        assert_eq!(a.delay_micros(0), 25);
        assert_eq!(a.delay_micros(20), 25 << 20);
        assert_eq!(a.delay_micros(40), 25 << 20, "the exponent is at most 20");
        let mut v = Vec::new();
        write_ack(&mut v, MAX_VARINT, &[0..=0], None);
        let Frame::Ack(a) = read_all(&v, PacketType::OneRtt).unwrap()[0] else { panic!() };
        assert_eq!(a.delay_micros(20), u64::MAX);
        // ECN
        let mut v = Vec::new();
        write_ack(&mut v, 0, &[3..=4], Some(EcnCounts { ect0: 5, ect1: 6, ce: 7 }));
        assert_eq!(v[0], 0x03);
        let Frame::Ack(a) = read_all(&v, PacketType::OneRtt).unwrap()[0] else { panic!() };
        assert_eq!(a.ecn, Some(EcnCounts { ect0: 5, ect1: 6, ce: 7 }));
    }

    #[test]
    fn what_wants_an_acknowledgement() {
        let b = samples_data();
        for f in samples(&b) {
            let expected = !matches!(f.frame_type(), 0x00 | 0x02 | 0x03 | 0x1c | 0x1d);
            assert_eq!(f.ack_eliciting(), expected, "{f:?}");
        }
    }

    #[test]
    fn frames_that_are_written_to_fill_a_packet_are_read_to_its_end() {
        let data = [9u8; 50];
        for (id, offset, fin) in [(0u64, 0u64, false), (4, 0, true), (8, 77, false), (1 << 30, 1 << 30, true)] {
            let mut v = vec![0x01];
            let before = v.len();
            write_stream_to_end(&mut v, id, offset, &data, fin);
            assert_eq!(v.len() - before, stream_header_len(id, offset, None) + data.len());
            assert_eq!(read_all(&v, PacketType::OneRtt), Ok(vec![Frame::Ping, Frame::Stream { id, offset, data: &data, fin }]));
            // and with a length it is that much more, and it is what the frame writes
            let mut w = Vec::new();
            Frame::Stream { id, offset, data: &data, fin }.write(&mut w);
            assert_eq!(w.len(), stream_header_len(id, offset, Some(data.len())) + data.len());
        }
        let mut w = Vec::new();
        Frame::Crypto { offset: 20_000, data: &data }.write(&mut w);
        assert_eq!(w.len(), crypto_header_len(20_000, data.len()) + data.len());
    }

    #[test]
    fn the_flags_of_a_stream_frame_type_are_those_of_the_rfc() {
        // 0x08 | OFF 0x04 | LEN 0x02 | FIN 0x01
        let f = |offset, fin| Frame::Stream { id: 1, offset, data: &[], fin }.frame_type();
        assert_eq!(f(0, false), 0x0a);
        assert_eq!(f(0, true), 0x0b);
        assert_eq!(f(1, false), 0x0e);
        assert_eq!(f(1, true), 0x0f);
        assert_eq!(hex(&written(&Frame::Stream { id: 1, offset: 0x10, data: &[0xaa], fin: true })), "0f011001aa");
    }

    #[test]
    fn frames_are_written_as_the_rfc_has_them() {
        // each by hand from the figures of RFC 9000 section 19
        let check = |f: Frame, h: &str| assert_eq!(hex(&written(&f)), h, "{f:?}");
        check(Frame::Ping, "01");
        check(Frame::HandshakeDone, "1e");
        check(Frame::ResetStream { id: 4, error: 0x0100, final_size: 9 }, "0404410009");
        check(Frame::StopSending { id: 4, error: 0x0100 }, "05044100");
        check(Frame::Crypto { offset: 0x10, data: &[1, 2, 3] }, "061003010203");
        check(Frame::NewToken { token: &[0xab, 0xcd] }, "0702abcd");
        check(Frame::MaxData(0x4000), "1080004000");
        check(Frame::MaxStreamData { id: 1, max: 0x3fff }, "11017fff");
        check(Frame::MaxStreams { bidirectional: true, max: 100 }, "124064");
        check(Frame::MaxStreams { bidirectional: false, max: 3 }, "1303");
        check(Frame::DataBlocked(5), "1405");
        check(Frame::StreamDataBlocked { id: 2, limit: 7 }, "150207");
        check(Frame::StreamsBlocked { bidirectional: true, limit: 8 }, "1608");
        check(Frame::StreamsBlocked { bidirectional: false, limit: 9 }, "1709");
        check(Frame::NewConnectionId { sequence: 2, retire_prior_to: 1, cid: &[0xaa, 0xbb], reset_token: &[0x11; 16] }, &format!("180201{}aabb{}", "02", "11".repeat(16)));
        check(Frame::RetireConnectionId(3), "1903");
        check(Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]), "1a0102030405060708");
        check(Frame::PathResponse([8, 7, 6, 5, 4, 3, 2, 1]), "1b0807060504030201");
        check(Frame::ConnectionClose { code: 0x0a, frame_type: Some(0x06), reason: b"hi" }, "1c0a06026869");
        check(Frame::ConnectionClose { code: 0x0100, frame_type: None, reason: b"x" }, "1d41000178");
        check(Frame::Stream { id: 1, offset: 0x10, data: &[0xaa], fin: true }, "0f011001aa");
        // an ACK of 10 to 12 and 4 to 6: the first range is 2, and 9, 8 and 7 are missing, so the gap is 2 (RFC 9000 section 19.3.1)
        let mut v = Vec::new();
        write_ack(&mut v, 5, &[10..=12, 4..=6], None);
        assert_eq!(hex(&v), "020c0501020202");
    }

    /// The line that quic-go's tests oracle (`tools/quicgo_oracle`) gives for a frame.
    fn describe(f: &Frame) -> Option<String> {
        let h = |b: &[u8]| hex(b);
        Some(match f {
            Frame::Padding(_) => return None,
            Frame::Ping => "PING".into(),
            Frame::Ack(a) => {
                let ranges: Vec<String> = a.ranges().map(|r| format!("{}-{}", r.end(), r.start())).collect();
                let ecn = a.ecn.map_or("-".to_string(), |e| format!("{},{},{}", e.ect0, e.ect1, e.ce));
                format!("ACK largest={} delay={} ranges={} ecn={}", a.largest, a.delay, ranges.join(","), ecn)
            }
            Frame::ResetStream { id, error, final_size } => format!("RESET_STREAM id={id} err={error} final={final_size}"),
            Frame::StopSending { id, error } => format!("STOP_SENDING id={id} err={error}"),
            Frame::Crypto { offset, data } => format!("CRYPTO off={offset} data={}", h(data)),
            Frame::NewToken { token } => format!("NEW_TOKEN token={}", h(token)),
            Frame::Stream { id, offset, data, fin } => format!("STREAM id={id} off={offset} fin={fin} data={}", h(data)),
            Frame::MaxData(m) => format!("MAX_DATA {m}"),
            Frame::MaxStreamData { id, max } => format!("MAX_STREAM_DATA id={id} max={max}"),
            Frame::MaxStreams { bidirectional, max } => format!("MAX_STREAMS bidi={bidirectional} max={max}"),
            Frame::DataBlocked(m) => format!("DATA_BLOCKED {m}"),
            Frame::StreamDataBlocked { id, limit } => format!("STREAM_DATA_BLOCKED id={id} limit={limit}"),
            Frame::StreamsBlocked { bidirectional, limit } => format!("STREAMS_BLOCKED bidi={bidirectional} limit={limit}"),
            Frame::NewConnectionId { sequence, retire_prior_to, cid, reset_token } => {
                format!("NEW_CONNECTION_ID seq={sequence} retire={retire_prior_to} cid={} token={}", h(cid), h(&reset_token[..]))
            }
            Frame::RetireConnectionId(s) => format!("RETIRE_CONNECTION_ID {s}"),
            Frame::PathChallenge(d) => format!("PATH_CHALLENGE {}", h(d)),
            Frame::PathResponse(d) => format!("PATH_RESPONSE {}", h(d)),
            Frame::ConnectionClose { code, frame_type: Some(t), reason } => format!("CONNECTION_CLOSE transport code={code} type={t} reason={}", h(reason)),
            Frame::ConnectionClose { code, frame_type: None, reason } => format!("CONNECTION_CLOSE app code={code} reason={}", h(reason)),
            Frame::HandshakeDone => "HANDSHAKE_DONE".into(),
        })
    }

    #[test]
    fn payloads_are_read_as_quic_go_reads_them() {
        // Each line: the kind of packet (Initial, Handshake, 1-RTT), a payload, and what quic-go (v0.59.1, its own frame parser, with
        // the shortest-encoding rule of the RFC that it leaves out added) reads from it: the frames, and ERR where it stops. The
        // payloads are frames that quic-go wrote of random contents and then changed here and there, and nonsense. Made by
        // `tools/quicgo_oracle/`.
        let mut checked = 0;
        let mut errors = 0;
        let mut written = 0;
        for line in include_str!("vectors_quicgo_frames.txt").lines() {
            let mut parts = line.splitn(3, ' ');
            // the kind of packet, and whether the payload is as quic-go wrote it (V) or changed (M)
            let head = parts.next().unwrap();
            let ty = match &head[..1] {
                "I" => PacketType::Initial,
                "H" => PacketType::Handshake,
                _ => PacketType::OneRtt,
            };
            let as_written = &head[1..] == "V";
            let payload = unhex(parts.next().unwrap());
            let expected = parts.next().unwrap_or("");
            let mut got: Vec<String> = Vec::new();
            for f in frames(&payload, ty) {
                match f {
                    Ok(f) => got.extend(describe(&f)),
                    Err(e) => {
                        got.push("ERR".into());
                        let _ = e;
                        break;
                    }
                }
            }
            assert_eq!(got.join(";"), expected, "{ty:?} {}", hex(&payload));
            checked += 1;
            if as_written && ty == PacketType::OneRtt {
                // and what quic-go wrote is what is written here, from the frames that were read, but for a STREAM frame that
                // quic-go left without a Length (as the last of the payload) and padding, which is a run of its zero bytes
                let mut w = Vec::new();
                for f in frames(&payload, ty) {
                    match f.unwrap() {
                        Frame::Stream { id, offset, data, fin } if payload[w.len()] & 0x02 == 0 => write_stream_to_end(&mut w, id, offset, data, fin),
                        f => f.write(&mut w),
                    }
                }
                assert_eq!(hex(&w), hex(&payload), "written differently");
                written += 1;
            }
            errors += usize::from(expected.ends_with("ERR"));
        }
        assert!(checked > 500 && errors > 100 && errors < checked - 100 && written > 300, "{checked} cases, {errors} errors, {written} written");
    }

    #[test]
    fn the_reader_never_panics_and_what_it_reads_is_what_it_would_write() {
        // a deterministic stream of nonsense, and of frames with bytes changed
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let b = samples_data();
        let good: Vec<Vec<u8>> = samples(&b).iter().map(written).collect();
        for round in 0..30_000u32 {
            let mut bytes: Vec<u8> = if round % 3 == 0 {
                (0..(next() % 40)).map(|_| next() as u8).collect()
            } else {
                let mut v = good[(next() as usize) % good.len()].clone();
                for _ in 0..1 + next() % 3 {
                    let i = (next() as usize) % v.len();
                    v[i] = next() as u8;
                }
                if next() % 4 == 0 {
                    v.truncate((next() as usize) % (v.len() + 1));
                }
                v
            };
            if round % 7 == 0 && !bytes.is_empty() {
                bytes[0] &= 0x1f;
            }
            for ty in ALL_TYPES {
                let mut it = frames(&bytes, ty);
                let mut rewritten = Vec::new();
                let mut ok = true;
                for f in &mut it {
                    match f {
                        Ok(f) => {
                            // what was read can be written, and read again as the same
                            let w = written(&f);
                            let again = read_all(&w, ty);
                            assert!(again.is_ok(), "{f:?} written as {w:02x?} is not read: {again:?} (from {bytes:02x?})");
                            if !matches!(f, Frame::Padding(_)) {
                                assert_eq!(again.unwrap(), vec![f], "{bytes:02x?}");
                            }
                            rewritten.extend_from_slice(&w);
                        }
                        Err(e) => {
                            ok = false;
                            assert!(e.transport_error() == FRAME_ENCODING_ERROR || e.transport_error() == PROTOCOL_VIOLATION);
                            let _ = e.to_string();
                        }
                    }
                }
                if ok && !bytes.is_empty() {
                    // everything was read, so what was written reads as the same frames
                    assert_eq!(read_all(&rewritten, ty).unwrap(), read_all(&bytes, ty).unwrap());
                }
            }
        }
    }
}
