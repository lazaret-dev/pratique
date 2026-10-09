//! HTTP/2 frames (RFC 9113 sections 4 and 6): a [`Header`] says what a frame is and how long, [`parse`] checks a
//! frame's payload against the rules that depend on the frame alone, and the `write_*` functions make frames.
//! There is no I/O and no state here; the rules that depend on the connection (is this stream open, is there
//! room in the window, did a header block just begin) are the connection's.
//!
//! Anything wrong with a frame comes back as a [`FrameError`] that says what error code to send and whether the
//! stream or the whole connection is lost.

use std::fmt;

/// What a client sends first on a connection (RFC 9113 section 3.4).
pub(crate) const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The length of a frame header.
pub(crate) const HEADER_LEN: usize = 9;

/// The largest frame payload a peer may send until it has been told otherwise.
pub(crate) const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest value of SETTINGS_MAX_FRAME_SIZE.
pub(crate) const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215;

/// The flow-control window every stream and the connection start with.
pub(crate) const DEFAULT_WINDOW: u32 = 65_535;

/// The largest a flow-control window may be.
pub(crate) const MAX_WINDOW: u32 = 0x7fff_ffff;

pub(crate) mod kind {
    pub(crate) const DATA: u8 = 0x0;
    pub(crate) const HEADERS: u8 = 0x1;
    pub(crate) const PRIORITY: u8 = 0x2;
    pub(crate) const RST_STREAM: u8 = 0x3;
    pub(crate) const SETTINGS: u8 = 0x4;
    pub(crate) const PUSH_PROMISE: u8 = 0x5;
    pub(crate) const PING: u8 = 0x6;
    pub(crate) const GOAWAY: u8 = 0x7;
    pub(crate) const WINDOW_UPDATE: u8 = 0x8;
    pub(crate) const CONTINUATION: u8 = 0x9;
}

pub(crate) mod flag {
    /// DATA and HEADERS: no more frames on this stream from the sender.
    pub(crate) const END_STREAM: u8 = 0x1;
    /// SETTINGS and PING: this frame answers one.
    pub(crate) const ACK: u8 = 0x1;
    /// HEADERS, PUSH_PROMISE and CONTINUATION: the header block is complete.
    pub(crate) const END_HEADERS: u8 = 0x4;
    /// DATA, HEADERS and PUSH_PROMISE: the payload has padding.
    pub(crate) const PADDED: u8 = 0x8;
    /// HEADERS: there are priority fields.
    pub(crate) const PRIORITY: u8 = 0x20;
}

/// The identifiers of the settings (RFC 9113 section 6.5.2).
pub(crate) mod setting {
    pub(crate) const HEADER_TABLE_SIZE: u16 = 0x1;
    pub(crate) const ENABLE_PUSH: u16 = 0x2;
    pub(crate) const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub(crate) const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub(crate) const MAX_FRAME_SIZE: u16 = 0x5;
    pub(crate) const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// An error code (RFC 9113 section 7); the codes this crate does not know are kept as they came.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ErrorCode(pub(crate) u32);

// the whole table of RFC 9113 section 7, though the client names only some of them (the test server the rest)
#[allow(dead_code)]
impl ErrorCode {
    pub(crate) const NO_ERROR: ErrorCode = ErrorCode(0x0);
    pub(crate) const PROTOCOL_ERROR: ErrorCode = ErrorCode(0x1);
    pub(crate) const INTERNAL_ERROR: ErrorCode = ErrorCode(0x2);
    pub(crate) const FLOW_CONTROL_ERROR: ErrorCode = ErrorCode(0x3);
    pub(crate) const SETTINGS_TIMEOUT: ErrorCode = ErrorCode(0x4);
    pub(crate) const STREAM_CLOSED: ErrorCode = ErrorCode(0x5);
    pub(crate) const FRAME_SIZE_ERROR: ErrorCode = ErrorCode(0x6);
    pub(crate) const REFUSED_STREAM: ErrorCode = ErrorCode(0x7);
    pub(crate) const CANCEL: ErrorCode = ErrorCode(0x8);
    pub(crate) const COMPRESSION_ERROR: ErrorCode = ErrorCode(0x9);
    pub(crate) const CONNECT_ERROR: ErrorCode = ErrorCode(0xa);
    pub(crate) const ENHANCE_YOUR_CALM: ErrorCode = ErrorCode(0xb);
    pub(crate) const INADEQUATE_SECURITY: ErrorCode = ErrorCode(0xc);
    pub(crate) const HTTP_1_1_REQUIRED: ErrorCode = ErrorCode(0xd);

    pub(crate) fn name(self) -> &'static str {
        match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "PROTOCOL_ERROR",
            0x2 => "INTERNAL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "SETTINGS_TIMEOUT",
            0x5 => "STREAM_CLOSED",
            0x6 => "FRAME_SIZE_ERROR",
            0x7 => "REFUSED_STREAM",
            0x8 => "CANCEL",
            0x9 => "COMPRESSION_ERROR",
            0xa => "CONNECT_ERROR",
            0xb => "ENHANCE_YOUR_CALM",
            0xc => "INADEQUATE_SECURITY",
            0xd => "HTTP_1_1_REQUIRED",
            _ => "an unknown error",
        }
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:#x})", self.name(), self.0)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if self.name() == "an unknown error" {
            write!(f, " ({:#x})", self.0)?;
        }
        Ok(())
    }
}

/// What is wrong with a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrameError {
    pub(crate) code: ErrorCode,
    /// The stream that is lost, if only one is; `None` if the whole connection is.
    pub(crate) stream: Option<u32>,
    pub(crate) reason: &'static str,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

fn connection_error(code: ErrorCode, reason: &'static str) -> FrameError {
    FrameError { code, stream: None, reason }
}

/// The nine bytes in front of every frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    /// The length of the payload.
    pub(crate) length: u32,
    pub(crate) kind: u8,
    pub(crate) flags: u8,
    /// 0 for the connection itself.
    pub(crate) stream: u32,
}

impl Header {
    pub(crate) fn parse(b: &[u8; HEADER_LEN]) -> Header {
        Header { length: u32::from_be_bytes([0, b[0], b[1], b[2]]), kind: b[3], flags: b[4], stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff }
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        debug_assert!(self.length <= MAX_FRAME_SIZE_LIMIT && self.stream <= 0x7fff_ffff);
        out.extend_from_slice(&self.length.to_be_bytes()[1..]);
        out.push(self.kind);
        out.push(self.flags);
        out.extend_from_slice(&self.stream.to_be_bytes());
    }

    pub(crate) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// A frame whose payload has passed the checks that need nothing but the frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame<'a> {
    /// `flow_len` is what the frame takes from the flow-control windows: the whole payload, padding too.
    Data { stream: u32, end_stream: bool, data: &'a [u8], flow_len: u32 },
    /// The priority fields, if there were any, are dropped: priorities are deprecated (RFC 9113 section 5.3).
    Headers { stream: u32, end_stream: bool, end_headers: bool, fragment: &'a [u8] },
    Priority { stream: u32 },
    RstStream { stream: u32, code: ErrorCode },
    Settings { ack: bool, values: Vec<(u16, u32)> },
    /// What a server promises to push; the promised stream and the header block are not kept, since a client that
    /// has turned push off treats this as an error.
    PushPromise { stream: u32 },
    Ping { ack: bool, data: [u8; 8] },
    GoAway { last_stream: u32, code: ErrorCode, debug: &'a [u8] },
    WindowUpdate { stream: u32, increment: u32 },
    Continuation { stream: u32, end_headers: bool, fragment: &'a [u8] },
    /// A frame of a kind this crate does not know, which is to be ignored (RFC 9113 section 4.1).
    Unknown { kind: u8, stream: u32 },
}

/// What is left of a payload without its padding, and how many bytes the padding took (the Pad Length field and
/// the padding).
fn unpad<'a>(h: &Header, payload: &'a [u8]) -> Result<(&'a [u8], usize), FrameError> {
    if !h.has(flag::PADDED) {
        return Ok((payload, 0));
    }
    let Some(&pad) = payload.first() else {
        return Err(connection_error(ErrorCode::FRAME_SIZE_ERROR, "a padded frame without its Pad Length"));
    };
    let pad = pad as usize;
    if pad >= payload.len() {
        return Err(connection_error(ErrorCode::PROTOCOL_ERROR, "padding as long as the frame"));
    }
    Ok((&payload[1..payload.len() - pad], 1 + pad))
}

/// Checks the payload of the frame `h` describes (`payload.len()` is `h.length`) and takes it apart.
pub(crate) fn parse<'a>(h: &Header, payload: &'a [u8]) -> Result<Frame<'a>, FrameError> {
    debug_assert_eq!(h.length as usize, payload.len());
    let on_a_stream = |what: &'static str| if h.stream == 0 { Err(connection_error(ErrorCode::PROTOCOL_ERROR, what)) } else { Ok(h.stream) };
    let on_the_connection = |what: &'static str| if h.stream != 0 { Err(connection_error(ErrorCode::PROTOCOL_ERROR, what)) } else { Ok(()) };
    let sized = |ok: bool, what: &'static str| if ok { Ok(()) } else { Err(connection_error(ErrorCode::FRAME_SIZE_ERROR, what)) };
    match h.kind {
        kind::DATA => {
            let stream = on_a_stream("DATA on stream 0")?;
            let (data, _) = unpad(h, payload)?;
            Ok(Frame::Data { stream, end_stream: h.has(flag::END_STREAM), data, flow_len: h.length })
        }
        kind::HEADERS => {
            let stream = on_a_stream("HEADERS on stream 0")?;
            let (mut body, _) = unpad(h, payload)?;
            if h.has(flag::PRIORITY) {
                sized(body.len() >= 5, "HEADERS too short for its priority fields")?;
                body = &body[5..];
            }
            Ok(Frame::Headers { stream, end_stream: h.has(flag::END_STREAM), end_headers: h.has(flag::END_HEADERS), fragment: body })
        }
        kind::PRIORITY => {
            let stream = on_a_stream("PRIORITY on stream 0")?;
            if payload.len() != 5 {
                return Err(FrameError { code: ErrorCode::FRAME_SIZE_ERROR, stream: Some(stream), reason: "PRIORITY of the wrong length" });
            }
            Ok(Frame::Priority { stream })
        }
        kind::RST_STREAM => {
            let stream = on_a_stream("RST_STREAM on stream 0")?;
            sized(payload.len() == 4, "RST_STREAM of the wrong length")?;
            Ok(Frame::RstStream { stream, code: ErrorCode(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])) })
        }
        kind::SETTINGS => {
            on_the_connection("SETTINGS on a stream")?;
            let ack = h.has(flag::ACK);
            sized(!ack || payload.is_empty(), "a SETTINGS acknowledgement with settings in it")?;
            sized(payload.len() % 6 == 0, "SETTINGS of a length that is not a multiple of 6")?;
            let values = payload.chunks_exact(6).map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]]))).collect();
            Ok(Frame::Settings { ack, values })
        }
        kind::PUSH_PROMISE => {
            let stream = on_a_stream("PUSH_PROMISE on stream 0")?;
            let (body, _) = unpad(h, payload)?;
            sized(body.len() >= 4, "PUSH_PROMISE too short for the promised stream")?;
            Ok(Frame::PushPromise { stream })
        }
        kind::PING => {
            on_the_connection("PING on a stream")?;
            sized(payload.len() == 8, "PING of the wrong length")?;
            let mut data = [0u8; 8];
            data.copy_from_slice(payload);
            Ok(Frame::Ping { ack: h.has(flag::ACK), data })
        }
        kind::GOAWAY => {
            on_the_connection("GOAWAY on a stream")?;
            sized(payload.len() >= 8, "GOAWAY too short")?;
            Ok(Frame::GoAway {
                last_stream: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff,
                code: ErrorCode(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])),
                debug: &payload[8..],
            })
        }
        kind::WINDOW_UPDATE => {
            sized(payload.len() == 4, "WINDOW_UPDATE of the wrong length")?;
            let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
            if increment == 0 {
                let stream = if h.stream == 0 { None } else { Some(h.stream) };
                return Err(FrameError { code: ErrorCode::PROTOCOL_ERROR, stream, reason: "a WINDOW_UPDATE of 0" });
            }
            Ok(Frame::WindowUpdate { stream: h.stream, increment })
        }
        kind::CONTINUATION => {
            let stream = on_a_stream("CONTINUATION on stream 0")?;
            Ok(Frame::Continuation { stream, end_headers: h.has(flag::END_HEADERS), fragment: payload })
        }
        other => Ok(Frame::Unknown { kind: other, stream: h.stream }),
    }
}

// ------------------------------------------------------------------------------------------------ writing

fn start(out: &mut Vec<u8>, length: usize, kind: u8, flags: u8, stream: u32) {
    Header { length: length as u32, kind, flags, stream }.write(out);
}

/// A SETTINGS frame with these (identifier, value) pairs.
pub(crate) fn write_settings(out: &mut Vec<u8>, values: &[(u16, u32)]) {
    start(out, values.len() * 6, kind::SETTINGS, 0, 0);
    for (id, value) in values {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn write_settings_ack(out: &mut Vec<u8>) {
    start(out, 0, kind::SETTINGS, flag::ACK, 0);
}

pub(crate) fn write_ping(out: &mut Vec<u8>, ack: bool, data: [u8; 8]) {
    start(out, 8, kind::PING, if ack { flag::ACK } else { 0 }, 0);
    out.extend_from_slice(&data);
}

pub(crate) fn write_window_update(out: &mut Vec<u8>, stream: u32, increment: u32) {
    debug_assert!((1..=MAX_WINDOW).contains(&increment));
    start(out, 4, kind::WINDOW_UPDATE, 0, stream);
    out.extend_from_slice(&increment.to_be_bytes());
}

pub(crate) fn write_rst_stream(out: &mut Vec<u8>, stream: u32, code: ErrorCode) {
    start(out, 4, kind::RST_STREAM, 0, stream);
    out.extend_from_slice(&code.0.to_be_bytes());
}

pub(crate) fn write_goaway(out: &mut Vec<u8>, last_stream: u32, code: ErrorCode, debug: &[u8]) {
    start(out, 8 + debug.len(), kind::GOAWAY, 0, 0);
    out.extend_from_slice(&last_stream.to_be_bytes());
    out.extend_from_slice(&code.0.to_be_bytes());
    out.extend_from_slice(debug);
}

/// One DATA frame; the caller keeps `data` within the frame size the peer allows.
pub(crate) fn write_data(out: &mut Vec<u8>, stream: u32, end_stream: bool, data: &[u8]) {
    start(out, data.len(), kind::DATA, if end_stream { flag::END_STREAM } else { 0 }, stream);
    out.extend_from_slice(data);
}

/// A header block as a HEADERS frame and as many CONTINUATION frames as `max_frame` needs.
pub(crate) fn write_header_block(out: &mut Vec<u8>, stream: u32, end_stream: bool, block: &[u8], max_frame: usize) {
    debug_assert!(max_frame >= DEFAULT_MAX_FRAME_SIZE as usize);
    let mut rest = block;
    let mut first = true;
    loop {
        let n = rest.len().min(max_frame);
        let last = n == rest.len();
        let mut flags = if last { flag::END_HEADERS } else { 0 };
        if first && end_stream {
            flags |= flag::END_STREAM;
        }
        start(out, n, if first { kind::HEADERS } else { kind::CONTINUATION }, flags, stream);
        out.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
        first = false;
        if last {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// Parses one whole frame (header and payload) given as bytes.
    fn parse_frame(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
        let h = Header::parse(bytes[..HEADER_LEN].try_into().unwrap());
        assert_eq!(h.length as usize, bytes.len() - HEADER_LEN, "the fixture's length field");
        parse(&h, &bytes[HEADER_LEN..])
    }

    fn made(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        f(&mut out);
        out
    }

    #[test]
    fn a_header_is_nine_bytes_and_the_reserved_bit_is_ignored() {
        let h = Header { length: 0x01_02_03, kind: kind::HEADERS, flags: 0x25, stream: 0x7fff_fffe };
        let bytes = made(|o| h.write(o));
        assert_eq!(bytes, [1, 2, 3, 1, 0x25, 0x7f, 0xff, 0xff, 0xfe]);
        assert_eq!(Header::parse(&bytes.clone().try_into().unwrap()), h);
        let mut with_r = bytes.clone();
        with_r[5] |= 0x80;
        assert_eq!(Header::parse(&with_r.try_into().unwrap()), h);
    }

    #[test]
    fn frames_as_python_hyperframe_writes_them() {
        // tools/h2_frame_oracle.py
        let fx = |hex: &str| unhex(hex);
        let b = fx("00000500010000000168656c6c6f");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Data { stream: 1, end_stream: true, data: b"hello", flow_len: 5 });
        let b = fx("0000080008000000030461626300000000");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Data { stream: 3, end_stream: false, data: b"abc", flow_len: 8 }, "four bytes of padding and the Pad Length are in the flow");
        let b = fx("00000101050000000182");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Headers { stream: 1, end_stream: true, end_headers: true, fragment: &[0x82] });
        let b = fx("0000020100000000058284");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Headers { stream: 5, end_stream: false, end_headers: false, fragment: &[0x82, 0x84] });
        let b = fx("000009012c0000000702800000030f820000");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Headers { stream: 7, end_stream: false, end_headers: true, fragment: &[0x82] }, "padding and priority fields are taken off");
        let b = fx("0000050200000000050000000107");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Priority { stream: 5 });
        let b = fx("00000403000000000100000008");
        assert_eq!(parse_frame(&b).unwrap(), Frame::RstStream { stream: 1, code: ErrorCode::CANCEL });
        let b = fx("000012040000000000000100001000000200000000000400100000");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Settings { ack: false, values: vec![(1, 4096), (2, 0), (4, 1_048_576)] });
        let b = fx("000000040100000000");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Settings { ack: true, values: vec![] });
        let b = fx("0000050504000000010000000282");
        assert_eq!(parse_frame(&b).unwrap(), Frame::PushPromise { stream: 1 });
        let b = fx("0000080600000000003132333435363738");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Ping { ack: false, data: *b"12345678" });
        let b = fx("0000080601000000003132333435363738");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Ping { ack: true, data: *b"12345678" });
        let b = fx("00000b0700000000000000000500000000627965");
        assert_eq!(parse_frame(&b).unwrap(), Frame::GoAway { last_stream: 5, code: ErrorCode::NO_ERROR, debug: b"bye" });
        let b = fx("0000040800000000010000ffff");
        assert_eq!(parse_frame(&b).unwrap(), Frame::WindowUpdate { stream: 1, increment: 65535 });
        let b = fx("0000040800000000007fffffff");
        assert_eq!(parse_frame(&b).unwrap(), Frame::WindowUpdate { stream: 0, increment: MAX_WINDOW });
        let b = fx("00000109040000000182");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Continuation { stream: 1, end_headers: true, fragment: &[0x82] });
        // a kind that is not known is passed over, whatever it holds
        let b = fx("000003fa000000000178797a");
        assert_eq!(parse_frame(&b).unwrap(), Frame::Unknown { kind: 0xfa, stream: 1 });
    }

    #[test]
    fn what_is_written_is_what_hyperframe_writes() {
        assert_eq!(made(|o| write_data(o, 1, true, b"hello")), unhex("00000500010000000168656c6c6f"));
        assert_eq!(made(|o| write_header_block(o, 1, true, &[0x82], 16384)), unhex("00000101050000000182"));
        assert_eq!(made(|o| write_rst_stream(o, 1, ErrorCode::CANCEL)), unhex("00000403000000000100000008"));
        assert_eq!(made(|o| write_settings(o, &[(1, 4096), (2, 0), (4, 1_048_576)])), unhex("000012040000000000000100001000000200000000000400100000"));
        assert_eq!(made(write_settings_ack), unhex("000000040100000000"));
        assert_eq!(made(|o| write_ping(o, false, *b"12345678")), unhex("0000080600000000003132333435363738"));
        assert_eq!(made(|o| write_ping(o, true, *b"12345678")), unhex("0000080601000000003132333435363738"));
        assert_eq!(made(|o| write_goaway(o, 5, ErrorCode::NO_ERROR, b"bye")), unhex("00000b0700000000000000000500000000627965"));
        assert_eq!(made(|o| write_window_update(o, 1, 65535)), unhex("0000040800000000010000ffff"));
        assert_eq!(made(|o| write_window_update(o, 0, MAX_WINDOW)), unhex("0000040800000000007fffffff"));
    }

    #[test]
    fn written_frames_parse_back() {
        let frames = made(|o| {
            write_data(o, 9, false, b"");
            write_data(o, 9, true, &[7u8; 300]);
            write_settings(o, &[]);
            write_goaway(o, 0x7fff_ffff, ErrorCode(0x99), b"");
        });
        let mut rest = &frames[..];
        let mut got = Vec::new();
        while !rest.is_empty() {
            let h = Header::parse(rest[..HEADER_LEN].try_into().unwrap());
            let end = HEADER_LEN + h.length as usize;
            got.push(format!("{:?}", parse(&h, &rest[HEADER_LEN..end]).unwrap()));
            rest = &rest[end..];
        }
        assert!(got[0].starts_with("Data { stream: 9, end_stream: false, data: [], flow_len: 0 }"), "{}", got[0]);
        assert!(got[1].contains("end_stream: true") && got[1].contains("flow_len: 300"));
        assert_eq!(got[2], "Settings { ack: false, values: [] }");
        assert!(got[3].contains("last_stream: 2147483647") && got[3].contains("code: an unknown error (0x99)"), "{}", got[3]);
    }

    #[test]
    fn a_header_block_is_split_into_continuation_frames_of_the_allowed_size() {
        let block: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let out = made(|o| write_header_block(o, 3, true, &block, 16_384));
        let mut rest = &out[..];
        let mut joined = Vec::new();
        let mut shapes = Vec::new();
        while !rest.is_empty() {
            let h = Header::parse(rest[..HEADER_LEN].try_into().unwrap());
            shapes.push((h.kind, h.flags, h.length));
            joined.extend_from_slice(&rest[HEADER_LEN..HEADER_LEN + h.length as usize]);
            rest = &rest[HEADER_LEN + h.length as usize..];
        }
        assert_eq!(shapes, [(kind::HEADERS, flag::END_STREAM, 16_384), (kind::CONTINUATION, 0, 16_384), (kind::CONTINUATION, flag::END_HEADERS, 7_232)]);
        assert_eq!(joined, block);
        // exactly one frame's worth, and nothing at all
        let out = made(|o| write_header_block(o, 3, false, &block[..16_384], 16_384));
        assert_eq!(out.len(), HEADER_LEN + 16_384);
        assert_eq!(out[4], flag::END_HEADERS);
        let out = made(|o| write_header_block(o, 3, false, &[], 16_384));
        assert_eq!(out, unhex("000000010400000003"));
    }

    /// A frame as bytes, for the cases hyperframe would not write.
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Header { length: payload.len() as u32, kind, flags, stream }.write(&mut out);
        out.extend_from_slice(payload);
        out
    }

    fn error_of(bytes: Vec<u8>) -> FrameError {
        parse_frame(&bytes).expect_err("this frame is not valid")
    }

    #[test]
    fn frames_that_break_the_rules_of_their_kind() {
        let conn = |code, reason| FrameError { code, stream: None, reason };
        let stream = |code, id, reason| FrameError { code, stream: Some(id), reason };
        let (protocol, size) = (ErrorCode::PROTOCOL_ERROR, ErrorCode::FRAME_SIZE_ERROR);

        // frames that need a stream, on stream 0
        assert_eq!(error_of(frame(kind::DATA, 0, 0, b"x")), conn(protocol, "DATA on stream 0"));
        assert_eq!(error_of(frame(kind::HEADERS, flag::END_HEADERS, 0, b"")), conn(protocol, "HEADERS on stream 0"));
        assert_eq!(error_of(frame(kind::PRIORITY, 0, 0, &[0; 5])), conn(protocol, "PRIORITY on stream 0"));
        assert_eq!(error_of(frame(kind::RST_STREAM, 0, 0, &[0; 4])), conn(protocol, "RST_STREAM on stream 0"));
        assert_eq!(error_of(frame(kind::PUSH_PROMISE, 0, 0, &[0; 4])), conn(protocol, "PUSH_PROMISE on stream 0"));
        assert_eq!(error_of(frame(kind::CONTINUATION, 0, 0, b"")), conn(protocol, "CONTINUATION on stream 0"));
        // frames that need stream 0, on a stream
        assert_eq!(error_of(frame(kind::SETTINGS, 0, 1, b"")), conn(protocol, "SETTINGS on a stream"));
        assert_eq!(error_of(frame(kind::PING, 0, 1, &[0; 8])), conn(protocol, "PING on a stream"));
        assert_eq!(error_of(frame(kind::GOAWAY, 0, 1, &[0; 8])), conn(protocol, "GOAWAY on a stream"));
        // lengths
        assert_eq!(error_of(frame(kind::RST_STREAM, 0, 1, &[0; 3])), conn(size, "RST_STREAM of the wrong length"));
        assert_eq!(error_of(frame(kind::SETTINGS, 0, 0, &[0; 5])), conn(size, "SETTINGS of a length that is not a multiple of 6"));
        assert_eq!(error_of(frame(kind::SETTINGS, flag::ACK, 0, &[0; 6])), conn(size, "a SETTINGS acknowledgement with settings in it"));
        assert_eq!(error_of(frame(kind::PING, 0, 0, &[0; 7])), conn(size, "PING of the wrong length"));
        assert_eq!(error_of(frame(kind::GOAWAY, 0, 0, &[0; 7])), conn(size, "GOAWAY too short"));
        assert_eq!(error_of(frame(kind::WINDOW_UPDATE, 0, 1, &[0; 5])), conn(size, "WINDOW_UPDATE of the wrong length"));
        assert_eq!(error_of(frame(kind::PUSH_PROMISE, 0, 1, &[0; 3])), conn(size, "PUSH_PROMISE too short for the promised stream"));
        // a PRIORITY of the wrong length loses its stream only
        assert_eq!(error_of(frame(kind::PRIORITY, 0, 3, &[0; 4])), stream(size, 3, "PRIORITY of the wrong length"));
        // a window update of nothing: the stream's loss, or the connection's if it is for the connection
        assert_eq!(error_of(frame(kind::WINDOW_UPDATE, 0, 3, &[0; 4])), stream(protocol, 3, "a WINDOW_UPDATE of 0"));
        assert_eq!(error_of(frame(kind::WINDOW_UPDATE, 0, 0, &[0; 4])), conn(protocol, "a WINDOW_UPDATE of 0"));
        assert_eq!(error_of(frame(kind::WINDOW_UPDATE, 0, 0, &[0x80, 0, 0, 0])), conn(protocol, "a WINDOW_UPDATE of 0"), "the reserved bit is not part of the increment");
    }

    #[test]
    fn padding_and_priority_fields_are_checked() {
        let conn = |code, reason| FrameError { code, stream: None, reason };
        // padding as long as the payload (RFC 9113 section 6.1; the Pad Length byte is not counted in it)
        assert_eq!(error_of(frame(kind::DATA, flag::PADDED, 1, &[4, 1, 2, 3])), conn(ErrorCode::PROTOCOL_ERROR, "padding as long as the frame"));
        assert_eq!(error_of(frame(kind::DATA, flag::PADDED, 1, &[])), conn(ErrorCode::FRAME_SIZE_ERROR, "a padded frame without its Pad Length"));
        // the longest padding that fits leaves no data
        assert_eq!(parse_frame(&frame(kind::DATA, flag::PADDED, 1, &[2, 1, 2])).unwrap(), Frame::Data { stream: 1, end_stream: false, data: &[], flow_len: 3 });
        // priority fields that do not fit
        assert_eq!(error_of(frame(kind::HEADERS, flag::PRIORITY, 1, &[0; 4])), conn(ErrorCode::FRAME_SIZE_ERROR, "HEADERS too short for its priority fields"));
        assert_eq!(error_of(frame(kind::HEADERS, flag::PRIORITY | flag::PADDED, 1, &[2, 0, 0, 0, 0, 9, 9])), conn(ErrorCode::FRAME_SIZE_ERROR, "HEADERS too short for its priority fields"), "5 bytes are needed after the padding is off");
        // PUSH_PROMISE with padding
        assert_eq!(parse_frame(&frame(kind::PUSH_PROMISE, flag::PADDED | flag::END_HEADERS, 1, &[1, 0, 0, 0, 2, 0x82, 0])).unwrap(), Frame::PushPromise { stream: 1 });
    }

    #[test]
    fn unknown_kinds_pass_whatever_they_hold() {
        for kind in [0x0a, 0x10, 0xfa, 0xff] {
            assert_eq!(parse_frame(&frame(kind, 0xff, 0, b"anything")).unwrap(), Frame::Unknown { kind, stream: 0 });
            assert_eq!(parse_frame(&frame(kind, 0, 7, b"")).unwrap(), Frame::Unknown { kind, stream: 7 });
        }
    }

    #[test]
    fn random_frames_never_panic() {
        let mut state = 0x6a09_e667_f3bc_c908u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 40) as usize;
            let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let kind = if next() % 4 == 0 { next() as u8 } else { (next() % 10) as u8 };
            let flags = next() as u8;
            let stream = if next() % 3 == 0 { 0 } else { (next() % 8) as u32 };
            let h = Header { length: len as u32, kind, flags, stream };
            if let Ok(Frame::Data { data, flow_len, .. }) = parse(&h, &payload) {
                assert!(data.len() <= flow_len as usize && flow_len as usize == len);
            }
        }
    }
}
