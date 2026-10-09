//! What the frame reader's tests and its fuzz target (`h3_frames`) both check. For any bytes, cut in whatever pieces, the reader must say
//! what a second parser says that has the whole stream before it: a few lines that walk the bytes with no state, so that a slip in the
//! reader's state machine (a length counted one off, a frame skipped too far, an error found a byte late) shows as a disagreement and
//! not as two readers that are wrong together. Every frame the reader has read is also written again and read back.
//!
//! The data of a DATA frame comes as ranges of whatever was fed (and a frame's bytes come in as many events as there were feeds), so
//! both sides are compared as the bytes in a run of data events, with the runs joined.

use super::*;
use crate::quic::wire;

/// What came out of a stream: data (the bytes of one run of DATA frames) or another event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seen {
    Data(Vec<u8>),
    Other(Event),
}

/// Everything that is said of a stream: what was read, whether the reader stopped on an error (its code; `u64::MAX` for a HEADERS
/// frame that is too long, which is not an error of the connection), and whether the stream ended between frames.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) seen: Vec<Seen>,
    pub(crate) result: Result<(), u64>,
    pub(crate) at_boundary: bool,
}

fn add_data(seen: &mut Vec<Seen>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    match seen.last_mut() {
        Some(Seen::Data(d)) => d.extend_from_slice(bytes),
        _ => seen.push(Seen::Data(bytes.to_vec())),
    }
}

fn code_of(e: &FrameError) -> u64 {
    match e {
        FrameError::Connection(c, _) => *c,
        FrameError::HeadersTooLarge => u64::MAX,
    }
}

/// What the reader makes of `input` fed in pieces of the sizes in `cuts` (over and over; none: all at once). It checks, as it goes, what
/// holds for any input: a data range is inside the piece it came from and is not empty, no HEADERS frame is longer than allowed, a
/// request stream has only data and headers, the control stream's SETTINGS is its first event and its only one, and after an error nothing
/// more is read.
pub(crate) fn run_reader(kind: Kind, max_headers: usize, input: &[u8], cuts: &[usize]) -> Outcome {
    let mut reader = FrameReader::new(kind, max_headers);
    let mut seen = vec![];
    let mut pos = 0;
    let mut i = 0;
    let mut events_total = 0;
    let mut result = Ok(());
    while pos < input.len() {
        let take = if cuts.is_empty() { input.len() } else { cuts[i % cuts.len()].max(1) };
        i += 1;
        let piece = &input[pos..(pos + take).min(input.len())];
        pos += piece.len();
        let mut events = vec![];
        let r = reader.feed(piece, &mut events);
        for e in events {
            match e {
                Event::Data(r) => {
                    assert!(r.start < r.end && r.end <= piece.len(), "{r:?} is not inside the {} bytes it came from", piece.len());
                    assert_eq!(kind, Kind::Request, "data on the control stream");
                    add_data(&mut seen, &piece[r]);
                }
                e => {
                    match (&e, kind) {
                        (Event::Headers(h), Kind::Request) => assert!(h.len() <= max_headers, "a HEADERS frame over the limit was kept"),
                        (Event::Settings(_), Kind::Control) => assert_eq!(events_total, 0, "SETTINGS is not the first thing on the control stream"),
                        (Event::GoAway(_) | Event::CancelPush(_), Kind::Control) => assert!(events_total > 0, "a frame before SETTINGS"),
                        _ => panic!("{e:?} on a stream of kind {kind:?}"),
                    }
                    seen.push(Seen::Other(e));
                }
            }
            events_total += 1;
        }
        if let Err(e) = r {
            result = Err(code_of(&e));
            // after an error nothing is read
            let mut more = vec![];
            assert!(reader.feed(b"\x00\x01x", &mut more).is_err(), "the reader went on after an error");
            assert!(more.is_empty());
            break;
        }
    }
    Outcome { seen, result, at_boundary: reader.at_frame_boundary() }
}

/// What a parser with the whole stream before it makes of it (see the top of the file).
pub(crate) fn model(kind: Kind, max_headers: usize, b: &[u8]) -> Outcome {
    let mut seen = vec![];
    let mut pos = 0;
    let mut first = true;
    let mut settings_seen = false;
    let done = |seen: Vec<Seen>, at_boundary: bool| Outcome { seen, result: Ok(()), at_boundary };
    let failed = |seen: Vec<Seen>, code: u64| Outcome { seen, result: Err(code), at_boundary: false };
    loop {
        if pos == b.len() {
            return done(seen, true);
        }
        let Some((t, n)) = wire::get_varint(&b[pos..]) else { return done(seen, false) };
        pos += n;
        // which frames may be here
        if matches!(t, 0x02 | 0x06 | 0x08 | 0x09) {
            return failed(seen, code::H3_FRAME_UNEXPECTED);
        }
        match kind {
            Kind::Request => match t {
                0x05 => return failed(seen, code::H3_ID_ERROR),
                0x03 | 0x04 | 0x07 | 0x0d => return failed(seen, code::H3_FRAME_UNEXPECTED),
                _ => {}
            },
            Kind::Control => {
                if first && t != 0x04 {
                    return failed(seen, code::H3_MISSING_SETTINGS);
                }
                if (t == 0x04 && settings_seen) || matches!(t, 0x00 | 0x01 | 0x05 | 0x0d) {
                    return failed(seen, code::H3_FRAME_UNEXPECTED);
                }
            }
        }
        first = false;
        let Some((len, n)) = wire::get_varint(&b[pos..]) else { return done(seen, false) };
        pos += n;
        let avail = (b.len() - pos) as u64;
        match t {
            0x00 => {
                let take = len.min(avail) as usize;
                add_data(&mut seen, &b[pos..pos + take]);
                pos += take;
                if len > avail {
                    return done(seen, false);
                }
            }
            0x01 => {
                if len > max_headers as u64 {
                    return failed(seen, u64::MAX);
                }
                if len > avail {
                    return done(seen, false);
                }
                seen.push(Seen::Other(Event::Headers(b[pos..pos + len as usize].to_vec())));
                pos += len as usize;
            }
            0x03 | 0x04 | 0x07 => {
                if len > MAX_WHOLE {
                    return failed(seen, code::H3_EXCESSIVE_LOAD);
                }
                if len > avail {
                    return done(seen, false);
                }
                let payload = &b[pos..pos + len as usize];
                pos += len as usize;
                if t == 0x04 {
                    settings_seen = true;
                    let mut pairs = vec![];
                    let mut at = 0;
                    while at < payload.len() {
                        let Some((id, n)) = wire::get_varint(&payload[at..]) else { return failed(seen, code::H3_FRAME_ERROR) };
                        at += n;
                        let Some((v, n)) = wire::get_varint(&payload[at..]) else { return failed(seen, code::H3_FRAME_ERROR) };
                        at += n;
                        pairs.push((id, v));
                    }
                    seen.push(Seen::Other(Event::Settings(pairs)));
                } else {
                    match wire::get_varint(payload) {
                        Some((v, n)) if n == payload.len() => seen.push(Seen::Other(if t == 0x07 { Event::GoAway(v) } else { Event::CancelPush(v) })),
                        _ => return failed(seen, code::H3_FRAME_ERROR),
                    }
                }
            }
            _ => {
                let take = len.min(avail) as usize;
                pos += take;
                if len > avail {
                    return done(seen, false);
                }
            }
        }
    }
}

/// The checks for one stream: the reader says what the model says, however the stream is cut (all at once, in the pieces of `cuts`, a
/// byte at a time), and what it read as a request stream is written again and read back as the same.
pub(crate) fn check(kind: Kind, max_headers: usize, input: &[u8], cuts: &[usize]) {
    let want = model(kind, max_headers, input);
    assert_eq!(run_reader(kind, max_headers, input, &[]), want, "the reader and the model disagree on {input:02x?} ({kind:?}, headers up to {max_headers})");
    if !cuts.is_empty() {
        assert_eq!(run_reader(kind, max_headers, input, cuts), want, "the reader and the model disagree on {input:02x?} cut in {cuts:?}");
    }
    if input.len() <= 4096 {
        assert_eq!(run_reader(kind, max_headers, input, &[1]), want, "the reader and the model disagree on {input:02x?}, a byte at a time");
    }
    if kind == Kind::Request && want.result.is_ok() {
        let mut again = vec![];
        for s in &want.seen {
            match s {
                Seen::Data(d) => put_data(&mut again, d),
                Seen::Other(Event::Headers(h)) => put_headers(&mut again, h),
                Seen::Other(e) => panic!("{e:?} on a request stream"),
            }
        }
        let back = run_reader(kind, max_headers, &again, &[]);
        assert_eq!(back.seen, want.seen, "what was written is not what was read");
        assert_eq!(back.result, Ok(()));
        assert!(back.at_boundary);
    }
    for s in &want.seen {
        if let Seen::Other(Event::Settings(pairs)) = s {
            // (any pairs: it may say no, it may not panic)
            let _ = PeerSettings::from_pairs(pairs);
        }
    }
}
