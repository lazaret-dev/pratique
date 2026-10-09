use super::*;
use crate::quic::wire::put_varint;

fn varint(v: u64) -> Vec<u8> {
    let mut out = vec![];
    put_varint(&mut out, v);
    out
}

fn frame(t: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    put_frame_header(&mut out, t, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn settings_frame(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = vec![];
    for &(id, v) in pairs {
        put_varint(&mut payload, id);
        put_varint(&mut payload, v);
    }
    frame(ty::SETTINGS, &payload)
}

/// What the reader says of `input` fed in pieces of `step` bytes: the events, with the data ranges turned into the bytes they name.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Data(Vec<u8>),
    Other(Event),
}

fn read(kind: Kind, max_headers: usize, input: &[u8], step: usize) -> (Vec<Seen>, Result<(), FrameError>) {
    let mut reader = FrameReader::new(kind, max_headers);
    let mut seen: Vec<Seen> = vec![];
    for piece in input.chunks(step.max(1)) {
        let mut events = vec![];
        let result = reader.feed(piece, &mut events);
        for e in events {
            match e {
                Event::Data(r) => {
                    assert!(r.start < r.end && r.end <= piece.len(), "{r:?} is not inside the {} bytes given", piece.len());
                    // (the bytes of a frame's payload are one run, however they came)
                    match seen.last_mut() {
                        Some(Seen::Data(d)) => d.extend_from_slice(&piece[r]),
                        _ => seen.push(Seen::Data(piece[r].to_vec())),
                    }
                }
                e => seen.push(Seen::Other(e)),
            }
        }
        if result.is_err() {
            return (seen, result);
        }
    }
    (seen, Ok(()))
}

fn request(input: &[u8]) -> (Vec<Seen>, Result<(), FrameError>) {
    read(Kind::Request, 1 << 20, input, input.len().max(1))
}

fn control(input: &[u8]) -> (Vec<Seen>, Result<(), FrameError>) {
    read(Kind::Control, 1 << 20, input, input.len().max(1))
}

/// An error, with its reason set aside (only the code is part of the protocol).
fn code_of(r: Result<(), FrameError>) -> Result<(), u64> {
    match r {
        Ok(()) => Ok(()),
        Err(FrameError::Connection(c, _)) => Err(c),
        Err(FrameError::HeadersTooLarge) => Err(u64::MAX),
    }
}

#[test]
fn headers_and_data_are_read() {
    let mut input = vec![];
    put_headers(&mut input, b"\x00\x00\xd1");
    put_data(&mut input, b"hello");
    put_data(&mut input, b" world");
    let (seen, r) = request(&input);
    assert_eq!(r, Ok(()));
    assert_eq!(seen[0], Seen::Other(Event::Headers(b"\x00\x00\xd1".to_vec())));
    // (two frames: the reader does not say where one ends, the bytes are the same)
    assert_eq!(seen[1], Seen::Data(b"hello world".to_vec()));
    assert_eq!(seen.len(), 2);
}

#[test]
fn the_pieces_the_input_comes_in_do_not_matter() {
    let mut input = vec![];
    put_headers(&mut input, &[7; 300]);
    put_data(&mut input, &[1; 70_000]);
    input.extend_from_slice(&frame(0x21, b"grease"));
    put_data(&mut input, b"x");
    put_headers(&mut input, b"trailers");
    let whole = read(Kind::Request, 1 << 20, &input, input.len());
    assert_eq!(whole.1, Ok(()));
    for step in [1, 2, 3, 5, 7, 64, 255, 256, 1000, 70_000] {
        assert_eq!(read(Kind::Request, 1 << 20, &input, step), whole, "in pieces of {step}");
    }
    assert_eq!(whole.0.len(), 3);
    assert_eq!(whole.0[1], Seen::Data([vec![1; 70_000], b"x".to_vec()].concat()));
}

#[test]
fn a_data_frame_is_reported_in_the_pieces_it_comes_in_and_not_copied() {
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut input = vec![];
    put_frame_header(&mut input, ty::DATA, 10);
    input.extend_from_slice(b"abcd");
    let mut events = vec![];
    reader.feed(&input, &mut events).unwrap();
    assert_eq!(events, vec![Event::Data(2..6)]);
    assert!(!reader.at_frame_boundary());
    events.clear();
    reader.feed(b"efghij\x00", &mut events).unwrap();
    // (six bytes finish the frame; the seventh is the type of the next one)
    assert_eq!(events, vec![Event::Data(0..6)]);
    assert!(!reader.at_frame_boundary());
    events.clear();
    reader.feed(&[0x01, b'z'], &mut events).unwrap();
    assert_eq!(events, vec![Event::Data(1..2)]);
    assert!(reader.at_frame_boundary());
}

#[test]
fn an_empty_data_frame_says_nothing_and_an_empty_headers_frame_is_a_headers_frame() {
    let mut input = vec![];
    put_data(&mut input, b"");
    put_headers(&mut input, b"");
    put_data(&mut input, b"");
    let (seen, r) = request(&input);
    assert_eq!(r, Ok(()));
    assert_eq!(seen, vec![Seen::Other(Event::Headers(vec![]))]);
}

#[test]
fn the_stream_may_end_only_between_frames() {
    let mut reader = FrameReader::new(Kind::Request, 100);
    assert!(reader.at_frame_boundary());
    let mut events = vec![];
    reader.feed(&[0x01], &mut events).unwrap(); // a type
    assert!(!reader.at_frame_boundary());
    reader.feed(&[0x03, b'a', b'b'], &mut events).unwrap(); // a length and a part
    assert!(!reader.at_frame_boundary());
    reader.feed(b"c", &mut events).unwrap();
    assert!(reader.at_frame_boundary());
    // half of a two-byte type
    reader.feed(&[0x40], &mut events).unwrap();
    assert!(!reader.at_frame_boundary());
    reader.feed(&[0x21], &mut events).unwrap(); // (the type 0x21 in two bytes) and no length yet
    assert!(!reader.at_frame_boundary());
    reader.feed(&[0x00], &mut events).unwrap();
    assert!(reader.at_frame_boundary());
}

#[test]
fn frames_of_unknown_types_are_skipped_whatever_their_length() {
    let mut input = vec![];
    input.extend_from_slice(&frame(0x21, b"a reserved type"));
    input.extend_from_slice(&frame(0x1f * 1000 + 0x21, b""));
    input.extend_from_slice(&frame(0x40, &[0; 300]));
    put_data(&mut input, b"d");
    let (seen, r) = request(&input);
    assert_eq!(r, Ok(()));
    assert_eq!(seen, vec![Seen::Data(b"d".to_vec())]);

    // one that is a gigabyte long is skipped as it comes, nothing is kept
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut events = vec![];
    let mut head = varint(0x2a);
    head.extend_from_slice(&varint(1 << 30));
    reader.feed(&head, &mut events).unwrap();
    for _ in 0..16 {
        reader.feed(&[0; 1 << 16], &mut events).unwrap();
    }
    assert!(events.is_empty());
    assert!(!reader.at_frame_boundary());
    // and a length of the largest size an integer has is not a reason to fail
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut head = varint(0x2a);
    head.extend_from_slice(&varint(MAX_VARINT));
    reader.feed(&head, &mut events).unwrap();
    reader.feed(&[0; 100], &mut events).unwrap();
    assert!(events.is_empty());
}

#[test]
fn a_data_frame_of_the_largest_length_is_read_as_it_comes() {
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut head = varint(ty::DATA);
    head.extend_from_slice(&varint(MAX_VARINT));
    let mut events = vec![];
    reader.feed(&head, &mut events).unwrap();
    assert!(events.is_empty());
    reader.feed(&[9; 1000], &mut events).unwrap();
    assert_eq!(events, vec![Event::Data(0..1000)]);
}

#[test]
fn the_frames_of_http2_that_http3_does_not_have_are_errors_on_either_stream() {
    for t in [0x02, 0x06, 0x08, 0x09] {
        assert_eq!(code_of(request(&frame(t, b"")).1), Err(code::H3_FRAME_UNEXPECTED), "{t:#x} on a request stream");
        let mut input = settings_frame(&[]);
        input.extend_from_slice(&frame(t, b""));
        assert_eq!(code_of(control(&input).1), Err(code::H3_FRAME_UNEXPECTED), "{t:#x} on the control stream");
        // (even with the type written in more bytes than it needs: it is the number that counts)
        let mut long = vec![0x40, t as u8, 0];
        assert_eq!(code_of(request(&long).1), Err(code::H3_FRAME_UNEXPECTED));
        long = vec![0x80, 0, 0, t as u8, 0];
        assert_eq!(code_of(request(&long).1), Err(code::H3_FRAME_UNEXPECTED));
    }
}

#[test]
fn a_request_stream_takes_headers_and_data_and_nothing_of_the_control_stream() {
    assert_eq!(code_of(request(&frame(ty::PUSH_PROMISE, &[0, 0x00])).1), Err(code::H3_ID_ERROR));
    for t in [ty::SETTINGS, ty::GOAWAY, ty::CANCEL_PUSH, ty::MAX_PUSH_ID] {
        assert_eq!(code_of(request(&frame(t, &[0])).1), Err(code::H3_FRAME_UNEXPECTED), "{t:#x}");
    }
    // the error is at the type: it does not wait for the frame
    assert_eq!(code_of(request(&[ty::SETTINGS as u8]).1), Err(code::H3_FRAME_UNEXPECTED));
}

#[test]
fn the_control_stream_begins_with_settings() {
    for first in [frame(ty::GOAWAY, &[0]), frame(ty::CANCEL_PUSH, &[0]), frame(ty::DATA, b"x"), frame(0x21, b""), frame(0x40, b"unknown")] {
        let first_type = first[0];
        assert_eq!(code_of(control(&first).1), Err(code::H3_MISSING_SETTINGS), "{first_type:#x} first");
    }
    let mut ok = settings_frame(&[(1, 2)]);
    ok.extend_from_slice(&frame(0x21, b"unknown"));
    ok.extend_from_slice(&frame(ty::GOAWAY, &[8]));
    let (seen, r) = control(&ok);
    assert_eq!(r, Ok(()));
    assert_eq!(seen, vec![Seen::Other(Event::Settings(vec![(1, 2)])), Seen::Other(Event::GoAway(8))]);
}

#[test]
fn what_the_control_stream_may_not_carry_after_settings() {
    let settings = settings_frame(&[]);
    let after = |f: Vec<u8>| {
        let mut input = settings.clone();
        input.extend_from_slice(&f);
        code_of(control(&input).1)
    };
    assert_eq!(after(settings_frame(&[])), Err(code::H3_FRAME_UNEXPECTED));
    assert_eq!(after(frame(ty::DATA, b"x")), Err(code::H3_FRAME_UNEXPECTED));
    assert_eq!(after(frame(ty::HEADERS, b"x")), Err(code::H3_FRAME_UNEXPECTED));
    assert_eq!(after(frame(ty::PUSH_PROMISE, &[0, 0])), Err(code::H3_FRAME_UNEXPECTED));
    assert_eq!(after(frame(ty::MAX_PUSH_ID, &[1])), Err(code::H3_FRAME_UNEXPECTED));
    assert_eq!(after(frame(ty::GOAWAY, &[0])), Ok(()));
    assert_eq!(after(frame(ty::CANCEL_PUSH, &[3])), Ok(()));
    assert_eq!(after(frame(0x21, b"")), Ok(()));
}

#[test]
fn settings_are_pairs() {
    let (seen, r) = control(&settings_frame(&[(0x01, 4096), (0x07, 16), (0x06, 1 << 20), (0x21, 0), (MAX_VARINT, MAX_VARINT)]));
    assert_eq!(r, Ok(()));
    assert_eq!(seen, vec![Seen::Other(Event::Settings(vec![(1, 4096), (7, 16), (6, 1 << 20), (0x21, 0), (MAX_VARINT, MAX_VARINT)]))]);
    // the reader does not judge the identifiers: that is for PeerSettings
    let (seen, r) = control(&settings_frame(&[(0x02, 0), (0x02, 1)]));
    assert_eq!(r, Ok(()));
    assert_eq!(seen, vec![Seen::Other(Event::Settings(vec![(2, 0), (2, 1)]))]);
    // a frame that ends in the middle of a pair, or of an integer
    assert_eq!(code_of(control(&frame(ty::SETTINGS, &[0x01])).1), Err(code::H3_FRAME_ERROR));
    assert_eq!(code_of(control(&frame(ty::SETTINGS, &[0x01, 0x02, 0x03])).1), Err(code::H3_FRAME_ERROR));
    assert_eq!(code_of(control(&frame(ty::SETTINGS, &[0x01, 0x40])).1), Err(code::H3_FRAME_ERROR));
    assert_eq!(code_of(control(&frame(ty::SETTINGS, &[0x40])).1), Err(code::H3_FRAME_ERROR));
}

#[test]
fn goaway_and_cancel_push_hold_one_integer() {
    let mut input = settings_frame(&[]);
    input.extend_from_slice(&frame(ty::GOAWAY, &varint(1 << 20)));
    input.extend_from_slice(&frame(ty::CANCEL_PUSH, &varint(MAX_VARINT)));
    let (seen, r) = control(&input);
    assert_eq!(r, Ok(()));
    assert_eq!(seen[1], Seen::Other(Event::GoAway(1 << 20)));
    assert_eq!(seen[2], Seen::Other(Event::CancelPush(MAX_VARINT)));
    // an integer written in more bytes than it needs is the same integer
    let mut input = settings_frame(&[]);
    input.extend_from_slice(&frame(ty::GOAWAY, &[0x40, 0x08]));
    assert_eq!(control(&input).0[1], Seen::Other(Event::GoAway(8)));

    for payload in [&[][..], &[0, 0], &[0x40], &[0x01, 0x00], &[0x80, 0, 0]] {
        for t in [ty::GOAWAY, ty::CANCEL_PUSH] {
            let mut input = settings_frame(&[]);
            input.extend_from_slice(&frame(t, payload));
            assert_eq!(code_of(control(&input).1), Err(code::H3_FRAME_ERROR), "{t:#x} {payload:?}");
        }
    }
}

#[test]
fn the_size_of_a_headers_frame_is_limited_at_its_length() {
    let mut input = vec![];
    put_headers(&mut input, &[1; 100]);
    assert_eq!(read(Kind::Request, 100, &input, 1000).1, Ok(()));
    assert_eq!(read(Kind::Request, 99, &input, 1000).1, Err(FrameError::HeadersTooLarge));
    // as soon as the length is known, before any of the field section has come
    let mut reader = FrameReader::new(Kind::Request, 99);
    assert_eq!(reader.feed(&input[..3], &mut vec![]), Err(FrameError::HeadersTooLarge));
    // a length that no memory could hold is refused the same way
    let mut head = varint(ty::HEADERS);
    head.extend_from_slice(&varint(MAX_VARINT));
    assert_eq!(FrameReader::new(Kind::Request, 1 << 20).feed(&head, &mut vec![]), Err(FrameError::HeadersTooLarge));
    // (data is not limited here)
    let mut input = vec![];
    put_data(&mut input, &[1; 1000]);
    assert_eq!(read(Kind::Request, 0, &input, 1000).1, Ok(()));
}

#[test]
fn the_control_frames_that_are_kept_whole_are_limited() {
    // as many pairs as fit in the limit are fine
    let pairs = (MAX_WHOLE / 2) as usize;
    let mut payload = vec![];
    for i in 0..pairs {
        payload.extend_from_slice(&[(i % 60) as u8 + 3, 0]);
    }
    assert_eq!(payload.len() as u64, MAX_WHOLE);
    let (seen, r) = control(&frame(ty::SETTINGS, &payload));
    assert_eq!(r, Ok(()));
    assert!(matches!(&seen[0], Seen::Other(Event::Settings(p)) if p.len() == pairs));
    // one byte more is too much, and it is said before the bytes come
    let mut head = varint(ty::SETTINGS);
    head.extend_from_slice(&varint(MAX_WHOLE + 1));
    assert_eq!(code_of(control(&head).1), Err(code::H3_EXCESSIVE_LOAD));
    let mut head = settings_frame(&[]);
    head.extend_from_slice(&varint(ty::GOAWAY));
    head.extend_from_slice(&varint(MAX_WHOLE + 1));
    assert_eq!(code_of(control(&head).1), Err(code::H3_EXCESSIVE_LOAD));
}

#[test]
fn after_an_error_nothing_is_read() {
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut events = vec![];
    assert!(reader.feed(&[ty::SETTINGS as u8], &mut events).is_err());
    let again = reader.feed(&frame(ty::DATA, b"x"), &mut events);
    assert!(matches!(again, Err(FrameError::Connection(code::H3_INTERNAL_ERROR, _))), "{again:?}");
    assert!(events.is_empty());
    assert!(!reader.at_frame_boundary());

    // an error found in the middle of a feed keeps what came before it
    let mut input = vec![];
    put_data(&mut input, b"ok");
    input.extend_from_slice(&frame(0x02, b""));
    let mut reader = FrameReader::new(Kind::Request, 100);
    let mut events = vec![];
    assert!(reader.feed(&input, &mut events).is_err());
    assert_eq!(events, vec![Event::Data(2..4)]);
}

#[test]
fn what_we_announce_is_what_we_read_back() {
    let s = Settings { qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, max_field_section_size: 65_536 };
    let start = control_stream_start(&s);
    assert_eq!(start[0], stream_type::CONTROL as u8);
    let (seen, r) = control(&start[1..]);
    assert_eq!(r, Ok(()));
    let Seen::Other(Event::Settings(pairs)) = &seen[0] else { panic!("{seen:?}") };
    assert_eq!(&pairs[..3], &[(0x01, 4096), (0x07, 16), (0x06, 65_536)]);
    // the last is one of the reserved identifiers, 0x1f * N + 0x21
    assert_eq!(pairs.len(), 4);
    assert_eq!((pairs[3].0 - 0x21) % 0x1f, 0);
    assert!(pairs[3].0 >= 0x21);
    let back = PeerSettings::from_pairs(pairs).unwrap();
    assert_eq!(back, PeerSettings { qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, max_field_section_size: Some(65_536) });
}

#[test]
fn what_the_peer_announces() {
    assert_eq!(
        PeerSettings::from_pairs(&[]).unwrap(),
        PeerSettings { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: None }
    );
    let s = PeerSettings::from_pairs(&[(0x01, 100), (0x07, 3), (0x06, 8000), (0x33, 1), (0x1f * 9 + 0x21, 5)]).unwrap();
    assert_eq!(s, PeerSettings { qpack_max_table_capacity: 100, qpack_blocked_streams: 3, max_field_section_size: Some(8000) });
    // (a limit of 0 is a limit)
    assert_eq!(PeerSettings::from_pairs(&[(0x06, 0)]).unwrap().max_field_section_size, Some(0));
    for id in [0x00, 0x02, 0x03, 0x04, 0x05] {
        assert_eq!(code_of(PeerSettings::from_pairs(&[(id, 0)]).map(|_| ())), Err(code::H3_SETTINGS_ERROR), "{id:#x}");
        assert_eq!(code_of(PeerSettings::from_pairs(&[(0x01, 0), (id, 1)]).map(|_| ())), Err(code::H3_SETTINGS_ERROR), "{id:#x} after another");
    }
    for id in [0x01, 0x06, 0x07, 0x21, 0x99] {
        assert_eq!(code_of(PeerSettings::from_pairs(&[(id, 0), (id, 0)]).map(|_| ())), Err(code::H3_SETTINGS_ERROR), "{id:#x} twice");
        assert_eq!(code_of(PeerSettings::from_pairs(&[(id, 0), (0x02 + 0x40, 0), (id, 1)]).map(|_| ())), Err(code::H3_SETTINGS_ERROR), "{id:#x} twice, apart");
    }
}

#[test]
fn the_error_codes_are_those_of_the_rfc() {
    let all = [
        code::H3_NO_ERROR,
        code::H3_GENERAL_PROTOCOL_ERROR,
        code::H3_INTERNAL_ERROR,
        code::H3_STREAM_CREATION_ERROR,
        code::H3_CLOSED_CRITICAL_STREAM,
        code::H3_FRAME_UNEXPECTED,
        code::H3_FRAME_ERROR,
        code::H3_EXCESSIVE_LOAD,
        code::H3_ID_ERROR,
        code::H3_SETTINGS_ERROR,
        code::H3_MISSING_SETTINGS,
        code::H3_REQUEST_REJECTED,
        code::H3_REQUEST_CANCELLED,
        code::H3_REQUEST_INCOMPLETE,
        code::H3_MESSAGE_ERROR,
        code::H3_CONNECT_ERROR,
        code::H3_VERSION_FALLBACK,
    ];
    for (i, c) in all.iter().enumerate() {
        assert_eq!(*c, 0x100 + i as u64);
    }
}

#[test]
fn random_streams_agree_with_the_model_however_they_are_cut() {
    use super::super::qpack::harness::{Choose, Xorshift};
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    let (mut failed, mut frames, mut data, mut mid_frame) = (0, 0, 0, 0);
    let types = [0x00u64, 0x01, 0x03, 0x04, 0x05, 0x07, 0x0d, 0x02, 0x06, 0x08, 0x09, 0x21, 0x40, 0x1f * 5 + 0x21];
    for _ in 0..6000 {
        let kind = if rng.below(2) == 0 { Kind::Request } else { Kind::Control };
        let max_headers = [0usize, 16, 300, 1 << 20][rng.below(4)];
        let mut input = vec![];
        if kind == Kind::Control && rng.below(8) != 0 {
            let pairs: Vec<(u64, u64)> = (0..rng.below(4)).map(|_| (rng.below(10) as u64, rng.below(70_000) as u64)).collect();
            input.extend_from_slice(&settings_frame(&pairs));
        }
        for _ in 0..rng.below(8) {
            let t = if kind == Kind::Request && rng.below(3) != 0 { [0x00, 0x01][rng.below(2)] } else { types[rng.below(types.len())] };
            let payload: Vec<u8> = match (t, rng.below(6)) {
                (0x07 | 0x03, 0..=3) => varint(rng.below(1 << 20) as u64),
                (0x04, 0..=3) => {
                    let mut p = vec![];
                    for _ in 0..rng.below(5) {
                        put_varint(&mut p, rng.below(10) as u64);
                        put_varint(&mut p, rng.below(1 << 16) as u64);
                    }
                    p
                }
                _ => {
                    let n = match rng.below(6) {
                        0 => 0,
                        1 => 1,
                        2 => rng.below(10),
                        3 => rng.below(40),
                        4 => rng.below(400),
                        _ => 16,
                    };
                    (0..n).map(|_| rng.byte()).collect()
                }
            };
            // a length that is right, or one that is not
            let len = match rng.below(12) {
                0 => payload.len() as u64 + 1,
                1 => (payload.len() as u64).saturating_sub(1),
                _ => payload.len() as u64,
            };
            put_frame_header(&mut input, t, len);
            input.extend_from_slice(&payload);
        }
        match rng.below(4) {
            0 => {
                let keep = rng.below(input.len() + 1);
                input.truncate(keep);
            }
            1 => input.extend((0..rng.below(6)).map(|_| rng.byte())),
            _ => {}
        }
        let cuts: Vec<usize> = (0..rng.below(5)).map(|_| 1 + rng.below(20)).collect();
        harness::check(kind, max_headers, &input, &cuts);
        let m = harness::model(kind, max_headers, &input);
        failed += usize::from(m.result.is_err());
        mid_frame += usize::from(m.result.is_ok() && !m.at_boundary);
        for s in &m.seen {
            match s {
                harness::Seen::Data(d) => data += d.len(),
                harness::Seen::Other(_) => frames += 1,
            }
        }
    }
    // (the streams do reach all of it: errors, frames of every kind, data, and a cut in the middle of a frame)
    assert!(failed > 500 && failed < 4500, "{failed} streams ended in an error");
    assert!(frames > 3000, "{frames} frames were read");
    assert!(data > 20_000, "{data} bytes of data were read");
    assert!(mid_frame > 300, "{mid_frame} streams ended in the middle of a frame");
}
