//! Entry points for the fuzzer (`fuzz/`), which cannot reach the `pub(crate)` HTTP/3 layers. Built only with
//! `--cfg pratique_fuzzing`. Each runs a layer on whatever bytes it is given and panics when a property that must hold for any
//! input does not (see `qpack_harness.rs` for the checks).

use super::connection::harness as connection_harness;
use super::frame::{self, harness as frame_harness, Kind};
use super::qpack::harness::{self, Choose};
use super::qpack::{Decoded, Decoder, Encoder, EncoderConfig};
use crate::http::h2::hpack::{Field, FieldRef};

/// Choices read off the bytes of an input: one byte for a number below 256, two for one that is larger. Out of bytes it chooses 0
/// and says it is exhausted.
struct Bytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bytes<'_> {
    fn next(&mut self) -> usize {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        usize::from(b)
    }
}

impl Choose for Bytes<'_> {
    fn below(&mut self, n: usize) -> usize {
        if n <= 1 {
            0
        } else if n <= 256 {
            self.next() % n
        } else {
            (self.next() << 8 | self.next()) % n
        }
    }

    fn exhausted(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// `data[0]` chooses the capacity the decoder announces, the blocked streams it allows and the longest list it keeps; the rest is a
/// script of steps, each a byte (what to do, and a stream number), a length and that many bytes: put them on the encoder stream,
/// decode them as a field section, abandon the stream, or take what the decoder has for the decoder stream. The decoder's
/// bookkeeping must add up after each step, a list it gives is within the limit, what it says on the decoder stream is whole
/// instructions, a section that waits has not got what it needs, and every list that decoded within the limit is written by our
/// encoder (in several ways) and read back by a fresh decoder as the same list. The first error ends the script: it is the end of
/// a connection.
pub fn qpack_decoder(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else { return };
    let capacity = [0usize, 64, 220, 4096][(sel & 3) as usize];
    let blocked = [0usize, 1, 4, 100][((sel >> 2) & 3) as usize];
    let limit = [100usize, 1000, 64 << 10, 1 << 20][((sel >> 4) & 3) as usize];
    let mut dec = Decoder::new(capacity, blocked, limit);
    let mut lists: Vec<Vec<Field>> = vec![];
    while let [op, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (payload, after) = tail.split_at(n);
        rest = after;
        let stream = u64::from(op >> 2) * 4;
        match op & 3 {
            0 => {
                if dec.encoder_stream(payload).is_err() {
                    break;
                }
            }
            1 => {
                let mut out = vec![];
                match dec.decode(stream, payload, &mut out) {
                    Err(_) => break,
                    Ok(Decoded::Done { within_limit }) => {
                        assert!(out.iter().map(Field::size).sum::<usize>() <= limit, "a list over the limit was given");
                        if within_limit {
                            lists.push(out);
                        }
                    }
                    Ok(Decoded::Blocked { required_insert_count }) => assert!(required_insert_count > dec.insert_count(), "a section waits for what is there"),
                }
            }
            2 => dec.cancel_stream(stream),
            _ => harness::check_decoder_stream(&dec.take_output()),
        }
        harness::check_decoder(&dec);
    }
    harness::check_decoder_stream(&dec.take_output());
    for list in lists.iter().take(3) {
        if list.iter().map(Field::size).sum::<usize>() <= 16 << 10 {
            harness::round_trip(list);
        }
    }
}

/// A whole exchange between our encoder and our decoder, its settings, requests, delays, cuts and abandoned streams all taken from
/// the bytes (see `qpack_harness.rs`): nothing the two say to each other is an error, what the decoder reads is what the encoder was
/// given, no stream waits on more than was allowed, and when everything has arrived the tables agree.
pub fn qpack_exchange(data: &[u8]) {
    harness::exchange(&mut Bytes { data, pos: 0 }, 400);
}

/// The encoder against a decoder stream it should not trust: `data[0]` chooses the peer's capacity and blocked streams and the
/// encoder's settings, and the rest is a script of requests (fields from the bytes) and arbitrary bytes for the decoder stream. An
/// instruction that makes no sense is an error (the end of the script, as it would be of a connection), anything else must leave the
/// books balanced: entries counted as referred to are the ones the sections not acknowledged refer to, nothing referred to is evicted,
/// the table is within its limits, and no more streams may be blocked than allowed.
pub fn qpack_encoder(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else { return };
    let capacity = [0usize, 64, 220, 4096, 1 << 21][(sel % 5) as usize];
    let peer_blocked = [0usize, 1, 4, 100][((sel >> 3) & 3) as usize];
    let cfg = EncoderConfig { table_capacity: [100usize, 300, 4096, 1 << 20][((sel >> 5) & 3) as usize], blocked_streams: [0usize, 1, 3, 50][((sel >> 1) & 3) as usize], only_safe_names: sel & 0x80 != 0 };
    let mut enc = Encoder::new(cfg);
    enc.set_peer_settings(capacity as u64, peer_blocked as u64);
    let mut recent = vec![];
    let mut next = 0u64;
    while let [op, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (payload, after) = tail.split_at(n);
        rest = after;
        if op & 1 == 0 {
            // a request: the fields come from the payload (a stream per request, now and then the last one again)
            let stream = if op & 8 != 0 && next > 0 { next - 4 } else { next += 4; next - 4 };
            let list = harness::fields(&mut Bytes { data: payload, pos: 0 }, &mut recent);
            let refs: Vec<FieldRef<'_>> = list.iter().map(|(f, s)| FieldRef { name: &f.name, value: &f.value, sensitive: *s }).collect();
            let mut block = vec![];
            enc.encode(stream, &refs, &mut block);
            let _ = enc.take_output();
        } else if enc.decoder_stream(payload).is_err() {
            break;
        }
        harness::check_encoder(&enc);
    }
}

/// Scripts for `qpack_decoder` made of the examples of RFC 9204 appendix B: the dynamic table, a section that waits, a duplicate, an
/// eviction, and sections made without a table.
pub fn qpack_example_decoder_scripts() -> Vec<Vec<u8>> {
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    // (what to do and the stream), then the bytes of it
    fn step(op: u8, stream: u8, bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![(stream << 2) | op, bytes.len() as u8];
        v.extend_from_slice(bytes);
        v
    }
    let capacity_4096_blocked_100_limit_1m = 0x30 | 0x0c | 0x03;
    let mut all = vec![];
    // the whole of the appendix's exchange
    let mut s = vec![capacity_4096_blocked_100_limit_1m];
    s.extend(step(0, 0, &hex("3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468")));
    s.extend(step(1, 1, &hex("0381 10 11")));
    s.extend(step(3, 0, &[]));
    s.extend(step(0, 0, &hex("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565")));
    s.extend(step(1, 2, &hex("0500 80 c1 81")));
    s.extend(step(2, 2, &[]));
    s.extend(step(0, 0, &hex("02")));
    s.extend(step(1, 2, &hex("0500 80 c1 81")));
    s.extend(step(3, 0, &[]));
    s.extend(step(0, 0, &hex("810d 6375 7374 6f6d 2d76 616c 7565 32")));
    s.extend(step(1, 3, &hex("0600 80")));
    s.extend(step(1, 4, &hex("0600 84")));
    all.push(s);
    // a section with no table: a literal with a static name, then the indexed static entries of a request
    let mut s = vec![0];
    s.extend(step(1, 0, &hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")));
    s.extend(step(1, 1, &hex("0000 d1 d7 c1 50 0b 7777772e6578616d706c652e636f6d")));
    all.push(s);
    // the second half: the section first, the instructions after it
    let mut s = vec![capacity_4096_blocked_100_limit_1m];
    s.extend(step(1, 1, &hex("0381 10 11")));
    s.extend(step(0, 0, &hex("3fbd01 c00f 7777772e6578616d706c652e636f6d")));
    s.extend(step(1, 1, &hex("0381 10 11")));
    s.extend(step(0, 0, &hex("c10c 2f73616d706c652f70617468")));
    s.extend(step(1, 1, &hex("0381 10 11")));
    all.push(s);
    all
}

/// Scripts for `qpack_encoder`: requests, and acknowledgments, cancellations and increments for the decoder stream.
pub fn qpack_example_encoder_scripts() -> Vec<Vec<u8>> {
    let step = |op: u8, bytes: &[u8]| -> Vec<u8> {
        let mut v = vec![op, bytes.len() as u8];
        v.extend_from_slice(bytes);
        v
    };
    let mut all = vec![];
    for sel in [0x3bu8, 0x7b, 0xfb, 0x00, 0x24] {
        let mut s = vec![sel];
        s.extend(step(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
        s.extend(step(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
        s.extend(step(1, &[0x84]));
        s.extend(step(0, &[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6]));
        s.extend(step(1, &[0x01]));
        s.extend(step(8, &[3, 3, 3, 3, 3, 3, 3, 3]));
        s.extend(step(1, &[0x48]));
        s.extend(step(1, &[0x88, 0x01, 0x4c]));
        all.push(s);
    }
    all
}

/// Scripts for `qpack_exchange`: pseudo-random choices.
pub fn qpack_example_exchange_scripts() -> Vec<Vec<u8>> {
    (1..=8u64)
        .map(|seed| {
            let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            (0..600)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x >> 24) as u8
                })
                .collect()
        })
        .collect()
}

/// The frame reader against a model that has the whole stream before it (`frame_harness.rs`). `data[0]` chooses whether the stream is a
/// request stream or the control stream and the longest HEADERS frame kept; `data[1]` how many of the bytes after it are the sizes of the
/// pieces the stream comes in (one more than the byte, repeated); the rest is the stream. However it is cut, the reader must say what the
/// model says (the frames, the error and the stream's end between frames), and what it read is written again and read back.
pub fn frames(data: &[u8]) {
    let (Some(&sel), Some(&n)) = (data.first(), data.get(1)) else { return };
    let kind = if sel & 1 == 0 { Kind::Request } else { Kind::Control };
    let max_headers = [0usize, 16, 300, 1 << 20][usize::from(sel >> 1) & 3];
    let rest = &data[2..];
    let n = usize::from(n & 15).min(rest.len());
    let cuts: Vec<usize> = rest[..n].iter().map(|b| usize::from(*b) + 1).collect();
    frame_harness::check(kind, max_headers, &rest[n..], &cuts);
}

/// Streams for `frames`: a response, the control stream of a server, and the ways they go wrong.
pub fn frame_example_streams() -> Vec<Vec<u8>> {
    let mut all = vec![];
    let with = |sel: u8, cuts: &[u8], stream: &[u8]| -> Vec<u8> {
        let mut v = vec![sel, cuts.len() as u8];
        v.extend_from_slice(cuts);
        v.extend_from_slice(stream);
        v
    };
    let mut response = vec![];
    frame::put_headers(&mut response, &[0x00, 0x00, 0xd9]);
    frame::put_data(&mut response, b"hello, ");
    frame::put_frame_header(&mut response, 0x21, 3);
    response.extend_from_slice(b"xyz");
    frame::put_data(&mut response, b"world");
    frame::put_headers(&mut response, &[0x00, 0x00, 0x20, 0x01, b'x', 0x01, b'y']);
    for sel in [6u8, 4, 2, 0] {
        all.push(with(sel, &[], &response));
        all.push(with(sel, &[0, 2, 6], &response));
    }
    // a HEADERS frame of exactly the size allowed (16) and one byte more
    for len in [16usize, 17] {
        let mut s = vec![];
        frame::put_headers(&mut s, &vec![0x11; len]);
        all.push(with(2, &[], &s));
    }
    let announce = frame::Settings { qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, max_field_section_size: 1 << 16 };
    let mut control = frame::control_stream_start(&announce)[1..].to_vec();
    frame::put_frame_header(&mut control, 0x07, 2);
    control.extend_from_slice(&[0x40, 0x08]);
    frame::put_frame_header(&mut control, 0x1f * 3 + 0x21, 2);
    control.extend_from_slice(&[0, 0]);
    frame::put_frame_header(&mut control, 0x03, 1);
    control.push(0x00);
    all.push(with(7, &[], &control));
    all.push(with(7, &[0, 4, 1], &control));
    // what a server must not send: a second SETTINGS, MAX_PUSH_ID, a frame of a request, no SETTINGS first, an HTTP/2 frame
    let mut second = frame::control_stream_start(&announce)[1..].to_vec();
    second.extend_from_slice(&frame::control_stream_start(&announce)[1..]);
    all.push(with(7, &[], &second));
    all.push(with(7, &[], &[0x04, 0x00, 0x0d, 0x01, 0x00]));
    all.push(with(7, &[], &[0x04, 0x00, 0x00, 0x01, b'x']));
    all.push(with(7, &[], &[0x07, 0x01, 0x00]));
    all.push(with(6, &[], &[0x00, 0x02, b'o', b'k', 0x02, 0x00]));
    all.push(with(6, &[], &[0x05, 0x02, 0x00, 0x00]));
    // control frames at the longest kept (16 KiB, begun and not finished) and one byte longer
    all.push(with(7, &[], &[0x04, 0x80, 0x00, 0x40, 0x00]));
    all.push(with(7, &[], &[0x04, 0x80, 0x00, 0x40, 0x01]));
    all.push(with(7, &[], &[0x04, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00]));
    all.push(with(7, &[], &[0x04, 0x00, 0x03, 0x80, 0x00, 0x40, 0x01]));
    all
}

/// A whole HTTP/3 client connection against a server the bytes of the input make up (see `connection_harness.rs`): `data[0] & 1` says
/// whether the server may also send bytes that mean nothing; the rest is the script. The connection's books add up after every step, a
/// connection that is lost has closed the transport with a code of the RFCs, the application sees each stream's events in order, a server
/// that says only what is well made does not lose the connection and what it sent is what is read, and what the client wrote is what a
/// decoder makes the requests of.
pub fn connection_exchange(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    connection_harness::exchange(&mut Bytes { data: rest, pos: 0 }, 300, sel & 1 == 1);
}

/// Scripts for `connection_exchange`: pseudo-random choices, with and without bytes that mean nothing.
pub fn connection_example_scripts() -> Vec<Vec<u8>> {
    (1..=12u64)
        .map(|seed| {
            let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut v = vec![(seed & 1) as u8 ^ 1];
            v.extend((0..1500).map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            }));
            v
        })
        .collect()
}
