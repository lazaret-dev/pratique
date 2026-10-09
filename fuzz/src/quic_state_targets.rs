//! The fuzz targets for the parts of QUIC that keep state: `quic_params`, `quic_buffers`, `quic_streams`, `quic_recovery` and
//! `quic_connection`. (The packets and frames are `quic_packet` and `quic_frame`, in `quic_targets.rs`.) Each runs a model next to the
//! code, or checks the books of the code after every step, so that what is found is a wrong answer and not only a crash:
//!
//! | target            | what must hold |
//! |-------------------|----------------|
//! | `quic_params`     | transport parameters are read or refused with a transport parameter error, never a panic; what is read is within the limits of RFC 9000 section 18.2, is written and read again as itself, and the writing is the same again; a cut anywhere in them is not a panic |
//! | `quic_buffers`    | by the first byte: a `RangeSet` is the same as a `BTreeSet` of numbers after every operation, as the fewest ranges; a `SendBuf` with a `Reassembler` for a receiver, with chunks that are lost, delivered twice and acknowledged late, sends exactly the bytes written, its books balance after every step, and when everything is acknowledged the receiver has it all; a `Reassembler` holds what a model of the bytes says, and refuses what the model says, and a refusal changes nothing |
//! | `quic_streams`    | by the first byte: two endpoints of streams, joined by a network that loses and delays and an application that does what the input says, lose and change no bytes, keep their books (`Streams::check`) after every step and end with nothing left; or one endpoint given the frames that the input makes (any, from a hostile peer) and the application's calls: no panic, the books hold, what it writes is frames that read and fit |
//! | `quic_recovery`   | loss recovery against a model of what was sent: bytes in flight and the count of ack-eliciting packets in flight are the model's after every step, an acknowledgment acknowledges exactly the packets sent in its ranges, no packet that the packet threshold or the time threshold says is lost is left outstanding, the timer is set when it has to be, the congestion window never goes under its minimum |
//! | `quic_connection` | a whole client connection, against the test server over a network that loses, duplicates, delays and corrupts, with settings and steps from the input (see `src/quic/fuzz_hooks.rs`): honest, every byte of every stream that was not reset comes out as it went in and the connection ends by the idle timeout; hostile, the server also sends the frames of the input, and nothing panics, grows without end or sends a datagram that is too large |

use crate::quic_targets::Cursor;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::time::{Duration, Instant};
use pratique::quic::connection::SentFrame;
use pratique::quic::frame::{self, Frame};
use pratique::quic::packet::PacketType;
use pratique::quic::rangeset::RangeSet;
use pratique::quic::reassembly::{self, Reassembler};
use pratique::quic::recovery::{Recovery, Sent, Space, PACKET_THRESHOLD};
use pratique::quic::sendbuf::{Chunk, SendBuf};
use pratique::quic::streams::{StreamError, StreamEvent, Streams, StreamsConfig};
use pratique::quic::transport_params::{self as tp, Sender, TransportParameters};

// ---------------------------------------------------------------------------------------------------------------------------
// quic_params

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

pub const PARAMS_DICT: &[&[u8]] = &[
    // the ids of the parameters, each with a length of 1 and a value of 1
    b"\x00\x04\x08\x08\x08\x08\x08\x08\x08\x08",
    b"\x01\x02\x75\x30",
    b"\x02\x10",
    b"\x03\x02\x45\xc0",
    b"\x04\x04\x80\x10\x00\x00",
    b"\x05\x04\x80\x04\x00\x00",
    b"\x06\x04\x80\x04\x00\x00",
    b"\x07\x04\x80\x04\x00\x00",
    b"\x08\x01\x64",
    b"\x09\x01\x64",
    b"\x0a\x01\x03",
    b"\x0b\x01\x19",
    b"\x0c\x00",
    b"\x0d\x29",
    b"\x0e\x01\x04",
    b"\x0f\x04\x01\x02\x03\x04",
    b"\x10\x04\x01\x02\x03\x04",
    b"\x20\x04\x80\x00\x40\x00",
    // a grease id, and an id that takes two bytes
    b"\x1b\x00",
    b"\x40\x58\x01\x00",
];

pub fn seeds_params() -> Vec<Vec<u8>> {
    let mut client = TransportParameters {
        max_idle_timeout: 30_000,
        initial_max_data: 1 << 20,
        initial_max_stream_data_bidi_local: 1 << 18,
        initial_max_stream_data_bidi_remote: 1 << 18,
        initial_max_stream_data_uni: 1 << 18,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        initial_source_connection_id: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        max_datagram_frame_size: Some(1200),
        ..TransportParameters::default()
    };
    client.unknown.push((27, vec![1, 2]));
    let mut server = client.clone();
    server.original_destination_connection_id = Some(vec![9, 9, 9, 9]);
    server.stateless_reset_token = Some([7; 16]);
    server.retry_source_connection_id = Some(vec![5, 5]);
    server.disable_active_migration = true;
    let mut seeds = Vec::new();
    for (p, sender, sel) in [(&client, Sender::Client, 0u8), (&server, Sender::Server, 1)] {
        let mut v = vec![sel];
        v.extend(p.encode(sender));
        seeds.push(v);
    }
    // what the RFC's own example has: the parameters of a client, and the ones that quic-go and aioquic send
    seeds.push([vec![0u8], hex("0f 04 01 02 03 04 04 02 44 00 01 02 40 64")].concat());
    // each limit of section 18.2 on both sides of its edge (the fuzzer does not find an exact edge like 2^14 by chance)
    for edge in [
        "0b 02 7f ff",                         // max_ack_delay 2^14 - 1: allowed
        "0b 04 80 00 40 00",                   // 2^14: refused
        "0a 01 14",                            // ack_delay_exponent 20: allowed
        "0a 01 15",                            // 21: refused
        "03 02 44 b0",                         // max_udp_payload_size 1200: allowed
        "03 02 44 af",                         // 1199: refused
        "08 08 d0 00 00 00 00 00 00 00",       // initial_max_streams_bidi 2^60: allowed
        "08 08 d0 00 00 00 00 00 00 01",       // 2^60 + 1: refused
        "09 08 d0 00 00 00 00 00 00 00",       // initial_max_streams_uni 2^60: allowed
        "09 08 d0 00 00 00 00 00 00 01",       // 2^60 + 1: refused
        "0e 01 02",                            // active_connection_id_limit 2: allowed
        "0e 01 01",                            // 1: refused
    ] {
        seeds.push([vec![0u8], hex("0f 04 01 02 03 04"), hex(edge)].concat());
    }
    seeds
}

/// A variable-length integer from the front of `b` (which has one): its value and its length in bytes.
fn varint(b: &[u8]) -> (u64, usize) {
    let n = 1usize << (b[0] >> 6);
    let mut v = u64::from(b[0] & 0x3f);
    for x in &b[1..n] {
        v = v << 8 | u64::from(*x);
    }
    (v, n)
}

pub fn params(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let sender = if sel & 1 == 0 { Sender::Client } else { Sender::Server };
    match TransportParameters::decode(rest, sender) {
        Err(e) => {
            assert_eq!(e.transport_error(), tp::TRANSPORT_PARAMETER_ERROR);
            assert!(!e.0.is_empty());
        }
        Ok(p) => {
            assert!(p.max_udp_payload_size >= tp::MIN_UDP_PAYLOAD_SIZE, "a payload size under 1200");
            assert!(u64::from(p.ack_delay_exponent) <= tp::MAX_ACK_DELAY_EXPONENT);
            assert!(p.max_ack_delay < tp::MAX_ACK_DELAY_LIMIT);
            assert!(p.active_connection_id_limit >= 2);
            assert!(p.initial_max_streams_bidi <= 1 << 60 && p.initial_max_streams_uni <= 1 << 60);
            for cid in [&p.initial_source_connection_id, &p.original_destination_connection_id, &p.retry_source_connection_id].into_iter().flatten() {
                assert!(cid.len() <= 20, "a connection id of {} bytes", cid.len());
            }
            assert!(p.initial_source_connection_id.is_some());
            assert!(sender == Sender::Server && p.original_destination_connection_id.is_some() || sender == Sender::Client && p.original_destination_connection_id.is_none());
            if sender == Sender::Client {
                assert!(p.stateless_reset_token.is_none() && p.preferred_address.is_none() && p.retry_source_connection_id.is_none());
            }
            assert!(p.unknown.iter().all(|(id, _)| ![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x20].contains(id)), "a known parameter among the unknown");

            // (a second reading of the ids: none is there twice, which is what the code that read them says it checks)
            let mut seen = std::collections::HashSet::new();
            let mut at = rest;
            while !at.is_empty() {
                let (id, n) = varint(at);
                let (len, m) = varint(&at[n..]);
                assert!(seen.insert(id), "parameter {id} is there twice, and the parameters were read");
                at = &at[n + m + len as usize..];
            }

            // written and read again as itself, and written the same
            let written = p.encode(sender);
            let back = TransportParameters::decode(&written, sender).expect("parameters that we wrote are read");
            assert_eq!(back, p, "parameters that were written are not read again as themselves");
            assert_eq!(back.encode(sender), written, "the writing is not the same the second time");

            // what a client would be told of a server's: the same without what only a server sends
            if sender == Sender::Server {
                let as_client = p.encode(Sender::Client);
                let c = TransportParameters::decode(&as_client, Sender::Client).expect("the client's view of the parameters");
                assert_eq!((c.max_idle_timeout, c.initial_max_data, c.initial_max_streams_bidi), (p.max_idle_timeout, p.initial_max_data, p.initial_max_streams_bidi));
                assert!(c.original_destination_connection_id.is_none() && c.stateless_reset_token.is_none());
            }
        }
    }
    // cut anywhere: not a panic
    for cut in 0..rest.len().min(400) {
        if let Ok(p) = TransportParameters::decode(&rest[..cut], sender) {
            let _ = p.encode(sender);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// quic_buffers

pub fn seeds_buffers() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for sel in 0u8..3 {
        // a script of everything in turn
        let mut v = vec![sel, 0];
        for i in 0..160u32 {
            v.push((i * 7 + 3) as u8);
        }
        seeds.push(v);
        let mut w = vec![sel, 1];
        for i in 0..120u32 {
            w.push((i * 13 + 5) as u8);
            w.push((i * 29) as u8);
        }
        seeds.push(w);
    }
    seeds
}

pub fn buffers(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    match sel % 3 {
        0 => rangeset_against_a_model(rest),
        1 => sendbuf_to_reassembler(rest),
        _ => reassembler_against_a_model(rest),
    }
}

/// The ranges of a set of numbers: the longest runs.
fn runs(model: &BTreeSet<u64>, base: u64) -> Vec<Range<u64>> {
    let mut out: Vec<Range<u64>> = Vec::new();
    for &x in model {
        match out.last_mut() {
            Some(r) if r.end == base + x => r.end += 1,
            _ => out.push(base + x..base + x + 1),
        }
    }
    out
}

fn rangeset_against_a_model(data: &[u8]) {
    const DOMAIN: u64 = 300;
    let mut c = Cursor(data);
    // the numbers are `base + x`: from 0, from the top of what ACK frames use, and from somewhere between
    let base = match c.u8() % 3 {
        0 => 0,
        1 => (1u64 << 62) - DOMAIN - 40,
        _ => c.u64() % ((1u64 << 62) - DOMAIN - 40),
    };
    let mut set = RangeSet::new();
    let mut model: BTreeSet<u64> = BTreeSet::new();
    let range = |a: u64, b: u64| -> Range<u64> { base + a..base + b };
    let in_model = |model: &BTreeSet<u64>, a: u64, b: u64| -> Vec<u64> { (a..b).filter(|x| model.contains(x)).collect() };
    for _ in 0..500 {
        if c.0.is_empty() {
            break;
        }
        let op = c.u8() % 12;
        let (a, b) = (u64::from(c.u16()) % (DOMAIN + 20), u64::from(c.u16()) % (DOMAIN + 20));
        match op {
            0 | 11 => {
                let (a, b) = if op == 0 { (a, b) } else { (a, a + 1 + b % 5) };
                let before = model.len();
                model.extend(a..b);
                assert_eq!(set.insert(range(a, b)), model.len() != before, "insert({a}..{b}) said the wrong thing about growing");
            }
            1 => {
                let new = model.insert(a);
                assert_eq!(set.insert_one(base + a), new);
            }
            2 => {
                for x in a..b {
                    model.remove(&x);
                }
                set.remove(range(a, b));
            }
            3 => {
                model.retain(|&x| x >= a);
                set.remove_below(base + a);
            }
            4 => {
                let max = a % 40;
                let want = if max == 0 { None } else { runs(&model, base).first().map(|r| r.start..r.end.min(r.start + max)) };
                assert_eq!(set.pop_first(max), want, "pop_first({max})");
                if let Some(r) = want {
                    for v in r {
                        model.remove(&(v - base));
                    }
                }
            }
            5 => {
                let n = (a % 6) as usize;
                let all = runs(&model, base);
                for r in all.iter().take(all.len().saturating_sub(n)) {
                    for v in r.clone() {
                        model.remove(&(v - base));
                    }
                }
                set.keep_highest(n);
            }
            6 => assert_eq!(set.contains(base + a), model.contains(&a)),
            7 => assert_eq!(set.covers(range(a, b)), a >= b || (a..b).all(|x| model.contains(&x))),
            8 => assert_eq!(set.intersects(range(a, b)), !in_model(&model, a, b).is_empty()),
            9 => {
                let parts = set.within(range(a, b));
                let sub: BTreeSet<u64> = in_model(&model, a, b).into_iter().collect();
                assert_eq!(parts, runs(&sub, base), "within({a}..{b})");
            }
            _ => {
                model.retain(|&x| x >= DOMAIN + 30);
                set.remove_below(base + DOMAIN + 30);
            }
        }
        let want = runs(&model, base);
        assert_eq!(set.iter().collect::<Vec<_>>(), want, "the ranges after operation {op}");
        assert_eq!(set.iter().rev().collect::<Vec<_>>(), want.iter().rev().cloned().collect::<Vec<_>>());
        assert_eq!(set.count(), model.len() as u64);
        assert_eq!(set.range_count(), want.len());
        assert_eq!(set.is_empty(), model.is_empty());
        assert_eq!(set.min(), model.iter().next().map(|x| base + x));
        assert_eq!(set.max(), model.iter().next_back().map(|x| base + x));
        assert_eq!(set.first(), want.first().cloned());
    }
}

/// The byte at `at` of the stream the send buffer is given.
fn byte(at: u64) -> u8 {
    at.wrapping_mul(131).wrapping_add(17) as u8
}

fn sendbuf_to_reassembler(data: &[u8]) {
    let mut c = Cursor(data);
    let mut sb = SendBuf::new();
    let mut rx = Reassembler::new();
    let mut written = 0u64;
    let mut finished = false;
    let mut fin_at: Option<u64> = None; // where the receiver has seen the end
    let mut total_new = 0u64;
    // chunks out and not yet acknowledged or declared lost, with whether they reached the receiver; and acknowledged ones, for late repeats
    let mut out: Vec<(Chunk, bool)> = Vec::new();
    let mut history: Vec<Chunk> = Vec::new();
    // positions that are acknowledged, as the books of the test say
    let mut acked: BTreeSet<u64> = BTreeSet::new();
    let mut max_len = 1 + c.u8() as usize % 200;
    // whether a chunk that ends the stream has been given out: the end is a position of its own, sent like a byte
    let mut fin_sent = false;

    let deliver = |rx: &mut Reassembler, sb: &SendBuf, ch: &Chunk, fin_at: &mut Option<u64>| {
        let mut bytes = Vec::new();
        sb.copy(ch.offset, ch.len, &mut bytes);
        for (i, b) in bytes.iter().enumerate() {
            assert_eq!(*b, byte(ch.offset + i as u64), "a chunk with other bytes than were written");
        }
        rx.insert(ch.offset, &bytes, 1 << 40).expect("a chunk of the stream is taken");
        if ch.fin {
            let end = ch.offset + ch.len as u64;
            assert!(fin_at.is_none_or(|e| e == end), "two ends");
            *fin_at = Some(end);
        }
    };

    for _ in 0..600 {
        if c.0.is_empty() {
            break;
        }
        let op = c.u8() % 9;
        let x = c.u8();
        match op {
            0 | 1 if !finished => {
                let n = (x as usize) * (1 + (op as usize) * 3);
                let data: Vec<u8> = (written..written + n as u64).map(byte).collect();
                sb.write(&data);
                written += n as u64;
            }
            2 if !finished => {
                sb.finish();
                finished = true;
            }
            3 | 4 | 5 => {
                let limit = match x % 4 {
                    0 => u64::MAX,
                    1 => sb.sent() + u64::from(c.u8()),
                    2 => sb.sent(),
                    _ => written / 2,
                };
                if op == 5 {
                    max_len = 1 + c.u8() as usize % 300;
                }
                let sent_before = sb.sent();
                let had_fin_before = sb.sent() == written && finished && sb.next_offset().is_none();
                let _ = had_fin_before;
                if let Some(ch) = sb.next_chunk(max_len, limit) {
                    assert!(ch.len <= max_len, "a chunk of {} bytes for room of {max_len}", ch.len);
                    assert!(ch.offset + ch.len as u64 <= written, "a chunk past what was written");
                    if ch.fin {
                        assert!(finished && ch.offset + ch.len as u64 == written, "an end that is not the end");
                        fin_sent = true;
                    }
                    if ch.new > 0 {
                        assert_eq!(ch.offset, sent_before, "new data is not where the new data begins");
                        assert_eq!(ch.new, ch.len as u64);
                        assert!(ch.offset + ch.len as u64 <= limit, "new data past the limit {limit}");
                        total_new += ch.new;
                    } else {
                        assert!(ch.offset + ch.len as u64 <= sent_before, "a resend of what was never sent");
                    }
                    let reaches = c.u8() % 5 != 0;
                    if reaches {
                        deliver(&mut rx, &sb, &ch, &mut fin_at);
                    }
                    out.push((ch, reaches));
                }
            }
            6 => {
                // an acknowledgment of a chunk that reached the receiver (the others are never acknowledged), or a late one of one that was
                if !out.is_empty() {
                    let i = x as usize % out.len();
                    if out[i].1 {
                        let (ch, _) = out.remove(i);
                        sb.on_acked(ch.offset, ch.len, ch.fin);
                        acked.extend(ch.offset..ch.offset + ch.len as u64 + u64::from(ch.fin));
                        history.push(ch);
                    }
                } else if !history.is_empty() {
                    let ch = history[x as usize % history.len()];
                    sb.on_acked(ch.offset, ch.len, ch.fin);
                }
            }
            7 => {
                // declared lost, whether it arrived or not
                if !out.is_empty() {
                    let (ch, _) = out.remove(x as usize % out.len());
                    sb.on_lost(ch.offset, ch.len, ch.fin);
                }
            }
            8 => match x % 4 {
                0 => {
                    // the connection starts over: everything out is lost
                    out.clear();
                    sb.mark_all_lost();
                }
                1 => {
                    // a report about a range that was never sent (a frame that is read back wrong would say that): nothing is lost by it, and
                    // nothing that was not sent is ever to be sent again
                    let at = sb.sent() + u64::from(fin_sent) + u64::from(c.u8() % 4);
                    sb.on_lost(at, 1 + c.u8() as usize % 50, c.u8() & 1 == 1);
                }
                _ => {}
            },
            _ => {}
        }
        // the books
        assert_eq!(sb.written(), written);
        assert!(sb.base() <= written && sb.base() <= sb.sent(), "the base {} is past what was sent ({}) or written ({written})", sb.base(), sb.sent());
        assert_eq!(sb.buffered() as u64, written - sb.base());
        assert_eq!(sb.sent(), total_new.min(written), "what was sent for the first time is not what the chunks said");
        for r in sb.lost_ranges() {
            assert!(r.start >= sb.base() && r.start < r.end, "a lost range {r:?} below the base {}", sb.base());
            assert!(r.end <= sb.sent() + u64::from(fin_sent), "a lost range {r:?} past what was sent ({}{})", sb.sent(), if fin_sent { " and the end" } else { "" });
        }
        if sb.is_fully_acked() {
            assert!(finished && (0..written + 1).all(|p| acked.contains(&p) || p < sb.base() || p == written && !finished), "fully acknowledged, but a position is not");
        }
    }

    // everything that is out is settled one way or the other, and what is lost is sent again until all is acknowledged
    for (ch, reached) in std::mem::take(&mut out) {
        if reached && c.u8() & 1 == 0 {
            sb.on_acked(ch.offset, ch.len, ch.fin);
        } else {
            sb.on_lost(ch.offset, ch.len, ch.fin);
        }
    }
    for i in 0..100_000 {
        let Some(ch) = sb.next_chunk(1 + c.u8() as usize % 300, u64::MAX) else { break };
        deliver(&mut rx, &sb, &ch, &mut fin_at);
        // (what is lost is lost for a while: the network is not bad for ever, and the input has run out)
        if i < 60 && c.u8() % 4 == 0 {
            sb.on_lost(ch.offset, ch.len, ch.fin);
        } else {
            sb.on_acked(ch.offset, ch.len, ch.fin);
        }
    }
    assert!(!sb.has_pending(), "something is still to send after everything was sent: lost {:?} sent {} written {written} base {} finished {finished} next_offset {:?} fully_acked {}", sb.lost_ranges(), sb.sent(), sb.base(), sb.next_offset(), sb.is_fully_acked());
    assert_eq!(sb.sent(), written);
    assert_eq!(rx.readable() as u64, written, "the receiver does not have all that was written");
    let got = rx.take();
    assert!(got.iter().enumerate().all(|(i, b)| *b == byte(i as u64)));
    if finished {
        assert_eq!(fin_at, Some(written), "the receiver was not told of the end");
        assert!(sb.is_fully_acked(), "everything arrived and is acknowledged, but the buffer says it is not");
    } else {
        assert_eq!(sb.base(), written, "all of it is acknowledged, but the buffer still holds some");
    }
}

fn reassembler_against_a_model(data: &[u8]) {
    const DOMAIN: u64 = 600;
    let mut c = Cursor(data);
    let mut r = Reassembler::new();
    // the bytes held (by offset), and where the reading is
    let mut held: BTreeMap<u64, u8> = BTreeMap::new();
    let mut read = 0u64;
    for _ in 0..500 {
        if c.0.is_empty() {
            break;
        }
        let op = c.u8() % 7;
        let x = c.u16();
        match op {
            0..=3 => {
                let offset = u64::from(x) % (DOMAIN + 40);
                let len = c.u8() as usize % 41;
                let window = [30u64, 100, 300, 1 << 40][c.u8() as usize % 4];
                let wrong = c.u8() % 5 == 0;
                let bytes: Vec<u8> = (0..len as u64).map(|i| (offset + i).wrapping_mul(7).wrapping_add(3) as u8 ^ if wrong && i == len as u64 / 2 { 0xff } else { 0 }).collect();
                let end = offset + len as u64;
                let before = (r.read_offset(), r.buffered(), r.end_offset(), r.readable());
                let result = r.insert(offset, &bytes, window);
                if end > read.saturating_add(window) {
                    assert_eq!(result, Err(reassembly::Error::Exceeded));
                } else if end <= read {
                    assert_eq!(result, Ok(()));
                } else {
                    let start = offset.max(read);
                    let clash = (start..end).any(|p| held.get(&p).is_some_and(|b| *b != bytes[(p - offset) as usize]));
                    if clash {
                        assert_eq!(result, Err(reassembly::Error::Inconsistent), "bytes that differ from the held were taken");
                    } else {
                        assert_eq!(result, Ok(()));
                        for p in start..end {
                            held.insert(p, bytes[(p - offset) as usize]);
                        }
                    }
                }
                if result.is_err() {
                    assert_eq!(before, (r.read_offset(), r.buffered(), r.end_offset(), r.readable()), "a refusal changed the buffer");
                }
            }
            4 => {
                let mut buf = vec![0u8; x as usize % 200];
                let n = r.read(&mut buf);
                let readable: Vec<u8> = (read..).map_while(|p| held.get(&p).copied()).take(buf.len()).collect();
                assert_eq!(&buf[..n], &readable[..], "what was read is not what the model has");
                assert_eq!(n, readable.len());
                for p in read..read + n as u64 {
                    held.remove(&p);
                }
                read += n as u64;
            }
            _ => {
                let all: Vec<u8> = (read..).map_while(|p| held.get(&p).copied()).collect();
                if op == 5 {
                    assert_eq!(r.take(), all);
                } else {
                    assert_eq!(r.discard(), all.len());
                }
                for p in read..read + all.len() as u64 {
                    held.remove(&p);
                }
                read += all.len() as u64;
            }
        }
        assert_eq!(r.read_offset(), read);
        assert_eq!(r.buffered(), held.len());
        assert_eq!(r.end_offset(), held.keys().next_back().map_or(read, |p| p + 1).max(read));
        assert_eq!(r.readable(), (read..).take_while(|p| held.contains_key(p)).count());
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// quic_streams

pub fn seeds_streams() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // the honest pair: settings, then a script that opens, writes, reads
    for (head, loss) in [(0x00u8, 0u8), (0x05, 20), (0x0a, 40)] {
        let mut v = vec![head, 0, loss, 9, 1, 2, 3, 4];
        for i in 0..200u32 {
            v.push((i * 37 + 11) as u8);
        }
        seeds.push(v);
    }
    // the hostile peer: a STREAM frame, a RESET_STREAM, a MAX_STREAM_DATA, a STOP_SENDING, a MAX_DATA
    for frame in [hex("0b 04 03 61 62 63"), hex("04 00 01 05"), hex("11 00 40 80"), hex("05 00 01"), hex("10 44 00"), hex("17 00"), hex("13 02")] {
        let mut v = vec![1u8, 0, 0, 1, 0, frame.len() as u8];
        v.extend_from_slice(&frame);
        v.extend_from_slice(&[0, 20, 3, 100, 1, 60, 3, 1]);
        seeds.push(v);
    }
    seeds
}

pub fn streams(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    if sel & 1 == 0 {
        StreamsPair::run(sel, rest);
    } else {
        hostile_peer(sel, rest);
    }
}

fn streams_config(client: bool, kind: u8) -> StreamsConfig {
    match kind % 3 {
        0 => StreamsConfig { client, max_data: 20_000, bidi_local: 6_000, bidi_remote: 6_000, uni: 6_000, max_streams_bidi: 8, max_streams_uni: 8, send_buffer: 8_000 },
        1 => StreamsConfig { client, max_data: 3000, bidi_local: 1500, bidi_remote: 1500, uni: 1500, max_streams_bidi: 3, max_streams_uni: 3, send_buffer: 2500 },
        _ => StreamsConfig { client, max_data: 9000, bidi_local: 4000, bidi_remote: 2500, uni: 3000, max_streams_bidi: 5, max_streams_uni: 2, send_buffer: 5000 },
    }
}

fn params_of(c: &StreamsConfig) -> TransportParameters {
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

fn is_client_initiated(id: u64) -> bool {
    id & 1 == 0
}

fn is_bidirectional(id: u64) -> bool {
    id & 2 == 0
}

/// A packet's frames, from a side that has some to write; what the packet is, and the bytes.
fn packet(from: &mut Streams, budget: usize) -> (Vec<u8>, Vec<SentFrame>) {
    let mut out = Vec::new();
    let mut sent = Vec::new();
    from.write_frames(&mut out, budget, &mut sent);
    assert!(out.len() <= budget, "{} bytes in a budget of {budget}", out.len());
    let mut n = 0;
    // (nothing at all reads as one error: a packet has a frame)
    for f in frame::frames(&out, PacketType::OneRtt).filter(|_| !out.is_empty()) {
        let f = f.expect("what the streams write is frames that read");
        assert!(frame::allowed_in(f.frame_type(), PacketType::OneRtt));
        n += 1;
    }
    assert!(out.is_empty() == sent.is_empty() && (out.is_empty() || n >= 1), "frames and what is said of them do not agree");
    (out, sent)
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

enum Ev {
    /// A packet arrives (at the server if `to_server`); then it is acknowledged later.
    Deliver { to_server: bool, bytes: Vec<u8>, sent: Vec<SentFrame> },
    Ack { to_server: bool, sent: Vec<SentFrame> },
    Lost { to_server: bool, sent: Vec<SentFrame> },
}

#[derive(Default)]
struct Book {
    written: BTreeMap<(bool, u64), Vec<u8>>,
    read: BTreeMap<(bool, u64), Vec<u8>>,
    ended: BTreeSet<(bool, u64)>,
    broken: BTreeSet<(bool, u64)>,
    fin_written: BTreeSet<(bool, u64)>,
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
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// Two endpoints of streams, a network between them, and an application that does what the input says.
struct StreamsPair<'a> {
    side: [Streams; 2],
    rng: Rng,
    now: u64,
    seq: u64,
    events: Vec<(u64, u64, Ev)>,
    book: Book,
    known: [BTreeSet<u64>; 2],
    loss: u64,
    script: Cursor<'a>,
}

impl<'a> StreamsPair<'a> {
    fn run(sel: u8, data: &'a [u8]) {
        let mut c = Cursor(data);
        let (kc, ks) = (c.u8() % 3, (c.u8() >> 2) % 3);
        let _ = sel;
        let loss = u64::from(c.u8() % 50);
        let seed = u64::from(c.u16()) << 16 | u64::from(c.u16()) | 1 << 40;
        let (cc, sc) = (streams_config(true, (sel >> 1) % 3 + kc), streams_config(false, (sel >> 3) % 3 + ks));
        let (mut cl, mut sv) = (Streams::new(cc), Streams::new(sc));
        cl.set_peer_params(&params_of(&sc));
        sv.set_peer_params(&params_of(&cc));
        let mut p = StreamsPair { side: [cl, sv], rng: Rng(seed), now: 0, seq: 0, events: Vec::new(), book: Book::default(), known: [BTreeSet::new(), BTreeSet::new()], loss, script: c };
        for _ in 0..800 {
            if p.script.0.is_empty() {
                break;
            }
            p.tick(true);
            for (w, s) in p.side.iter().enumerate() {
                if let Err(e) = s.check() {
                    panic!("side {w}: {e}");
                }
            }
        }
        p.finish();
        p.check_books();
    }

    fn push(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.events.push((at, self.seq, ev));
    }

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
                    let to = usize::from(to_server);
                    for f in frame::frames(&bytes, PacketType::OneRtt) {
                        if let Err(e) = self.side[to].on_frame(&f.expect("a frame that reads")) {
                            panic!("an honest peer was found at fault: {e}");
                        }
                    }
                    let back = at + 1 + self.rng.below(12);
                    self.push(back, Ev::Ack { to_server: !to_server, sent });
                }
                Ev::Ack { to_server, sent } => acked(&mut self.side[usize::from(to_server)], &sent),
                Ev::Lost { to_server, sent } => lost(&mut self.side[usize::from(!to_server)], &sent),
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

    fn app_read(&mut self, who: usize, id: u64, max: usize) {
        let key = (who == 1, id);
        let mut buf = vec![0u8; max.max(1)];
        for _ in 0..10_000 {
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

    fn app_write(&mut self, who: usize, id: u64, len: usize, fin: bool) {
        let key = (who == 0, id);
        let at = self.book.written.entry(key).or_default().len();
        let chunk: Vec<u8> = (0..len).map(|i| ((at + i) as u8).wrapping_mul(7).wrapping_add(id as u8)).collect();
        match self.side[who].write(id, &chunk, fin) {
            Ok(n) => {
                assert!(n <= len);
                self.book.written.get_mut(&key).unwrap().extend_from_slice(&chunk[..n]);
                if fin && n == len {
                    self.book.fin_written.insert(key);
                }
            }
            Err(StreamError::Reset(_)) => panic!("a write says the stream was reset by the peer"),
            Err(_) => {}
        }
    }

    /// One step of time, and what the input says the applications do in it.
    fn tick(&mut self, active: bool) {
        self.now += 1;
        if active {
            for who in 0..2 {
                let op = self.script.u8();
                let arg = self.script.u8();
                let known: Vec<u64> = self.known[who].iter().copied().collect();
                let id = if known.is_empty() { None } else { Some(known[arg as usize % known.len()]) };
                let ours = |id: u64| is_client_initiated(id) == (who == 0);
                match (op % 10, id) {
                    (0, _) => {
                        if let Ok(id) = self.side[who].open(arg & 1 == 0) {
                            self.known[who].insert(id);
                        }
                    }
                    (1 | 2 | 3, Some(id)) if ours(id) || is_bidirectional(id) => {
                        let fin_ok = !self.book.fin_written.contains(&(who == 0, id));
                        let len = 1 + (usize::from(op >> 4) * 256 + usize::from(arg)) % 2500;
                        self.app_write(who, id, len, fin_ok && arg % 8 == 0);
                    }
                    (4 | 5 | 6, Some(id)) if !ours(id) || is_bidirectional(id) => {
                        if self.side[who].contains(id) {
                            self.app_read(who, id, 1 + usize::from(arg) * 4);
                        }
                    }
                    (7, Some(id)) if (ours(id) || is_bidirectional(id)) && arg % 8 == 0 => {
                        let _ = self.side[who].reset(id, 1000 + id);
                        self.book.broken.insert((who == 0, id));
                    }
                    (8, Some(id)) if (!ours(id) || is_bidirectional(id)) && arg % 8 == 0 => {
                        let _ = self.side[who].stop_sending(id, 2000 + id);
                        self.book.broken.insert((who != 0, id));
                    }
                    _ => {}
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
        for step in 0..30_000 {
            self.tick(false);
            if step % 7 == 0 {
                for who in 0..2 {
                    let ids: Vec<u64> = self.side[who].stream_ids();
                    for id in ids {
                        let ours = is_client_initiated(id) == (who == 0);
                        if (ours || is_bidirectional(id)) && !self.book.fin_written.contains(&(who == 0, id)) {
                            let _ = self.side[who].write(id, &[], true);
                            self.book.fin_written.insert((who == 0, id));
                        }
                        if self.side[who].contains(id) {
                            self.app_read(who, id, 1500);
                        }
                    }
                }
            }
            if self.events.is_empty() && !self.side[0].has_pending() && !self.side[1].has_pending() && self.side[0].stream_ids().is_empty() && self.side[1].stream_ids().is_empty() {
                return;
            }
        }
        panic!("it does not end: {} events, pending {} {}; streams left {:?} {:?}", self.events.len(), self.side[0].has_pending(), self.side[1].has_pending(), self.side[0].stream_ids(), self.side[1].stream_ids());
    }

    fn check_books(&self) {
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

/// One endpoint of streams that is given what a hostile peer might send, and the calls of an application.
fn hostile_peer(sel: u8, data: &[u8]) {
    let mut c = Cursor(data);
    let client = sel & 2 != 0;
    let mut s = Streams::new(streams_config(client, (sel >> 2) % 3 + c.u8() % 3));
    // (the limits that the peer set, from its transport parameters: not always the same as ours)
    let peer = streams_config(!client, c.u8() % 3);
    if sel & 0x40 == 0 {
        s.set_peer_params(&params_of(&peer));
    }
    let mut out: Vec<Vec<SentFrame>> = Vec::new();
    let mut ids: Vec<u64> = Vec::new();
    for _ in 0..400 {
        if c.0.is_empty() {
            break;
        }
        let op = c.u8() % 10;
        let x = c.u8();
        match op {
            0 | 1 => {
                // frames that the input makes
                let len = (x as usize % 100).min(c.0.len());
                let (bytes, rest) = c.0.split_at(len);
                c.0 = rest;
                for f in frame::frames(bytes, PacketType::OneRtt) {
                    let Ok(f) = f else { break };
                    if let Frame::Stream { id, .. } | Frame::ResetStream { id, .. } | Frame::StopSending { id, .. } | Frame::MaxStreamData { id, .. } | Frame::StreamDataBlocked { id, .. } = &f {
                        ids.push(*id);
                    }
                    if let Err(e) = s.on_frame(&f) {
                        assert!([0x03, 0x04, 0x05, 0x06, 0x07, 0x0a].contains(&e.code), "an error of code {:#x} ({})", e.code, e.reason);
                        break;
                    }
                }
            }
            2 => {
                if let Ok(id) = s.open(x & 1 == 0) {
                    ids.push(id);
                }
            }
            3 | 4 => {
                if !ids.is_empty() {
                    let id = ids[x as usize % ids.len()];
                    let n = usize::from(c.u8()) * 20;
                    let data = vec![x; n];
                    if let Ok(k) = s.write(id, &data, x % 7 == 0) {
                        assert!(k <= n);
                    }
                }
            }
            5 => {
                if !ids.is_empty() {
                    let id = ids[x as usize % ids.len()];
                    let mut buf = vec![0u8; usize::from(c.u8()) * 8];
                    if let Ok((k, _)) = s.read(id, &mut buf) {
                        assert!(k <= buf.len());
                    }
                }
            }
            6 => {
                if !ids.is_empty() {
                    let id = ids[x as usize % ids.len()];
                    let _ = if x & 1 == 0 { s.reset(id, u64::from(x)) } else { s.stop_sending(id, u64::from(x)) };
                }
            }
            7 | 8 => {
                let budget = [30, 100, 300, 1200][(x & 3) as usize];
                let (_, sent) = packet(&mut s, budget);
                out.push(sent);
            }
            _ => {
                if !out.is_empty() {
                    let sent = out.remove(x as usize % out.len());
                    if x & 0x80 == 0 {
                        acked(&mut s, &sent);
                    } else {
                        lost(&mut s, &sent);
                    }
                }
            }
        }
        while let Some(e) = s.poll_event() {
            if let StreamEvent::Readable(id) | StreamEvent::Writable(id) | StreamEvent::Stopped(id, _) = e {
                ids.push(id);
            }
        }
        if let Err(e) = s.check() {
            panic!("the books after operation {op}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// quic_recovery

pub fn seeds_recovery() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for k in 0u32..4 {
        let mut v = vec![k as u8];
        for i in 0..300u32 {
            v.push((i.wrapping_mul(53).wrapping_add(k * 19)) as u8);
        }
        seeds.push(v);
    }
    seeds
}

/// What the model knows of one packet that is out.
#[derive(Clone, Copy)]
struct Out {
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
    time: Instant,
}

pub fn recovery(data: &[u8]) {
    let mut c = Cursor(data);
    let mds = [1200usize, 1252, 1472][c.u8() as usize % 3];
    let mut rec: Recovery<u64> = Recovery::new(mds);
    let start = Instant::now();
    let mut now = start;
    let mut next_pn = [0u64; 3];
    let mut out: [BTreeMap<u64, Out>; 3] = [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()];
    let mut discarded = [false; 3];
    let mut confirmed = false;
    let mut handshake_keys = false;

    for _ in 0..500 {
        if c.0.is_empty() {
            break;
        }
        let op = c.u8() % 12;
        let (a, b) = (c.u8(), c.u8());
        match op {
            0..=3 => {
                // a packet is sent
                let si = (a % 3) as usize;
                if !discarded[si] {
                    let space = Space::ALL[si];
                    let ack_eliciting = b & 1 == 0;
                    let in_flight = ack_eliciting || b & 2 != 0;
                    let size = 40 + (usize::from(b) * 5 + usize::from(a)) % 1400;
                    let pn = next_pn[si];
                    next_pn[si] += 1;
                    rec.on_packet_sent(now, space, Sent { pn, time: now, size, ack_eliciting, in_flight, payload: (si as u64) << 56 | pn });
                    out[si].insert(pn, Out { size, ack_eliciting, in_flight, time: now });
                }
            }
            4 | 5 | 6 => {
                // an acknowledgment of up to three ranges (some of packets that were never sent)
                let si = (a % 3) as usize;
                if discarded[si] || next_pn[si] == 0 {
                    continue;
                }
                let space = Space::ALL[si];
                let mut set = RangeSet::new();
                for _ in 0..1 + b % 3 {
                    // (never one that was not sent: the connection closes for that before recovery is told)
                    let end = u64::from(c.u8()) % next_pn[si];
                    let len = 1 + u64::from(c.u8()) % 8;
                    set.insert(end.saturating_sub(len - 1)..end + 1);
                }
                let largest = set.max().expect("a range");
                let delay = Duration::from_micros(u64::from(c.u8()) * 400);
                now += Duration::from_micros(u64::from(c.u16()) * 4);
                let want: Vec<u64> = out[si].keys().copied().filter(|pn| set.contains(*pn)).collect();
                let outcome = rec.on_ack_received(now, space, largest, delay, set.iter().rev().map(|r| r.start..=r.end - 1));
                let got: Vec<u64> = outcome.acked.iter().map(|p| p.pn).collect();
                assert_eq!(got, want, "an acknowledgment of {set:?} acknowledged other packets than those sent in the ranges");
                for p in &outcome.acked {
                    assert_eq!(p.payload, (si as u64) << 56 | p.pn);
                    out[si].remove(&p.pn);
                }
                let largest_acked = rec.largest_acked(space).expect("something was acknowledged");
                for p in &outcome.lost {
                    assert!(p.pn <= largest_acked && !set.contains(p.pn), "lost packet {} (largest acknowledged {largest_acked})", p.pn);
                    assert_eq!(p.payload, (si as u64) << 56 | p.pn);
                    assert!(out[si].remove(&p.pn).is_some(), "a packet lost that was not out");
                }
                if !outcome.acked.is_empty() {
                    no_loss_left(&rec, space, &out[si], now, largest_acked);
                }
            }
            7 => {
                // the timer
                if let Some(t) = rec.timer() {
                    now = now.max(t);
                    let timeout = rec.on_timeout(now);
                    let si = timeout.lost_space.index();
                    for p in &timeout.lost {
                        assert!(out[si].remove(&p.pn).is_some(), "a packet lost that was not out");
                    }
                    match timeout.probe {
                        None => {
                            if let Some(largest) = rec.largest_acked(timeout.lost_space) {
                                no_loss_left(&rec, timeout.lost_space, &out[si], now, largest);
                            }
                        }
                        Some(p) => {
                            assert!(timeout.lost.is_empty());
                            assert_eq!(p.space, timeout.lost_space);
                            if p.anti_deadlock {
                                assert!(out.iter().all(|o| o.values().all(|x| !(x.in_flight && x.ack_eliciting))), "an anti-deadlock probe with packets in flight");
                            }
                        }
                    }
                }
            }
            8 => {
                // the clock moves
                now += Duration::from_micros(u64::from(a) * u64::from(b) * 3 + if a == 0 { 3_000_000 } else { 0 });
            }
            9 => {
                // keys are given up
                let si = (a % 3) as usize;
                if si < 2 && !discarded[si] {
                    discarded[si] = true;
                    let gone = rec.discard_space(now, Space::ALL[si]);
                    let want: Vec<u64> = out[si].keys().copied().collect();
                    assert_eq!(gone.iter().map(|p| p.pn).collect::<Vec<_>>(), want);
                    out[si].clear();
                    if si == 1 {
                        handshake_keys = false;
                    }
                }
            }
            10 => match a % 5 {
                0 => {
                    if !discarded[1] {
                        handshake_keys = true;
                        rec.set_handshake_keys(true);
                    }
                }
                1 => {
                    confirmed = true;
                    rec.on_handshake_confirmed(now);
                }
                2 => rec.set_max_ack_delay(Duration::from_millis(u64::from(b) % 64)),
                3 => rec.set_max_datagram_size(1200 + usize::from(b) * 20),
                _ => {
                    let gone = rec.reset(if b & 1 == 0 { Some(Duration::from_millis(u64::from(b))) } else { None });
                    let n: usize = out.iter().map(|o| o.len()).sum();
                    assert_eq!(gone.len(), n, "a reset gave back {} packets of {n}", gone.len());
                    for o in &mut out {
                        o.clear();
                    }
                }
            },
            _ => {
                if let Some(t) = rec.next_send_time(now) {
                    assert!(t > now, "the pacer says to wait until a time that is not after now");
                }
            }
        }
        let _ = handshake_keys;

        // the books
        let flight: usize = out.iter().flat_map(|o| o.values()).filter(|p| p.in_flight).map(|p| p.size).sum();
        assert_eq!(rec.bytes_in_flight(), flight, "bytes in flight");
        for si in 0..3 {
            let space = Space::ALL[si];
            let eliciting = out[si].values().filter(|p| p.in_flight && p.ack_eliciting).count();
            assert_eq!(rec.ack_eliciting_in_flight(space), eliciting, "ack-eliciting packets in flight in {space:?}");
            let listed: Vec<u64> = rec.outstanding(space).map(|p| p.pn).collect();
            assert_eq!(listed, out[si].keys().copied().collect::<Vec<_>>(), "the packets outstanding in {space:?}");
        }
        let cc = rec.congestion();
        assert!(cc.window() >= 2 * cc.max_datagram_size(), "a window of {} under the minimum", cc.window());
        assert_eq!(cc.bytes_in_flight(), rec.bytes_in_flight());
        // a timer is set when something that a probe or a loss time is for is out
        let early = [0usize, 1].iter().any(|&si| out[si].values().any(|p| p.in_flight && p.ack_eliciting));
        let late = out[2].values().any(|p| p.in_flight && p.ack_eliciting);
        if early || (late && confirmed) {
            assert!(rec.timer().is_some(), "ack-eliciting packets are in flight and there is no timer");
        }
        // (a round trip is a time that passed: no longer than the run so far, or what a first estimate says before a sample)
        let elapsed = now - start;
        assert!(rec.latest_rtt() <= elapsed, "a latest round trip of {:?} in {elapsed:?}", rec.latest_rtt());
        assert!(rec.smoothed_rtt() <= elapsed.max(pratique::quic::recovery::INITIAL_RTT), "a smoothed round trip of {:?} in {elapsed:?}", rec.smoothed_rtt());
    }
}

/// No packet that was sent before the largest that is acknowledged, and is lost by the packet threshold or by the time threshold, is
/// left outstanding: they were declared lost.
fn no_loss_left(rec: &Recovery<u64>, space: Space, out: &BTreeMap<u64, Out>, now: Instant, largest: u64) {
    let loss_delay = (rec.latest_rtt().max(rec.smoothed_rtt()) * 9 / 8).max(Duration::from_millis(1));
    for (&pn, p) in out.range(..=largest) {
        assert!(pn + PACKET_THRESHOLD > largest, "packet {pn} is {} behind the largest acknowledged ({largest}) in {space:?} and is not lost", largest - pn);
        assert!(now.saturating_duration_since(p.time) < loss_delay, "packet {pn} was sent {:?} ago (the loss delay is {loss_delay:?}) before one that was acknowledged and is not lost", now.saturating_duration_since(p.time));
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// quic_connection

pub fn seeds_connection() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // honest: a clean network, a lossy one, with a Retry, with small windows; hostile: with frames
    for (b0, b1, b2, b3) in [(0x00u8, 0u8, 0u8, 0u8), (0x44, 0x15, 0x21, 0x30), (0x82, 0x2a, 0x13, 0x02), (0xc8, 0x3f, 0x05, 0x4c), (0x01, 0x05, 0x08, 0x00), (0x41, 0x2a, 0x00, 0x11)] {
        let mut v = vec![b0, b1, b2, b3, 1, 2, 3, 4];
        for i in 0..260u32 {
            v.push((i.wrapping_mul(61).wrapping_add(u32::from(b0))) as u8);
        }
        seeds.push(v);
    }
    // hostile: scripts that open a stream, write, and make the server send STREAM, RESET_STREAM, MAX_DATA and so on
    for frames in [hex("0b 04 03 61 62 63"), hex("04 01 01 05"), hex("12 00"), hex("1c 0a 06 00"), hex("18 02 01 08"), hex("19 01"), hex("1a 01 02 03 04 05 06 07 08")] {
        let mut v = vec![0x01u8, 0, 0, 0, 1, 2, 3, 4];
        v.extend_from_slice(&[3, 0, 0, 0, 12, 0, 0, frames.len() as u8]);
        v.extend_from_slice(&frames);
        v.extend_from_slice(&[0, 0, 0, 40, 4, 0, 0, 50, 0, 0, 0, 40]);
        seeds.push(v);
    }
    seeds
}

pub fn connection(data: &[u8]) {
    pratique::quic::fuzz_hooks::connection(data)
}

pub const CONNECTION_DICT: &[&[u8]] = &[
    // the ops that matter: open a bidirectional stream, write, read, a key update, a ping
    b"\x03\x00",
    b"\x04\x00\x00\x10",
    b"\x06\x00\x00\x10",
    b"\x0e\x00\x00\x00",
    b"\x0d\x00\x00\x00",
    b"\x0f\x00\x00\x00",
    // frames for the server to send: STREAM with a length and fin, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
    // DATA_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, CONNECTION_CLOSE
    b"\x0b\x01\x02ab",
    b"\x04\x01\x01\x01",
    b"\x05\x01\x01",
    b"\x10\x44\x00",
    b"\x11\x01\x44\x00",
    b"\x12\x40\x64",
    b"\x14\x01",
    b"\x18\x02\x00\x08",
    b"\x19\x00",
    b"\x1a\x01\x02\x03\x04\x05\x06\x07\x08",
    b"\x1c\x0a\x06\x00",
];
