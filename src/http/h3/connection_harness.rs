//! A transport that is in memory, and a whole exchange between an HTTP/3 client connection and a server that is made up of what a script
//! (the bytes of a fuzzer's input, or a pseudo-random generator in the tests) chooses: requests, responses (well made, with a QPACK table
//! that is filled and acknowledged as it should be, or made of bytes that mean nothing), delays in what the server's encoder says, slow
//! writes, resets, GOAWAY, streams of unknown types, an application that reads when it likes.
//!
//! What it sets out to prove, whatever the script says:
//!
//! * the connection's books add up after every step (nothing held without bound, the streams that wait for the table are the ones the
//!   decoder counts), and it never panics;
//! * a connection that fails has closed the transport with a code of RFC 9114 or RFC 9204, and every stream that was not complete fails;
//! * what the application sees of a stream is in order (head, body, trailers, end; or a failure, and then nothing else);
//! * as long as the server says nothing that is not well made, the connection is not lost, and a response that was well made and was
//!   read to its end is what the server sent (the status, the fields, the body, the trailers), whatever the pieces it came in and
//!   whatever order its parts reached the client (the table's entries after the section that uses them, say);
//! * what the client wrote is what a decoder makes of it: every request's field section decodes, with the client's encoder stream, to the
//!   fields of the request, and the body that was taken is the body that was written, as DATA frames.

use super::*;
use crate::http::h3::qpack::harness::Choose;
use crate::http::h2::hpack::FieldRef;
use std::collections::HashMap;

// ------------------------------------------------------------------------------------------------ the transport

/// What we wrote on a stream.
#[derive(Default, Debug)]
pub(crate) struct Sent {
    pub(crate) data: Vec<u8>,
    pub(crate) fin: bool,
    pub(crate) reset: Option<u64>,
}

/// What the server has sent on a stream, to be read.
#[derive(Default)]
pub(crate) struct Recv {
    pub(crate) data: VecDeque<u8>,
    pub(crate) fin: bool,
    pub(crate) reset: Option<u64>,
    /// The end has been read: a stream that is over is gone (the real transport may say so or may say "the end" again; a connection that
    /// counts on the second is wrong, so this one says it is gone).
    pub(crate) fin_read: bool,
}

/// The streams of a connection, in memory: the server's side is whatever the script puts in with `push`.
pub(crate) struct Fake {
    pub(crate) opened: [u64; 2],
    pub(crate) max_open: [u64; 2],
    pub(crate) sent: HashMap<u64, Sent>,
    pub(crate) recv: HashMap<u64, Recv>,
    pub(crate) events: VecDeque<TransportEvent>,
    pub(crate) stopped_by_us: HashMap<u64, u64>,
    pub(crate) closed: Option<(u64, String)>,
    /// How much a write takes at most.
    pub(crate) room: usize,
    /// What was written, in order: the stream, where in it, and how much.
    pub(crate) log: Vec<(u64, usize, usize)>,
}

impl Fake {
    pub(crate) fn new() -> Fake {
        Fake { opened: [0, 0], max_open: [100, 100], sent: HashMap::new(), recv: HashMap::new(), events: VecDeque::new(), stopped_by_us: HashMap::new(), closed: None, room: usize::MAX, log: Vec::new() }
    }

    /// The server sends bytes (and perhaps ends the stream) on stream `id`.
    pub(crate) fn push(&mut self, id: u64, bytes: &[u8], fin: bool) {
        let r = self.recv.entry(id).or_default();
        r.data.extend(bytes);
        r.fin |= fin;
        self.events.push_back(TransportEvent::Readable(id));
    }

    pub(crate) fn reset_by_server(&mut self, id: u64, code: u64) {
        self.recv.entry(id).or_default().reset = Some(code);
        self.events.push_back(TransportEvent::Readable(id));
    }

    pub(crate) fn written(&self, id: u64) -> &[u8] {
        self.sent.get(&id).map_or(&[], |s| &s.data)
    }

    pub(crate) fn closed_with(&self) -> Option<u64> {
        self.closed.as_ref().map(|c| c.0)
    }
}

impl Transport for Fake {
    fn open_stream(&mut self, bidirectional: bool) -> Result<u64, TransportError> {
        let k = usize::from(!bidirectional);
        if self.opened[k] >= self.max_open[k] {
            return Err(TransportError::Blocked);
        }
        let id = self.opened[k] * 4 + if bidirectional { 0 } else { 2 };
        self.opened[k] += 1;
        self.sent.insert(id, Sent::default());
        Ok(id)
    }

    fn write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, TransportError> {
        let room = self.room;
        let s = self.sent.get_mut(&id).ok_or(TransportError::Unknown)?;
        let n = data.len().min(room);
        if n == 0 && !data.is_empty() {
            return Err(TransportError::Blocked);
        }
        if n > 0 {
            self.log.push((id, s.data.len(), n));
        }
        s.data.extend_from_slice(&data[..n]);
        if n == data.len() && fin {
            s.fin = true;
        }
        Ok(n)
    }

    fn read(&mut self, id: u64, buf: &mut [u8]) -> Result<(usize, bool), TransportError> {
        let r = self.recv.get_mut(&id).ok_or(TransportError::Unknown)?;
        if let Some(c) = r.reset {
            return Err(TransportError::Reset(c));
        }
        if r.fin_read {
            return Err(TransportError::Unknown);
        }
        if r.data.is_empty() {
            return if r.fin {
                r.fin_read = true;
                Ok((0, true))
            } else {
                Err(TransportError::Blocked)
            };
        }
        let n = r.data.len().min(buf.len());
        for (i, b) in r.data.drain(..n).enumerate() {
            buf[i] = b;
        }
        let fin = r.data.is_empty() && r.fin;
        r.fin_read |= fin;
        Ok((n, fin))
    }

    fn reset(&mut self, id: u64, error: u64) -> Result<(), TransportError> {
        self.sent.get_mut(&id).ok_or(TransportError::Unknown)?.reset = Some(error);
        Ok(())
    }

    fn stop_sending(&mut self, id: u64, error: u64) -> Result<(), TransportError> {
        self.stopped_by_us.insert(id, error);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.events.pop_front()
    }

    fn close(&mut self, error: u64, reason: &[u8]) {
        if self.closed.is_none() {
            self.closed = Some((error, String::from_utf8_lossy(reason).into_owned()));
        }
    }
}

// ------------------------------------------------------------------------------------------------ the exchange

pub(crate) const SERVER_CONTROL: u64 = 3;
pub(crate) const SERVER_QPACK_ENCODER: u64 = 7;
pub(crate) const SERVER_QPACK_DECODER: u64 = 11;

/// A response that was made well, as the script made it.
#[derive(Clone, Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Option<Vec<(String, String)>>,
}

/// What the application has seen of a stream.
#[derive(Default, Debug)]
struct Seen {
    head: Option<(u16, Fields)>,
    body: Vec<u8>,
    trailers: Option<Fields>,
    ended: bool,
    failed: Option<StreamError>,
}

/// A request that was sent.
struct Sentry {
    /// The fields it must have been written with (pseudo-headers first).
    fields: Vec<(String, String)>,
    /// What the application sent as body, as far as it was taken.
    body: Vec<u8>,
    /// The application said it was the end, and all of the body was taken.
    ended_by_us: bool,
    seen: Seen,
    /// Nothing but whole responses of the script's making was sent on it.
    pristine: bool,
    response: Option<Response>,
    /// The script reset it, or released it.
    cut: bool,
}

const RESPONSE_NAMES: &[&str] = &["server", "content-type", "cache-control", "x-a", "x-b", "x-trace", "set-cookie", "etag", "x-long-name-for-the-table"];

fn value<C: Choose>(c: &mut C) -> String {
    match c.below(6) {
        0 => String::new(),
        1 => "text/html".into(),
        2 => format!("v{}", c.below(4)),
        3 => format!("{}{}", "z".repeat(c.below(150)), c.below(3)),
        4 => "no-store".into(),
        _ => format!("agent/{}", c.below(30)),
    }
}

/// Up to `max` bytes that run on from one the script chooses (a body that is all of its own makes no sense to spend a script's bytes on).
fn pattern<C: Choose>(c: &mut C, max: usize) -> Vec<u8> {
    let n = c.below(max + 1);
    let start = c.byte();
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

fn pairs<C: Choose>(c: &mut C, max: usize) -> Vec<(String, String)> {
    (0..c.below(max + 1)).map(|_| (RESPONSE_NAMES[c.below(RESPONSE_NAMES.len())].to_string(), value(c))).collect()
}

fn valid_code(c: u64) -> bool {
    (0x100..=0x110).contains(&c) || (0x200..=0x202).contains(&c)
}

/// What a run came to (for the tests, to see that the scripts reach what they are meant to).
#[derive(Default, Debug)]
pub(crate) struct Stats {
    /// Responses that were well made and that the application read to their end.
    pub(crate) responses: usize,
    /// Times a stream was waiting for the table.
    pub(crate) waited: usize,
    /// Times the connection was lost by our finding.
    pub(crate) lost: usize,
    /// Streams that failed.
    pub(crate) failed: usize,
    /// Entries that the client's encoder made in the table of the server.
    pub(crate) inserted: usize,
}

/// One run: the connection and the server it talks to, as the script makes them. With `garbage` the script may also send bytes that
/// mean nothing; without, the server says only what is well made, and the connection must not be lost.
pub(crate) fn exchange<C: Choose>(c: &mut C, max_steps: usize, garbage: bool) -> Stats {
    let mut stats = Stats::default();
    let cfg = Config {
        max_header_list: [200, 4096, 64 << 10][c.below(3)],
        qpack_table_capacity: [0, 220, 4096][c.below(3)],
        qpack_blocked_streams: [0, 1, 16][c.below(3)],
        encoder: EncoderConfig { table_capacity: [100, 4096][c.below(2)], blocked_streams: [0, 1, 4][c.below(3)], only_safe_names: c.below(2) == 0 },
        body_buffer: [300, 5000, 1 << 20][c.below(3)],
        send_buffer: [100, 4096, 256 << 10][c.below(3)],
    };
    let server_capacity = [0u64, 220, 4096][c.below(3)];
    let server_blocked = [0u64, 1, 16][c.below(3)];
    let server_max_section = [None, Some(400u64), Some(1 << 20)][c.below(3)];
    let mut conn = Connection::new(cfg);
    let mut t = Fake::new();
    t.room = [3, 100, usize::MAX][c.below(3)];
    conn.process(&mut t).unwrap();

    // the server's own streams, with what a server says first
    let mut settings = vec![(0x01, server_capacity), (0x07, server_blocked)];
    if let Some(m) = server_max_section {
        settings.push((0x06, m));
    }
    let mut control = vec![0x00];
    {
        let mut payload = vec![];
        for &(id, v) in &settings {
            crate::quic::wire::put_varint(&mut payload, id);
            crate::quic::wire::put_varint(&mut payload, v);
        }
        frame::put_frame_header(&mut control, frame::ty::SETTINGS, payload.len() as u64);
        control.extend_from_slice(&payload);
    }
    t.push(SERVER_CONTROL, &control, false);
    t.push(SERVER_QPACK_ENCODER, &[0x02], false);
    t.push(SERVER_QPACK_DECODER, &[0x03], false);
    conn.process(&mut t).unwrap();

    // the server's encoder: it makes the table the client announced
    let mut server_enc = Encoder::new(EncoderConfig { table_capacity: 4096, blocked_streams: 16, only_safe_names: false });
    server_enc.set_peer_settings(cfg.qpack_table_capacity as u64, cfg.qpack_blocked_streams as u64);
    let mut held_instructions: Vec<u8> = vec![];
    let mut decoder_stream_fed = 1; // (the type byte is not an instruction)

    let mut reqs: HashMap<u64, Sentry> = HashMap::new();
    let mut order: Vec<u64> = vec![];
    let mut tainted = false;
    // bytes were put on the encoder stream that the server's encoder did not make: what the client's table holds is not what the server believes
    let mut table_corrupt = false;
    let mut next_uni = 15u64;
    // the streams of the server that are of a type nobody knows (RFC 9114 section 6.2.3 has the server make some on purpose): what of the
    // type is yet to be said, and the ones that have not ended
    let mut grease: Vec<(u64, Vec<u8>)> = vec![];
    let mut unfinished_uni: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut goaway_last: Option<u64> = None;
    let mut transport_gone = false;

    for _ in 0..max_steps {
        if c.exhausted() {
            break;
        }
        let pick = |c: &mut C, order: &Vec<u64>| -> Option<u64> { if order.is_empty() { None } else { Some(order[c.below(order.len())]) } };
        match c.below(16) {
            // a request
            0 | 1 => {
                let path = format!("/{}", ["", "a", "b/c", "index.html?x=1"][c.below(4)]);
                let extra: Vec<(String, String)> = (0..c.below(3)).map(|_| (["accept", "user-agent", "x-a", "Accept-Encoding"][c.below(4)].to_string(), value(c))).collect();
                let method = ["GET", "GET", "POST", "HEAD"][c.below(4)];
                let end = c.below(3) != 0;
                let req = Request { method, scheme: "https", authority: "example.com", path: &path, headers: &extra, secret: &[] };
                if let Ok(id) = conn.open_stream(&mut t, &req, end) {
                    let mut fields = vec![(":method".to_string(), method.to_string()), (":scheme".to_string(), "https".to_string()), (":authority".to_string(), "example.com".to_string()), (":path".to_string(), path.clone())];
                    fields.extend(extra.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.clone())));
                    order.push(id);
                    reqs.insert(id, Sentry { fields, body: vec![], ended_by_us: end, seen: Seen::default(), pristine: true, response: None, cut: false });
                }
            }
            // a response made well, perhaps with its table entries held back
            2 | 3 | 4 => {
                if let Some(id) = pick(c, &order) {
                    let s = reqs.get_mut(&id).unwrap();
                    if s.pristine && s.response.is_none() && !s.cut {
                        let status = [200u16, 200, 404, 204, 304][c.below(5)];
                        let headers = pairs(c, 4);
                        let bodiless = status == 204 || status == 304 || s.fields[0].1 == "HEAD";
                        // (now and then a body that is more than the connection reads ahead of an application that does not read: the
                        // connection has to stop reading, and go on when the application does)
                        let big = !bodiless && c.below(24) == 0;
                        let body: Vec<u8> = if bodiless {
                            vec![]
                        } else if big {
                            let start = c.byte();
                            (0..66_000 + c.below(60_000)).map(|i| start.wrapping_add(i as u8)).collect()
                        } else {
                            pattern(c, 400)
                        };
                        let trailers = if c.below(3) == 0 { Some(pairs(c, 2)) } else { None };
                        let r = Response { status, headers, body, trailers };
                        let mut bytes = vec![];
                        if c.below(4) == 0 {
                            // an interim response first
                            let sec = encode(&mut server_enc, id, &[(":status".to_string(), "103".to_string())]);
                            frame::put_headers(&mut bytes, &sec);
                        }
                        let mut fields = vec![(":status".to_string(), status.to_string())];
                        fields.extend(r.headers.iter().cloned());
                        frame::put_headers(&mut bytes, &encode(&mut server_enc, id, &fields));
                        let mut left = &r.body[..];
                        while !left.is_empty() {
                            let n = (1 + c.below(if big { 20_000 } else { 150 })).min(left.len());
                            frame::put_data(&mut bytes, &left[..n]);
                            left = &left[n..];
                        }
                        if let Some(tr) = &r.trailers {
                            frame::put_headers(&mut bytes, &encode(&mut server_enc, id, tr));
                        }
                        // what the server's encoder says goes in order: it is delivered now, or held back (and then so is everything after it)
                        held_instructions.extend_from_slice(&server_enc.take_output());
                        if c.below(2) == 0 && !held_instructions.is_empty() {
                            t.push(SERVER_QPACK_ENCODER, &held_instructions, false);
                            held_instructions.clear();
                        }
                        // the bytes come whole or in two parts (the second may be no more than the end of the stream: a response whose last frame
                        // is complete, and has not been told that it is the last)
                        if c.below(2) == 0 && bytes.len() > 1 {
                            let cut = 1 + c.below(bytes.len());
                            t.push(id, &bytes[..cut], false);
                            t.push(id, &bytes[cut..], true);
                        } else {
                            t.push(id, &bytes, true);
                        }
                        s.response = Some(r);
                    }
                }
            }
            // what the server's encoder said and was held back
            5 => {
                if !held_instructions.is_empty() {
                    let n = 1 + c.below(held_instructions.len());
                    let part: Vec<u8> = held_instructions.drain(..n).collect();
                    t.push(SERVER_QPACK_ENCODER, &part, false);
                }
            }
            // what the client's decoder said, to the server's encoder
            6 => {
                // (the client's decoder stream is the third of its unidirectional streams: id 10)
                let out = t.written(10).to_vec();
                if !tainted && out.len() > decoder_stream_fed {
                    let new = &out[decoder_stream_fed..];
                    decoder_stream_fed = out.len();
                    if let Err(e) = server_enc.decoder_stream(new) {
                        panic!("the client's decoder stream is not understood by an encoder that has been told only what is true: {e}");
                    }
                }
            }
            // the application reads
            7 | 8 => {
                if let Some(id) = pick(c, &order) {
                    let take = c.below(2) == 0;
                    let size = [1usize, 7, 100, 5000][c.below(4)];
                    for _ in 0..1 + c.below(4) {
                        let ready = conn.ready(id);
                        let ev = if take {
                            let mut into = vec![];
                            let e = conn.take_stream_data(id, &mut into);
                            if let StreamEvent::Data(n) = &e {
                                assert_eq!(into.len(), *n);
                                reqs.get_mut(&id).unwrap().seen.body.extend_from_slice(&into);
                                StreamEvent::Data(*n)
                            } else {
                                e
                            }
                        } else {
                            let mut buf = vec![0u8; size];
                            let e = conn.poll_stream(id, &mut buf);
                            if let StreamEvent::Data(n) = &e {
                                reqs.get_mut(&id).unwrap().seen.body.extend_from_slice(&buf[..*n]);
                            }
                            e
                        };
                        // (what `ready` says is what the application is given: a wake-up for news is never missed or empty)
                        assert_eq!(ready, !matches!(ev, StreamEvent::Pending), "ready said {ready} and the stream gave {ev:?}");
                        let s = &mut reqs.get_mut(&id).unwrap().seen;
                        observe(s, ev);
                    }
                }
            }
            // the application sends body
            9 => {
                if let Some(id) = pick(c, &order) {
                    let data = pattern(c, 300);
                    let end = c.below(3) == 0;
                    let s = reqs.get_mut(&id).unwrap();
                    let capacity = conn.send_capacity(id);
                    let writable = conn.writable(id);
                    let result = conn.send_data(&mut t, id, &data, end);
                    // (a writer that waits for room is told when there is some: if there is none it is not told, and nothing is taken)
                    assert!(writable || result == Ok(0), "writable said no and send_data gave {result:?}");
                    if let Ok(taken) = result {
                        assert!(taken <= data.len());
                        assert!(taken <= capacity, "{taken} bytes taken, room for {capacity}");
                        s.body.extend_from_slice(&data[..taken]);
                        if end && taken == data.len() {
                            s.ended_by_us = true;
                        }
                    }
                }
            }
            // the application lets go of a stream
            10 if c.below(4) == 0 => {
                if let Some(id) = pick(c, &order) {
                    conn.release_stream(&mut t, id);
                    order.retain(|&x| x != id);
                    reqs.get_mut(&id).unwrap().cut = true;
                }
            }
            // the server resets a stream, or stops what we send
            11 if c.below(4) == 0 => {
                if let Some(id) = pick(c, &order) {
                    let s = reqs.get_mut(&id).unwrap();
                    if c.below(2) == 0 {
                        t.reset_by_server(id, [code::H3_REQUEST_REJECTED, code::H3_REQUEST_CANCELLED, code::H3_INTERNAL_ERROR, 0x1234][c.below(4)]);
                    } else {
                        t.events.push_back(TransportEvent::Stopped(id, [code::H3_NO_ERROR, code::H3_REQUEST_REJECTED][c.below(2)]));
                    }
                    s.cut = true;
                }
            }
            // the transport takes less or more
            12 => t.room = [0, 3, 100, usize::MAX][c.below(4)],
            // GOAWAY, in order
            13 if c.below(8) == 0 => {
                let id = (c.below(20) as u64) * 4;
                if goaway_last.is_none_or(|g| id <= g) {
                    goaway_last = Some(id);
                    let mut bytes = vec![];
                    let mut payload = vec![];
                    crate::quic::wire::put_varint(&mut payload, id);
                    frame::put_frame_header(&mut bytes, frame::ty::GOAWAY, payload.len() as u64);
                    bytes.extend_from_slice(&payload);
                    t.push(SERVER_CONTROL, &bytes, false);
                    // (the streams at and over it were not taken)
                    for (sid, r) in reqs.iter_mut() {
                        if *sid >= id {
                            r.cut = true;
                        }
                    }
                }
            }
            // bytes that mean nothing, or a stream of a type that is not known, or the transport is gone
            14 if garbage => {
                tainted = true;
                let n = c.below(40);
                let alphabet = [0u8, 1, 2, 3, 4, 5, 7, 0x0d, 0x21, 0x40, 0x80, 0xc0, 0xff, 8, 9, 6];
                let bytes: Vec<u8> = (0..n).map(|_| if c.below(3) == 0 { c.byte() } else { alphabet[c.below(alphabet.len())] }).collect();
                let fin = c.below(12) == 0;
                match c.below(6) {
                    0 => t.push(SERVER_CONTROL, &bytes, fin),
                    1 => {
                        table_corrupt = true;
                        t.push(SERVER_QPACK_ENCODER, &bytes, fin)
                    }
                    2 => t.push(SERVER_QPACK_DECODER, &bytes, fin),
                    3 => {
                        let id = next_uni;
                        next_uni += 4;
                        let mut b = vec![[0x21u8, 0x40, 0x01, 0x00, 0x02, 0x03][c.below(6)]];
                        b.extend_from_slice(&bytes);
                        t.push(id, &b, fin);
                        if !fin {
                            unfinished_uni.insert(id);
                        }
                    }
                    _ => {
                        if let Some(id) = pick(c, &order) {
                            reqs.get_mut(&id).unwrap().pristine = false;
                            t.push(id, &bytes, fin);
                        }
                    }
                }
            }
            _ => {
                if c.below(3) == 0 {
                    // a stream of a type that is not known: a new one, or more on one that is open (its type may come in pieces, and it may end
                    // at any point)
                    if grease.is_empty() || c.below(3) == 0 {
                        let mut ty = vec![];
                        crate::quic::wire::put_varint(&mut ty, 0x1f * c.below(1000) as u64 + 0x21);
                        grease.push((next_uni, ty));
                        next_uni += 4;
                    }
                    let i = c.below(grease.len());
                    let (id, pending) = &mut grease[i];
                    let mut b = vec![];
                    if !pending.is_empty() {
                        let n = 1 + c.below(pending.len());
                        b.extend(pending.drain(..n));
                    }
                    if pending.is_empty() {
                        b.extend(pattern(c, 20));
                    }
                    let fin = c.below(3) == 0;
                    let id = *id;
                    t.push(id, &b, fin);
                    if fin {
                        grease.remove(i);
                        unfinished_uni.remove(&id);
                    } else {
                        unfinished_uni.insert(id);
                    }
                } else if c.below(40) == 0 && !transport_gone {
                    transport_gone = true;
                    conn.transport_closed(code::H3_NO_ERROR, "the transport is gone");
                }
            }
        }
        // (the application may not be called when the connection is lost: it answers with what it has)
        let before = conn.error().is_some();
        let result = conn.process(&mut t);
        conn.assert_books();
        if conn.decoder.blocked_streams() > 0 {
            stats.waited += 1;
        }
        match (&result, conn.error()) {
            (Ok(()), None) => {}
            (Err(e), Some(f)) => assert_eq!(e, f),
            (r, e) => panic!("process said {r:?} and the connection's error is {e:?}"),
        }
        if let Some(e) = conn.error() {
            if e.local && !before {
                assert!(valid_code(e.code), "closed with {:#x}, which is not a code of the RFC", e.code);
                assert_eq!(t.closed_with(), Some(e.code), "the connection is lost and the transport was not closed with its code");
            }
        }
        // a server that says only what is well made does not lose the connection
        if !tainted && !transport_gone {
            assert!(conn.error().is_none(), "a well-made server lost the connection: {:?}", conn.error());
        }
    }

    // the end: the server's encoder has said everything, the application reads everything there is, and the transport takes everything
    t.room = usize::MAX;
    if !held_instructions.is_empty() {
        t.push(SERVER_QPACK_ENCODER, &held_instructions, false);
    }
    for _ in 0..3 {
        let _ = conn.process(&mut t);
        for &id in reqs.keys().copied().collect::<Vec<_>>().iter() {
            if reqs[&id].cut && !order.contains(&id) {
                continue;
            }
            for _ in 0..2000 {
                let mut into = vec![];
                let ready = conn.ready(id);
                let ev = conn.take_stream_data(id, &mut into);
                assert_eq!(ready, !matches!(ev, StreamEvent::Pending), "ready said {ready} and the stream gave {ev:?}");
                let s = &mut reqs.get_mut(&id).unwrap().seen;
                if let StreamEvent::Data(_) = &ev {
                    s.body.extend_from_slice(&into);
                }
                let done = matches!(ev, StreamEvent::Pending | StreamEvent::End | StreamEvent::Failed(_));
                observe(s, ev);
                if done {
                    break;
                }
                if conn.needs_processing() {
                    let _ = conn.process(&mut t);
                }
            }
        }
    }
    conn.assert_books();
    // a stream of a type that is not known is remembered only while it is open (a connection that is lost reads no more)
    if conn.error().is_none() {
        for id in &conn.ignored {
            assert!(unfinished_uni.contains(id), "stream {id} ended, and the connection still remembers it as one it turned away");
        }
    }
    let gone = conn.error().is_some();
    stats.lost = usize::from(gone && !transport_gone);
    if !tainted && !transport_gone {
        assert!(!gone, "a well-made server lost the connection at the end: {:?}", conn.error());
    }

    // what a well-made response that was read to its end says
    for (id, s) in &reqs {
        if let Some(f) = &s.seen.failed {
            assert!(valid_code(f.code) || f.code == 0x1234 || f.code == 0, "a stream failed with {:#x}", f.code);
        }
        if s.seen.ended {
            assert!(s.seen.failed.is_none(), "a stream ended and failed");
        }
        stats.failed += usize::from(s.seen.failed.is_some());
        if s.pristine && s.seen.ended && !table_corrupt {
            stats.responses += 1;
            let r = s.response.as_ref().expect("a response that was never sent ended");
            let (status, headers) = s.seen.head.as_ref().expect("an end with no head");
            assert_eq!(*status, r.status, "stream {id}");
            assert_eq!(headers, &r.headers, "stream {id}");
            assert_eq!(s.seen.body, r.body, "the body of stream {id}");
            assert_eq!(s.seen.trailers, r.trailers, "the trailers of stream {id}");
        }
        // a response that was well made, sent to its end and not cut short is read to its end by an application that reads everything (or it
        // is refused for its size): the end of a stream that waited for the table, or came with the last of the table's entries, is not lost
        if s.pristine && s.response.is_some() && !s.cut && !table_corrupt && !gone && !transport_gone && !s.seen.ended {
            let too_large = s.seen.failed.as_ref().is_some_and(|f| f.code == code::H3_EXCESSIVE_LOAD);
            // (bytes that mean nothing, put on the control stream, can make a GOAWAY that is well made: the requests it names are
            // rejected, as they must be, though the script never cut them. Found by the field run's fuzzing: 07 01 00 is GOAWAY(0))
            let rejected = tainted && conn.goaway.is_some_and(|g| *id >= g) && s.seen.failed.as_ref().is_some_and(|f| f.code == code::H3_REQUEST_REJECTED);
            assert!(too_large || rejected, "a well-made response to stream {id} was not read to its end: {:?}", s.seen);
        }
        if !tainted && !s.cut && !gone {
            if let Some(f) = &s.seen.failed {
                // (a response that was well made is lost only for being too large to take)
                assert!(f.code == code::H3_EXCESSIVE_LOAD, "a well-made response to stream {id} failed: {f:?}");
            }
        }
    }

    // what the client wrote, read back
    if !gone {
        stats.inserted = check_client_output(&t, &reqs, server_capacity, server_blocked, &conn, &order);
    }
    stats
}

fn encode(e: &mut Encoder, stream: u64, fields: &[(String, String)]) -> Vec<u8> {
    let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
    let mut out = vec![];
    e.encode(stream, &refs, &mut out);
    out
}

/// Notes what the application was told, and checks that it is told in order.
fn observe(s: &mut Seen, ev: StreamEvent) {
    assert!(s.failed.is_none() || matches!(ev, StreamEvent::Failed(_) | StreamEvent::Pending), "{ev:?} after a failure");
    match ev {
        StreamEvent::Pending => {}
        StreamEvent::Head(h) => {
            assert!(s.head.is_none() && !s.ended && s.body.is_empty(), "a head that is not the first thing");
            s.head = Some((h.status, h.headers));
        }
        StreamEvent::Data(_) => {
            assert!(s.head.is_some() && !s.ended && s.trailers.is_none(), "data out of its place");
        }
        StreamEvent::Trailers(t) => {
            assert!(s.head.is_some() && !s.ended && s.trailers.is_none(), "trailers out of their place");
            s.trailers = Some(t);
        }
        StreamEvent::End => {
            assert!(s.head.is_some(), "an end with no head");
            s.ended = true;
        }
        StreamEvent::Failed(f) => {
            assert!(!s.ended, "a failure after the end");
            if let Some(before) = &s.failed {
                assert_eq!(before, &f, "a failure that changed");
            }
            s.failed = Some(f);
        }
    }
}

/// The client's streams, read as a server would read them: in the order the bytes were written, the encoder stream and the requests, by a
/// decoder that has the limits the server announced. Every request's field section must decode (when the entries it waits for have come)
/// to the fields of the request, and the frames of a request must be its head, its body as it was taken, and its end when the application
/// said so. Returns how many entries the client's encoder made.
fn check_client_output(t: &Fake, reqs: &HashMap<u64, Sentry>, server_capacity: u64, server_blocked: u64, conn: &Connection, order: &[u64]) -> usize {
    let mut dec = Decoder::new(server_capacity as usize, server_blocked as usize, 1 << 24);
    let mut readers: HashMap<u64, FrameReader> = HashMap::new();
    let mut waiting: Vec<(u64, Vec<u8>)> = vec![];
    let mut decoded: HashMap<u64, Vec<(String, String)>> = HashMap::new();
    let mut bodies: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut sections: HashMap<u64, usize> = HashMap::new();
    let try_decode = |dec: &mut Decoder, id: u64, block: &[u8], decoded: &mut HashMap<u64, Vec<(String, String)>>, waiting: &mut Vec<(u64, Vec<u8>)>| {
        let mut got = vec![];
        match dec.decode(id, block, &mut got) {
            Ok(Decoded::Done { within_limit: true }) => {
                decoded.insert(id, got.iter().map(|f| (String::from_utf8_lossy(&f.name).into_owned(), String::from_utf8_lossy(&f.value).into_owned())).collect());
            }
            Ok(Decoded::Blocked { .. }) => waiting.push((id, block.to_vec())),
            other => panic!("the request on stream {id} does not decode: {other:?}"),
        }
    };
    for &(id, at, n) in &t.log {
        let bytes = &t.sent[&id].data[at..at + n];
        match id {
            2 | 10 => {}
            6 => {
                // (the first byte is the stream's type)
                let instr = if at == 0 { &bytes[1..] } else { bytes };
                dec.encoder_stream(instr).unwrap_or_else(|e| panic!("the client's encoder stream was refused by a decoder: {e}"));
                // what waited for it
                for (sid, block) in std::mem::take(&mut waiting) {
                    try_decode(&mut dec, sid, &block, &mut decoded, &mut waiting);
                }
            }
            _ if id & 3 == 0 => {
                let reader = readers.entry(id).or_insert_with(|| FrameReader::new(Kind::Request, 1 << 24));
                let mut events = vec![];
                reader.feed(bytes, &mut events).unwrap_or_else(|e| panic!("what the client wrote on stream {id} is not frames: {e:?}"));
                for e in events {
                    match e {
                        Event::Headers(block) => {
                            *sections.entry(id).or_default() += 1;
                            try_decode(&mut dec, id, &block, &mut decoded, &mut waiting);
                        }
                        Event::Data(r) => bodies.entry(id).or_default().extend_from_slice(&bytes[r]),
                        other => panic!("{other:?} in a request"),
                    }
                }
            }
            _ => {}
        }
    }
    assert!(waiting.is_empty(), "a request waits for entries of the table that the client never made");
    for (id, s) in reqs {
        let Some(sent) = t.sent.get(id) else { continue };
        if s.cut || sent.reset.is_some() {
            continue;
        }
        assert_eq!(sections.get(id), Some(&1), "the field sections of the request on stream {id}: sent {:?} (fin {}), the connection has it: {:?}, order has it: {}", t.sent.get(id).map(|s| s.data.len()), sent.fin, conn_has(conn, *id), order.contains(id));
        assert_eq!(decoded.get(id), Some(&s.fields), "the fields of the request on stream {id}");
        assert_eq!(bodies.get(id).cloned().unwrap_or_default(), s.body, "the body written on stream {id}");
        assert!(readers[id].at_frame_boundary() || !sent.fin, "the client ended stream {id} in the middle of a frame");
        if s.ended_by_us {
            assert!(sent.fin, "the end of the request on stream {id} was not written");
        } else {
            assert!(!sent.fin, "the request on stream {id} was ended when the application had not");
        }
    }
    dec.insert_count() as usize
}

fn conn_has(c: &Connection, id: u64) -> String {
    match c.streams.get(&id) {
        None => "no".into(),
        Some(s) => format!("yes: out pending {} fin {} finished {} id {:?} stopped {:?} failure {:?} dirty {}", s.out.pending(), s.out.fin, s.out.finished, s.out.id, s.send_stopped, s.failure, c.dirty.contains(&id)),
    }
}
