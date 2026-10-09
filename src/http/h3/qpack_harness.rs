//! A model-based exchange between an [`Encoder`] and a [`Decoder`] over links that delay, cut and drop things, and the checks of the
//! tables' bookkeeping that go with it. The tests run it on a pseudo-random generator and the fuzzer on the bytes it is given, so
//! that it can look for the sequence that breaks something (`h3_qpack_exchange`); the decoder's own target (`h3_qpack`) uses the
//! same checks on a decoder fed with what no encoder wrote.
//!
//! What the exchange sets out to prove, for any sequence of requests, deliveries and abandoned streams: nothing that the two ends
//! say to each other is an error; what the decoder reads is what the encoder was given; no stream is ever blocked on more than the
//! decoder allowed; and when everything has arrived the tables agree (the decoder may hold, besides what the encoder holds, some
//! older entries the encoder let go of) and nothing is still counted as referred to.

use super::*;

/// Where an exchange gets its choices from.
pub(crate) trait Choose {
    /// A number below `n` (0 if `n` is 0 or 1).
    fn below(&mut self, n: usize) -> usize;

    fn byte(&mut self) -> u8 {
        self.below(256) as u8
    }

    /// True when there is nothing left to choose from (a script that is out of bytes).
    fn exhausted(&self) -> bool {
        false
    }
}

/// A pseudo-random sequence (xorshift), for tests.
pub(crate) struct Xorshift(pub(crate) u64);

impl Choose for Xorshift {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        if n <= 1 { 0 } else { (self.0 % n as u64) as usize }
    }
}

/// The bookkeeping of an encoder must add up (the entries it counts as referred to are the ones the sections it has not had
/// acknowledged refer to, and they are all still in the table), and it must keep to its limits.
pub(crate) fn check_encoder(enc: &Encoder) {
    let t = &enc.table;
    assert_eq!(t.size, t.entries.iter().map(|e| e.field.size()).sum::<usize>(), "the table's size is not the sum of its entries");
    assert!(t.size <= t.capacity, "the table is over the capacity announced");
    assert!(t.capacity <= enc.peer_max_capacity.min(MAX_ANNOUNCED), "a capacity over what the peer allows");
    assert!(t.size <= enc.cfg.table_capacity, "the table holds more than the encoder lets it");
    assert!(enc.known_received <= t.inserted(), "the decoder is believed to have more than was inserted");
    let mut counted: HashMap<u64, u32> = HashMap::new();
    for q in enc.outstanding.values() {
        assert!(!q.is_empty());
        for s in q {
            assert!(s.required > 0 && s.required <= t.inserted());
            assert_eq!(s.refs.iter().max().map(|m| m + 1), Some(s.required), "a section's required insert count is not its largest reference");
            for abs in &s.refs {
                assert!(t.get(*abs).is_some(), "an entry was evicted while a section the decoder has not acknowledged refers to it");
                *counted.entry(*abs).or_default() += 1;
            }
        }
    }
    for (i, e) in t.entries.iter().enumerate() {
        assert_eq!(e.refs, counted.get(&(t.dropped + i as u64)).copied().unwrap_or(0), "the references to an entry are not the ones its sections hold");
    }
    assert!(enc.inbox.len() <= 12, "more of the decoder stream is held than an instruction can need");
    assert!(enc.blocked_count() <= enc.cfg.blocked_streams.min(enc.peer_max_blocked), "more streams may be blocked than the encoder or the decoder allows");
}

/// The decoder's table adds up and is within what was announced, and what it holds of an instruction that has not all come, and
/// of the streams that wait, is bounded.
pub(crate) fn check_decoder(dec: &Decoder) {
    let t = &dec.table;
    assert_eq!(t.size, t.entries.iter().map(|e| e.field.size()).sum::<usize>());
    assert!(t.size <= t.capacity && t.capacity <= dec.max_capacity, "the table is over what was announced");
    assert!(dec.known_received <= t.inserted());
    assert!(dec.blocked.len() <= dec.max_blocked, "more streams wait than were allowed");
    assert!(dec.inbox.len() <= 2 * (4 * t.capacity + 8) + 40, "more of the encoder stream is held than an instruction could need");
}

/// Both ends hold the same entries, except that the decoder may still hold some that the encoder has let go of (the oldest).
pub(crate) fn tables_agree(enc: &Encoder, dec: &Decoder) {
    assert_eq!(enc.table.inserted(), dec.table.inserted());
    let (e, d) = (&enc.table.entries, &dec.table.entries);
    assert!(d.len() >= e.len());
    for (a, b) in e.iter().rev().zip(d.iter().rev()) {
        assert_eq!(a.field, b.field);
    }
    assert!(enc.table.size <= dec.table.size && dec.table.size <= dec.table.capacity);
}

const NAMES: &[&str] = &[":authority", "user-agent", "accept", "accept-encoding", "content-type", "x-trace", "cookie", "x-long-name-for-the-table", "authorization", "if-none-match", ":path", "range", ":method", "content-length"];

fn bytes<C: Choose>(c: &mut C, n: usize) -> Vec<u8> {
    (0..n).map(|_| c.byte()).collect()
}

/// A list of fields, with the sensitive ones marked. Names and values repeat, so that the tables are used; some are made of the
/// bytes the choices give, so that a script can reach any.
pub(crate) fn fields<C: Choose>(c: &mut C, recent: &mut Vec<Field>) -> Vec<(Field, bool)> {
    let mut v = vec![];
    for _ in 0..c.below(9) {
        let (name, value): (Vec<u8>, Vec<u8>) = match c.below(8) {
            0 => (b":method".to_vec(), b"GET".to_vec()),
            1 if !recent.is_empty() => {
                let f = &recent[c.below(recent.len())];
                (f.name.clone(), f.value.clone())
            }
            2 => {
                let n = 1 + c.below(10);
                let name = bytes(c, n);
                let n = c.below(30);
                (name, bytes(c, n))
            }
            _ => {
                let name = NAMES[c.below(NAMES.len())].as_bytes().to_vec();
                let value = match c.below(7) {
                    0 => vec![],
                    1 => b"gzip".to_vec(),
                    2 => format!("v{}", c.below(4)).into_bytes(),
                    3 => {
                        let n = c.below(120);
                        let mut v = vec![b'z'; n];
                        v.push(b'0' + c.below(3) as u8);
                        v
                    }
                    4 => b"*/*".to_vec(),
                    5 => {
                        let n = c.below(24);
                        bytes(c, n)
                    }
                    _ => format!("agent/{}", c.below(30)).into_bytes(),
                };
                (name, value)
            }
        };
        let field = Field { name, value };
        if recent.len() < 12 {
            recent.push(field.clone());
        } else {
            let i = c.below(12);
            recent[i] = field.clone();
        }
        v.push((field, c.below(12) == 0));
    }
    v
}

struct Pending {
    stream: u64,
    block: Vec<u8>,
    fields: Vec<Field>,
}

/// What an exchange did, to tell whether it did anything: how many times a section had to wait, how many entries the decoder
/// evicted and how many were inserted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub(crate) waited: u64,
    pub(crate) evicted: u64,
    pub(crate) inserted: u64,
}

struct World {
    enc: Encoder,
    dec: Decoder,
    peer_blocked: usize,
    to_decoder: Vec<u8>,
    to_encoder: Vec<u8>,
    pending: Vec<Pending>,
    next_stream: u64,
    /// Streams that were abandoned (reset): not used again.
    dead: Vec<u64>,
    recent: Vec<Field>,
    waited: u64,
}

impl World {
    fn step<C: Choose>(&mut self, c: &mut C) {
        match c.below(10) {
            0..=2 => {
                // a request, on a stream that is new or (sometimes) on the one that was last used
                let reuse = self.next_stream > 0 && c.below(6) == 0 && !self.dead.contains(&(self.next_stream - 4));
                let stream = if reuse {
                    self.next_stream - 4
                } else {
                    self.next_stream += 4;
                    self.next_stream - 4
                };
                let list = fields(c, &mut self.recent);
                let refs: Vec<FieldRef<'_>> = list.iter().map(|(f, s)| FieldRef { name: &f.name, value: &f.value, sensitive: *s }).collect();
                let mut block = vec![];
                self.enc.encode(stream, &refs, &mut block);
                self.to_decoder.extend(self.enc.take_output());
                self.pending.push(Pending { stream, block, fields: list.into_iter().map(|(f, _)| f).collect() });
            }
            3 | 4 => {
                // part of the encoder stream arrives (maybe cut in the middle of an instruction)
                let n = c.below(self.to_decoder.len() + 1);
                let part: Vec<u8> = self.to_decoder.drain(..n).collect();
                self.dec.encoder_stream(&part).expect("the decoder refused what the encoder wrote on its stream");
            }
            5..=7 => {
                // a section is tried (the first of its stream that has not been decoded yet)
                if self.pending.is_empty() {
                    return;
                }
                let i = c.below(self.pending.len());
                if self.pending[..i].iter().any(|p| p.stream == self.pending[i].stream) {
                    return;
                }
                let mut out = vec![];
                match self.dec.decode(self.pending[i].stream, &self.pending[i].block, &mut out).expect("the decoder refused a section the encoder wrote") {
                    Decoded::Done { within_limit } => {
                        assert!(within_limit);
                        assert_eq!(out, self.pending[i].fields, "the decoder read other fields than the encoder was given");
                        self.pending.remove(i);
                    }
                    Decoded::Blocked { .. } => self.waited += 1,
                }
                self.to_encoder.extend(self.dec.take_output());
            }
            8 => {
                // a stream is abandoned (with the sections of it that were not decoded: they are read in order, so the later ones
                // would never be read either)
                if self.pending.is_empty() {
                    return;
                }
                let stream = self.pending[c.below(self.pending.len())].stream;
                self.pending.retain(|p| p.stream != stream);
                self.dead.push(stream);
                self.dec.cancel_stream(stream);
                self.to_encoder.extend(self.dec.take_output());
            }
            _ => {
                // the decoder stream arrives
                let n = c.below(self.to_encoder.len() + 1);
                let part: Vec<u8> = self.to_encoder.drain(..n).collect();
                self.enc.decoder_stream(&part).expect("the encoder refused what the decoder wrote on its stream");
            }
        }
    }

    /// Everything that is on the way arrives, every section is decoded, and every acknowledgment is delivered.
    fn flush(&mut self) {
        let all = std::mem::take(&mut self.to_decoder);
        self.dec.encoder_stream(&all).expect("the decoder refused what the encoder wrote on its stream");
        while !self.pending.is_empty() {
            let p = self.pending.remove(0);
            let mut out = vec![];
            assert_eq!(self.dec.decode(p.stream, &p.block, &mut out), Ok(Decoded::Done { within_limit: true }), "a section is still blocked with all of the encoder stream delivered");
            assert_eq!(out, p.fields);
        }
        self.to_encoder.extend(self.dec.take_output());
        let all = std::mem::take(&mut self.to_encoder);
        self.enc.decoder_stream(&all).expect("the encoder refused what the decoder wrote on its stream");
        check_encoder(&self.enc);
        check_decoder(&self.dec);
        tables_agree(&self.enc, &self.dec);
        assert_eq!(self.enc.blocked_count(), 0);
        assert_eq!(self.enc.known_received, self.enc.table.inserted(), "the decoder has told the encoder about every entry (by section acknowledgments and increments)");
        assert!(self.enc.table.entries.iter().all(|e| e.refs == 0), "every section is acknowledged or abandoned, so nothing is still referred to");
        assert_eq!(self.dec.blocked_streams(), 0);
        assert!(self.dec.blocked_streams() <= self.peer_blocked);
    }
}

/// Runs an exchange of up to `steps` steps, the settings and what happens in it taken from `c`.
pub(crate) fn exchange<C: Choose>(c: &mut C, steps: usize) -> Stats {
    let capacity = [0usize, 64, 100, 200, 400, 1000, 4096, 16384][c.below(8)];
    let peer_blocked = [0usize, 1, 2, 4, 16][c.below(5)];
    let cfg = EncoderConfig { table_capacity: [0usize, 100, 300, 4096, 100_000][c.below(5)], blocked_streams: [0usize, 1, 2, 8][c.below(4)], only_safe_names: c.below(2) == 0 };
    let mut enc = Encoder::new(cfg);
    enc.set_peer_settings(capacity as u64, peer_blocked as u64);
    let mut w = World { enc, dec: Decoder::new(capacity, peer_blocked, 1 << 20), peer_blocked, to_decoder: vec![], to_encoder: vec![], pending: vec![], next_stream: 0, dead: vec![], recent: vec![], waited: 0 };
    for _ in 0..steps {
        if c.exhausted() {
            break;
        }
        w.step(c);
        check_encoder(&w.enc);
        check_decoder(&w.dec);
        assert!(w.dec.insert_count() <= w.enc.table.inserted());
    }
    w.flush();
    Stats { waited: w.waited, evicted: w.dec.table.dropped, inserted: w.dec.insert_count() }
}

/// A list that was decoded is written by encoders of different settings and read back by a fresh decoder as the same list, twice
/// on one pair (the second section uses what the first put in the tables), whether or not the fields are marked sensitive.
pub(crate) fn round_trip(list: &[Field]) {
    for (cfg, sensitive) in [
        (EncoderConfig::default(), false),
        (EncoderConfig { blocked_streams: 2, only_safe_names: false, ..EncoderConfig::default() }, false),
        (EncoderConfig { blocked_streams: 2, only_safe_names: false, ..EncoderConfig::default() }, true),
        (EncoderConfig { table_capacity: 300, blocked_streams: 1, only_safe_names: false }, false),
    ] {
        let mut enc = Encoder::new(cfg);
        enc.set_peer_settings(4096, 16);
        let mut dec = Decoder::new(4096, 16, 1 << 24);
        for stream in [0u64, 4, 8] {
            let refs: Vec<FieldRef<'_>> = list.iter().map(|f| FieldRef { name: &f.name, value: &f.value, sensitive }).collect();
            let mut block = vec![];
            enc.encode(stream, &refs, &mut block);
            dec.encoder_stream(&enc.take_output()).expect("a decoder refused what our encoder wrote on its stream");
            let mut out = vec![];
            assert_eq!(dec.decode(stream, &block, &mut out), Ok(Decoded::Done { within_limit: true }), "a section we wrote does not decode");
            assert_eq!(out, list, "a section we wrote decodes to other fields");
            enc.decoder_stream(&dec.take_output()).expect("our encoder refused what a decoder wrote on its stream");
            check_encoder(&enc);
            check_decoder(&dec);
        }
    }
}

/// What a decoder says on the decoder stream is made of whole instructions, with no acknowledgment of nothing and no increment of 0.
pub(crate) fn check_decoder_stream(bytes: &[u8]) {
    let mut pos = 0;
    while pos < bytes.len() {
        let first = bytes[pos];
        let prefix = if first & 0x80 != 0 { 7 } else { 6 };
        let v = get_int(bytes, &mut pos, prefix).expect("the decoder stream ends inside an instruction or has a bad integer");
        if first & 0xc0 == 0 {
            assert!(v >= 1, "an Insert Count Increment of 0");
        }
    }
}
