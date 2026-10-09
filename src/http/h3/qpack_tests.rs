//! The tests of `qpack.rs`: the primitives, the examples of RFC 9204 appendix B, the decoder's limits, the encoder and the
//! decoder together (also in the random exchanges of `qpack_harness.rs`) and against ls-qpack (a fixture, and a peer for
//! `tools/qpack_interop.py`).

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn f(name: &str, value: &str) -> Field {
    Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec() }
}

fn refs(fields: &[Field]) -> Vec<FieldRef<'_>> {
    fields.iter().map(|f| FieldRef { name: &f.name, value: &f.value, sensitive: false }).collect()
}

fn decoder() -> Decoder {
    Decoder::new(4096, 100, 1 << 20)
}

fn decode_ok(d: &mut Decoder, stream: u64, block: &[u8]) -> Vec<Field> {
    let mut out = Vec::new();
    assert_eq!(d.decode(stream, block, &mut out), Ok(Decoded::Done { within_limit: true }));
    out
}

// ---------------------------------------------------------------------------------------------------- primitives

#[test]
fn integers_as_in_rfc_7541_appendix_c1() {
    let mut v = Vec::new();
    put_int(&mut v, 5, 0, 10);
    assert_eq!(v, [0x0a]);
    v.clear();
    put_int(&mut v, 5, 0, 1337);
    assert_eq!(v, [0x1f, 0x9a, 0x0a]);
    v.clear();
    put_int(&mut v, 8, 0, 42);
    assert_eq!(v, [0x2a]);
    for (bytes, prefix, value) in [(&[0x0a][..], 5, 10), (&[0x1f, 0x9a, 0x0a][..], 5, 1337), (&[0x2a][..], 8, 42)] {
        let mut pos = 0;
        assert_eq!(get_int(bytes, &mut pos, prefix), Ok(value));
        assert_eq!(pos, bytes.len());
    }
}

#[test]
fn integers_round_trip_at_every_prefix_and_the_edges() {
    for prefix in 1..=8u32 {
        for value in [0, 1, (1u64 << prefix) - 2, (1 << prefix) - 1, 1 << prefix, 127, 128, 255, 256, 16383, 16384, 1 << 31, (1 << 32) + 5, MAX_INT - 1, MAX_INT] {
            let mut v = vec![];
            put_int(&mut v, prefix, 0, value);
            let mut pos = 0;
            assert_eq!(get_int(&v, &mut pos, prefix), Ok(value), "prefix {prefix}, value {value}");
            assert_eq!(pos, v.len());
            // every proper prefix of it is short, not wrong
            for cut in 0..v.len() {
                assert_eq!(get_int(&v[..cut], &mut 0, prefix), Err(Bad::Short));
            }
        }
    }
}

#[test]
fn integers_over_62_bits_are_refused() {
    let mut v = vec![];
    put_int(&mut v, 8, 0, MAX_INT + 1);
    assert!(matches!(get_int(&v, &mut 0, 8), Err(Bad::Invalid(_))));
    // 2^64 - 1, and a very long one that is all zero bits after the first byte
    let mut v = vec![0xff];
    v.extend([0xff; 9]);
    v.push(0x01);
    assert!(matches!(get_int(&v, &mut 0, 8), Err(Bad::Invalid(_))));
    let mut v = vec![0xff];
    v.extend([0x80; 20]);
    v.push(0);
    assert!(matches!(get_int(&v, &mut 0, 8), Err(Bad::Invalid(_))));
}

#[test]
fn strings_are_huffman_coded_when_that_is_shorter() {
    let mut v = vec![];
    put_string(&mut v, 8, 0, b"www.example.com");
    assert_eq!(v, unhex("8c f1e3c2e5f23a6ba0ab90f4ff"));
    let mut v = vec![];
    put_string(&mut v, 8, 0, b"\x00\x01\x02");
    assert_eq!(v, [3, 0, 1, 2]);
    for s in [&b""[..], b"a", b"custom-key", b"\xff\xfe\xfd", &[b'z'; 300]] {
        for prefix in [4u32, 6, 8] {
            let mut v = vec![];
            put_string(&mut v, prefix, 0, s);
            let mut out = vec![];
            let mut pos = 0;
            assert_eq!(get_string(&v, &mut pos, prefix, 1000, 1000, &mut out), Ok(true));
            assert_eq!(out, s);
            assert_eq!(pos, v.len());
        }
    }
}

#[test]
fn a_string_over_the_limit_is_read_past() {
    let mut v = vec![];
    put_string(&mut v, 8, 0, &[b'q'; 50]);
    v.push(0xaa);
    let mut out = vec![];
    let mut pos = 0;
    assert_eq!(get_string(&v, &mut pos, 8, 10, 1000, &mut out), Ok(false));
    assert_eq!(pos, v.len() - 1);
    // one longer than the wait limit is an error before its bytes are there
    assert!(matches!(get_string(&[0x7f, 0xff, 0x7f], &mut 0, 8, 10, 1000, &mut vec![]), Err(Bad::Invalid(_))));
}

#[test]
fn the_static_table_is_the_one_of_rfc_9204_appendix_a() {
    assert_eq!(STATIC.len(), 99);
    assert_eq!(STATIC[0], (":authority", ""));
    assert_eq!(STATIC[1], (":path", "/"));
    assert_eq!(STATIC[17], (":method", "GET"));
    assert_eq!(STATIC[25], (":status", "200"));
    assert_eq!(STATIC[95], ("user-agent", ""));
    assert_eq!(STATIC[98], ("x-frame-options", "sameorigin"));
    assert_eq!(static_lookup(b":method", b"GET"), (Some(17), Some(15)));
    assert_eq!(static_lookup(b":method", b"PATCH"), (None, Some(15)));
    assert_eq!(static_lookup(b"x-nothing", b""), (None, None));
}

// ---------------------------------------------------------------------------------------------------- RFC 9204 appendix B

#[test]
fn appendix_b_a_literal_with_a_static_name() {
    let mut d = decoder();
    let got = decode_ok(&mut d, 0, &unhex("0000 510b 2f69 6e64 6578 2e68 746d 6c"));
    assert_eq!(got, [f(":path", "/index.html")]);
    assert!(d.take_output().is_empty(), "no entry was used: nothing to acknowledge");
}

#[test]
fn appendix_b_the_whole_exchange() {
    let mut d = decoder();
    // the dynamic table, a blocking section, its acknowledgment
    d.encoder_stream(&unhex("3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468")).unwrap();
    assert_eq!((d.insert_count(), d.table_state()), (2, (2, 106)));
    let got = decode_ok(&mut d, 4, &unhex("0381 10 11"));
    assert_eq!(got, [f(":authority", "www.example.com"), f(":path", "/sample/path")]);
    assert_eq!(d.take_output(), unhex("84"));
    // a speculative insert, acknowledged by an increment
    d.encoder_stream(&unhex("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565")).unwrap();
    assert_eq!((d.insert_count(), d.table_state()), (3, (3, 160)));
    assert_eq!(d.take_output(), unhex("01"));
    // the section that comes before the duplicate it needs: blocked, then cancelled
    let mut out = vec![];
    assert_eq!(d.decode(8, &unhex("0500 80 c1 81"), &mut out), Ok(Decoded::Blocked { required_insert_count: 4 }));
    assert_eq!(d.blocked_streams(), 1);
    d.cancel_stream(8);
    assert_eq!(d.blocked_streams(), 0);
    assert_eq!(d.take_output(), unhex("48"));
    // the duplicate arrives; a section like that one decodes now
    d.encoder_stream(&unhex("02")).unwrap();
    assert_eq!((d.insert_count(), d.table_state()), (4, (4, 217)));
    let got = decode_ok(&mut d, 8, &unhex("0500 80 c1 81"));
    assert_eq!(got, [f(":authority", "www.example.com"), f(":path", "/"), f("custom-key", "custom-value")]);
    assert_eq!(d.take_output(), unhex("88"));
    // an insertion that evicts the oldest entry
    d.encoder_stream(&unhex("810d 6375 7374 6f6d 2d76 616c 7565 32")).unwrap();
    assert_eq!((d.insert_count(), d.table_state()), (5, (4, 215)));
    assert_eq!(d.take_output(), unhex("01"));
    // entry 0 is gone: a section that names it is refused (the prefix: required 5, base 5; index 4 is absolute 0)
    let mut out = vec![];
    assert_eq!(d.decode(12, &unhex("0600 84"), &mut out), Err(Error::Decompression("a reference to an entry that was evicted")));
    // and entry 4 is the newest (relative 0)
    let got = decode_ok(&mut d, 12, &unhex("0600 80"));
    assert_eq!(got, [f("custom-key", "custom-value2")]);
}

#[test]
fn instructions_in_any_pieces_come_out_the_same() {
    let wire = unhex("3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468 4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565 02");
    let mut whole = decoder();
    whole.encoder_stream(&wire).unwrap();
    for step in [1, 2, 3, 7] {
        let mut d = decoder();
        for piece in wire.chunks(step) {
            d.encoder_stream(piece).unwrap();
        }
        assert_eq!(d.table_state(), whole.table_state(), "in pieces of {step}");
        assert_eq!(d.insert_count(), 4);
        assert!(d.inbox.is_empty());
    }
}

// ---------------------------------------------------------------------------------------------------- what the decoder refuses

fn two_entries() -> Decoder {
    let mut d = decoder();
    d.encoder_stream(&unhex("3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468")).unwrap();
    d
}

#[test]
fn the_decoder_refuses_what_no_encoder_would_send() {
    for (why, block) in [
        ("not even a prefix", ""),
        ("no base", "00"),
        ("a required insert count past the range", "ff02 00"),
        ("a required insert count of zero that is not coded as zero", "01 00"),
        ("a required insert count that is too far ahead of the table", "c8 00"),
        ("a negative base", "03 82"),
        ("a static index that does not exist", "0000 ff24"),
        ("an entry at or above the required insert count", "0300 12"),
        ("an entry before the first", "0381 80"),
        ("a literal that is cut before its value", "0000 51"),
        ("a value that is cut", "0000 510b 2f"),
        ("an integer over 62 bits", "0000 ff ffffffffffffffffff 7f"),
        ("a Huffman string with padding that is too long", "0000 51 81 ff"),
        ("a name that is cut", "0000 2b 6162"),
        ("a post-base name reference to an entry at or above the required insert count", "0300 00 01 78"),
    ] {
        let mut d = two_entries();
        let mut out = vec![];
        let r = d.decode(0, &unhex(block), &mut out);
        assert!(matches!(r, Err(Error::Decompression(_))), "{why} ({block}): {r:?}");
    }
}

#[test]
fn a_section_may_not_refer_to_an_entry_the_encoder_did_not_say_it_needed() {
    // two entries have arrived, and the section says it needs 1 (written 2): the entry with absolute index 1 is in the table, and
    // may not be used, however the line reaches it (RFC 9204 section 4.5.1.1: nothing at or above the required insert count)
    let mut d = two_entries();
    let mut out = vec![];
    // base 1 (delta 0), post-base index 0: absolute index 1
    assert!(matches!(d.decode(0, &unhex("02 00 10"), &mut out), Err(Error::Decompression(_))));
    // base 2 (delta 1), relative index 0: absolute index 1
    let mut d = two_entries();
    assert!(matches!(d.decode(0, &unhex("02 01 80"), &mut out), Err(Error::Decompression(_))));
    // and the entry below it is fine, by either way
    let mut d = two_entries();
    out.clear();
    assert_eq!(d.decode(0, &unhex("02 00 80"), &mut out), Ok(Decoded::Done { within_limit: true }));
    assert_eq!(out, vec![f(":authority", "www.example.com")]);
    // a base below the required count (the sign bit set, delta 0: base 0): post-base index 0 is entry 0, and 1 is the one that was not asked for
    let mut d = two_entries();
    out.clear();
    assert_eq!(d.decode(0, &unhex("02 80 10"), &mut out), Ok(Decoded::Done { within_limit: true }));
    assert_eq!(out, vec![f(":authority", "www.example.com")]);
    assert!(matches!(d.decode(4, &unhex("02 80 11"), &mut out), Err(Error::Decompression(_))));
}

#[test]
fn a_duplicate_is_read_with_a_five_bit_prefix() {
    // twenty entries (k0 to k19, each with the value v), then Duplicate of the entry 16 back from the newest: k3
    let mut d = decoder();
    let mut bytes = vec![0x3f, 0xe1, 0x1f];
    for i in 0..20 {
        let name = format!("k{i}");
        bytes.push(0x40 | name.len() as u8);
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&[1, b'v']);
    }
    bytes.push(0x10);
    d.encoder_stream(&bytes).unwrap();
    assert_eq!(d.insert_count(), 21);
    // (a section that needs all 21: written 22; the newest entry, relative index 0)
    let got = decode_ok(&mut d, 0, &unhex("16 00 80"));
    assert_eq!(got, vec![f("k3", "v")]);
}

#[test]
fn a_section_may_have_no_lines() {
    let mut d = two_entries();
    assert_eq!(decode_ok(&mut d, 0, &unhex("0000")), []);
    // (it refers to nothing, though it declares what it needs: the table is ahead of that, so it is read at once)
    assert_eq!(decode_ok(&mut d, 4, &unhex("0300")), []);
    assert_eq!(d.take_output(), unhex("84"), "a section that declares entries is acknowledged, used or not");
}

#[test]
fn too_many_blocked_streams_are_an_error() {
    let mut d = Decoder::new(4096, 2, 1 << 20);
    let mut out = vec![];
    // required 3 (encoded 4), base 3: nothing is there yet
    for stream in [0, 4] {
        assert_eq!(d.decode(stream, &unhex("04 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 3 }));
    }
    // the same stream again is the same stream
    assert_eq!(d.decode(4, &unhex("04 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 3 }));
    assert_eq!(d.blocked_streams(), 2);
    assert_eq!(d.decode(8, &unhex("04 00 80"), &mut out), Err(Error::Decompression("more blocked streams than were allowed")));
    // none at all, when the decoder said none
    let mut d = Decoder::new(4096, 0, 1 << 20);
    assert!(d.decode(0, &unhex("04 00 80"), &mut out).is_err());
}

#[test]
fn a_stream_that_has_what_it_waited_for_is_not_counted_as_blocked() {
    // one blocked stream is allowed. Stream 0 waits for the first entry; when that arrives it is no longer blocked, though it has
    // not been tried again, so stream 4, which waits for the second, is the one blocked stream and not a second.
    let mut d = Decoder::new(4096, 1, 1 << 20);
    let mut out = vec![];
    assert_eq!(d.decode(0, &unhex("02 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 1 }));
    assert_eq!(d.blocked_streams(), 1);
    d.encoder_stream(&unhex("3fbd01 c00f 7777772e6578616d706c652e636f6d")).unwrap();
    assert_eq!(d.blocked_streams(), 0);
    assert_eq!(d.decode(4, &unhex("03 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 2 }));
    assert_eq!(d.blocked_streams(), 1);
    // and a third, with the second still waiting, is one too many
    assert_eq!(d.decode(8, &unhex("03 00 80"), &mut out), Err(Error::Decompression("more blocked streams than were allowed")));
}

#[test]
fn a_section_may_wait_for_as_many_entries_as_the_table_could_hold_at_once() {
    // A table of 64 bytes holds 2 entries at the most (32 bytes each, an empty name and value), so the Required Insert Count is
    // written modulo 4. A section that waits for entries the decoder has not got is the hard case of the unwrapping: when it needs
    // exactly as many more than have come as the table could ever hold, its count equals the largest value there could be.
    let mut d = Decoder::new(64, 100, 1 << 20);
    let mut out = vec![];
    // nothing in; the section needs 2 (written 3)
    assert_eq!(d.decode(0, &unhex("03 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 2 }));
    // one in; it needs 3 (written 4)
    d.encoder_stream(&unhex("3f21 4000")).unwrap();
    assert_eq!(d.insert_count(), 1);
    assert_eq!(d.decode(4, &unhex("04 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 3 }));
    // two in; it needs 4 (written 1: the count has gone round)
    d.encoder_stream(&unhex("4000")).unwrap();
    assert_eq!(d.insert_count(), 2);
    assert_eq!(d.decode(8, &unhex("01 00 80"), &mut out), Ok(Decoded::Blocked { required_insert_count: 4 }));
    // (written 2, the count has gone round and it is a section for the first entry, which is there)
    out.clear();
    assert_eq!(d.decode(12, &unhex("02 00 80"), &mut out), Ok(Decoded::Done { within_limit: true }));
    assert_eq!(out, vec![f("", "")]);
}

#[test]
fn a_blocked_section_is_decoded_when_what_it_needs_has_come() {
    let mut d = decoder();
    let mut out = vec![];
    // the section of stream 4 of the appendix, before the instructions that make its entries
    assert_eq!(d.decode(4, &unhex("0381 10 11"), &mut out), Ok(Decoded::Blocked { required_insert_count: 2 }));
    d.encoder_stream(&unhex("3fbd01 c00f 7777772e6578616d706c652e636f6d")).unwrap();
    assert_eq!(d.decode(4, &unhex("0381 10 11"), &mut out), Ok(Decoded::Blocked { required_insert_count: 2 }));
    assert_eq!(d.blocked_streams(), 1);
    d.encoder_stream(&unhex("c10c 2f73616d706c652f70617468")).unwrap();
    assert_eq!(decode_ok(&mut d, 4, &unhex("0381 10 11")).len(), 2);
    assert_eq!(d.blocked_streams(), 0);
}

#[test]
fn the_decoder_refuses_instructions_that_cannot_be_carried_out() {
    for (why, wire) in [
        ("a capacity over what the decoder allows", "3fe21f"),
        ("an entry that does not fit the table (it has no capacity yet)", "4161 0162"),
        ("a name reference to a static entry that does not exist", "3fbd01 ff24 01 78"),
        ("a name reference to a dynamic entry that is not there", "3fbd01 8000"),
        ("a duplicate of an entry that is not there", "3fbd01 02"),
        ("a Huffman string that does not decode", "3fbd01 c0 81ff"),
        ("a string longer than any entry could be", "3fbd01 c0 7fffff01"),
        ("an integer over 62 bits", "3fbd01 c0 ff ffffffffffffffffff 7f"),
    ] {
        let mut d = decoder();
        let r = d.encoder_stream(&unhex(wire));
        assert!(matches!(r, Err(Error::EncoderStream(_))), "{why} ({wire}): {r:?}");
    }
    // an entry bigger than the capacity, though it is not 0
    let mut d = decoder();
    let mut wire = unhex("2a"); // capacity 10
    wire.extend(unhex("4161 0162"));
    assert!(matches!(d.encoder_stream(&wire), Err(Error::EncoderStream(_))));
}

#[test]
fn shrinking_the_capacity_evicts() {
    let mut d = two_entries();
    d.encoder_stream(&unhex("3a")).unwrap(); // capacity 26: nothing fits
    assert_eq!(d.table_state(), (0, 0));
    assert_eq!(d.insert_count(), 2);
    // and what was evicted is gone, not renumbered
    let mut out = vec![];
    assert!(d.decode(0, &unhex("0381 10"), &mut out).is_err());
}

#[test]
fn a_header_list_over_the_limit_is_read_to_its_end() {
    let mut d = Decoder::new(4096, 100, 100);
    let mut block = vec![0, 0];
    // three fields of 3+3+32 = 38: two fit, the third does not; then one that does not fit either; then a short one is still not
    // let in (the list is over the limit)
    for v in ["aaa", "bbb", "ccc", "ddd"] {
        block.push(0x20 | 3); // literal name, 3 bytes, no Huffman
        block.extend(b"xyz");
        block.push(3);
        block.extend(v.as_bytes());
    }
    let mut out = vec![];
    assert_eq!(d.decode(0, &block, &mut out), Ok(Decoded::Done { within_limit: false }));
    assert_eq!(out, [f("xyz", "aaa"), f("xyz", "bbb")]);
    // a value larger than the limit by itself
    let mut block = vec![0, 0, 0x51];
    put_int(&mut block, 7, 0, 300);
    block.extend(vec![b'v'; 300]);
    block.extend(unhex("d1")); // and :method GET after it
    let mut out = vec![];
    assert_eq!(d.decode(0, &block, &mut out), Ok(Decoded::Done { within_limit: false }));
    assert_eq!(out, [f(":method", "GET")]);
}

#[test]
fn many_lines_naming_a_large_entry_cost_nothing_beyond_the_limit() {
    // the table holds one entry of about 4 kB and the limit is 1 kB: a block of 100000 one-byte references is read, and nothing is
    // kept (this is quick because no copy of the entry is made for a line that is over the limit)
    let mut d = Decoder::new(4096, 100, 1024);
    let value = vec![b'x'; 4000];
    let mut ins = vec![];
    put_int(&mut ins, 5, 0x20, 4096);
    put_string(&mut ins, 6, 0x40, b"big");
    put_string(&mut ins, 8, 0, &value);
    d.encoder_stream(&ins).unwrap();
    let mut block = vec![0x02, 0x00]; // required 1 (encoded 2), base 1
    block.extend(vec![0x80; 100_000]);
    let start = std::time::Instant::now();
    let mut out = vec![];
    assert_eq!(d.decode(0, &block, &mut out), Ok(Decoded::Done { within_limit: false }));
    assert!(out.is_empty());
    assert!(start.elapsed() < std::time::Duration::from_secs(1), "{:?}", start.elapsed());
}

// ---------------------------------------------------------------------------------------------------- the encoder and the decoder

/// One encoder and one decoder joined by links that deliver everything at once and in order.
struct Link {
    enc: Encoder,
    dec: Decoder,
}

impl Link {
    fn new(cfg: EncoderConfig, decoder_capacity: usize, decoder_blocked: usize) -> Link {
        let mut enc = Encoder::new(cfg);
        enc.set_peer_settings(decoder_capacity as u64, decoder_blocked as u64);
        Link { enc, dec: Decoder::new(decoder_capacity, decoder_blocked, 1 << 20) }
    }

    /// Sends a request, delivers the encoder stream first and the acknowledgment after; returns the bytes of the section.
    fn send(&mut self, stream: u64, fields: &[Field]) -> Vec<u8> {
        let mut block = vec![];
        self.enc.encode(stream, &refs(fields), &mut block);
        self.dec.encoder_stream(&self.enc.take_output()).unwrap();
        assert_eq!(decode_ok(&mut self.dec, stream, &block), fields);
        self.enc.decoder_stream(&self.dec.take_output()).unwrap();
        harness::tables_agree(&self.enc, &self.dec);
        block
    }
}

fn request(path: &str) -> Vec<Field> {
    vec![
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "api.example.com"),
        f(":path", path),
        f("user-agent", "pratique/0.1"),
        f("accept", "*/*"),
        f("accept-encoding", "gzip, deflate"),
        f("x-request-id", "7f3a9c"),
    ]
}

#[test]
fn with_no_dynamic_table_the_encoder_uses_none() {
    let mut link = Link::new(EncoderConfig::default(), 0, 0);
    let block = link.send(0, &request("/a"));
    assert_eq!(&block[..2], [0, 0], "required insert count 0, base 0");
    assert!(link.enc.take_output().is_empty());
    assert_eq!(link.enc.table_state(), (0, 0));
    // and the same when the peer allows one and the encoder is told not to
    let mut link = Link::new(EncoderConfig { table_capacity: 0, ..EncoderConfig::default() }, 4096, 16);
    link.send(0, &request("/a"));
    assert_eq!(link.enc.table_state(), (0, 0));
}

#[test]
fn until_the_peers_settings_are_known_nothing_is_inserted() {
    let mut enc = Encoder::new(EncoderConfig::default());
    let mut block = vec![];
    enc.encode(0, &refs(&request("/a")), &mut block);
    assert!(enc.take_output().is_empty());
    assert_eq!(&block[..2], [0, 0]);
}

#[test]
fn what_was_acknowledged_is_used_by_the_next_request() {
    let mut link = Link::new(EncoderConfig::default(), 4096, 16);
    let first = link.send(0, &request("/a"));
    assert_eq!(&first[..2], [0, 0], "the first request refers to nothing that is not acknowledged, so no stream waits");
    // user-agent, :authority and accept-encoding were put in the table: the safe names of this request that are not in the static table
    assert_eq!(link.enc.table_state().0, 3);
    let second = link.send(4, &request("/b"));
    assert!(second.len() < first.len() - 20, "{} then {}", first.len(), second.len());
    assert_ne!(second[0], 0, "it names entries");
    assert_eq!(link.enc.table_state().0, 3, "and inserts nothing more: they are all there");
    // the encoder says nothing on its stream for a request like the second
    assert!(link.enc.take_output().is_empty());
    assert_eq!(link.enc.blocked_count(), 0);
    // with the entries in the table the decoder's acknowledgment of the section is all it sends
    assert_eq!(link.enc.outstanding.len(), 0);
}

#[test]
fn nothing_but_the_safe_names_is_inserted_unless_asked() {
    let mut link = Link::new(EncoderConfig::default(), 4096, 16);
    link.send(0, &[f("x-secret-ish", "abc"), f("cookie", "a=b"), f("authorization", "Bearer x")]);
    assert_eq!(link.enc.table_state(), (0, 0));
    let mut link = Link::new(EncoderConfig { only_safe_names: false, ..EncoderConfig::default() }, 4096, 16);
    link.send(0, &[f("x-secret-ish", "abc"), f("cookie", "a=b")]);
    assert_eq!(link.enc.table_state().0, 2);
}

#[test]
fn a_sensitive_field_is_never_put_in_the_table_and_is_marked() {
    let mut enc = Encoder::new(EncoderConfig { only_safe_names: false, ..EncoderConfig::default() });
    enc.set_peer_settings(4096, 16);
    let mut dec = decoder();
    for (name, value) in [("authorization", "Bearer abc"), ("x-token", "t0ken")] {
        let mut block = vec![];
        enc.encode(0, &[FieldRef { name: name.as_bytes(), value: value.as_bytes(), sensitive: true }], &mut block);
        assert!(enc.take_output().is_empty(), "{name}");
        assert_eq!(&block[..2], [0, 0]);
        assert_ne!(block[2] & 0x20, 0, "{name}: the N bit says no one in between may index it");
        let mut out = vec![];
        assert_eq!(dec.decode(0, &block, &mut out), Ok(Decoded::Done { within_limit: true }));
        assert_eq!(out, [f(name, value)]);
    }
    assert_eq!(enc.table_state(), (0, 0));
}

#[test]
fn a_field_with_a_value_that_was_inserted_is_not_inserted_twice() {
    let mut link = Link::new(EncoderConfig::default(), 4096, 16);
    // two requests before the first is acknowledged: build both, deliver after
    let mut enc_wire = vec![];
    let mut blocks = vec![];
    for stream in [0, 4] {
        let mut b = vec![];
        link.enc.encode(stream, &refs(&request("/a")), &mut b);
        enc_wire.extend(link.enc.take_output());
        blocks.push(b);
    }
    assert_eq!(link.enc.table_state().0, 3, "three entries, not six");
    link.dec.encoder_stream(&enc_wire).unwrap();
    for (i, b) in blocks.iter().enumerate() {
        assert_eq!(decode_ok(&mut link.dec, 4 * i as u64, b), request("/a"));
    }
}

#[test]
fn a_stream_may_wait_only_if_the_encoder_is_set_to_let_it() {
    let cfg = EncoderConfig { blocked_streams: 2, ..EncoderConfig::default() };
    let mut link = Link::new(cfg, 4096, 16);
    let mut wire = vec![];
    let mut blocks = vec![];
    for stream in [0, 4, 8] {
        let mut b = vec![];
        link.enc.encode(stream, &refs(&request("/a")), &mut b);
        wire.push(link.enc.take_output());
        blocks.push(b);
    }
    assert_ne!(blocks[0][0], 0, "the first refers to what it inserts");
    assert_ne!(blocks[1][0], 0, "and so does the second");
    assert_eq!(blocks[2][0], 0, "the third would be a third stream waiting: it is all literals and static");
    assert_eq!(link.enc.blocked_count(), 2);
    // the sections arrive before the encoder stream: they wait
    let mut out = vec![];
    assert_eq!(link.dec.decode(0, &blocks[0], &mut out), Ok(Decoded::Blocked { required_insert_count: 3 }));
    for w in &wire {
        link.dec.encoder_stream(w).unwrap();
    }
    for (i, b) in blocks.iter().enumerate() {
        assert_eq!(decode_ok(&mut link.dec, 4 * i as u64, b), request("/a"));
    }
    link.enc.decoder_stream(&link.dec.take_output()).unwrap();
    assert_eq!(link.enc.blocked_count(), 0);
}

#[test]
fn the_peers_limit_on_blocked_streams_is_kept_whatever_the_encoder_is_set_to() {
    let cfg = EncoderConfig { blocked_streams: 100, ..EncoderConfig::default() };
    let mut link = Link::new(cfg, 4096, 1);
    let mut b = vec![];
    link.enc.encode(0, &refs(&request("/a")), &mut b);
    let mut b2 = vec![];
    link.enc.encode(4, &refs(&request("/a")), &mut b2);
    assert_ne!(b[0], 0);
    assert_eq!(b2[0], 0);
    assert_eq!(link.enc.blocked_count(), 1);
}

#[test]
fn a_table_that_is_full_makes_room_only_with_what_the_decoder_has_acknowledged() {
    // capacity 220 holds three entries of 71
    let cfg = EncoderConfig { table_capacity: 220, ..EncoderConfig::default() };
    let mut link = Link::new(cfg, 4096, 16);
    for (i, ua) in ["agent-aaaaaaaaaaaaaaaaaaaaaaa", "agent-bbbbbbbbbbbbbbbbbbbbbbb", "agent-ccccccccccccccccccccccc", "agent-ddddddddddddddddddddddd", "agent-eeeeeeeeeeeeeeeeeeeeeeee"].iter().enumerate() {
        link.send(4 * i as u64, &[f(":method", "GET"), f("user-agent", ua)]);
        assert!(link.enc.table_state().1 <= 220);
    }
    assert_eq!(link.enc.table_state().0, 3);
    // the newest agent is there, the oldest was evicted
    let block = link.send(40, &[f("user-agent", "agent-eeeeeeeeeeeeeeeeeeeeeeee")]);
    assert!(block.len() < 6, "{block:?}");
    // now the decoder's acknowledgments are held back: the encoder inserts nothing it would have to evict for
    let mut wire = vec![];
    let mut blocks = vec![];
    for (i, ua) in ["agent-1111111111111111111111", "agent-2222222222222222222222", "agent-3333333333333333333333", "agent-4444444444444444444444"].iter().enumerate() {
        let mut b = vec![];
        link.enc.encode(100 + 4 * i as u64, &refs(&[f("user-agent", ua)]), &mut b);
        wire.extend(link.enc.take_output());
        blocks.push((100 + 4 * i as u64, b, ua));
    }
    link.dec.encoder_stream(&wire).unwrap();
    for (stream, b, ua) in &blocks {
        assert_eq!(decode_ok(&mut link.dec, *stream, b), [f("user-agent", ua)]);
    }
    harness::tables_agree(&link.enc, &link.dec);
    assert!(link.enc.table_state().1 <= 220);
    link.enc.decoder_stream(&link.dec.take_output()).unwrap();
    link.send(200, &[f("user-agent", "agent-5555555555555555555555")]);
}

#[test]
fn the_capacity_announced_is_the_peers_maximum_and_the_encoder_keeps_to_less() {
    // ls-qpack (LiteSpeed, aioquic) counts the entries a Required Insert Count wraps around from the capacity it was last given
    // instead of the maximum it announced; the two are the same when the encoder announces the maximum
    let cfg = EncoderConfig { table_capacity: 300, ..EncoderConfig::default() };
    let mut link = Link::new(cfg, 1024, 16);
    link.send(0, &request("/a"));
    assert_eq!(link.dec.table.capacity, 1024);
    for i in 0..50 {
        link.send(4 + 4 * i, &[f("user-agent", &format!("agent-number-{i:04}-xxxxxxxxxxxxxxxxxxxxxxxx"))]);
        assert!(link.enc.table_state().1 <= 300);
        assert!(link.dec.table_state().1 <= 1024);
    }
    // the decoder holds more than the encoder lets itself use
    assert!(link.dec.table_state().1 > 300);
}

#[test]
fn an_entry_that_a_section_refers_to_is_not_evicted_by_the_same_section() {
    // the table has room for two entries; the section refers to the first and then inserts a second and a third
    let cfg = EncoderConfig { table_capacity: 150, only_safe_names: false, ..EncoderConfig::default() };
    let mut link = Link::new(cfg, 4096, 16);
    link.send(0, &[f("x-a", "1111111111111111111111")]);
    link.send(4, &[f("x-b", "2222222222222222222222")]);
    assert_eq!(link.enc.table_state().0, 2);
    link.send(8, &[f("x-a", "1111111111111111111111"), f("x-c", "3333333333333333333333"), f("x-d", "4444444444444444444444")]);
}

#[test]
fn an_acknowledgment_that_does_not_fit_is_an_error() {
    let mut enc = Encoder::new(EncoderConfig::default());
    enc.set_peer_settings(4096, 16);
    assert_eq!(enc.decoder_stream(&unhex("84")), Err(Error::DecoderStream("an acknowledgment of a stream with no section waiting")));
    let mut enc = Encoder::new(EncoderConfig::default());
    assert_eq!(enc.decoder_stream(&unhex("00")), Err(Error::DecoderStream("an insert count increment of 0")));
    assert_eq!(enc.decoder_stream(&unhex("01")), Err(Error::DecoderStream("an insert count increment beyond what was sent")));
    // cancelling a stream with nothing outstanding is allowed
    let mut enc = Encoder::new(EncoderConfig::default());
    assert_eq!(enc.decoder_stream(&unhex("48")), Ok(()));
    // and the decoder stream may come in pieces
    let mut enc = Encoder::new(EncoderConfig::default());
    assert_eq!(enc.decoder_stream(&unhex("ff")), Ok(()));
    assert_eq!(enc.decoder_stream(&unhex("7f")), Err(Error::DecoderStream("an acknowledgment of a stream with no section waiting")));
}

#[test]
fn a_cancelled_stream_frees_what_it_held() {
    let cfg = EncoderConfig { blocked_streams: 4, ..EncoderConfig::default() };
    let mut enc = Encoder::new(cfg);
    enc.set_peer_settings(4096, 16);
    let mut b = vec![];
    enc.encode(0, &refs(&request("/a")), &mut b);
    assert!(enc.table.entries.iter().all(|e| e.refs == 1));
    enc.decoder_stream(&unhex("40")).unwrap();
    assert!(enc.table.entries.iter().all(|e| e.refs == 0));
    assert_eq!(enc.blocked_count(), 0);
}

// ---------------------------------------------------------------------------------------------------- a random exchange

#[test]
fn random_exchanges_decode_to_what_was_encoded() {
    // sections are made, delivered late and out of step with the encoder stream (so some wait), the acknowledgments come late,
    // some streams are abandoned (see `harness::exchange`)
    let mut total = harness::Stats::default();
    for seed in 1..=600u64 {
        let s = harness::exchange(&mut harness::Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1), 300);
        total.waited += s.waited;
        total.evicted += s.evicted;
        total.inserted += s.inserted;
    }
    // (that the exchanges did what they are for: sections waited, the table was cycled through, entries were inserted)
    assert!(total.waited > 100 && total.evicted > 1000 && total.inserted > 5000, "{total:?}");
}

// ---------------------------------------------------------------------------------------------------- against ls-qpack

enum Event {
    Enc(Vec<u8>),
    Block { stream: u64, block: Vec<u8>, fields: Vec<Field> },
    Cancel(u64),
}

/// The sessions of a fixture of `tools/qpack_interop.py`: the decoder's capacity and blocked streams, and what happened.
fn parse_fixture(text: &str) -> Vec<(usize, usize, Vec<Event>)> {
    let mut sessions: Vec<(usize, usize, Vec<Event>)> = vec![];
    for line in text.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        let unhex_or_empty = |s: &str| if s == "-" { vec![] } else { unhex(s) };
        match w.first().copied() {
            Some("session") => sessions.push((w[1].parse().unwrap(), w[2].parse().unwrap(), vec![])),
            Some("enc") => sessions.last_mut().unwrap().2.push(Event::Enc(unhex_or_empty(w[1]))),
            Some("block") => sessions.last_mut().unwrap().2.push(Event::Block { stream: w[1].parse().unwrap(), block: unhex_or_empty(w[2]), fields: vec![] }),
            Some("field") => {
                if let Some(Event::Block { fields, .. }) = sessions.last_mut().unwrap().2.last_mut() {
                    fields.push(Field { name: unhex_or_empty(w[1]), value: unhex_or_empty(w[2]) });
                }
            }
            Some("cancel") => sessions.last_mut().unwrap().2.push(Event::Cancel(w[1].parse().unwrap())),
            _ => {}
        }
    }
    sessions
}

#[test]
fn decodes_what_lsqpack_encoded() {
    // tests/data/qpack_lsqpack.txt was recorded by `tools/qpack_interop.py --record` while ls-qpack 0.3.24 (pylsqpack) encoded
    // random field lists for this decoder, with the decoder's acknowledgments going back to it: capacities from 0 to 4096, 0
    // to 16 blocked streams, sections that came before the instructions they needed, streams that were abandoned
    let sessions = parse_fixture(include_str!("../../../tests/data/qpack_lsqpack.txt"));
    assert_eq!(sessions.len(), 40);
    let (mut sections, mut waited, mut evicted, mut inserted) = (0, 0, 0, 0);
    for (i, (capacity, blocked, events)) in sessions.iter().enumerate() {
        let mut dec = Decoder::new(*capacity, *blocked, 1 << 20);
        let mut pending: Vec<(u64, &[u8], &[Field])> = vec![];
        let try_decode = |dec: &mut Decoder, stream: u64, block: &[u8], fields: &[Field]| -> bool {
            let mut out = vec![];
            match dec.decode(stream, block, &mut out) {
                Ok(Decoded::Done { within_limit }) => {
                    assert!(within_limit);
                    assert_eq!(out, fields, "session {i}, stream {stream}");
                    true
                }
                Ok(Decoded::Blocked { .. }) => false,
                Err(e) => panic!("session {i}, stream {stream}: {e}"),
            }
        };
        for event in events {
            match event {
                Event::Enc(bytes) => {
                    dec.encoder_stream(bytes).unwrap_or_else(|e| panic!("session {i}: {e}"));
                    let mut still = vec![];
                    for (stream, block, fields) in std::mem::take(&mut pending) {
                        if try_decode(&mut dec, stream, block, fields) {
                            sections += 1;
                        } else {
                            still.push((stream, block, fields));
                        }
                    }
                    pending = still;
                }
                Event::Block { stream, block, fields } => {
                    if try_decode(&mut dec, *stream, block, fields) {
                        sections += 1;
                    } else {
                        waited += 1;
                        pending.push((*stream, block, fields));
                    }
                }
                Event::Cancel(stream) => {
                    pending.retain(|p| p.0 != *stream);
                    dec.cancel_stream(*stream);
                }
            }
            assert!(dec.blocked_streams() <= *blocked);
        }
        assert!(pending.is_empty(), "session {i}: sections are still waiting");
        evicted += dec.table.dropped;
        inserted += dec.insert_count();
    }
    // (that the fixture has what it is for)
    assert!(sections > 500 && waited > 40 && evicted > 20 && inserted > 150, "{sections} {waited} {evicted} {inserted}");
}

/// A peer that `tools/qpack_interop.py` talks to over standard input and output, one line a command, so that ls-qpack (through
/// pylsqpack) can be the other end of a live exchange in both directions: its encoder with our decoder, our encoder with its
/// decoder. (Everything it does is what the library does; this only moves bytes in and out as hexadecimal.)
///
///     init DEC_CAP DEC_BLOCKED ENC_CAP ENC_BLOCKED PEER_CAP PEER_BLOCKED SAFE_ONLY  -> ok
///     enc-stream HEX            (the encoder stream, into the decoder)               -> ok | err TEXT
///     decode STREAM HEX                                                              -> done NAME/VALUE ... | blocked N | err TEXT
///     dec-out                   (what the decoder has for the decoder stream)        -> hex HEX
///     cancel STREAM                                                                  -> ok
///     encode STREAM NAME/VALUE[/s] ...                                               -> block HEX ENC HEX
///     dec-stream HEX            (the decoder stream, into the encoder)               -> ok | err TEXT
///
/// An empty string is written `-`.
#[test]
#[ignore = "driven by tools/qpack_interop.py"]
fn qpack_peer() {
    use std::io::{BufRead, Write};
    fn h(b: &[u8]) -> String {
        if b.is_empty() { "-".into() } else { b.iter().map(|x| format!("{x:02x}")).collect() }
    }
    fn u(s: &str) -> Vec<u8> {
        if s == "-" { vec![] } else { unhex(s) }
    }
    let mut enc = Encoder::new(EncoderConfig::default());
    let mut dec = decoder();
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let w: Vec<&str> = line.split_whitespace().collect();
        let reply = match w.first().copied() {
            Some("init") => {
                let n: Vec<usize> = w[1..].iter().map(|x| x.parse().unwrap()).collect();
                dec = Decoder::new(n[0], n[1], 1 << 20);
                enc = Encoder::new(EncoderConfig { table_capacity: n[2], blocked_streams: n[3], only_safe_names: n[6] != 0 });
                enc.set_peer_settings(n[4] as u64, n[5] as u64);
                "ok".to_string()
            }
            Some("enc-stream") => match dec.encoder_stream(&u(w[1])) {
                Ok(()) => "ok".into(),
                Err(e) => format!("err {e}"),
            },
            Some("decode") => {
                let mut out = vec![];
                match dec.decode(w[1].parse().unwrap(), &u(w[2]), &mut out) {
                    Ok(Decoded::Done { .. }) => {
                        let mut r = String::from("done");
                        for f in &out {
                            r += &format!(" {}/{}", h(&f.name), h(&f.value));
                        }
                        r
                    }
                    Ok(Decoded::Blocked { required_insert_count }) => format!("blocked {required_insert_count}"),
                    Err(e) => format!("err {e}"),
                }
            }
            Some("dec-out") => format!("hex {}", h(&dec.take_output())),
            Some("cancel") => {
                dec.cancel_stream(w[1].parse().unwrap());
                "ok".into()
            }
            Some("encode") => {
                let owned: Vec<(Vec<u8>, Vec<u8>, bool)> = w[2..]
                    .iter()
                    .map(|t| {
                        let p: Vec<&str> = t.split('/').collect();
                        (u(p[0]), u(p[1]), p.get(2) == Some(&"s"))
                    })
                    .collect();
                let list: Vec<FieldRef<'_>> = owned.iter().map(|(n, v, s)| FieldRef { name: n, value: v, sensitive: *s }).collect();
                let mut block = vec![];
                enc.encode(w[1].parse().unwrap(), &list, &mut block);
                format!("block {} {}", h(&block), h(&enc.take_output()))
            }
            Some("dec-stream") => match enc.decoder_stream(&u(w[1])) {
                Ok(()) => "ok".into(),
                Err(e) => format!("err {e}"),
            },
            Some("quit") => break,
            _ => format!("err unknown command {line}"),
        };
        let mut o = stdout.lock();
        writeln!(o, "@@ {reply}").unwrap();
        o.flush().unwrap();
    }
}
