//! The fuzz targets of QUIC (`src/quic/`): `quic_packet` and `quic_frame`. The QUIC layers are public, so these call them
//! directly. What must hold, whatever the bytes:
//!
//! | target        | what must hold |
//! |---------------|----------------|
//! | `quic_packet` | `data[0]` odd: a packet is made from the fields in the input, sealed, read back, opened (its packet number and payload are what went in) and not opened with one bit changed anywhere. `data[0]` even: a datagram is read as coalesced packets, every field inside its packet and each packet inside the datagram; a packet that opens with the Initial keys that anyone can make is sealed again to the same bytes |
//! | `quic_frame`  | a payload is read as frames or refused with a transport error; every frame that is read lies inside the payload, is written and read again as itself, and is allowed in the packet it was in |

use pratique::quic::frame::{self, Frame};
use pratique::quic::keys::{self, Keys};
use pratique::quic::packet::{self, PacketType};
use pratique::tls::Suite;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// Where the connection ids, the token and the other pieces begin (the headers of the packets in the dictionary).
pub const QUIC_DICT: &[&[u8]] = &[
    // the first byte and version of an Initial, a 0-RTT, a Handshake and a Retry packet, a Version Negotiation packet, a short header
    b"\xc0\x00\x00\x00\x01",
    b"\xd0\x00\x00\x00\x01",
    b"\xe0\x00\x00\x00\x01",
    b"\xf0\x00\x00\x00\x01",
    b"\x80\x00\x00\x00\x00",
    b"\x40",
    // frames: PADDING, PING, ACK (of 0; with a range; with ECN counts), CRYPTO, NEW_TOKEN, STREAM (with offset and length, with fin), MAX_DATA, ...
    b"\x00",
    b"\x01",
    b"\x02\x00\x00\x00\x00",
    b"\x02\x0a\x00\x01\x02\x02\x02",
    b"\x03\x00\x00\x00\x00\x01\x02\x03",
    b"\x06\x00\x05",
    b"\x07\x02",
    b"\x0e\x04\x10\x03",
    b"\x0b\x04\x03",
    b"\x10\x44\x00",
    // NEW_CONNECTION_ID, CONNECTION_CLOSE (of the transport; of the application), PATH_CHALLENGE, HANDSHAKE_DONE
    b"\x18\x02\x01\x08",
    b"\x1c\x0a\x06\x00",
    b"\x1d\x41\x00\x00",
    b"\x1a\x01\x02\x03\x04\x05\x06\x07\x08",
    b"\x1e",
    // a frame type in too many bytes; the largest varints
    b"\x40\x01",
    b"\xff\xff\xff\xff\xff\xff\xff\xff",
    b"\x3f\xff",
];

const CLIENT_INITIAL: &str = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
const SERVER_INITIAL: &str = "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee";
const CHACHA_PACKET: &str = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";
const RETRY: &str = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
const VERSION_NEGOTIATION: &str = "ea00000000089aac5a49ba87a84908f92f4336fa951ba14547471600000001";

/// A byte at a time from the input, zeros when it has run out.
pub struct Cursor<'a>(pub &'a [u8]);

impl<'a> Cursor<'a> {
    pub fn u8(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, self.0), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.u8()).collect()
    }
    pub fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }
}

fn inside(whole: &[u8], part: &[u8]) -> bool {
    part.is_empty() || {
        let (w, p) = (whole.as_ptr() as usize, part.as_ptr() as usize);
        p >= w && p + part.len() <= w + whole.len()
    }
}

pub fn packet(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    if sel & 1 == 0 {
        read_datagram(sel, rest);
    } else {
        build_and_read(sel, rest);
    }
}

/// A datagram of packets, the way a receiver goes through it.
fn read_datagram(sel: u8, datagram: &[u8]) {
    let short_len = (sel >> 1) as usize % 21;
    let mut rest = datagram;
    for _ in 0..64 {
        if rest.is_empty() {
            break;
        }
        let Ok(p) = packet::parse(rest, short_len) else { break };
        assert!(p.len >= 1 && p.len <= rest.len(), "a packet outside the datagram");
        for part in [p.dcid, p.scid, p.token, p.versions] {
            assert!(inside(&rest[..p.len], part), "a field outside the packet");
        }
        assert!(p.dcid.len() <= 255 && p.scid.len() <= 255);
        if p.version == 1 {
            assert!(p.dcid.len() <= packet::MAX_CID_LEN && p.scid.len() <= packet::MAX_CID_LEN);
        }
        match p.ty {
            PacketType::Initial | PacketType::ZeroRtt | PacketType::Handshake | PacketType::OneRtt => {
                assert!(p.pn_offset >= 1 && p.pn_offset < p.len, "the packet number is outside the packet");
            }
            PacketType::VersionNegotiation => assert!(!p.versions.is_empty() && p.versions.len() % 4 == 0 && packet::versions(p.versions).count() == p.versions.len() / 4),
            PacketType::Retry => {
                assert!(p.retry_tag.is_some() && p.len == rest.len());
                // (whether it is genuine is for the keys; any original destination connection id will do for no panic)
                let _ = keys::retry_is_genuine(p.scid, &rest[..p.len]);
                let _ = keys::retry_is_genuine(&[], &rest[..p.len]);
            }
        }
        if p.ty == PacketType::Initial {
            // Initial keys are the same for everyone, so a packet can be opened here, and one that is is sealed to the same bytes
            for side in 0..2 {
                let (client, server) = keys::initial_keys(p.dcid);
                let mut keys = if side == 0 { client } else { server };
                let mut copy = rest[..p.len].to_vec();
                if let Ok(o) = keys.open(&mut copy, p.pn_offset, None) {
                    assert!(o.payload.start > p.pn_offset && o.payload.end <= copy.len() - keys::TAG_LEN + 0 && o.payload.start <= o.payload.end);
                    let pn_len = (o.first & 3) as usize + 1;
                    assert_eq!(o.payload.start, p.pn_offset + pn_len);
                    let mut again = copy[..o.payload.end].to_vec();
                    let (client, server) = keys::initial_keys(p.dcid);
                    let mut keys = if side == 0 { client } else { server };
                    keys.seal(&mut again, p.pn_offset, pn_len, o.pn).expect("a packet that opened has the room for a sample");
                    assert_eq!(again, &rest[..p.len], "an Initial packet that opened is not sealed to what it was");
                }
            }
        }
        rest = &rest[p.len..];
    }
}

/// A packet made from the input.
fn build_and_read(sel: u8, data: &[u8]) {
    let mut c = Cursor(data);
    let long = sel & 2 != 0;
    let ty = match (sel >> 2) & 3 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::OneRtt,
    };
    let ty = if long && ty == PacketType::OneRtt { PacketType::Initial } else if !long { PacketType::OneRtt } else { ty };
    let dcid_len = c.u8() as usize % 21;
    let scid_len = c.u8() as usize % 21;
    let token_len = c.u8() as usize % 40;
    let pn_len = 1 + (c.u8() as usize % 4);
    let suite = Suite::ALL[c.u8() as usize % 3];
    let flip = c.u64();
    let pn = c.u64() & ((1 << 62) - 1);
    let dcid = c.take(dcid_len);
    let scid = c.take(scid_len);
    let token = if ty == PacketType::Initial { c.take(token_len) } else { Vec::new() };
    let secret = c.take(suite.hash().output_len().min(48));
    let mut secret = secret;
    secret.resize(suite.hash().output_len(), 7);
    let payload = c.0.to_vec();

    let mut out = Vec::new();
    let pn_offset;
    if long {
        let h = packet::write_long_header(&mut out, ty, &dcid, &scid, &token, pn, pn_len);
        out.extend_from_slice(&payload);
        packet::finish_long(&mut out, h, keys::TAG_LEN);
        pn_offset = h.pn_offset;
    } else {
        pn_offset = packet::write_short_header(&mut out, &dcid, flip & 1 == 1, flip & 2 == 2, pn, pn_len);
        out.extend_from_slice(&payload);
    }
    let clear = out.clone();
    let mut sealer = Keys::new(suite, &secret);
    let sealed = sealer.seal(&mut out, pn_offset, pn_len, pn);
    // (a payload that is too short for a sample is refused, and no other)
    assert_eq!(sealed.is_err(), payload.len() + pn_len < 4, "a refusal to seal that is not for a payload that is too short");
    if sealed.is_err() {
        assert_eq!(out, clear, "a refused packet is changed");
        return;
    }
    assert_eq!(out.len(), clear.len() + keys::TAG_LEN);

    let p = packet::parse(&out, dcid.len()).expect("a packet we made is read");
    assert_eq!((p.ty, p.dcid, p.pn_offset, p.len), (ty, &dcid[..], pn_offset, out.len()));
    if long {
        assert_eq!((p.scid, p.token, p.version), (&scid[..], &token[..], 1));
    }
    let mut opener = Keys::new(suite, &secret);
    let mut copy = out.clone();
    let o = opener.open(&mut copy, pn_offset, pn.checked_sub(1)).expect("a packet we sealed is opened");
    assert_eq!(o.pn, pn);
    assert_eq!(o.first, clear[0]);
    assert_eq!(&copy[o.payload.clone()], &payload[..]);
    assert_eq!(&copy[..o.payload.start], &clear[..pn_offset + pn_len]);

    // and not with one bit changed
    let bit = (flip >> 2) as usize % (out.len() * 8);
    let mut bad = out.clone();
    bad[bit / 8] ^= 1 << (bit % 8);
    assert!(Keys::new(suite, &secret).open(&mut bad, pn_offset, pn.checked_sub(1)).is_err(), "a packet with bit {bit} changed is opened");
}

pub fn frame(data: &[u8]) {
    let Some((&sel, payload)) = data.split_first() else { return };
    let ty = [PacketType::Initial, PacketType::Handshake, PacketType::ZeroRtt, PacketType::OneRtt][(sel & 3) as usize];
    let mut count = 0;
    for f in frame::frames(payload, ty) {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                assert!(e.transport_error() == frame::FRAME_ENCODING_ERROR || e.transport_error() == frame::PROTOCOL_VIOLATION);
                assert!(!e.to_string().is_empty());
                break;
            }
        };
        count += 1;
        assert!(count <= payload.len(), "more frames than bytes");
        assert!(frame::allowed_in(f.frame_type(), ty), "a frame that the packet may not have");
        match f {
            Frame::Crypto { data, .. } | Frame::Stream { data, .. } => assert!(inside(payload, data)),
            Frame::NewToken { token } => assert!(inside(payload, token) && !token.is_empty()),
            Frame::NewConnectionId { cid, reset_token, .. } => assert!(inside(payload, cid) && inside(payload, &reset_token[..]) && (1..=20).contains(&cid.len())),
            Frame::ConnectionClose { reason, .. } => assert!(inside(payload, reason)),
            Frame::Ack(a) => {
                let mut next_above = None::<u64>;
                let mut n = 0u64;
                for r in a.ranges() {
                    assert!(r.start() <= r.end());
                    if let Some(above) = next_above {
                        assert!(r.end() + 2 <= above, "ranges of an ACK touch");
                    }
                    next_above = Some(*r.start());
                    n += 1;
                }
                assert_eq!(n, a.additional_ranges() + 1);
                assert!(a.acknowledges(a.largest) && !a.acknowledges(a.largest.saturating_add(1)) || a.largest == (1 << 62) - 1);
            }
            _ => {}
        }
        // written and read again as itself
        let mut w = Vec::new();
        f.write(&mut w);
        assert_eq!(w.len(), f.len());
        let back: Vec<_> = frame::frames(&w, ty).collect();
        assert_eq!(back.len(), 1, "a frame that is written is not one frame");
        assert_eq!(back[0], Ok(f), "a frame that is written is not read again as itself");
    }
}

pub fn seeds_packet() -> Vec<Vec<u8>> {
    let with = |sel: u8, hex: &str| {
        let mut v = vec![sel];
        v.extend(unhex(hex));
        v
    };
    let mut seeds = vec![
        // read: a client Initial, a server Initial, a coalesced pair, a short header packet with no connection id, a Retry, a Version Negotiation
        with(0, CLIENT_INITIAL),
        with(0, SERVER_INITIAL),
        with(0, &format!("{SERVER_INITIAL}{CHACHA_PACKET}")),
        with(0, CHACHA_PACKET),
        with(0, RETRY),
        with(0, VERSION_NEGOTIATION),
        with(16, "5db01fd24a586a9cf33dec094aaec6d6b4b7a5e15f5a3f05d06cf1ad0355c19dcce0807eecf7bf1c844a66e1ecd1f74b2a2d69bfd25d217833edd973246597bd5107ea15cb1e210045396afa602fe23432f4ab24ce251b"),
    ];
    // built: each kind of packet, with a payload of a PING and of nothing, each pn length, each suite
    for sel in [1u8, 3, 5, 7, 9, 11, 13, 15, 17, 23] {
        seeds.push(vec![sel, 8, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 77, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 6, 0, 3, 1, 2, 3]);
        seeds.push(vec![sel, 0, 0, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 1, 0]);
    }
    seeds
}

pub fn seeds_frame() -> Vec<Vec<u8>> {
    // the frames that quic-go wrote (`src/quic/vectors_quicgo_frames.txt`), as 1-RTT payloads, and the same as Initial ones
    let mut seeds = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in include_str!("../../src/quic/vectors_quicgo_frames.txt").lines() {
        let mut parts = line.splitn(3, ' ');
        let head = parts.next().unwrap();
        let payload = unhex(parts.next().unwrap());
        if head != "1V" || !seen.insert(payload.clone()) {
            continue;
        }
        let mut v = vec![3u8];
        v.extend_from_slice(&payload);
        seeds.push(v);
    }
    seeds
}
