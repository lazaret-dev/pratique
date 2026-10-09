//! QUIC packet headers (RFC 9000 section 17): telling what a packet in a datagram is without any key (its type, its
//! connection ids, where its packet number begins and where it ends), and writing the headers of the packets we send.
//!
//! The first byte and the packet number of a packet are protected (see [`keys`](super::keys)); what is read here is what is
//! not: the form, the version and the connection ids, the token and the length of a long header. Where the packet number
//! begins is known from them, and so is where the packet ends, which is how packets that were put in one datagram one after
//! the other (RFC 9000 section 12.2) are told apart.
//!
//! Version 1 only. A long header of another version is [`ParseError::UnsupportedVersion`] (a client drops it), except
//! Version Negotiation, which is version 0 and is read.

use super::wire::{get_varint, patch_length, put_varint_len, Reader, Truncated};

/// QUIC version 1 (RFC 9000).
pub const VERSION_1: u32 = 1;

/// The longest connection id in version 1.
pub const MAX_CID_LEN: usize = 20;

/// The length of the integrity tag at the end of a Retry packet.
pub const RETRY_TAG_LEN: usize = 16;

/// What a packet is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    /// A short header packet, which carries 1-RTT data.
    OneRtt,
}

/// A packet in a datagram, as far as it can be read without keys. Nothing in it is checked beyond what its shape needs: whether
/// it is genuine is for the keys to say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Packet<'a> {
    pub ty: PacketType,
    /// The version in a long header (0 for Version Negotiation); 0 in a short header, which has none.
    pub version: u32,
    pub dcid: &'a [u8],
    /// Empty in a short header, which has none.
    pub scid: &'a [u8],
    /// The token of an Initial packet; the retry token of a Retry packet.
    pub token: &'a [u8],
    /// The versions a Version Negotiation packet lists, 4 bytes each (a multiple of 4 bytes).
    pub versions: &'a [u8],
    /// The integrity tag of a Retry packet.
    pub retry_tag: Option<&'a [u8; RETRY_TAG_LEN]>,
    /// Where the packet number begins, from the start of the packet (for a packet that has one).
    pub pn_offset: usize,
    /// How many bytes of the datagram the packet takes: all that is left of it for a short header packet, a Retry
    /// packet or Version Negotiation, and what its Length field says (and the header) for the other long header packets.
    pub len: usize,
}

/// Why a packet cannot be read. A datagram with a packet like this in it is dropped (RFC 9000 section 5.2.2 and 12.2): what
/// follows such a packet in the datagram cannot be told where it begins.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// The datagram ends in the middle of a field, or before the end of what the Length field says.
    Truncated,
    /// The bit that is always 1 is 0.
    FixedBitClear,
    /// A connection id of more than 20 bytes in a version 1 packet.
    ConnectionIdTooLong,
    /// A long header packet of a version other than 1.
    UnsupportedVersion(u32),
    /// Something else that a packet of this kind cannot be.
    Invalid(&'static str),
}

impl From<Truncated> for ParseError {
    fn from(_: Truncated) -> ParseError {
        ParseError::Truncated
    }
}

/// True if the packet that begins with `first` has a long header.
pub fn is_long(first: u8) -> bool {
    first & 0x80 != 0
}

/// Reads the packet that begins at the start of `datagram`. `short_dcid_len` is how long the connection ids that we gave out
/// are: a short header does not say.
pub fn parse(datagram: &[u8], short_dcid_len: usize) -> Result<Packet<'_>, ParseError> {
    let mut r = Reader::new(datagram);
    let first = r.u8()?;
    if !is_long(first) {
        if first & 0x40 == 0 {
            return Err(ParseError::FixedBitClear);
        }
        let dcid = r.bytes(short_dcid_len)?;
        let pn_offset = r.position();
        // (the packet number, at least one byte of it, and its payload)
        if datagram.len() <= pn_offset {
            return Err(ParseError::Truncated);
        }
        return Ok(Packet { ty: PacketType::OneRtt, version: 0, dcid, scid: &[], token: &[], versions: &[], retry_tag: None, pn_offset, len: datagram.len() });
    }
    let version = r.u32()?;
    let dcid_len = r.u8()? as usize;
    if version == VERSION_1 && dcid_len > MAX_CID_LEN {
        return Err(ParseError::ConnectionIdTooLong);
    }
    let dcid = r.bytes(dcid_len)?;
    let scid_len = r.u8()? as usize;
    if version == VERSION_1 && scid_len > MAX_CID_LEN {
        return Err(ParseError::ConnectionIdTooLong);
    }
    let scid = r.bytes(scid_len)?;
    if version == 0 {
        // Version Negotiation: what is left is the versions (the bits of the first byte are of no matter)
        let versions = r.rest();
        if versions.is_empty() || versions.len() % 4 != 0 {
            return Err(ParseError::Invalid("a Version Negotiation packet lists whole versions"));
        }
        return Ok(Packet { ty: PacketType::VersionNegotiation, version, dcid, scid, token: &[], versions, retry_tag: None, pn_offset: 0, len: datagram.len() });
    }
    if version != VERSION_1 {
        return Err(ParseError::UnsupportedVersion(version));
    }
    if first & 0x40 == 0 {
        return Err(ParseError::FixedBitClear);
    }
    let ty = match (first >> 4) & 0x03 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::Retry,
    };
    if ty == PacketType::Retry {
        let rest = r.rest();
        if rest.len() < RETRY_TAG_LEN {
            return Err(ParseError::Truncated);
        }
        let (token, tag) = rest.split_at(rest.len() - RETRY_TAG_LEN);
        let tag: &[u8; RETRY_TAG_LEN] = tag.try_into().expect("16 bytes");
        return Ok(Packet { ty, version, dcid, scid, token, versions: &[], retry_tag: Some(tag), pn_offset: 0, len: datagram.len() });
    }
    let token = if ty == PacketType::Initial { r.length_prefixed()? } else { &[] };
    let length = r.varint()?;
    if length > r.rest().len() as u64 {
        return Err(ParseError::Truncated);
    }
    if length == 0 {
        return Err(ParseError::Invalid("a packet with no packet number"));
    }
    let pn_offset = r.position();
    Ok(Packet { ty, version, dcid, scid, token, versions: &[], retry_tag: None, pn_offset, len: pn_offset + length as usize })
}

/// The versions of a Version Negotiation packet (see [`Packet::versions`]).
pub fn versions(list: &[u8]) -> impl Iterator<Item = u32> + '_ {
    list.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}

/// What [`write_long_header`] tells of the header it wrote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LongHeader {
    /// Where the two-byte Length field is, to be filled in with [`finish_long`] when the packet is complete.
    pub length_at: usize,
    /// Where the packet number begins.
    pub pn_offset: usize,
}

/// Appends the header of an Initial, 0-RTT or Handshake packet: up to and including the packet number, in `pn_len` bytes
/// (1 to 4; see [`packet_number_len`](super::wire::packet_number_len)), of which `pn` is the low bytes. The Length field
/// is left to be filled in.
///
/// Panics if `ty` is not one of those three, if `token` is given for any but an Initial packet, or if an id is too long.
pub fn write_long_header(out: &mut Vec<u8>, ty: PacketType, dcid: &[u8], scid: &[u8], token: &[u8], pn: u64, pn_len: usize) -> LongHeader {
    assert!((1..=4).contains(&pn_len));
    assert!(dcid.len() <= MAX_CID_LEN && scid.len() <= MAX_CID_LEN);
    let type_bits: u8 = match ty {
        PacketType::Initial => 0,
        PacketType::ZeroRtt => 1,
        PacketType::Handshake => 2,
        other => panic!("{other:?} is not a long header packet with a packet number"),
    };
    assert!(ty == PacketType::Initial || token.is_empty(), "only an Initial packet has a token");
    out.push(0xc0 | (type_bits << 4) | (pn_len as u8 - 1));
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    if ty == PacketType::Initial {
        super::wire::put_varint(out, token.len() as u64);
        out.extend_from_slice(token);
    }
    let length_at = out.len();
    put_varint_len(out, 0, 2);
    let pn_offset = out.len();
    out.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    LongHeader { length_at, pn_offset }
}

/// Fills in the Length field of the packet that begins at `start` in `out` and whose header [`write_long_header`] wrote: `out`
/// holds the header and the payload, and the authentication tag that [`keys`](super::keys) puts at the end, of `tag_len` bytes, is
/// counted.
pub fn finish_long(out: &mut [u8], header: LongHeader, tag_len: usize) {
    let length = out.len() - header.pn_offset + tag_len;
    patch_length(out, header.length_at, length as u64);
}

/// Appends the header of a short header packet, up to and including the packet number (`pn_len` bytes of it). Returns where the
/// packet number begins.
pub fn write_short_header(out: &mut Vec<u8>, dcid: &[u8], spin: bool, key_phase: bool, pn: u64, pn_len: usize) -> usize {
    assert!((1..=4).contains(&pn_len));
    out.push(0x40 | (u8::from(spin) << 5) | (u8::from(key_phase) << 2) | (pn_len as u8 - 1));
    out.extend_from_slice(dcid);
    let pn_offset = out.len();
    out.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    pn_offset
}

/// Whether the Length field of an Initial, 0-RTT or Handshake packet could be read from the start of `after_token` (a helper
/// for tests and for fuzzing: `parse` is what reads packets).
#[doc(hidden)]
pub fn length_field(after_token: &[u8]) -> Option<(u64, usize)> {
    get_varint(after_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;

    // RFC 9001 appendix A.2: the first Initial packet of a client, as it is sent
    fn client_initial() -> Vec<u8> {
        let mut p = unhex(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
        );
        // (the first byte and the packet number are protected: what is read does not depend on them)
        assert_eq!(p.len(), 1200);
        p.shrink_to_fit();
        p
    }

    #[test]
    fn a_clients_initial_packet_is_read_without_keys() {
        let p = client_initial();
        let pk = parse(&p, 8).unwrap();
        assert_eq!(pk.ty, PacketType::Initial);
        assert_eq!(pk.version, 1);
        assert_eq!(pk.dcid, unhex("8394c8f03e515708"));
        assert_eq!(pk.scid, b"");
        assert_eq!(pk.token, b"");
        assert_eq!(pk.pn_offset, 18);
        // the Length field says 1182: the packet number and the payload and the tag
        assert_eq!(pk.len, 1200);
    }

    #[test]
    fn a_servers_initial_packet_is_read_without_keys() {
        // RFC 9001 appendix A.3
        let p = unhex("cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee");
        let pk = parse(&p, 8).unwrap();
        assert_eq!(pk.ty, PacketType::Initial);
        assert_eq!(pk.dcid, b"");
        assert_eq!(pk.scid, unhex("f067a5502a4262b5"));
        assert_eq!(pk.pn_offset, 18);
        assert_eq!(pk.len, p.len());
    }

    #[test]
    fn a_retry_packet_is_read_with_its_token_and_tag() {
        // RFC 9001 appendix A.4
        let p = unhex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let pk = parse(&p, 8).unwrap();
        assert_eq!(pk.ty, PacketType::Retry);
        assert_eq!(pk.dcid, b"");
        assert_eq!(pk.scid, unhex("f067a5502a4262b5"));
        assert_eq!(pk.token, b"token");
        assert_eq!(pk.retry_tag.unwrap()[..], unhex("04a265ba2eff4d829058fb3f0f2496ba")[..]);
        assert_eq!(pk.len, 36);
        // a Retry packet that has no room for its tag
        assert_eq!(parse(&p[..15 + 15], 8), Err(ParseError::Truncated));
        // and one that is nothing but the tag
        assert_eq!(parse(&p[..15 + 16], 8).unwrap().token, b"");
        assert_eq!(parse(&p[..15 + 17], 8).unwrap().token, b"t");
    }

    #[test]
    fn version_negotiation_lists_versions() {
        let p = unhex("ea00000000089aac5a49ba87a84908f92f4336fa951ba14547471600000001");
        let pk = parse(&p, 8).unwrap();
        assert_eq!(pk.ty, PacketType::VersionNegotiation);
        assert_eq!(pk.version, 0);
        assert_eq!(pk.dcid, unhex("9aac5a49ba87a849"));
        assert_eq!(pk.scid, unhex("f92f4336fa951ba1"));
        assert_eq!(versions(pk.versions).collect::<Vec<_>>(), [0x4547_4716, 1]);
        // not whole versions, or none
        assert_eq!(parse(&p[..p.len() - 1], 8), Err(ParseError::Invalid("a Version Negotiation packet lists whole versions")));
        assert_eq!(parse(&p[..p.len() - 8], 8), Err(ParseError::Invalid("a Version Negotiation packet lists whole versions")));
    }

    #[test]
    fn a_short_header_packet_takes_the_rest_of_the_datagram() {
        let mut p = vec![0x41];
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        p.extend_from_slice(&[0xaa; 30]);
        let pk = parse(&p, 8).unwrap();
        assert_eq!((pk.ty, pk.dcid, pk.pn_offset, pk.len), (PacketType::OneRtt, &[1u8, 2, 3, 4, 5, 6, 7, 8][..], 9, 39));
        // our connection ids are of another length
        assert_eq!(parse(&p, 4).unwrap().pn_offset, 5);
        assert_eq!(parse(&p, 0).unwrap().pn_offset, 1);
        // nothing after the connection id
        assert_eq!(parse(&p[..9], 8), Err(ParseError::Truncated));
        assert_eq!(parse(&p[..5], 8), Err(ParseError::Truncated));
        // the fixed bit
        p[0] = 0x01;
        assert_eq!(parse(&p, 8), Err(ParseError::FixedBitClear));
    }

    #[test]
    fn what_cannot_be_read_is_refused() {
        let good = client_initial();
        // cut anywhere: no panic, and an error at every length short of the packet
        for n in 0..good.len() {
            assert!(parse(&good[..n], 8).is_err(), "{n} bytes");
        }
        // another version
        let mut p = good.clone();
        p[4] = 2;
        assert_eq!(parse(&p, 8), Err(ParseError::UnsupportedVersion(2)));
        // the fixed bit of a long header
        let mut p = good.clone();
        p[0] &= !0x40;
        assert_eq!(parse(&p, 8), Err(ParseError::FixedBitClear));
        // an id that is too long
        let mut p = good.clone();
        p[5] = 21;
        assert_eq!(parse(&p, 8), Err(ParseError::ConnectionIdTooLong));
        // a Length of nothing
        let mut p = good.clone();
        p[16] = 0;
        p[17] = 0;
        assert_eq!(parse(&p, 8), Err(ParseError::Invalid("a packet with no packet number")));
        // a Length that is more than there is
        let mut p = good.clone();
        p[16] = 0x7f;
        p[17] = 0xff;
        assert_eq!(parse(&p, 8), Err(ParseError::Truncated));
    }

    #[test]
    fn packets_in_one_datagram_are_told_apart_by_their_lengths() {
        // a Handshake packet followed by a short header packet, in one datagram (RFC 9000 section 12.2)
        let mut d = Vec::new();
        let h = write_long_header(&mut d, PacketType::Handshake, &[1, 2, 3, 4], &[5, 6], &[], 7, 2);
        d.extend_from_slice(&[0xee; 40]);
        finish_long(&mut d, h, 16);
        d.extend_from_slice(&[0xdd; 16]);
        let first_len = d.len();
        d.push(0x40);
        d.extend_from_slice(&[9, 9, 9, 9]);
        d.extend_from_slice(&[0xcc; 25]);
        let p1 = parse(&d, 4).unwrap();
        assert_eq!((p1.ty, p1.dcid, p1.scid, p1.pn_offset, p1.len), (PacketType::Handshake, &[1u8, 2, 3, 4][..], &[5u8, 6][..], h.pn_offset, first_len));
        let p2 = parse(&d[p1.len..], 4).unwrap();
        assert_eq!((p2.ty, p2.dcid, p2.pn_offset, p2.len), (PacketType::OneRtt, &[9u8, 9, 9, 9][..], 5, 30));
    }

    #[test]
    fn headers_are_written_as_they_are_read() {
        let mut out = Vec::new();
        let h = write_long_header(&mut out, PacketType::Initial, &[0xaa; 8], &[0xbb; 4], b"tok", 0x1234, 2);
        out.extend_from_slice(&[0; 30]);
        finish_long(&mut out, h, 16);
        // first byte: long, fixed, Initial, reserved 0, packet number 2 bytes
        assert_eq!(out[0], 0xc1);
        assert_eq!(&out[1..5], [0, 0, 0, 1]);
        let p = parse(&out, 0).unwrap_err();
        // (the Length field counts the 16 bytes of tag that are not there yet)
        assert_eq!(p, ParseError::Truncated);
        out.extend_from_slice(&[0; 16]);
        let p = parse(&out, 0).unwrap();
        assert_eq!((p.ty, p.token, p.pn_offset, p.len), (PacketType::Initial, &b"tok"[..], h.pn_offset, out.len()));
        assert_eq!(&out[h.pn_offset..h.pn_offset + 2], [0x12, 0x34]);

        let mut short = Vec::new();
        let at = write_short_header(&mut short, &[1, 2, 3], true, true, 0xabcdef, 3);
        assert_eq!(short[0], 0x40 | 0x20 | 0x04 | 2);
        assert_eq!(at, 4);
        assert_eq!(&short[4..], [0xab, 0xcd, 0xef]);
    }
}
