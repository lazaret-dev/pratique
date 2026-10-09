//! QUIC packet protection (RFC 9001 section 5): the keys that come from a TLS traffic secret (or, for Initial packets, from
//! the Destination Connection ID), header protection, the AEAD that protects the payload, key update, and the Retry integrity tag.
//!
//! A packet is protected in two layers. The payload is sealed by an AEAD whose nonce is the packet number xor-ed into an IV and
//! whose associated data is the header, packet number included. Then the low bits of the first byte and the packet number are
//! masked with bytes taken from a sample of the sealed payload, which hides how long the packet number is and what it is. Taking
//! a packet apart goes the other way, and has to: the mask comes from the sample, the sample from the packet as it was sent, so
//! the header is unmasked first and only then does the length of the packet number, and so the associated data, become known.
//!
//! Nothing here keeps state about which packet numbers have been seen; that, and which keys apply to which packet, is for the
//! connection above. What is kept is how many packets a key has sealed and how many it has failed to open, because RFC 9001
//! section 6.6 limits both (see [`PacketKey::confidentiality_limit_reached`] and [`PacketKey::integrity_limit_reached`]).

use super::wire::decode_packet_number;
use crate::crypto::aes::Aes;
use crate::crypto::chacha20poly1305::ChaCha20Mask;
use crate::crypto::dit::Dit;
use crate::tls::suite::{expand_label, hkdf_extract, Aead, Suite, AEAD_TAG_LEN};
use crate::util::ct_eq;
use crate::zeroize::{Zeroize, Zeroizing};
use std::ops::Range;

/// The length of the tag that ends every protected packet.
pub const TAG_LEN: usize = AEAD_TAG_LEN;

/// Where in a packet the sample for the header protection mask begins, counted from the start of the packet number: as if the
/// packet number were four bytes long, whatever it is (RFC 9001 section 5.4.2).
const SAMPLE_OFFSET: usize = 4;
const SAMPLE_LEN: usize = 16;

/// The low bits of the first byte that header protection hides: the reserved bits, the key phase and the length of the packet
/// number in a short header packet, the reserved bits and the length of the packet number in a long header packet.
const LONG_FIRST_BYTE_MASK: u8 = 0x0f;
const SHORT_FIRST_BYTE_MASK: u8 = 0x1f;

/// The salt that Initial secrets are made with, for version 1 (RFC 9001 section 5.2).
pub const INITIAL_SALT_V1: [u8; 20] =
    [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];

/// The key and nonce of the AEAD that signs a Retry packet, for version 1 (RFC 9001 section 5.8).
const RETRY_KEY_V1: [u8; 16] = [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];
const RETRY_NONCE_V1: [u8; 12] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

/// Whether the reserved bits of a first byte that has been unmasked are zero, as RFC 9000 sections 17.2 and 17.3 require of a
/// packet that has been opened: if not, the connection is to be closed with PROTOCOL_VIOLATION.
pub fn reserved_bits_clear(first: u8) -> bool {
    let reserved = if first & 0x80 != 0 { 0x0c } else { 0x18 };
    first & reserved == 0
}

// ---------------------------------------------------------------------------------------------------------------------------
// header protection

#[derive(Clone)]
enum Mask {
    Aes(Aes),
    ChaCha(ChaCha20Mask),
}

/// The key for header protection (RFC 9001 section 5.4). It is made once from a secret and not changed by a key update.
#[derive(Clone)]
pub struct HeaderKey {
    mask: Mask,
}

/// A packet number as it was sent, with the first byte, after header protection has been taken off.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unmasked {
    /// The first byte of the packet, as it was before it was protected.
    pub first: u8,
    /// How many bytes the packet number takes (1 to 4).
    pub pn_len: usize,
    /// The packet number as sent: its low `8 * pn_len` bits (see [`decode_packet_number`]).
    pub truncated_pn: u64,
}

impl HeaderKey {
    pub fn new(suite: Suite, key: &[u8]) -> HeaderKey {
        assert_eq!(key.len(), suite.key_len());
        let mask = match suite {
            Suite::Aes128GcmSha256 | Suite::Aes256GcmSha384 => Mask::Aes(Aes::new(key)),
            Suite::Chacha20Poly1305Sha256 => Mask::ChaCha(ChaCha20Mask::new(key)),
        };
        HeaderKey { mask }
    }

    /// The five bytes that go over the first byte and a packet number of up to four, taken from `sample`.
    pub fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; 5] {
        match &self.mask {
            Mask::Aes(aes) => {
                let b = aes.encrypt_block(sample);
                [b[0], b[1], b[2], b[3], b[4]]
            }
            Mask::ChaCha(c) => c.mask(sample),
        }
    }

    /// The sample of a packet: 16 bytes, from four bytes after where the packet number begins. `None` if the packet ends too soon
    /// for there to be one (so a packet needs a payload of at least `4 - pn_len` bytes, and `seal` has to refuse a smaller one).
    fn sample(packet: &[u8], pn_offset: usize) -> Option<[u8; SAMPLE_LEN]> {
        let start = pn_offset.checked_add(SAMPLE_OFFSET)?;
        let end = start.checked_add(SAMPLE_LEN)?;
        packet.get(start..end)?.try_into().ok()
    }

    /// Masks the first byte and the `pn_len` bytes of packet number that begin at `pn_offset`, of a packet that is whole and sealed
    /// (the tag is on the end). Returns false, and does nothing, if the packet is too short to have a sample.
    pub fn protect(&self, packet: &mut [u8], pn_offset: usize, pn_len: usize) -> bool {
        debug_assert!((1..=4).contains(&pn_len));
        let Some(sample) = Self::sample(packet, pn_offset) else { return false };
        let mask = self.mask(&sample);
        packet[0] ^= mask[0] & if packet[0] & 0x80 != 0 { LONG_FIRST_BYTE_MASK } else { SHORT_FIRST_BYTE_MASK };
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        true
    }

    /// Takes header protection off in place and reads what it hid: the first byte and the packet number. `packet` is exactly one
    /// packet (a packet of a coalesced datagram is cut at its Length). `None` if it is too short to have a sample, in which case
    /// the packet is to be dropped.
    ///
    /// The packet is changed whether or not it then turns out to be genuine, as a forgery's header is as good as any, so the
    /// first byte and the packet number must not be trusted before the payload has been opened.
    pub fn unprotect(&self, packet: &mut [u8], pn_offset: usize) -> Option<Unmasked> {
        let sample = Self::sample(packet, pn_offset)?;
        let mask = self.mask(&sample);
        let first = packet[0] ^ (mask[0] & if packet[0] & 0x80 != 0 { LONG_FIRST_BYTE_MASK } else { SHORT_FIRST_BYTE_MASK });
        let pn_len = (first & 3) as usize + 1;
        packet[0] = first;
        let mut truncated_pn = 0u64;
        for i in 0..pn_len {
            let b = packet[pn_offset + i] ^ mask[1 + i];
            packet[pn_offset + i] = b;
            truncated_pn = (truncated_pn << 8) | b as u64;
        }
        Some(Unmasked { first, pn_len, truncated_pn })
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// the AEAD

/// How many packets one key may seal before the confidentiality of what it sealed is at risk (RFC 9001 section 6.6 and appendix
/// B.1): 2^23 under AES-GCM, and for ChaCha20-Poly1305 2^62, which is more than there are packet numbers.
pub fn confidentiality_limit(suite: Suite) -> u64 {
    match suite {
        Suite::Aes128GcmSha256 | Suite::Aes256GcmSha384 => 1 << 23,
        Suite::Chacha20Poly1305Sha256 => 1 << 62,
    }
}

/// How many packets one key may fail to open before forgeries become likely (RFC 9001 appendix B.2): 2^52 under AES-GCM, 2^36
/// under ChaCha20-Poly1305.
pub fn integrity_limit(suite: Suite) -> u64 {
    match suite {
        Suite::Aes128GcmSha256 | Suite::Aes256GcmSha384 => 1 << 52,
        Suite::Chacha20Poly1305Sha256 => 1 << 36,
    }
}

/// The AEAD key and IV of one direction at one generation of keys, and how much it has been used.
pub struct PacketKey {
    suite: Suite,
    aead: Aead,
    iv: [u8; 12],
    sealed: u64,
    failed: u64,
}

impl Drop for PacketKey {
    fn drop(&mut self) {
        self.iv.zeroize(); // (the key schedule of the AEAD wipes itself)
    }
}

impl PacketKey {
    pub fn new(suite: Suite, key: &[u8], iv: &[u8]) -> PacketKey {
        assert_eq!(key.len(), suite.key_len());
        let mut v = [0u8; 12];
        v.copy_from_slice(iv);
        PacketKey { suite, aead: Aead::new(suite, key), iv: v, sealed: 0, failed: 0 }
    }

    /// The IV with the packet number, as eight bytes on the right, xor-ed into it (RFC 9001 section 5.3).
    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
        let p = pn.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= p[i];
        }
        n
    }

    /// Seals a payload in place. `buf` holds the payload followed by [`TAG_LEN`] bytes of room, and becomes the sealed payload and
    /// its tag; `header` is the packet from its first byte to the end of the packet number, as it will be sent but for header
    /// protection (so the Length field of a long header has to be right already).
    pub fn seal(&mut self, pn: u64, header: &[u8], buf: &mut [u8]) {
        let nonce = self.nonce(pn);
        self.aead.seal_in_place(&nonce, header, buf);
        self.sealed += 1;
    }

    /// Opens a payload in place: `buf` is the sealed payload and its tag. On success, returns the length of the payload, which
    /// is then at the start of `buf`; on failure `buf` is untouched and the failure is counted.
    pub fn open(&mut self, pn: u64, header: &[u8], buf: &mut [u8]) -> Option<usize> {
        let nonce = self.nonce(pn);
        let r = self.aead.open_in_place(&nonce, header, buf);
        if r.is_none() {
            self.failed += 1;
        }
        r
    }

    /// How many packets this key has sealed.
    pub fn sealed(&self) -> u64 {
        self.sealed
    }

    /// How many packets this key has failed to open.
    pub fn failed(&self) -> u64 {
        self.failed
    }

    /// How many packets this key may seal (see [`confidentiality_limit`]).
    pub fn confidentiality_limit(&self) -> u64 {
        confidentiality_limit(self.suite)
    }

    /// Whether this key has sealed as many packets as it may: it must not seal another, and a connection has to have started a
    /// key update well before (or be closed).
    pub fn confidentiality_limit_reached(&self) -> bool {
        self.sealed >= confidentiality_limit(self.suite)
    }

    /// Whether this key has failed to open as many packets as it may: the connection is to be closed.
    pub fn integrity_limit_reached(&self) -> bool {
        self.failed >= integrity_limit(self.suite)
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// keys

/// What is wrong with a packet that could not be opened. All of them but the last are a reason to drop the packet and go on; the
/// last one comes from a packet that was genuine and is a reason to close the connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// There is no room for a sample, or no payload for a tag.
    TooShort,
    /// The payload did not verify: wrong key, or damaged, or forged.
    Authentication,
    /// The packet is genuine and its reserved bits are not zero (PROTOCOL_VIOLATION).
    ReservedBits,
}

/// The seal has been refused: the payload is too short for a sample to be taken, so the sender has to pad it (with PADDING
/// frames) to at least `4 - pn_len` bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayloadTooShort;

/// A packet that has been opened, which is in place in the buffer it came in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opened {
    /// The packet number, in full.
    pub pn: u64,
    /// The first byte, with header protection off.
    pub first: u8,
    /// Where the frames are in the packet.
    pub payload: Range<usize>,
}

/// The keys for one direction at one encryption level: header protection and AEAD, and what a key update needs.
pub struct Keys {
    suite: Suite,
    secret: Zeroizing<Vec<u8>>,
    pub header: HeaderKey,
    pub packet: PacketKey,
}

/// The AEAD key, the IV and the header protection key that a secret makes (RFC 9001 section 5.1).
fn derive(suite: Suite, secret: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let alg = suite.hash();
    let key = Zeroizing::new(expand_label(alg, secret, "quic key", &[], suite.key_len()));
    let iv = Zeroizing::new(expand_label(alg, secret, "quic iv", &[], 12));
    let hp = Zeroizing::new(expand_label(alg, secret, "quic hp", &[], suite.key_len()));
    (key, iv, hp)
}

impl Keys {
    /// The keys that a traffic secret of TLS 1.3 (or an Initial secret) makes, for `suite`.
    pub fn new(suite: Suite, secret: &[u8]) -> Keys {
        let (key, iv, hp) = derive(suite, secret);
        Keys { suite, secret: Zeroizing::new(secret.to_vec()), header: HeaderKey::new(suite, &hp), packet: PacketKey::new(suite, &key, &iv) }
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The keys of the next generation (RFC 9001 section 6): a new secret from this one, so a new AEAD key and IV, and the same
    /// key for header protection.
    pub fn next(&self) -> Keys {
        let alg = self.suite.hash();
        let secret = Zeroizing::new(expand_label(alg, &self.secret, "quic ku", &[], alg.output_len()));
        let (key, iv, _hp) = derive(self.suite, &secret);
        Keys { suite: self.suite, secret, header: self.header.clone(), packet: PacketKey::new(self.suite, &key, &iv) }
    }

    /// Protects a packet that has been written in full, but for the tag, which this adds: `packet` is the header, through the
    /// packet number (`pn_len` bytes of it at `pn_offset`, the low bytes of `pn`), and the payload. A long header's Length field
    /// has to count the tag already ([`finish_long`](super::packet::finish_long) with [`TAG_LEN`]).
    ///
    /// Refuses, and leaves the packet as it is, if the payload is too short.
    pub fn seal(&mut self, packet: &mut Vec<u8>, pn_offset: usize, pn_len: usize, pn: u64) -> Result<(), PayloadTooShort> {
        let header_end = pn_offset + pn_len;
        debug_assert!(packet.len() >= header_end);
        debug_assert!(packet[pn_offset..header_end] == pn.to_be_bytes()[8 - pn_len..], "the packet number is written as it is sent");
        if packet.len() - header_end + TAG_LEN < SAMPLE_OFFSET + SAMPLE_LEN - pn_len {
            return Err(PayloadTooShort);
        }
        let payload_len = packet.len() - header_end;
        packet.resize(packet.len() + TAG_LEN, 0);
        let (header, body) = packet.split_at_mut(header_end);
        debug_assert_eq!(body.len(), payload_len + TAG_LEN);
        // one switch to data-independent timing for the seal and the header protection, where each would make its own (on
        // an Apple M5 a switch on and off costs about 30 ns, B-103)
        let _dit = Dit::on();
        self.packet.seal(pn, header, body);
        let protected = self.header.protect(packet, pn_offset, pn_len);
        debug_assert!(protected);
        Ok(())
    }

    /// Takes a packet apart: header protection off, the packet number recovered (`largest_received` is the largest packet number
    /// received so far in this packet number space, if any), the payload opened in place. `packet` is exactly the packet, from its
    /// first byte to its last (the datagram, for a short header packet; the Length of it, for a long one).
    ///
    /// For a short header packet that is in a key phase other than this one's, use [`HeaderKey::unprotect`] and
    /// [`PacketKey::open`] with the keys of that phase.
    pub fn open(&mut self, packet: &mut [u8], pn_offset: usize, largest_received: Option<u64>) -> Result<Opened, OpenError> {
        let _dit = Dit::on(); // one switch for both steps, as in `seal`
        let hdr = self.header.unprotect(packet, pn_offset).ok_or(OpenError::TooShort)?;
        let pn = decode_packet_number(largest_received, hdr.truncated_pn, hdr.pn_len);
        let payload = open_payload(&mut self.packet, packet, pn_offset, &hdr, pn)?;
        Ok(Opened { pn, first: hdr.first, payload })
    }
}

/// Opens the payload of a packet whose header protection has been taken off, with `key`, and checks what only a genuine packet
/// can be held to. Returns where the frames are.
pub fn open_payload(key: &mut PacketKey, packet: &mut [u8], pn_offset: usize, hdr: &Unmasked, pn: u64) -> Result<Range<usize>, OpenError> {
    let header_end = pn_offset + hdr.pn_len;
    if packet.len() < header_end + TAG_LEN {
        return Err(OpenError::TooShort);
    }
    let (header, body) = packet.split_at_mut(header_end);
    let n = key.open(pn, header, body).ok_or(OpenError::Authentication)?;
    if !reserved_bits_clear(hdr.first) {
        return Err(OpenError::ReservedBits);
    }
    Ok(header_end..header_end + n)
}

// ---------------------------------------------------------------------------------------------------------------------------
// Initial keys and the Retry tag

/// The secrets of Initial packets, for the client and for the server, from the Destination Connection ID that the client chose
/// in its first Initial packet (RFC 9001 section 5.2).
pub fn initial_secrets(dcid: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let alg = Suite::Aes128GcmSha256.hash();
    let initial = Zeroizing::new(hkdf_extract(alg, &INITIAL_SALT_V1, dcid));
    let client = Zeroizing::new(expand_label(alg, &initial, "client in", &[], alg.output_len()));
    let server = Zeroizing::new(expand_label(alg, &initial, "server in", &[], alg.output_len()));
    (client, server)
}

/// The keys for Initial packets: those that the client seals with and the server opens, and those the other way round.
/// (Initial packets are protected with AES-128-GCM.)
pub fn initial_keys(dcid: &[u8]) -> (Keys, Keys) {
    let (client, server) = initial_secrets(dcid);
    (Keys::new(Suite::Aes128GcmSha256, &client), Keys::new(Suite::Aes128GcmSha256, &server))
}

/// The tag that ends a Retry packet, which is the integrity check of that packet, made from the Destination Connection ID that
/// the client's first Initial packet had and the Retry packet as far as the tag (RFC 9001 section 5.8).
pub fn retry_tag(original_dcid: &[u8], retry_without_tag: &[u8]) -> [u8; TAG_LEN] {
    assert!(original_dcid.len() <= 255);
    let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid);
    pseudo.extend_from_slice(retry_without_tag);
    // AES-128-GCM of nothing: the tag is all there is
    let mut tag = [0u8; TAG_LEN];
    Aead::new(Suite::Aes128GcmSha256, &RETRY_KEY_V1).seal_in_place(&RETRY_NONCE_V1, &pseudo, &mut tag);
    tag
}

/// Whether `retry` (a whole Retry packet, tag included) is one that a server that was sent a first Initial packet with
/// `original_dcid` could have made. A client that gets a Retry packet that is not has to drop it.
pub fn retry_is_genuine(original_dcid: &[u8], retry: &[u8]) -> bool {
    let Some(split) = retry.len().checked_sub(TAG_LEN) else { return false };
    let (body, tag) = retry.split_at(split);
    ct_eq(&retry_tag(original_dcid, body), tag)
}

#[cfg(test)]
mod tests {
    use super::super::packet::{finish_long, write_long_header, write_short_header, PacketType};
    use super::super::vectors::*;
    use super::*;
    use crate::util::{hex, unhex};

    const AES128: Suite = Suite::Aes128GcmSha256;

    #[test]
    fn initial_secrets_and_keys_are_those_of_the_rfc() {
        // RFC 9001 appendix A.1
        let (client, server) = initial_secrets(&unhex(DCID));
        assert_eq!(hex(&client), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        assert_eq!(hex(&server), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
        let (key, iv, hp) = derive(AES128, &client);
        assert_eq!(hex(&key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
        let (key, iv, hp) = derive(AES128, &server);
        assert_eq!(hex(&key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex(&iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex(&hp), "c206b8d9b9f0f37644430b490eeaa314");
    }

    #[test]
    fn chacha20_keys_are_those_of_the_rfc() {
        // RFC 9001 appendix A.5
        let (key, iv, hp) = derive(Suite::Chacha20Poly1305Sha256, &unhex(CHACHA_SECRET));
        assert_eq!(hex(&key), "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
        assert_eq!(hex(&iv), "e0459b3474bdd0e44a41c144");
        assert_eq!(hex(&hp), "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    }

    #[test]
    fn header_protection_masks_are_those_of_the_rfc() {
        // A.2: the sample of the client Initial packet, and the mask it makes with the client's header protection key
        let k = HeaderKey::new(AES128, &unhex("9f50449e04a0e810283a1e9933adedd2"));
        assert_eq!(hex(&k.mask(&unhex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap())), "437b9aec36");
        // A.3: the server's
        let k = HeaderKey::new(AES128, &unhex("c206b8d9b9f0f37644430b490eeaa314"));
        assert_eq!(hex(&k.mask(&unhex("2cd0991cd25b0aac406a5816b6394100").try_into().unwrap())), "2ec0d8356a");
        // A.5: ChaCha20
        let k = HeaderKey::new(Suite::Chacha20Poly1305Sha256, &unhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"));
        assert_eq!(hex(&k.mask(&unhex("5e5cd55c41f69080575d7999c25a5bfb").try_into().unwrap())), "aefefe7d03");
    }

    /// The client Initial packet of appendix A.2, written but not protected: its header, the CRYPTO frame and the padding.
    fn client_initial_unprotected() -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let h = write_long_header(&mut out, PacketType::Initial, &unhex(DCID), &[], &[], CLIENT_INITIAL_PN, 4);
        out.extend_from_slice(&unhex(CLIENT_INITIAL_CRYPTO));
        out.resize(out.len() + CLIENT_INITIAL_PADDING, 0);
        finish_long(&mut out, h, TAG_LEN);
        (out, h.pn_offset)
    }

    #[test]
    fn the_client_initial_packet_of_the_rfc_is_sealed_as_it_is() {
        // RFC 9001 appendix A.2
        let (mut p, pn_offset) = client_initial_unprotected();
        assert_eq!(hex(&p[..pn_offset + 4]), CLIENT_INITIAL_HEADER);
        let (mut client, _server) = initial_keys(&unhex(DCID));
        client.seal(&mut p, pn_offset, 4, CLIENT_INITIAL_PN).unwrap();
        assert_eq!(p.len(), 1200);
        assert_eq!(hex(&p), CLIENT_INITIAL_PACKET);
        assert_eq!(client.packet.sealed(), 1);
    }

    #[test]
    fn the_client_initial_packet_of_the_rfc_is_opened() {
        let mut p = unhex(CLIENT_INITIAL_PACKET);
        // the server opens it with the keys it makes from the same Destination Connection ID
        let (mut client_side, _) = initial_keys(&unhex(DCID));
        let o = client_side.open(&mut p, 18, None).unwrap();
        assert_eq!(o.pn, CLIENT_INITIAL_PN);
        assert_eq!(o.first, 0xc3);
        assert_eq!(hex(&p[..22]), CLIENT_INITIAL_HEADER);
        assert_eq!(o.payload, 22..1200 - TAG_LEN);
        assert_eq!(hex(&p[o.payload.start..o.payload.start + unhex(CLIENT_INITIAL_CRYPTO).len()]), CLIENT_INITIAL_CRYPTO);
        assert!(p[o.payload.start + unhex(CLIENT_INITIAL_CRYPTO).len()..o.payload.end].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_server_initial_packet_of_the_rfc_is_sealed_and_opened() {
        // RFC 9001 appendix A.3: the header has the Length of the whole packet, 0x4075, in it already
        let (_, mut server_keys) = initial_keys(&unhex(DCID));
        let mut p = unhex(SERVER_INITIAL_HEADER);
        p.extend_from_slice(&unhex(SERVER_INITIAL_PAYLOAD));
        server_keys.seal(&mut p, 18, 2, SERVER_INITIAL_PN).unwrap();
        assert_eq!(hex(&p), SERVER_INITIAL_PACKET);

        // the client opens it with the same keys
        let (_, mut server_keys) = initial_keys(&unhex(DCID));
        let mut q = unhex(SERVER_INITIAL_PACKET);
        let o = server_keys.open(&mut q, 18, None).unwrap();
        assert_eq!(o.pn, SERVER_INITIAL_PN);
        assert_eq!(hex(&q[o.payload]), SERVER_INITIAL_PAYLOAD);
    }

    #[test]
    fn the_chacha20_short_header_packet_of_the_rfc_is_sealed_and_opened() {
        // RFC 9001 appendix A.5: the header "4200bff4" is a short header with no destination connection id and a packet number of
        // three bytes, 0x00bff4, of the packet number 654360564 (0x2700bff4); the payload is a PING
        let mut keys = Keys::new(Suite::Chacha20Poly1305Sha256, &unhex(CHACHA_SECRET));
        let mut p = unhex(CHACHA_HEADER);
        p.extend_from_slice(&unhex(CHACHA_PAYLOAD));
        assert_eq!(p[0] & 3, 2);
        keys.seal(&mut p, 1, 3, CHACHA_PN).unwrap();
        assert_eq!(hex(&p), CHACHA_PACKET);

        // the peer has received up to a little before it, and gets all of the packet number back
        let mut keys = Keys::new(Suite::Chacha20Poly1305Sha256, &unhex(CHACHA_SECRET));
        let mut q = unhex(CHACHA_PACKET);
        let o = keys.open(&mut q, 1, Some(654_360_000)).unwrap();
        assert_eq!(o.pn, CHACHA_PN);
        assert_eq!(o.first, 0x42);
        assert_eq!(hex(&q[o.payload]), CHACHA_PAYLOAD);
    }

    #[test]
    fn packets_protected_by_aioquic_are_the_same_here() {
        // 72 packets of an independent implementation: every suite, long and short headers, every length of packet number, and the
        // same under the next generation of keys
        for &(suite_id, secret, clear, pn_offset, pn_len, pn, sealed, sealed_next) in super::super::vectors_aioquic::AIOQUIC {
            let suite = Suite::from_id(suite_id).unwrap();
            let secret = unhex(secret);
            let clear = unhex(clear);
            let what = format!("{suite:?} pn_len {pn_len} pn {pn} {} bytes", clear.len());
            for (generation, expected) in [(0, sealed), (1, sealed_next)] {
                let mut keys = Keys::new(suite, &secret);
                if generation == 1 {
                    keys = keys.next();
                }
                let mut p = clear.clone();
                keys.seal(&mut p, pn_offset, pn_len, pn).unwrap();
                assert_eq!(hex(&p), expected, "sealed: {what}, generation {generation}");

                // and opened, by keys that have seen the packet before
                let mut p = unhex(expected);
                let mut keys = Keys::new(suite, &secret);
                if generation == 1 {
                    keys = keys.next();
                }
                let o = keys.open(&mut p, pn_offset, pn.checked_sub(1)).unwrap_or_else(|e| panic!("{e:?}: {what}, generation {generation}"));
                assert_eq!(o.pn, pn, "{what}");
                assert_eq!(p[..o.payload.end], clear[..], "opened: {what}, generation {generation}");
            }
        }
    }

    #[test]
    fn the_retry_tag_of_the_rfc_is_made_and_checked() {
        // RFC 9001 appendix A.4
        let retry = unhex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let odcid = unhex(DCID);
        assert_eq!(hex(&retry_tag(&odcid, &retry[..retry.len() - TAG_LEN])), "04a265ba2eff4d829058fb3f0f2496ba");
        assert!(retry_is_genuine(&odcid, &retry));
        // not for another original destination connection id
        assert!(!retry_is_genuine(&unhex("8394c8f03e515709"), &retry));
        assert!(!retry_is_genuine(&[], &retry));
        // nor with any bit changed, in the packet or in the tag
        for i in 0..retry.len() * 8 {
            let mut r = retry.clone();
            r[i / 8] ^= 1 << (i % 8);
            assert!(!retry_is_genuine(&odcid, &r), "bit {i}");
        }
        // nor one that is shorter than a tag
        assert!(!retry_is_genuine(&odcid, &retry[..15]));
        assert!(!retry_is_genuine(&odcid, &[]));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // what no vector covers

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// A packet to seal: long (a Handshake packet) or short, with a payload of `payload_len` bytes.
    fn build(rng: &mut Lcg, long: bool, pn: u64, pn_len: usize, payload_len: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let dcid = rng.bytes(8);
        let (pn_offset, h) = if long {
            let h = write_long_header(&mut out, PacketType::Handshake, &dcid, &rng.bytes(4), &[], pn, pn_len);
            (h.pn_offset, Some(h))
        } else {
            (write_short_header(&mut out, &dcid, rng.next() & 1 == 1, rng.next() & 1 == 1, pn, pn_len), None)
        };
        out.extend_from_slice(&rng.bytes(payload_len));
        if let Some(h) = h {
            finish_long(&mut out, h, TAG_LEN);
        }
        (out, pn_offset)
    }

    #[test]
    fn what_is_sealed_is_opened_by_every_suite() {
        let mut rng = Lcg(7);
        for suite in Suite::ALL {
            let secret = rng.bytes(suite.hash().output_len());
            for long in [false, true] {
                for pn_len in 1..=4usize {
                    for payload_len in [4 - pn_len, 4, 5, 20, 100, 1200] {
                        let pn = rng.next() << (rng.next() % 12);
                        let (clear, pn_offset) = build(&mut rng, long, pn, pn_len, payload_len);
                        let mut p = clear.clone();
                        Keys::new(suite, &secret).seal(&mut p, pn_offset, pn_len, pn).unwrap();
                        assert_eq!(p.len(), clear.len() + TAG_LEN);
                        let header_end = pn_offset + pn_len;
                        if payload_len >= 4 {
                            assert_ne!(p[header_end..header_end + 4], clear[header_end..header_end + 4], "the payload is hidden");
                        }
                        // the peer has everything before this one, so the packet number comes back in full
                        let o = Keys::new(suite, &secret)
                            .open(&mut p, pn_offset, pn.checked_sub(1))
                            .unwrap_or_else(|e| panic!("{suite:?} long {long} pn_len {pn_len} payload {payload_len}: {e:?}"));
                        assert_eq!(o.pn, pn);
                        assert_eq!(o.first, clear[0]);
                        assert_eq!(p[o.payload.clone()], clear[header_end..]);
                        assert_eq!(p[pn_offset..header_end], clear[pn_offset..header_end]);
                    }
                }
            }
        }
    }

    #[test]
    fn a_payload_too_short_for_a_sample_is_refused_and_the_packet_left_alone() {
        let mut rng = Lcg(3);
        let mut keys = Keys::new(AES128, &rng.bytes(32));
        // the sample begins four bytes into the packet number's place and takes 16 bytes: with the tag that is 16 bytes of it,
        // so what is missing is `4 - pn_len` bytes of payload
        for pn_len in 1..=4usize {
            let (clear, pn_offset) = build(&mut rng, false, 5, pn_len, 4 - pn_len);
            let mut p = clear.clone();
            assert_eq!(keys.seal(&mut p, pn_offset, pn_len, 5), Ok(()), "pn_len {pn_len}");
            assert_eq!(p.len(), clear.len() + TAG_LEN);
            assert_eq!(Keys::new(AES128, &[0; 32]).header.protect(&mut [0; 4], 1, 1), false);
        }
        assert_eq!(keys.packet.sealed(), 4);
        for pn_len in 1..=3usize {
            let (clear, pn_offset) = build(&mut rng, false, 5, pn_len, 3 - pn_len);
            let mut p = clear.clone();
            assert_eq!(keys.seal(&mut p, pn_offset, pn_len, 5), Err(PayloadTooShort), "pn_len {pn_len}");
            assert_eq!(p, clear);
        }
        assert_eq!(keys.packet.sealed(), 4);
    }

    #[test]
    fn a_packet_that_is_changed_anywhere_is_not_opened() {
        let mut rng = Lcg(11);
        for suite in Suite::ALL {
            let secret = rng.bytes(suite.hash().output_len());
            for long in [false, true] {
                let (clear, pn_offset) = build(&mut rng, long, 0x1234, 2, 60);
                let mut p = clear.clone();
                Keys::new(suite, &secret).seal(&mut p, pn_offset, 2, 0x1234).unwrap();
                // every bit of the packet; but the bits of the first byte that the header protection leaves alone, and, in a long
                // header, the version and the connection ids and the Length, are only tied to the packet by what the AEAD covers
                for bit in 0..p.len() * 8 {
                    let mut q = p.clone();
                    q[bit / 8] ^= 1 << (bit % 8);
                    let mut opener = Keys::new(suite, &secret);
                    let r = opener.open(&mut q, pn_offset, Some(0x1233));
                    assert!(r.is_err(), "{suite:?} long {long}: bit {bit} changed and the packet opened");
                }
                // and the genuine one does
                let mut opener = Keys::new(suite, &secret);
                assert!(opener.open(&mut p.clone(), pn_offset, Some(0x1233)).is_ok());
                // not with the keys of another secret
                let mut other = Keys::new(suite, &rng.bytes(suite.hash().output_len()));
                assert_eq!(other.open(&mut p.clone(), pn_offset, Some(0x1233)), Err(OpenError::Authentication));
                assert_eq!(other.packet.failed(), 1);
                // nor when the packet number is taken to be another one
                let mut opener = Keys::new(suite, &secret);
                assert!(opener.open(&mut p.clone(), pn_offset, Some(0x1233 + 0x8000)).is_err());
            }
        }
    }

    #[test]
    fn a_packet_that_is_cut_short_is_not_opened() {
        let mut rng = Lcg(5);
        let secret = rng.bytes(32);
        let (clear, pn_offset) = build(&mut rng, false, 9, 1, 40);
        let mut p = clear.clone();
        Keys::new(AES128, &secret).seal(&mut p, pn_offset, 1, 9).unwrap();
        for cut in 0..p.len() {
            let mut q = p[..cut].to_vec();
            let r = Keys::new(AES128, &secret).open(&mut q, pn_offset, None);
            assert!(r.is_err(), "cut at {cut}");
        }
        // not even a sample
        assert_eq!(Keys::new(AES128, &secret).open(&mut p[..pn_offset + 19].to_vec(), pn_offset, None), Err(OpenError::TooShort));
        // a pn_offset that is nonsense
        assert_eq!(Keys::new(AES128, &secret).open(&mut p.clone(), usize::MAX - 3, None), Err(OpenError::TooShort));
        assert_eq!(Keys::new(AES128, &secret).open(&mut [], 0, None), Err(OpenError::TooShort));
    }

    #[test]
    fn reserved_bits_that_are_not_zero_are_told_only_for_a_genuine_packet() {
        let mut rng = Lcg(13);
        let secret = rng.bytes(32);
        for long in [false, true] {
            let (clear, pn_offset) = build(&mut rng, long, 1, 1, 30);
            // the two reserved bits of a long header, 0x08 and 0x04; of a short header 0x10 and 0x08 (0x04 there is the key phase)
            let bits: &[u8] = if long { &[0x08, 0x04, 0x0c] } else { &[0x10, 0x08, 0x18] };
            for &reserved in bits {
                let mut bad = clear.clone();
                bad[0] |= reserved;
                let mut p = bad.clone();
                Keys::new(AES128, &secret).seal(&mut p, pn_offset, 1, 1).unwrap();
                assert_eq!(Keys::new(AES128, &secret).open(&mut p, pn_offset, None), Err(OpenError::ReservedBits), "long {long} bits {reserved:#x}");
                // the same bits changed in a packet that was sent properly: not genuine any more, and not told as a violation
                let mut p = clear.clone();
                Keys::new(AES128, &secret).seal(&mut p, pn_offset, 1, 1).unwrap();
                p[0] ^= reserved;
                let wrong = Keys::new(AES128, &secret).open(&mut p, pn_offset, None);
                assert_eq!(wrong, Err(OpenError::Authentication));
            }
            // and a packet that has the other bits (of the key phase, of the spin, of the packet type) is not told
            for other in if long { [0x00u8, 0x10, 0x20] } else { [0x00, 0x04, 0x20] } {
                let mut p = clear.clone();
                p[0] ^= other;
                assert!(reserved_bits_clear(p[0]));
            }
        }
        assert!(reserved_bits_clear(0xc3) && reserved_bits_clear(0x43) && !reserved_bits_clear(0xcf) && !reserved_bits_clear(0x58));
        for bit in [0x04, 0x08] {
            assert!(!reserved_bits_clear(0xc0 | bit), "long {bit:#x}");
        }
        for bit in [0x08, 0x10] {
            assert!(!reserved_bits_clear(0x40 | bit), "short {bit:#x}");
        }
        assert!(reserved_bits_clear(0x40 | 0x04) && reserved_bits_clear(0x40 | 0x20) && reserved_bits_clear(0xc0 | 0x10) && reserved_bits_clear(0xc0 | 0x20));
    }

    #[test]
    fn key_update_makes_new_keys_and_keeps_the_header_key() {
        let mut rng = Lcg(17);
        for suite in Suite::ALL {
            let secret = rng.bytes(suite.hash().output_len());
            // generation `n` of the keys that `secret` makes
            let generation = |n: usize| {
                let mut k = Keys::new(suite, &secret);
                for _ in 0..n {
                    k = k.next();
                }
                k
            };
            let (clear, pn_offset) = build(&mut rng, false, 77, 2, 50);
            let sealed_by = |n: usize| {
                let mut p = clear.clone();
                generation(n).seal(&mut p, pn_offset, 2, 77).unwrap();
                p
            };
            // (a new generation is a new key: it has sealed nothing and failed nothing)
            let mut used = generation(0);
            used.seal(&mut clear.clone(), pn_offset, 2, 77).unwrap();
            assert!(used.open(&mut vec![0; 40], pn_offset, None).is_err());
            assert_eq!((used.packet.sealed(), used.packet.failed()), (1, 1));
            let fresh = used.next();
            assert_eq!((fresh.packet.sealed(), fresh.packet.failed()), (0, 0));
            let packets = [sealed_by(0), sealed_by(1), sealed_by(2)];
            assert_ne!(packets[0], packets[1]);
            assert_ne!(packets[1], packets[2]);
            // the key for header protection is the same in all of them, the AEAD key is not
            for n in 1..3 {
                assert_eq!(generation(0).header.mask(&[7; 16]), generation(n).header.mask(&[7; 16]));
            }
            for (opener, sealer) in (0..3).flat_map(|a| (0..3).map(move |b| (a, b))) {
                let r = generation(opener).open(&mut packets[sealer].clone(), pn_offset, Some(76));
                assert_eq!(r.is_ok(), opener == sealer, "{suite:?}: generation {opener} opens one of generation {sealer}");
            }
        }
    }

    #[test]
    fn use_is_counted_and_has_a_limit() {
        let mut rng = Lcg(19);
        let secret = rng.bytes(32);
        let mut k = Keys::new(AES128, &secret);
        assert!(!k.packet.confidentiality_limit_reached());
        let (clear, pn_offset) = build(&mut rng, false, 1, 1, 10);
        for i in 0..3u64 {
            let mut p = clear.clone();
            p[pn_offset] = i as u8;
            k.seal(&mut p, pn_offset, 1, i).unwrap();
        }
        assert_eq!(k.packet.sealed(), 3);
        assert_eq!(k.packet.failed(), 0);
        // a failure is counted, a success is not
        let mut p = clear.clone();
        Keys::new(AES128, &secret).seal(&mut p, pn_offset, 1, 1).unwrap();
        p[pn_offset + 3] ^= 1;
        assert!(k.open(&mut p, pn_offset, None).is_err());
        assert_eq!(k.packet.failed(), 1);
        assert_eq!(confidentiality_limit(AES128), 1 << 23);
        assert_eq!(confidentiality_limit(Suite::Aes256GcmSha384), 1 << 23);
        assert_eq!(integrity_limit(AES128), 1 << 52);
        assert_eq!(confidentiality_limit(Suite::Chacha20Poly1305Sha256), 1 << 62);
        assert_eq!(integrity_limit(Suite::Chacha20Poly1305Sha256), 1 << 36);
        k.packet.sealed = (1 << 23) - 1;
        assert!(!k.packet.confidentiality_limit_reached());
        k.packet.sealed = 1 << 23;
        assert!(k.packet.confidentiality_limit_reached());
        k.packet.failed = (1 << 52) - 1;
        assert!(!k.packet.integrity_limit_reached());
        k.packet.failed += 1;
        assert!(k.packet.integrity_limit_reached());
    }

    #[test]
    fn the_nonce_is_the_iv_with_the_packet_number_xored_into_its_end() {
        let k = PacketKey::new(AES128, &[0; 16], &unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hex(&k.nonce(0)), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&k.nonce(2)), "fa044b2f42a3fd3b46fb255e");
        assert_eq!(hex(&k.nonce(0x3fff_ffff_ffff_ffff)), "fa044b2f" .to_string() + &hex(&[0x42 ^ 0x3f, 0xa3 ^ 0xff, 0xfd ^ 0xff, 0x3b ^ 0xff, 0x46 ^ 0xff, 0xfb ^ 0xff, 0x25 ^ 0xff, 0x5c ^ 0xff]));
    }
}
