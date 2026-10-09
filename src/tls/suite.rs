//! TLS 1.3 cipher suites, the HKDF key schedule helpers, and the per-direction record cipher.

use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::crypto::gcm::AesGcm;
use crate::crypto::hmac::{self, Hmac};
use crate::crypto::sha2::{HashAlg, Sha256, Sha384, Sha512};
use crate::error::{Error, Result};
use crate::zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Suite {
    /// Every cipher suite this library implements.
    pub const ALL: [Suite; 3] = [Suite::Chacha20Poly1305Sha256, Suite::Aes128GcmSha256, Suite::Aes256GcmSha384];

    /// The suites in the order the ClientHello offers them, which servers that honour client
    /// preference follow. AES-GCM first when the CPU has AES instructions in use (several times
    /// faster than ChaCha20-Poly1305 there); otherwise ChaCha20-Poly1305 first, because the
    /// portable constant-time AES is much slower than ChaCha20.
    pub fn preference_order() -> [Suite; 3] {
        if crate::crypto::aes::hardware_accelerated() {
            [Suite::Aes128GcmSha256, Suite::Aes256GcmSha384, Suite::Chacha20Poly1305Sha256]
        } else {
            [Suite::Chacha20Poly1305Sha256, Suite::Aes128GcmSha256, Suite::Aes256GcmSha384]
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Suite::Aes128GcmSha256 => 0x1301,
            Suite::Aes256GcmSha384 => 0x1302,
            Suite::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn from_id(id: u16) -> Option<Suite> {
        Suite::ALL.into_iter().find(|s| s.id() == id)
    }

    pub fn hash(self) -> HashAlg {
        match self {
            Suite::Aes128GcmSha256 | Suite::Chacha20Poly1305Sha256 => HashAlg::Sha256,
            Suite::Aes256GcmSha384 => HashAlg::Sha384,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Suite::Aes128GcmSha256 => 16,
            Suite::Aes256GcmSha384 | Suite::Chacha20Poly1305Sha256 => 32,
        }
    }

    /// How many records one traffic key may protect before we rotate it with a KeyUpdate
    /// (counting the KeyUpdate record itself). RFC 8446 section 5.5 allows 2^24.5 full-size records
    /// under AES-GCM before the confidentiality margin of 2^-57 is gone; we stop at 2^24. The
    /// ChaCha20-Poly1305 limit is far higher, so the bound there only has to keep the 64-bit
    /// sequence number from ever wrapping.
    pub fn records_per_key(self) -> u64 {
        match self {
            Suite::Aes128GcmSha256 | Suite::Aes256GcmSha384 => 1 << 24,
            Suite::Chacha20Poly1305Sha256 => 1 << 48,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Suite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Suite::Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }
}

// ---- runtime-dispatched HMAC / HKDF over the negotiated hash ----

pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => Hmac::<Sha256>::mac(key, data),
        HashAlg::Sha384 => Hmac::<Sha384>::mac(key, data),
        HashAlg::Sha512 => Hmac::<Sha512>::mac(key, data),
    }
}

pub fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => hmac::hkdf_extract::<Sha256>(salt, ikm),
        HashAlg::Sha384 => hmac::hkdf_extract::<Sha384>(salt, ikm),
        HashAlg::Sha512 => hmac::hkdf_extract::<Sha512>(salt, ikm),
    }
}

pub fn expand_label(alg: HashAlg, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    Prk::new(alg, secret).expand_label(label, context, len)
}

pub fn derive_secret(alg: HashAlg, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(alg, secret, label, transcript_hash, alg.output_len())
}

/// A secret keyed into HMAC once, for several HKDF-Expand-Label outputs from it (B-104): the key and IV of a record cipher,
/// the two handshake traffic secrets, the application traffic secrets and the resumption master secret. Each output after
/// the first then costs two compressions of the hash instead of four.
pub(crate) enum Prk {
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl Prk {
    pub(crate) fn new(alg: HashAlg, secret: &[u8]) -> Prk {
        match alg {
            HashAlg::Sha256 => Prk::Sha256(Hmac::new(secret)),
            HashAlg::Sha384 => Prk::Sha384(Hmac::new(secret)),
            HashAlg::Sha512 => Prk::Sha512(Hmac::new(secret)),
        }
    }

    pub(crate) fn expand_label(&self, label: &str, context: &[u8], len: usize) -> Vec<u8> {
        match self {
            Prk::Sha256(h) => hmac::hkdf_expand_label_with(h, label, context, len),
            Prk::Sha384(h) => hmac::hkdf_expand_label_with(h, label, context, len),
            Prk::Sha512(h) => hmac::hkdf_expand_label_with(h, label, context, len),
        }
    }

    /// Derive-Secret: HKDF-Expand-Label over a transcript hash, as long as the hash.
    pub(crate) fn derive_secret(&self, label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        let len = match self {
            Prk::Sha256(_) => 32,
            Prk::Sha384(_) => 48,
            Prk::Sha512(_) => 64,
        };
        self.expand_label(label, transcript_hash, len)
    }
}

// ---- AEAD ----

#[derive(Clone)]
pub(crate) enum Aead {
    Gcm(AesGcm),
    ChaCha(ChaCha20Poly1305),
}

impl Aead {
    pub(crate) fn new(suite: Suite, key: &[u8]) -> Aead {
        match suite {
            Suite::Aes128GcmSha256 | Suite::Aes256GcmSha384 => Aead::Gcm(AesGcm::new(key)),
            Suite::Chacha20Poly1305Sha256 => Aead::ChaCha(ChaCha20Poly1305::new(key)),
        }
    }

    /// `buf` = plaintext followed by `AEAD_TAG_LEN` bytes of room; becomes ciphertext || tag.
    pub(crate) fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) {
        match self {
            Aead::Gcm(g) => g.seal_in_place(nonce, aad, buf),
            Aead::ChaCha(c) => c.seal_in_place(nonce, aad, buf),
        }
    }

    /// `buf` = ciphertext || tag. Returns the plaintext length on success; on failure `buf` is untouched.
    pub(crate) fn open_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        match self {
            Aead::Gcm(g) => g.open_in_place(nonce, aad, buf),
            Aead::ChaCha(c) => c.open_in_place(nonce, aad, buf),
        }
    }
}

pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Record types (RFC 8446 section 5.1).
pub const RT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const RT_ALERT: u8 = 21;
pub const RT_HANDSHAKE: u8 = 22;
pub const RT_APPLICATION_DATA: u8 = 23;

/// Keys, IV and sequence number for one direction of the record protocol.
pub struct RecordCipher {
    suite: Suite,
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
    secret: Vec<u8>,
}

impl Drop for RecordCipher {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl RecordCipher {
    /// Clears the IV and the traffic secret; the AEAD key schedule wipes itself when `aead` drops.
    fn wipe(&mut self) {
        self.iv.zeroize();
        self.secret.zeroize();
    }

    pub fn new(suite: Suite, traffic_secret: &[u8]) -> RecordCipher {
        let prk = Prk::new(suite.hash(), traffic_secret);
        let key = Zeroizing::new(prk.expand_label("key", &[], suite.key_len()));
        let iv_vec = Zeroizing::new(prk.expand_label("iv", &[], 12));
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        RecordCipher { suite, aead: Aead::new(suite, &key), iv, seq: 0, secret: traffic_secret.to_vec() }
    }

    /// The cipher for the next generation of traffic keys (KeyUpdate, RFC 8446 section 7.2).
    pub fn next_generation(&self) -> RecordCipher {
        let alg = self.suite.hash();
        let next = Zeroizing::new(expand_label(alg, &self.secret, "traffic upd", &[], alg.output_len()));
        RecordCipher::new(self.suite, &next)
    }

    /// How many records this key has protected or opened so far (the sequence number).
    pub fn records(&self) -> u64 {
        self.seq
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    /// Protects `content` as a record whose true type is `inner_type` and appends the complete wire
    /// record to `out`. The content is copied once, into `out`, and encrypted there in place.
    pub fn encrypt_into(&mut self, inner_type: u8, content: &[u8], out: &mut Vec<u8>) {
        debug_assert!(content.len() <= MAX_PLAINTEXT);
        let ct_len = content.len() + 1 + AEAD_TAG_LEN;
        let header = [RT_APPLICATION_DATA, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
        let start = out.len();
        out.reserve(5 + ct_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        out.push(inner_type);
        out.resize(start + 5 + ct_len, 0); // room for the tag
        let nonce = self.nonce();
        self.aead.seal_in_place(&nonce, &header, &mut out[start + 5..]);
        self.seq += 1;
    }

    /// Protects `content` as a record whose true type is `inner_type`; returns the complete wire record.
    #[cfg(test)]
    pub fn encrypt(&mut self, inner_type: u8, content: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(5 + content.len() + 1 + AEAD_TAG_LEN);
        self.encrypt_into(inner_type, content, &mut rec);
        rec
    }

    /// Opens a protected record in place. `payload` is the record body (ciphertext || tag) exactly
    /// as received. Returns (true content type, content length); the content is `payload[..len]`.
    /// If authentication fails `payload` is left untouched and the sequence number does not advance.
    pub fn decrypt_in_place(&mut self, header: &[u8; 5], payload: &mut [u8]) -> Result<(u8, usize)> {
        let nonce = self.nonce();
        let mut n = self
            .aead
            .open_in_place(&nonce, header, payload)
            .ok_or_else(|| Error::Tls("bad_record_mac: record failed authentication".into()))?;
        self.seq += 1;
        // the whole TLSInnerPlaintext, padding included, is at most 2^14 + 1 octets (RFC 8446 section 5.4)
        if n > MAX_PLAINTEXT + 1 {
            return Err(Error::Tls("record_overflow: inner plaintext too long".into()));
        }
        // Strip the optional zero padding; the last non-zero byte is the true content type.
        while n > 0 && payload[n - 1] == 0 {
            n -= 1;
        }
        if n == 0 {
            return Err(Error::Tls("unexpected_message: record with no content type".into()));
        }
        let inner_type = payload[n - 1];
        Ok((inner_type, n - 1))
    }

    /// Like `encrypt`, with `padding` zeros after the content type (RFC 8446 section 5.4) and no limit on the length.
    #[cfg(test)]
    pub fn encrypt_padded(&mut self, inner_type: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let ct_len = content.len() + 1 + padding + AEAD_TAG_LEN;
        let header = [RT_APPLICATION_DATA, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
        let mut rec = header.to_vec();
        rec.extend_from_slice(content);
        rec.push(inner_type);
        rec.resize(5 + ct_len, 0);
        let nonce = self.nonce();
        self.aead.seal_in_place(&nonce, &header, &mut rec[5..]);
        self.seq += 1;
        rec
    }

    /// Opens a protected record; returns (true content type, content).
    #[cfg(test)]
    pub fn decrypt(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut buf = ciphertext.to_vec();
        let (t, len) = self.decrypt_in_place(header, &mut buf)?;
        buf.truncate(len);
        Ok((t, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inner_plaintext_padding_included_is_at_most_2_to_the_14_plus_1() {
        // RFC 8446 section 5.4; tlsfuzzer's test-tls13-record-layer-limits found the padding was not counted
        for suite in Suite::ALL {
            let secret = vec![7u8; suite.hash().output_len()];
            let (mut enc, mut dec) = (RecordCipher::new(suite, &secret), RecordCipher::new(suite, &secret));
            for (content, padding, ok) in [(36, MAX_PLAINTEXT - 36, true), (36, MAX_PLAINTEXT - 35, false), (MAX_PLAINTEXT, 0, true), (MAX_PLAINTEXT - 8, 9, false)] {
                let rec = enc.encrypt_padded(RT_HANDSHAKE, &vec![1u8; content], padding);
                let header: [u8; 5] = rec[..5].try_into().unwrap();
                match dec.decrypt(&header, &rec[5..]) {
                    Ok((t, body)) => assert!(ok && t == RT_HANDSHAKE && body.len() == content, "{content} + {padding}"),
                    Err(e) => {
                        assert!(!ok && e.to_string().contains("record_overflow"), "{content} + {padding}: {e}");
                        // (the sequence moved on: the record opened)
                        dec = RecordCipher::new(suite, &secret);
                        enc = RecordCipher::new(suite, &secret);
                    }
                }
            }
        }
    }

    #[test]
    fn record_roundtrip_all_suites() {
        for suite in Suite::ALL {
            let secret = vec![0x42u8; suite.hash().output_len()];
            let mut enc = RecordCipher::new(suite, &secret);
            let mut dec = RecordCipher::new(suite, &secret);
            for i in 0..3u8 {
                let msg = vec![i; 100 + i as usize];
                let rec = enc.encrypt(RT_APPLICATION_DATA, &msg);
                let header: [u8; 5] = rec[..5].try_into().unwrap();
                let (t, body) = dec.decrypt(&header, &rec[5..]).unwrap();
                assert_eq!(t, RT_APPLICATION_DATA);
                assert_eq!(body, msg);
            }
            // replayed (wrong sequence) record must fail
            let rec = enc.encrypt(RT_HANDSHAKE, b"x");
            let header: [u8; 5] = rec[..5].try_into().unwrap();
            let mut fresh = RecordCipher::new(suite, &secret);
            assert!(fresh.decrypt(&header, &rec[5..]).is_err());
            // key update changes keys
            let mut next = enc.next_generation();
            let rec2 = next.encrypt(RT_APPLICATION_DATA, b"y");
            let header2: [u8; 5] = rec2[..5].try_into().unwrap();
            assert!(dec.decrypt(&header2, &rec2[5..]).is_err());
        }
    }

    #[test]
    fn in_place_apis_match_allocating_ones() {
        for suite in Suite::ALL {
            let secret = vec![0x24u8; suite.hash().output_len()];
            let mut a = RecordCipher::new(suite, &secret);
            let mut b = RecordCipher::new(suite, &secret);
            let mut dec = RecordCipher::new(suite, &secret);
            // encrypt_into appends after whatever is already in the buffer.
            let mut out = b"PREFIX".to_vec();
            for len in [0usize, 1, 15, 16, 255, 1000, MAX_PLAINTEXT] {
                let msg: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
                let reference = a.encrypt(RT_HANDSHAKE, &msg);
                let before = out.len();
                b.encrypt_into(RT_HANDSHAKE, &msg, &mut out);
                assert_eq!(&out[before..], &reference[..], "{suite:?} len {len}");
                assert_eq!(&out[..6], b"PREFIX");

                let header: [u8; 5] = reference[..5].try_into().unwrap();
                let mut body = reference[5..].to_vec();
                let (t, n) = dec.decrypt_in_place(&header, &mut body).unwrap();
                assert_eq!((t, &body[..n]), (RT_HANDSHAKE, &msg[..]));
            }
        }
    }

    #[test]
    fn decrypt_in_place_strips_padding_and_rejects_bad_records() {
        for suite in Suite::ALL {
            let secret = vec![0x11u8; suite.hash().output_len()];
            let mut enc = RecordCipher::new(suite, &secret);
            let mut dec = RecordCipher::new(suite, &secret);

            // A record carrying zero padding after the content type (RFC 8446 section 5.4).
            let mut padded = b"hello".to_vec();
            padded.push(RT_APPLICATION_DATA);
            padded.extend_from_slice(&[0u8; 7]);
            let ct_len = padded.len() + AEAD_TAG_LEN;
            let header = [RT_APPLICATION_DATA, 3, 3, (ct_len >> 8) as u8, ct_len as u8];
            padded.resize(ct_len, 0);
            enc.aead.seal_in_place(&enc.nonce(), &header, &mut padded);
            enc.seq += 1;
            let (t, n) = dec.decrypt_in_place(&header, &mut padded).unwrap();
            assert_eq!((t, &padded[..n]), (RT_APPLICATION_DATA, &b"hello"[..]));

            // Corrupted record: error, buffer untouched, sequence number not consumed.
            let rec = enc.encrypt(RT_APPLICATION_DATA, b"next");
            let header: [u8; 5] = rec[..5].try_into().unwrap();
            let mut bad = rec[5..].to_vec();
            bad[0] ^= 1;
            let snapshot = bad.clone();
            assert!(dec.decrypt_in_place(&header, &mut bad).is_err());
            assert_eq!(bad, snapshot);
            let mut good = rec[5..].to_vec();
            let (t, n) = dec.decrypt_in_place(&header, &mut good).unwrap();
            assert_eq!((t, &good[..n]), (RT_APPLICATION_DATA, &b"next"[..]));

            // All-zero plaintext has no content type; a bare tag is not a record either.
            let mut zeros = vec![0u8; 4 + AEAD_TAG_LEN];
            let hdr = [RT_APPLICATION_DATA, 3, 3, 0, zeros.len() as u8];
            enc.aead.seal_in_place(&enc.nonce(), &hdr, &mut zeros);
            enc.seq += 1;
            assert!(dec.decrypt_in_place(&hdr, &mut zeros).is_err());
            assert!(dec.decrypt_in_place(&hdr, &mut [0u8; 3]).is_err());
        }
    }

    #[test]
    fn rfc8448_traffic_key_derivation() {
        // RFC 8448 section 3: server handshake traffic secret -> write key and iv (TLS_AES_128_GCM_SHA256)
        let s_hs = crate::util::unhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let key = expand_label(HashAlg::Sha256, &s_hs, "key", &[], 16);
        let iv = expand_label(HashAlg::Sha256, &s_hs, "iv", &[], 12);
        assert_eq!(crate::util::hex(&key), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(crate::util::hex(&iv), "5d313eb2671276ee13000b30");
    }

    /// The next generation of traffic keys (RFC 8446 section 7.2: HKDF-Expand-Label(secret,
    /// "traffic upd", "", Hash.length), then the usual key and iv) against values from Python's
    /// `hmac` and `cryptography` AEADs: the record is the first one under the new key (sequence 0)
    /// carrying "hello, key update" as application data.
    #[test]
    fn key_update_derivation_matches_an_independent_implementation() {
        let cases = [
            (
                Suite::Aes128GcmSha256,
                "4ea2bec0cc17ed98d6be703f8660a8af6467b2092f3b3e7ee3f8768f8d8babf9",
                "be0d030120b0ccc90b2e8b4e",
                "170303002248e487b8423aa23debc68049c39eeb9760e02479a25bbbc07e17e1169d533efb9f7b",
            ),
            (
                Suite::Aes256GcmSha384,
                "9bcc0d868a504487ca1e0ad650b0d8a95576a776044b38636376a2e65c13ea47c8ddb676cd89cb3d9ba5759a33674b65",
                "51a981a0d896514a0e4da524",
                "17030300221b3bfd9f226ece0c046ecd0a4a8398e9334c8926bb203ca16c3a148967f5058595cd",
            ),
            (
                Suite::Chacha20Poly1305Sha256,
                "4ea2bec0cc17ed98d6be703f8660a8af6467b2092f3b3e7ee3f8768f8d8babf9",
                "be0d030120b0ccc90b2e8b4e",
                "1703030022786d89db32c24c24e47cffa6ff1e9021b45f323738b80a5b2efa0db0da71a0fe4224",
            ),
        ];
        for (suite, next_secret, iv, record) in cases {
            let first = RecordCipher::new(suite, &vec![0x42u8; suite.hash().output_len()]);
            let mut next = first.next_generation();
            assert_eq!(crate::util::hex(&next.secret), next_secret, "{:?}", suite);
            assert_eq!(crate::util::hex(&next.iv), iv, "{:?}", suite);
            assert_eq!(next.records(), 0);
            assert_eq!(crate::util::hex(&next.encrypt(RT_APPLICATION_DATA, b"hello, key update")), record, "{:?}", suite);
            assert_eq!(next.records(), 1);
            // and the generation after that is another one, not the same keys again
            assert_ne!(next.next_generation().secret, next.secret);
        }
    }

    #[test]
    fn record_cipher_secrets_are_wiped_and_type_has_drop_glue() {
        assert!(std::mem::needs_drop::<RecordCipher>());
        let mut c = RecordCipher::new(Suite::Chacha20Poly1305Sha256, &[0x33u8; 32]);
        assert!(c.iv.iter().any(|&b| b != 0) && c.secret.iter().any(|&b| b != 0));
        c.wipe();
        assert_eq!(c.iv, [0u8; 12]);
        assert!(c.secret.is_empty());
    }
}
