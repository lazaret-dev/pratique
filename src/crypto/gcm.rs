//! AES-GCM authenticated encryption (NIST SP 800-38D), 96-bit nonces only (as in TLS 1.3).

use super::dit::Dit;
use super::aes::Aes;
#[cfg(any(test, pratique_fuzzing))]
use super::aes::Backend;
use super::ghash::GhashKey;
use crate::util::ct_eq;
use crate::zeroize::Zeroize;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct AesGcm {
    aes: Aes,
    ghash: GhashKey,
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl AesGcm {
    /// `key` must be 16 or 32 bytes. Uses the hardware AES and GHASH where the CPU has them (see
    /// [`super::aes`]), the constant-time portable code otherwise.
    pub fn new(key: &[u8]) -> Self {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        AesGcm::from_aes(Aes::new(key))
    }

    /// Like [`AesGcm::new`] with an explicit implementation, for the tests that compare them.
    #[cfg(any(test, pratique_fuzzing))]
    pub(crate) fn with_backend(key: &[u8], backend: Backend) -> Self {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        AesGcm::from_aes(Aes::with_backend(key, backend))
    }

    fn from_aes(aes: Aes) -> Self {
        let mut h = aes.encrypt_block(&[0u8; 16]);
        let ghash = GhashKey::new(&h, aes.backend());
        h.zeroize();
        AesGcm { aes, ghash }
    }

    #[cfg(any(test, pratique_fuzzing))]
    pub(crate) fn backend(&self) -> Backend {
        self.aes.backend()
    }

    /// Clears the hash subkey; the AES key schedule wipes itself when `aes` is dropped.
    fn wipe(&mut self) {
        self.ghash.wipe();
    }

    fn ctr_xor(&self, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
        // J0 uses counter 1; data starts at 2
        self.aes.ctr_xor(nonce, 2, data);
    }

    fn tag(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        self.mask_tag(nonce, self.ghash.hash(aad, ciphertext))
    }

    /// The tag from the GHASH value `s`: it is XORed with the encryption of J0.
    fn mask_tag(&self, nonce: &[u8; NONCE_LEN], mut s: [u8; 16]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let mut ek = self.aes.encrypt_block(&j0);
        for (t, k) in s.iter_mut().zip(ek.iter()) {
            *t ^= k;
        }
        ek.zeroize();
        s
    }

    /// Encrypts in place. `buf` holds the plaintext followed by `TAG_LEN` bytes of room; on return
    /// it holds ciphertext || tag.
    pub fn seal_in_place(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        assert!(buf.len() >= TAG_LEN, "buffer must have room for the tag");
        let n = buf.len() - TAG_LEN;
        let (data, tag_out) = buf.split_at_mut(n);
        // one pass over the data where the CPU has the code for it, else CTR and then GHASH
        let tag = match self.aes.gcm_seal(nonce, aad, data, self.ghash.powers()) {
            Some(tag) => tag,
            None => match self.short(nonce, data.len()) {
                // a short message and J0 from one pass of the portable cipher
                Some((mut j0, mut ks)) => {
                    for (d, k) in data.iter_mut().zip(ks.iter()) {
                        *d ^= k;
                    }
                    let mut tag = self.ghash.hash(aad, data);
                    for (t, k) in tag.iter_mut().zip(j0.iter()) {
                        *t ^= k;
                    }
                    j0.zeroize();
                    ks.zeroize();
                    tag
                }
                None => {
                    self.ctr_xor(nonce, data);
                    self.tag(nonce, aad, data)
                }
            },
        };
        tag_out.copy_from_slice(&tag);
    }

    /// Decrypts in place. `buf` holds ciphertext || tag. On success returns the plaintext length
    /// and `buf[..len]` holds the plaintext; on failure returns `None` and `buf` is untouched
    /// (the tag is verified before anything is decrypted).
    pub fn open_in_place(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        if buf.len() < TAG_LEN {
            return None;
        }
        let n = buf.len() - TAG_LEN;
        let (data, tag) = buf.split_at_mut(n);
        if let Some(expected) = self.aes.gcm_open(nonce, aad, data, self.ghash.powers()) {
            // decrypted and hashed in one pass: the tag is checked now, and if it is wrong the ciphertext is put back (the
            // keystream is the same, so one more XOR does it) and nothing has changed
            if !ct_eq(&expected, tag) {
                self.ctr_xor(nonce, data);
                return None;
            }
            return Some(n);
        }
        if let Some((mut j0, mut ks)) = self.short(nonce, n) {
            let mut expected = self.ghash.hash(aad, data);
            for (t, k) in expected.iter_mut().zip(j0.iter()) {
                *t ^= k;
            }
            let good = ct_eq(&expected, tag);
            if good {
                for (d, k) in data.iter_mut().zip(ks.iter()) {
                    *d ^= k;
                }
            }
            j0.zeroize();
            ks.zeroize();
            return good.then_some(n);
        }
        let expected = self.tag(nonce, aad, data);
        if !ct_eq(&expected, tag) {
            return None;
        }
        self.ctr_xor(nonce, data);
        Some(n)
    }

    /// J0's encryption and the keystream of a message of at most 48 bytes, from one pass of the portable cipher (`None`
    /// for a longer message, or on the hardware path).
    fn short(&self, nonce: &[u8; NONCE_LEN], len: usize) -> Option<([u8; 16], [u8; 48])> {
        if len > 48 {
            return None;
        }
        self.aes.j0_and_short_keystream(nonce)
    }

    /// [`AesGcm::seal_in_place`] by the two steps, CTR and then GHASH, whatever the CPU has: what the hardware path did
    /// before B-85 gave it one pass. Test builds only, for the timing tests that compare the two
    /// (`crypto::timing::aes_gcm_seal_parts`).
    #[cfg(test)]
    pub(crate) fn seal_in_place_two_passes(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) {
        let _dit = Dit::on();
        let n = buf.len() - TAG_LEN;
        let (data, tag_out) = buf.split_at_mut(n);
        self.ctr_xor(nonce, data);
        let tag = self.tag(nonce, aad, data);
        tag_out.copy_from_slice(&tag);
    }

    /// [`AesGcm::seal_in_place`] with the aarch64 one-pass kernel as it was from B-85 until the timing tests (it read each
    /// group of ciphertext back from memory to hash it; `aes_hw::SEAL_BY_RELOAD`). The same as `seal_in_place` elsewhere.
    /// Test builds only.
    #[cfg(test)]
    pub(crate) fn seal_in_place_by_reload(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) {
        super::aes_hw::SEAL_BY_RELOAD.with(|c| c.set(true));
        self.seal_in_place(nonce, aad, buf);
        super::aes_hw::SEAL_BY_RELOAD.with(|c| c.set(false));
    }

    /// Returns ciphertext || tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        out.resize(plaintext.len() + TAG_LEN, 0);
        self.seal_in_place(nonce, aad, &mut out);
        out
    }

    /// Verifies the tag over `ciphertext_and_tag` and returns the plaintext.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext_and_tag: &[u8]) -> Option<Vec<u8>> {
        let mut buf = ciphertext_and_tag.to_vec();
        let n = self.open_in_place(nonce, aad, &mut buf)?;
        buf.truncate(n);
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    /// Every implementation this machine can run: the portable one always, the hardware one where
    /// the CPU has it. Each test below runs on all of them.
    fn gcms(key: &[u8]) -> Vec<AesGcm> {
        let mut v = vec![AesGcm::with_backend(key, Backend::Portable)];
        if super::super::aes_hw::available() {
            v.push(AesGcm::with_backend(key, Backend::Hardware));
        }
        v
    }

    /// The two-step seal and the one-pass seal as it was until the timing tests (which read its ciphertext back), which those
    /// tests compare with the one-pass seal, give the same bytes as it (every length around the groups of eight blocks,
    /// both key sizes, every implementation).
    #[test]
    fn the_two_step_seal_is_the_same_as_the_one_pass_seal() {
        let nonce = [7u8; 12];
        for key_len in [16usize, 32] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            for g in gcms(&key) {
                for len in (0..300).chain([1024, 1040, 4096 + 5]) {
                    let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                    let mut one = plain.clone();
                    one.extend_from_slice(&[0u8; TAG_LEN]);
                    let mut two = one.clone();
                    let mut reload = one.clone();
                    g.seal_in_place(&nonce, b"aad", &mut one);
                    g.seal_in_place_two_passes(&nonce, b"aad", &mut two);
                    g.seal_in_place_by_reload(&nonce, b"aad", &mut reload);
                    assert_eq!(one, two, "{:?}, {key_len}-byte key, {len} bytes", g.backend());
                    assert_eq!(one, reload, "{:?}, {key_len}-byte key, {len} bytes (by reload)", g.backend());
                    // and it opens
                    assert_eq!(g.open_in_place(&nonce, b"aad", &mut one), Some(len));
                    assert_eq!(one[..len], plain[..]);
                }
            }
        }
    }

    #[test]
    fn nist_test_case_1_and_2() {
        let nonce = [0u8; 12];
        for g in gcms(&[0u8; 16]) {
            assert_eq!(hex(&g.seal(&nonce, &[], &[])), "58e2fccefa7e3061367f1d57a4e7455a", "{:?}", g.backend());
            assert_eq!(
                hex(&g.seal(&nonce, &[], &[0u8; 16])),
                "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
                "{:?}",
                g.backend()
            );
        }
    }

    /// SP 800-38D test cases 3 and 4 (a 64-byte message, then a 60-byte one with 20 bytes of AAD)
    /// and the AES-256 cases 15 and 16.
    #[test]
    fn nist_test_cases_3_4_15_16() {
        let key128 = unhex("feffe9928665731c6d6a8f9467308308");
        let key256 = unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce: [u8; 12] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let pt = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let cases: [(&[u8], &[u8], &[u8], &str, &str); 4] = [
            (
                &key128,
                &pt[..],
                &[],
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (
                &key128,
                &pt[..60],
                &aad,
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
            (
                &key256,
                &pt[..],
                &[],
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                "b094dac5d93471bdec1a502270e3cc6c",
            ),
            (
                &key256,
                &pt[..60],
                &aad,
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            ),
        ];
        for (key, pt, aad, ct, tag) in cases {
            for g in gcms(key) {
                let out = g.seal(&nonce, aad, pt);
                assert_eq!(hex(&out[..pt.len()]), ct, "ciphertext, {:?}, key {}", g.backend(), key.len());
                assert_eq!(hex(&out[pt.len()..]), tag, "tag, {:?}, key {}", g.backend(), key.len());
                assert_eq!(g.open(&nonce, aad, &out).unwrap(), pt);
            }
        }
    }

    fn sample_plaintext() -> Vec<u8> {
        (0..77u32).map(|i| ((i * 7 + 3) & 255) as u8).collect()
    }

    #[test]
    fn matches_reference_aes128() {
        let key = unhex("01060b10151a1f24292e33383d42474c");
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
        for g in gcms(&key) {
            let ct = g.seal(&nonce, b"tls13 record header", &sample_plaintext());
            assert_eq!(
                hex(&ct),
                "2cd0cbc979ed22bbd19e6960cfd68df4fb515037e4aba5f1360ca34579bf4e73c963bdc822d9ac16ec0a25609fcd41e5857b82fadd2ec0224db01aa5deb1cfc2c16e79435e224169784e0e34b5fb3b1756198fc2272cbd14ae438cfccb"
            );
            assert_eq!(g.open(&nonce, b"tls13 record header", &ct).unwrap(), sample_plaintext());
        }
    }

    #[test]
    fn matches_reference_aes256() {
        let key = unhex("01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979c");
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
        for g in gcms(&key) {
            let ct = g.seal(&nonce, b"tls13 record header", &sample_plaintext());
            assert_eq!(
                hex(&ct),
                "ec9a2c39a74caa83be6b3b7d967a7f2c27ca67a70006b3e4dd260ba92f31eb9e2ea7dfdfb552cba6018ef34dc32c9bce838b0c1e67c5b2efb9fee64c02a2582a4ac4f9c1f7672a202aa4974f00a639d57d29bdc1882422f2f96fd39eb4"
            );
            assert_eq!(g.open(&nonce, b"tls13 record header", &ct).unwrap(), sample_plaintext());
        }
    }

    #[test]
    fn matches_independent_vectors() {
        use crate::crypto::aead_vectors::*;
        use crate::crypto::sha2::{Hash, Sha256};
        for &(idx, klen, n, alen, ct_sha, tag) in GCM_VECTORS {
            for g in gcms(&det_key(idx, klen)) {
                let nonce = det_nonce(idx);
                let aad = det_aad(idx, alen);
                let pt = det_pt(idx, n);
                let out = g.seal(&nonce, &aad, &pt);
                assert_eq!(hex(&Sha256::digest(&out[..n])), ct_sha, "ciphertext, vector {idx} (len {n}, key {klen}, {:?})", g.backend());
                assert_eq!(hex(&out[n..]), tag, "tag, vector {idx}, {:?}", g.backend());
                assert_eq!(g.open(&nonce, &aad, &out).unwrap(), pt);
            }
        }
    }

    /// The portable and hardware implementations agree with each other on keys, nonces, AAD and
    /// message lengths chosen to cross every block and unrolling boundary, in both directions.
    #[test]
    fn backends_agree_on_random_inputs() {
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        for key_len in [16usize, 32] {
            for len in [0usize, 1, 15, 16, 17, 47, 63, 64, 65, 127, 128, 129, 255, 256, 1000, 4096, 16384 + 1] {
                for aad_len in [0usize, 5, 16, 29] {
                    let key: Vec<u8> = (0..key_len).map(|_| next()).collect();
                    let nonce: [u8; 12] = core::array::from_fn(|_| next());
                    let aad: Vec<u8> = (0..aad_len).map(|_| next()).collect();
                    let pt: Vec<u8> = (0..len).map(|_| next()).collect();
                    let all = gcms(&key);
                    let want = all[0].seal(&nonce, &aad, &pt);
                    for g in &all {
                        assert_eq!(g.seal(&nonce, &aad, &pt), want, "{:?} key {key_len} len {len} aad {aad_len}", g.backend());
                        assert_eq!(g.open(&nonce, &aad, &want).as_deref(), Some(&pt[..]));
                    }
                }
            }
        }
    }

    /// Every length from 0 to 520 (all the remainders after groups of eight blocks and after whole blocks) with additional
    /// data of several sizes (the one-pass hardware code hashes it by groups of eight blocks too): the implementations agree,
    /// a wrong tag or wrong additional data is refused with the buffer exactly as it was, and a right one opens.
    #[test]
    fn every_length_with_every_kind_of_additional_data() {
        let key: Vec<u8> = (0..16).map(|i| (i * 17 + 1) as u8).collect();
        let nonce = [0x5au8; 12];
        let all = gcms(&key);
        for len in 0..=520usize {
            for aad_len in [0usize, 5, 13, 16, 17, 127, 128, 129, 300] {
                let aad: Vec<u8> = (0..aad_len).map(|i| (i * 7 + len) as u8).collect();
                let pt: Vec<u8> = (0..len).map(|i| (i * 5 + aad_len) as u8).collect();
                let want = all[0].seal(&nonce, &aad, &pt);
                for g in &all {
                    let mut buf = pt.clone();
                    buf.resize(len + TAG_LEN, 0);
                    g.seal_in_place(&nonce, &aad, &mut buf);
                    assert_eq!(buf, want, "{:?} len {len} aad {aad_len}", g.backend());
                    // wrong tag, wrong additional data: refused, buffer as it was
                    let mut bad_tag = want.clone();
                    *bad_tag.last_mut().unwrap() ^= 0x80;
                    let before = bad_tag.clone();
                    assert!(g.open_in_place(&nonce, &aad, &mut bad_tag).is_none());
                    assert_eq!(bad_tag, before, "{:?} len {len} aad {aad_len}", g.backend());
                    let mut wrong_aad = want.clone();
                    let mut other = aad.clone();
                    other.push(1);
                    assert!(g.open_in_place(&nonce, &other, &mut wrong_aad).is_none());
                    assert_eq!(wrong_aad, want);
                    // and the right one opens
                    let n = g.open_in_place(&nonce, &aad, &mut buf).unwrap();
                    assert_eq!(&buf[..n], &pt[..]);
                }
            }
        }
    }

    #[test]
    fn in_place_failure_leaves_buffer_untouched() {
        for g in gcms(&[5u8; 32]) {
            let nonce = [2u8; 12];
            for len in [0usize, 1, 16, 17, 300, 16384] {
                let pt: Vec<u8> = (0..len).map(|i| (i * 3) as u8).collect();
                let mut buf = pt.clone();
                buf.resize(len + TAG_LEN, 0xaa);
                g.seal_in_place(&nonce, b"hdr", &mut buf);
                assert_eq!(buf, g.seal(&nonce, b"hdr", &pt));

                let mut bad = buf.clone();
                let pos = (len / 2).min(bad.len() - 1);
                bad[pos] ^= 1;
                let before = bad.clone();
                assert!(g.open_in_place(&nonce, b"hdr", &mut bad).is_none());
                assert_eq!(bad, before);

                let n = g.open_in_place(&nonce, b"hdr", &mut buf).unwrap();
                assert_eq!(&buf[..n], &pt[..]);
            }
            assert!(g.open_in_place(&nonce, b"", &mut [0u8; 15]).is_none());
        }
    }

    #[test]
    fn rejects_tampering() {
        for g in gcms(&[7u8; 16]) {
            let nonce = [1u8; 12];
            let mut ct = g.seal(&nonce, b"aad", b"hello world");
            assert!(g.open(&nonce, b"aad", &ct).is_some());
            assert!(g.open(&nonce, b"AAD", &ct).is_none());
            ct[0] ^= 1;
            assert!(g.open(&nonce, b"aad", &ct).is_none());
            assert!(g.open(&nonce, b"aad", &[0u8; 5]).is_none());
        }
    }

    #[test]
    fn secrets_are_wiped_and_types_have_drop_glue() {
        assert!(std::mem::needs_drop::<AesGcm>());
        for mut g in gcms(&[0x42u8; 32]) {
            assert!(!g.ghash.is_wiped());
            g.wipe();
            assert!(g.ghash.is_wiped());
        }
    }
}
