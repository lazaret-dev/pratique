//! AES-128 / AES-256 block encryption (FIPS 197). Only the forward cipher is implemented because
//! GCM uses counter mode.
//!
//! Two implementations sit behind [`Aes`], chosen once per process:
//!
//! * **hardware**: AES-NI on x86-64, the ARMv8 Cryptography Extensions on aarch64 (see
//!   (`aes_hw`). Detected at run time, and only used after a self-test against known
//!   answers and the portable code passed;
//! * **portable**: a bitsliced circuit with no table lookups and no secret-dependent branches or
//!   addresses (`aes_ct`), used on every other CPU and whenever the hardware path
//!   is unavailable or fails its self-test. `--cfg pratique_portable` forces it.
//!
//! Neither indexes memory with a key or data byte, so there is no cache-timing channel; the
//! table-based AES this replaces had one (backlog B-20).

use super::dit::Dit;
use super::{aes_ct, aes_hw};

/// Which implementation an [`Aes`] uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Backend {
    Portable,
    Hardware,
}

/// The backend new keys get: hardware if this CPU has it and the self-test passed.
pub(crate) fn default_backend() -> Backend {
    if aes_hw::available() {
        Backend::Hardware
    } else {
        Backend::Portable
    }
}

/// True if AES and GHASH run on the CPU's own instructions (AES-NI and PCLMULQDQ, or the ARMv8
/// AES and PMULL instructions) in this process, false if they use the portable constant-time code.
/// Either way the answer is the same and neither has table lookups; this only says which is faster.
pub fn hardware_accelerated() -> bool {
    default_backend() == Backend::Hardware
}

#[derive(Clone)]
enum Imp {
    Portable(aes_ct::Keys),
    Hardware(aes_hw::Keys),
}

#[derive(Clone)]
pub struct Aes {
    imp: Imp,
}

impl Aes {
    /// `key` must be 16 or 32 bytes.
    pub fn new(key: &[u8]) -> Aes {
        Aes::with_backend(key, default_backend())
    }

    /// Like [`Aes::new`] with an explicit implementation (the tests compare them). Asking for
    /// the hardware one on a CPU without it panics.
    // in builds without the hardware path `aes_hw::Keys` is uninhabited and `new` panics
    #[allow(unreachable_code)]
    pub(crate) fn with_backend(key: &[u8], backend: Backend) -> Aes {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        let imp = match backend {
            Backend::Portable => Imp::Portable(aes_ct::Keys::new(key)),
            Backend::Hardware => Imp::Hardware(aes_hw::Keys::new(key)),
        };
        Aes { imp }
    }

    pub(crate) fn backend(&self) -> Backend {
        match self.imp {
            Imp::Portable(_) => Backend::Portable,
            Imp::Hardware(_) => Backend::Hardware,
        }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        match &self.imp {
            Imp::Hardware(k) => k.encrypt_block(block),
            Imp::Portable(k) => {
                // the circuit works on four blocks at once; the other three lanes are idle
                let mut four = [0u8; 64];
                four[..16].copy_from_slice(block);
                k.encrypt4(&mut four);
                let out: [u8; 16] = four[..16].try_into().unwrap();
                crate::zeroize::Zeroize::zeroize(&mut four);
                out
            }
        }
    }

    /// XORs `data` with the CTR keystream for blocks `nonce || counter`, `nonce || counter + 1`,
    /// ... (a 32-bit big-endian counter that wraps, as in GCM). A last partial block uses the
    /// front of its keystream block.
    pub fn ctr_xor(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        match &self.imp {
            Imp::Hardware(k) => k.ctr_xor(nonce, counter, data),
            Imp::Portable(k) => {
                let mut counter = counter;
                for chunk in data.chunks_mut(64) {
                    let mut blocks = [0u8; 64];
                    for b in 0..4u32 {
                        let at = 16 * b as usize;
                        blocks[at..at + 12].copy_from_slice(nonce);
                        blocks[at + 12..at + 16].copy_from_slice(&counter.wrapping_add(b).to_be_bytes());
                    }
                    k.encrypt4(&mut blocks);
                    for (d, ks) in chunk.iter_mut().zip(blocks.iter()) {
                        *d ^= ks;
                    }
                    crate::zeroize::Zeroize::zeroize(&mut blocks);
                    counter = counter.wrapping_add(chunk.len().div_ceil(16) as u32);
                }
            }
        }
    }

    /// For GCM on the portable path, where a call costs a pass over four blocks: the encryption of J0 (`nonce || 1`, which
    /// masks the tag) and the keystream of the three blocks after it, from one pass, for a message of at most 48 bytes
    /// (which would otherwise take two). `None` on the hardware path, where a block costs no more alone.
    pub(crate) fn j0_and_short_keystream(&self, nonce: &[u8; 12]) -> Option<([u8; 16], [u8; 48])> {
        match &self.imp {
            Imp::Hardware(_) => None,
            Imp::Portable(k) => {
                let mut blocks = [0u8; 64];
                for b in 0..4u32 {
                    let at = 16 * b as usize;
                    blocks[at..at + 12].copy_from_slice(nonce);
                    blocks[at + 12..at + 16].copy_from_slice(&(1 + b).to_be_bytes());
                }
                k.encrypt4(&mut blocks);
                let j0: [u8; 16] = blocks[..16].try_into().unwrap();
                let ks: [u8; 48] = blocks[16..].try_into().unwrap();
                crate::zeroize::Zeroize::zeroize(&mut blocks);
                Some((j0, ks))
            }
        }
    }

    /// AES-GCM encryption of `data` in place in one pass, where the CPU has the code for it: the tag (the GHASH value S of
    /// `aad` and the ciphertext, masked with E(J0)). `None` if not (then CTR and GHASH are done one after the other).
    pub(crate) fn gcm_seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], powers: Option<&aes_hw::Powers>) -> Option<[u8; 16]> {
        match (&self.imp, powers) {
            (Imp::Hardware(k), Some(p)) => k.gcm_seal(nonce, aad, data, p),
            _ => None,
        }
    }

    /// The same for decryption: `data` is plaintext afterwards, the tag returned is the one the ciphertext it was should
    /// have, and the message's is still to be checked against it (and the ciphertext put back if it is wrong:
    /// [`Aes::ctr_xor`] does that).
    pub(crate) fn gcm_open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], powers: Option<&aes_hw::Powers>) -> Option<[u8; 16]> {
        match (&self.imp, powers) {
            (Imp::Hardware(k), Some(p)) => k.gcm_open(nonce, aad, data, p),
            _ => None,
        }
    }

    #[cfg(test)]
    fn wipe(&mut self) {
        match &mut self.imp {
            Imp::Portable(k) => k.wipe(),
            Imp::Hardware(k) => k.wipe(),
        }
    }

    #[cfg(test)]
    fn is_wiped(&self) -> bool {
        match &self.imp {
            Imp::Portable(k) => k.is_wiped(),
            Imp::Hardware(k) => k.is_wiped(),
        }
    }
}

/// The straightforward table-based AES this module used to be, kept as an independent oracle for
/// the tests. It leaks through its S-box lookups and is never used by the library.
#[cfg(test)]
pub(crate) mod reference {
    const fn build_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        let mut p: u8 = 1;
        let mut q: u8 = 1;
        loop {
            // multiply p by 3
            p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
            // divide q by 3 (multiply by 0xf6)
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            if q & 0x80 != 0 {
                q ^= 0x09;
            }
            let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
            sbox[p as usize] = x ^ 0x63;
            if p == 1 {
                break;
            }
        }
        sbox[0] = 0x63;
        sbox
    }

    static SBOX: [u8; 256] = build_sbox();

    pub(crate) fn sbox_table() -> [u8; 256] {
        SBOX
    }

    fn xtime(x: u8) -> u8 {
        (x << 1) ^ (((x >> 7) & 1).wrapping_mul(0x1b))
    }

    pub(crate) fn expand_key(key: &[u8]) -> ([[u8; 16]; 15], usize) {
        assert!(key.len() == 16 || key.len() == 32, "unsupported AES key length");
        let nk = key.len() / 4;
        let nr = nk + 6;
        let total_words = 4 * (nr + 1);
        let mut w: Vec<[u8; 4]> = Vec::with_capacity(total_words);
        for i in 0..nk {
            w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        let mut rcon: u8 = 1;
        for i in nk..total_words {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = [SBOX[t[0] as usize], SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize]];
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        let mut round_keys = [[0u8; 16]; 15];
        for r in 0..=nr {
            for c in 0..4 {
                round_keys[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        (round_keys, nr)
    }

    pub(crate) fn encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
        let (rk, nr) = expand_key(key);
        let xor = |s: &mut [u8; 16], k: &[u8; 16]| s.iter_mut().zip(k).for_each(|(a, b)| *a ^= b);
        let mut s = *block;
        xor(&mut s, &rk[0]);
        for r in 1..=nr {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let o = s;
            for c in 0..4 {
                for row in 0..4 {
                    s[4 * c + row] = o[4 * ((c + row) % 4) + row];
                }
            }
            if r != nr {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    let t = a[0] ^ a[1] ^ a[2] ^ a[3];
                    s[4 * c] = a[0] ^ t ^ xtime(a[0] ^ a[1]);
                    s[4 * c + 1] = a[1] ^ t ^ xtime(a[1] ^ a[2]);
                    s[4 * c + 2] = a[2] ^ t ^ xtime(a[2] ^ a[3]);
                    s[4 * c + 3] = a[3] ^ t ^ xtime(a[3] ^ a[0]);
                }
            }
            xor(&mut s, &rk[r]);
        }
        s
    }

    /// CTR keystream XOR with GCM's counter layout.
    pub(crate) fn ctr_xor(key: &[u8], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        let mut counter = counter;
        for chunk in data.chunks_mut(16) {
            let mut block = [0u8; 16];
            block[..12].copy_from_slice(nonce);
            block[12..].copy_from_slice(&counter.to_be_bytes());
            let ks = encrypt_block(key, &block);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            counter = counter.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    /// The backends to test: portable always, hardware where this CPU has it.
    fn backends() -> Vec<Backend> {
        let mut v = vec![Backend::Portable];
        if aes_hw::available() {
            v.push(Backend::Hardware);
        }
        v
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 24
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn sbox_spot_checks() {
        let t = reference::sbox_table();
        assert_eq!(t[0x00], 0x63);
        assert_eq!(t[0x01], 0x7c);
        assert_eq!(t[0x53], 0xed);
        assert_eq!(t[0xff], 0x16);
    }

    #[test]
    fn fips197_aes128() {
        for b in backends() {
            let aes = Aes::with_backend(&unhex("000102030405060708090a0b0c0d0e0f"), b);
            let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff").try_into().unwrap();
            assert_eq!(hex(&aes.encrypt_block(&pt)), "69c4e0d86a7b0430d8cdb78070b4c55a", "{b:?}");
        }
    }

    #[test]
    fn fips197_aes256() {
        for b in backends() {
            let aes = Aes::with_backend(&unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), b);
            let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff").try_into().unwrap();
            assert_eq!(hex(&aes.encrypt_block(&pt)), "8ea2b7ca516745bfeafc49904b496089", "{b:?}");
        }
    }

    #[test]
    fn fips197_appendix_b_and_nist_ecb_vectors() {
        // FIPS 197 appendix B, and the first AES-128 / AES-256 ECB known-answer vectors of SP 800-38A
        let cases = [
            ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
            ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
            ),
        ];
        for (key, pt, ct) in cases {
            let pt: [u8; 16] = unhex(pt).try_into().unwrap();
            for b in backends() {
                let aes = Aes::with_backend(&unhex(key), b);
                assert_eq!(hex(&aes.encrypt_block(&pt)), ct, "{b:?}");
            }
        }
    }

    #[test]
    fn every_backend_matches_the_table_reference_on_random_keys_and_blocks() {
        let mut rng = Lcg(7);
        for len in [16usize, 32] {
            for _ in 0..40 {
                let key = rng.bytes(len);
                let block: [u8; 16] = rng.bytes(16).try_into().unwrap();
                let want = reference::encrypt_block(&key, &block);
                for b in backends() {
                    assert_eq!(Aes::with_backend(&key, b).encrypt_block(&block), want, "{b:?} key {len}");
                }
            }
        }
    }

    #[test]
    fn ctr_matches_the_reference_for_every_length_and_counter_start() {
        let mut rng = Lcg(8);
        for key_len in [16usize, 32] {
            let key = rng.bytes(key_len);
            let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
            // lengths cover: empty, partial blocks, the 4-block and 8-block boundaries of the two
            // implementations, and a few multiples of both
            let lengths = [0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257, 500, 1031];
            // starting counters include the 32-bit wrap
            let counters = [0u32, 1, 2, 0xffff_fff9, 0xffff_fffe, 0xffff_ffff];
            for &len in &lengths {
                for &ctr in &counters {
                    let data = rng.bytes(len);
                    let mut want = data.clone();
                    reference::ctr_xor(&key, &nonce, ctr, &mut want);
                    for b in backends() {
                        let mut got = data.clone();
                        Aes::with_backend(&key, b).ctr_xor(&nonce, ctr, &mut got);
                        assert_eq!(got, want, "{b:?}, key {key_len}, len {len}, counter {ctr:#x}");
                    }
                }
            }
        }
    }

    #[test]
    fn ctr_works_on_unaligned_buffers() {
        let mut rng = Lcg(9);
        let key = rng.bytes(16);
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let backing = rng.bytes(400);
        for offset in 0..9 {
            let mut want = backing[offset..offset + 300].to_vec();
            reference::ctr_xor(&key, &nonce, 2, &mut want);
            for b in backends() {
                let mut buf = backing.clone();
                Aes::with_backend(&key, b).ctr_xor(&nonce, 2, &mut buf[offset..offset + 300]);
                assert_eq!(&buf[offset..offset + 300], &want[..], "{b:?} offset {offset}");
                // bytes outside the slice are untouched
                assert_eq!(&buf[..offset], &backing[..offset]);
                assert_eq!(&buf[offset + 300..], &backing[offset + 300..]);
            }
        }
    }

    #[test]
    fn the_hardware_backend_is_used_when_the_cpu_has_it() {
        // a CPU that advertises the instructions ends up on the hardware path (its self-test
        // passing is part of `available`), one that does not is on the portable path
        let backend = Aes::new(&[0u8; 16]).backend();
        assert_eq!(backend == Backend::Hardware, aes_hw::cpu_supports());
        assert_eq!(backend, default_backend());
        eprintln!("AES backend on this machine: {backend:?}");
    }

    #[test]
    fn key_schedule_is_wiped_and_type_has_drop_glue() {
        assert!(std::mem::needs_drop::<Aes>());
        for b in backends() {
            let mut a = Aes::with_backend(&[0x42u8; 32], b);
            assert!(!a.is_wiped(), "{b:?}");
            a.wipe();
            assert!(a.is_wiped(), "{b:?}");
        }
    }
}
