//! GHASH (NIST SP 800-38D section 6.4), the universal hash inside AES-GCM.
//!
//! GCM numbers the bits of a block backwards: in the 128-bit big-endian value of a block, the top
//! bit is the coefficient of x^0. Reversing all 128 bits turns a block into an ordinary polynomial
//! (bit `k` = coefficient of x^k) over GF(2), so a field multiplication becomes a plain
//! carry-less multiplication followed by a reduction modulo x^128 + x^7 + x^2 + x + 1. The hash
//! runs entirely in that reflected form and reverses the result at the end.
//!
//! Portable products use the independently derived Boolean primitives in
//! `clmul_clean` and `clmul_batch_clean`. On64-bit targets, fifty payload blocks
//! share each batch with fourteen public guard lanes; the fixed guard product is
//! removed before reduction. On32-bit targets and for tails, the accepted scalar
//! recurrence is retained. PCLMULQDQ/PMULL keep their existing hardware path.

use super::aes::Backend;
use super::aes_hw;
#[cfg(target_pointer_width = "64")]
use super::clmul_batch_clean::guarded::{
    clmul128x50_batch_xor_prepared, PreparedPolynomial128x50, PAYLOAD_LANES,
};
use super::clmul_batch_clean::BatchWorking128x64;
use super::clmul_clean::clmul64_portable;
use crate::zeroize::Zeroize;
#[cfg(target_pointer_width = "64")]
use crate::zeroize::Zeroizing;

// The clean primitive exposes its retained arrays without depending on the
// production zeroization implementation. Every aggregate is covered here.
impl Zeroize for BatchWorking128x64 {
    fn zeroize(&mut self) {
        for words in self.words64_mut() {
            words.zeroize();
        }
        for words in self.words128_mut() {
            words.zeroize();
        }
    }
}

/// 64 x 64 -> 128 bit carry-less product on the chosen implementation.
#[inline(always)]
fn clmul64<const HW: bool>(a: u64, b: u64) -> u128 {
    if HW {
        // SAFETY: `HW = true` is only instantiated by `hash_with::<true>`, whose callers
        // (`aes_hw`) run it after the CPU features were checked, in a function compiled with them.
        unsafe { aes_hw::clmul64(a, b) }
    } else {
        clmul64_portable(a, b)
    }
}

/// Product of two reflected field elements, reduced: `(lo, hi)` of the 255-bit carry-less product
/// by Karatsuba (three 64-bit multiplications instead of four), then folded modulo
/// x^128 + x^7 + x^2 + x + 1.
#[inline(always)]
fn mul<const HW: bool>(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64::<HW>(a0, b0);
    let hi = clmul64::<HW>(a1, b1);
    let mid = clmul64::<HW>(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    let p_lo = lo ^ (mid << 64);
    let p_hi = hi ^ (mid >> 64);
    reduce(p_lo, p_hi)
}

/// `p_lo + p_hi * x^128` modulo x^128 + x^7 + x^2 + x + 1, where x^128 = x^7 + x^2 + x + 1.
#[inline(always)]
fn reduce(p_lo: u128, p_hi: u128) -> u128 {
    // p_hi * (1 + x + x^2 + x^7) can spill up to 7 bits past x^127; those fold once more
    let spill = (p_hi >> 121) ^ (p_hi >> 126) ^ (p_hi >> 127);
    let fold = |v: u128| v ^ (v << 1) ^ (v << 2) ^ (v << 7);
    p_lo ^ fold(p_hi) ^ fold(spill)
}

/// Absorbs `data` into `acc`, zero-padding a final partial block. All values are reflected.
#[inline(always)]
fn absorb<const HW: bool>(h: u128, mut acc: u128, data: &[u8]) -> u128 {
    let mut chunks = data.chunks_exact(16);
    for c in &mut chunks {
        let x = u128::from_be_bytes(c.try_into().unwrap()).reverse_bits();
        acc = mul::<HW>(acc ^ x, h);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut b = [0u8; 16];
        b[..rest.len()].copy_from_slice(rest);
        acc = mul::<HW>(acc ^ u128::from_be_bytes(b).reverse_bits(), h);
    }
    acc
}

/// Absorb full public-length batches, then preserve scalar zero-padding of the tail.
/// Each batch expands the same recurrence with its incoming state in block one.
#[cfg(target_pointer_width = "64")]
fn absorb_portable(
    h: u128,
    prepared: &PreparedPolynomial128x50,
    mut acc: u128,
    data: &[u8],
) -> u128 {
    let mut batches = data.chunks_exact(PAYLOAD_LANES * 16);
    for batch in &mut batches {
        let mut blocks = Zeroizing::new([0u128; PAYLOAD_LANES]);
        for (block, bytes) in blocks.iter_mut().zip(batch.chunks_exact(16)) {
            *block = u128::from_be_bytes(bytes.try_into().unwrap()).reverse_bits();
        }
        blocks[0] ^= acc;
        {
            // Only zero storage moves into the guard. The populated workspace is
            // borrowed in place and wiped at this scope boundary after output use.
            let mut working = Zeroizing::new(BatchWorking128x64::empty());
            clmul128x50_batch_xor_prepared(&blocks, prepared, &mut working);
            acc = reduce(working.output()[0], working.output()[1]);
        }
        // The raw block guard wipes its retained array at the iteration boundary.
        // Scalar values and compiler-generated copies remain best effort.
    }
    absorb::<false>(h, acc, batches.remainder())
}

/// Prepare H^50 ... H once per portable key, using the accepted scalar primitive.
#[cfg(target_pointer_width = "64")]
fn prepare_powers(h: u128, prepared: &mut PreparedPolynomial128x50) {
    let mut powers = Zeroizing::new([0u128; PAYLOAD_LANES]);
    let mut power = Zeroizing::new(0u128);
    *power = h;
    for slot in powers.iter_mut().rev() {
        *slot = *power;
        *power = mul::<false>(*power, h);
    }
    prepared.prepare(&powers);
    // Retained raw powers and runningpower use existing volatile guards on
    // normal return and unwinding; scalar/register copies remain best effort.
}

/// GHASH of `aad` and `ct` (each zero-padded to a block boundary, then the two bit lengths) under
/// the reflected hash key `h`. Returns the big-endian block value `S`.
///
/// `#[inline(always)]` so that the hardware wrappers in `aes_hw`, which are compiled with the
/// CPU features enabled, get the carry-less multiplication inlined.
#[inline(always)]
pub(super) fn hash_with<const HW: bool>(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut acc = absorb::<HW>(h, 0, aad);
    acc = absorb::<HW>(h, acc, ct);
    let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    acc = mul::<HW>(acc ^ lens.reverse_bits(), h);
    let s = acc.reverse_bits();
    acc.zeroize();
    s
}

/// The hash key H, prepared for the chosen implementation.
#[cfg_attr(not(target_pointer_width = "64"), derive(Clone))]
pub(super) struct GhashKey {
    /// H as a reflected field element.
    h: u128,
    hw: bool,
    /// H^1 ... H^8 in the form of the one-pass hardware GCM, where this CPU has one (see [`aes_hw::Keys::gcm_seal`]).
    powers: Option<aes_hw::Powers>,
    /// Fifty real powers plus public guard operands, retained for the key lifetime.
    #[cfg(target_pointer_width = "64")]
    portable_powers: Option<PreparedPolynomial128x50>,
}

#[cfg(target_pointer_width = "64")]
impl Clone for GhashKey {
    fn clone(&self) -> Self {
        let mut key = Self {
            h: self.h,
            hw: self.hw,
            powers: self.powers.clone(),
            portable_powers: self
                .portable_powers
                .as_ref()
                .map(|_| PreparedPolynomial128x50::empty()),
        };
        if let (Some(destination), Some(source)) =
            (key.portable_powers.as_mut(), self.portable_powers.as_ref())
        {
            destination.copy_from(source);
        }
        key
    }
}

impl Drop for GhashKey {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl GhashKey {
    /// `h` is the hash subkey, the encryption of the zero block. `backend` is the AES backend of
    /// the key that produced it; the hardware multiplier is used with the hardware AES.
    pub(super) fn new(h: &[u8; 16], backend: Backend) -> GhashKey {
        let hw = backend == Backend::Hardware;
        let reflected = u128::from_be_bytes(*h).reverse_bits();
        let key = GhashKey {
            h: reflected,
            hw,
            powers: if hw { aes_hw::ghash_powers(h) } else { None },
            #[cfg(target_pointer_width = "64")]
            portable_powers: if hw {
                None
            } else {
                Some(PreparedPolynomial128x50::empty())
            },
        };
        // The retained key object moves through the existing constructor API.
        // Wiping is best effort for compiler-created copies and register spills.
        #[cfg(target_pointer_width = "64")]
        {
            let mut key = key;
            if let Some(prepared) = key.portable_powers.as_mut() {
                prepare_powers(reflected, prepared);
            }
            key
        }
        #[cfg(not(target_pointer_width = "64"))]
        key
    }

    /// H^1 ... H^8 for the one-pass hardware GCM, if there is one.
    pub(super) fn powers(&self) -> Option<&aes_hw::Powers> {
        self.powers.as_ref()
    }

    pub(super) fn wipe(&mut self) {
        self.h.zeroize();
        if let Some(p) = self.powers.as_mut() {
            p.zeroize();
        }
        #[cfg(target_pointer_width = "64")]
        if let Some(p) = self.portable_powers.as_mut() {
            for words in p.words_mut() {
                words.zeroize();
            }
        }
    }

    #[cfg(test)]
    pub(super) fn is_wiped(&self) -> bool {
        let scalar_and_hardware =
            self.h == 0 && self.powers.iter().all(|p| p.iter().all(|&x| x == 0));
        #[cfg(target_pointer_width = "64")]
        return scalar_and_hardware
            && self
                .portable_powers
                .iter()
                .all(|p| p.words().iter().all(|words| words.iter().all(|&x| x == 0)));
        #[cfg(not(target_pointer_width = "64"))]
        scalar_and_hardware
    }

    /// GHASH of `aad` and `ct` as a 16-byte block.
    pub(super) fn hash(&self, aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let s = if self.hw {
            aes_hw::ghash_hw(self.h, aad, ct)
        } else {
            #[cfg(target_pointer_width = "64")]
            {
                if aad.len() < PAYLOAD_LANES * 16 && ct.len() < PAYLOAD_LANES * 16 {
                    return hash_with::<false>(self.h, aad, ct).to_be_bytes();
                }
                let prepared = self
                    .portable_powers
                    .as_ref()
                    .expect("portable GHASH powers");
                let mut acc = absorb_portable(self.h, prepared, 0, aad);
                acc = absorb_portable(self.h, prepared, acc, ct);
                let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
                acc = mul::<false>(acc ^ lens.reverse_bits(), self.h);
                let s = acc.reverse_bits();
                acc.zeroize();
                s
            }
            #[cfg(not(target_pointer_width = "64"))]
            {
                hash_with::<false>(self.h, aad, ct)
            }
        };
        s.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn batch_working_zeroize_covers_every_retained_word() {
        let mut working = BatchWorking128x64::empty();
        let before64 = working
            .words64_mut()
            .map(|words| (words.as_ptr(), words.len()));
        let before128 = working
            .words128_mut()
            .map(|words| (words.as_ptr(), words.len()));
        assert_eq!(before64.iter().map(|entry| entry.1).sum::<usize>(), 320);
        assert_eq!(before128.iter().map(|entry| entry.1).sum::<usize>(), 5);
        for words in working.words64_mut() {
            words.fill(0xa5a5_a5a5_a5a5_a5a5);
        }
        for words in working.words128_mut() {
            words.fill(u128::MAX);
        }
        working.zeroize();
        assert!(working
            .words64_mut()
            .iter()
            .all(|words| words.iter().all(|&x| x == 0)));
        assert!(working
            .words128_mut()
            .iter()
            .all(|words| words.iter().all(|&x| x == 0)));
        assert_eq!(
            working
                .words64_mut()
                .map(|words| (words.as_ptr(), words.len())),
            before64
        );
        assert_eq!(
            working
                .words128_mut()
                .map(|words| (words.as_ptr(), words.len())),
            before128
        );
    }

    /// The bit-at-a-time multiplication this module replaced (NIST SP 800-38D algorithm 1):
    /// simple enough to check by eye, and the oracle for everything here.
    fn gf_mul(x: u128, y: u128) -> u128 {
        const R: u128 = 0xe1 << 120;
        let mut z = 0u128;
        let mut v = y;
        for i in 0..128 {
            let bit = (x >> (127 - i)) & 1;
            z ^= v & 0u128.wrapping_sub(bit);
            let lsb = v & 1;
            v = (v >> 1) ^ (R & 0u128.wrapping_sub(lsb));
        }
        z
    }

    fn reference_ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
        let mut acc = 0u128;
        for data in [aad, ct] {
            for chunk in data.chunks(16) {
                let mut b = [0u8; 16];
                b[..chunk.len()].copy_from_slice(chunk);
                acc = gf_mul(acc ^ u128::from_be_bytes(b), h);
            }
        }
        gf_mul(
            acc ^ (((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8)),
            h,
        )
    }

    /// Carry-less multiplication bit by bit.
    fn slow_clmul(a: u64, b: u64) -> u128 {
        let mut r = 0u128;
        for i in 0..64 {
            if (b >> i) & 1 == 1 {
                r ^= (a as u128) << i;
            }
        }
        r
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn u128(&mut self) -> u128 {
            ((self.next() as u128) << 64)
                ^ (self.next() >> 7) as u128
                ^ ((self.next() as u128) << 31)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 33) as u8).collect()
        }
    }

    fn edge_u64s() -> Vec<u64> {
        let mut v = vec![
            0,
            1,
            2,
            3,
            u64::MAX,
            1 << 63,
            (1 << 63) | 1,
            0x8000_0000_0000_0001,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
        ];
        v.extend((0..64).map(|i| 1u64 << i));
        v
    }

    #[test]
    fn portable_clmul_matches_the_bit_by_bit_product() {
        let mut rng = Lcg(11);
        let edges = edge_u64s();
        for &a in &edges {
            for &b in &edges {
                assert_eq!(clmul64_portable(a, b), slow_clmul(a, b), "{a:#x} * {b:#x}");
            }
        }
        for _ in 0..2000 {
            let (a, b) = (rng.next(), rng.next());
            assert_eq!(clmul64_portable(a, b), slow_clmul(a, b), "{a:#x} * {b:#x}");
        }
    }

    #[test]
    fn hardware_clmul_matches_the_portable_one() {
        if !aes_hw::available() {
            return;
        }
        let mut rng = Lcg(12);
        let edges = edge_u64s();
        for &a in &edges {
            for &b in &edges {
                // SAFETY: `available()` was checked above
                assert_eq!(unsafe { aes_hw::clmul64(a, b) }, slow_clmul(a, b));
            }
        }
        for _ in 0..2000 {
            let (a, b) = (rng.next(), rng.next());
            assert_eq!(unsafe { aes_hw::clmul64(a, b) }, slow_clmul(a, b));
        }
    }

    #[test]
    fn field_multiplication_matches_the_reference_on_both_multipliers() {
        let mut rng = Lcg(13);
        let mut cases = vec![
            (0u128, 0u128),
            (1, 1),
            (u128::MAX, u128::MAX),
            (1 << 127, 1 << 127),
            (1 << 127, 3),
            (u128::MAX, 1),
        ];
        for i in 0..128 {
            cases.push((1u128 << i, rng.u128()));
            cases.push((rng.u128(), 1u128 << i));
        }
        for _ in 0..500 {
            cases.push((rng.u128(), rng.u128()));
        }
        for (x, y) in cases {
            let want = gf_mul(x, y);
            let got = mul::<false>(x.reverse_bits(), y.reverse_bits()).reverse_bits();
            assert_eq!(got, want, "portable {x:#x} * {y:#x}");
            if aes_hw::available() {
                let got = mul::<true>(x.reverse_bits(), y.reverse_bits()).reverse_bits();
                assert_eq!(got, want, "hardware {x:#x} * {y:#x}");
            }
        }
    }

    #[test]
    fn ghash_matches_the_reference_for_many_lengths_and_both_multipliers() {
        let mut rng = Lcg(14);
        for aad_len in [0usize, 1, 13, 16, 17, 32, 33] {
            for ct_len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100, 257, 1024] {
                let h = rng.u128();
                let (aad, ct) = (rng.bytes(aad_len), rng.bytes(ct_len));
                let want = reference_ghash(h, &aad, &ct);
                let key = h.to_be_bytes();
                let portable = GhashKey::new(&key, Backend::Portable);
                assert_eq!(
                    u128::from_be_bytes(portable.hash(&aad, &ct)),
                    want,
                    "portable aad {aad_len} ct {ct_len}"
                );
                if aes_hw::available() {
                    let hw = GhashKey::new(&key, Backend::Hardware);
                    assert_eq!(
                        u128::from_be_bytes(hw.hash(&aad, &ct)),
                        want,
                        "hardware aad {aad_len} ct {ct_len}"
                    );
                }
            }
        }
    }

    #[test]
    fn batches_preserve_nonzero_incoming_state_and_partial_tails() {
        let mut rng = Lcg(0x8a5c_27b1_6d09_4e3f);
        for h in [0, 1, 1 << 127, u128::MAX, rng.u128()] {
            let key = GhashKey::new(&h.to_be_bytes(), Backend::Portable);
            #[cfg(target_pointer_width = "64")]
            let prepared = key.portable_powers.as_ref().unwrap();
            for len in [
                0, 1, 15, 16, 784, 799, 800, 801, 816, 1008, 1023, 1024, 1025, 1040, 1599, 1600,
                1601, 1616, 2047, 2048, 2049, 2399, 2400, 2401, 3089,
            ] {
                let initial = rng.u128();
                let data = rng.bytes(len);
                let mut expected = initial;
                for chunk in data.chunks(16) {
                    let mut block = [0u8; 16];
                    block[..chunk.len()].copy_from_slice(chunk);
                    expected = gf_mul(expected ^ u128::from_be_bytes(block), h);
                }
                #[cfg(target_pointer_width = "64")]
                let actual = absorb_portable(key.h, prepared, initial.reverse_bits(), &data);
                #[cfg(not(target_pointer_width = "64"))]
                let actual = absorb::<false>(key.h, initial.reverse_bits(), &data);
                assert_eq!(actual.reverse_bits(), expected, "len {len}, h {h:#x}");
            }
        }
    }

    #[test]
    fn batches_keep_aad_and_ciphertext_padding_independent() {
        let mut rng = Lcg(0x49e0_b7a2_8c36_15df);
        for (aad_len, ct_len) in [
            (0, 800),
            (1, 799),
            (15, 800),
            (17, 801),
            (799, 800),
            (800, 799),
            (800, 800),
            (801, 801),
            (1599, 1600),
            (1600, 1601),
            (0, 1024),
            (1, 1023),
            (15, 1024),
            (17, 1025),
            (1023, 1024),
            (1024, 1023),
            (1024, 1024),
            (1025, 1025),
            (2047, 2048),
            (2048, 2049),
            (2049, 16385),
        ] {
            let h = rng.u128();
            let aad = rng.bytes(aad_len);
            let ct = rng.bytes(ct_len);
            let expected = reference_ghash(h, &aad, &ct).to_be_bytes();
            let portable = GhashKey::new(&h.to_be_bytes(), Backend::Portable);
            assert_eq!(
                portable.hash(&aad, &ct),
                expected,
                "aad {aad_len} ct {ct_len}"
            );
            let cloned = portable.clone();
            let mut wiped = portable;
            wiped.wipe();
            assert!(wiped.is_wiped());
            assert!(wiped.clone().is_wiped());
            assert!(!cloned.is_wiped());
            assert_eq!(cloned.hash(&aad, &ct), expected);
            if aes_hw::available() {
                let hardware = GhashKey::new(&h.to_be_bytes(), Backend::Hardware);
                assert_eq!(hardware.hash(&aad, &ct), expected);
            }
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn guarded_zero_key_clone_preserves_guards_and_wiped_state() {
        let key = GhashKey::new(&[0; 16], Backend::Portable);
        assert!(!key.is_wiped());
        let cloned = key.clone();
        assert!(!cloned.is_wiped());
        assert_eq!(cloned.hash(b"aad", &[0x5a; 2049]), [0; 16]);
        let mut wiped = cloned;
        wiped.wipe();
        assert!(wiped.is_wiped());
        assert!(wiped.clone().is_wiped());
        assert!(!key.is_wiped());
    }

    /// SP 800-38D test case 2 (the zero key): H = E_K(0^128), and GHASH(H, {}, C) for its single
    /// ciphertext block; the reference tag is 0xab6e47d42cec13bdf53a67b21257bddf.
    #[test]
    fn nist_gcm_test_case_2_hash() {
        let h: [u8; 16] = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
            .try_into()
            .unwrap();
        let c = unhex("0388dace60b6a392f328c2b971b2fe78");
        let want = "f38cbb1ad69223dcc3457ae5b6b0f885";
        for backend in [Backend::Portable, Backend::Hardware] {
            if backend == Backend::Hardware && !aes_hw::available() {
                continue;
            }
            assert_eq!(
                hex(&GhashKey::new(&h, backend).hash(&[], &c)),
                want,
                "{backend:?}"
            );
        }
    }

    #[test]
    fn wipe_clears_the_hash_key() {
        assert!(std::mem::needs_drop::<GhashKey>());
        let mut k = GhashKey::new(&[0x42u8; 16], Backend::Portable);
        assert!(!k.is_wiped());
        k.wipe();
        assert!(k.is_wiped());
    }
}
