//! GHASH (NIST SP 800-38D section 6.4), the universal hash inside AES-GCM, in constant time.
//!
//! GCM numbers the bits of a block backwards: in the 128-bit big-endian value of a block, the top
//! bit is the coefficient of x^0. Reversing all 128 bits turns a block into an ordinary polynomial
//! (bit `k` = coefficient of x^k) over GF(2), so a field multiplication becomes a plain
//! carry-less multiplication followed by a reduction modulo x^128 + x^7 + x^2 + x + 1. The hash
//! runs entirely in that reflected form and reverses the result at the end.
//!
//! The carry-less 64 x 64 -> 128 bit product (`clmul64`) is the only primitive that differs:
//! PCLMULQDQ or PMULL where the CPU has them ([`super::aes_hw`]), otherwise `bmul64`, which gets
//! it from integer multiplications on operands with holes in them so that the carries never
//! collide (the technique of BearSSL's `ghash_ctmul64`). Neither has a secret-dependent branch or
//! address, and `bmul64` relies on the CPU's integer multiplier taking the same time for any
//! operands, as it does on every mainstream desktop, server and phone core.

use super::aes::Backend;
use super::aes_hw;
use crate::zeroize::Zeroize;

/// Low 64 bits of the carry-less product of `x` and `y`.
///
/// The operands are split into four classes of every fourth bit. A product of two such classes
/// has at most 16 ones landing on any position, so the integer sums cannot carry into the next
/// position that is kept; masking the right positions out of the XOR of the integer products
/// leaves exactly the carry-less sums.
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// The full 128-bit carry-less product from [`bmul64`]. The high half is the bit-reversed low
/// half of the product of the bit-reversed operands (reversing maps product bit m to 126 - m),
/// shifted by one because the product has only 127 bits.
#[inline(always)]
fn clmul64_portable(a: u64, b: u64) -> u128 {
    let lo = bmul64(a, b);
    let hi = bmul64(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
    ((hi as u128) << 64) | lo as u128
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
#[derive(Clone)]
pub(super) struct GhashKey {
    /// H as a reflected field element.
    h: u128,
    hw: bool,
    /// H^1 ... H^8 in the form of the one-pass hardware GCM, where this CPU has one (see [`aes_hw::Keys::gcm_seal`]).
    powers: Option<aes_hw::Powers>,
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
        GhashKey { h: u128::from_be_bytes(*h).reverse_bits(), hw, powers: if hw { aes_hw::ghash_powers(h) } else { None } }
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
    }

    #[cfg(test)]
    pub(super) fn is_wiped(&self) -> bool {
        self.h == 0 && self.powers.iter().all(|p| p.iter().all(|&x| x == 0))
    }

    /// GHASH of `aad` and `ct` as a 16-byte block.
    pub(super) fn hash(&self, aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let s = if self.hw { aes_hw::ghash_hw(self.h, aad, ct) } else { hash_with::<false>(self.h, aad, ct) };
        s.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

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
        gf_mul(acc ^ (((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8)), h)
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
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0
        }
        fn u128(&mut self) -> u128 {
            ((self.next() as u128) << 64) ^ (self.next() >> 7) as u128 ^ ((self.next() as u128) << 31)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 33) as u8).collect()
        }
    }

    fn edge_u64s() -> Vec<u64> {
        let mut v = vec![0, 1, 2, 3, u64::MAX, 1 << 63, (1 << 63) | 1, 0x8000_0000_0000_0001, 0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa];
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
        let mut cases = vec![(0u128, 0u128), (1, 1), (u128::MAX, u128::MAX), (1 << 127, 1 << 127), (1 << 127, 3), (u128::MAX, 1)];
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
                assert_eq!(u128::from_be_bytes(portable.hash(&aad, &ct)), want, "portable aad {aad_len} ct {ct_len}");
                if aes_hw::available() {
                    let hw = GhashKey::new(&key, Backend::Hardware);
                    assert_eq!(u128::from_be_bytes(hw.hash(&aad, &ct)), want, "hardware aad {aad_len} ct {ct_len}");
                }
            }
        }
    }

    /// SP 800-38D test case 2 (the zero key): H = E_K(0^128), and GHASH(H, {}, C) for its single
    /// ciphertext block; the reference tag is 0xab6e47d42cec13bdf53a67b21257bddf.
    #[test]
    fn nist_gcm_test_case_2_hash() {
        let h: [u8; 16] = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e").try_into().unwrap();
        let c = unhex("0388dace60b6a392f328c2b971b2fe78");
        let want = "f38cbb1ad69223dcc3457ae5b6b0f885";
        for backend in [Backend::Portable, Backend::Hardware] {
            if backend == Backend::Hardware && !aes_hw::available() {
                continue;
            }
            assert_eq!(hex(&GhashKey::new(&h, backend).hash(&[], &c)), want, "{backend:?}");
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
