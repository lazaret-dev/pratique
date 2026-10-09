//! Poly1305 one-time authenticator (RFC 8439 section 2.5).
//!
//! Two implementations with the same interface; the one matching the pointer width is used:
//!
//! * `radix64`: two 64-bit limbs and a third of a few bits (after OpenSSL's `crypto/poly1305/poly1305.c`): four
//!   64 x 64 -> 128-bit products and two small ones per block, where three 44-bit limbs (poly1305-donna-64, used here
//!   before B-57) take nine. Fast on 64-bit CPUs, where such a product is one instruction or two: about 1.65 times the
//!   44-bit limbs on an x86-64 VM, and faster for short messages too.
//! * `limbs32`: five 26-bit limbs with 64-bit products (after poly1305-donna-32). Used on 32-bit
//!   targets, where 128-bit multiplies would be library calls.
//!
//! On x86-64 CPUs with AVX2, messages of 2 KiB or more go four blocks at a time through `avx2` (B-104), the 26-bit
//! limbs of `limbs32` in the four lanes of 256-bit registers: 1.7 times the speed of `radix64` at 16 KiB on an x86-64
//! server (see `avx2::MIN` for where it starts).
//!
//! Both are compiled in test builds so the same vectors run against each on any host. Both are
//! constant-time: no secret-dependent branches, indices or variable-time instructions.

#[cfg(target_pointer_width = "64")]
pub(crate) use radix64::Poly1305;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) use limbs32::Poly1305;

#[cfg(any(test, not(target_pointer_width = "64")))]
#[inline(always)]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(any(test, target_pointer_width = "64"))]
#[inline(always)]
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(any(test, target_pointer_width = "64"))]
pub(crate) mod radix64 {
    use super::le64;
    use crate::zeroize::Zeroize;

    pub(crate) struct Poly1305 {
        /// r, clamped: the top four bits of each 32-bit word and the low two bits of the last three are clear, so r1 is a
        /// multiple of 4.
        r: [u64; 2],
        /// h, partly reduced: h = h0 + h1 2^64 + h2 2^128, h2 at most 4 between blocks.
        h: [u64; 3],
        pad: [u64; 2],
    }

    impl Drop for Poly1305 {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    /// a + b + carry, and the carry out (0 or 1), with no branch.
    #[inline(always)]
    fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let t = a as u128 + b as u128 + carry as u128;
        (t as u64, (t >> 64) as u64)
    }

    impl Poly1305 {
        fn wipe(&mut self) {
            self.r.zeroize();
            self.h.zeroize();
            self.pad.zeroize();
        }

        pub(crate) fn new(key: &[u8; 32]) -> Self {
            let r0 = le64(&key[0..8]) & 0x0fff_fffc_0fff_ffff;
            let r1 = le64(&key[8..16]) & 0x0fff_fffc_0fff_fffc;
            Poly1305 { r: [r0, r1], h: [0; 3], pad: [le64(&key[16..24]), le64(&key[24..32])] }
        }

        /// Absorbs one 16-byte block. `hibit` is the 2^128 padding bit that every full block of the
        /// AEAD construction carries (it is clear only for a short final block of a plain message).
        #[inline(always)]
        pub(crate) fn block(&mut self, m: &[u8; 16], hibit: bool) {
            let [r0, r1] = self.r;
            // 2^130 = 5 mod p and r1 is a multiple of 4, so h1 r1 2^128 = h1 (r1 / 4) 2^130 = h1 (5 r1 / 4) = h1 s1 mod p
            let s1 = r1 + (r1 >> 2);
            let [h0, h1, h2] = self.h;
            // h += m: h2 at most 4 + 1 + 1
            let (h0, c) = adc(h0, le64(&m[0..8]), 0);
            let (h1, c) = adc(h1, le64(&m[8..16]), c);
            let h2 = h2 + c + u64::from(hibit);
            // h *= r, partly reduced. r0 < 2^60 and s1 < 2^61, so the sums of products are under 2^126, and h2 s1 and
            // h2 r0 (h2 at most 6) fit in 64 bits
            let mul = |a: u64, b: u64| a as u128 * b as u128;
            let d0 = mul(h0, r0) + mul(h1, s1);
            let d1 = mul(h0, r1) + mul(h1, r0) + (h2 * s1) as u128 + (d0 >> 64);
            let h2 = h2 * r0 + (d1 >> 64) as u64;
            // what is at 2^130 and above comes back times 5: (h2 >> 2) 5 = (h2 & !3) + (h2 >> 2)
            let c = (h2 & !3) + (h2 >> 2);
            let (h0, c) = adc(d0 as u64, c, 0);
            let (h1, c) = adc(d1 as u64, 0, c);
            self.h = [h0, h1, (h2 & 3) + c];
        }

        /// Absorbs whole 16-byte blocks, each with the 2^128 bit: four at a time with AVX2 where the CPU has it and the
        /// data is long enough for that to pay (B-104), the rest one at a time.
        pub(crate) fn blocks(&mut self, data: &[u8]) {
            debug_assert!(data.len() % 16 == 0);
            #[allow(unused_mut)]
            let mut data = data;
            #[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
            if data.len() >= super::avx2::MIN && super::avx2::available() {
                let n = data.len() / 64 * 64;
                // SAFETY: the CPU has AVX2, just checked
                unsafe { super::avx2::blocks(&mut self.h, self.r, &data[..n]) };
                data = &data[n..];
            }
            for c in data.chunks_exact(16) {
                self.block(<&[u8; 16]>::try_from(c).unwrap(), true);
            }
        }

        pub(crate) fn finish(self) -> [u8; 16] {
            // (the key material is wiped when `self` drops at the end of this function)
            let [h0, h1, h2] = self.h;
            // h < 5 2^128 < 2p, so h mod p is h - p if that is not below zero, which is when bit 130 of h + 5 is set
            let (g0, c) = adc(h0, 5, 0);
            let (g1, c) = adc(h1, 0, c);
            let take = 0u64.wrapping_sub((h2 + c) >> 2); // all ones when h >= p
            let h0 = (h0 & !take) | (g0 & take);
            let h1 = (h1 & !take) | (g1 & take);
            // (h + pad) mod 2^128
            let (h0, c) = adc(h0, self.pad[0], 0);
            let (h1, _) = adc(h1, self.pad[1], c);
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&h0.to_le_bytes());
            tag[8..].copy_from_slice(&h1.to_le_bytes());
            tag
        }
    }

    #[cfg(test)]
    mod wipe_test {
        use super::*;

        #[test]
        fn state_is_wiped_and_type_has_drop_glue() {
            assert!(std::mem::needs_drop::<Poly1305>());
            let mut p = Poly1305::new(&[0xa5u8; 32]);
            p.block(&[0x77; 16], true);
            assert!(p.r != [0; 2] && p.h != [0; 3]);
            p.wipe();
            assert!(p.r == [0; 2] && p.h == [0; 3] && p.pad == [0; 2]);
        }
    }
}

#[cfg(any(test, not(target_pointer_width = "64")))]
pub(crate) mod limbs32 {
    use super::le32;
    use crate::zeroize::Zeroize;

    const MASK26: u32 = 0x3ff_ffff;

    pub(crate) struct Poly1305 {
        r: [u32; 5],
        h: [u32; 5],
        s: [u32; 4],
    }

    impl Drop for Poly1305 {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    impl Poly1305 {
        fn wipe(&mut self) {
            self.r.zeroize();
            self.h.zeroize();
            self.s.zeroize();
        }

        pub(crate) fn new(key: &[u8; 32]) -> Self {
            let r = [
                le32(&key[0..4]) & 0x3ff_ffff,
                (le32(&key[3..7]) >> 2) & 0x3ff_ff03,
                (le32(&key[6..10]) >> 4) & 0x3ff_c0ff,
                (le32(&key[9..13]) >> 6) & 0x3f0_3fff,
                (le32(&key[12..16]) >> 8) & 0x00f_ffff,
            ];
            let s = [le32(&key[16..20]), le32(&key[20..24]), le32(&key[24..28]), le32(&key[28..32])];
            Poly1305 { r, h: [0; 5], s }
        }

        #[inline(always)]
        pub(crate) fn block(&mut self, m: &[u8; 16], hibit: bool) {
            let [r0, r1, r2, r3, r4] = self.r;
            let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
            let hb = (hibit as u32) << 24;
            let mut h0 = self.h[0] + (le32(&m[0..4]) & MASK26);
            let mut h1 = self.h[1] + ((le32(&m[3..7]) >> 2) & MASK26);
            let mut h2 = self.h[2] + ((le32(&m[6..10]) >> 4) & MASK26);
            let mut h3 = self.h[3] + ((le32(&m[9..13]) >> 6) & MASK26);
            let mut h4 = self.h[4] + ((le32(&m[12..16]) >> 8) | hb);

            let m = |a: u32, b: u32| a as u64 * b as u64;
            let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
            let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
            let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
            let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
            let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

            let mut c = (d0 >> 26) as u32;
            h0 = (d0 as u32) & MASK26;
            d1 += c as u64;
            c = (d1 >> 26) as u32;
            h1 = (d1 as u32) & MASK26;
            d2 += c as u64;
            c = (d2 >> 26) as u32;
            h2 = (d2 as u32) & MASK26;
            d3 += c as u64;
            c = (d3 >> 26) as u32;
            h3 = (d3 as u32) & MASK26;
            d4 += c as u64;
            c = (d4 >> 26) as u32;
            h4 = (d4 as u32) & MASK26;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= MASK26;
            h1 += c;
            self.h = [h0, h1, h2, h3, h4];
        }

        /// Absorbs whole 16-byte blocks, each with the 2^128 bit.
        #[cfg_attr(test, allow(dead_code))] // (on 64-bit targets the tests use `block`)
        pub(crate) fn blocks(&mut self, data: &[u8]) {
            debug_assert!(data.len() % 16 == 0);
            for c in data.chunks_exact(16) {
                self.block(<&[u8; 16]>::try_from(c).unwrap(), true);
            }
        }

        pub(crate) fn finish(self) -> [u8; 16] {
            let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
            let mask = MASK26;
            // fully carry h
            let mut c = h1 >> 26;
            h1 &= mask;
            h2 += c;
            c = h2 >> 26;
            h2 &= mask;
            h3 += c;
            c = h3 >> 26;
            h3 &= mask;
            h4 += c;
            c = h4 >> 26;
            h4 &= mask;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= mask;
            h1 += c;
            c = h1 >> 26;
            h1 &= mask;
            h2 += c;

            // compute h + -p
            let mut g0 = h0.wrapping_add(5);
            c = g0 >> 26;
            g0 &= mask;
            let mut g1 = h1.wrapping_add(c);
            c = g1 >> 26;
            g1 &= mask;
            let mut g2 = h2.wrapping_add(c);
            c = g2 >> 26;
            g2 &= mask;
            let mut g3 = h3.wrapping_add(c);
            c = g3 >> 26;
            g3 &= mask;
            let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

            // select h if h < p, else g (constant time)
            let sel = (g4 >> 31).wrapping_sub(1);
            let nsel = !sel;
            g0 &= sel;
            g1 &= sel;
            g2 &= sel;
            g3 &= sel;
            let g4 = g4 & sel;
            h0 = (h0 & nsel) | g0;
            h1 = (h1 & nsel) | g1;
            h2 = (h2 & nsel) | g2;
            h3 = (h3 & nsel) | g3;
            h4 = (h4 & nsel) | g4;

            // h mod 2^128
            let w0 = h0 | (h1 << 26);
            let w1 = (h1 >> 6) | (h2 << 20);
            let w2 = (h2 >> 12) | (h3 << 14);
            let w3 = (h3 >> 18) | (h4 << 8);

            // add s
            let mut f = w0 as u64 + self.s[0] as u64;
            let t0 = f as u32;
            f = w1 as u64 + self.s[1] as u64 + (f >> 32);
            let t1 = f as u32;
            f = w2 as u64 + self.s[2] as u64 + (f >> 32);
            let t2 = f as u32;
            f = w3 as u64 + self.s[3] as u64 + (f >> 32);
            let t3 = f as u32;

            let mut tag = [0u8; 16];
            tag[0..4].copy_from_slice(&t0.to_le_bytes());
            tag[4..8].copy_from_slice(&t1.to_le_bytes());
            tag[8..12].copy_from_slice(&t2.to_le_bytes());
            tag[12..16].copy_from_slice(&t3.to_le_bytes());
            tag
        }
    }

    #[cfg(test)]
    mod wipe_test {
        use super::*;

        #[test]
        fn state_is_wiped_and_type_has_drop_glue() {
            assert!(std::mem::needs_drop::<Poly1305>());
            let mut p = Poly1305::new(&[0xa5u8; 32]);
            p.block(&[0x77; 16], true);
            assert!(p.r != [0; 5] && p.h != [0; 5]);
            p.wipe();
            assert!(p.r == [0; 5] && p.s == [0; 4] && p.h == [0; 5]);
        }
    }
}

impl Poly1305 {
    /// Feeds `data` zero-padded to a multiple of 16 bytes, every block with the high bit set (the
    /// AEAD construction of RFC 8439 section 2.8).
    pub(crate) fn update_padded(&mut self, data: &[u8]) {
        let whole = data.len() / 16 * 16;
        self.blocks(&data[..whole]);
        let rem = &data[whole..];
        if !rem.is_empty() {
            let mut b = [0u8; 16];
            b[..rem.len()].copy_from_slice(rem);
            self.block(&b, true);
        }
    }
}

// ---------------------------------------------------------------- four blocks at a time with AVX2 (B-104)
// The 26-bit limbs of `limbs32`, one block in each 64-bit lane of 256-bit registers. Each lane takes every fourth block and
// multiplies by r^4: lane i holds (h + m_i) r^4 + m_(i+4)) r^4 + ...; the last step multiplies the lanes by r^4, r^3, r^2
// and r instead, so that adding the lanes gives what a block at a time would have. Constant time like the scalar code: the
// same instructions for every key and message, `vpmuludq` among them (fixed latency), and no branch but on the length.

#[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
mod avx2 {
    use crate::zeroize::Zeroize;
    use core::arch::x86_64::*;

    /// The least data that goes this way. On its own this path is level with `radix64` at 384 bytes and 1.35 times
    /// quicker at 1 KiB, but in the AEAD a 1 KiB record came out 7 percent slower on the x86-64 server of BENCHMARKS.md
    /// (whose cores lower their clock a little while 256-bit multiplications run, for whatever runs with them), and a 16
    /// KiB one 10 percent quicker: so from 2 KiB.
    pub(super) const MIN: usize = 2048;

    const M26: u64 = (1 << 26) - 1;

    pub(super) fn available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// a b mod p in five 26-bit limbs (scalar), carried (`carry26`).
    fn mul26(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        let s = [0, 5 * b[1], 5 * b[2], 5 * b[3], 5 * b[4]];
        let d0 = a[0] * b[0] + a[1] * s[4] + a[2] * s[3] + a[3] * s[2] + a[4] * s[1];
        let d1 = a[0] * b[1] + a[1] * b[0] + a[2] * s[4] + a[3] * s[3] + a[4] * s[2];
        let d2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * s[4] + a[4] * s[3];
        let d3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * s[4];
        let d4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];
        carry26([d0, d1, d2, d3, d4])
    }

    /// One carry pass and the top limb's carry folded back (times 5): every limb below 2^26 but the second, which can be
    /// 2^26 plus a few.
    fn carry26(d: [u64; 5]) -> [u64; 5] {
        let [mut d0, mut d1, mut d2, mut d3, mut d4] = d;
        d1 += d0 >> 26;
        d0 &= M26;
        d2 += d1 >> 26;
        d1 &= M26;
        d3 += d2 >> 26;
        d2 &= M26;
        d4 += d3 >> 26;
        d3 &= M26;
        d0 += 5 * (d4 >> 26);
        d4 &= M26;
        d1 += d0 >> 26;
        d0 &= M26;
        [d0, d1, d2, d3, d4]
    }

    /// `radix64`'s (h0, h1, h2) as 26-bit limbs. h2 is at most 4, so the top limb is below 2^27.
    fn to26(h: [u64; 3]) -> [u64; 5] {
        [h[0] & M26, (h[0] >> 26) & M26, ((h[0] >> 52) | (h[1] << 12)) & M26, (h[1] >> 14) & M26, (h[1] >> 40) | (h[2] << 24)]
    }

    /// Back to (h0, h1, h2), from limbs as `carry26` leaves them: the value is below 2^130 + 2^53, so h2 is at most 4, as
    /// `radix64` needs.
    fn from26(l: [u64; 5]) -> [u64; 3] {
        let low = l[0] as u128 + ((l[1] as u128) << 26) + ((l[2] as u128) << 52) + ((l[3] as u128) << 78);
        let (t, c) = low.overflowing_add(((l[4] & ((1 << 24) - 1)) as u128) << 104);
        [t as u64, (t >> 64) as u64, (l[4] >> 24) + c as u64]
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn splat(x: u64) -> __m256i {
        _mm256_set1_epi64x(x as i64)
    }

    /// The limbs of four lanes' values, from scalar limbs (`f(i)` gives limb i of each lane).
    #[inline]
    #[target_feature(enable = "avx2")]
    fn lanes(f: impl Fn(usize) -> [u64; 4]) -> [__m256i; 5] {
        let mut v = [_mm256_setzero_si256(); 5];
        for (i, x) in v.iter_mut().enumerate() {
            let w = f(i);
            *x = _mm256_set_epi64x(w[3] as i64, w[2] as i64, w[1] as i64, w[0] as i64);
        }
        v
    }

    /// 5 r for the limbs of r above the first (2^130 = 5 mod p), for `mul`.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn times5(r: &[__m256i; 5]) -> [__m256i; 5] {
        let f = |x: __m256i| _mm256_add_epi64(x, _mm256_slli_epi64::<2>(x));
        [_mm256_setzero_si256(), f(r[1]), f(r[2]), f(r[3]), f(r[4])]
    }

    /// h r in each lane, partly carried. h's limbs are below 2^27 + 2^9 and r's below 2^26 + a few (s = 5 r below 2^29),
    /// so each product is below 2^56 and each sum of five below 2^59. The carries run in two chains at once (limbs 0 to
    /// 4, and 3, 4, 0, 1), which leaves every limb below 2^26 + 2^9.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn mul(h: &[__m256i; 5], r: &[__m256i; 5], s: &[__m256i; 5]) -> [__m256i; 5] {
        let m = |a, b| _mm256_mul_epu32(a, b);
        let add = |a, b| _mm256_add_epi64(a, b);
        let d0 = add(add(add(m(h[0], r[0]), m(h[1], s[4])), add(m(h[2], s[3]), m(h[3], s[2]))), m(h[4], s[1]));
        let d1 = add(add(add(m(h[0], r[1]), m(h[1], r[0])), add(m(h[2], s[4]), m(h[3], s[3]))), m(h[4], s[2]));
        let d2 = add(add(add(m(h[0], r[2]), m(h[1], r[1])), add(m(h[2], r[0]), m(h[3], s[4]))), m(h[4], s[3]));
        let d3 = add(add(add(m(h[0], r[3]), m(h[1], r[2])), add(m(h[2], r[1]), m(h[3], r[0]))), m(h[4], s[4]));
        let d4 = add(add(add(m(h[0], r[4]), m(h[1], r[3])), add(m(h[2], r[2]), m(h[3], r[1]))), m(h[4], r[0]));
        let mask = splat(M26);
        let (mut d0, mut d1, mut d2, mut d3, mut d4) = (d0, d1, d2, d3, d4);
        let c = _mm256_srli_epi64::<26>(d0);
        d0 = _mm256_and_si256(d0, mask);
        d1 = add(d1, c);
        let c = _mm256_srli_epi64::<26>(d3);
        d3 = _mm256_and_si256(d3, mask);
        d4 = add(d4, c);
        let c = _mm256_srli_epi64::<26>(d1);
        d1 = _mm256_and_si256(d1, mask);
        d2 = add(d2, c);
        let c = _mm256_srli_epi64::<26>(d4);
        d4 = _mm256_and_si256(d4, mask);
        d0 = add(d0, add(c, _mm256_slli_epi64::<2>(c)));
        let c = _mm256_srli_epi64::<26>(d2);
        d2 = _mm256_and_si256(d2, mask);
        d3 = add(d3, c);
        let c = _mm256_srli_epi64::<26>(d0);
        d0 = _mm256_and_si256(d0, mask);
        d1 = add(d1, c);
        let c = _mm256_srli_epi64::<26>(d3);
        d3 = _mm256_and_si256(d3, mask);
        d4 = add(d4, c);
        [d0, d1, d2, d3, d4]
    }

    /// The four blocks at `p` as limbs with the 2^128 bit, their lanes in the order of blocks 0, 2, 1, 3 (which the
    /// interleaving of two 32-byte loads gives).
    ///
    /// # Safety
    /// `p` points to 64 readable bytes.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn load(p: *const u8) -> [__m256i; 5] {
        let a = _mm256_loadu_si256(p as *const __m256i);
        let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let lo = _mm256_unpacklo_epi64(a, b);
        let hi = _mm256_unpackhi_epi64(a, b);
        let mask = splat(M26);
        [
            _mm256_and_si256(lo, mask),
            _mm256_and_si256(_mm256_srli_epi64::<26>(lo), mask),
            _mm256_and_si256(_mm256_or_si256(_mm256_srli_epi64::<52>(lo), _mm256_slli_epi64::<12>(hi)), mask),
            _mm256_and_si256(_mm256_srli_epi64::<14>(hi), mask),
            _mm256_or_si256(_mm256_srli_epi64::<40>(hi), splat(1 << 24)),
        ]
    }

    /// Absorbs `data` (a whole number of 64-byte groups, at least one) into `radix64`'s state `h` with its clamped `r`.
    ///
    /// # Safety
    /// The CPU must have AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn blocks(h: &mut [u64; 3], r: [u64; 2], data: &[u8]) {
        assert!(data.len() % 64 == 0 && !data.is_empty());
        let mut r1 = to26([r[0], r[1], 0]);
        let mut r2 = mul26(&r1, &r1);
        let mut r3 = mul26(&r2, &r1);
        let mut r4 = mul26(&r3, &r1);
        let step = lanes(|i| [r4[i]; 4]);
        let step5 = times5(&step);
        // the last group's lanes hold its blocks 0, 2, 1 and 3
        let last = lanes(|i| [r4[i], r2[i], r3[i], r1[i]]);
        let last5 = times5(&last);
        let mut h26 = to26(*h);
        let mut acc = lanes(|i| [h26[i], 0, 0, 0]);
        let groups = data.len() / 64;
        let p = data.as_ptr();
        for g in 0..groups {
            let m = load(p.add(64 * g));
            let mut x = [_mm256_setzero_si256(); 5];
            for i in 0..5 {
                x[i] = _mm256_add_epi64(acc[i], m[i]);
            }
            // An empty asm that takes the sums and gives them back, for the compiler: without it, it works out that they
            // can be over 32 bits (it cannot see they are below 2^28), drops the masks of the 32 x 32-bit products, and
            // makes each a full 64 x 64-bit one, three instructions where one does (`vpmuludq` reads only the low 32 bits).
            // SAFETY: the template is a comment: no instruction, no memory, the registers given back as they came.
            core::arch::asm!(
                "/* {0} {1} {2} {3} {4} */",
                inout(ymm_reg) x[0], inout(ymm_reg) x[1], inout(ymm_reg) x[2], inout(ymm_reg) x[3], inout(ymm_reg) x[4],
                options(nomem, nostack, preserves_flags),
            );
            if g + 1 == groups {
                acc = mul(&x, &last, &last5);
                break;
            }
            acc = mul(&x, &step, &step5);
        }
        // the lanes added, then carried as `radix64` keeps h
        let mut l = [0u64; 5];
        for (i, v) in acc.iter().enumerate() {
            let mut w = [0u64; 4];
            _mm256_storeu_si256(w.as_mut_ptr() as *mut __m256i, *v);
            l[i] = w[0] + w[1] + w[2] + w[3];
            w.zeroize();
        }
        *h = from26(carry26(l));
        for x in [&mut r1, &mut r2, &mut r3, &mut r4, &mut h26, &mut l] {
            x.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::aead_vectors::POLY1305_VECTORS;
    use crate::util::{hex, unhex};

    /// `blocks` (four at a time with AVX2 on an x86-64 that has it, B-104) gives what a block at a time gives: random keys
    /// and keys whose r has every bit the clamp allows, states left by a few blocks before, lengths from 2 KiB to
    /// several groups past it with a tail of single blocks, and blocks of all ones (which keep h near its largest).
    #[test]
    fn whole_blocks_at_once_agree_with_one_at_a_time() {
        let mut seed = 0x1305_cafe_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        #[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
        if !super::avx2::available() {
            eprintln!("no AVX2 on this CPU: only the scalar path is checked");
        }
        for round in 0..3000 {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next() as u8);
            if round % 7 == 0 {
                key[..16].fill(0xff);
            }
            let pre = (next() % 4) as usize;
            let len = 16 * (next() % 200) as usize + if round % 3 == 0 { 2048 } else { 0 };
            let mut data = vec![0u8; 16 * pre + len];
            data.iter_mut().for_each(|b| *b = next() as u8);
            if round % 5 == 0 {
                data.fill(0xff);
            }
            let mut a = super::radix64::Poly1305::new(&key);
            let mut b = super::radix64::Poly1305::new(&key);
            for c in data.chunks_exact(16) {
                a.block(c.try_into().unwrap(), true);
            }
            for c in data[..16 * pre].chunks_exact(16) {
                b.block(c.try_into().unwrap(), true);
            }
            b.blocks(&data[16 * pre..]);
            // one more block each (from the state `blocks` left), then the tags
            a.block(&[0xff; 16], true);
            b.block(&[0xff; 16], true);
            assert_eq!(a.finish(), b.finish(), "round {round}: key {}, {pre} blocks before, {len} bytes", hex(&key));
        }
    }

    /// RFC 8439 message semantics: a trailing partial block gets a 0x01 marker byte and no high bit.
    macro_rules! mac {
        ($imp:ident, $key:expr, $msg:expr) => {{
            let mut p = super::$imp::Poly1305::new($key);
            let mut it = $msg.chunks_exact(16);
            for c in &mut it {
                p.block(<&[u8; 16]>::try_from(c).unwrap(), true);
            }
            let rem = it.remainder();
            if !rem.is_empty() {
                let mut b = [0u8; 16];
                b[..rem.len()].copy_from_slice(rem);
                b[rem.len()] = 1;
                p.block(&b, false);
            }
            p.finish()
        }};
    }

    #[test]
    fn rfc8439_2_5_2_both_implementations() {
        let key: [u8; 32] = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(hex(&mac!(radix64, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(hex(&mac!(limbs32, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /// The two implementations agree where the arithmetic is at its limits: r with every bit the clamp allows, blocks of
    /// all ones (with and without the 2^128 bit, and short final blocks), h that ends at p, just over and just under, and
    /// long runs of each, and random keys and messages.
    #[test]
    fn both_implementations_agree_at_the_limits() {
        let mut keys: Vec<[u8; 32]> = vec![[0xff; 32], [0; 32], [0x0f; 32], [0xf0; 32]];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..40 {
            keys.push(core::array::from_fn(|_| next() as u8));
        }
        let mut messages: Vec<Vec<u8>> = Vec::new();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1000, 4096] {
            messages.push(vec![0xff; len]);
            messages.push(vec![0; len]);
            messages.push((0..len).map(|_| next() as u8).collect());
        }
        for key in &keys {
            for msg in &messages {
                assert_eq!(mac!(radix64, key, msg), mac!(limbs32, key, msg), "key {} length {}", hex(key), msg.len());
                // and every block with the high bit, as the AEAD feeds them
                let mut a = super::radix64::Poly1305::new(key);
                let mut b = super::limbs32::Poly1305::new(key);
                for c in msg.chunks(16) {
                    let mut block = [0u8; 16];
                    block[..c.len()].copy_from_slice(c);
                    a.block(&block, true);
                    b.block(&block, true);
                }
                assert_eq!(a.finish(), b.finish());
            }
        }
        // the last step of `finish` at its edge: with r = 1 (and s = 0) h is the sum of the blocks, and three blocks of
        // 2^128 and one of 2^128 - 5 - k make h = p - k, whose tag is h mod p
        let mut key = [0u8; 32];
        key[0] = 1;
        for (k, tag) in [(1i64, "faffffffffffffffffffffffffffffff"), (0, "00000000000000000000000000000000"), (-1, "01000000000000000000000000000000"), (-4, "04000000000000000000000000000000")] {
            let v = (u128::MAX - 4).wrapping_sub(k as u128); // 2^128 - 5 - k
            let last = v.to_le_bytes();
            let mut a = super::radix64::Poly1305::new(&key);
            let mut b = super::limbs32::Poly1305::new(&key);
            for _ in 0..3 {
                a.block(&[0; 16], true);
                b.block(&[0; 16], true);
            }
            a.block(&last, false);
            b.block(&last, false);
            assert_eq!((hex(&a.finish()), hex(&b.finish())), (tag.to_string(), tag.to_string()), "h = p - ({k})");
        }
    }

    #[test]
    fn independent_vectors_both_implementations() {
        assert!(POLY1305_VECTORS.len() > 150);
        for (i, &(key, msg, tag)) in POLY1305_VECTORS.iter().enumerate() {
            let key: [u8; 32] = unhex(key).try_into().unwrap();
            let msg = unhex(msg);
            assert_eq!(hex(&mac!(radix64, &key, msg)), tag, "radix64 vector {i}");
            assert_eq!(hex(&mac!(limbs32, &key, msg)), tag, "limbs32 vector {i}");
        }
    }
}
