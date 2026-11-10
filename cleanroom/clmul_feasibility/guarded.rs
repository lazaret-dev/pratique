//! Experimental fixed public guard lanes for the independently authored circuit.
//!
//! Fifty payload products share a 64-lane circuit with fourteen fixed public
//! products. Each abstract nonconstant circuit wire has both a one and a zero
//! among the guard lanes, even when every payload key or block is zero. The
//! known guard-product XOR is removed after aggregation. This is a testable
//! representation change, not a proof of arbitrary value-independent hardware
//! timing. Packing, final aggregation and actual optimized code require review.

use core::hint::black_box;
use super::{BatchWorking128x64, PreparedPolynomial128x64, circuit, transpose_in_place};

#[path = "guard_constants.rs"]
mod constants;

pub const PAYLOAD_LANES: usize = 50;

/// Prepared polynomial planes retained in the caller's final destination.
/// There is no populated by-value constructor, Clone or Copy implementation.
pub struct PreparedPolynomial128x50 {
    planes: PreparedPolynomial128x64,
}

impl PreparedPolynomial128x50 {
    pub const fn empty() -> Self {
        Self { planes: PreparedPolynomial128x64::empty() }
    }

    /// Prepare fifty real powers plus public guard operands in place.
    /// The caller must wipe its borrowed raw powers separately.
    pub fn prepare(&mut self, b: &[u128; PAYLOAD_LANES]) {
        for (i, &word) in b.iter().enumerate() {
            self.planes.low.0[i] = word as u64;
            self.planes.high.0[i] = (word >> 64) as u64;
            self.planes.mixed.0[i] = self.planes.low.0[i] ^ self.planes.high.0[i];
        }
        for (i, &(_, word)) in constants::PAIRS.iter().enumerate() {
            let j = i + PAYLOAD_LANES;
            self.planes.low.0[j] = word as u64;
            self.planes.high.0[j] = (word >> 64) as u64;
            self.planes.mixed.0[j] = self.planes.low.0[j] ^ self.planes.high.0[j];
        }
        transpose_in_place(&mut self.planes.low.0);
        transpose_in_place(&mut self.planes.high.0);
        transpose_in_place(&mut self.planes.mixed.0);
    }

    /// Expose every retained key-derived word to the caller's volatile wipe.
    pub fn words_mut(&mut self) -> [&mut [u64; 64]; 3] {
        self.planes.words_mut()
    }

    /// Borrow the retained words for lifecycle assertions without secret copies.
    #[cfg(test)]
    pub fn words(&self) -> [&[u64; 64]; 3] {
        self.planes.words()
    }
}

#[inline(never)]
fn guarded_sum(a: &mut [u64; 64], b: &[u64; 64], p: &mut [u64; 128], out: &mut u128) {
    transpose_in_place(a);
    // Opaque borrowed boundaries retain all lanes when the caller only needs
    // parity. They do not independently certify the compiler's internal DAG.
    circuit::planes_product(black_box(a), black_box(b), black_box(p));
    let p = black_box(&*p);
    let mut lo = 0;
    let mut hi = 0;
    for bit in 0..64 {
        lo ^= u64::from(p[bit].count_ones() & 1) << bit;
        hi ^= u64::from(p[bit + 64].count_ones() & 1) << bit;
    }
    *out = u128::from(lo) ^ (u128::from(hi) << 64);
}

/// Exact XOR of fifty unreduced 128-by-128 polynomial products.
///
/// The existing retained working container is reused, including all wipe
/// exposure APIs. Borrowed raw blocks remain the caller's wipe obligation.
#[inline(never)]
pub fn clmul128x50_batch_xor_prepared(
    a: &[u128; PAYLOAD_LANES],
    b: &PreparedPolynomial128x50,
    working: &mut BatchWorking128x64,
) {
    for (i, &word) in a.iter().enumerate() {
        working.low[i] = word as u64;
        working.high[i] = (word >> 64) as u64;
        working.mixed[i] = working.low[i] ^ working.high[i];
    }
    for (i, &(word, _)) in constants::PAIRS.iter().enumerate() {
        let j = i + PAYLOAD_LANES;
        working.low[j] = word as u64;
        working.high[j] = (word >> 64) as u64;
        working.mixed[j] = working.low[j] ^ working.high[j];
    }
    guarded_sum(&mut working.low, &b.planes.low.0, &mut working.product_planes, &mut working.sums[0]);
    guarded_sum(&mut working.high, &b.planes.high.0, &mut working.product_planes, &mut working.sums[1]);
    guarded_sum(&mut working.mixed, &b.planes.mixed.0, &mut working.product_planes, &mut working.sums[2]);
    working.sums[2] ^= working.sums[0] ^ working.sums[1];
    working.output[0] = working.sums[0] ^ (working.sums[2] << 64) ^ constants::CORRECTION[0];
    working.output[1] = working.sums[1] ^ (working.sums[2] >> 64) ^ constants::CORRECTION[1];
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::{BitAnd, BitXor};

    const GUARD_MASK: u64 = !((1 << PAYLOAD_LANES) - 1);

    #[derive(Clone, Copy, Default)]
    struct GuardWord(u64);

    impl GuardWord {
        fn checked(v: u64) -> Self {
            assert_ne!(v & GUARD_MASK, 0, "abstract wire lost its one sentinel");
            assert_ne!(v & GUARD_MASK, GUARD_MASK, "abstract wire lost its zero sentinel");
            Self(v)
        }
    }

    impl BitXor for GuardWord {
        type Output = Self;
        fn bitxor(self, rhs: Self) -> Self { Self::checked(self.0 ^ rhs.0) }
    }

    impl BitAnd for GuardWord {
        type Output = Self;
        fn bitand(self, rhs: Self) -> Self { Self::checked(self.0 & rhs.0) }
    }

    fn oracle(a: u128, b: u128) -> [u128; 2] {
        let mut p = [0, 0];
        for i in 0..128 {
            if b >> i & 1 != 0 {
                p[0] ^= a << i;
                if i != 0 { p[1] ^= a >> (128-i); }
            }
        }
        p
    }

    fn next(s: &mut u64) -> u128 {
        fn step(s: &mut u64) -> u64 {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *s
        }
        u128::from(step(s)) | (u128::from(step(s)) << 64)
    }

    #[test]
    fn every_abstract_wire_has_both_public_sentinel_values() {
        for group in 0..3 {
            let part = |v: u128| match group {
                0 => v as u64,
                1 => (v >> 64) as u64,
                _ => v as u64 ^ (v >> 64) as u64,
            };
            let mut a = [0; 64];
            let mut b = [0; 64];
            for (i, &(x, y)) in constants::PAIRS.iter().enumerate() {
                a[i + PAYLOAD_LANES] = part(x);
                b[i + PAYLOAD_LANES] = part(y);
            }
            transpose_in_place(&mut a);
            transpose_in_place(&mut b);
            let a = a.map(GuardWord::checked);
            let b = b.map(GuardWord::checked);
            let mut out = [GuardWord::default(); 128];
            circuit::planes_product(&a, &b, &mut out);
            assert_eq!(out[127].0, 0); // The known constant coefficient is exempt.
        }
    }

    #[test]
    fn public_correction_is_exact_and_zero_payload_is_zero() {
        let mut expected = [0, 0];
        for &(a, b) in &constants::PAIRS {
            let p = oracle(a, b);
            expected[0] ^= p[0];
            expected[1] ^= p[1];
        }
        assert_eq!(constants::CORRECTION, expected);
        let mut prepared = PreparedPolynomial128x50::empty();
        prepared.prepare(&[0; PAYLOAD_LANES]);
        let mut working = BatchWorking128x64::empty();
        clmul128x50_batch_xor_prepared(&[0; PAYLOAD_LANES], &prepared, &mut working);
        assert_eq!(working.output(), &[0, 0]);
    }

    #[test]
    fn fifty_lane_edges_and_random_products_match_independent_oracle() {
        let mut rng = 0x7b7b_13a6_9192_4242;
        let mut a = [0; PAYLOAD_LANES];
        let mut b = [0; PAYLOAD_LANES];
        let mut prepared = PreparedPolynomial128x50::empty();
        let mut working = BatchWorking128x64::empty();
        for case in 0..180 {
            for i in 0..PAYLOAD_LANES {
                a[i] = match case {
                    0 => 0, 1 => u128::MAX, 2..=129 => 1 << (case-2), _ => next(&mut rng),
                };
                b[i] = match case {
                    0 => next(&mut rng), 1 => u128::MAX, 2..=129 => 1 << ((case+i)%128),
                    130 => 0, _ => next(&mut rng),
                };
            }
            let mut expected = [0, 0];
            for i in 0..PAYLOAD_LANES {
                let p = oracle(a[i], b[i]);
                expected[0] ^= p[0];
                expected[1] ^= p[1];
            }
            prepared.prepare(&b);
            clmul128x50_batch_xor_prepared(&a, &prepared, &mut working);
            assert_eq!(working.output(), &expected, "case {case}");
        }
    }

    #[test]
    fn guarded_preparation_retains_and_exposes_all_key_storage() {
        let mut p = PreparedPolynomial128x50::empty();
        let before = p.words_mut().map(|x| x.as_ptr());
        let b = [u128::MAX; PAYLOAD_LANES];
        p.prepare(&b);
        let after = p.words_mut().map(|x| x.as_ptr());
        assert_eq!(before, after);
        assert_eq!(p.words_mut().iter().map(|x| x.len()).sum::<usize>(), 192);
        for words in p.words_mut() { words.fill(0); }
        assert!(p.words().iter().all(|x| x.iter().all(|&w| w == 0)));
        assert_eq!(b, [u128::MAX; PAYLOAD_LANES]);
    }

    // Direct SP800-38D Algorithm1 oracle, used only in tests. This deliberately
    // uses the opposite NIST bit convention rather than the circuit recurrence.
    fn nist_multiply(x: u128, mut v: u128) -> u128 {
        let mut z = 0;
        for bit in (0..128).rev() {
            if x >> bit & 1 != 0 { z ^= v; }
            let odd = v & 1 != 0;
            v >>= 1;
            if odd { v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000; }
        }
        z
    }

    // Independent long division of a 256-bit polynomial, tests only.
    fn reduce(mut p: [u128; 2]) -> u128 {
        for bit in (128..256).rev() {
            if p[bit / 128] >> (bit & 127) & 1 != 0 {
                p[bit / 128] ^= 1 << (bit & 127);
                for term in [0, 1, 2, 7] {
                    let dst = bit - 128 + term;
                    p[dst / 128] ^= 1 << (dst & 127);
                }
            }
        }
        p[0]
    }

    #[test]
    fn fifty_lane_weighted_batches_match_nist_with_carried_state() {
        let mut rng = 0x22aa_34df_6319_8b75;
        for h in [0, 1, u128::MAX, 1 << 127, 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e] {
            let mut powers = [0; PAYLOAD_LANES];
            let mut power = h;
            for i in (0..PAYLOAD_LANES).rev() {
                powers[i] = power.reverse_bits();
                power = nist_multiply(power, h);
            }
            let mut prepared = PreparedPolynomial128x50::empty();
            prepared.prepare(&powers);
            let mut working = BatchWorking128x64::empty();
            let mut sequential = 0;
            let mut grouped = 0u128;
            for _ in 0..5 {
                let mut a = [0; PAYLOAD_LANES];
                for word in &mut a {
                    let block = next(&mut rng);
                    sequential = nist_multiply(sequential ^ block, h);
                    *word = block.reverse_bits();
                }
                a[0] ^= grouped.reverse_bits();
                clmul128x50_batch_xor_prepared(&a, &prepared, &mut working);
                grouped = reduce(*working.output()).reverse_bits();
                assert_eq!(grouped, sequential);
            }
        }
    }
}
