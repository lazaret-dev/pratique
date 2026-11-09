#![no_std]
#![forbid(unsafe_code)]
//! Experimental larger-batch Boolean multiplier; not integrated or accepted.
//!
//! Each coefficient of a polynomial is a u64 containing 64 independent lanes.
//! Karatsuba uses only AND (coefficient product) and XOR (coefficient sum).
//! Fixed butterfly permutations transpose between lanes and coefficients.

mod circuit;

#[path = "../../src/crypto/clmul_clean.rs"]
mod accepted;

/// Retain the accepted exact single-product interface.
#[inline(always)]
pub fn clmul64_portable(a: u64, b: u64) -> u128 {
    accepted::clmul64_portable(a, b)
}

#[inline(always)]
fn transpose_step<const SHIFT: usize>(q: &mut [u64; 64], mask: u64) {
    for block in (0..64).step_by(SHIFT << 1) {
        for j in 0..SHIFT {
            let lo = block + j;
            let hi = lo + SHIFT;
            let exchanged = ((q[lo] >> SHIFT) ^ q[hi]) & mask;
            q[lo] ^= exchanged << SHIFT;
            q[hi] ^= exchanged;
        }
    }
}

/// Involutory 64 by 64 bit-matrix transpose in the caller's retained storage.
#[inline(never)]
pub fn transpose_in_place(q: &mut [u64; 64]) {
    transpose_step::<1>(q, 0x5555_5555_5555_5555);
    transpose_step::<2>(q, 0x3333_3333_3333_3333);
    transpose_step::<4>(q, 0x0f0f_0f0f_0f0f_0f0f);
    transpose_step::<8>(q, 0x00ff_00ff_00ff_00ff);
    transpose_step::<16>(q, 0x0000_ffff_0000_ffff);
    transpose_step::<32>(q, 0x0000_0000_ffff_ffff);
}

/// Value wrapper for independent non-secret probes; the integration path uses
/// the borrowed in-place API for both preparation and working data.
#[inline(never)]
pub fn transpose(mut q: [u64; 64]) -> [u64; 64] {
    transpose_in_place(&mut q);
    q
}

/// Exact independent products; wide batching is an experimental scope option.
#[inline(never)]
pub fn clmul64x64_portable(a: [u64; 64], b: [u64; 64]) -> [u128; 64] {
    let mut p = [0; 128];
    circuit::planes_product(&transpose(a), &transpose(b), &mut p);
    let mut low = [0; 64];
    let mut high = [0; 64];
    low.copy_from_slice(&p[..64]);
    high.copy_from_slice(&p[64..]);
    let low = transpose(low);
    let high = transpose(high);
    let mut out = [0; 64];
    for i in 0..64 {
        out[i] = u128::from(low[i]) ^ (u128::from(high[i]) << 64);
    }
    out
}

/// Optional prepared operand with fixed layout; key lifecycle is not integrated.
#[derive(Clone)]
pub struct Prepared64([u64; 64]);

impl Prepared64 {
    /// Construct zero storage before any key material enters the destination.
    pub const fn empty() -> Self {
        Self([0; 64])
    }

    /// Populate retained storage from a caller-owned input, without scratch arrays.
    /// The caller remains responsible for wiping the source when appropriate.
    pub fn prepare(&mut self, b: &[u64; 64]) {
        self.0.copy_from_slice(b);
        transpose_in_place(&mut self.0);
    }
}

/// XOR of 64 unreduced products, useful only if an integrator changes scheduling.
/// Preparation is excluded from this call and must be measured separately.
#[inline(never)]
pub fn clmul64_batch_xor_prepared(
    a: &mut [u64; 64],
    b: &Prepared64,
    product_planes: &mut [u64; 128],
    result: &mut u128,
) {
    transpose_in_place(a);
    circuit::planes_product(a, &b.0, product_planes);
    let mut low = 0u64;
    let mut high = 0u64;
    for bit in 0..64 {
        low ^= u64::from(product_planes[bit].count_ones() & 1) << bit;
        high ^= u64::from(product_planes[bit + 64].count_ones() & 1) << bit;
    }
    *result = u128::from(low) ^ (u128::from(high) << 64);
}

/// Three prepared operand sets for 64 independent 128-bit polynomial products.
/// This experimental container has no production key lifecycle integration.
#[derive(Clone)]
pub struct PreparedPolynomial128x64 {
    low: Prepared64,
    high: Prepared64,
    mixed: Prepared64,
}

impl PreparedPolynomial128x64 {
    /// Return only zero state; retained key material is initialized in place.
    pub const fn empty() -> Self {
        Self {
            low: Prepared64::empty(),
            high: Prepared64::empty(),
            mixed: Prepared64::empty(),
        }
    }

    /// Borrow the caller's raw powers and fill the destination's planes directly.
    ///
    /// No source-owned intermediate key arrays or populated return value are
    /// created. Caller-owned raw powers still require the caller's zeroization.
    /// This does not promise erasure of compiler-generated moves/register spills.
    pub fn prepare(&mut self, b: &[u128; 64]) {
        for i in 0..64 {
            self.low.0[i] = b[i] as u64;
            self.high.0[i] = (b[i] >> 64) as u64;
            self.mixed.0[i] = self.low.0[i] ^ self.high.0[i];
        }
        transpose_in_place(&mut self.low.0);
        transpose_in_place(&mut self.high.0);
        transpose_in_place(&mut self.mixed.0);
    }

    /// Expose all prepared secret words to the caller's existing zeroization.
    pub(crate) fn words_mut(&mut self) -> [&mut [u64; 64]; 3] {
        [&mut self.low.0, &mut self.high.0, &mut self.mixed.0]
    }

    #[cfg(test)]
    pub(crate) fn words(&self) -> [&[u64; 64]; 3] {
        [&self.low.0, &self.high.0, &self.mixed.0]
    }
}

/// Caller-owned aggregates used by the prepared polynomial product.
///
/// Construct this zero state before processing secret-derived data. The caller
/// must wipe every slice exposed by `words64_mut` and `words128_mut` after its
/// final use of `output`. There is no populated workspace return or Clone/Copy
/// implementation. The circuit's scalar temporaries and compiler-generated
/// moves, registers and spills are outside this source-owned aggregate claim.
pub struct BatchWorking128x64 {
    low: [u64; 64],
    high: [u64; 64],
    mixed: [u64; 64],
    product_planes: [u64; 128],
    sums: [u128; 3],
    output: [u128; 2],
}

impl BatchWorking128x64 {
    /// Return only zero storage; populate the retained destination in place.
    pub const fn empty() -> Self {
        Self {
            low: [0; 64],
            high: [0; 64],
            mixed: [0; 64],
            product_planes: [0; 128],
            sums: [0; 3],
            output: [0; 2],
        }
    }

    /// Borrow [low 128 bits, high 128 bits] of the unreduced product XOR.
    pub fn output(&self) -> &[u128; 2] {
        &self.output
    }

    /// Expose every 64-bit aggregate to the caller's volatile zeroization.
    pub fn words64_mut(&mut self) -> [&mut [u64]; 4] {
        [
            &mut self.low,
            &mut self.high,
            &mut self.mixed,
            &mut self.product_planes,
        ]
    }

    /// Expose every 128-bit aggregate, including results, for caller wiping.
    pub fn words128_mut(&mut self) -> [&mut [u128]; 2] {
        [&mut self.sums, &mut self.output]
    }
}

/// Write the XOR of 64 unreduced 128 by 128 products in caller-owned storage.
/// The raw block input is borrowed and remains the caller's wiping obligation.
#[inline(never)]
pub fn clmul128_batch_xor_prepared(
    a: &[u128; 64],
    b: &PreparedPolynomial128x64,
    working: &mut BatchWorking128x64,
) {
    for i in 0..64 {
        working.low[i] = a[i] as u64;
        working.high[i] = (a[i] >> 64) as u64;
        working.mixed[i] = working.low[i] ^ working.high[i];
    }
    clmul64_batch_xor_prepared(
        &mut working.low,
        &b.low,
        &mut working.product_planes,
        &mut working.sums[0],
    );
    clmul64_batch_xor_prepared(
        &mut working.high,
        &b.high,
        &mut working.product_planes,
        &mut working.sums[1],
    );
    clmul64_batch_xor_prepared(
        &mut working.mixed,
        &b.mixed,
        &mut working.product_planes,
        &mut working.sums[2],
    );
    working.sums[2] ^= working.sums[0] ^ working.sums[1];
    working.output[0] = working.sums[0] ^ (working.sums[2] << 64);
    working.output[1] = working.sums[1] ^ (working.sums[2] >> 64);
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    // Non-secret test fixtures can return by value; production key preparation
    // must initialize the final retained destination through a mutable borrow.
    fn prepared64(b: &[u64; 64]) -> Prepared64 {
        let mut p = Prepared64::empty();
        p.prepare(b);
        p
    }

    fn prepared128(b: &[u128; 64]) -> PreparedPolynomial128x64 {
        let mut p = PreparedPolynomial128x64::empty();
        p.prepare(b);
        p
    }

    // Only public non-secret test fixtures are returned by value here.
    // The integration API borrows both the input and retained working state.
    fn batch64(a: &[u64; 64], b: &Prepared64) -> u128 {
        let mut coefficients = *a;
        let mut product_planes = [0; 128];
        let mut result = 0;
        clmul64_batch_xor_prepared(&mut coefficients, b, &mut product_planes, &mut result);
        result
    }

    fn batch128(a: &[u128; 64], b: &PreparedPolynomial128x64) -> [u128; 2] {
        let mut working = BatchWorking128x64::empty();
        clmul128_batch_xor_prepared(a, b, &mut working);
        *working.output()
    }

    #[test]
    fn working_storage_is_retained_and_exposes_every_aggregate_for_wiping() {
        let mut working = BatchWorking128x64::empty();
        let addresses = [
            working.low.as_ptr(),
            working.high.as_ptr(),
            working.mixed.as_ptr(),
            working.product_planes.as_ptr(),
        ];
        assert_eq!(
            working.words64_mut().iter().map(|w| w.len()).sum::<usize>(),
            320
        );
        assert_eq!(
            working
                .words128_mut()
                .iter()
                .map(|w| w.len())
                .sum::<usize>(),
            5
        );

        let mut state = 0x510e_527f_ade6_82d1;
        let mut input = [0; 64];
        let mut powers = [0; 64];
        for i in 0..64 {
            input[i] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
            powers[i] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
        }
        let before = input;
        let prepared = prepared128(&powers);
        clmul128_batch_xor_prepared(&input, &prepared, &mut working);
        let expected = *working.output();
        assert_ne!(expected, [0, 0]);
        assert_eq!(input, before);
        assert_eq!(
            addresses,
            [
                working.low.as_ptr(),
                working.high.as_ptr(),
                working.mixed.as_ptr(),
                working.product_planes.as_ptr(),
            ]
        );
        assert!(working.product_planes.iter().any(|word| *word != 0));

        // Non-secret fixtures use fill here to test complete buffer exposure.
        // The production owner must use its volatile zeroization instead.
        for words in working.words64_mut() {
            words.fill(0);
        }
        for words in working.words128_mut() {
            words.fill(0);
        }
        // Exhaustive destructuring makes a newly added owner require a check.
        let BatchWorking128x64 {
            low,
            high,
            mixed,
            product_planes,
            sums,
            output,
        } = &working;
        assert_eq!(*low, [0; 64]);
        assert_eq!(*high, [0; 64]);
        assert_eq!(*mixed, [0; 64]);
        assert_eq!(*product_planes, [0; 128]);
        assert_eq!(*sums, [0; 3]);
        assert_eq!(*output, [0; 2]);
        clmul128_batch_xor_prepared(&input, &prepared, &mut working);
        assert_eq!(*working.output(), expected);
        assert_eq!(input, before);
    }

    fn oracle(a: u64, b: u64) -> u128 {
        let mut out = 0;
        for bit in 0..64 {
            if b & (1 << bit) != 0 {
                out ^= u128::from(a) << bit;
            }
        }
        out
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn prepared_clone_can_be_wiped_without_changing_original() {
        let a = [0x1234_5678_9abc_def0_0123_4567_89ab_cdef; 64];
        let mut b = [0; 64];
        b[0] = 0x6a09_e667_f3bc_c909_bb67_ae85_84ca_a73b;
        let original = prepared128(&b);
        let before = batch128(&a, &original);
        assert_ne!(before, [0, 0]);
        let mut copy = original.clone();
        for words in copy.words_mut() {
            words.fill(0);
        }
        assert!(copy.words().into_iter().all(|w| w.iter().all(|v| *v == 0)));
        assert_eq!(batch128(&a, &copy), [0, 0]);
        assert_eq!(batch128(&a, &original), before);
    }

    #[test]
    fn preparation_borrows_inputs_and_replaces_all_retained_planes() {
        let mut raw = [0; 64];
        raw[0] = u128::MAX;
        raw[63] = 1 << 127;
        let expected_raw = raw;
        let mut destination = PreparedPolynomial128x64::empty();
        assert!(
            destination
                .words()
                .into_iter()
                .all(|w| w.iter().all(|v| *v == 0))
        );
        let addresses = destination.words().map(|w| w.as_ptr());
        destination.prepare(&raw);
        assert_eq!(raw, expected_raw);
        assert_eq!(addresses, destination.words().map(|w| w.as_ptr()));
        assert!(
            destination
                .words()
                .into_iter()
                .any(|w| w.iter().any(|v| *v != 0))
        );
        destination.prepare(&[0; 64]);
        assert_eq!(addresses, destination.words().map(|w| w.as_ptr()));
        assert!(
            destination
                .words()
                .into_iter()
                .all(|w| w.iter().all(|v| *v == 0))
        );

        let raw64 = [0x6a09_e667_f3bc_c909; 64];
        let mut narrow = Prepared64::empty();
        narrow.prepare(&raw64);
        assert_eq!(narrow.0, transpose(raw64));
        narrow.prepare(&[0; 64]);
        assert_eq!(narrow.0, [0; 64]);
    }

    #[test]
    fn transpose_every_lane_and_bit() {
        for lane in 0..64 {
            for bit in 0..64 {
                let mut q = [0; 64];
                q[lane] = 1 << bit;
                let mut expected = [0; 64];
                expected[bit] = 1 << lane;
                assert_eq!(transpose(q), expected);
            }
        }
    }

    fn check(a: [u64; 64], b: [u64; 64]) {
        let actual = clmul64x64_portable(a, b);
        let swapped = clmul64x64_portable(b, a);
        let mut sum = 0;
        for lane in 0..64 {
            let expected = oracle(a[lane], b[lane]);
            assert_eq!(actual[lane], expected, "lane {lane}");
            assert_eq!(swapped[lane], expected, "commutativity, lane {lane}");
            assert_eq!(clmul64_portable(a[lane], b[lane]), expected);
            sum ^= expected;
        }
        assert_eq!(batch64(&a, &prepared64(&b)), sum);
    }

    #[test]
    fn every_single_bit_pair() {
        for a_bit in 0..64 {
            let a = [1 << a_bit; 64];
            let mut b = [0; 64];
            for (bit, value) in b.iter_mut().enumerate() {
                *value = 1 << bit;
            }
            check(a, b);
        }
    }

    #[test]
    fn edges_and_mixed_lanes() {
        let cases = [
            0,
            1,
            u64::MAX,
            1 << 63,
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0xffff_ffff,
            0xffff_ffff_0000_0000,
        ];
        for a in cases {
            for b in cases {
                check([a; 64], [b; 64]);
            }
        }
        let mut a = [0; 64];
        let mut b = [0; 64];
        for lane in 0..64 {
            a[lane] = cases[lane & 7];
            b[lane] = cases[(lane >> 3) & 7];
        }
        check(a, b);
    }

    #[test]
    fn deterministic_random_pairs() {
        let mut state = 0x6a09_e667_f3bc_c909;
        // 192 * 64 = 12,288 pairs, each also checked in reverse order.
        for _ in 0..192 {
            let mut a = [0; 64];
            let mut b = [0; 64];
            for lane in 0..64 {
                a[lane] = next(&mut state);
                b[lane] = next(&mut state);
            }
            check(a, b);
        }
    }

    #[test]
    fn wide_polynomial_oracle_and_boundaries() {
        fn oracle128(a: u128, b: u128) -> [u128; 2] {
            let mut p = [0; 2];
            for bit in 0..128 {
                if (b >> bit) & 1 != 0 {
                    p[0] ^= a << bit;
                    if bit != 0 {
                        p[1] ^= a >> (128 - bit);
                    }
                }
            }
            p
        }

        let mut state = 0x3c6e_f372_fe94_f82b;
        for iteration in 0..128 {
            let mut a = [0; 64];
            let mut b = [0; 64];
            let mut expected = [0; 2];
            for lane in 0..64 {
                a[lane] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
                b[lane] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
                let p = oracle128(a[lane], b[lane]);
                expected[0] ^= p[0];
                expected[1] ^= p[1];
            }
            assert_eq!(batch128(&a, &prepared128(&b)), expected);
            for lane in [0, 31, 32, 63] {
                let mut a = [0; 64];
                let mut b = [0; 64];
                a[lane] = 1 << iteration;
                b[lane] = u128::MAX;
                assert_eq!(batch128(&a, &prepared128(&b)), oracle128(a[lane], b[lane]));
            }
        }
    }

    /// Direct transcription of SP 800-38D Algorithm 1, test oracle only.
    fn nist_multiply(x: u128, mut v: u128) -> u128 {
        let mut z = 0;
        for bit in (0..128).rev() {
            if (x >> bit) & 1 != 0 {
                z ^= v;
            }
            let odd = v & 1 != 0;
            v >>= 1;
            if odd {
                v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000;
            }
        }
        z
    }

    /// Long division by x^128+x^7+x^2+x+1, test oracle only.
    fn reduce(mut p: [u128; 2]) -> u128 {
        for bit in (128..256).rev() {
            if (p[bit / 128] >> (bit & 127)) & 1 != 0 {
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
    fn weighted_batch_matches_nist_recurrence() {
        let mut state = 0xa54f_f53a_5f1d_36f1;
        for h in [
            0,
            1,
            u128::MAX,
            1 << 127,
            0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e,
        ] {
            let mut powers = [0; 64];
            let mut power = h;
            for index in (0..64).rev() {
                powers[index] = power.reverse_bits();
                power = nist_multiply(power, h);
            }
            let prepared = prepared128(&powers);
            let mut sequential = 0;
            let mut grouped = 0u128;
            for _ in 0..3 {
                let mut a = [0; 64];
                for lane in 0..64 {
                    let block = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
                    sequential = nist_multiply(sequential ^ block, h);
                    a[lane] = block.reverse_bits();
                }
                a[0] ^= grouped.reverse_bits();
                grouped = reduce(batch128(&a, &prepared)).reverse_bits();
                assert_eq!(grouped, sequential);
            }
        }
    }
}
