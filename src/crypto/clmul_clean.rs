//! Clean-room portable carry-less multiplication for GHASH.
//!
//! Bits are polynomial coefficients over GF(2), as used by the multiplication
//! operation in NIST SP 800-38D.  The fixed-work construction below returns the
//! unreduced product; GHASH's existing composition and reduction remain a
//! separate concern.

const fn every_fifth_bit(offset: u32) -> u128 {
    let mut mask = 0u128;
    let mut bit = offset;
    while bit < 128 {
        mask |= 1u128 << bit;
        bit += 5;
    }
    mask
}

const PLANE_0: u128 = every_fifth_bit(0);
const PLANE_1: u128 = every_fifth_bit(1);
const PLANE_2: u128 = every_fifth_bit(2);
const PLANE_3: u128 = every_fifth_bit(3);
const PLANE_4: u128 = every_fifth_bit(4);

#[inline(always)]
fn coefficient_parities(a: u64, b: u64, output_plane: u128) -> u128 {
    (u128::from(a) * u128::from(b)) & output_plane
}

/// Return the 128-bit carry-less polynomial product of `a` and `b`.
///
/// Each operand is separated into five residue classes by exponent modulo
/// five.  A class contains at most thirteen one-bit coefficients.  Therefore an
/// ordinary product of two classes has base-32 digits no greater than
/// thirteen: carries cannot cross a five-bit digit boundary.  The low bit of
/// every digit is exactly the parity of the corresponding polynomial
/// coefficient.
///
/// The 25 products and their addresses are fixed independently of the input.
/// This contains no secret-indexed table, secret-dependent branch, or
/// secret-dependent loop bound.
#[inline(always)]
pub(crate) fn clmul64_portable(a: u64, b: u64) -> u128 {
    let a0 = a & PLANE_0 as u64;
    let a1 = a & PLANE_1 as u64;
    let a2 = a & PLANE_2 as u64;
    let a3 = a & PLANE_3 as u64;
    let a4 = a & PLANE_4 as u64;
    let b0 = b & PLANE_0 as u64;
    let b1 = b & PLANE_1 as u64;
    let b2 = b & PLANE_2 as u64;
    let b3 = b & PLANE_3 as u64;
    let b4 = b & PLANE_4 as u64;

    // Terms are grouped by (a residue + b residue) modulo five.  A product
    // cannot set an earlier matching mask bit when the true sum is at least
    // five, so the same five masks cover all residue sums from zero to eight.
    let out0 = coefficient_parities(a0, b0, PLANE_0)
        ^ coefficient_parities(a1, b4, PLANE_0)
        ^ coefficient_parities(a2, b3, PLANE_0)
        ^ coefficient_parities(a3, b2, PLANE_0)
        ^ coefficient_parities(a4, b1, PLANE_0);
    let out1 = coefficient_parities(a0, b1, PLANE_1)
        ^ coefficient_parities(a1, b0, PLANE_1)
        ^ coefficient_parities(a2, b4, PLANE_1)
        ^ coefficient_parities(a3, b3, PLANE_1)
        ^ coefficient_parities(a4, b2, PLANE_1);
    let out2 = coefficient_parities(a0, b2, PLANE_2)
        ^ coefficient_parities(a1, b1, PLANE_2)
        ^ coefficient_parities(a2, b0, PLANE_2)
        ^ coefficient_parities(a3, b4, PLANE_2)
        ^ coefficient_parities(a4, b3, PLANE_2);
    let out3 = coefficient_parities(a0, b3, PLANE_3)
        ^ coefficient_parities(a1, b2, PLANE_3)
        ^ coefficient_parities(a2, b1, PLANE_3)
        ^ coefficient_parities(a3, b0, PLANE_3)
        ^ coefficient_parities(a4, b4, PLANE_3);
    let out4 = coefficient_parities(a0, b4, PLANE_4)
        ^ coefficient_parities(a1, b3, PLANE_4)
        ^ coefficient_parities(a2, b2, PLANE_4)
        ^ coefficient_parities(a3, b1, PLANE_4)
        ^ coefficient_parities(a4, b0, PLANE_4);

    out0 ^ out1 ^ out2 ^ out3 ^ out4
}

#[cfg(test)]
mod tests {
    use super::clmul64_portable;

    fn polynomial_oracle(a: u64, b: u64) -> u128 {
        let mut product = 0u128;
        for bit in 0..64 {
            if b & (1u64 << bit) != 0 {
                product ^= u128::from(a) << bit;
            }
        }
        product
    }

    fn check(a: u64, b: u64) {
        let expected = polynomial_oracle(a, b);
        assert_eq!(clmul64_portable(a, b), expected, "a={a:#018x}, b={b:#018x}");
        assert_eq!(clmul64_portable(b, a), expected, "commutativity");
    }

    #[test]
    fn zero_one_and_boundaries() {
        for (a, b) in [
            (0, 0),
            (0, u64::MAX),
            (1, 0),
            (1, 1),
            (1, u64::MAX),
            (u64::MAX, u64::MAX),
            (1 << 63, 1),
            (1 << 63, 1 << 63),
            (1, 1 << 63),
            (0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
            (0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa),
        ] {
            check(a, b);
        }
    }

    #[test]
    fn every_pair_of_single_bits() {
        for a_bit in 0..64 {
            for b_bit in 0..64 {
                check(1u64 << a_bit, 1u64 << b_bit);
            }
        }
    }

    #[test]
    fn deterministic_random_pairs() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..10_000 {
            // A fixed xorshift sequence is sufficient for reproducible test
            // coverage; it is not used for cryptographic randomness.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let a = state;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            check(a, state);
        }
    }

    #[test]
    fn every_pair_of_five_bit_residue_planes() {
        let planes = [
            super::PLANE_0 as u64,
            super::PLANE_1 as u64,
            super::PLANE_2 as u64,
            super::PLANE_3 as u64,
            super::PLANE_4 as u64,
        ];

        for a in planes {
            for b in planes {
                check(a, b);
                check(!a, b);
                check(a, !b);
                check(!a, !b);
            }
        }
    }

    #[test]
    fn exhaustive_byte_pairs() {
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                check(u64::from(a), u64::from(b));
            }
        }
    }

    #[test]
    fn differs_from_ordinary_integer_multiplication() {
        let a = 0b11u64;
        let b = 0b11u64;
        assert_eq!(clmul64_portable(a, b), 0b101);
        assert_ne!(clmul64_portable(a, b), u128::from(a) * u128::from(b));
    }

    fn previous_64_step(a: u64, b: u64) -> u128 {
        let mut product = 0u128;
        let a = u128::from(a);

        for bit in 0..64 {
            let coefficient = u128::from((b >> bit) & 1);
            let mask = 0u128.wrapping_sub(coefficient);
            product ^= (a << bit) & mask;
        }

        product
    }

    #[inline(never)]
    fn benchmark_previous(a: u64, b: u64) -> u128 {
        previous_64_step(a, b)
    }

    #[inline(never)]
    fn benchmark_candidate(a: u64, b: u64) -> u128 {
        clmul64_portable(a, b)
    }

    #[test]
    #[ignore = "manual release-mode throughput measurement"]
    fn benchmark_against_previous_clean_primitive() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        const INPUTS: usize = 1 << 15;
        const ROUNDS: usize = 9;
        let mut pairs = Vec::with_capacity(INPUTS);
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..INPUTS {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let a = state;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            pairs.push((a, state));
        }

        fn measure(pairs: &[(u64, u64)], operation: fn(u64, u64) -> u128) -> (Duration, u128) {
            let start = Instant::now();
            let mut checksum = 0u128;
            for &(a, b) in pairs {
                checksum ^= operation(black_box(a), black_box(b));
            }
            (start.elapsed(), black_box(checksum))
        }

        let _ = measure(&pairs, benchmark_previous);
        let _ = measure(&pairs, benchmark_candidate);

        let mut previous = Vec::with_capacity(ROUNDS);
        let mut candidate = Vec::with_capacity(ROUNDS);
        let mut checksum = 0u128;
        for _ in 0..ROUNDS {
            let (previous_time, previous_checksum) = measure(&pairs, benchmark_previous);
            let (candidate_time, candidate_checksum) = measure(&pairs, benchmark_candidate);
            assert_eq!(previous_checksum, candidate_checksum);
            checksum ^= previous_checksum;
            previous.push(previous_time);
            candidate.push(candidate_time);
        }
        previous.sort_unstable();
        candidate.sort_unstable();
        let previous = previous[ROUNDS / 2];
        let candidate = candidate[ROUNDS / 2];
        let operations = INPUTS as f64;
        let previous_ns = previous.as_secs_f64() * 1e9 / operations;
        let candidate_ns = candidate.as_secs_f64() * 1e9 / operations;

        eprintln!("previous 64-step median: {previous_ns:.3} ns/product");
        eprintln!("five-residue median:      {candidate_ns:.3} ns/product");
        eprintln!(
            "speedup:                   {:.2}x",
            previous_ns / candidate_ns
        );
        eprintln!("checksum:                  {checksum:#034x}");

        let zero_pairs = vec![(0u64, 0u64); INPUTS];
        let dense_pairs = vec![(u64::MAX, u64::MAX); INPUTS];
        let mut class_medians = Vec::new();
        for (name, class) in [
            ("zero", zero_pairs.as_slice()),
            ("dense", dense_pairs.as_slice()),
            ("random", pairs.as_slice()),
        ] {
            let mut samples = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                samples.push(measure(class, benchmark_candidate).0);
            }
            samples.sort_unstable();
            let ns = samples[ROUNDS / 2].as_secs_f64() * 1e9 / operations;
            eprintln!("{name:>6} input median:       {ns:.3} ns/product");
            class_medians.push(ns);
        }
        let slowest = class_medians
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let fastest = class_medians.iter().copied().fold(f64::INFINITY, f64::min);
        eprintln!(
            "input-class median spread:   {:.2}%",
            (slowest / fastest - 1.0) * 100.0
        );
    }
}
