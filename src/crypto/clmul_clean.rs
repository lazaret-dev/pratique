//! Clean-room portable carry-less multiplication for GHASH.
//!
//! Bits are polynomial coefficients over GF(2), as used by the multiplication
//! operation in NIST SP 800-38D.  The fixed 64-step construction below returns
//! the unreduced product; GHASH's existing composition and reduction remain a
//! separate concern.

/// Return the 128-bit carry-less polynomial product of `a` and `b`.
///
/// The loop bound and shift counts are public and fixed.  A full-width mask
/// selects each partial product without a branch or a data-dependent address.
#[inline(always)]
pub(crate) fn clmul64_portable(a: u64, b: u64) -> u128 {
    let mut product = 0u128;
    let a = u128::from(a);

    for bit in 0..64 {
        let coefficient = u128::from((b >> bit) & 1);
        let mask = 0u128.wrapping_sub(coefficient);
        product ^= (a << bit) & mask;
    }

    product
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
    fn differs_from_ordinary_integer_multiplication() {
        let a = 0b11u64;
        let b = 0b11u64;
        assert_eq!(clmul64_portable(a, b), 0b101);
        assert_ne!(clmul64_portable(a, b), u128::from(a) * u128::from(b));
    }
}
