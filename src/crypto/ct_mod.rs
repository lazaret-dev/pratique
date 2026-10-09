//! Constant-time arithmetic modulo a public odd number of up to a few limbs: the group orders of P-256 and P-384 for
//! ECDSA signing, and the order L of edwards25519 for Ed25519 signing (B-109). The values are secret (nonces, private
//! scalars, their products); the modulus is not.
//!
//! The rules are those of `ecdh.rs`, whose field arithmetic this mirrors with the number of limbs fixed at compile time
//! (`N`): the loops run over all `N` limbs whatever the values, comparisons and conditional subtractions are made with
//! masks rather than branches, and the masks pass through `black_box` (without it LLVM has turned such a select back
//! into a branch on the data before; see `ecdh::mask_of`). Products are Montgomery products (CIOS); the inverse is
//! Fermat's, a^(m-2), whose exponent is public, so the sequence of squarings and products is the same for every value.
//!
//! What a caller must know:
//!
//! * a value "in range" is below the modulus; [`Modulus::mul`] also takes one operand of up to `N` limbs that is not
//!   reduced (any value below R = 2^(64 N)) as long as the other is in range, which is what [`Modulus::to_mont`] and
//!   [`Modulus::reduce_wide`] use to reduce values of any size;
//! * the modulus must be odd, and above 2^(64 N - 64) (its top limb is not zero); both are checked when it is made.

use super::bignum::{self, Mont};
use crate::zeroize::Zeroize;
use std::hint::black_box;

/// All ones if the low bit of `bit` is set, else zero, opaque to the optimiser.
#[inline]
pub(crate) fn mask_of(bit: u64) -> u64 {
    black_box(0u64.wrapping_sub(bit & 1))
}

/// All ones if every limb of `a` is zero, else zero.
#[inline]
pub(crate) fn zero_mask<const N: usize>(a: &[u64; N]) -> u64 {
    let x = a.iter().fold(0u64, |acc, &l| acc | l);
    // (x | -x) has its top bit set exactly when x != 0
    mask_of(((x | x.wrapping_neg()) >> 63) ^ 1)
}

/// `a` where `mask` is all ones, `b` where it is zero.
#[inline]
pub(crate) fn select<const N: usize>(mask: u64, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    for i in 0..N {
        r[i] = (a[i] & mask) | (b[i] & !mask);
    }
    r
}

/// a - b and the borrow (1 if b > a), over all `N` limbs.
#[inline]
fn sub_borrow<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut d = [0u64; N];
    let mut borrow = 0u64;
    for i in 0..N {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (y, b2) = x.overflowing_sub(borrow);
        d[i] = y;
        borrow = (b1 | b2) as u64;
    }
    (d, borrow)
}

/// Arithmetic modulo `m`, an odd number of `N` limbs whose top limb is not zero.
#[derive(Clone)]
pub(crate) struct Modulus<const N: usize> {
    m: [u64; N],
    /// -m^-1 mod 2^64
    m0inv: u64,
    /// R^2 and R^3 mod m, R = 2^(64 N)
    r2: [u64; N],
    r3: [u64; N],
    /// m - 2, the exponent of Fermat's inverse (public)
    m_minus_2: [u64; N],
}

impl<const N: usize> Modulus<N> {
    /// The modulus from big-endian hex (public constants). Panics on an even modulus or a zero top limb.
    pub(crate) fn from_hex(hex: &str) -> Modulus<N> {
        let v = bignum::from_hex(hex);
        let mut m = [0u64; N];
        assert!(bignum::trimmed_len(&v) == N, "a modulus of exactly {N} limbs");
        m.copy_from_slice(&v[..N]);
        Modulus::new(m)
    }

    pub(crate) fn new(m: [u64; N]) -> Modulus<N> {
        assert!(m[0] & 1 == 1 && m[N - 1] != 0, "an odd modulus of {N} full limbs");
        // Newton's iteration for m^-1 mod 2^64 (each step doubles the correct low bits: 1, 2, 4, ..., 64)
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        // R^2 mod m by the variable-time code: the modulus is public
        let mont = Mont::new(&m);
        let one = mont.one(); // R mod m
        let to_arr = |v: Vec<u64>| -> [u64; N] {
            let mut a = [0u64; N];
            a.copy_from_slice(&v[..N]);
            a
        };
        let r2 = to_arr(mont.to_mont(&one));
        let r3 = to_arr(mont.to_mont(&r2));
        let mut m_minus_2 = m;
        let (d, borrow) = sub_borrow(&m, &{
            let mut two = [0u64; N];
            two[0] = 2;
            two
        });
        debug_assert_eq!(borrow, 0);
        m_minus_2.copy_from_slice(&d);
        Modulus { m, m0inv: inv.wrapping_neg(), r2, r3, m_minus_2 }
    }

    /// The arithmetic for a SECRET modulus (an RSA prime): the constants are made without the variable-time code, so
    /// that nothing in their making depends on the value. The modulus must be odd; its top limb may be zero.
    pub(crate) fn new_secret(m: [u64; N]) -> Modulus<N> {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let mut two = [0u64; N];
        two[0] = 2;
        let (m_minus_2, _) = sub_borrow(&m, &two);
        let mut k = Modulus { m, m0inv: inv.wrapping_neg(), r2: [0u64; N], r3: [0u64; N], m_minus_2 };
        // R^2 mod m: 1 doubled 128 N times, each doubling a constant-time addition (a value below m stays below m)
        let mut x = [0u64; N];
        x[0] = 1;
        x = k.reduce_below_twice(&x); // 1 mod m (m is at least 3)
        for _ in 0..128 * N {
            x = k.add(&x, &x);
        }
        k.r2 = x;
        k.r3 = k.mul(&x, &x); // R^4 / R
        k
    }

    /// The modulus itself.
    pub(crate) fn value(&self) -> &[u64; N] {
        &self.m
    }

    /// 1 in the Montgomery domain: R mod m.
    #[inline]
    pub(crate) fn one(&self) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        self.to_mont(&one)
    }

    /// m - 2 (Fermat's exponent: a^(m-2) is a^-1 for a prime m).
    pub(crate) fn minus_two(&self) -> &[u64; N] {
        &self.m_minus_2
    }

    /// base^exp for a SECRET exponent, both the base and the result in the Montgomery domain: fixed windows of 4 bits
    /// over all 64 N bits of the exponent, four squarings and one product per window whatever its value, and the table
    /// entry read by scanning all 16 with masks. So the work and every memory address are the same for every exponent
    /// and base.
    pub(crate) fn pow_secret(&self, base: &[u64; N], exp: &[u64; N]) -> [u64; N] {
        let mut table = [[0u64; N]; 16];
        table[0] = self.one();
        for i in 1..16 {
            table[i] = self.mul(&table[i - 1], base);
        }
        let mut r = table[0];
        for i in (0..N * 16).rev() {
            for _ in 0..4 {
                r = self.sqr(&r);
            }
            let nibble = black_box((exp[i / 16] >> (4 * (i % 16))) & 15);
            let mut sel = [0u64; N];
            for (j, entry) in table.iter().enumerate() {
                let x = nibble ^ j as u64;
                // all ones when x == 0
                let hit = mask_of(((x | x.wrapping_neg()) >> 63) ^ 1);
                for l in 0..N {
                    sel[l] |= entry[l] & hit;
                }
            }
            r = self.mul(&r, &sel);
            sel.zeroize();
        }
        table.zeroize();
        r
    }

    /// (carry : t) - m if that is not negative, else t: one subtraction, kept or not by a mask. Correct whenever
    /// (carry : t) < 2 m.
    #[inline]
    fn reduce_once(&self, t: &[u64; N], carry: u64) -> [u64; N] {
        let (d, borrow) = sub_borrow(t, &self.m);
        // (carry : t) >= m exactly when the top carry is set or the subtraction did not borrow
        let mask = mask_of(carry | (borrow ^ 1));
        select(mask, &d, t)
    }

    /// A value below 2 m (or 2^(64 N), whichever is less) brought below m.
    #[inline]
    pub(crate) fn reduce_below_twice(&self, a: &[u64; N]) -> [u64; N] {
        self.reduce_once(a, 0)
    }

    #[inline]
    pub(crate) fn add(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut t = [0u64; N];
        let mut carry = 0u64;
        for i in 0..N {
            let s = a[i] as u128 + b[i] as u128 + carry as u128;
            t[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        self.reduce_once(&t, carry)
    }

    #[inline]
    #[cfg_attr(not(test), allow(dead_code))] // nothing signs with a subtraction yet; the tests check it with the rest
    pub(crate) fn sub(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let (mut d, borrow) = sub_borrow(a, b);
        // add m back if it went below zero
        let mask = mask_of(borrow);
        let mut carry = 0u64;
        for i in 0..N {
            let s = d[i] as u128 + (self.m[i] & mask) as u128 + carry as u128;
            d[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        d
    }

    /// The Montgomery product a b / R mod m (CIOS), for a b < m R: both below m, or one below m and the other any
    /// value of `N` limbs.
    #[inline]
    pub(crate) fn mul(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        // t holds N + 2 limbs; an array of N + 2 is not expressible with a const generic, so the top two are apart
        let mut t = [0u64; N];
        let mut t_n = 0u64;
        let mut t_n1: u64;
        for i in 0..N {
            let mut c = 0u64;
            for j in 0..N {
                let s = t[j] as u128 + (a[j] as u128) * (b[i] as u128) + c as u128;
                t[j] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t_n as u128 + c as u128;
            t_n = s as u64;
            t_n1 = (s >> 64) as u64;

            let q = t[0].wrapping_mul(self.m0inv);
            let s = t[0] as u128 + (q as u128) * (self.m[0] as u128);
            let mut c = (s >> 64) as u64;
            for j in 1..N {
                let s = t[j] as u128 + (q as u128) * (self.m[j] as u128) + c as u128;
                t[j - 1] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t_n as u128 + c as u128;
            t[N - 1] = s as u64;
            t_n = t_n1 + (s >> 64) as u64;
        }
        self.reduce_once(&t, t_n)
    }

    #[inline]
    pub(crate) fn sqr(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, a)
    }

    /// a R mod m: the Montgomery form of `a`, which may be any value of `N` limbs (it is reduced on the way).
    #[inline]
    pub(crate) fn to_mont(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, &self.r2)
    }

    /// a / R mod m: back from the Montgomery form.
    #[inline]
    pub(crate) fn from_mont(&self, a: &[u64; N]) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// (lo + hi R) mod m, for any two values of `N` limbs: a number of up to 2 N limbs reduced, in normal form.
    pub(crate) fn reduce_wide(&self, lo: &[u64; N], hi: &[u64; N]) -> [u64; N] {
        // lo r2 / R = lo R and hi r3 / R = hi R^2: their sum is (lo + hi R) R, the Montgomery form of the value
        let x = self.add(&self.mul(lo, &self.r2), &self.mul(hi, &self.r3));
        self.from_mont(&x)
    }

    /// a^(m-2) = a^-1 in the Montgomery domain (and 0 for 0). The exponent is public: the same squarings and products
    /// for every `a`.
    pub(crate) fn invert(&self, a: &[u64; N]) -> [u64; N] {
        let mut r = self.to_mont(&{
            let mut one = [0u64; N];
            one[0] = 1;
            one
        });
        for i in (0..N * 64).rev() {
            r = self.sqr(&r);
            if (self.m_minus_2[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// All ones if a < m, else zero.
    #[inline]
    pub(crate) fn below_mask(&self, a: &[u64; N]) -> u64 {
        let (_, borrow) = sub_borrow(a, &self.m);
        mask_of(borrow)
    }
}

impl<const N: usize> Zeroize for Modulus<N> {
    /// For a secret modulus (an RSA prime): every constant derived from it goes too.
    fn zeroize(&mut self) {
        self.m.zeroize();
        self.m0inv.zeroize();
        self.r2.zeroize();
        self.r3.zeroize();
        self.m_minus_2.zeroize();
    }
}

/// Big-endian bytes (at most 8 N) as `N` little-endian limbs.
pub(crate) fn limbs_from_be<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert!(bytes.len() <= 8 * N, "at most {N} limbs");
    let mut l = [0u64; N];
    for (i, b) in bytes.iter().rev().enumerate() {
        l[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    l
}

/// `N` limbs as exactly `len` big-endian bytes (the limbs above `len` bytes must be zero).
pub(crate) fn limbs_to_be<const N: usize>(l: &[u64; N], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len {
        out[len - 1 - i] = (l[i / 8] >> (8 * (i % 8))) as u8;
    }
    out
}

/// Little-endian bytes (at most 8 N) as `N` limbs.
pub(crate) fn limbs_from_le<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert!(bytes.len() <= 8 * N, "at most {N} limbs");
    let mut l = [0u64; N];
    for (i, b) in bytes.iter().enumerate() {
        l[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    l
}

/// `N` limbs as exactly `len` little-endian bytes.
pub(crate) fn limbs_to_le<const N: usize>(l: &[u64; N], len: usize) -> Vec<u8> {
    (0..len).map(|i| (l[i / 8] >> (8 * (i % 8))) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::Rng;

    const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    const ED25519_L: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

    fn rand_limbs<const N: usize>(rng: &mut Rng) -> [u64; N] {
        let mut a = [0u64; N];
        for l in a.iter_mut() {
            *l = rng.next_u64();
        }
        a
    }

    /// A random value below m (by clearing top bits, then one subtraction).
    fn rand_below<const N: usize>(rng: &mut Rng, m: &Modulus<N>) -> [u64; N] {
        // a top limb of at most m's makes a < 2 m, which one subtraction brings below m
        let mut a = rand_limbs::<N>(rng);
        let top = m.m[N - 1];
        a[N - 1] = if top == u64::MAX { a[N - 1] } else { a[N - 1] % (top + 1) };
        m.reduce_below_twice(&a)
    }

    fn check<const N: usize>(hex: &str) {
        let m = Modulus::<N>::from_hex(hex);
        let reference = Mont::new(&m.m);
        let big = |a: &[u64; N]| a.to_vec();
        let mut rng = Rng::new(0x5eed ^ N as u64);
        let mut edges: Vec<[u64; N]> = vec![[0u64; N], {
            let mut one = [0u64; N];
            one[0] = 1;
            one
        }];
        let mut mm1 = m.m;
        mm1[0] -= 1;
        edges.push(mm1);
        for _ in 0..400 {
            edges.push(rand_below(&mut rng, &m));
        }
        for (i, a) in edges.iter().enumerate() {
            let b = &edges[(i * 7 + 3) % edges.len()];
            assert_eq!(big(&m.mul(a, b)), reference.mul(&big(a), &big(b)), "mul");
            assert_eq!(big(&m.add(a, b)), reference.add(&big(a), &big(b)), "add");
            assert_eq!(big(&m.sub(a, b)), reference.sub(&big(a), &big(b)), "sub");
            assert_eq!(big(&m.to_mont(a)), reference.to_mont(&big(a)), "to_mont");
            assert_eq!(big(&m.from_mont(a)), reference.from_mont(&big(a)), "from_mont");
            if zero_mask(a) == 0 {
                assert_eq!(m.from_mont(&m.mul(&m.invert(&m.to_mont(a)), &m.to_mont(a))), {
                    let mut one = [0u64; N];
                    one[0] = 1;
                    one
                });
            }
            assert_eq!(m.below_mask(a), u64::MAX);
        }
        assert_eq!(m.below_mask(&m.m), 0);
        assert_eq!(m.below_mask(&[u64::MAX; N]), 0);
        // to_mont and reduce_wide on values that are not reduced: any N limbs, and any 2 N limbs
        for _ in 0..400 {
            let lo = rand_limbs::<N>(&mut rng);
            let hi = rand_limbs::<N>(&mut rng);
            let mut wide = lo.to_vec();
            wide.extend_from_slice(&hi);
            let want = bignum_mod(&wide, &m.m);
            assert_eq!(big(&m.reduce_wide(&lo, &hi)), want, "reduce_wide");
            assert_eq!(big(&m.from_mont(&m.to_mont(&lo))), bignum_mod(&lo, &m.m), "to_mont of an unreduced value");
        }
        for (lo, hi) in [([u64::MAX; N], [u64::MAX; N]), ([0; N], [u64::MAX; N]), ([u64::MAX; N], [0; N])] {
            let mut wide = lo.to_vec();
            wide.extend_from_slice(&hi);
            assert_eq!(big(&m.reduce_wide(&lo, &hi)), bignum_mod(&wide, &m.m));
        }
    }

    /// x mod m by long division one bit at a time (slow and obviously right).
    fn bignum_mod(x: &[u64], m: &[u64]) -> Vec<u64> {
        let mont = Mont::new(m);
        let mut r = vec![0u64; m.len()];
        for bit in (0..x.len() * 64).rev() {
            r = mont.add(&r, &r);
            if (x[bit / 64] >> (bit % 64)) & 1 == 1 {
                let mut one = vec![0u64; m.len()];
                one[0] = 1;
                r = mont.add(&r, &one);
            }
        }
        r
    }

    #[test]
    fn the_arithmetic_agrees_with_the_variable_time_code() {
        check::<4>(P256_N);
        check::<6>(P384_N);
        check::<4>(ED25519_L);
    }

    /// The constants made without the variable-time code are the same, for moduli of RSA-prime sizes too (with a zero
    /// top limb as well), and the secret-exponent power is the plain one.
    #[test]
    fn secret_moduli_and_secret_exponents() {
        fn run<const N: usize>(rng: &mut Rng, top_zero: bool) {
            let mut m = rand_limbs::<N>(rng);
            m[0] |= 1;
            if top_zero {
                m[N - 1] = 0;
                m[N - 2] |= 1 << 63;
            } else {
                m[N - 1] |= 1 << 63;
            }
            let secret = Modulus::<N>::new_secret(m);
            let reference = Mont::new(&m[..bignum::trimmed_len(&m)]);
            let used = reference.limbs();
            if !top_zero {
                let public = Modulus::<N>::new(m);
                assert_eq!(secret.r2, public.r2, "R^2, {N} limbs");
                assert_eq!(secret.r3, public.r3, "R^3, {N} limbs");
                assert_eq!(secret.m0inv, public.m0inv);
            }
            for round in 0..4 {
                // a base below m: its limbs from the second-highest of m up are zero
                let mut base = rand_limbs::<N>(rng);
                for l in base.iter_mut().skip(used - 1) {
                    *l = 0;
                }
                let mut exp = rand_limbs::<N>(rng);
                if round == 1 {
                    exp = [u64::MAX; N];
                }
                let got = secret.from_mont(&secret.pow_secret(&secret.to_mont(&base), &exp));
                // the plain square-and-multiply of the variable-time code, from the top bit
                let mut want = vec![0u64; used];
                want[0] = 1;
                want = reference.to_mont(&want);
                let b = reference.to_mont(&base[..used].to_vec());
                for bit in (0..N * 64).rev() {
                    want = reference.sqr(&want);
                    if (exp[bit / 64] >> (bit % 64)) & 1 == 1 {
                        want = reference.mul(&want, &b);
                    }
                }
                let want = reference.from_mont(&want);
                assert_eq!(&got[..used], &want[..], "{N} limbs");
                assert!(got[used..].iter().all(|&l| l == 0));
            }
        }
        let mut rng = Rng::new(108);
        run::<4>(&mut rng, false);
        run::<16>(&mut rng, false);
        run::<16>(&mut rng, true);
        run::<24>(&mut rng, false);
        run::<32>(&mut rng, false);
    }

    #[test]
    fn byte_conversions_round_trip() {
        let be: Vec<u8> = (1..=32).collect();
        let l = limbs_from_be::<4>(&be);
        assert_eq!(l[3] >> 56, 1);
        assert_eq!(limbs_to_be(&l, 32), be);
        assert_eq!(limbs_to_le(&limbs_from_le::<4>(&be), 32), be);
        assert_eq!(limbs_from_le::<4>(&be)[0] & 0xff, 1);
    }
}
