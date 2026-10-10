//! ECDH over NIST P-256 and P-384 (secp256r1, secp384r1), for the TLS 1.3 key exchange, and \[k\]G for key generation
//! and ECDSA signing.
//!
//! `ecdsa.rs` only ever handles public values and uses variable-time big-number code. A key
//! exchange multiplies a SECRET scalar by a point, so this module is written differently:
//!
//! * field elements are fixed-size limb arrays (`N` limbs, fixed at compile time: 4 for P-256, 6 for P-384), and the
//!   arithmetic (Montgomery multiplication, addition, subtraction) has no branch or memory index that depends on a
//!   value, only on the public size of the field; P-256's prime has a reduction of its own (its low limb is 2^64 - 1,
//!   so the multiple of p to add is the low limb itself, and two of its limbs are 0 and 2^32 - 1), with the same
//!   property;
//! * points are in projective coordinates and use the *complete* formulas of Renes, Costello and Batina ("Complete
//!   addition formulas for prime order elliptic curves", 2016, algorithms 4, 5 and 6, for curves with a = -3, which
//!   both of these are): addition, addition of an affine point and doubling. They have no special cases (doubling, the
//!   point at infinity, adding a point to its negative; the affine point of algorithm 5 is never infinity), so the same
//!   sequence of field operations runs whatever the data;
//! * \[k\]P for the peer's point P (the shared secret): the scalar in fixed 4-bit windows from the top, every window four
//!   doublings and one addition, and the table entry is chosen by scanning all 16 entries with masks (no
//!   secret-dependent address);
//! * \[k\]G for the generator G (a public key, an ECDSA signature's nonce point; B-115): a table of j 256^i G for j from 1
//!   to 8 (made once for the process, from public values, in affine form), the scalar written as signed 4-bit digits
//!   (-8 to 8, one more digit than the scalar has nibbles, for the last carry), and \[k\]G is 16 times the sum of the
//!   odd digits' entries plus the sum of the even digits' entries: about 2 len additions of an affine point and 4
//!   doublings, where \[k\]P takes 8 len doublings and 2 len additions. Each lookup reads all 8 entries of its row with masks, a negative digit negates the
//!   entry by a mask, and a zero digit makes the addition anyway and keeps the sum it had, by a mask (`x25519_base.rs`
//!   does the same on edwards25519);
//! * the final inversion is a fixed-exponent exponentiation (the exponent, p - 2, is public: its windows, and whether
//!   one is zero, are the same for every value);
//! * the masks are passed through `black_box`: without it LLVM rewrote the conditional subtraction as
//!   a branch on the data (the timing test caught it, |t| above 100 before, below 3 after).
//!
//! What it does not do: clear every register and stack copy (the scalar and the running point are
//! overwritten when done, which is best effort, see `zeroize::Zeroize`), or defend against power or
//! fault attacks. The peer's point is validated (uncompressed, coordinates below p, on the
//! curve); both curves have cofactor 1, so that also puts it in the right group.
//!
//! The values are checked against the Python `cryptography` package (OpenSSL), against the
//! variable-time big-number code, and with a statistical timing test (`timing.rs`).

use super::bignum::{self, Mont};
use super::dit::Dit;
use super::ecdsa::Curve;
use super::rand;
use crate::error::Result;
use crate::zeroize::{Zeroize, Zeroizing};
use std::hint::black_box;
use std::sync::OnceLock;

/// A field element: `N` limbs, least significant first.
type Limbs<const N: usize> = [u64; N];

/// A point in projective coordinates, every value in Montgomery form. (0 : 1 : 0) is infinity.
type Point<const N: usize> = [Limbs<N>; 3];

/// A point in affine coordinates (x, y), Montgomery form: an entry of the generator's table (never infinity).
type Affine<const N: usize> = [Limbs<N>; 2];

/// P-256's prime, 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P256_P: [u64; 4] = [u64::MAX, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001];

/// Digits of the largest scalar (P-384: 96 nibbles and the last carry).
const MAX_DIGITS: usize = 97;

/// Arithmetic modulo one prime of `N` limbs, plus the curve's constants.
struct Field<const N: usize> {
    p: Limbs<N>,
    /// -p^-1 mod 2^64
    m0inv: u64,
    /// R^2 mod p
    r2: Limbs<N>,
    /// R mod p: 1 in Montgomery form
    one: Limbs<N>,
    /// The curve constant b, Montgomery form.
    b: Limbs<N>,
    /// The generator, Montgomery form.
    g: Affine<N>,
    /// p - 2, the inversion exponent (public).
    p_minus_2: Limbs<N>,
    /// The group order n.
    order: Limbs<N>,
    /// Bytes in a coordinate or a scalar (32 or 48).
    len: usize,
    /// j 256^i G for i up to `len` and j from 1 to 8 (row i, entry j - 1), made on first use.
    base: OnceLock<Vec<[Affine<N>; 8]>>,
}

fn to_limbs<const N: usize>(v: &[u64]) -> Limbs<N> {
    let mut l = [0u64; N];
    l[..v.len()].copy_from_slice(v);
    l
}

fn build<const N: usize>(p: &str, b: &str, gx: &str, gy: &str, order: &str) -> Field<N> {
    let pv = bignum::from_hex(p);
    let mont = Mont::new(&pv);
    assert_eq!(mont.limbs(), N, "a prime of N limbs");
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(pv[0].wrapping_mul(inv)));
    }
    let one = mont.one();
    let to_m = |h: &str| to_limbs::<N>(&mont.to_mont(&mont.fit(&bignum::from_hex(h))));
    let mut p_minus_2 = pv.clone();
    p_minus_2[0] -= 2; // p ends in ...ff or ...ffff, never below 2
    let f = Field {
        p: to_limbs(&pv),
        m0inv: inv.wrapping_neg(),
        r2: to_limbs(&mont.to_mont(&one)),
        one: to_limbs(&one),
        b: to_m(b),
        g: [to_m(gx), to_m(gy)],
        p_minus_2: to_limbs(&p_minus_2),
        order: to_limbs(&bignum::from_hex(order)),
        len: 8 * N,
        base: OnceLock::new(),
    };
    // the four-limb field is P-256's, whose reduction `mul` specialises
    assert!(N != 4 || (f.p[..] == P256_P[..] && f.m0inv == 1));
    f
}

fn p256() -> &'static Field<4> {
    static F: OnceLock<Field<4>> = OnceLock::new();
    F.get_or_init(|| {
        build(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )
    })
}

fn p384() -> &'static Field<6> {
    static F: OnceLock<Field<6>> = OnceLock::new();
    F.get_or_init(|| {
        build(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        )
    })
}

/// All ones if the low bit of `bit` is set, else zero.
///
/// The `black_box` matters: without it LLVM sees "mask from a 0/1 value, then `(a & mask) | (b & !mask)`"
/// and turns the select back into a branch on the secret-dependent bit (found by the timing test:
/// the generated `reduce_once` had a `jne` on it).
#[inline]
fn mask_of(bit: u64) -> u64 {
    black_box(0u64.wrapping_sub(bit & 1))
}

/// All ones if `a == b`, else zero, without a branch.
#[inline]
fn eq_mask(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    black_box((((x | x.wrapping_neg()) >> 63) & 1).wrapping_sub(1))
}

/// `a` where `mask` is all ones, `b` where it is zero.
#[inline]
fn select<const N: usize>(mask: u64, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
    let mut r = [0u64; N];
    for i in 0..N {
        r[i] = (a[i] & mask) | (b[i] & !mask);
    }
    r
}

impl<const N: usize> Field<N> {
    /// `t` minus p if (carry : t) >= p, else `t`: one conditional subtraction, by mask.
    #[inline]
    fn reduce_once(&self, t: &Limbs<N>, carry: u64) -> Limbs<N> {
        let mut d = [0u64; N];
        let mut borrow = 0u64;
        for i in 0..N {
            let (x, b1) = t[i].overflowing_sub(self.p[i]);
            let (y, b2) = x.overflowing_sub(borrow);
            d[i] = y;
            borrow = (b1 | b2) as u64;
        }
        // (carry : t) >= p exactly when the top carry is set or the subtraction did not borrow
        select(mask_of(carry | (borrow ^ 1)), &d, t)
    }

    #[inline]
    fn add(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
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
    fn sub(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        let mut d = [0u64; N];
        let mut borrow = 0u64;
        for i in 0..N {
            let (x, b1) = a[i].overflowing_sub(b[i]);
            let (y, b2) = x.overflowing_sub(borrow);
            d[i] = y;
            borrow = (b1 | b2) as u64;
        }
        // add p back if it went below zero
        let mask = mask_of(borrow);
        let mut carry = 0u64;
        for i in 0..N {
            let s = d[i] as u128 + (self.p[i] & mask) as u128 + carry as u128;
            d[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        d
    }

    /// Montgomery product a * b / R mod p, with a final conditional subtraction.
    #[inline]
    fn mul(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        if N == 4 {
            self.mul_p256(a, b)
        } else {
            self.mul_cios(a, b)
        }
    }

    /// The Montgomery product by rows (CIOS): each limb of b times a, added, then the multiple of p that clears the
    /// lowest limb, shifted out.
    #[inline(always)]
    fn mul_cios(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        // t holds N + 2 limbs: an array of N + 2 is not expressible with a const generic, so the top two are apart
        let mut t = [0u64; N];
        let mut t_n = 0u64;
        for i in 0..N {
            let bi = b[i] as u128;
            let mut c = 0u128;
            for j in 0..N {
                let s = t[j] as u128 + a[j] as u128 * bi + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = t_n as u128 + c;
            t_n = s as u64;
            let t_n1 = (s >> 64) as u64;

            let q = t[0].wrapping_mul(self.m0inv) as u128;
            let s = t[0] as u128 + q * self.p[0] as u128;
            let mut c = s >> 64;
            for j in 1..N {
                let s = t[j] as u128 + q * self.p[j] as u128 + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = t_n as u128 + c;
            t[N - 1] = s as u64;
            t_n = t_n1 + (s >> 64) as u64;
        }
        self.reduce_once(&t, t_n)
    }

    /// The Montgomery product for P-256's prime (`N` is 4): -p^-1 mod 2^64 is 1, so the multiple of p that clears the
    /// low limb is the low limb q itself, and t + q p, shifted down a limb, is t[1] + q 2^32, t[2], t[3] + q p[3] and the
    /// limb above (p's low limb, 2^64 - 1, turns q into a carry of q; its second limb is 2^32 - 1, its third 0). The
    /// same operations for every value, as in the general product.
    #[inline(always)]
    fn mul_p256(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        let mut t = [0u64; 4];
        let mut tn = 0u64; // the limb above t
        for i in 0..4 {
            let bi = b[i] as u128;
            let mut c = 0u128;
            for j in 0..4 {
                let s = t[j] as u128 + a[j] as u128 * bi + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = tn as u128 + c;
            tn = s as u64;
            let tn1 = (s >> 64) as u64;
            let q = t[0];
            let s = t[1] as u128 + ((q as u128) << 32);
            let t0 = s as u64;
            let s = t[2] as u128 + (s >> 64);
            let t1 = s as u64;
            let s = t[3] as u128 + q as u128 * P256_P[3] as u128 + (s >> 64);
            let t2 = s as u64;
            let s = tn as u128 + (s >> 64);
            t = [t0, t1, t2, s as u64];
            tn = tn1 + (s >> 64) as u64;
        }
        let mut r = [0u64; N];
        r[..4].copy_from_slice(&t);
        self.reduce_once(&r, tn)
    }

    #[inline]
    fn square(&self, a: &Limbs<N>) -> Limbs<N> {
        self.mul(a, a)
    }

    fn to_mont(&self, a: &Limbs<N>) -> Limbs<N> {
        self.mul(a, &self.r2)
    }

    fn from_mont(&self, a: &Limbs<N>) -> Limbs<N> {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// a^(p-2): the inverse of a Montgomery-form value (and 0 for 0), in windows of four bits. The exponent is public,
    /// so the pattern of squarings and products (a window of zeros has none) does not depend on `a`, nor does any
    /// address: the table entry a window reads is its value.
    fn invert(&self, a: &Limbs<N>) -> Limbs<N> {
        let mut table = [self.one; 16];
        table[1] = *a;
        for i in 2..16 {
            table[i] = self.mul(&table[i - 1], a);
        }
        let mut r = self.one;
        for w in (0..16 * N).rev() {
            for _ in 0..4 {
                r = self.square(&r);
            }
            let nibble = ((self.p_minus_2[w / 16] >> (4 * (w % 16))) & 15) as usize;
            if nibble != 0 {
                r = self.mul(&r, &table[nibble]);
            }
        }
        table.zeroize();
        r
    }

    fn is_zero(&self, a: &Limbs<N>) -> bool {
        a.iter().fold(0u64, |acc, &x| acc | x) == 0
    }

    fn infinity(&self) -> Point<N> {
        [[0; N], self.one, [0; N]]
    }

    /// Complete addition (Renes-Costello-Batina 2016, algorithm 4: a = -3). Also doubles.
    fn point_add(&self, p: &Point<N>, q: &Point<N>) -> Point<N> {
        let (x1, y1, z1) = (&p[0], &p[1], &p[2]);
        let (x2, y2, z2) = (&q[0], &q[1], &q[2]);
        let t0 = self.mul(x1, x2);
        let t1 = self.mul(y1, y2);
        let t2 = self.mul(z1, z2);
        let t3 = self.add(x1, y1);
        let t4 = self.add(x2, y2);
        let t3 = self.mul(&t3, &t4);
        let t4 = self.add(&t0, &t1);
        let t3 = self.sub(&t3, &t4);
        let t4 = self.add(y1, z1);
        let x3 = self.add(y2, z2);
        let t4 = self.mul(&t4, &x3);
        let x3 = self.add(&t1, &t2);
        let t4 = self.sub(&t4, &x3);
        let x3 = self.add(x1, z1);
        let y3 = self.add(x2, z2);
        let x3 = self.mul(&x3, &y3);
        let y3 = self.add(&t0, &t2);
        let y3 = self.sub(&x3, &y3);
        self.add_tail(t0, t1, t2, t3, t4, y3)
    }

    /// Complete addition of an affine point (algorithm 5: algorithm 4 with Z2 = 1, three products fewer). `q` is never
    /// infinity, which affine coordinates cannot hold; `p` may be.
    fn point_add_affine(&self, p: &Point<N>, q: &Affine<N>) -> Point<N> {
        let (x1, y1, z1) = (&p[0], &p[1], &p[2]);
        let (x2, y2) = (&q[0], &q[1]);
        let t0 = self.mul(x1, x2);
        let t1 = self.mul(y1, y2);
        let t3 = self.add(x2, y2);
        let t4 = self.add(x1, y1);
        let t3 = self.mul(&t3, &t4);
        let t4 = self.add(&t0, &t1);
        let t3 = self.sub(&t3, &t4);
        // (Y1 + Z1)(Y2 + 1) - (Y1 Y2 + Z1) = Y2 Z1 + Y1, and so for X
        let t4 = self.mul(y2, z1);
        let t4 = self.add(&t4, y1);
        let y3 = self.mul(x2, z1);
        let y3 = self.add(&y3, x1);
        self.add_tail(t0, t1, *z1, t3, t4, y3)
    }

    /// The part algorithms 4 and 5 share, from t0 = X1 X2, t1 = Y1 Y2, t2 = Z1 Z2, t3 = X1 Y2 + X2 Y1,
    /// t4 = Y1 Z2 + Y2 Z1 and y3 = X1 Z2 + X2 Z1.
    #[inline(always)]
    fn add_tail(&self, t0: Limbs<N>, t1: Limbs<N>, t2: Limbs<N>, t3: Limbs<N>, t4: Limbs<N>, y3: Limbs<N>) -> Point<N> {
        let b = &self.b;
        let z3 = self.mul(b, &t2);
        let x3 = self.sub(&y3, &z3);
        let z3 = self.add(&x3, &x3);
        let x3 = self.add(&x3, &z3);
        let z3 = self.sub(&t1, &x3);
        let x3 = self.add(&t1, &x3);
        let y3 = self.mul(b, &y3);
        let t1 = self.add(&t2, &t2);
        let t2 = self.add(&t1, &t2);
        let y3 = self.sub(&y3, &t2);
        let y3 = self.sub(&y3, &t0);
        let t1 = self.add(&y3, &y3);
        let y3 = self.add(&t1, &y3);
        let t1 = self.add(&t0, &t0);
        let t0 = self.add(&t1, &t0);
        let t0 = self.sub(&t0, &t2);
        let t1 = self.mul(&t4, &y3);
        let t2 = self.mul(&t0, &y3);
        let y3 = self.mul(&x3, &z3);
        let y3 = self.add(&y3, &t2);
        let x3 = self.mul(&t3, &x3);
        let x3 = self.sub(&x3, &t1);
        let z3 = self.mul(&t4, &z3);
        let t1 = self.mul(&t3, &t0);
        let z3 = self.add(&z3, &t1);
        [x3, y3, z3]
    }

    /// Complete doubling (algorithm 6: a = -3), step for step as the paper lists it.
    fn point_double(&self, p: &Point<N>) -> Point<N> {
        let (x, y, z) = (&p[0], &p[1], &p[2]);
        let b = &self.b;
        let t0 = self.square(x); // 1
        let t1 = self.square(y); // 2
        let t2 = self.square(z); // 3
        let t3 = self.mul(x, y); // 4
        let t3 = self.add(&t3, &t3); // 5
        let z3 = self.mul(x, z); // 6
        let z3 = self.add(&z3, &z3); // 7
        let y3 = self.mul(b, &t2); // 8
        let y3 = self.sub(&y3, &z3); // 9
        let x3 = self.add(&y3, &y3); // 10
        let y3 = self.add(&x3, &y3); // 11
        let x3 = self.sub(&t1, &y3); // 12
        let y3 = self.add(&t1, &y3); // 13
        let y3 = self.mul(&x3, &y3); // 14
        let x3 = self.mul(&x3, &t3); // 15
        let t3 = self.add(&t2, &t2); // 16
        let t2 = self.add(&t2, &t3); // 17
        let z3 = self.mul(b, &z3); // 18
        let z3 = self.sub(&z3, &t2); // 19
        let z3 = self.sub(&z3, &t0); // 20
        let t3 = self.add(&z3, &z3); // 21
        let z3 = self.add(&z3, &t3); // 22
        let t3 = self.add(&t0, &t0); // 23
        let t0 = self.add(&t3, &t0); // 24
        let t0 = self.sub(&t0, &t2); // 25
        let t0 = self.mul(&t0, &z3); // 26
        let y3 = self.add(&y3, &t0); // 27
        let t0 = self.mul(y, z); // 28
        let t0 = self.add(&t0, &t0); // 29
        let z3 = self.mul(&t0, &z3); // 30
        let x3 = self.sub(&x3, &z3); // 31
        let z3 = self.mul(&t0, &t1); // 32
        let z3 = self.add(&z3, &z3); // 33
        let z3 = self.add(&z3, &z3); // 34
        [x3, y3, z3]
    }

    /// k * p for a big-endian scalar `k` of exactly `self.len` bytes, in constant time.
    fn scalar_mul(&self, k: &[u8], p: &Point<N>) -> Point<N> {
        debug_assert_eq!(k.len(), self.len);
        // table[i] = i * p
        let mut table = [self.infinity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = if i % 2 == 0 { self.point_double(&table[i / 2]) } else { self.point_add(&table[i - 1], p) };
        }
        let mut r = self.infinity();
        for &byte in k {
            for nibble in [byte >> 4, byte & 15] {
                for _ in 0..4 {
                    r = self.point_double(&r);
                }
                let want = black_box(nibble) as u64;
                let mut sel = [[0u64; N]; 3];
                for (i, entry) in table.iter().enumerate() {
                    let mask = eq_mask(i as u64, want);
                    for c in 0..3 {
                        for l in 0..N {
                            sel[c][l] |= entry[c][l] & mask;
                        }
                    }
                }
                r = self.point_add(&r, &sel);
                sel.zeroize();
            }
        }
        table.zeroize();
        r
    }

    /// The generator's table: j 256^i G for i from 0 to `len` and j from 1 to 8, affine. Made once for the process from
    /// public values: the points by additions and doublings, then one inversion for all their Z coordinates
    /// (Montgomery's trick: the products of the first k, the inverse of the product of all, each inverse from those by
    /// two products). No entry is infinity: j 256^i is never a multiple of the prime order n.
    fn base_table(&self) -> &[[Affine<N>; 8]] {
        self.base.get_or_init(|| {
            let rows = self.len + 1;
            let mut points: Vec<Point<N>> = Vec::with_capacity(8 * rows);
            let mut row: Point<N> = [self.g[0], self.g[1], self.one]; // 256^i G
            for _ in 0..rows {
                let mut q = row;
                for _ in 0..8 {
                    points.push(q);
                    q = self.point_add(&q, &row);
                }
                for _ in 0..8 {
                    row = self.point_double(&row);
                }
            }
            let mut before = Vec::with_capacity(points.len());
            let mut all = self.one;
            for p in &points {
                before.push(all);
                all = self.mul(&all, &p[2]);
            }
            let mut inv = self.invert(&all);
            let mut table = vec![[[[0u64; N]; 2]; 8]; rows];
            for k in (0..points.len()).rev() {
                let zinv = self.mul(&inv, &before[k]);
                table[k / 8][k % 8] = [self.mul(&points[k][0], &zinv), self.mul(&points[k][1], &zinv)];
                inv = self.mul(&inv, &points[k][2]);
            }
            table
        })
    }

    /// `h` plus `digit` (-8 to 8) times the row's point: every entry of the row is read, the one for |digit| kept by
    /// masks, its y negated by a mask for a negative digit, the sum made in every case and kept only for a digit that
    /// is not zero.
    #[inline]
    fn add_digit(&self, h: &Point<N>, row: &[Affine<N>; 8], digit: i8) -> Point<N> {
        let negative = ((digit as u8) >> 7) as u64;
        let sign = digit >> 7; // -1 or 0
        let size = ((digit ^ sign) - sign) as u64; // |digit|, 0 to 8
        let mut t: Affine<N> = [[0u64; N]; 2];
        for (j, entry) in row.iter().enumerate() {
            let hit = eq_mask(size, j as u64 + 1);
            for c in 0..2 {
                for l in 0..N {
                    t[c][l] |= entry[c][l] & hit;
                }
            }
        }
        let minus_y = self.sub(&[0u64; N], &t[1]);
        t[1] = select(mask_of(negative), &minus_y, &t[1]);
        let mut sum = self.point_add_affine(h, &t);
        let keep = !eq_mask(size, 0);
        let r = [select(keep, &sum[0], &h[0]), select(keep, &sum[1], &h[1]), select(keep, &sum[2], &h[2])];
        t.zeroize();
        sum.zeroize();
        r
    }

    /// k G for a big-endian scalar `k` of exactly `self.len` bytes, in constant time, by the generator's table.
    fn mul_base(&self, k: &[u8]) -> Point<N> {
        let len = self.len;
        debug_assert_eq!(k.len(), len);
        // 2 len nibbles, the lowest first, then signed: a digit of 8 or more becomes digit - 16 and carries 1; the last
        // carry is a digit of its own (0 or 1)
        let mut e = [0i8; MAX_DIGITS];
        for i in 0..len {
            let byte = k[len - 1 - i];
            e[2 * i] = (byte & 15) as i8;
            e[2 * i + 1] = (byte >> 4) as i8;
        }
        let mut carry = 0i8;
        for d in e.iter_mut().take(2 * len) {
            *d += carry;
            carry = (*d + 8) >> 4;
            *d -= carry << 4;
        }
        e[2 * len] = carry;
        let table = self.base_table();
        // 16 (the odd digits' entries) + (the even digits' entries): digit i is worth 16^i = 16^(i mod 2) 256^(i / 2)
        let mut h = self.infinity();
        for i in (1..2 * len).step_by(2) {
            h = self.add_digit(&h, &table[i / 2], e[i]);
        }
        for _ in 0..4 {
            h = self.point_double(&h);
        }
        for i in (0..=2 * len).step_by(2) {
            h = self.add_digit(&h, &table[i / 2], e[i]);
        }
        e.zeroize();
        h
    }

    /// Big-endian bytes (exactly `self.len`) to limbs; `None` if the value is not below `limit`.
    /// Variable time: used on public values (peer coordinates) and on the scalar's range check.
    fn parse_below(&self, bytes: &[u8], limit: &Limbs<N>) -> Option<Limbs<N>> {
        if bytes.len() != self.len {
            return None;
        }
        let l = to_limbs::<N>(&bignum::from_be_bytes(bytes));
        for i in (0..N).rev() {
            if l[i] != limit[i] {
                return if l[i] < limit[i] { Some(l) } else { None };
            }
        }
        None
    }

    fn to_bytes(&self, a: &Limbs<N>) -> Vec<u8> {
        bignum::to_be_bytes(a, self.len)
    }

    /// (x, y) as big-endian bytes of the affine point, or `None` for the point at infinity.
    fn affine(&self, p: &Point<N>) -> Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
        if self.is_zero(&p[2]) {
            return None;
        }
        let zinv = self.invert(&p[2]);
        let x = self.from_mont(&self.mul(&p[0], &zinv));
        let y = self.from_mont(&self.mul(&p[1], &zinv));
        Some((Zeroizing::new(self.to_bytes(&x)), Zeroizing::new(self.to_bytes(&y))))
    }

    /// y^2 = x^3 - 3x + b, for Montgomery-form coordinates.
    fn on_curve(&self, x: &Limbs<N>, y: &Limbs<N>) -> bool {
        let y2 = self.square(y);
        let x2 = self.square(x);
        let x3 = self.mul(&x2, x);
        let three_x = self.add(&self.add(x, x), x);
        let rhs = self.add(&self.sub(&x3, &three_x), &self.b);
        y2 == rhs
    }

    /// Is `k` (big-endian, `len` bytes) a valid private scalar, 1 <= k < n?
    fn scalar_in_range(&self, k: &[u8]) -> bool {
        match self.parse_below(k, &self.order) {
            Some(l) => !self.is_zero(&l),
            None => false,
        }
    }

    fn public_key(&self, scalar: &[u8]) -> Option<Vec<u8>> {
        if !self.scalar_in_range(scalar) {
            return None;
        }
        let mut r = self.mul_base(scalar);
        let affine = self.affine(&r);
        r.zeroize();
        let (x, y) = affine?;
        let mut out = Vec::with_capacity(1 + 2 * self.len);
        out.push(4);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        Some(out)
    }

    fn shared_secret(&self, scalar: &[u8], peer_public: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if !self.scalar_in_range(scalar) {
            return None;
        }
        if peer_public.len() != 1 + 2 * self.len || peer_public[0] != 4 {
            return None;
        }
        let x = self.to_mont(&self.parse_below(&peer_public[1..1 + self.len], &self.p)?);
        let y = self.to_mont(&self.parse_below(&peer_public[1 + self.len..], &self.p)?);
        if !self.on_curve(&x, &y) {
            return None;
        }
        let mut r = self.scalar_mul(scalar, &[x, y, self.one]);
        let out = self.affine(&r).map(|(x, _)| x);
        r.zeroize();
        out
    }
}

/// The uncompressed SEC1 encoding (0x04 || x || y) of the generator times `scalar`, or `None` if
/// `scalar` is not in 1..n or has the wrong length.
pub fn public_key(curve: Curve, scalar: &[u8]) -> Option<Vec<u8>> {
    let _dit = Dit::on(); // data-independent timing while the secret is in use (crypto::dit)
    match curve {
        Curve::P256 => p256().public_key(scalar),
        Curve::P384 => p384().public_key(scalar),
        Curve::P521 => None,
    }
}

/// Bytes in a scalar of the curve; `None` for P-521, which the ECDSA code verifies with but the key exchange does not offer.
fn scalar_len(curve: Curve) -> Option<usize> {
    match curve {
        Curve::P256 => Some(32),
        Curve::P384 => Some(48),
        Curve::P521 => None,
    }
}

/// A fresh private scalar (uniform in 1..n, by rejection sampling) and its public key.
pub fn generate(curve: Curve) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let Some(len) = scalar_len(curve) else {
        return Err(crate::error::Error::Tls(format!("{curve:?} is not a curve of the key exchange")));
    };
    loop {
        let mut k = Zeroizing::new(vec![0u8; len]);
        rand::fill(&mut k)?;
        // A rejected candidate is discarded, so how often this repeats reveals nothing about the key.
        if let Some(public) = public_key(curve, &k) {
            return Ok((k, public));
        }
    }
}

/// The ECDH shared secret: the x coordinate of `scalar` times the peer's point, as `len` bytes.
/// `None` if the scalar is out of range or the peer's point is not a valid uncompressed point of
/// the curve (wrong length or prefix, a coordinate not below p, or not on the curve).
pub fn shared_secret(curve: Curve, scalar: &[u8], peer_public: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let _dit = Dit::on(); // data-independent timing while the secret is in use (crypto::dit)
    match curve {
        Curve::P256 => p256().shared_secret(scalar, peer_public),
        Curve::P384 => p384().shared_secret(scalar, peer_public),
        Curve::P521 => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::ecdh_vectors::{PUBLIC, SHARED};
    use super::*;
    use crate::fuzz::Rng;
    use crate::util::unhex;

    fn curve_of(name: &str) -> Curve {
        match name {
            "p256" => Curve::P256,
            "p384" => Curve::P384,
            _ => panic!("curve {name}"),
        }
    }

    /// Runs `check` on both fields.
    macro_rules! both {
        ($check:ident) => {
            $check(p256());
            $check(p384());
        };
    }

    /// The affine coordinates of a point, Montgomery form (None for infinity): for comparing projective points.
    fn norm<const N: usize>(f: &Field<N>, p: &Point<N>) -> Option<Affine<N>> {
        if f.is_zero(&p[2]) {
            return None;
        }
        let zinv = f.invert(&p[2]);
        Some([f.mul(&p[0], &zinv), f.mul(&p[1], &zinv)])
    }

    fn g<const N: usize>(f: &Field<N>) -> Point<N> {
        [f.g[0], f.g[1], f.one]
    }

    /// A scalar of `len` bytes from a random number (below n by clearing the top bit, which both orders have set).
    fn random_scalar<const N: usize>(f: &Field<N>, rng: &mut Rng) -> Vec<u8> {
        let mut k = rng.bytes(f.len);
        k[0] &= 0x7f;
        k
    }

    #[test]
    fn the_field_matches_the_variable_time_bignum_code() {
        fn check<const N: usize>(f: &Field<N>) {
            let mut rng = Rng::new(77);
            let reference = Mont::new(&f.p);
            for _ in 0..300 {
                let mut a = [0u64; N];
                let mut b = [0u64; N];
                for i in 0..N {
                    a[i] = rng.next_u64();
                    b[i] = rng.next_u64();
                }
                // reduce into range by clearing the top bits until below p
                while bignum::cmp(&a, &f.p) != std::cmp::Ordering::Less {
                    a[N - 1] >>= 1;
                }
                while bignum::cmp(&b, &f.p) != std::cmp::Ordering::Less {
                    b[N - 1] >>= 1;
                }
                assert_eq!(&f.mul(&a, &b)[..], &reference.mul(&a, &b)[..], "mul");
                assert_eq!(&f.mul_cios(&a, &b)[..], &reference.mul(&a, &b)[..], "mul by rows");
                assert_eq!(&f.add(&a, &b)[..], &reference.add(&a, &b)[..], "add");
                assert_eq!(&f.sub(&a, &b)[..], &reference.sub(&a, &b)[..], "sub");
                // the inverse, in the Montgomery domain: a * a^-1 = 1
                if !f.is_zero(&a) {
                    let inv = f.invert(&a);
                    assert_eq!(f.mul(&a, &inv), f.one, "inverse");
                }
            }
            // edges: 0, 1, p - 1 on both sides
            let zero = [0u64; N];
            let mut pm1 = f.p;
            pm1[0] -= 1;
            for (a, b) in [(zero, zero), (f.one, pm1), (pm1, pm1), (pm1, zero)] {
                assert_eq!(&f.mul(&a, &b)[..], &reference.mul(&a, &b)[..]);
                assert_eq!(&f.add(&a, &b)[..], &reference.add(&a, &b)[..]);
                assert_eq!(&f.sub(&a, &b)[..], &reference.sub(&a, &b)[..]);
            }
            assert!(f.is_zero(&f.invert(&zero)));
        }
        both!(check);
    }

    #[test]
    fn generators_are_on_the_curve_and_infinity_behaves() {
        fn check<const N: usize>(f: &Field<N>) {
            assert!(f.on_curve(&f.g[0], &f.g[1]));
            let g = g(f);
            let inf = f.infinity();
            // O + G = G, G + O = G, O + O = O (as projective points: compare after normalizing)
            for (p, q) in [(&inf, &g), (&g, &inf)] {
                let (x, y) = f.affine(&f.point_add(p, q)).unwrap();
                assert_eq!((&x[..], &y[..]), (&f.to_bytes(&f.from_mont(&f.g[0]))[..], &f.to_bytes(&f.from_mont(&f.g[1]))[..]));
            }
            assert!(f.affine(&f.point_add(&inf, &inf)).is_none());
            assert!(f.affine(&f.point_double(&inf)).is_none());
            // G + (-G) = O, by both additions
            let neg_g: Point<N> = [f.g[0], f.sub(&[0; N], &f.g[1]), f.one];
            assert!(f.affine(&f.point_add(&g, &neg_g)).is_none());
            assert!(f.affine(&f.point_add_affine(&g, &[neg_g[0], neg_g[1]])).is_none());
            // 2G computed as G + G stays on the curve
            let (x, y) = f.affine(&f.point_add(&g, &g)).unwrap();
            let (xm, ym) = (f.to_mont(&to_limbs(&bignum::from_be_bytes(&x))), f.to_mont(&to_limbs(&bignum::from_be_bytes(&y))));
            assert!(f.on_curve(&xm, &ym));
            // n * G = infinity, (n - 1) * G = -G, by both multiplications
            let mut n_bytes = f.to_bytes(&f.order);
            assert!(f.affine(&f.scalar_mul(&n_bytes, &g)).is_none());
            assert!(f.affine(&f.mul_base(&n_bytes)).is_none());
            *n_bytes.last_mut().unwrap() -= 1; // both orders end in an odd byte, so no borrow
            let neg_y = f.to_bytes(&f.from_mont(&f.sub(&[0; N], &f.g[1])));
            for r in [f.scalar_mul(&n_bytes, &g), f.mul_base(&n_bytes)] {
                let (x, y) = f.affine(&r).unwrap();
                assert_eq!(&x[..], &f.to_bytes(&f.from_mont(&f.g[0]))[..]);
                assert_eq!(&y[..], &neg_y[..]);
            }
        }
        both!(check);
    }

    /// The addition of an affine point and the doubling (algorithms 5 and 6) give what the general addition gives, on
    /// random points, on equal and opposite points, and with infinity.
    #[test]
    fn the_three_formulas_agree() {
        fn check<const N: usize>(f: &Field<N>) {
            let mut rng = Rng::new(0x5ca1a);
            let gp = g(f);
            let mut points = vec![f.infinity(), gp, f.point_add(&gp, &gp)];
            for _ in 0..20 {
                points.push(f.scalar_mul(&random_scalar(f, &mut rng), &gp));
            }
            for (i, p) in points.iter().enumerate() {
                assert_eq!(norm(f, &f.point_double(p)), norm(f, &f.point_add(p, p)), "doubling, point {i}");
                for (j, q) in points.iter().enumerate() {
                    let Some(qa) = norm(f, q) else { continue };
                    let want = norm(f, &f.point_add(p, q));
                    assert_eq!(norm(f, &f.point_add_affine(p, &qa)), want, "affine addition, points {i} and {j}");
                    // with p scaled (another Z for the same point)
                    let s = f.to_mont(&[7; N]);
                    let scaled = [f.mul(&p[0], &s), f.mul(&p[1], &s), f.mul(&p[2], &s)];
                    assert_eq!(norm(f, &f.point_add_affine(&scaled, &qa)), want);
                    // p + q where q is p and where q is -p
                    let minus = [qa[0], f.sub(&[0; N], &qa[1])];
                    assert_eq!(norm(f, &f.point_add_affine(q, &qa)), norm(f, &f.point_double(q)));
                    assert_eq!(norm(f, &f.point_add_affine(q, &minus)), None);
                }
            }
        }
        both!(check);
    }

    /// The table holds what it says: entry (i, j) is (j + 1) 256^i G, made here by the variable-base multiplication.
    #[test]
    fn the_generators_table_holds_its_multiples() {
        fn check<const N: usize>(f: &Field<N>) {
            let table = f.base_table();
            assert_eq!(table.len(), f.len + 1);
            for i in [0, 1, 2, f.len / 2, f.len - 1] {
                for j in 0..8 {
                    // (j + 1) 256^i as a big-endian scalar of len bytes
                    let mut k = vec![0u8; f.len];
                    k[f.len - 1 - i] = j as u8 + 1;
                    let want = norm(f, &f.scalar_mul(&k, &g(f))).unwrap();
                    assert_eq!(table[i][j], want, "row {i}, entry {j}");
                }
            }
            // the last row is 2^(8 len) G, beyond the scalar's bytes: 2^(8 len) mod n, by doublings
            let mut p = g(f);
            for _ in 0..8 * f.len {
                p = f.point_double(&p);
            }
            assert_eq!(table[f.len][0], norm(f, &p).unwrap());
        }
        both!(check);
    }

    /// k G by the table is k G by the variable-base multiplication, for random scalars and for those whose digits are
    /// all at an edge: all 8 (each a -8 and a carry), all 7, all 15 (each -1 and a carry), all 0 but one, and the
    /// largest (whose last carry makes the extra digit 1).
    #[test]
    fn the_generators_table_gives_what_the_ladder_gives() {
        fn check<const N: usize>(f: &Field<N>) {
            let mut rng = Rng::new(0xba5e);
            let mut scalars: Vec<Vec<u8>> = (0..40).map(|_| random_scalar(f, &mut rng)).collect();
            for fill in [0x88u8, 0x77, 0x11, 0x80, 0x08] {
                scalars.push(vec![fill; f.len]);
            }
            let mut ffs = vec![0xffu8; f.len];
            ffs[0] = 0x7f;
            scalars.push(ffs);
            let mut n_minus_1 = f.to_bytes(&f.order);
            *n_minus_1.last_mut().unwrap() -= 1;
            scalars.push(n_minus_1.clone());
            let mut n_minus_2 = n_minus_1.clone();
            *n_minus_2.last_mut().unwrap() -= 1;
            scalars.push(n_minus_2);
            for pos in [0, 1, f.len / 2, f.len - 1] {
                for v in [1u8, 8, 0x80, 0xf8] {
                    let mut k = vec![0u8; f.len];
                    k[pos] = v;
                    scalars.push(k);
                }
            }
            for k in &scalars {
                assert_eq!(norm(f, &f.mul_base(k)), norm(f, &f.scalar_mul(k, &g(f))), "k = {}", crate::util::hex(k));
            }
            assert!(norm(f, &f.mul_base(&vec![0u8; f.len])).is_none(), "0 G");
        }
        both!(check);
    }

    #[test]
    fn public_keys_match_openssl() {
        assert!(PUBLIC.len() >= 20);
        for (name, scalar, public) in PUBLIC {
            let got = public_key(curve_of(name), &unhex(scalar)).expect("scalar in range");
            assert_eq!(got, unhex(public), "{name} public key of {scalar}");
        }
    }

    #[test]
    fn shared_secrets_match_openssl() {
        assert!(SHARED.len() >= 20);
        for (name, scalar, peer, secret) in SHARED {
            let got = shared_secret(curve_of(name), &unhex(scalar), &unhex(peer)).expect("valid inputs");
            assert_eq!(&got[..], &unhex(secret)[..], "{name} secret for scalar {scalar}");
        }
    }

    #[test]
    fn both_sides_agree_for_fresh_keys() {
        for (curve, len) in [(Curve::P256, 32), (Curve::P384, 48)] {
            for _ in 0..6 {
                let (a, pa) = generate(curve).unwrap();
                let (b, pb) = generate(curve).unwrap();
                assert_eq!(pa.len(), 1 + 2 * len);
                let s1 = shared_secret(curve, &a, &pb).unwrap();
                let s2 = shared_secret(curve, &b, &pa).unwrap();
                assert_eq!(&s1[..], &s2[..]);
                assert_eq!(s1.len(), len);
            }
        }
    }

    #[test]
    fn out_of_range_scalars_are_refused() {
        fn check<const N: usize>(f: &Field<N>) {
            let mut one = vec![0u8; f.len];
            *one.last_mut().unwrap() = 1;
            let g = f.public_key(&one).unwrap();
            let zero = vec![0u8; f.len];
            let n = f.to_bytes(&f.order);
            let mut n_plus_1 = n.clone();
            *n_plus_1.last_mut().unwrap() += 1;
            for bad in [&zero[..], &n[..], &n_plus_1[..], &vec![0xffu8; f.len][..], &vec![1u8; f.len - 1][..], &vec![1u8; f.len + 1][..]] {
                assert!(f.public_key(bad).is_none());
                assert!(f.shared_secret(bad, &g).is_none());
            }
        }
        both!(check);
        assert!(public_key(Curve::P521, &[1; 66]).is_none());
        assert!(generate(Curve::P521).is_err());
    }

    #[test]
    fn invalid_peer_points_are_refused() {
        fn check<const N: usize>(f: &Field<N>, curve: Curve) {
            let (k, _) = generate(curve).unwrap();
            let mut one = vec![0u8; f.len];
            *one.last_mut().unwrap() = 1;
            let good = f.public_key(&one).unwrap(); // the generator
            assert!(shared_secret(curve, &k, &good).is_some());
            let with = |edit: &dyn Fn(&mut Vec<u8>)| {
                let mut p = good.clone();
                edit(&mut p);
                shared_secret(curve, &k, &p)
            };
            // wrong prefix: compressed (2, 3), hybrid (6, 7), zero, other
            for prefix in [0u8, 2, 3, 5, 6, 7, 0xff] {
                assert!(with(&|p| p[0] = prefix).is_none(), "prefix {prefix}");
            }
            // truncated, extended, empty, only the prefix
            assert!(with(&|p| {
                p.pop();
            })
            .is_none());
            assert!(with(&|p| p.push(0)).is_none());
            assert!(with(&|p| p.clear()).is_none());
            assert!(with(&|p| p.truncate(1)).is_none());
            // y off by one: not on the curve
            assert!(with(&|p| *p.last_mut().unwrap() ^= 1).is_none());
            // x off by one
            let last_x = f.len;
            assert!(with(&|p| p[last_x] ^= 1).is_none());
            // the point (0, 0) is not on either curve
            assert!(with(&|p| p[1..].fill(0)).is_none());
            // coordinates equal to p, and above it, even if they would be on the curve mod p
            let pb = f.to_bytes(&f.p);
            assert!(with(&|p| p[1..1 + f.len].copy_from_slice(&pb)).is_none());
            assert!(with(&|p| p[1 + f.len..].copy_from_slice(&pb)).is_none());
            assert!(with(&|p| p[1..1 + f.len].fill(0xff)).is_none());
        }
        check(p256(), Curve::P256);
        check(p384(), Curve::P384);
    }
}
