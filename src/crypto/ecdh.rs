//! ECDH over NIST P-256 and P-384 (secp256r1, secp384r1), for the TLS 1.3 key exchange.
//!
//! `ecdsa.rs` only ever handles public values and uses variable-time big-number code. A key
//! exchange multiplies a SECRET scalar by a point, so this module is written differently:
//!
//! * field elements are fixed-size limb arrays, and the arithmetic (Montgomery multiplication,
//!   addition, subtraction) has no branch or memory index that depends on a value, only on the
//!   public size of the field;
//! * points are in projective coordinates and use the *complete* addition formulas of Renes,
//!   Costello and Batina ("Complete addition formulas for prime order elliptic curves", 2016,
//!   algorithm 4, for curves with a = -3, which both of these are). They have no special cases
//!   (doubling, the point at infinity, adding a point to its negative), so the same sequence of
//!   field operations runs whatever the data; doubling is just an addition of a point to itself;
//! * the scalar is processed in fixed 4-bit windows from the top, every window is four doublings
//!   and one addition, and the table entry is chosen by scanning all 16 entries with masks (no
//!   secret-dependent address);
//! * the final inversion is a fixed-exponent exponentiation (the exponent, p - 2, is public);
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

use super::dit::Dit;
use super::bignum::{self, Mont};
use super::ecdsa::Curve;
use super::rand;
use crate::error::Result;
use crate::zeroize::{Zeroize, Zeroizing};
use std::hint::black_box;
use std::sync::OnceLock;

/// Limbs of the larger field (P-384). Smaller fields leave the upper limbs zero.
const L: usize = 6;
type Limbs = [u64; L];

/// A point in projective coordinates, every value in Montgomery form. (0 : 1 : 0) is infinity.
type Point = [Limbs; 3];

/// Arithmetic modulo one prime, plus the curve's constants.
struct Field {
    /// Limbs in use (4 or 6).
    n: usize,
    p: Limbs,
    /// -p^-1 mod 2^64
    m0inv: u64,
    /// R^2 mod p
    r2: Limbs,
    /// R mod p: 1 in Montgomery form
    one: Limbs,
    /// The curve constant b, Montgomery form.
    b: Limbs,
    /// The generator, Montgomery form.
    g: [Limbs; 2],
    /// p - 2, the inversion exponent (public).
    p_minus_2: Limbs,
    /// The group order n.
    order: Limbs,
    /// Bytes in a coordinate or a scalar (32 or 48).
    len: usize,
}

fn to_limbs(v: &[u64]) -> Limbs {
    let mut l = [0u64; L];
    l[..v.len()].copy_from_slice(v);
    l
}

fn build(p: &str, b: &str, gx: &str, gy: &str, order: &str, len: usize) -> Field {
    let pv = bignum::from_hex(p);
    let mont = Mont::new(&pv);
    let n = mont.limbs();
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(pv[0].wrapping_mul(inv)));
    }
    let one = mont.one();
    let to_m = |h: &str| to_limbs(&mont.to_mont(&mont.fit(&bignum::from_hex(h))));
    let mut p_minus_2 = pv.clone();
    p_minus_2[0] -= 2; // p ends in ...ff or ...ffff, never below 2
    Field {
        n,
        p: to_limbs(&pv),
        m0inv: inv.wrapping_neg(),
        r2: to_limbs(&mont.to_mont(&one)),
        one: to_limbs(&one),
        b: to_m(b),
        g: [to_m(gx), to_m(gy)],
        p_minus_2: to_limbs(&p_minus_2),
        order: to_limbs(&bignum::from_hex(order)),
        len,
    }
}

/// The curve's arithmetic; `None` for P-521, which the ECDSA code verifies with but the key exchange does not offer.
fn try_field(curve: Curve) -> Option<&'static Field> {
    static P256: OnceLock<Field> = OnceLock::new();
    static P384: OnceLock<Field> = OnceLock::new();
    Some(match curve {
        Curve::P256 => P256.get_or_init(|| {
            build(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                32,
            )
        }),
        Curve::P384 => P384.get_or_init(|| {
            build(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                48,
            )
        }),
        Curve::P521 => return None,
    })
}

#[cfg(test)]
fn field(curve: Curve) -> &'static Field {
    try_field(curve).expect("a curve of the key exchange")
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

impl Field {
    /// `t` minus p if (carry : t) >= p, else `t`: one conditional subtraction, by mask.
    #[inline]
    fn reduce_once(&self, t: &Limbs, carry: u64) -> Limbs {
        let mut d = [0u64; L];
        let mut borrow = 0u64;
        for i in 0..self.n {
            let (x, b1) = t[i].overflowing_sub(self.p[i]);
            let (y, b2) = x.overflowing_sub(borrow);
            d[i] = y;
            borrow = (b1 | b2) as u64;
        }
        // (carry : t) >= p exactly when the top carry is set or the subtraction did not borrow
        let mask = mask_of(carry | (borrow ^ 1));
        let mut r = [0u64; L];
        for i in 0..self.n {
            r[i] = (d[i] & mask) | (t[i] & !mask);
        }
        r
    }

    fn add(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut t = [0u64; L];
        let mut carry = 0u64;
        for i in 0..self.n {
            let s = a[i] as u128 + b[i] as u128 + carry as u128;
            t[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        self.reduce_once(&t, carry)
    }

    fn sub(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut d = [0u64; L];
        let mut borrow = 0u64;
        for i in 0..self.n {
            let (x, b1) = a[i].overflowing_sub(b[i]);
            let (y, b2) = x.overflowing_sub(borrow);
            d[i] = y;
            borrow = (b1 | b2) as u64;
        }
        // add p back if it went below zero
        let mask = mask_of(borrow);
        let mut carry = 0u64;
        for i in 0..self.n {
            let s = d[i] as u128 + (self.p[i] & mask) as u128 + carry as u128;
            d[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        d
    }

    /// Montgomery product a * b / R mod p (CIOS), with a final conditional subtraction.
    fn mul(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let n = self.n;
        let mut t = [0u64; L + 2];
        for i in 0..n {
            let mut c = 0u64;
            for j in 0..n {
                let s = t[j] as u128 + (a[j] as u128) * (b[i] as u128) + c as u128;
                t[j] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[n] as u128 + c as u128;
            t[n] = s as u64;
            t[n + 1] = (s >> 64) as u64;

            let m = t[0].wrapping_mul(self.m0inv);
            let s = t[0] as u128 + (m as u128) * (self.p[0] as u128);
            let mut c = (s >> 64) as u64;
            for j in 1..n {
                let s = t[j] as u128 + (m as u128) * (self.p[j] as u128) + c as u128;
                t[j - 1] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[n] as u128 + c as u128;
            t[n - 1] = s as u64;
            t[n] = t[n + 1] + (s >> 64) as u64;
            t[n + 1] = 0;
        }
        let mut r = [0u64; L];
        r[..n].copy_from_slice(&t[..n]);
        self.reduce_once(&r, t[n])
    }

    fn square(&self, a: &Limbs) -> Limbs {
        self.mul(a, a)
    }

    fn to_mont(&self, a: &Limbs) -> Limbs {
        self.mul(a, &self.r2)
    }

    fn from_mont(&self, a: &Limbs) -> Limbs {
        let mut one = [0u64; L];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// a^(p-2): the inverse of a Montgomery-form value (and 0 for 0). The exponent is public, so
    /// the pattern of squarings and multiplications does not depend on `a`.
    fn invert(&self, a: &Limbs) -> Limbs {
        let mut r = self.one;
        for i in (0..self.n * 64).rev() {
            r = self.square(&r);
            if (self.p_minus_2[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    fn is_zero(&self, a: &Limbs) -> bool {
        a.iter().fold(0u64, |acc, &x| acc | x) == 0
    }

    fn infinity(&self) -> Point {
        [[0; L], self.one, [0; L]]
    }

    /// Complete addition (Renes-Costello-Batina 2016, algorithm 4: a = -3). Also doubles.
    fn point_add(&self, p: &Point, q: &Point) -> Point {
        let (x1, y1, z1) = (&p[0], &p[1], &p[2]);
        let (x2, y2, z2) = (&q[0], &q[1], &q[2]);
        let b = &self.b;
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

    /// k * p for a big-endian scalar `k` of exactly `self.len` bytes, in constant time.
    fn scalar_mul(&self, k: &[u8], p: &Point) -> Point {
        debug_assert_eq!(k.len(), self.len);
        // table[i] = i * p
        let mut table = [self.infinity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = self.point_add(&table[i - 1], p);
        }
        let mut r = self.infinity();
        for &byte in k {
            for nibble in [byte >> 4, byte & 15] {
                for _ in 0..4 {
                    r = self.point_add(&r, &r);
                }
                let want = black_box(nibble) as u64;
                let mut sel = [[0u64; L]; 3];
                for (i, entry) in table.iter().enumerate() {
                    let mask = eq_mask(i as u64, want);
                    for c in 0..3 {
                        for l in 0..self.n {
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

    /// Big-endian bytes (exactly `self.len`) to limbs; `None` if the value is not below `limit`.
    /// Variable time: used on public values (peer coordinates) and on the scalar's range check.
    fn parse_below(&self, bytes: &[u8], limit: &Limbs) -> Option<Limbs> {
        if bytes.len() != self.len {
            return None;
        }
        let l = to_limbs(&bignum::from_be_bytes(bytes));
        for i in (0..self.n).rev() {
            if l[i] != limit[i] {
                return if l[i] < limit[i] { Some(l) } else { None };
            }
        }
        None
    }

    fn to_bytes(&self, a: &Limbs) -> Vec<u8> {
        bignum::to_be_bytes(&a[..self.n], self.len)
    }

    /// (x, y) as big-endian bytes of the affine point, or `None` for the point at infinity.
    fn affine(&self, p: &Point) -> Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
        if self.is_zero(&p[2]) {
            return None;
        }
        let zinv = self.invert(&p[2]);
        let x = self.from_mont(&self.mul(&p[0], &zinv));
        let y = self.from_mont(&self.mul(&p[1], &zinv));
        Some((Zeroizing::new(self.to_bytes(&x)), Zeroizing::new(self.to_bytes(&y))))
    }

    /// y^2 = x^3 - 3x + b, for Montgomery-form coordinates.
    fn on_curve(&self, x: &Limbs, y: &Limbs) -> bool {
        let y2 = self.square(y);
        let x2 = self.square(x);
        let x3 = self.mul(&x2, x);
        let three_x = self.add(&self.add(x, x), x);
        let rhs = self.add(&self.sub(&x3, &three_x), &self.b);
        y2 == rhs
    }
}

/// Is `k` (big-endian, `len` bytes) a valid private scalar, 1 <= k < n?
fn scalar_in_range(f: &Field, k: &[u8]) -> bool {
    match f.parse_below(k, &f.order) {
        Some(l) => !f.is_zero(&l),
        None => false,
    }
}

/// The uncompressed SEC1 encoding (0x04 || x || y) of the generator times `scalar`, or `None` if
/// `scalar` is not in 1..n or has the wrong length.
pub fn public_key(curve: Curve, scalar: &[u8]) -> Option<Vec<u8>> {
    let _dit = Dit::on(); // data-independent timing while the secret is in use (crypto::dit)
    let f = try_field(curve)?;
    if !scalar_in_range(f, scalar) {
        return None;
    }
    let g: Point = [f.g[0], f.g[1], f.one];
    let r = f.scalar_mul(scalar, &g);
    let (x, y) = f.affine(&r)?;
    let mut out = Vec::with_capacity(1 + 2 * f.len);
    out.push(4);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

/// A fresh private scalar (uniform in 1..n, by rejection sampling) and its public key.
pub fn generate(curve: Curve) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let Some(f) = try_field(curve) else {
        return Err(crate::error::Error::Tls(format!("{curve:?} is not a curve of the key exchange")));
    };
    loop {
        let mut k = Zeroizing::new(vec![0u8; f.len]);
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
    let f = try_field(curve)?;
    if !scalar_in_range(f, scalar) {
        return None;
    }
    if peer_public.len() != 1 + 2 * f.len || peer_public[0] != 4 {
        return None;
    }
    let x = f.to_mont(&f.parse_below(&peer_public[1..1 + f.len], &f.p)?);
    let y = f.to_mont(&f.parse_below(&peer_public[1 + f.len..], &f.p)?);
    if !f.on_curve(&x, &y) {
        return None;
    }
    let mut r = f.scalar_mul(scalar, &[x, y, f.one]);
    let out = f.affine(&r).map(|(x, _)| x);
    r.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::super::ecdh_vectors::{PUBLIC, SHARED};
    use super::*;
    use crate::util::unhex;

    fn curve_of(name: &str) -> Curve {
        match name {
            "p256" => Curve::P256,
            "p384" => Curve::P384,
            _ => panic!("curve {name}"),
        }
    }

    #[test]
    fn the_field_matches_the_variable_time_bignum_code() {
        let mut rng = crate::fuzz::Rng::new(77);
        for curve in [Curve::P256, Curve::P384] {
            let f = field(curve);
            let reference = Mont::new(&f.p[..f.n]);
            for _ in 0..300 {
                let mut a = [0u64; L];
                let mut b = [0u64; L];
                for i in 0..f.n {
                    a[i] = rng.next_u64();
                    b[i] = rng.next_u64();
                }
                // reduce into range by clearing the top bits until below p
                while bignum::cmp(&a[..f.n], &f.p[..f.n]) != std::cmp::Ordering::Less {
                    a[f.n - 1] >>= 1;
                }
                while bignum::cmp(&b[..f.n], &f.p[..f.n]) != std::cmp::Ordering::Less {
                    b[f.n - 1] >>= 1;
                }
                assert_eq!(&f.mul(&a, &b)[..f.n], &reference.mul(&a[..f.n], &b[..f.n])[..], "mul");
                assert_eq!(&f.add(&a, &b)[..f.n], &reference.add(&a[..f.n], &b[..f.n])[..], "add");
                assert_eq!(&f.sub(&a, &b)[..f.n], &reference.sub(&a[..f.n], &b[..f.n])[..], "sub");
                // the inverse, in the Montgomery domain: a * a^-1 = 1
                if !f.is_zero(&a) {
                    let inv = f.invert(&a);
                    assert_eq!(f.mul(&a, &inv), f.one, "inverse");
                }
            }
            // edges: 0, 1, p - 1 on both sides
            let zero = [0u64; L];
            let mut pm1 = f.p;
            pm1[0] -= 1;
            for (a, b) in [(zero, zero), (f.one, pm1), (pm1, pm1), (pm1, zero)] {
                assert_eq!(&f.mul(&a, &b)[..f.n], &reference.mul(&a[..f.n], &b[..f.n])[..]);
                assert_eq!(&f.add(&a, &b)[..f.n], &reference.add(&a[..f.n], &b[..f.n])[..]);
                assert_eq!(&f.sub(&a, &b)[..f.n], &reference.sub(&a[..f.n], &b[..f.n])[..]);
            }
        }
    }

    #[test]
    fn generators_are_on_the_curve_and_infinity_behaves() {
        for curve in [Curve::P256, Curve::P384] {
            let f = field(curve);
            assert!(f.on_curve(&f.g[0], &f.g[1]));
            let g: Point = [f.g[0], f.g[1], f.one];
            let inf = f.infinity();
            // O + G = G, G + O = G, O + O = O (as projective points: compare after normalizing)
            for (p, q) in [(&inf, &g), (&g, &inf)] {
                let (x, y) = f.affine(&f.point_add(p, q)).unwrap();
                assert_eq!((&x[..], &y[..]), (&f.to_bytes(&f.from_mont(&f.g[0]))[..], &f.to_bytes(&f.from_mont(&f.g[1]))[..]));
            }
            assert!(f.affine(&f.point_add(&inf, &inf)).is_none());
            // G + (-G) = O
            let neg_g: Point = [f.g[0], f.sub(&[0; L], &f.g[1]), f.one];
            assert!(f.affine(&f.point_add(&g, &neg_g)).is_none());
            // 2G computed as G + G stays on the curve
            let (x, y) = f.affine(&f.point_add(&g, &g)).unwrap();
            let (xm, ym) = (f.to_mont(&to_limbs(&bignum::from_be_bytes(&x))), f.to_mont(&to_limbs(&bignum::from_be_bytes(&y))));
            assert!(f.on_curve(&xm, &ym));
            // n * G = infinity, (n - 1) * G = -G
            let mut n_bytes = f.to_bytes(&f.order);
            assert!(f.affine(&f.scalar_mul(&n_bytes, &g)).is_none());
            *n_bytes.last_mut().unwrap() -= 1; // both orders end in an odd byte, so no borrow
            let (x, y) = f.affine(&f.scalar_mul(&n_bytes, &g)).unwrap();
            assert_eq!(&x[..], &f.to_bytes(&f.from_mont(&f.g[0]))[..]);
            let neg_y = f.to_bytes(&f.from_mont(&f.sub(&[0; L], &f.g[1])));
            assert_eq!(&y[..], &neg_y[..]);
        }
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
        for curve in [Curve::P256, Curve::P384] {
            for _ in 0..6 {
                let (a, pa) = generate(curve).unwrap();
                let (b, pb) = generate(curve).unwrap();
                assert_eq!(pa.len(), 1 + 2 * field(curve).len);
                let s1 = shared_secret(curve, &a, &pb).unwrap();
                let s2 = shared_secret(curve, &b, &pa).unwrap();
                assert_eq!(&s1[..], &s2[..]);
                assert_eq!(s1.len(), field(curve).len);
            }
        }
    }

    #[test]
    fn out_of_range_scalars_are_refused() {
        for curve in [Curve::P256, Curve::P384] {
            let f = field(curve);
            let g = public_key(curve, &{
                let mut one = vec![0u8; f.len];
                *one.last_mut().unwrap() = 1;
                one
            })
            .unwrap();
            let zero = vec![0u8; f.len];
            let n = f.to_bytes(&f.order);
            let mut n_plus_1 = n.clone();
            *n_plus_1.last_mut().unwrap() += 1;
            for bad in [&zero[..], &n[..], &n_plus_1[..], &vec![0xffu8; f.len][..], &vec![1u8; f.len - 1][..], &vec![1u8; f.len + 1][..]] {
                assert!(public_key(curve, bad).is_none());
                assert!(shared_secret(curve, bad, &g).is_none());
            }
        }
    }

    #[test]
    fn invalid_peer_points_are_refused() {
        for curve in [Curve::P256, Curve::P384] {
            let f = field(curve);
            let (k, _) = generate(curve).unwrap();
            let mut one = vec![0u8; f.len];
            *one.last_mut().unwrap() = 1;
            let good = public_key(curve, &one).unwrap(); // the generator
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
    }
}
