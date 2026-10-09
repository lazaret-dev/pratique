//! ECDSA signature verification over NIST P-256, P-384 and P-521.
//!
//! Verification only, so every value is public and nothing here is constant time (signing and the key
//! exchange, which do handle secrets, are in `ecdh.rs` and elsewhere and are written differently). What this
//! module is written for is speed, because a TLS handshake checks two signatures (the certificate's and the
//! server's `CertificateVerify`) and for a client that opens many connections that is most of what a handshake
//! costs:
//!
//! * field elements are fixed-size limb arrays (`[u64; N]`, N = 4, 6 or 9, a const generic, so the loops of the
//!   Montgomery multiplication are unrolled and nothing is allocated; the arithmetic is in `bignum::fixed`, which RSA
//!   uses too), and P-256's prime has a reduction of its own, one product a step where the general one makes five
//!   (B-49);
//! * `u1*G + u2*Q` is computed by one interleaved pass over the width-w non-adjacent forms of the two scalars
//!   (Straus-Shamir): one doubling per bit, and an addition only at the nonzero digits (about one in w + 1);
//! * the multiples of the generator come from a table of 32 odd multiples in affine form (built once, on first
//!   use), so adding them is the cheaper mixed addition; the public key's own table (8 odd multiples) is made
//!   per signature;
//! * the final comparison `x(R) mod n == r` is made without converting R to affine coordinates (no second
//!   inversion): `X == r * Z^2`, or `X == (r + n) * Z^2` in the rare case that `r + n` is still below p.
//!
//! The old, simple implementation (a vector of limbs per value, one bit per step) is kept under `cfg(test)` as
//! the reference the new one is compared with, on random keys and signatures and on the special cases of the
//! group law (adding a point to itself, to its negative).

use super::bignum::fixed::{add_carry, compare, is_zero, limbs_from_be, limbs_from_hex, sub_borrow, Fe, Field};
use super::sha2::HashAlg;
use crate::asn1::{self, Der};
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    /// For verification only (certificates, a TLS signature): the key exchange offers P-256 and P-384.
    P521,
}

impl Curve {
    /// Bytes of a coordinate (and of a scalar) in an encoding.
    pub fn coord_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }
}

/// A point in Jacobian coordinates (X : Y : Z), Montgomery form, meaning (X / Z^2, Y / Z^3); Z = 0 is the point at
/// infinity.
#[derive(Clone, Copy)]
pub(crate) struct Jac<const N: usize> {
    x: Fe<N>,
    y: Fe<N>,
    z: Fe<N>,
}

/// A point other than infinity, Montgomery form.
#[derive(Clone, Copy)]
pub(crate) struct Aff<const N: usize> {
    x: Fe<N>,
    y: Fe<N>,
}

/// Width of the windows over the generator's scalar: its table holds the odd multiples 1G, 3G, ... up to
/// (2^(W_G - 1) - 1) G.
const W_G: u32 = 7;
const G_TABLE: usize = 1 << (W_G - 2);
/// The same for the public key's scalar, whose table is made for each signature.
const W_Q: u32 = 5;
const Q_TABLE: usize = 1 << (W_Q - 2);
/// The most limbs a number has here (P-521: 9).
const MAX_LIMBS: usize = 9;
/// Digits of a width-w NAF of a number of up to 64 * MAX_LIMBS bits: one more than its bits, and a spare.
const MAX_DIGITS: usize = 64 * MAX_LIMBS + 2;

/// A curve y^2 = x^3 - 3x + b over GF(p) with a prime group order n (and cofactor 1).
pub(crate) struct Group<const N: usize> {
    f: Field<N>,
    n: Field<N>,
    b: Fe<N>,
    g: Aff<N>,
    /// Bytes of a coordinate in an encoded point (the field's size in bytes: 66 for P-521, less than 8 N).
    coord_len: usize,
    /// Bits of the group order (521 for P-521): how many of a digest's leftmost bits make the number signed.
    n_bits: usize,
    /// 1G, 3G, 5G, ..., built on first use.
    g_table: OnceLock<Vec<Aff<N>>>,
}

/// The point operations of a verification's main pass (`Group::mul_add`): this file's ([`Plain`]), or a copy of them
/// compiled for an instruction set extension (`ecdsa_hw`, B-104).
pub(crate) trait Points<const N: usize> {
    fn double(g: &Group<N>, p: &Jac<N>) -> Jac<N>;
    fn add(g: &Group<N>, p: &Jac<N>, q: &Jac<N>) -> Jac<N>;
    fn add_affine(g: &Group<N>, p: &Jac<N>, q: &Aff<N>) -> Jac<N>;
}

/// The point operations as this file compiles them.
pub(crate) struct Plain;

impl<const N: usize> Points<N> for Plain {
    fn double(g: &Group<N>, p: &Jac<N>) -> Jac<N> {
        g.double(p)
    }
    fn add(g: &Group<N>, p: &Jac<N>, q: &Jac<N>) -> Jac<N> {
        g.add(p, q)
    }
    fn add_affine(g: &Group<N>, p: &Jac<N>, q: &Aff<N>) -> Jac<N> {
        g.add_affine(p, q)
    }
}

impl<const N: usize> Group<N> {
    fn new(p: &str, b: &str, gx: &str, gy: &str, n: &str, coord_len: usize) -> Group<N> {
        let f = Field::<N>::new(p);
        let order = Field::<N>::new(n);
        let to_m = |h: &str| f.to_mont(&limbs_from_hex(h));
        let (b, gx, gy) = (to_m(b), to_m(gx), to_m(gy));
        let n_bits = order.m.iter().rposition(|&l| l != 0).map_or(0, |i| 64 * i + 64 - order.m[i].leading_zeros() as usize);
        Group { f, n: order, b, g: Aff { x: gx, y: gy }, coord_len, n_bits, g_table: OnceLock::new() }
    }

    /// The field of the coordinates, for the point operations, with a fact the compiler cannot see made plain to it: the
    /// group of 4 limbs is P-256, whose prime has its own reduction (`bignum::fixed`). Without it every product in the
    /// operations' code carries the general reduction as well, never used there, which doubles their size (B-104).
    #[inline(always)]
    fn field(&self) -> &Field<N> {
        if N == 4 && !self.f.is_p256() {
            unreachable!("the group of 4 limbs is P-256");
        }
        &self.f
    }

    fn infinity(&self) -> Jac<N> {
        Jac { x: self.f.one, y: self.f.one, z: [0; N] }
    }

    fn jac(&self, p: &Aff<N>) -> Jac<N> {
        Jac { x: p.x, y: p.y, z: self.f.one }
    }

    /// Checks y^2 = x^3 - 3x + b for Montgomery-form coordinates.
    fn on_curve(&self, p: &Aff<N>) -> bool {
        let f = &self.f;
        let lhs = f.sqr(&p.y);
        let x3 = f.mul(&f.sqr(&p.x), &p.x);
        let three_x = f.add(&f.add(&p.x, &p.x), &p.x);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        lhs == rhs
    }

    /// Point doubling for a = -3 (dbl-2001-b): 3 multiplications and 5 squarings.
    #[inline(never)] // one copy, which the additions' rare case, the tables and `Plain` call
    fn double(&self, p: &Jac<N>) -> Jac<N> {
        self.double_inline(p)
    }

    /// `double`, `#[inline(always)]` (as is the field arithmetic under it), for a copy compiled with an instruction set
    /// extension (`ecdsa_hw`); the same for `add_inline` and `add_affine_inline`.
    #[inline(always)]
    pub(crate) fn double_inline(&self, p: &Jac<N>) -> Jac<N> {
        let f = self.field();
        if is_zero(&p.z) {
            return *p;
        }
        let delta = f.sqr(&p.z);
        let gamma = f.sqr(&p.y);
        let beta = f.mul(&p.x, &gamma);
        let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
        let alpha = f.add(&f.add(&t, &t), &t);
        let beta2 = f.add(&beta, &beta);
        let beta4 = f.add(&beta2, &beta2);
        let x3 = f.sub(&f.sub(&f.sqr(&alpha), &beta4), &beta4);
        let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.y, &p.z)), &gamma), &delta);
        let gamma2 = f.sqr(&gamma);
        let g2x2 = f.add(&gamma2, &gamma2);
        let g2x4 = f.add(&g2x2, &g2x2);
        let g2x8 = f.add(&g2x4, &g2x4);
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g2x8);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// p + q for an affine q (madd-2007-bl: 7 multiplications and 4 squarings), special cases included.
    #[inline(never)] // one copy, which the additions' rare case, the tables and `Plain` call
    fn add_affine(&self, p: &Jac<N>, q: &Aff<N>) -> Jac<N> {
        self.add_affine_inline(p, q)
    }

    #[inline(always)]
    pub(crate) fn add_affine_inline(&self, p: &Jac<N>, q: &Aff<N>) -> Jac<N> {
        let f = self.field();
        if is_zero(&p.z) {
            return self.jac(q);
        }
        let z1z1 = f.sqr(&p.z);
        let u2 = f.mul(&q.x, &z1z1);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &p.x);
        let r0 = f.sub(&s2, &p.y);
        if is_zero(&h) {
            // the same x: the same point (double it) or its negative (infinity)
            return if is_zero(&r0) { self.double(p) } else { self.infinity() };
        }
        let hh = f.sqr(&h);
        let i = f.add(&hh, &hh);
        let i = f.add(&i, &i);
        let j = f.mul(&h, &i);
        let r = f.add(&r0, &r0);
        let v = f.mul(&p.x, &i);
        let x3 = f.sub(&f.sub(&f.sub(&f.sqr(&r), &j), &v), &v);
        let y1j = f.mul(&p.y, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&y1j, &y1j));
        let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.z, &h)), &z1z1), &hh);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// p + q (add-2007-bl: 11 multiplications and 5 squarings), special cases included.
    #[inline(never)] // one copy, which the additions' rare case, the tables and `Plain` call
    fn add(&self, p: &Jac<N>, q: &Jac<N>) -> Jac<N> {
        self.add_inline(p, q)
    }

    #[inline(always)]
    pub(crate) fn add_inline(&self, p: &Jac<N>, q: &Jac<N>) -> Jac<N> {
        let f = self.field();
        if is_zero(&p.z) {
            return *q;
        }
        if is_zero(&q.z) {
            return *p;
        }
        let z1z1 = f.sqr(&p.z);
        let z2z2 = f.sqr(&q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &u1);
        let r0 = f.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&r0) { self.double(p) } else { self.infinity() };
        }
        let h2 = f.add(&h, &h);
        let i = f.sqr(&h2);
        let j = f.mul(&h, &i);
        let r = f.add(&r0, &r0);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.sub(&f.sqr(&r), &j), &v), &v);
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let zs = f.sub(&f.sub(&f.sqr(&f.add(&p.z, &q.z)), &z1z1), &z2z2);
        let z3 = f.mul(&zs, &h);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn neg_jac(&self, p: &Jac<N>) -> Jac<N> {
        Jac { x: p.x, y: self.f.neg(&p.y), z: p.z }
    }

    /// The odd multiples 1G, 3G, ..., in affine form, with one inversion for all of them (Montgomery's trick).
    fn build_g_table(&self) -> Vec<Aff<N>> {
        let f = &self.f;
        let g = self.jac(&self.g);
        let g2 = self.double(&g);
        let mut pts: Vec<Jac<N>> = Vec::with_capacity(G_TABLE);
        pts.push(g);
        for i in 1..G_TABLE {
            let next = self.add(&pts[i - 1], &g2);
            pts.push(next);
        }
        // running products of the Z coordinates, one inversion, then back down
        let mut prefix: Vec<Fe<N>> = Vec::with_capacity(G_TABLE);
        let mut acc = f.one;
        for p in &pts {
            acc = f.mul(&acc, &p.z);
            prefix.push(acc);
        }
        let mut inv_acc = f.inv(&acc);
        let mut out = vec![Aff { x: [0; N], y: [0; N] }; G_TABLE];
        for i in (0..G_TABLE).rev() {
            let zinv = if i == 0 { inv_acc } else { f.mul(&inv_acc, &prefix[i - 1]) };
            inv_acc = f.mul(&inv_acc, &pts[i].z);
            let zinv2 = f.sqr(&zinv);
            out[i] = Aff { x: f.mul(&pts[i].x, &zinv2), y: f.mul(&pts[i].y, &f.mul(&zinv2, &zinv)) };
        }
        out
    }

    /// u1 * G + u2 * Q, for plain (not Montgomery) scalars: one pass over both width-w NAFs, with the point operations
    /// of `P`.
    fn mul_add<P: Points<N>>(&self, u1: &Fe<N>, u2: &Fe<N>, q: &Aff<N>) -> Jac<N> {
        let g_table = self.g_table.get_or_init(|| self.build_g_table());
        let mut d1 = [0i8; MAX_DIGITS];
        let mut d2 = [0i8; MAX_DIGITS];
        let l1 = wnaf(u1, W_G, &mut d1);
        let l2 = wnaf(u2, W_Q, &mut d2);

        // Q, 3Q, 5Q, ...
        let mut q_table = [self.infinity(); Q_TABLE];
        q_table[0] = self.jac(q);
        let q2 = P::double(self, &q_table[0]);
        for i in 1..Q_TABLE {
            q_table[i] = P::add(self, &q_table[i - 1], &q2);
        }

        let mut r = self.infinity();
        for i in (0..l1.max(l2)).rev() {
            r = P::double(self, &r);
            if i < l1 && d1[i] != 0 {
                let e = &g_table[(d1[i].unsigned_abs() as usize) / 2];
                let e = if d1[i] < 0 { Aff { x: e.x, y: self.f.neg(&e.y) } } else { *e };
                r = P::add_affine(self, &r, &e);
            }
            if i < l2 && d2[i] != 0 {
                let e = &q_table[(d2[i].unsigned_abs() as usize) / 2];
                let e = if d2[i] < 0 { self.neg_jac(e) } else { *e };
                r = P::add(self, &r, &e);
            }
        }
        r
    }

    /// The affine coordinates (plain integers) of a point, or `None` for infinity. Only the tests need it: a
    /// verification compares without it.
    #[cfg(test)]
    fn to_affine(&self, p: &Jac<N>) -> Option<(Fe<N>, Fe<N>)> {
        if is_zero(&p.z) {
            return None;
        }
        let f = &self.f;
        let zinv = f.inv(&p.z);
        let zinv2 = f.sqr(&zinv);
        let x = f.mul(&p.x, &zinv2);
        let y = f.mul(&p.y, &f.mul(&zinv2, &zinv));
        Some((f.from_mont(&x), f.from_mont(&y)))
    }

    /// The point of an uncompressed SEC1 public key (0x04 || X || Y), if it is one: right length, coordinates
    /// below the field prime, and on the curve.
    fn public_point(&self, public_key: &[u8]) -> Option<Aff<N>> {
        let cl = self.coord_len;
        if public_key.len() != 1 + 2 * cl || public_key[0] != 0x04 {
            return None;
        }
        let qx: Fe<N> = limbs_from_be(&public_key[1..1 + cl])?;
        let qy: Fe<N> = limbs_from_be(&public_key[1 + cl..])?;
        if compare(&qx, &self.f.m) != Ordering::Less || compare(&qy, &self.f.m) != Ordering::Less {
            return None;
        }
        let q = Aff { x: self.f.to_mont(&qx), y: self.f.to_mont(&qy) };
        self.on_curve(&q).then_some(q)
    }

    fn verify<P: Points<N>>(&self, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
        let Some(q) = self.public_point(public_key) else { return false };

        // the signature: SEQUENCE { INTEGER r, INTEGER s }, both in 1..n
        let parse = || -> Option<(Fe<N>, Fe<N>)> {
            let mut outer = Der::new(sig_der);
            let mut seq = outer.sequence().ok()?;
            outer.finish().ok()?;
            let r = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER).ok()?).ok()?;
            let s = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER).ok()?).ok()?;
            seq.finish().ok()?;
            Some((limbs_from_be(&r)?, limbs_from_be(&s)?))
        };
        let Some((r, s)) = parse() else { return false };
        for v in [&r, &s] {
            if is_zero(v) || compare(v, &self.n.m) != Ordering::Less {
                return false;
            }
        }

        // e: as many of the digest's leftmost bits as the order has (SEC 1 section 4.1.3, step 5), as a number, so below
        // 2^n_bits and so below 2 n. (For P-256 and P-384 that is whole bytes; the order of P-521 has 521 bits, more than
        // any SHA-2 digest, which is then taken whole: the shift is for a longer one.)
        let take = digest.len().min(self.n_bits.div_ceil(8));
        let Some(mut e) = limbs_from_be::<N>(&digest[..take]) else { return false };
        let extra = (8 * take).saturating_sub(self.n_bits);
        if extra > 0 {
            for i in 0..N {
                e[i] = (e[i] >> extra) | if i + 1 < N { e[i + 1] << (64 - extra) } else { 0 };
            }
        }
        if compare(&e, &self.n.m) != Ordering::Less {
            e = sub_borrow(&e, &self.n.m).0;
        }

        // w = s^-1 in Montgomery form, so that mul(e, w) = e / s as a plain number (s is public: the quick binary inversion)
        let nf = &self.n;
        let w = nf.to_mont(&nf.inv_vartime(&s));
        let u1 = nf.mul(&e, &w);
        let u2 = nf.mul(&r, &w);

        let rp = self.mul_add::<P>(&u1, &u2, &q);
        if is_zero(&rp.z) {
            return false;
        }
        // x(R) mod n == r, with x = X / Z^2: X == r Z^2, or X == (r + n) Z^2 if r + n < p can be a coordinate
        let f = &self.f;
        let z2 = f.sqr(&rp.z);
        if f.mul(&f.to_mont(&r), &z2) == rp.x {
            return true;
        }
        let (r_plus_n, carry) = add_carry(&r, &self.n.m);
        if !carry && compare(&r_plus_n, &f.m) == Ordering::Less {
            return f.mul(&f.to_mont(&r_plus_n), &z2) == rp.x;
        }
        false
    }
}

/// The width-w non-adjacent form of `k`, least significant digit first, into `out`; returns how many digits.
/// Every digit is zero or odd with absolute value below 2^(w-1), and no two nonzero digits are less than w apart,
/// so a nonzero one comes about every w + 1 bits. (w is at most 7 so that a digit fits in an `i8`.)
fn wnaf(k: &[u64], w: u32, out: &mut [i8; MAX_DIGITS]) -> usize {
    debug_assert!((2..=7).contains(&w) && k.len() <= MAX_LIMBS);
    // one limb more than k has: adding the correction for a negative digit can carry out of the top
    const V: usize = MAX_LIMBS + 1;
    let mut v = [0u64; V];
    v[..k.len()].copy_from_slice(k);
    let mask = (1u64 << w) - 1;
    let half = 1u64 << (w - 1);
    let mut len = 0;
    let mut top = k.len(); // limbs at or above this one are zero
    while top > 0 && v[top - 1] == 0 {
        top -= 1;
    }
    while top > 0 {
        let mut digit = 0i8;
        if v[0] & 1 == 1 {
            let m = v[0] & mask;
            if m >= half {
                // digit m - 2^w, below zero: add 2^w - m to make the low w bits zero
                let add = (1u64 << w) - m;
                let mut carry = add;
                for limb in v.iter_mut() {
                    let (s, c) = limb.overflowing_add(carry);
                    *limb = s;
                    carry = c as u64;
                    if carry == 0 {
                        break;
                    }
                }
                digit = -(add as i8);
                if top < V && v[top] != 0 {
                    top += 1;
                }
            } else {
                // digit m: subtract it
                let mut borrow = m;
                for limb in v.iter_mut() {
                    let (s, b) = limb.overflowing_sub(borrow);
                    *limb = s;
                    borrow = b as u64;
                    if borrow == 0 {
                        break;
                    }
                }
                digit = m as i8;
            }
        }
        out[len] = digit;
        len += 1;
        // shift right by one
        for i in 0..top {
            v[i] = (v[i] >> 1) | if i + 1 < V { v[i + 1] << 63 } else { 0 };
        }
        while top > 0 && v[top - 1] == 0 {
            top -= 1;
        }
    }
    len
}

fn p256() -> &'static Group<4> {
    static G: OnceLock<Group<4>> = OnceLock::new();
    G.get_or_init(|| {
        Group::new(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            32,
        )
    })
}

fn p384() -> &'static Group<6> {
    static G: OnceLock<Group<6>> = OnceLock::new();
    G.get_or_init(|| {
        Group::new(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            48,
        )
    })
}

/// The constants are SEC 2 section 2.6.1's (read back from `openssl ecparam -name secp521r1 -param_enc explicit`):
/// p = 2^521 - 1, a = -3.
fn p521() -> &'static Group<9> {
    static G: OnceLock<Group<9>> = OnceLock::new();
    G.get_or_init(|| {
        Group::new(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            66,
        )
    })
}

/// Whether `public_key` is an uncompressed SEC1 point (0x04 || X || Y) on `curve`, which is all a public key
/// has to be for [`verify`] to use it.
pub fn is_valid_public_key(curve: Curve, public_key: &[u8]) -> bool {
    match curve {
        Curve::P256 => p256().public_point(public_key).is_some(),
        Curve::P384 => p384().public_point(public_key).is_some(),
        Curve::P521 => p521().public_point(public_key).is_some(),
    }
}

/// Verifies an ASN.1 DER-encoded ECDSA signature over `digest` (already hashed).
///
/// `public_key` is an uncompressed SEC1 point (0x04 || X || Y).
pub fn verify_prehashed(curve: Curve, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
    match curve {
        Curve::P256 => p256_verifier()(public_key, digest, sig_der),
        Curve::P384 => p384().verify::<Plain>(public_key, digest, sig_der),
        Curve::P521 => p521().verify::<Plain>(public_key, digest, sig_der),
    }
}

/// A P-256 verification (public key, digest, DER signature): [`p256_verify`], or [`p256_verify_with`] the point
/// operations of an instruction set extension, which the parent offers (`ecdsa_hw`, B-104).
pub(crate) type Verify = fn(&[u8], &[u8], &[u8]) -> bool;

/// The P-256 verification this process uses, decided once: the parent's (`ecdsa_hw`: on x86-64 with BMI2, the point
/// operations compiled to use it, about an eighth quicker), or, if it has none (another CPU, a build without `net`),
/// this file's. This file stays free of `unsafe` and of anything that names a CPU, as `sha2` does with its `Accel`.
fn p256_verifier() -> Verify {
    static V: OnceLock<Verify> = OnceLock::new();
    *V.get_or_init(|| super::ecdsa_hardware().unwrap_or(p256_verify))
}

/// P-256 verification with this file's point operations.
pub(crate) fn p256_verify(public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
    p256().verify::<Plain>(public_key, digest, sig_der)
}

/// P-256 verification with the point operations of `P`.
#[allow(dead_code)] // used by ecdsa_hw.rs (the `net` part)
pub(crate) fn p256_verify_with<P: Points<4>>(public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
    p256().verify::<P>(public_key, digest, sig_der)
}

/// Hashes `msg` with `alg` and verifies the signature.
pub fn verify(curve: Curve, public_key: &[u8], alg: HashAlg, msg: &[u8], sig_der: &[u8]) -> bool {
    verify_prehashed(curve, public_key, &alg.digest(msg), sig_der)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::bignum;
    use crate::crypto::test_vectors as tv;
    use crate::util::unhex;

    /// The old implementation: a vector of limbs per value, Jacobian coordinates, one bit per step. Slow, simple,
    /// and checked against the test vectors for years; the new code is compared with it.
    mod reference {
        use super::super::Curve;
        use crate::crypto::bignum::{self, Mont};
        use std::sync::OnceLock;

        pub(super) struct Params {
            pub(super) f: Mont, // field GF(p)
            pub(super) n: Mont, // group order
            pub(super) b: Vec<u64>,  // curve constant b (Montgomery form in f)
            pub(super) gx: Vec<u64>, // generator, Montgomery form
            pub(super) gy: Vec<u64>,
        }

        #[derive(Clone)]
        pub(super) struct Point {
            pub(super) x: Vec<u64>,
            pub(super) y: Vec<u64>,
            pub(super) z: Vec<u64>, // z == 0 means the point at infinity
        }

        pub(super) fn build(p: &str, b: &str, gx: &str, gy: &str, n: &str) -> Params {
            let f = Mont::new(&bignum::from_hex(p));
            let nn = Mont::new(&bignum::from_hex(n));
            let to_m = |h: &str| f.to_mont(&f.fit(&bignum::from_hex(h)));
            let (b, gx, gy) = (to_m(b), to_m(gx), to_m(gy));
            Params { f, n: nn, b, gx, gy }
        }

        pub(super) fn params(curve: Curve) -> &'static Params {
            static P256: OnceLock<Params> = OnceLock::new();
            static P384: OnceLock<Params> = OnceLock::new();
            static P521: OnceLock<Params> = OnceLock::new();
            match curve {
                Curve::P256 => P256.get_or_init(|| {
                    build(
                        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        )
                }),
                Curve::P384 => P384.get_or_init(|| {
                    build(
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                        )
                }),
                Curve::P521 => P521.get_or_init(|| {
                    build(
                        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
                        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
                        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
                        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
                        )
                }),
            }
        }

        impl Params {
            pub(super) fn infinity(&self) -> Point {
                Point { x: self.f.one(), y: self.f.one(), z: self.f.zero() }
            }

            pub(super) fn is_infinity(&self, p: &Point) -> bool {
                bignum::is_zero(&p.z)
            }

            pub(super) fn affine_point(&self, x: &[u64], y: &[u64]) -> Point {
                Point { x: x.to_vec(), y: y.to_vec(), z: self.f.one() }
            }

            /// Point doubling for a = -3 (dbl-2001-b).
            pub(super) fn double(&self, p: &Point) -> Point {
                let f = &self.f;
                if self.is_infinity(p) {
                    return p.clone();
                }
                let delta = f.sqr(&p.z);
                let gamma = f.sqr(&p.y);
                let beta = f.mul(&p.x, &gamma);
                let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
                let alpha = f.add(&f.add(&t, &t), &t);
                let beta2 = f.add(&beta, &beta);
                let beta4 = f.add(&beta2, &beta2);
                let beta8 = f.add(&beta4, &beta4);
                let x3 = f.sub(&f.sqr(&alpha), &beta8);
                let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.y, &p.z)), &gamma), &delta);
                let gamma2 = f.sqr(&gamma);
                let g2x2 = f.add(&gamma2, &gamma2);
                let g2x4 = f.add(&g2x2, &g2x2);
                let g2x8 = f.add(&g2x4, &g2x4);
                let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g2x8);
                Point { x: x3, y: y3, z: z3 }
            }

            /// General Jacobian point addition (add-1998-cmo-2), with the special cases handled.
            pub(super) fn add(&self, p: &Point, q: &Point) -> Point {
                let f = &self.f;
                if self.is_infinity(p) {
                    return q.clone();
                }
                if self.is_infinity(q) {
                    return p.clone();
                }
                let z1z1 = f.sqr(&p.z);
                let z2z2 = f.sqr(&q.z);
                let u1 = f.mul(&p.x, &z2z2);
                let u2 = f.mul(&q.x, &z1z1);
                let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
                let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
                let h = f.sub(&u2, &u1);
                let r = f.sub(&s2, &s1);
                if bignum::is_zero(&h) {
                    return if bignum::is_zero(&r) { self.double(p) } else { self.infinity() };
                }
                let hh = f.sqr(&h);
                let hhh = f.mul(&h, &hh);
                let v = f.mul(&u1, &hh);
                let v2 = f.add(&v, &v);
                let x3 = f.sub(&f.sub(&f.sqr(&r), &hhh), &v2);
                let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.mul(&s1, &hhh));
                let z3 = f.mul(&f.mul(&p.z, &q.z), &h);
                Point { x: x3, y: y3, z: z3 }
            }

            /// Converts to affine coordinates, returned as ordinary integers.
            pub(super) fn to_affine(&self, p: &Point) -> Option<(Vec<u64>, Vec<u64>)> {
                if self.is_infinity(p) {
                    return None;
                }
                let f = &self.f;
                let zinv = f.inv(&p.z);
                let zinv2 = f.sqr(&zinv);
                let x = f.mul(&p.x, &zinv2);
                let y = f.mul(&p.y, &f.mul(&zinv2, &zinv));
                Some((f.from_mont(&x), f.from_mont(&y)))
            }

            /// Checks y^2 = x^3 - 3x + b for Montgomery-form coordinates.
            pub(super) fn on_curve(&self, x: &[u64], y: &[u64]) -> bool {
                let f = &self.f;
                let lhs = f.sqr(y);
                let x3 = f.mul(&f.sqr(x), x);
                let three_x = f.add(&f.add(x, x), x);
                let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
                lhs == rhs
            }
        }
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A pseudo-random number in 1..n, as limbs, for the curve of `pr`.
    fn random_scalar(pr: &reference::Params, state: &mut u64) -> Vec<u64> {
        let n = pr.n.modulus().to_vec();
        loop {
            let mut v: Vec<u64> = (0..n.len()).map(|_| splitmix(state)).collect();
            // a mix of sizes: sometimes only some of the bits, to make short and sparse scalars too
            match splitmix(state) % 4 {
                0 => {
                    let keep = (splitmix(state) % (64 * n.len() as u64)) as usize;
                    for i in 0..64 * n.len() {
                        if i >= keep {
                            v[i / 64] &= !(1u64 << (i % 64));
                        }
                    }
                }
                1 => v.iter_mut().for_each(|l| *l &= 0x8000_0000_8000_0001), // sparse
                _ => {}
            }
            if !bignum::is_zero(&v) && bignum::cmp(&v, &n) == Ordering::Less {
                return v;
            }
        }
    }

    /// k * G by the reference code, as plain affine coordinates.
    fn ref_mul_g(pr: &reference::Params, k: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let g = pr.affine_point(&pr.gx, &pr.gy);
        let mut r = pr.infinity();
        for i in (0..bignum::bit_len(k)).rev() {
            r = pr.double(&r);
            if bignum::bit(k, i) {
                r = pr.add(&r, &g);
            }
        }
        pr.to_affine(&r).expect("k is in 1..n")
    }

    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
        if v.first().map_or(true, |&b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    }

    fn der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let (r, s) = (der_int(r), der_int(s));
        let len = r.len() + s.len();
        // (P-521's r and s take more than 127 bytes together: the long form of the length)
        let mut out = if len < 0x80 { vec![0x30, len as u8] } else { vec![0x30, 0x81, len as u8] };
        out.extend(r);
        out.extend(s);
        out
    }

    /// The leftmost bits of `digest`, as many as the order `n` has (SEC 1 section 4.1.3, step 5), as a number.
    fn digest_number(n: &[u64], digest: &[u8]) -> Vec<u64> {
        let bits = bignum::bit_len(n);
        let take = digest.len().min(bits.div_ceil(8));
        let mut e = bignum::from_be_bytes(&digest[..take]);
        let extra = (8 * take).saturating_sub(bits);
        for _ in 0..extra {
            let mut carry = 0;
            for l in e.iter_mut().rev() {
                let next = *l & 1;
                *l = (*l >> 1) | (carry << 63);
                carry = next;
            }
        }
        e
    }

    /// Signs `digest` with private key `d` and nonce `k` using the reference arithmetic: (public key, DER signature).
    fn ref_sign(curve: Curve, d: &[u64], k: &[u64], digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pr = reference::params(curve);
        let cl = curve.coord_len();
        let nm = &pr.n;
        let (qx, qy) = ref_mul_g(pr, d);
        let mut public = vec![4u8];
        public.extend(bignum::to_be_bytes(&qx, cl));
        public.extend(bignum::to_be_bytes(&qy, cl));

        let (rx, _) = ref_mul_g(pr, k);
        let mut r = nm.fit(&rx);
        if bignum::cmp(&r, nm.modulus()) != Ordering::Less {
            r = nm.sub(&r, &nm.fit(nm.modulus()));
        }
        let mut e = nm.fit(&digest_number(nm.modulus(), digest));
        if bignum::cmp(&e, nm.modulus()) != Ordering::Less {
            e = nm.sub(&e, &nm.fit(nm.modulus()));
        }
        // s = k^-1 (e + r d)
        let rd = nm.mul(&nm.to_mont(&r), &nm.to_mont(&nm.fit(d)));
        let sum = nm.add(&nm.to_mont(&e), &rd);
        let s = nm.from_mont(&nm.mul(&nm.inv(&nm.to_mont(&nm.fit(k))), &sum));
        (public, der_sig(&bignum::to_be_bytes(&r, cl), &bignum::to_be_bytes(&s, cl)))
    }

    #[test]
    fn generators_are_on_curve_and_order_is_correct() {
        for c in [Curve::P256, Curve::P384, Curve::P521] {
            let pr = reference::params(c);
            assert!(pr.on_curve(&pr.gx, &pr.gy), "G not on curve");
            // n * G must be the point at infinity
            let n = pr.n.modulus().to_vec();
            let g = pr.affine_point(&pr.gx, &pr.gy);
            let mut r = pr.infinity();
            for i in (0..bignum::bit_len(&n)).rev() {
                r = pr.double(&r);
                if bignum::bit(&n, i) {
                    r = pr.add(&r, &g);
                }
            }
            assert!(pr.is_infinity(&r), "n*G != infinity");
        }
        assert!(p256().on_curve(&p256().g));
        assert!(p384().on_curve(&p384().g));
        assert!(p521().on_curve(&p521().g));
        // (n - 1) G + G is infinity with the new code too
        fn group_order_check<const N: usize>(g: &Group<N>) {
            let (nm1, _) = sub_borrow(&g.n.m, &{
                let mut one = [0u64; N];
                one[0] = 1;
                one
            });
            let mut one = [0u64; N];
            one[0] = 1;
            let r = g.mul_add::<Plain>(&nm1, &one, &g.g);
            assert!(is_zero(&r.z), "(n-1) G + G is not infinity");
        }
        group_order_check(p256());
        group_order_check(p384());
        group_order_check(p521());
    }

    #[test]
    fn wnaf_digits_add_up_to_the_number_and_are_spaced() {
        let mut state = 7u64;
        for w in 2..=7u32 {
            for round in 0..400 {
                let limbs = 1 + round % MAX_LIMBS;
                let k: Vec<u64> = (0..limbs).map(|_| match splitmix(&mut state) % 5 {
                    0 => 0,
                    1 => u64::MAX,
                    _ => splitmix(&mut state),
                }).collect();
                let mut digits = [0i8; MAX_DIGITS];
                let len = wnaf(&k, w, &mut digits);
                assert!(len <= 64 * limbs + 1);
                // the digits are odd or zero, below 2^(w-1), and a nonzero one is followed by w - 1 zeros
                let mut last_nonzero: Option<usize> = None;
                for (i, &d) in digits[..len].iter().enumerate() {
                    if d != 0 {
                        assert!(d % 2 != 0 && (d.unsigned_abs() as u32) < (1 << (w - 1)), "digit {d} for w {w}");
                        if let Some(l) = last_nonzero {
                            assert!(i - l >= w as usize, "digits {l} and {i} too close for w {w}");
                        }
                        last_nonzero = Some(i);
                    }
                }
                if len > 0 {
                    assert_ne!(digits[len - 1], 0, "the top digit is zero");
                }
                assert!(digits[len..].iter().all(|&d| d == 0));
                // sum of d_i 2^i == k, in a number twice as wide as needed: positives minus negatives
                let mut pos = vec![0u64; MAX_LIMBS + 2];
                let mut neg = vec![0u64; MAX_LIMBS + 2];
                for (i, &d) in digits[..len].iter().enumerate() {
                    if d == 0 {
                        continue;
                    }
                    let target = if d > 0 { &mut pos } else { &mut neg };
                    let mut carry = (d.unsigned_abs() as u128) << (i % 64);
                    let mut limb = i / 64;
                    while carry != 0 {
                        let s = target[limb] as u128 + (carry & u64::MAX as u128);
                        target[limb] = s as u64;
                        carry = (carry >> 64) + (s >> 64);
                        limb += 1;
                    }
                }
                // pos - neg == k (all limbs of k, then zeros)
                let mut borrow = 0u64;
                let mut diff = vec![0u64; MAX_LIMBS + 2];
                for i in 0..MAX_LIMBS + 2 {
                    let (a, b1) = pos[i].overflowing_sub(neg[i]);
                    let (c, b2) = a.overflowing_sub(borrow);
                    diff[i] = c;
                    borrow = (b1 | b2) as u64;
                }
                assert_eq!(borrow, 0);
                let mut want = k.clone();
                want.resize(MAX_LIMBS + 2, 0);
                assert_eq!(diff, want, "w {w} k {k:x?}");
            }
        }
    }

    fn check_mul_add<const N: usize, P: Points<N>>(g: &Group<N>, curve: Curve, rounds: usize) {
        let pr = reference::params(curve);
        let mut state = 0x1234_5678_9abc_def0 ^ N as u64;
        let to_fe = |v: &[u64]| -> Fe<N> {
            let mut a = [0u64; N];
            a.copy_from_slice(&bignum::from_be_bytes(&bignum::to_be_bytes(v, 8 * N))[..N]);
            a
        };
        for round in 0..rounds {
            let d = random_scalar(pr, &mut state);
            let u1 = random_scalar(pr, &mut state);
            let u2 = random_scalar(pr, &mut state);
            let (qx, qy) = ref_mul_g(pr, &d);
            let q = Aff { x: g.f.to_mont(&to_fe(&qx)), y: g.f.to_mont(&to_fe(&qy)) };
            assert!(g.on_curve(&q));
            // the reference: u1 G + u2 Q = (u1 + u2 d) G
            let nm = &pr.n;
            let total = nm.from_mont(&nm.add(&nm.to_mont(&nm.fit(&u1)), &nm.mul(&nm.to_mont(&nm.fit(&u2)), &nm.to_mont(&nm.fit(&d)))));
            let want = if bignum::is_zero(&total) { None } else { Some(ref_mul_g(pr, &total)) };
            let got = g.to_affine(&g.mul_add::<P>(&to_fe(&u1), &to_fe(&u2), &q));
            match (want, got) {
                (None, None) => {}
                (Some((wx, wy)), Some((gx, gy))) => {
                    assert_eq!(to_fe(&wx), gx, "x, round {round}");
                    assert_eq!(to_fe(&wy), gy, "y, round {round}");
                }
                (w, g) => panic!("round {round}: reference {:?}, new {:?}", w.is_some(), g.is_some()),
            }
        }
    }

    #[test]
    fn the_new_scalar_multiplication_matches_the_reference_p256() {
        check_mul_add::<4, Plain>(p256(), Curve::P256, 60);
    }

    #[test]
    fn the_new_scalar_multiplication_matches_the_reference_p384() {
        check_mul_add::<6, Plain>(p384(), Curve::P384, 30);
    }

    #[test]
    fn the_new_scalar_multiplication_matches_the_reference_p521() {
        check_mul_add::<9, Plain>(p521(), Curve::P521, 12);
    }

    /// The special cases of the group law, which a random input never reaches: Q = G with equal scalars (the sum
    /// meets the same point, so an addition is a doubling), Q = -G (it meets the negative: infinity), zero
    /// scalars, and the largest ones.
    fn check_special_cases<const N: usize, P: Points<N>>(g: &Group<N>) {
        let f = &g.f;
        let one = {
            let mut o = [0u64; N];
            o[0] = 1;
            o
        };
        let g_aff = g.g;
        let minus_g = Aff { x: g.g.x, y: f.neg(&g.g.y) };
        let n_minus_1 = sub_borrow(&g.n.m, &one).0;
        let zero = [0u64; N];
        let affine = |p: &Jac<N>| g.to_affine(p);
        let two = {
            let mut t = [0u64; N];
            t[0] = 2;
            t
        };
        // 2G by u1 = 1, u2 = 1, Q = G, and by u1 = 2
        let a = affine(&g.mul_add::<P>(&one, &one, &g_aff));
        let b = affine(&g.mul_add::<P>(&two, &zero, &g_aff));
        let c = affine(&g.mul_add::<P>(&zero, &two, &g_aff));
        assert!(a.is_some());
        assert_eq!(a, b);
        assert_eq!(a, c);
        // Q = -G with u1 = u2: infinity; any scalar times G minus itself
        let mut state = 99u64;
        for _ in 0..20 {
            let mut k = [0u64; N];
            for l in k.iter_mut() {
                *l = splitmix(&mut state);
            }
            k[N - 1] &= g.n.m[N - 1] >> 1; // below n
            assert!(affine(&g.mul_add::<P>(&k, &k, &minus_g)).is_none(), "kG - kG");
            // and u1 G + u2 G = (u1 + u2) G, whatever the digits do when they meet
            let mut k2 = k;
            k2[0] ^= 0x55;
            let sum = g.n.add(&k, &k2);
            let x = affine(&g.mul_add::<P>(&k, &k2, &g_aff));
            let y = affine(&g.mul_add::<P>(&sum, &zero, &g_aff));
            assert_eq!(x, y, "kG + k'G");
        }
        // (n - 1) G is -G
        let m = affine(&g.mul_add::<P>(&n_minus_1, &zero, &g_aff)).unwrap();
        assert_eq!(m.0, f.from_mont(&g_aff.x));
        assert_eq!(m.1, f.from_mont(&minus_g.y));
        // zero and zero: infinity
        assert!(affine(&g.mul_add::<P>(&zero, &zero, &g_aff)).is_none());
    }

    #[test]
    fn special_cases_of_the_group_law_are_right() {
        check_special_cases::<4, Plain>(p256());
        check_special_cases::<6, Plain>(p384());
        check_special_cases::<9, Plain>(p521());
    }

    #[test]
    fn signatures_made_with_the_reference_arithmetic_verify_and_tampered_ones_do_not() {
        for (curve, rounds) in [(Curve::P256, 40), (Curve::P384, 20), (Curve::P521, 12)] {
            let pr = reference::params(curve);
            let mut state = 42u64 + rounds as u64;
            for round in 0..rounds {
                let d = random_scalar(pr, &mut state);
                let k = random_scalar(pr, &mut state);
                // digests of all the lengths the callers use (and an empty one, and one longer than the order)
                let len = [32usize, 48, 64, 20, 0, 70][round % 6];
                let digest: Vec<u8> = (0..len).map(|_| splitmix(&mut state) as u8).collect();
                let (public, sig) = ref_sign(curve, &d, &k, &digest);
                assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} round {round}: a good signature fails");
                assert!(is_valid_public_key(curve, &public));
                // one bit of the digest, of the signature, of the key: all refused
                if !digest.is_empty() {
                    let mut bad = digest.clone();
                    bad[round % digest.len()] ^= 1 << (round % 8);
                    // (a bit beyond the order's width, in a long digest, is not part of the number)
                    if 8 * len <= bignum::bit_len(pr.n.modulus()) {
                        assert!(!verify_prehashed(curve, &public, &bad, &sig), "{curve:?} round {round}: bad digest");
                    }
                }
                let mut bad = sig.clone();
                let at = 4 + (round * 7) % (sig.len() - 4);
                bad[at] ^= 1 << (round % 8);
                assert!(!verify_prehashed(curve, &public, &digest, &bad), "{curve:?} round {round}: bad signature");
                let mut bad = public.clone();
                let at = 1 + (round * 5) % (public.len() - 1);
                bad[at] ^= 1 << (round % 8);
                assert!(!verify_prehashed(curve, &bad, &digest, &sig), "{curve:?} round {round}: bad key");
            }
        }
    }

    /// k * P by the reference code, in Jacobian coordinates (infinity if k is a multiple of the order).
    fn ref_mul_point(pr: &reference::Params, k: &[u64], p: &reference::Point) -> reference::Point {
        let mut r = pr.infinity();
        for i in (0..bignum::bit_len(k)).rev() {
            r = pr.double(&r);
            if bignum::bit(k, i) {
                r = pr.add(&r, p);
            }
        }
        r
    }

    /// An x coordinate between n and p is a case no random signature reaches (the chance is about 2^-64): the
    /// verifier must take x(R) mod n = x - n as r. It is made by choosing R first: a point (x, y) with x = n + t,
    /// a digest, and s; r = t; then the public key is the point that makes u1 G + u2 Q equal R.
    fn check_x_between_n_and_p(curve: Curve) {
        let pr = reference::params(curve);
        let cl = curve.coord_len();
        let f = &pr.f;
        let nm = &pr.n;
        let n = nm.modulus().to_vec();
        // (p + 1) / 4: p is 3 mod 4 for both curves, so y = rhs^((p+1)/4) is a square root when there is one
        let mut exp = f.modulus().to_vec();
        let mut carry = 1u64;
        for l in exp.iter_mut() {
            let (v, c) = l.overflowing_add(carry);
            *l = v;
            carry = c as u64;
        }
        assert_eq!(carry, 0);
        for i in 0..exp.len() {
            exp[i] = (exp[i] >> 2) | exp.get(i + 1).map_or(0, |h| h << 62);
        }
        let mut t = 0u64;
        let (x_m, y_m) = loop {
            t += 1;
            let mut small = vec![0u64; f.limbs()];
            small[0] = t;
            let x_plain = f.add(&f.fit(&n), &small);
            let x_m = f.to_mont(&x_plain);
            let three_x = f.add(&f.add(&x_m, &x_m), &x_m);
            let rhs = f.add(&f.sub(&f.mul(&f.sqr(&x_m), &x_m), &three_x), &pr.b);
            let y_m = f.pow(&rhs, &exp);
            if f.sqr(&y_m) == rhs {
                break (x_m, y_m);
            }
            assert!(t < 100, "no point with x just above n");
        };
        let big_r = pr.affine_point(&x_m, &y_m);
        let mut state = 0xabcdef ^ cl as u64;
        for round in 0..3 {
            // (64 bytes at most: the order of P-521 has 521 bits, and a longer digest would be cut)
            let digest: Vec<u8> = (0..cl.min(64)).map(|_| splitmix(&mut state) as u8).collect();
            let e = nm.fit(&bignum::from_be_bytes(&digest));
            assert_eq!(bignum::cmp(&e, &n), Ordering::Less, "(the chance that a random digest is not below n is 2^-32)");
            let s = random_scalar(pr, &mut state);
            let mut r = vec![0u64; nm.limbs()];
            r[0] = t;
            let w = nm.inv(&nm.to_mont(&nm.fit(&s)));
            let u1 = nm.mul(&nm.to_mont(&e), &w); // Montgomery form: e / s
            let u2 = nm.mul(&nm.to_mont(&r), &w);
            let (u1, u2) = (nm.from_mont(&u1), nm.from_mont(&u2));
            // Q = (R - u1 G) / u2
            let g = pr.affine_point(&pr.gx, &pr.gy);
            let mut u1g = ref_mul_point(pr, &u1, &g);
            u1g.y = f.sub(&f.zero(), &u1g.y);
            let diff = pr.add(&big_r, &u1g);
            let u2_inv = nm.from_mont(&nm.inv(&nm.to_mont(&nm.fit(&u2))));
            let q = ref_mul_point(pr, &u2_inv, &diff);
            let (qx, qy) = pr.to_affine(&q).expect("Q is a point");
            let mut public = vec![4u8];
            public.extend(bignum::to_be_bytes(&qx, cl));
            public.extend(bignum::to_be_bytes(&qy, cl));
            let sig = der_sig(&bignum::to_be_bytes(&r, cl), &bignum::to_be_bytes(&s, cl));
            assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} round {round}: x = n + {t} is not matched");
            // and not for an r that is neither x nor x - n
            let mut other = r.clone();
            other[0] += 1;
            let sig = der_sig(&bignum::to_be_bytes(&other, cl), &bignum::to_be_bytes(&s, cl));
            assert!(!verify_prehashed(curve, &public, &digest, &sig));
        }
    }

    #[test]
    fn an_x_coordinate_between_n_and_p_is_matched_by_r_equal_to_x_minus_n() {
        check_x_between_n_and_p(Curve::P256);
        check_x_between_n_and_p(Curve::P384);
        check_x_between_n_and_p(Curve::P521);
    }

    #[test]
    fn digests_at_or_above_the_order_are_reduced() {
        for curve in [Curve::P256, Curve::P384] {
            let pr = reference::params(curve);
            let cl = curve.coord_len();
            let mut state = 77u64;
            let n_bytes = bignum::to_be_bytes(pr.n.modulus(), cl);
            let mut n_plus_1 = n_bytes.clone();
            *n_plus_1.last_mut().unwrap() += 1;
            let mut n_minus_1 = n_bytes.clone();
            *n_minus_1.last_mut().unwrap() -= 1;
            // all ones (above the order), the order itself, one above, one below, and a longer one (only its first cl bytes count)
            for digest in [vec![0xffu8; cl], n_bytes.clone(), n_plus_1, n_minus_1, vec![0xff; cl + 16]] {
                let d = random_scalar(pr, &mut state);
                let k = random_scalar(pr, &mut state);
                let (public, sig) = ref_sign(curve, &d, &k, &digest);
                assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} digest {:x?}", &digest[..4]);
            }
        }
    }

    /// Adding two Jacobian points that are the same point written with different Z (the general addition, whose
    /// special cases no scalar of the verifier reaches by chance): it doubles, and for the negative it gives infinity.
    fn check_general_add_special_cases<const N: usize, P: Points<N>>(g: &Group<N>) {
        let f = &g.f;
        let mut k = [0u64; N];
        k[0] = 0x1234_5678_9abc;
        let p = g.mul_add::<Plain>(&k, &[0u64; N], &g.g); // some multiple of G, with Z != 1
        assert!(!is_zero(&p.z));
        let lambda = f.to_mont(&{
            let mut l = [0u64; N];
            l[0] = 0xdead_beef;
            l[1] = 3;
            l
        });
        let l2 = f.sqr(&lambda);
        let l3 = f.mul(&l2, &lambda);
        let same = Jac { x: f.mul(&p.x, &l2), y: f.mul(&p.y, &l3), z: f.mul(&p.z, &lambda) };
        assert_eq!(g.to_affine(&p), g.to_affine(&same));
        assert_eq!(g.to_affine(&P::double(g, &p)), g.to_affine(&g.double(&p)), "2P");
        assert_eq!(g.to_affine(&P::add(g, &p, &same)), g.to_affine(&g.double(&p)), "P + P by the general addition");
        assert!(g.to_affine(&P::add(g, &p, &g.neg_jac(&same))).is_none(), "P + (-P)");
        // the mixed addition with the same special cases
        let (ax, ay) = g.to_affine(&p).unwrap();
        let aff = Aff { x: f.to_mont(&ax), y: f.to_mont(&ay) };
        assert_eq!(g.to_affine(&P::add_affine(g, &p, &aff)), g.to_affine(&g.double(&p)), "P + P by the mixed addition");
        let neg = Aff { x: aff.x, y: f.neg(&aff.y) };
        assert!(g.to_affine(&P::add_affine(g, &p, &neg)).is_none(), "P + (-P) by the mixed addition");
        // with infinity on either side
        assert_eq!(g.to_affine(&P::add(g, &g.infinity(), &p)), g.to_affine(&p));
        assert_eq!(g.to_affine(&P::add(g, &p, &g.infinity())), g.to_affine(&p));
        assert_eq!(g.to_affine(&P::add_affine(g, &g.infinity(), &aff)), g.to_affine(&p));
    }

    /// The checks of the point operations above, on P-256 with the operations of `P`: what `ecdsa_hw` runs on its copy.
    #[allow(dead_code)] // used by ecdsa_hw.rs (the `net` part)
    pub(crate) fn check_p256_points<P: Points<4>>() {
        check_mul_add::<4, P>(p256(), Curve::P256, 30);
        check_special_cases::<4, P>(p256());
        check_general_add_special_cases::<4, P>(p256());
    }

    #[test]
    fn the_general_and_mixed_additions_handle_equal_and_opposite_points() {
        check_general_add_special_cases::<4, Plain>(p256());
        check_general_add_special_cases::<6, Plain>(p384());
    }

    #[test]
    fn signatures_with_r_or_s_out_of_range_or_zero_are_refused() {
        let pr = reference::params(Curve::P256);
        let mut state = 11u64;
        let d = random_scalar(pr, &mut state);
        let k = random_scalar(pr, &mut state);
        let digest = [7u8; 32];
        let (public, sig) = ref_sign(Curve::P256, &d, &k, &digest);
        assert!(verify_prehashed(Curve::P256, &public, &digest, &sig));
        let n = bignum::to_be_bytes(pr.n.modulus(), 32);
        let zero = [0u8; 32];
        let one = {
            let mut o = [0u8; 32];
            o[31] = 1;
            o
        };
        // take r and s out of the good signature
        let r = &sig[4..4 + sig[3] as usize];
        let s_at = 4 + sig[3] as usize;
        let s = &sig[s_at + 2..];
        for (rr, ss) in [(&zero[..], s), (r, &zero[..]), (&n[..], s), (r, &n[..]), (&one[..], &one[..])] {
            let bad = der_sig(rr, ss);
            assert!(!verify_prehashed(Curve::P256, &public, &digest, &bad), "r {rr:x?} s {ss:x?}");
        }
    }

    #[test]
    fn p256_sha256_verifies() {
        let pk = unhex(tv::P256_PUBKEY);
        let sig = unhex(tv::P256_SHA256_SIG);
        assert!(verify(Curve::P256, &pk, HashAlg::Sha256, tv::EC_MSG, &sig));
        assert!(!verify(Curve::P256, &pk, HashAlg::Sha256, b"tampered", &sig));
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify(Curve::P256, &pk, HashAlg::Sha256, tv::EC_MSG, &bad));
    }

    #[test]
    fn p256_with_sha384_truncates_digest() {
        let pk = unhex(tv::P256_PUBKEY);
        assert!(verify(Curve::P256, &pk, HashAlg::Sha384, tv::EC_MSG, &unhex(tv::P256_SHA384_SIG)));
    }

    #[test]
    fn p384_verifies() {
        let pk = unhex(tv::P384_PUBKEY);
        assert!(verify(Curve::P384, &pk, HashAlg::Sha384, tv::EC_MSG, &unhex(tv::P384_SHA384_SIG)));
        assert!(verify(Curve::P384, &pk, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P384_SHA256_SIG)));
        assert!(!verify(Curve::P384, &pk, HashAlg::Sha384, b"nope", &unhex(tv::P384_SHA384_SIG)));
    }

    #[test]
    fn rejects_wrong_curve_and_off_curve_keys() {
        let pk256 = unhex(tv::P256_PUBKEY);
        assert!(!verify(Curve::P384, &pk256, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P256_SHA256_SIG)));
        let mut off = pk256.clone();
        off[40] ^= 1;
        assert!(!verify(Curve::P256, &off, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P256_SHA256_SIG)));
    }

    #[test]
    fn keys_with_coordinates_not_below_p_or_of_the_wrong_shape_are_refused() {
        let pk = unhex(tv::P256_PUBKEY);
        assert!(is_valid_public_key(Curve::P256, &pk));
        // x + p: the same point written with an unreduced coordinate
        let mut unreduced = pk.clone();
        let p = bignum::to_be_bytes(pr_modulus(), 32);
        unreduced[1..33].copy_from_slice(&p);
        assert!(!is_valid_public_key(Curve::P256, &unreduced));
        assert!(!is_valid_public_key(Curve::P256, &pk[..64]));
        let mut compressed_prefix = pk.clone();
        compressed_prefix[0] = 2;
        assert!(!is_valid_public_key(Curve::P256, &compressed_prefix));
        assert!(!is_valid_public_key(Curve::P384, &pk));
        // the point at infinity has no encoding here: all zeros is not on the curve
        let mut zeros = vec![4u8];
        zeros.extend([0u8; 64]);
        assert!(!is_valid_public_key(Curve::P256, &zeros));
    }

    fn pr_modulus() -> &'static [u64] {
        reference::params(Curve::P256).f.modulus()
    }
}
