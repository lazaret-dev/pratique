//! Ed25519 signature verification (RFC 8032, section 5.1.7), with the verification rules of Go's
//! `crypto/ed25519` and of the `ref10` implementation that most of the ecosystem derives from.
//!
//! Only verification is here: this crate never signs. Everything it handles is public (keys,
//! messages, signatures), so the arithmetic is variable time. The point formulas themselves are branch-free
//! (every coordinate goes through the same field operations whatever the values), which is what lets
//! `x25519_base` use them on a secret scalar: what is variable time here is the choice of operations (the
//! windows of `double_scalar_mul_base`, which digit is added, and the comparisons).
//!
//! # The rules, and why they are these
//!
//! RFC 8032 leaves some choices to implementations, and implementations disagree on them. Two
//! verifiers that disagree on a signature are a problem wherever two parties must reach the same
//! verdict (a transparency log and its clients, for one), so this one follows a single reference
//! exactly: Go's `crypto/ed25519.Verify`, whose behaviour is pinned by the large vector set
//! described at <https://hdevalence.ca/blog/2020-10-04-its-25519am> and which the Go checksum
//! database and Go's `note` signatures are checked with. A signature is accepted if and only if
//!
//! * it is 64 bytes and the top three bits of its last byte are clear;
//! * `S`, its second half, is canonical: below the group order `L` (so `S` and `S + L` are not both
//!   accepted: signatures are not malleable by that route);
//! * the public key decodes to a point on the curve, where decoding is permissive in the two ways
//!   `ref10` is: a `y` coordinate of `p` or more is reduced modulo `p`, and a zero `x` with the sign
//!   bit set is accepted. (RFC 8032 says to reject both. Neither can be used to forge anything, but
//!   they mean a key has more than one encoding, and the hash below uses the bytes as given);
//! * `R' = [S]B - [k]A` encodes, in canonical form, to exactly the first 32 bytes of the signature,
//!   where `k = SHA-512(R || A || M)` read as a 512-bit little-endian number and reduced modulo `L`.
//!
//! The last rule makes this the *cofactorless* check `[S]B = R + [k]A`, not the cofactored
//! `[8][S]B = [8]R + [8][k]A` that RFC 8032 also allows. The two differ only for signatures whose
//! `R` or whose key has a component of small order. The consequences, all deliberate and all
//! identical to Go's:
//!
//! * `R` is never decoded, only compared as bytes, so a non-canonical `R` never verifies;
//! * a signature with a small-order component in `R` or `A` (a "low-order residue") is rejected
//!   unless the equation happens to balance exactly;
//! * a public key of small order is *accepted as a key* (there are 14 encodings of such points). With
//!   `A` the identity, `R` the identity and `S = 0`, the equation holds for every message. That is
//!   not a flaw in this verifier but a property of Ed25519 that applications relying on a key being
//!   a real signer's key must keep in mind: a key an attacker chose is the attacker's key.
//!
//! The checks that "unspecified" behaviours would need to be locked in are in the tests: a set of
//! signatures built to hit every combination of small-order points, non-canonical encodings and
//! mixed-order keys, each with the verdict Go's own implementation gives (`tools/ed25519_vectors.go`
//! regenerates the file, `tests/data/ed25519_vectors.txt`).

use super::fe25519::Fe;
use super::sha2::{Hash, Sha512};

/// The length of a public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// The length of a signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The order of the base point, L = 2^252 + 27742317777372353535851937790883648493, as four
/// little-endian 64-bit limbs.
const L: [u64; 4] = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000];

/// Verifies `signature` over `message` against `public_key`. A key or signature of the wrong length
/// is simply not valid.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(a_bytes), Ok(sig)) = (<&[u8; 32]>::try_from(public_key), <&[u8; 64]>::try_from(signature)) else {
        return false;
    };
    if sig[63] & 224 != 0 {
        return false;
    }
    let Some(a) = Point::decode(a_bytes) else {
        return false;
    };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    if !scalar_is_canonical(&s_bytes) {
        return false;
    }

    let mut h = Sha512::new();
    h.update(&sig[..32]);
    h.update(a_bytes);
    h.update(message);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let k = scalar_reduce(&wide);

    // [S]B = R + [k]A  <=>  [k](-A) + [S]B = R
    let r = double_scalar_mul_base(&k, &a.neg(), &s_bytes);
    r.encode()[..] == sig[..32]
}

// ---------------------------------------------------------------- scalars modulo L

pub(super) fn limbs_from_le(b: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for (i, limb) in r.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(w);
    }
    r
}

pub(super) fn limbs_to_le(l: &[u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, limb) in l.iter().enumerate() {
        r[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    r
}

/// a >= b, for 256-bit little-endian limb arrays.
fn limbs_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a - b, assuming a >= b.
fn limbs_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    r
}

/// Whether the 256-bit little-endian number is below L.
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    !limbs_ge(&limbs_from_le(s), &L)
}

/// A 512-bit little-endian number reduced modulo L, one bit at a time (shift, then subtract L if the
/// result is L or more). It is slow by the standards of a reduction and does not matter: it runs
/// once per signature, on public data, and is easy to check by eye.
pub(super) fn scalar_reduce(wide: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        // r < L < 2^253, so 2r + 1 fits in 254 bits
        let b = ((wide[bit / 8] >> (bit % 8)) & 1) as u64;
        let mut carry = b;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if limbs_ge(&r, &L) {
            r = limbs_sub(&r, &L);
        }
    }
    limbs_to_le(&r)
}

// ---------------------------------------------------------------- the curve

/// A point of edwards25519 (-x^2 + y^2 = 1 + d x^2 y^2) in extended coordinates: x = X/Z, y = Y/Z,
/// x*y = T/Z.
#[derive(Clone, Copy)]
pub(super) struct Point {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) z: Fe,
    pub(super) t: Fe,
}

impl Point {
    #[cfg(test)]
    const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    pub(super) fn base() -> Point {
        Point { x: Fe::BASE_X, y: Fe::BASE_Y, z: Fe::ONE, t: Fe::BASE_X.mul(Fe::BASE_Y) }
    }

    /// Decodes a point the way `ref10` and Go do: `y` is the low 255 bits (reduced modulo p if they
    /// are p or more), `x` is the square root of (y^2 - 1) / (d y^2 + 1) whose parity is the top bit,
    /// and a zero `x` is accepted whatever the top bit says.
    fn decode(bytes: &[u8; 32]) -> Option<Point> {
        let y = Fe::from_bytes(bytes);
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = Fe::D.mul(y2).add(Fe::ONE);
        let mut x = sqrt_ratio(u, v)?;
        if x.is_negative() != (bytes[31] >> 7 == 1) {
            x = x.neg();
        }
        Some(Point { x, y, z: Fe::ONE, t: x.mul(y) })
    }

    /// The canonical encoding: y, with the parity of x in the top bit.
    pub(super) fn encode(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(zinv);
        let y = self.y.mul(zinv);
        let mut out = y.to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    fn neg(&self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    /// The unified addition law (add-2008-hwcd-3 with a = -1 and k = 2d). It has no exceptional cases
    /// on this curve, so it is also correct for doubling, for the identity and for points of small
    /// order.
    pub(super) fn add(&self, o: &Point) -> Point {
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let c = self.t.mul(Fe::D2).mul(o.t);
        let zz = self.z.mul(o.z);
        let d = zz.add(zz);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }

    /// Doubling (dbl-2008-hwcd with a = -1).
    pub(super) fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(zz);
        let d = a.neg();
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }
}

/// A square root of u/v, if there is one (RFC 8032 section 5.1.3): the candidate
/// r = u v^3 (u v^7)^((p-5)/8) satisfies v r^2 = u or v r^2 = -u when u/v is a square, and the second
/// case is repaired by multiplying with a square root of -1. Zero is its own square root; a zero
/// denominator has no root unless the numerator is zero too.
fn sqrt_ratio(u: Fe, v: Fe) -> Option<Fe> {
    let v3 = v.square().mul(v);
    let v7 = v3.square().mul(v);
    let r = u.mul(v3).mul(u.mul(v7).pow22523());
    let check = v.mul(r.square());
    if check.equals(u) {
        Some(r)
    } else if check.equals(u.neg()) {
        Some(r.mul(Fe::SQRT_M1))
    } else {
        None
    }
}

/// [k]P + [s]B for the base point B, variable time (everything here is public): both scalars as signed digits in
/// windows (wNAF; width 5 for P, from a table of P, 3P, ..., 15P made per call, and width 8 for B, from a table of
/// B, 3B, ..., 127B made once), one chain of doublings from the top digit, and an addition only where a digit is
/// not zero (about 70 for two random scalars, against about 190 with one bit at a time); doublings that no addition
/// follows skip the fourth coordinate (ref10's `ge_double_scalarmult_vartime`, B-103). Any 256-bit scalars.
pub(super) fn double_scalar_mul_base(k: &[u8; 32], p: &Point, s: &[u8; 32]) -> Point {
    let kd = wnaf(k, 5);
    let sd = wnaf(s, 8);
    // P, 3P, 5P, ..., 15P, ready to be added
    let mut pt = [p.to_cached(); 8];
    let p2 = p.double();
    for i in 1..8 {
        pt[i] = pt[i - 1].add_to(&p2).to_extended().to_cached();
    }
    let bt = base_table();
    let mut top = 257;
    while top > 0 && kd[top - 1] == 0 && sd[top - 1] == 0 {
        top -= 1;
    }
    let mut r = Projective::IDENTITY;
    for i in (0..top).rev() {
        let mut c = r.double();
        let (dk, ds) = (kd[i], sd[i]);
        if dk != 0 {
            let e = c.to_extended();
            c = if dk > 0 { e.add_cached(&pt[(dk / 2) as usize]) } else { e.sub_cached(&pt[(-dk / 2) as usize]) };
        }
        if ds != 0 {
            let e = c.to_extended();
            c = if ds > 0 { e.add_affine(&bt[(ds / 2) as usize]) } else { e.sub_affine(&bt[(-ds / 2) as usize]) };
        }
        r = c.to_projective();
    }
    r.to_extended()
}

/// `k` (little endian, any 256-bit value) in width-`w` non-adjacent form: digits that are zero or odd and below
/// 2^(w-1) in size, nonzero digits at least `w` positions apart, sum of digit[i] * 2^i equal to k. One more position
/// than bits, for the carry out of the top.
fn wnaf(k: &[u8; 32], w: usize) -> [i16; 257] {
    let mut bits = [0u8; 257];
    for (i, b) in bits.iter_mut().take(256).enumerate() {
        *b = (k[i / 8] >> (i % 8)) & 1;
    }
    let mut digits = [0i16; 257];
    let (width, half) = (1i32 << w, 1i32 << (w - 1));
    let mut i = 0;
    let mut carry = 0i32;
    while i < 257 {
        let bit = bits[i] as i32 + carry;
        if bit & 1 == 0 {
            // an even position (0 or 2 with the carry) passes the carry on unchanged when it is 2 (1 + 1 = 10 binary)
            carry = bit >> 1;
            i += 1;
            continue;
        }
        // the window of `w` bits from here, with the carry added at its bottom
        let mut window = carry;
        for j in 0..w {
            if i + j < 257 {
                window += (bits[i + j] as i32) << j;
            }
        }
        window &= width - 1;
        if window < half {
            digits[i] = window as i16;
            carry = 0;
        } else {
            digits[i] = (window - width) as i16;
            carry = 1;
        }
        // the window's other bits are accounted for: skip them (they become zero digits)
        i += w;
    }
    digits
}

/// B, 3B, 5B, ..., 127B as affine (y + x, y - x, 2dxy), made once for the process.
fn base_table() -> &'static [Affine; 64] {
    static TABLE: std::sync::OnceLock<[Affine; 64]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let b = Point::base();
        let b2 = b.double();
        let mut cur = b;
        let mut out = [Affine { ypx: Fe::ZERO, ymx: Fe::ZERO, xy2d: Fe::ZERO }; 64];
        for (i, slot) in out.iter_mut().enumerate() {
            if i > 0 {
                cur = cur.add(&b2);
            }
            *slot = cur.to_affine();
        }
        out
    })
}

/// (Y + X, Y - X, Z, 2dT) of an extended point: an addend for `Point::add_cached` (ref10's `ge_cached`).
#[derive(Clone, Copy)]
struct Cached {
    ypx: Fe,
    ymx: Fe,
    z: Fe,
    t2d: Fe,
}

/// (y + x, y - x, 2dxy) of a point with Z = 1: an addend for `Point::add_affine` (ref10's `ge_precomp`).
#[derive(Clone, Copy)]
pub(super) struct Affine {
    pub(super) ypx: Fe,
    pub(super) ymx: Fe,
    pub(super) xy2d: Fe,
}

/// (X : Y : Z : T) with x = X/Z and y = Y/T: what a doubling or an addition gives before it is put back into one of
/// the other forms (ref10's `ge_p1p1`).
pub(super) struct Completed {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// (X : Y : Z) without T: enough to double (ref10's `ge_p2`).
pub(super) struct Projective {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) z: Fe,
}

impl Projective {
    const IDENTITY: Projective = Projective { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE };

    /// Doubling (dbl-2008-hwcd with a = -1, ref10's `ge_p2_dbl`): four squarings.
    pub(super) fn double(&self) -> Completed {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let b = zz.add(zz);
        let aa = self.x.add(self.y).square();
        let y = yy.add(xx);
        let z = yy.sub(xx);
        Completed { x: aa.sub(y), y, z, t: b.sub(z) }
    }

    fn to_extended(&self) -> Point {
        Point { x: self.x.mul(self.z), y: self.y.mul(self.z), z: self.z.square(), t: self.x.mul(self.y) }
    }
}

impl Completed {
    pub(super) fn to_projective(&self) -> Projective {
        Projective { x: self.x.mul(self.t), y: self.y.mul(self.z), z: self.z.mul(self.t) }
    }

    pub(super) fn to_extended(&self) -> Point {
        Point { x: self.x.mul(self.t), y: self.y.mul(self.z), z: self.z.mul(self.t), t: self.x.mul(self.y) }
    }
}

impl Cached {
    /// self + q for an extended q, as an extended point.
    fn add_to(&self, q: &Point) -> Completed {
        q.add_cached(self)
    }
}

impl Point {
    fn to_cached(&self) -> Cached {
        Cached { ypx: self.y.add(self.x), ymx: self.y.sub(self.x), z: self.z, t2d: self.t.mul(Fe::D2) }
    }

    /// The affine form; only for the base-point table, which is made once.
    fn to_affine(&self) -> Affine {
        self.to_affine_given(self.z.invert())
    }

    /// The affine form, given 1/Z (for tables whose inverses are made together).
    pub(super) fn to_affine_given(&self, zinv: Fe) -> Affine {
        let (x, y) = (self.x.mul(zinv), self.y.mul(zinv));
        Affine { ypx: y.add(x), ymx: y.sub(x), xy2d: x.mul(y).mul(Fe::D2) }
    }

    /// self + q (ref10's `ge_add`; add-2008-hwcd-3 with the addend's products made beforehand).
    fn add_cached(&self, q: &Cached) -> Completed {
        let a = self.y.sub(self.x).mul(q.ymx);
        let b = self.y.add(self.x).mul(q.ypx);
        let c = q.t2d.mul(self.t);
        let zz = self.z.mul(q.z);
        let d = zz.add(zz);
        Completed { x: b.sub(a), y: b.add(a), z: d.add(c), t: d.sub(c) }
    }

    /// self - q (ref10's `ge_sub`).
    fn sub_cached(&self, q: &Cached) -> Completed {
        let a = self.y.sub(self.x).mul(q.ypx);
        let b = self.y.add(self.x).mul(q.ymx);
        let c = q.t2d.mul(self.t);
        let zz = self.z.mul(q.z);
        let d = zz.add(zz);
        Completed { x: b.sub(a), y: b.add(a), z: d.sub(c), t: d.add(c) }
    }

    /// self + q for an affine q (ref10's `ge_madd`): one multiplication fewer.
    pub(super) fn add_affine(&self, q: &Affine) -> Completed {
        let a = self.y.sub(self.x).mul(q.ymx);
        let b = self.y.add(self.x).mul(q.ypx);
        let c = q.xy2d.mul(self.t);
        let d = self.z.add(self.z);
        Completed { x: b.sub(a), y: b.add(a), z: d.add(c), t: d.sub(c) }
    }

    /// self - q for an affine q (ref10's `ge_msub`).
    fn sub_affine(&self, q: &Affine) -> Completed {
        let a = self.y.sub(self.x).mul(q.ypx);
        let b = self.y.add(self.x).mul(q.ymx);
        let c = q.xy2d.mul(self.t);
        let d = self.z.add(self.z);
        Completed { x: b.sub(a), y: b.add(a), z: d.sub(c), t: d.add(c) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    /// [k]P + [s]B one bit at a time (Shamir's trick, the code before B-103): the reference the windowed version is
    /// checked against.
    fn double_scalar_mul_base_plain(k: &[u8; 32], p: &Point, s: &[u8; 32]) -> Point {
        let b = Point::base();
        let pb = p.add(&b);
        let mut r = Point::IDENTITY;
        for i in (0..256).rev() {
            r = r.double();
            let kb = (k[i / 8] >> (i % 8)) & 1;
            let sb = (s[i / 8] >> (i % 8)) & 1;
            match (kb, sb) {
                (0, 0) => {}
                (1, 0) => r = r.add(p),
                (0, _) => r = r.add(&b),
                _ => r = r.add(&pb),
            }
        }
        r
    }

    const SIGN_INPUT: &str = include_str!("../../tests/data/ed25519_sign_input.txt");
    const VECTORS: &str = include_str!("../../tests/data/ed25519_vectors.txt");

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// (public key, message, signature) for every data line of ed25519_sign_input.txt.
    fn sign_input() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        SIGN_INPUT
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                assert_eq!(f.len(), 3, "{l}");
                (unhex(f[0]), unhex(f[1]), unhex(f[2]))
            })
            .collect()
    }

    #[test]
    fn rfc8032_section_7_1() {
        // TEST 1 and TEST 2 are the first two lines of the known-answer file.
        let v = sign_input();
        assert_eq!(hex(&v[0].0), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(v[0].1.is_empty());
        assert!(verify(&v[0].0, &v[0].1, &v[0].2));
        assert_eq!(hex(&v[1].1), "72");
        assert!(verify(&v[1].0, &v[1].1, &v[1].2));
        // TEST 3 (two-byte message) and TEST SHA(abc) (the message is the 64 bytes SHA-512("abc")),
        // regenerated with OpenSSL from the RFC's secret keys
        let t3_pk = unhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let t3_sig = unhex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
        assert!(verify(&t3_pk, &unhex("af82"), &t3_sig));
        assert!(!verify(&t3_pk, &unhex("af83"), &t3_sig));
        let abc_pk = unhex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
        let abc_msg = Sha512::digest(b"abc");
        let abc_sig = unhex("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
        assert!(verify(&abc_pk, &abc_msg, &abc_sig));
    }

    #[test]
    fn the_known_answer_signatures_verify_and_their_corruptions_do_not() {
        let v = sign_input();
        assert_eq!(v.len(), 128);
        for (n, (pk, msg, sig)) in v.iter().enumerate() {
            assert!(verify(pk, msg, sig), "vector {n}");
            // a handful of single-bit corruptions of the signature, the key and the message
            for j in 0..6 {
                let bit = (n * 37 + j * 91) % 512;
                let mut bad = sig.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(!verify(pk, msg, &bad), "vector {n}: flipped signature bit {bit}");
            }
            for j in 0..2 {
                let bit = (n * 53 + j * 101) % 256;
                let mut bad = pk.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(!verify(&bad, msg, sig), "vector {n}: flipped key bit {bit}");
            }
            let mut longer = msg.clone();
            longer.push(0);
            assert!(!verify(pk, &longer, sig), "vector {n}: extended message");
            if let Some((last, rest)) = msg.split_last() {
                let mut bad = rest.to_vec();
                bad.push(last ^ 1);
                assert!(!verify(pk, &bad, sig), "vector {n}: flipped message");
            }
        }
    }

    #[test]
    fn lengths_must_be_exact() {
        let (pk, msg, sig) = sign_input().remove(1);
        assert!(verify(&pk, &msg, &sig));
        assert!(!verify(&pk[..31], &msg, &sig));
        let mut long_pk = pk.clone();
        long_pk.push(0);
        assert!(!verify(&long_pk, &msg, &sig));
        assert!(!verify(&[], &msg, &sig));
        assert!(!verify(&pk, &msg, &sig[..63]));
        let mut long_sig = sig.clone();
        long_sig.push(0);
        assert!(!verify(&pk, &msg, &long_sig));
        assert!(!verify(&pk, &msg, &[]));
    }

    /// Go's `crypto/ed25519.Verify` on every vector of tests/data/ed25519_vectors.txt: the two must agree
    /// on all of them, including the ones no sensible signer would produce.
    #[test]
    fn agrees_with_go_on_every_vector() {
        let mut n = 0;
        let mut accepted = 0;
        for line in VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(':').collect();
            assert_eq!(f.len(), 6, "{line}");
            let (family, key, sig, msg, go) = (f[0], unhex(f[1]), unhex(f[2]), unhex(f[3]), f[4]);
            let ours = verify(&key, &msg, &sig);
            assert_eq!(ours, go == "1", "{family}: key {} sig {} message {}: Go says {go}", f[1], f[2], f[3]);
            n += 1;
            accepted += ours as usize;
        }
        // the file really has the families it is meant to have
        assert!(n >= 1000, "{n} vectors");
        assert!(accepted > 50 && accepted < n / 2, "{accepted} of {n} accepted");
    }

    /// The vector families that pin the individual rules, spelled out so that a change to one of them shows
    /// up as a failure of a named property and not only as a vector number.
    #[test]
    fn the_rules_in_the_module_documentation() {
        let fam = |name: &str| -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, bool)> {
            VECTORS
                .lines()
                .filter(|l| l.starts_with(&format!("{name}:")))
                .map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (unhex(f[1]), unhex(f[2]), unhex(f[3]), f[4] == "1")
                })
                .collect()
        };
        // S + L and friends never verify, whatever else is right about the signature
        for (k, sig, m, go) in fam("malleable") {
            assert!(!go && !verify(&k, &m, &sig));
        }
        // a key with a component of small order verifies exactly when the reduced k kills the component:
        // the verifier reduces k modulo L (reduced-only is accepted, full-only is not)
        let reduced = fam("mixed-order-reduced-only");
        let full = fam("mixed-order-full-only");
        assert!(!reduced.is_empty() && !full.is_empty());
        for (k, sig, m, go) in reduced {
            assert!(go && verify(&k, &m, &sig));
        }
        for (k, sig, m, go) in full {
            assert!(!go && !verify(&k, &m, &sig));
        }
        // a torsion component in R is never accepted unless it cancels against the key's
        for (k, sig, m, go) in fam("residue-R") {
            assert!(!go && !verify(&k, &m, &sig));
        }
        for (k, sig, m, go) in fam("residue-RA-cancels") {
            assert!(go && verify(&k, &m, &sig));
        }
        // small-order keys are accepted as keys: the identity with R the identity and S = 0 verifies for
        // any message, in all three of the identity's encodings that Go accepts as a key
        let identity = "0100000000000000000000000000000000000000000000000000000000000000";
        let identity_sign = "0100000000000000000000000000000000000000000000000000000000000080";
        let identity_noncanonical = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        let zero_sig = unhex(&format!("{identity}{}", "00".repeat(32)));
        for key in [identity, identity_sign, identity_noncanonical] {
            assert!(verify(&unhex(key), b"anything at all", &zero_sig), "{key}");
        }
        // ... but R is compared as bytes, so the same signature with R written non-canonically does not
        let noncanonical_r = unhex(&format!("{identity_noncanonical}{}", "00".repeat(32)));
        assert!(!verify(&unhex(identity), b"anything at all", &noncanonical_r));
        let sign_r = unhex(&format!("{identity_sign}{}", "00".repeat(32)));
        assert!(!verify(&unhex(identity), b"anything at all", &sign_r));
    }

    #[test]
    fn scalars_reduce_modulo_l() {
        let cases = [
            ("00", "00"),
            ("01", "01"),
            ("ecd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000", "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
            ("edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000", "00"),
            ("eed3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000", "01"),
            ("daa7ebb934c624b0ac39ef45bdf3bd29000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000", "00"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000", "1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903"),
            ("39300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080", "b021c9d07e3a0cfe0e98be05c38a76f232dffa0be93976e71e4d18be8da0cc09"),
            ("0700000000000000000000000000000000000000000000000000000000000000689faee7d21893c0b2e6bc17f5cef7a600000000000000000000000000000080", "0700000000000000000000000000000000000000000000000000000000000000"),
            ("6300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000efcdab8967452301", "e00d2fc2174202403d36251c13ea65b2a8b6149c89b06bfd35eb6af5dcbce80c"),
        ];
        for (wide, want) in cases {
            let mut w = [0u8; 64];
            let bytes = unhex(wide);
            w[..bytes.len()].copy_from_slice(&bytes);
            let mut expect = [0u8; 32];
            let e = unhex(want);
            expect[..e.len()].copy_from_slice(&e);
            assert_eq!(hex(&scalar_reduce(&w)), hex(&expect), "{wide}");
        }
        // canonical means below L
        let l = limbs_to_le(&L);
        assert!(!scalar_is_canonical(&l));
        let mut below = l;
        below[0] -= 1;
        assert!(scalar_is_canonical(&below));
        let mut above = l;
        above[0] += 1;
        assert!(!scalar_is_canonical(&above));
        assert!(scalar_is_canonical(&[0u8; 32]));
        assert!(!scalar_is_canonical(&[0xff; 32]));
    }

    #[test]
    fn the_group_law() {
        let b = Point::base();
        assert_eq!(hex(&b.encode()), "5866666666666666666666666666666666666666666666666666666666666666");
        assert_eq!(hex(&b.double().encode()), "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");
        assert_eq!(hex(&b.add(&b).encode()), hex(&b.double().encode()));
        assert_eq!(hex(&b.add(&b.double()).encode()), "d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712");
        assert_eq!(hex(&b.double().double().double().encode()), "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321");
        // [1000]B by the double-scalar routine, with k = 0 and s = 1000
        let mut s = [0u8; 32];
        s[..2].copy_from_slice(&1000u16.to_le_bytes());
        assert_eq!(hex(&double_scalar_mul_base(&[0; 32], &Point::IDENTITY, &s).encode()), "e7caaa83373a94afae43fec59b447c99ba282b19a7616c24c785ad8966a1e10e");
        // the order of B is L: [L]B is the identity and [L-1]B is -B
        let identity = "0100000000000000000000000000000000000000000000000000000000000000";
        let l = limbs_to_le(&L);
        assert_eq!(hex(&double_scalar_mul_base(&[0; 32], &Point::IDENTITY, &l).encode()), identity);
        let mut l1 = l;
        l1[0] -= 1;
        assert_eq!(hex(&double_scalar_mul_base(&[0; 32], &Point::IDENTITY, &l1).encode()), hex(&b.neg().encode()));
        // the two scalars act on their own points: [3]B + [5]B = [8]B
        let (mut k, mut s) = ([0u8; 32], [0u8; 32]);
        k[0] = 3;
        s[0] = 5;
        assert_eq!(hex(&double_scalar_mul_base(&k, &b, &s).encode()), "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321");
        // P + (-P) is the identity, and the identity is neutral
        assert_eq!(hex(&b.add(&b.neg()).encode()), identity);
        assert_eq!(hex(&b.add(&Point::IDENTITY).encode()), hex(&b.encode()));
        assert_eq!(hex(&Point::IDENTITY.double().encode()), identity);
    }

    #[test]
    fn points_of_small_order() {
        // the two generators of the points of order 8 that the vector generator found
        for enc in ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"] {
            let t = Point::decode(&arr32(enc)).expect("on the curve");
            assert_eq!(hex(&t.encode()), enc);
            let t4 = t.double().double();
            // order exactly 8: 4T is not the identity (it is the point of order 2, (0, -1)), 8T is
            assert_eq!(hex(&t4.encode()), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
            assert_eq!(hex(&t4.double().encode()), "0100000000000000000000000000000000000000000000000000000000000000");
        }
    }

    #[test]
    fn decoding_is_as_permissive_as_ref10_and_no_more() {
        let canonical = |s: &str| hex(&Point::decode(&arr32(s)).expect(s).encode());
        // y = p and y = p + 1 reduce to y = 0 and y = 1
        assert_eq!(canonical("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), "0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(canonical("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), "0100000000000000000000000000000000000000000000000000000000000000");
        // x = 0 with the sign bit set is accepted and means x = 0
        assert_eq!(canonical("0100000000000000000000000000000000000000000000000000000000000080"), "0100000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(canonical("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        // the sign bit picks the other root otherwise
        let b = Point::decode(&arr32("5866666666666666666666666666666666666666666666666666666666666666")).unwrap();
        let minus_b = Point::decode(&arr32("58666666666666666666666666666666666666666666666666666666666666e6")).unwrap();
        assert_eq!(hex(&b.neg().encode()), hex(&minus_b.encode()));
        // y = 2 is not on the curve ((y^2 - 1) / (d y^2 + 1) is not a square)
        assert!(Point::decode(&arr32("0200000000000000000000000000000000000000000000000000000000000000")).is_none());
    }

    /// (A, k, s, [k]A + [s]B) for random points A, computed with an independent implementation (Python
    /// integers, affine coordinates, tools/ed25519_vectors.py). The scalars are not reduced.
    const MULTIPLES: &[(&str, &str, &str, &str)] = &[
        ("3dd392cc02d0b240df956e5306318332acfb903db2fa70316a0593d217d94678", "bccfd54a23a7ea79e8a8faf35d30d28eee3fecffe352809c8c26e13cc6b3a704", "90dc4e8e025172a1a9323fa9329e288016009f008dece2d9ba2daa47dc40e800", "f65bce1ba2f6aeff2e34f089f2edc7de3b40bb13a024242cd675b7295d02ae92"),
        ("58f066984c724ab46130eb89b0518813a0698f196a9ce8d664d828cd38f0b47d", "6a0b4f148c65b7ea98db14c87c81c0c8a0a6b889d0a226f9790c421b7099b308", "abaddb71149a87a0561adfc6e96173eb4c69538dfba4a5f9d950191f6fc73e0b", "493dfde57f72a5754d79059f41bae234043e66332ed91b4f8a153c82984775a4"),
        ("2996d5efe7e89b87c9d16f0e911704d4a9c4d5d7c6cf92c57c5659f9a8a1b833", "acde190ae428efbe8b46a95b8fac99c2f8cb42fdb65ccc6e1b8b2e1e95793108", "3bd231c04ac85c6aa46e59930a972e007139ec0f3b234bcb588e3e7b8c98af04", "b4f44e980c277a883bece0fb126af4b954d6129fa418651f00eff6bfbce9dbeb"),
        ("9a8db8c22cb424d4167387c17312a5e72797d706ecb774b346ea19026c3cb51e", "ba7da3aa6199a1ecb2225d776d6d0b1de4cf32ddedfce763fc2b76f92d2a751e", "8a469993e50249b6b68673bbbf37e299e646d56a4235517dfdcca281dcb92311", "90f2dad41e7567b7a175fc4ddce6af42ca3c969bb96963682e66bf8cdc20464f"),
        ("8c62a249dc262874c3a1b7df2cde6930ab68af042e93829702fa8b7c3d570e09", "92d8d004cbd630bc1ffb2d24e3264202a65c0617dd729ca8aaa6d4e03898fe06", "d63ca982c4343b340697c1ad260a4515aaf76fc73d98d76c8844542aac72f106", "89ae93828e841e5b7ae3e0cee4dd0f92fb471b04e8981c17de272bf6340897bb"),
        ("445aa6db3fb20b86482bcf5220b2a4505ff1f3e9f9a99e31a3649fc61797f9a3", "6185f8b43245a2a87aa3264f2d59c6ec1c1c321426ff36461aded5ac4d6b9906", "8d2121251c7b37233d2a0c5cd3ccf3ed1fff13c804402fb21f008b0cd94a930d", "fb3a286b8ff063d125653bfd3cfb1a256bd8f431871577cc1ab104a2f6478633"),
        ("dd770b6e91352c0187ce0c1c53200e08f75c396096c5e6c7766b6a2058b7e884", "a6114ed172335e99fdbcc9ef564a4e418c9017a26e3d0be8acba32d308682a0b", "cdd64c7b1bfa383448b19f8a90b35b911c1afac430f6bfbc886d8d52472dc714", "4feace3d0e50ee19c40e6337763d125447adae5341f4769db0e6d1a34518cda4"),
        ("82cb31361b3d3ac9d6e8269d0af6f1a70aa97bfea6d9b4a553d7844e317e5cd2", "7b8aee560aa202f77f52eea4a4e8e76d7978fa307433cc8084492c802bc69c16", "6cd36b722bf9dc4a18916d4dd6c71b7e54e6433d97af2cb2bd1a3ff15e7b0406", "e135ce0fe244ac3a35a691607719ffa5bd2e59a28485dd2358a8b58c2afa9514"),
        ("738ed77acf0370964f0d88ae8f6b6611d89170471ba80d4a2a914d2cb56f807b", "9d1ff8612255c4e4cbdd672be261cd62737b666393fd0adef648e08d17777e1b", "f177c04800854b704301de82bf8de5dee9c71a7174833eae5aee409195c14e01", "a897b4a51112cb770ebf979296e71200f1bb3a8825fcbc49f837f7f2cc957eb0"),
        ("00d18d9336f794133fb16663f45ea25462150ce85cb5aef83d86885ff12818d4", "1120069996a942fff57b26dcd76e2b1c171ca759bd26345bda756a251fcee107", "62993f0614cd217978a0a4969a51d01976b97e8228b30fa22c1b816e2761d30e", "0bdca1e070c6293056944ee8c89a908cf67f65dda584844856d6869c1572df59"),
        ("5f5d7f82410eda5c571cb084862f083b6b119295550165e11359a3df22bbdd59", "853dafa9181dcda9f0d430cb16fc8b93113acff3da015eb783d923b8ed108d0a", "315de94d598d740da9ccf1bd406a9f8b32930089ac5d2416430f9f85eb2f110c", "c387989b1fa48793a7938389a4bab2cb5c259f4df5b20e0a9fa038c293f880ed"),
        ("22be858b4cb1c07a2efecd721a5f72bbd6ac3362c5c3e2b9c18c0b69c95f9bcb", "0c8e9c185e67a85e8395012b9df0551fca9caca3dc40347f3a7dcc3b38522b12", "df4e69ce180cffca2762e7818cf999f46e151450a371cebeb41a6a430d8d1b15", "6d90b83b6fbc8033e964b69394f5950eadb0ed65cabea32e406333eee3bf728c"),
        ("18a0d9f0edf9037afa57905dd1e931bdb4048c509485a33a631100e762925266", "02592d7f0946402e8ea0e6f285f8616656e8d47b50cffaf2743bbe68a1b6b509", "8593095ec7b22976575b31f63938ecdf9a34ee2ef2f3dc1a92a71bc3273a6f0a", "b1363d428e9837093529428a36ef0cd8e1dd72003cb7f009a27015383e68d2d8"),
        ("f384404a2f55f9442b9a267163fd0d3959dea6699fc5e3404dbb66b91862842b", "bcb440a648dfb2010b85408e5afd7ba80f63e4e61531dcfc5daa44c0813ff11e", "022ee8b4cf8fba0707a78dcad13e09b4970522b45f68896f79be79a476a0b918", "1cdf4aacc03a3d1b79efd50f63693b707ff31d3c9eded5b351353457b4d42b60"),
        ("b72d218b2b9da74518c473ae5ad2ee6474cfc51ab785c320a63ce7aa8fab3963", "3308f81d8ed83c83d94da7954ddd0607d89632237ac7da4edac0b06b38a60507", "b54cf1bb70eba08590dcdd3967423bc5c5d9c9b6ce06886e1f181466d2fd5718", "427e0c7fdab4134adb221166bb491366ad51ae13acbeb9d04dd359371c92046d"),
        ("a151f4b5ae07be65a317c7fabe2f61062524243324708435aa1e8309e7569e4f", "93164f92d218af8404e1a9bf157dbbfa87c93a27fdad612a480cf0f40a4b5213", "ebd3f973a7d695b2c57e4e23d77eeee5598c18110fcb5e8887213010babb9604", "ddf021b163ccfde1c4037e75ece3584a0fe0e405108e2640db85577699ade921"),
        ("2ca64c25d01b97e9c1a158869f85773b19004bbcb4a58fe630c16874b6b26969", "bf802cb4cf561be23e4fb9adfca15c0a5ca554fefed452d5dccdc01e1076c80e", "e943104fc56e9e0e5d136987d45e1e9e669585ca529bdc18ea511afe53564213", "66a4c8d350ae8b906b8f4d66bc3597801d1f80082b2bebef9d635a7643ab877c"),
        ("d2016def0673fce1a1fc09a0ae668fe69a66f204d5095b7f14846180467beb3c", "6a85afaa9e20bd0fa15943e3b2380abe6cecf3917fe9e6c27a7e8ad3b4842718", "02101d29e193aa94259f4238c39e5a0323393064f8857be0484a5bf2b3c3131f", "148954c6fe1ba3782528792faecc6ccf0aa8b1de874c5d53cfda040bb542ce60"),
        ("4af93e82683c0ddc119d48497fdb27e8dd3f7d0225dcda3f11377164b59a56af", "8c3487ae558946f661da7cd59aaac4837b119d5707ca98f82a6081bf15aba719", "60074daf2854f1af47ee1ede3daacf93a29f5f6c074ec56fe675be30a2418a00", "969defad3f61ff94876690dbd2958672d9c5c453abba043d8fdc0efa719c46c2"),
        ("a9056a4b4505ca33699c8d5650b172577f8ae94504f0273899438a7792261f46", "847c11e5f36c23e6ae35fb0ff2259d281c562b6b5a941d228fa64e6c989f5518", "77002bcf882d35670e16fa2fb643510af89e5eca4270bb955248278d0f584606", "161e04935fcef0aebb21bdd0a7845954bcebbebc07925a4f76d73717c79f02cb"),
    ];

    /// The windowed double-scalar multiplication (B-103) gives the plain one's point for random scalars over all of
    /// 0..2^256, the ends of that range, and points of every order (random encodings, about half of which decode),
    /// the identity and the base point.
    #[test]
    fn the_windowed_multiplication_agrees_with_the_plain_one() {
        let mut rng = crate::fuzz::Rng::new(0xed25519);
        let mut points = vec![Point::IDENTITY, Point::base(), Point::base().neg()];
        while points.len() < 40 {
            if let Some(p) = Point::decode(&rng.bytes(32).try_into().unwrap()) {
                points.push(p);
            }
        }
        let mut scalars: Vec<[u8; 32]> = vec![[0u8; 32], [0xffu8; 32], [1u8; 32]];
        let mut one = [0u8; 32];
        one[0] = 1;
        scalars.push(one);
        for _ in 0..40 {
            scalars.push(rng.bytes(32).try_into().unwrap());
        }
        for (i, p) in points.iter().enumerate() {
            for j in 0..scalars.len() {
                let (k, s) = (scalars[j], scalars[(j * 7 + i) % scalars.len()]);
                let want = double_scalar_mul_base_plain(&k, p, &s).encode();
                assert_eq!(double_scalar_mul_base(&k, p, &s).encode(), want, "point {i}, scalars {j}");
            }
        }
    }

    /// The signed digits add up to the scalar, are odd or zero, below 2^(w-1) in size and at least w apart.
    #[test]
    fn the_signed_digits_represent_the_scalar() {
        let mut rng = crate::fuzz::Rng::new(0x5a1e);
        for t in 0..300 {
            let k: [u8; 32] = if t == 0 { [0xffu8; 32] } else { rng.bytes(32).try_into().unwrap() };
            for w in [5usize, 8] {
                let d = wnaf(&k, w);
                // the sum, in 64-bit limbs with a fifth for the carry, as a signed 2-adic sum
                let mut acc = [0i128; 6];
                for (i, &digit) in d.iter().enumerate() {
                    if digit != 0 {
                        assert!(digit % 2 != 0 && (digit.unsigned_abs() as i32) < (1 << (w - 1)), "digit {digit}");
                        acc[i / 64] += (digit as i128) << (i % 64);
                    }
                }
                for i in 0..5 {
                    let c = acc[i] >> 64;
                    acc[i] -= c << 64;
                    acc[i + 1] += c;
                }
                let want = limbs_from_le(&k);
                for i in 0..4 {
                    assert_eq!(acc[i] as u64, want[i], "w = {w}");
                }
                assert_eq!(acc[4], 0, "w = {w}");
                let nz: Vec<usize> = (0..257).filter(|&i| d[i] != 0).collect();
                assert!(nz.windows(2).all(|p| p[1] - p[0] >= w), "w = {w}: digits too close");
            }
        }
    }

    #[test]
    fn double_scalar_multiplication_agrees_with_an_independent_implementation() {
        for (a, k, s, want) in MULTIPLES {
            let p = Point::decode(&arr32(a)).expect(a);
            assert_eq!(hex(&double_scalar_mul_base(&arr32(k), &p, &arr32(s)).encode()), *want, "A = {a}");
        }
    }

    /// The group laws on points that come from random bytes (about half of all strings decode), which
    /// covers points of every order and the unreduced and sign-bit encodings.
    #[test]
    fn the_group_laws_hold_on_arbitrary_points() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let mut points = Vec::new();
        while points.len() < 24 {
            let mut b = [0u8; 32];
            for chunk in b.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            if let Some(p) = Point::decode(&b) {
                points.push(p);
            }
        }
        let e = |p: &Point| hex(&p.encode());
        for w in points.windows(3) {
            let (p, q, r) = (w[0], w[1], w[2]);
            assert_eq!(e(&p.add(&q)), e(&q.add(&p)));
            assert_eq!(e(&p.add(&q).add(&r)), e(&p.add(&q.add(&r))));
            assert_eq!(e(&p.double()), e(&p.add(&p)));
            assert_eq!(e(&p.add(&p.neg())), e(&Point::IDENTITY));
            assert_eq!(e(&p.add(&Point::IDENTITY)), e(&p));
            // the encoding decodes to the same point
            assert_eq!(e(&Point::decode(&p.encode()).unwrap()), e(&p));
            // [3]p + [5]B = [3]p + [5]B computed in two pieces
            let (mut k, mut s) = ([0u8; 32], [0u8; 32]);
            k[0] = 3;
            s[0] = 5;
            let whole = double_scalar_mul_base(&k, &p, &s);
            let parts = double_scalar_mul_base(&k, &p, &[0; 32]).add(&double_scalar_mul_base(&[0; 32], &p, &s));
            assert_eq!(e(&whole), e(&parts));
            assert_eq!(e(&double_scalar_mul_base(&k, &p, &[0; 32])), e(&p.add(&p).add(&p)));
        }
    }
}
