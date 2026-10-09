//! X25519 key generation by a table: [k]B for the base point B of edwards25519, in constant time, mapped to the
//! u-coordinate X25519 uses (B-103). It gives what the Montgomery ladder gives for u = 9 (`x25519(k, BASE_POINT)`), in
//! about a third of the field operations.
//!
//! This is ref10's `ge_scalarmult_base`. The scalar is written as 64 signed digits of 4 bits, -8 to 8, and a table holds
//! j 256^i B for i below 32 and j from 1 to 8 (made once for the process, from public values). Then
//! [k]B = 16 (sum of the odd digits' entries) + (sum of the even digits' entries): 64 additions of an affine point and
//! 4 doublings, where the ladder makes 255 steps of 9 products and squares.
//!
//! Constant time, as the ladder is:
//!
//! * the digits come from shifts, masks and additions of the scalar's bytes, the same for every scalar;
//! * each lookup reads all 8 entries of its row (the row is a public loop index) and keeps the one it needs with masks,
//!   and a negative digit negates the entry with a mask; a zero digit keeps the identity, also with masks;
//! * the additions and doublings are the same field operations on every input (the formulas of `ed25519.rs`, which
//!   are branch-free; the extended addition law has no exceptional cases on this curve, so the identity and repeated
//!   points need no special treatment);
//! * the conversion at the end is one inversion by a fixed chain of products and squares.
//!
//! So neither a branch nor a memory address depends on the scalar. `crypto::timing` checks it like the ladder.

use super::ed25519::{Affine, Point, Projective};
use super::fe25519::Fe;
use crate::zeroize::Zeroize;
use std::sync::OnceLock;

/// The u-coordinate of [k]B (32 bytes, as X25519 encodes it), for a scalar below 2^255, such as a clamped X25519
/// scalar.
pub(crate) fn public_u(k: &[u8; 32]) -> [u8; 32] {
    let mut p = mul_base(k);
    // edwards25519 to curve25519: u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y). [k]B is never the identity (where Z = Y)
    // for a clamped k: k is 8 m with 2^251 <= m < 2^252 < L, so m is not a multiple of L, B's order.
    let u = p.z.add(p.y).mul(p.z.sub(p.y).invert()).to_bytes();
    for c in [&mut p.x, &mut p.y, &mut p.z, &mut p.t] {
        c.0.zeroize();
    }
    u
}

/// [k]B in extended coordinates, for k < 2^255 (little endian).
pub(super) fn mul_base(k: &[u8; 32]) -> Point {
    debug_assert!(k[31] < 128, "a scalar below 2^255");
    // 4-bit digits 0 to 15 (the top one 0 to 7), then signed: a digit of 8 or more becomes digit - 16 and carries 1
    let mut e = [0i8; 64];
    for i in 0..32 {
        e[2 * i] = (k[i] & 15) as i8;
        e[2 * i + 1] = (k[i] >> 4) as i8;
    }
    let mut carry = 0i8;
    for d in e.iter_mut().take(63) {
        *d += carry;
        carry = (*d + 8) >> 4;
        *d -= carry << 4;
    }
    e[63] += carry;

    let table = table();
    let mut h = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };
    for i in (1..64).step_by(2) {
        h = h.add_affine(&select(&table[i / 2], e[i])).to_extended();
    }
    // times 16
    let mut s = Projective { x: h.x, y: h.y, z: h.z };
    for _ in 0..3 {
        s = s.double().to_projective();
    }
    h = s.double().to_extended();
    for i in (0..64).step_by(2) {
        h = h.add_affine(&select(&table[i / 2], e[i])).to_extended();
    }
    e.zeroize();
    for c in [&mut s.x, &mut s.y, &mut s.z] {
        c.0.zeroize();
    }
    h
}

/// The entry for `digit` (-8 to 8) of a row: |digit| times the row's point, negated if the digit is negative, the
/// identity (1, 1, 0) for 0. Every entry is read; the choice is made with masks.
fn select(row: &[Affine; 8], digit: i8) -> Affine {
    let negative = ((digit as u8) >> 7) as u64;
    let sign = digit >> 7; // -1 or 0
    let size = ((digit ^ sign) - sign) as u64; // |digit|, 0 to 8
    let mut t = Affine { ypx: Fe::ONE, ymx: Fe::ONE, xy2d: Fe::ZERO };
    for (j, entry) in row.iter().enumerate() {
        // 1 where size == j + 1: (size ^ (j + 1)) - 1 has its top bit set only when the xor is 0
        let hit = (size ^ (j as u64 + 1)).wrapping_sub(1) >> 63;
        cmov(&mut t.ypx, &entry.ypx, hit);
        cmov(&mut t.ymx, &entry.ymx, hit);
        cmov(&mut t.xy2d, &entry.xy2d, hit);
    }
    // -(x, y) = (-x, y): y + x and y - x trade places, 2dxy changes sign
    let minus = Affine { ypx: t.ymx, ymx: t.ypx, xy2d: t.xy2d.neg() };
    cmov(&mut t.ypx, &minus.ypx, negative);
    cmov(&mut t.ymx, &minus.ymx, negative);
    cmov(&mut t.xy2d, &minus.xy2d, negative);
    t
}

/// a = b if `choice` is 1, unchanged if it is 0, by a mask.
#[inline]
fn cmov(a: &mut Fe, b: &Fe, choice: u64) {
    let mask = 0u64.wrapping_sub(choice);
    for i in 0..5 {
        a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
    }
}

/// j 256^i B for i below 32 and j from 1 to 8, in affine form (y + x, y - x, 2dxy), made once for the process: 256
/// points by additions and doublings, then one inversion for all their Z coordinates (Montgomery's trick: the products
/// of the first k, the inverse of the product of all, then each inverse from those by two products).
fn table() -> &'static [[Affine; 8]; 32] {
    static TABLE: OnceLock<[[Affine; 8]; 32]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut points = [Point::base(); 256];
        let mut row = Point::base(); // 256^i B
        for i in 0..32 {
            let mut q = row;
            for j in 0..8 {
                points[8 * i + j] = q;
                q = q.add(&row);
            }
            for _ in 0..8 {
                row = row.double();
            }
        }
        let mut before = [Fe::ONE; 256]; // the product of the Z of the points before each
        let mut all = Fe::ONE;
        for (b, p) in before.iter_mut().zip(&points) {
            *b = all;
            all = all.mul(p.z);
        }
        let mut inv = all.invert(); // then the inverse of the product of the Z up to the current point
        let mut out = [[Affine { ypx: Fe::ONE, ymx: Fe::ONE, xy2d: Fe::ZERO }; 8]; 32];
        for k in (0..256).rev() {
            out[k / 8][k % 8] = points[k].to_affine_given(inv.mul(before[k]));
            inv = inv.mul(points[k].z);
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x25519::{x25519, BASE_POINT};

    fn rng(seed: &mut u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            chunk.copy_from_slice(&seed.to_le_bytes());
        }
        out
    }

    fn clamp(mut k: [u8; 32]) -> [u8; 32] {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }

    /// The table holds what it says: entry (i, j) is (j + 1) 256^i B, checked against points made by the verifier's
    /// code, one inversion each.
    #[test]
    fn the_table_holds_the_multiples_of_the_base_point() {
        let table = table();
        let mut row = Point::base();
        for (i, entries) in table.iter().enumerate() {
            let mut q = row;
            for (j, entry) in entries.iter().enumerate() {
                let zinv = q.z.invert();
                let want = q.to_affine_given(zinv);
                assert!(entry.ypx.equals(want.ypx) && entry.ymx.equals(want.ymx) && entry.xy2d.equals(want.xy2d), "entry {i}, {j}");
                q = q.add(&row);
            }
            for _ in 0..8 {
                row = row.double();
            }
        }
    }

    /// Every digit, -8 to 8, selects the right entry or its negative, or the identity.
    #[test]
    fn every_digit_selects_its_entry() {
        let row = &table()[3];
        for digit in -8i8..=8 {
            let got = select(row, digit);
            let (ypx, ymx, xy2d) = match digit {
                0 => (Fe::ONE, Fe::ONE, Fe::ZERO),
                d if d > 0 => {
                    let e = &row[d as usize - 1];
                    (e.ypx, e.ymx, e.xy2d)
                }
                d => {
                    let e = &row[(-d) as usize - 1];
                    (e.ymx, e.ypx, e.xy2d.neg())
                }
            };
            assert!(got.ypx.equals(ypx) && got.ymx.equals(ymx) && got.xy2d.equals(xy2d), "digit {digit}");
        }
    }

    /// [k]B by the table equals [k]B by the verifier's (variable-time, independently written) multiplication, for
    /// scalars whose digits hit every value and sign, carries running the whole length, and random ones.
    #[test]
    fn the_table_multiplication_agrees_with_the_verifiers() {
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut scalars = vec![[0u8; 32], [0x77u8; 32], [0x88; 32], [0x99; 32], [0x11; 32], [0xff; 32]];
        scalars[5][31] = 0x7f;
        let mut one = [0u8; 32];
        one[0] = 1;
        scalars.push(one);
        for d in 0..16u8 {
            scalars.push([d | (d << 4); 32]);
        }
        for _ in 0..64 {
            let mut k = rng(&mut seed);
            k[31] &= 127;
            scalars.push(k);
        }
        let base = Point::base();
        for k in &scalars {
            let mut k = *k;
            k[31] &= 127;
            let want = crate::crypto::ed25519::double_scalar_mul_base(&[0u8; 32], &base, &k).encode();
            assert_eq!(mul_base(&k).encode(), want, "k = {k:02x?}");
        }
    }

    /// And the u-coordinate is the ladder's, for the RFC 7748 keys and random clamped scalars.
    #[test]
    fn the_u_coordinate_is_the_ladders() {
        let mut seed = 0xfeed_face_cafe_beefu64;
        for _ in 0..200 {
            let k = clamp(rng(&mut seed));
            assert_eq!(public_u(&k), x25519(&k, &BASE_POINT), "k = {k:02x?}");
        }
        for k in [[0u8; 32], [0xff; 32], [0x88; 32]] {
            let k = clamp(k);
            assert_eq!(public_u(&k), x25519(&k, &BASE_POINT));
        }
    }
}
