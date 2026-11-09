//! Portable, constant-time AES (FIPS 197): the cipher is *bitsliced*, so it contains no table
//! lookups and no secret-dependent branches or addresses, on any CPU.
//!
//! Four blocks are processed at once. The 64 bytes of the four blocks are spread over eight
//! `u64` "planes": plane `i` holds bit `i` of every byte. The state byte of block `b` at row `r` and
//! column `c` (byte `16 b + 4 c + r` of the input, the order FIPS 197 uses) is lane
//! `16 r + 4 b + c` of a plane (bit of the `u64`): a row of all four blocks is one 16-bit field, so
//! that turning the rows of every column (in `MixColumns`) is a rotation of the whole word. In this form
//!
//! * `SubBytes` uses the independently derived quadratic field tower and FIPS 197 affine map
//!   in `aes_sbox_tower_clean`, using Boolean operations on all 64 bytes at once;
//! * `ShiftRows` and `MixColumns` are lane permutations (masks and shifts);
//! * `AddRoundKey` is an `XOR` with the round key spread over the planes the same way.
//!
//! It is not as fast as AES-NI (see [`super::aes_hw`], which is used instead when the CPU has
//! it) but it is not a table either. The key schedule uses the same circuit for `SubWord`, so
//! the key never indexes memory.

use super::aes_sbox_tower_clean::sbox;
use crate::zeroize::Zeroize;

type Planes = [u64; 8];

/// Largest key schedule: AES-256 has 14 rounds, so 15 round keys.
pub(super) const MAX_ROUND_KEYS: usize = 15;

// ---- bit-plane packing ---------------------------------------------------------------------

/// Transposes an 8x8 bit matrix held in a `u64` (bit `8 * r + c` is row `r`, column `c`): three
/// rounds of swapping blocks across the diagonal (Hacker's Delight, section 7-3).
#[inline(always)]
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^ t ^ (t << 28)
}

/// The input byte that goes to each lane: lane `16 r + 4 b + c` holds byte `16 b + 4 c + r`.
const LANE_BYTE: [u8; 64] = {
    let mut t = [0u8; 64];
    let mut lane = 0;
    while lane < 64 {
        let (r, b, c) = (lane / 16, (lane / 4) % 4, lane % 4);
        t[lane] = (16 * b + 4 * c + r) as u8;
        lane += 1;
    }
    t
};

/// Spreads 64 bytes over eight planes: bit `i` of byte `LANE_BYTE[j]` becomes bit `j` of `planes[i]`.
///
/// The bytes are put in lane order first; then each group of eight is an 8x8 bit matrix (row = byte,
/// column = bit), whose transpose has one byte per plane, which goes to the group's eight lanes of that plane.
fn pack(input: &[u8; 64]) -> Planes {
    let mut bytes = [0u8; 64];
    for (lane, b) in bytes.iter_mut().enumerate() {
        *b = input[LANE_BYTE[lane] as usize];
    }
    let mut p = [0u64; 8];
    for g in 0..8 {
        let w = transpose8(u64::from_le_bytes(
            bytes[8 * g..8 * g + 8].try_into().unwrap(),
        ));
        for (i, plane) in p.iter_mut().enumerate() {
            *plane |= ((w >> (8 * i)) & 0xff) << (8 * g);
        }
    }
    p
}

/// The inverse of [`pack`].
fn unpack(p: &Planes) -> [u8; 64] {
    let mut lanes = [0u8; 64];
    for g in 0..8 {
        let mut w = 0u64;
        for (i, plane) in p.iter().enumerate() {
            w |= ((plane >> (8 * g)) & 0xff) << (8 * i);
        }
        lanes[8 * g..8 * g + 8].copy_from_slice(&transpose8(w).to_le_bytes());
    }
    let mut out = [0u8; 64];
    for (lane, b) in lanes.iter().enumerate() {
        out[LANE_BYTE[lane] as usize] = *b;
    }
    lanes.zeroize();
    out
}

// ---- GF(2^8) on planes (the tests check the products against the textbook ones) -------------

/// Reduces a 15-term polynomial product modulo x^8 + x^4 + x^3 + x + 1.
#[cfg(test)]
fn reduce(mut t: [u64; 15]) -> Planes {
    // x^k = x^(k-4) + x^(k-5) + x^(k-7) + x^(k-8) for k >= 8; going down means a term that a
    // higher one folded into is itself folded later.
    for k in (8..15).rev() {
        let v = t[k];
        t[k - 4] ^= v;
        t[k - 5] ^= v;
        t[k - 7] ^= v;
        t[k - 8] ^= v;
    }
    [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]
}

/// Lane-wise product in GF(2^8).
#[cfg(test)]
fn gf_mul(a: &Planes, b: &Planes) -> Planes {
    let mut t = [0u64; 15];
    for i in 0..8 {
        for j in 0..8 {
            t[i + j] ^= a[i] & b[j];
        }
    }
    reduce(t)
}

/// Lane-wise square in GF(2^8); linear, so it costs no `AND`s.
#[cfg(test)]
fn gf_sq(a: &Planes) -> Planes {
    let mut t = [0u64; 15];
    for i in 0..8 {
        t[2 * i] = a[i];
    }
    reduce(t)
}

// ---- ShiftRows and MixColumns as lane permutations -----------------------------------------

/// The lanes of row `r` whose column `c` has `c + r < 4` (`low`), or `c + r >= 4`.
const fn row_mask(r: usize, low: bool) -> u64 {
    let mut m = 0u64;
    let mut b = 0;
    while b < 4 {
        let mut c = 0;
        while c < 4 {
            if (c + r < 4) == low {
                m |= 1u64 << (16 * r + 4 * b + c);
            }
            c += 1;
        }
        b += 1;
    }
    m
}

const ROW0: u64 = 0xffff;
const LOW: [u64; 4] = [
    row_mask(0, true),
    row_mask(1, true),
    row_mask(2, true),
    row_mask(3, true),
];
const HIGH: [u64; 4] = [
    row_mask(0, false),
    row_mask(1, false),
    row_mask(2, false),
    row_mask(3, false),
];

/// New state byte (column c, row r) is old byte (column (c + r) % 4, row r): in row r's field, each
/// block's four lanes (one per column) turn by r places.
#[inline(always)]
fn shift_rows_plane(x: u64) -> u64 {
    (x & ROW0)
        | ((x >> 1) & LOW[1])
        | ((x << 3) & HIGH[1])
        | ((x >> 2) & LOW[2])
        | ((x << 2) & HIGH[2])
        | ((x >> 3) & LOW[3])
        | ((x << 1) & HIGH[3])
}

/// Rotates the four rows of every column: new row r is old row (r + 1) % 4 (a row is a 16-bit field).
#[inline(always)]
fn rot_rows_1(x: u64) -> u64 {
    x.rotate_right(16)
}

/// New row r is old row (r + 2) % 4.
#[inline(always)]
fn rot_rows_2(x: u64) -> u64 {
    x.rotate_right(32)
}

#[inline(always)]
fn shift_rows(s: &mut Planes) {
    for p in s.iter_mut() {
        *p = shift_rows_plane(*p);
    }
}

/// Multiplication by x in GF(2^8) on every lane.
#[inline(always)]
fn xtime(u: &Planes) -> Planes {
    let h = u[7];
    [h, u[0] ^ h, u[1], u[2] ^ h, u[3] ^ h, u[4], u[5], u[6]]
}

/// Column c becomes (2a0 + 3a1 + a2 + a3, a0 + 2a1 + 3a2 + a3, ...). With u = a + rot1(a) this is
/// rot1(a) + rot2(u) + xtime(u): for row 0, `a1 + (a2 + a3) + 2 (a0 + a1)`.
#[inline(always)]
fn mix_columns(s: &mut Planes) {
    let mut u = [0u64; 8];
    for i in 0..8 {
        u[i] = s[i] ^ rot_rows_1(s[i]);
    }
    let x = xtime(&u);
    for i in 0..8 {
        s[i] = rot_rows_1(s[i]) ^ rot_rows_2(u[i]) ^ x[i];
    }
}

// ---- keys ----------------------------------------------------------------------------------

/// The expanded key in the form the cipher uses: every round key spread over the planes, and
/// repeated for each of the four blocks.
#[derive(Clone)]
pub(super) struct Keys {
    rk: [Planes; MAX_ROUND_KEYS],
    rounds: usize,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Keys {
    pub(super) fn new(key: &[u8]) -> Keys {
        let (bytes, rounds) = expand_key(key);
        let mut rk = [[0u64; 8]; MAX_ROUND_KEYS];
        for r in 0..=rounds {
            let mut four = [0u8; 64];
            for b in 0..4 {
                four[16 * b..16 * b + 16].copy_from_slice(&bytes[r]);
            }
            rk[r] = pack(&four);
            four.zeroize();
        }
        let mut bytes = bytes;
        bytes.zeroize();
        Keys { rk, rounds }
    }

    pub(super) fn wipe(&mut self) {
        self.rk.zeroize();
        self.rounds = 0;
    }

    #[cfg(test)]
    pub(super) fn is_wiped(&self) -> bool {
        self.rounds == 0 && self.rk.iter().flatten().all(|&w| w == 0)
    }

    /// Encrypts four blocks (64 bytes) in place.
    pub(super) fn encrypt4(&self, blocks: &mut [u8; 64]) {
        let mut s = pack(blocks);
        add_round_key(&mut s, &self.rk[0]);
        for r in 1..self.rounds {
            s = sbox(&s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            add_round_key(&mut s, &self.rk[r]);
        }
        s = sbox(&s);
        shift_rows(&mut s);
        add_round_key(&mut s, &self.rk[self.rounds]);
        *blocks = unpack(&s);
        s.zeroize();
    }
}

#[inline(always)]
fn add_round_key(s: &mut Planes, k: &Planes) {
    for i in 0..8 {
        s[i] ^= k[i];
    }
}

/// SubWord on a word: the four bytes go through the same circuit as the cipher's.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut buf = [0u8; 64];
    buf[..4].copy_from_slice(&w);
    let planes = sbox(&pack(&buf));
    let out = unpack(&planes);
    buf.zeroize();
    [out[0], out[1], out[2], out[3]]
}

/// The AES key schedule (FIPS 197 section 5.2) for a 16- or 32-byte key: the round keys as bytes
/// (16 per round key, in state order) and the number of rounds. Constant time: the only
/// secret-dependent step, SubWord, uses the bitsliced S-box.
pub(super) fn expand_key(key: &[u8]) -> ([[u8; 16]; MAX_ROUND_KEYS], usize) {
    assert!(
        key.len() == 16 || key.len() == 32,
        "unsupported AES key length"
    );
    let nk = key.len() / 4;
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let mut w = [[0u8; 4]; 4 * MAX_ROUND_KEYS];
    for i in 0..nk {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    let mut rcon: u8 = 1;
    for i in nk..total_words {
        let mut t = w[i - 1];
        if i % nk == 0 {
            t = sub_word([t[1], t[2], t[3], t[0]]);
            t[0] ^= rcon;
            // rcon is a public constant sequence: no secret is involved in this step
            rcon = (rcon << 1) ^ (if rcon & 0x80 != 0 { 0x1b } else { 0 });
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        let p = w[i - nk];
        w[i] = [p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]];
    }
    let mut out = [[0u8; 16]; MAX_ROUND_KEYS];
    for r in 0..=nr {
        for c in 0..4 {
            out[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    w.zeroize();
    (out, nr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic generator for test inputs.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 24
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.next() as u8;
            }
        }
    }

    #[test]
    fn pack_and_unpack_are_inverse_and_a_row_of_all_blocks_is_one_field() {
        let mut rng = Lcg(1);
        for _ in 0..50 {
            let mut b = [0u8; 64];
            rng.fill(&mut b);
            let p = pack(&b);
            assert_eq!(unpack(&p), b);
            // bit i of the byte of block b, row r, column c (input byte 16 b + 4 c + r) is bit 16 r + 4 b + c of plane i
            for blk in 0..4 {
                for r in 0..4 {
                    for c in 0..4 {
                        let (byte, lane) = (16 * blk + 4 * c + r, 16 * r + 4 * blk + c);
                        for i in 0..8 {
                            assert_eq!((p[i] >> lane) & 1, ((b[byte] >> i) & 1) as u64);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn sbox_matches_the_table_for_all_256_inputs() {
        let table = crate::crypto::aes::reference::sbox_table();
        // 64 lanes per call
        for base in (0..256).step_by(64) {
            let mut b = [0u8; 64];
            for (j, v) in b.iter_mut().enumerate() {
                *v = (base + j) as u8;
            }
            let out = unpack(&sbox(&pack(&b)));
            for j in 0..64 {
                assert_eq!(out[j], table[base + j], "S-box of {:#04x}", base + j);
            }
        }
    }

    #[test]
    fn clean_tower_sbox_every_byte_in_every_lane() {
        let table = crate::crypto::aes::reference::sbox_table();
        for byte in 0..256usize {
            for lane in 0..64 {
                let q = core::array::from_fn(|plane| (((byte >> plane) & 1) as u64) << lane);
                let actual = sbox(&q);
                for out_lane in 0..64 {
                    let value = actual.iter().enumerate().fold(0u8, |value, (plane, bits)| {
                        value | (((bits >> out_lane) & 1) as u8) << plane
                    });
                    assert_eq!(value, table[if out_lane == lane { byte } else { 0 }]);
                }
            }
        }
    }

    #[test]
    fn clean_tower_sbox_ten_thousand_mixed_plane_inputs() {
        let table = crate::crypto::aes::reference::sbox_table();
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..10_000 {
            let q = core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            });
            let actual = sbox(&q);
            for lane in 0..64 {
                let byte = q.iter().enumerate().fold(0usize, |byte, (plane, bits)| {
                    byte | (((bits >> lane) & 1) as usize) << plane
                });
                let value = actual.iter().enumerate().fold(0u8, |value, (plane, bits)| {
                    value | (((bits >> lane) & 1) as u8) << plane
                });
                assert_eq!(value, table[byte]);
            }
        }
    }

    #[test]
    fn gf_mul_and_square_agree_with_the_textbook_product() {
        fn slow(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0;
            for _ in 0..8 {
                if b & 1 != 0 {
                    p ^= a;
                }
                let hi = a & 0x80;
                a <<= 1;
                if hi != 0 {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            p
        }
        let mut rng = Lcg(2);
        for _ in 0..20 {
            let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
            rng.fill(&mut x);
            rng.fill(&mut y);
            let prod = unpack(&gf_mul(&pack(&x), &pack(&y)));
            let sq = unpack(&gf_sq(&pack(&x)));
            for j in 0..64 {
                assert_eq!(prod[j], slow(x[j], y[j]));
                assert_eq!(sq[j], slow(x[j], x[j]));
            }
        }
    }

    #[test]
    fn shift_rows_and_mix_columns_match_the_byte_definitions() {
        let mut rng = Lcg(3);
        for _ in 0..20 {
            let mut b = [0u8; 64];
            rng.fill(&mut b);
            let mut s = pack(&b);
            shift_rows(&mut s);
            let got = unpack(&s);
            for blk in 0..4 {
                for c in 0..4 {
                    for r in 0..4 {
                        assert_eq!(
                            got[16 * blk + 4 * c + r],
                            b[16 * blk + 4 * ((c + r) % 4) + r],
                            "shift_rows"
                        );
                    }
                }
            }
            let mut s = pack(&b);
            mix_columns(&mut s);
            let got = unpack(&s);
            let mul2 = |x: u8| (x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0 });
            let mul3 = |x: u8| mul2(x) ^ x;
            for blk in 0..4 {
                for c in 0..4 {
                    let a: [u8; 4] = core::array::from_fn(|r| b[16 * blk + 4 * c + r]);
                    for r in 0..4 {
                        let want =
                            mul2(a[r]) ^ mul3(a[(r + 1) % 4]) ^ a[(r + 2) % 4] ^ a[(r + 3) % 4];
                        assert_eq!(got[16 * blk + 4 * c + r], want, "mix_columns");
                    }
                }
            }
        }
    }

    #[test]
    fn key_schedule_matches_the_table_based_reference() {
        let mut rng = Lcg(4);
        for len in [16usize, 32] {
            for _ in 0..10 {
                let mut key = vec![0u8; len];
                rng.fill(&mut key);
                let (got, nr) = expand_key(&key);
                let (want, want_nr) = crate::crypto::aes::reference::expand_key(&key);
                assert_eq!(nr, want_nr);
                assert_eq!(&got[..=nr], &want[..=nr]);
            }
        }
    }

    #[test]
    fn wipe_clears_the_round_keys() {
        let mut k = Keys::new(&[0x42u8; 32]);
        assert!(!k.is_wiped());
        assert!(k.rk[0].iter().any(|&w| w != 0));
        k.wipe();
        assert!(k.is_wiped());
    }
}
