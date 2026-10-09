//! X25519 Diffie-Hellman (RFC 7748) with 5 x 51-bit limb field arithmetic.
//! The Montgomery ladder uses constant-time conditional swaps and no
//! secret-dependent branches or table lookups. Key generation ([`public_key`]) uses a table of
//! multiples of the base point instead (`x25519_base`), every entry of a row read at each lookup, so it
//! has no secret-dependent branches or memory addresses either.

use super::dit::Dit;
use super::fe25519::{Fe, MASK51};
use crate::zeroize::Zeroize;

/// `a * k` for a small constant `k` (the ladder's 121665).
#[inline(always)]
fn mul_small(a: Fe, k: u64) -> Fe {
    let mut c = [0u128; 5];
    for i in 0..5 {
        c[i] = a.0[i] as u128 * k as u128;
    }
    let m = MASK51 as u128;
    for i in 0..4 {
        c[i + 1] += c[i] >> 51;
        c[i] &= m;
    }
    let carry = (c[4] >> 51) as u64;
    c[4] &= m;
    let mut r = [c[0] as u64, c[1] as u64, c[2] as u64, c[3] as u64, c[4] as u64];
    r[0] += carry * 19;
    Fe(r).carry()
}

#[inline(always)]
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// The X25519 function: scalar multiplication of the u-coordinate `u` by `scalar`.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let _dit = Dit::on(); // data-independent timing while the secret is in use (crypto::dit)
    #[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
    if bmi2::available() {
        // SAFETY: the CPU has BMI2, just checked.
        return unsafe { bmi2::ladder(scalar, u) };
    }
    ladder(scalar, u)
}

/// The same ladder compiled for x86-64 CPUs with BMI2 (B-104): its `mulx` multiplies without touching the flags, which
/// frees the compiler's scheduling of the field products, about a tenth quicker. The code is the same as the plain
/// ladder's (`ladder` and the field operations it uses are `#[inline(always)]`, so this copy is all compiled with the
/// feature); `mulx`, like `mul`, takes the same time for every operand, so it is as constant time.
#[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
mod bmi2 {
    pub(super) fn available() -> bool {
        std::is_x86_feature_detected!("bmi2")
    }

    /// # Safety
    /// Only on a CPU with BMI2 (`available()`).
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        super::ladder(scalar, u)
    }
}

/// The Montgomery ladder of RFC 7748 section 5, with the scalar clamped.
#[inline(always)]
fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= k_t;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = k_t;

        // every sum and difference here goes into a product, and every operand of one is the output of a product
        // (or of `mul_small`), so they skip the carry pass (`Fe::add_lazy`, `Fe::sub_lazy`, B-103)
        let a = x2.add_lazy(z2);
        let aa = a.square();
        let b = x2.sub_lazy(z2);
        let bb = b.square();
        let e = aa.sub_lazy(bb);
        let c = x3.add_lazy(z3);
        let d = x3.sub_lazy(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add_lazy(cb).square();
        z3 = x1.mul(da.sub_lazy(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add_lazy(mul_small(e, 121665)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    let out = x2.mul(z2.invert()).to_bytes();
    // Best effort: clear the clamped scalar and the ladder state that depends on it.
    k.zeroize();
    x2.0.zeroize();
    z2.0.zeroize();
    x3.0.zeroize();
    z3.0.zeroize();
    out
}

/// A deliberately NOT constant-time copy of the ladder (it does extra work when a scalar bit is
/// set), used only as a positive control for the timing harness in `timing.rs`: the harness must
/// flag it, otherwise a clean result for the real function would mean nothing.
#[cfg(test)]
pub(crate) fn x25519_leaky_control(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    for t in (0..255).rev() {
        let k_t = (k[t / 8] >> (t % 8)) & 1;
        if k_t == 1 {
            // secret-dependent extra work, as in a textbook square-and-multiply
            x3 = std::hint::black_box(x3.mul(x2));
        }
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(mul_small(e, 121665)));
    }
    x2.mul(z2.invert()).to_bytes()
}

pub const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Derives the public key for a private scalar: what `x25519(private, &BASE_POINT)` gives, by a table of multiples of
/// the base point instead of the ladder (`x25519_base`: constant time like the ladder, and about twice as quick, B-103).
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    let _dit = Dit::on();
    let mut k = *private;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let u = super::x25519_base::public_u(&k);
    k.zeroize();
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    fn arr(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// The ladder as it was before B-103: every sum and difference carried, a squaring as a product.
    fn reference(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        let mut k = *scalar;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        let x1 = Fe::from_bytes(u);
        let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
        let mut swap = 0u64;
        for t in (0..255).rev() {
            let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
            swap ^= k_t;
            cswap(swap, &mut x2, &mut x3);
            cswap(swap, &mut z2, &mut z3);
            swap = k_t;
            let a = x2.add(z2);
            let aa = a.mul(a);
            let b = x2.sub(z2);
            let bb = b.mul(b);
            let e = aa.sub(bb);
            let (c, d) = (x3.add(z3), x3.sub(z3));
            let (da, cb) = (d.mul(a), c.mul(b));
            let s = da.add(cb);
            x3 = s.mul(s);
            let t2 = da.sub(cb);
            z3 = x1.mul(t2.mul(t2));
            x2 = aa.mul(bb);
            z2 = e.mul(aa.add(mul_small(e, 121665)));
        }
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        let mut zi = Fe::ONE;
        for i in (0..=254).rev() {
            zi = zi.mul(zi);
            if i >= 5 || matches!(i, 3 | 1 | 0) {
                zi = zi.mul(z2);
            }
        }
        x2.mul(zi).to_bytes()
    }

    /// The ladder with lazy sums and differences, the squaring and the addition-chain inverse gives what the
    /// plain one does (compiled with BMI2 and without, B-104), for random scalars and u-coordinates, u = 0, 1, p - 1,
    /// and encodings at and above p.
    #[test]
    fn the_fast_ladder_agrees_with_the_plain_one() {
        let mut rng = crate::fuzz::Rng::new(0x7748);
        let mut specials: Vec<[u8; 32]> = vec![[0u8; 32], BASE_POINT];
        let mut one = [0u8; 32];
        one[0] = 1;
        specials.push(one);
        let mut p_minus_1 = [0xffu8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        specials.push(p_minus_1);
        let mut p_plus_1 = p_minus_1;
        p_plus_1[0] = 0xee;
        specials.push(p_plus_1);
        specials.push([0xffu8; 32]);
        for i in 0..300 {
            let k: [u8; 32] = rng.bytes(32).try_into().unwrap();
            let u: [u8; 32] = if i < specials.len() { specials[i] } else { rng.bytes(32).try_into().unwrap() };
            let want = reference(&k, &u);
            // the ladder this CPU uses (with BMI2 on an x86-64 that has it), and the plain one
            assert_eq!(x25519(&k, &u), want, "scalar {}, u {}", hex(&k), hex(&u));
            assert_eq!(ladder(&k, &u), want, "scalar {}, u {}", hex(&k), hex(&u));
        }
    }

    #[test]
    fn rfc7748_function_vectors() {
        assert_eq!(
            hex(&x25519(
                &arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                &arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            )),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
        assert_eq!(
            hex(&x25519(
                &arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                &arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
            )),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let a = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = public_key(&a);
        let b_pub = public_key(&b);
        assert_eq!(hex(&a_pub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex(&b_pub), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex(&x25519(&a, &b_pub)), shared);
        assert_eq!(hex(&x25519(&b, &a_pub)), shared);
    }

    #[test]
    fn rfc7748_iterated_once_and_1000() {
        // RFC 7748 section 5.2: k = u = 9, iterate
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        let r = x25519(&k, &u);
        u = k;
        k = r;
        assert_eq!(hex(&k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        for _ in 1..1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
        }
        assert_eq!(hex(&k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }
}
