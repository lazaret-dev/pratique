//! Ed25519 signing (RFC 8032, section 5.1.6), for the test TLS server and nothing else.
//!
//! **This is not constant-time.** It reuses the verifier's variable-time point arithmetic (a plain
//! double-and-add over the secret scalar), so the time a signature takes depends on the secret key. A
//! network attacker who can time many signatures can recover it. That is acceptable for a throwaway key
//! that protects a connection between two test programs on one machine, and for nothing else: do not sign
//! with a key that matters. The signing a production server would need (constant-time, and with ECDSA
//! keys, which the rest of this crate's secret-scalar code is built for) is a separate piece of work, see
//! BACKLOG B-78.
//!
//! The verifier in `ed25519.rs` is the check: the tests here sign with this code and verify with that, and
//! against the RFC's vectors and signatures made by OpenSSL.

use super::ed25519::{double_scalar_mul_base, limbs_from_le, scalar_reduce, Point};
use super::sha2::{Hash, Sha512};

/// The public key for a 32-byte secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (a, _) = expand(seed);
    base_mul(&a).encode()
}

/// The signature (64 bytes) of `message` under the key with this secret seed. Deterministic, as RFC 8032
/// says: the same seed and message give the same signature.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (a, prefix) = expand(seed);
    let public = base_mul(&a).encode();

    let mut h = Sha512::new();
    h.update(&prefix);
    h.update(message);
    let r = scalar_reduce(&h.finalize().try_into().expect("SHA-512 gives 64 bytes"));
    let big_r = base_mul(&r).encode();

    let mut h = Sha512::new();
    h.update(&big_r);
    h.update(&public);
    h.update(message);
    let k = scalar_reduce(&h.finalize().try_into().expect("SHA-512 gives 64 bytes"));

    // S = (r + k * a) mod L, from the 512-bit number r + k * a
    let mut wide = mul_256(&limbs_from_le(&k), &limbs_from_le(&a));
    let mut carry = 0u128;
    let r_limbs = limbs_from_le(&r);
    for (i, limb) in wide.iter_mut().enumerate() {
        let add = if i < 4 { r_limbs[i] as u128 } else { 0 };
        let sum = *limb as u128 + add + carry;
        *limb = sum as u64;
        carry = sum >> 64;
    }
    debug_assert_eq!(carry, 0, "k * a + r is below 2^512");
    let mut wide_bytes = [0u8; 64];
    for (i, limb) in wide.iter().enumerate() {
        wide_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    let s = scalar_reduce(&wide_bytes);

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&big_r);
    signature[32..].copy_from_slice(&s);
    signature
}

/// The clamped secret scalar and the nonce prefix: SHA-512 of the seed, split in two halves.
fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let digest = Sha512::digest(seed);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    prefix.copy_from_slice(&digest[32..]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (a, prefix)
}

/// [s]B.
fn base_mul(s: &[u8; 32]) -> Point {
    double_scalar_mul_base(&[0u8; 32], &Point::base(), s)
}

/// The 512-bit product of two 256-bit little-endian numbers.
fn mul_256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = a[i] as u128 * b[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{self, limbs_to_le};
    use crate::util::{hex, unhex};

    fn seed(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn rfc8032_section_7_1_test_1_and_2() {
        // TEST 1: empty message
        let s1 = seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assert_eq!(hex(&public_key(&s1)), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(
            hex(&sign(&s1, b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // TEST 2: one byte
        let s2 = seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        assert_eq!(hex(&public_key(&s2)), "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        assert_eq!(
            hex(&sign(&s2, &[0x72])),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    }

    #[test]
    fn rfc8032_section_7_1_test_3() {
        let s3 = seed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        assert_eq!(hex(&public_key(&s3)), "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        assert_eq!(
            hex(&sign(&s3, &unhex("af82"))),
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        );
    }

    #[test]
    fn what_is_signed_verifies_and_is_deterministic() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..24 {
            let mut s = [0u8; 32];
            for b in s.iter_mut() {
                *b = next() as u8;
            }
            let message: Vec<u8> = (0..(next() % 300) as usize).map(|_| next() as u8).collect();
            let public = public_key(&s);
            let sig = sign(&s, &message);
            assert!(ed25519::verify(&public, &message, &sig), "round {round}");
            assert_eq!(sig, sign(&s, &message));
            let mut other = message.clone();
            other.push(0);
            assert!(!ed25519::verify(&public, &other, &sig), "round {round}");
        }
    }

    #[test]
    fn the_scalar_product_is_the_product() {
        // (2^256 - 1)^2 = 2^512 - 2^257 + 1
        let m = [u64::MAX; 4];
        assert_eq!(mul_256(&m, &m), [1, 0, 0, 0, u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(mul_256(&[0; 4], &m), [0; 8]);
        assert_eq!(mul_256(&[7, 0, 0, 0], &[6, 0, 0, 0]), [42, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(limbs_to_le(&[1, 0, 0, 0])[0], 1);
    }
}
