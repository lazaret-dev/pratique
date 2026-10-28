//! Bounded RSA-2048 key generation for offline provisioning. No external process.
//! Uses the OS random source and the existing constant-time Montgomery arithmetic.
//! Candidate selection/rejection is variable-time; this is not an online signing API.
use super::{
    ct_mod::{self, Modulus},
    rand,
    rsa_sign::RsaSigningKey,
};
use crate::{
    asn1::write as der,
    error::{Error, Result},
    zeroize::Zeroizing,
};

const E: u64 = 65537;
const ROUNDS: usize = 80;
type Half = [u64; 16];

// Private-key DER owns every intermediate allocation in a zeroizing buffer.
// The generic DER writer is used only for public algorithm/version fields.
fn private_tlv(tag: u8, content: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(content.len() + 10));
    out.push(tag);
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let length = content.len().to_be_bytes();
        let start = length.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (length.len() - start) as u8);
        out.extend_from_slice(&length[start..]);
    }
    out.extend_from_slice(content);
    out
}
fn private_integer(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let value = &bytes[first..];
    let mut content = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    if value.is_empty() || value[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(value);
    private_tlv(0x02, &content)
}
fn private_sequence(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut content = Zeroizing::new(Vec::new());
    for part in parts {
        content.extend_from_slice(part);
    }
    private_tlv(0x30, &content)
}

fn small_remainder(n: &[u64], divisor: u64) -> u64 {
    let mut r = 0u128;
    for word in n.iter().rev() {
        r = ((r << 64) | *word as u128) % divisor as u128;
    }
    r as u64
}
fn minus_one(mut n: Half) -> Half {
    n[0] -= 1;
    n
}
fn half(n: &mut Half) {
    for i in 0..16 {
        n[i] = (n[i] >> 1) | if i < 15 { n[i + 1] << 63 } else { 0 };
    }
}
fn random_half() -> Result<Zeroizing<Half>> {
    let mut bytes = Zeroizing::new([0u8; 128]);
    rand::fill(&mut *bytes)?;
    Ok(Zeroizing::new(ct_mod::limbs_from_be(&*bytes)))
}
fn primes() -> Vec<u64> {
    (3..2048u64)
        .step_by(2)
        .filter(|n| {
            (3..)
                .step_by(2)
                .take_while(|d| d * d <= *n)
                .all(|d| n % d != 0)
        })
        .collect()
}
fn probable_prime(n: &Half) -> Result<bool> {
    let modulus = Modulus::new_secret(*n);
    let nm1 = Zeroizing::new(minus_one(*n));
    let mut exponent = Zeroizing::new(*nm1);
    let mut s = 0;
    while exponent[0] & 1 == 0 {
        half(&mut exponent);
        s += 1;
    }
    let one = Zeroizing::new(modulus.one());
    let negative_one = Zeroizing::new(modulus.to_mont(&nm1));
    for _ in 0..ROUNDS {
        // Uniform independent bases in [2,n-2], with bounded rejection.
        let mut base = None;
        for _ in 0..128 {
            let candidate = random_half()?;
            if modulus.below_mask(&candidate) != 0
                && *candidate != *nm1
                && (candidate[1..].iter().any(|x| *x != 0) || candidate[0] >= 2)
            {
                base = Some(candidate);
                break;
            }
        }
        let base = base.ok_or_else(|| Error::Key("RSA random-base rejection limit".into()))?;
        let mut x = Zeroizing::new(modulus.pow_secret(&modulus.to_mont(&base), &exponent));
        if *x == *one || *x == *negative_one {
            continue;
        }
        let mut passed = false;
        for _ in 1..s {
            *x = modulus.sqr(&x);
            if *x == *negative_one {
                passed = true;
                break;
            }
            if *x == *one {
                break;
            }
        }
        if !passed {
            return Ok(false);
        }
    }
    Ok(true)
}
fn prime(small: &[u64]) -> Result<Zeroizing<Half>> {
    for _ in 0..32768 {
        let mut n = random_half()?;
        n[15] |= 3 << 62; // Both high bits set: p*q has exactly 2048 bits.
        n[0] |= 1;
        if small_remainder(&*n, E) == 1 || small.iter().any(|p| small_remainder(&*n, *p) == 0) {
            continue;
        }
        if probable_prime(&n)? {
            return Ok(n);
        }
    }
    Err(Error::Key("RSA prime-generation attempt limit".into()))
}
fn product(a: &Half, b: &Half) -> Zeroizing<[u64; 32]> {
    let mut out = Zeroizing::new([0u64; 32]);
    for i in 0..16 {
        let mut carry = 0u128;
        for j in 0..16 {
            let v = a[i] as u128 * b[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = v as u64;
            carry = v >> 64;
        }
        out[i + 16] = carry as u64;
    }
    out
}
// 65537^-1 modulo an even number m coprime to 65537. Pick k such that
// k*m+1 is divisible by 65537; d=(k*m+1)/65537. All loops have fixed lengths.
fn exponent(m: &[u64]) -> Result<Zeroizing<Vec<u8>>> {
    let r = small_remainder(m, E);
    if r == 0 {
        return Err(Error::Key("RSA exponent is not invertible".into()));
    }
    let mut inv = 1u64;
    // Fermat in the public, small prime field: r^(65535) modulo 65537.
    for _ in 0..16 {
        inv = (inv * inv % E) * r % E;
    }
    let k = E - inv;
    let mut value = Zeroizing::new(vec![0u64; m.len() + 1]);
    let mut carry = 1u128;
    for (i, word) in m.iter().enumerate() {
        let v = *word as u128 * k as u128 + carry;
        value[i] = v as u64;
        carry = v >> 64;
    }
    value[m.len()] = carry as u64;
    let mut rem = 0u128;
    for word in value.iter_mut().rev() {
        let v = (rem << 64) | *word as u128;
        *word = (v / E as u128) as u64;
        rem = v % E as u128;
    }
    if rem != 0 || value[m.len()] != 0 {
        return Err(Error::Key("RSA exponent division failed".into()));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(m.len() * 8));
    for word in value[..m.len()].iter().rev() {
        bytes.extend(word.to_be_bytes());
    }
    Ok(bytes)
}

/// Generates a two-prime RSA-2048 key, exponent 65537, as unencrypted PKCS#8 DER.
/// 80 independent Miller–Rabin rounds per candidate, trial division, separated
/// primes and a signing self-check. Secret intermediate buffers are wiped on drop.
pub fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>> {
    let small = primes();
    let p = prime(&small)?;
    let mut q = None;
    for _ in 0..128 {
        let candidate = prime(&small)?;
        let (lo, hi) = if *p < *candidate {
            (&*p, &*candidate)
        } else {
            (&*candidate, &*p)
        };
        // Subtract in little-endian limb order, then normalize the sign below.
        // Separation does not depend on which candidate was subtracted first.
        let mut diff = Zeroizing::new([0u64; 16]);
        let mut borrow = false;
        for i in 0..16 {
            let (a, b) = hi[i].overflowing_sub(lo[i]);
            let (a, c) = a.overflowing_sub(borrow as u64);
            diff[i] = a;
            borrow = b || c;
        }
        if borrow {
            let mut carry = 1u128;
            for v in diff.iter_mut() {
                let n = (!*v) as u128 + carry;
                *v = n as u64;
                carry = n >> 64;
            }
        }
        if diff[15] != 0 || diff[14] >> 28 != 0 {
            q = Some(candidate);
            break;
        }
    }
    let q = q.ok_or_else(|| Error::Key("RSA prime-separation limit".into()))?;
    let n = product(&p, &q);
    let pm1 = Zeroizing::new(minus_one(*p));
    let qm1 = Zeroizing::new(minus_one(*q));
    let phi = product(&pm1, &qm1);
    let d = exponent(&*phi)?;
    let dp = exponent(&*pm1)?;
    let dq = exponent(&*qm1)?;
    let pm = Modulus::new_secret(*p);
    let qi = Zeroizing::new(pm.from_mont(&pm.pow_secret(&pm.to_mont(&q), pm.minus_two())));
    let nb = ct_mod::limbs_to_be(&*n, 256);
    let pb = Zeroizing::new(ct_mod::limbs_to_be(&*p, 128));
    let qb = Zeroizing::new(ct_mod::limbs_to_be(&*q, 128));
    let qib = Zeroizing::new(ct_mod::limbs_to_be(&*qi, 128));
    // Validates CRT consistency and performs a blinded, verified signature.
    RsaSigningKey::from_crt(&nb, &[1, 0, 1], &pb, &qb, &dp, &dq, &qib)?;
    let fields: Vec<Zeroizing<Vec<u8>>> = [&[0][..], &nb, &[1, 0, 1], &d, &pb, &qb, &dp, &dq, &qib]
        .iter()
        .map(|v| private_integer(v))
        .collect();
    let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
    let pkcs1 = private_sequence(&refs);
    let octets = private_tlv(0x04, &pkcs1);
    Ok(private_sequence(&[
        &der::integer(&[0]),
        &der::sequence(&[&der::oid_str("1.2.840.113549.1.1.1"), &der::tlv(0x05, &[])]),
        &octets,
    ]))
}
