//! RSA signing: RSASSA-PSS (what TLS 1.3 signs with an RSA key) and RSASSA-PKCS1-v1_5 (certificates, CRLs and the
//! like), RFC 8017, in constant time (B-109).
//!
//! The signature is m^d mod n for the encoded message m. It is computed with the Chinese remainder theorem, as
//! m^dp mod p and m^dq mod q combined (Garner's formula), and everything that touches p, q, dp, dq or qinv is
//! constant time:
//!
//! * the arithmetic modulo p and q is `ct_mod`'s, with constants made without the variable-time code
//!   (`Modulus::new_secret`);
//! * the exponentiation runs fixed windows of 4 bits over every bit of the exponent's limbs, with four squarings and one
//!   product each, and reads all 16 table entries to pick one (`Modulus::pow_secret`);
//! * the recombination's subtraction, product and addition are fixed loops over all limbs.
//!
//! On top of that, two defences that the constant-time code should make unnecessary and that cost little:
//!
//! * **base blinding**: the message is multiplied by r^e before the exponentiation and the result by r^-1 after it,
//!   for a random r, so the exponentiation never works on a value the caller chose. The pair (r^e, r^-1) is made when
//!   the key is loaded (r^-1 by Fermat modulo p and q, constant time) and squared after each use, as OpenSSL did;
//! * **checking the signature before it leaves**: s^e mod n must give m back, or nothing is returned. A fault in one
//!   of the two halves of a CRT signature (a glitch, a cosmic ray, a bug) would otherwise hand out a value from which
//!   gcd(s^e - m, n) is a factor of n (Boneh, DeMillo and Lipton, 1997).
//!
//! Keys of 2048 to 8192 bits are taken (moduli of 32, 48, 64, 96 or 128 limbs, two primes of half that); smaller ones
//! are refused, as the CA/Browser Forum and NIST refuse them. The data-independent-timing mode of ARM (`crypto::dit`)
//! is held while the secrets are in use. `crypto::timing` checks the exponentiation and whole signatures.

use super::ct_mod::{self, Modulus};
use super::dit::Dit;
use super::rand;
use super::rsa::{self, RsaPublicKey};
use super::sha2::HashAlg;
use crate::error::{Error, Result};
use crate::util::ct_eq;
use crate::zeroize::{Zeroize, Zeroizing};
use std::sync::Mutex;

/// An RSA private key with the CRT parameters (two primes).
pub struct RsaSigningKey {
    crt: Crt,
    public: RsaPublicKey,
    /// n and e, big-endian, minimal
    n: Vec<u8>,
    e: Vec<u8>,
    /// the modulus's length in bits and bytes
    bits: usize,
    k: usize,
}

impl std::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaSigningKey({} bits)", self.bits)
    }
}

/// The CRT key of one of the sizes taken: H limbs per prime, F = 2 H for the modulus.
enum Crt {
    K2048(Box<CrtKey<16, 32>>),
    K3072(Box<CrtKey<24, 48>>),
    K4096(Box<CrtKey<32, 64>>),
    K6144(Box<CrtKey<48, 96>>),
    K8192(Box<CrtKey<64, 128>>),
}

/// The parts of the private key, in the forms the arithmetic uses.
struct CrtKey<const H: usize, const F: usize> {
    p: Modulus<H>,
    q: Modulus<H>,
    dp: [u64; H],
    dq: [u64; H],
    qinv: [u64; H],
    /// the public modulus (the blinding and the check work modulo n)
    n: Modulus<F>,
    e: u64,
    /// (r^e, r^-1) in n's Montgomery domain, squared after each use
    blinding: Mutex<([u64; F], [u64; F])>,
}

impl<const H: usize, const F: usize> Drop for CrtKey<H, F> {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        if let Ok(mut b) = self.blinding.lock() {
            b.0.zeroize();
            b.1.zeroize();
        }
    }
}

/// The product of two H-limb numbers, as F = 2 H limbs, by fixed loops.
fn mul_wide<const H: usize, const F: usize>(a: &[u64; H], b: &[u64; H]) -> [u64; F] {
    debug_assert_eq!(F, 2 * H);
    let mut out = [0u64; F];
    for i in 0..H {
        let mut carry = 0u128;
        for j in 0..H {
            let t = a[i] as u128 * b[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + H] = carry as u64;
    }
    out
}

/// The low and high halves of an F-limb number, H limbs each.
fn halves<const H: usize, const F: usize>(x: &[u64; F]) -> ([u64; H], [u64; H]) {
    let mut lo = [0u64; H];
    let mut hi = [0u64; H];
    lo.copy_from_slice(&x[..H]);
    hi.copy_from_slice(&x[H..]);
    (lo, hi)
}

/// Big-endian bytes as exactly `N` limbs, or `None` if the value does not fit.
fn limbs<const N: usize>(bytes: &[u8]) -> Option<[u64; N]> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let bytes = &bytes[start..];
    (bytes.len() <= 8 * N).then(|| ct_mod::limbs_from_be(bytes))
}

impl<const H: usize, const F: usize> CrtKey<H, F> {
    fn new(n: &[u8], e: u64, p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]) -> Result<Box<CrtKey<H, F>>> {
        let bad = |what: &str| Error::Key(format!("an RSA private key whose {what}"));
        let n_l = limbs::<F>(n).ok_or_else(|| bad("modulus does not fit its size"))?;
        let mut p_l = Zeroizing::new(limbs::<H>(p).ok_or_else(|| bad("first prime is longer than half the modulus"))?);
        let mut q_l = Zeroizing::new(limbs::<H>(q).ok_or_else(|| bad("second prime is longer than half the modulus"))?);
        let dp_l = Zeroizing::new(limbs::<H>(dp).ok_or_else(|| bad("first CRT exponent is too long"))?);
        let dq_l = Zeroizing::new(limbs::<H>(dq).ok_or_else(|| bad("second CRT exponent is too long"))?);
        let qinv_l = Zeroizing::new(limbs::<H>(qinv).ok_or_else(|| bad("CRT coefficient is too long"))?);
        // p and q odd and above 1; p q = n; the CRT values below their primes. Checked by masks and a constant-time
        // comparison, so the checks themselves say nothing about the primes.
        if (p_l[0] & q_l[0] & 1) == 0 {
            return Err(bad("primes are not both odd"));
        }
        let pq = Zeroizing::new(mul_wide::<H, F>(&p_l, &q_l));
        let pq_bytes = Zeroizing::new(ct_mod::limbs_to_be(&*pq, 8 * F));
        if !ct_eq(&pq_bytes, &ct_mod::limbs_to_be(&n_l, 8 * F)) {
            return Err(bad("primes do not multiply to its modulus"));
        }
        let p_mod = Modulus::new_secret(*p_l);
        let q_mod = Modulus::new_secret(*q_l);
        if p_mod.below_mask(&dp_l) & q_mod.below_mask(&dq_l) & p_mod.below_mask(&qinv_l) == 0 {
            return Err(bad("CRT values are not below their primes"));
        }
        // qinv q = 1 mod p (a wrong coefficient would make every recombination wrong)
        let one_check = p_mod.mul(&p_mod.to_mont(&q_l), &qinv_l); // q R qinv / R
        let mut one = [0u64; H];
        one[0] = 1;
        if !ct_eq(&ct_mod::limbs_to_be(&one_check, 8 * H), &ct_mod::limbs_to_be(&one, 8 * H)) {
            return Err(bad("CRT coefficient is not the inverse of q modulo p"));
        }
        p_l.zeroize();
        q_l.zeroize();
        let n_mod = Modulus::new(n_l);
        let mut key = Box::new(CrtKey { p: p_mod, q: q_mod, dp: *dp_l, dq: *dq_l, qinv: *qinv_l, n: n_mod, e, blinding: Mutex::new(([0u64; F], [0u64; F])) });
        key.blinding = Mutex::new(key.new_blinding()?);
        Ok(key)
    }

    /// x^e mod n for the public exponent, in n's Montgomery domain (square and multiply over e's bits: e is public).
    fn pow_e(&self, x_m: &[u64; F]) -> [u64; F] {
        let mut r = *x_m;
        let top = 63 - self.e.leading_zeros();
        for bit in (0..top).rev() {
            r = self.n.sqr(&r);
            if (self.e >> bit) & 1 == 1 {
                r = self.n.mul(&r, x_m);
            }
        }
        r
    }

    /// The CRT half modulo `prime` of x (F limbs, any value): x^exp mod prime, in the prime's Montgomery domain.
    fn half(prime: &Modulus<H>, x: &[u64; F], exp: &[u64; H]) -> [u64; H] {
        let (lo, hi) = halves::<H, F>(x);
        let mut x_p = prime.reduce_wide(&lo, &hi);
        let mut base = prime.to_mont(&x_p);
        let r = prime.pow_secret(&base, exp);
        x_p.zeroize();
        base.zeroize();
        r
    }

    /// Garner's recombination: the value below n that is m1 mod p (given in p's Montgomery domain) and m2 mod q
    /// (normal form): m2 + q ((m1 - m2) qinv mod p).
    fn combine(&self, m1_m: &[u64; H], m2: &[u64; H]) -> [u64; F] {
        let mut m2_m = self.p.to_mont(m2); // m2 < q < 2^(64 H): reduced on the way
        let mut diff_m = self.p.sub(m1_m, &m2_m);
        let mut h = self.p.mul(&diff_m, &self.qinv); // (m1 - m2) R qinv / R: normal form
        let mut hq = mul_wide::<H, F>(&h, self.q_limbs());
        let mut out = [0u64; F];
        let mut carry = 0u64;
        for i in 0..F {
            let add = if i < H { m2[i] } else { 0 };
            let s = hq[i] as u128 + add as u128 + carry as u128;
            out[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        for v in [&mut m2_m, &mut diff_m, &mut h] {
            v.zeroize();
        }
        hq.zeroize();
        out
    }

    fn q_limbs(&self) -> &[u64; H] {
        self.q.value()
    }

    /// x^d mod n by the CRT, for x below n (normal form).
    fn private_op(&self, x: &[u64; F]) -> [u64; F] {
        let mut m1_m = Self::half(&self.p, x, &self.dp);
        let mut m2_m = Self::half(&self.q, x, &self.dq);
        let mut m2 = self.q.from_mont(&m2_m);
        let out = self.combine(&m1_m, &m2);
        for v in [&mut m1_m, &mut m2_m, &mut m2] {
            v.zeroize();
        }
        out
    }

    /// A fresh blinding pair (r^e, r^-1), both in n's Montgomery domain, for a random r. r^-1 is r^(p-2) mod p and
    /// r^(q-2) mod q recombined (Fermat, by the constant-time power).
    fn new_blinding(&self) -> Result<([u64; F], [u64; F])> {
        // a random r fails only if it shares a factor with n (never, for a real key): a few tries, then the key is wrong
        for _ in 0..4 {
            // r random below n: F limbs with the top one zero (n's top limb is not)
            let mut bytes = Zeroizing::new(vec![0u8; 8 * F]);
            rand::fill(&mut bytes)?;
            let mut r = ct_mod::limbs_from_be::<F>(&bytes);
            r[F - 1] = 0;
            let inv_p = Self::half(&self.p, &r, self.p.minus_two());
            let inv_q = Self::half(&self.q, &r, self.q.minus_two());
            let inv_q_normal = self.q.from_mont(&inv_q);
            let r_inv = self.combine(&inv_p, &inv_q_normal);
            // r must be invertible: r r^-1 = 1 (fails only if r shares a factor with n, which a random r does not)
            let r_m = self.n.to_mont(&r);
            let r_inv_m = self.n.to_mont(&r_inv);
            let product = self.n.from_mont(&self.n.mul(&r_m, &r_inv_m));
            let mut one = [0u64; F];
            one[0] = 1;
            if ct_eq(&ct_mod::limbs_to_be(&product, 8 * F), &ct_mod::limbs_to_be(&one, 8 * F)) {
                return Ok((self.pow_e(&r_m), r_inv_m));
            }
        }
        Err(Error::Key("an RSA private key whose primes and CRT values do not fit together".into()))
    }

    /// The signature of the encoded message `em` (exactly the modulus's length, below n), blinded and checked.
    fn sign(&self, em: &[u8], public: &RsaPublicKey) -> Result<Vec<u8>> {
        let m = limbs::<F>(em).ok_or_else(|| Error::Key("an RSA message representative longer than the modulus".into()))?;
        if self.n.below_mask(&m) == 0 {
            return Err(Error::Key("an RSA message representative not below the modulus".into()));
        }
        let (a, ai) = {
            let mut pair = self.blinding.lock().unwrap_or_else(|e| e.into_inner());
            let now = *pair;
            pair.0 = self.n.sqr(&pair.0);
            pair.1 = self.n.sqr(&pair.1);
            now
        };
        let _dit = Dit::on();
        let mut blinded = self.n.from_mont(&self.n.mul(&self.n.to_mont(&m), &a));
        let mut s_blinded = self.private_op(&blinded);
        let s = self.n.from_mont(&self.n.mul(&self.n.to_mont(&s_blinded), &ai));
        blinded.zeroize();
        s_blinded.zeroize();
        let k = em.len();
        let signature = ct_mod::limbs_to_be(&s, 8 * F).split_off(8 * F - k);
        // the check: s^e mod n is m again, or a fault happened and the signature (which could give away a prime) is dropped
        match public.public_op(&signature) {
            Some(back) if ct_eq(&back, em) => Ok(signature),
            _ => Err(Error::Key("an RSA signature failed its own check (a fault, or an inconsistent key); nothing was sent".into())),
        }
    }
}

impl Crt {
    fn sign(&self, em: &[u8], public: &RsaPublicKey) -> Result<Vec<u8>> {
        match self {
            Crt::K2048(k) => k.sign(em, public),
            Crt::K3072(k) => k.sign(em, public),
            Crt::K4096(k) => k.sign(em, public),
            Crt::K6144(k) => k.sign(em, public),
            Crt::K8192(k) => k.sign(em, public),
        }
    }
}

impl RsaSigningKey {
    /// Parses PKCS#1's `RSAPrivateKey` (RFC 8017 appendix A.1.2), two primes (version 0) only.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<RsaSigningKey> {
        use crate::asn1::{self, Der, TAG_INTEGER};
        let bad = |e: crate::verify_error::Error| Error::Key(format!("not an RSA private key (PKCS#1 RSAPrivateKey): {e}"));
        let mut outer = Der::new(der);
        let mut seq = outer.sequence().map_err(bad)?;
        outer.finish().map_err(bad)?;
        let version = asn1::unsigned_integer(&seq.expect(TAG_INTEGER).map_err(bad)?).map_err(bad)?;
        if version != [0] {
            return Err(Error::Key("an RSA private key with more than two primes (multi-prime, version 1) is not supported".into()));
        }
        let mut field = || -> Result<Zeroizing<Vec<u8>>> { Ok(Zeroizing::new(asn1::unsigned_integer(&seq.expect(TAG_INTEGER).map_err(bad)?).map_err(bad)?)) };
        let n = field()?;
        let e = field()?;
        let _d = field()?;
        let p = field()?;
        let q = field()?;
        let dp = field()?;
        let dq = field()?;
        let qinv = field()?;
        seq.finish().map_err(bad)?;
        RsaSigningKey::from_crt(&n, &e, &p, &q, &dp, &dq, &qinv)
    }

    /// The key from its CRT parameters (big-endian): the modulus, the public exponent, the primes p and q,
    /// dp = d mod (p - 1), dq = d mod (q - 1) and qinv = q^-1 mod p.
    pub fn from_crt(n: &[u8], e: &[u8], p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]) -> Result<RsaSigningKey> {
        let public = RsaPublicKey::from_components(n, e).map_err(|err| Error::Key(format!("an RSA key whose public part is refused: {err}")))?;
        let bits = public.bits();
        let k = (bits + 7) / 8;
        let e_value = e.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        let limbs_n = (bits + 63) / 64;
        let crt = match limbs_n {
            32 => Crt::K2048(CrtKey::new(n, e_value, p, q, dp, dq, qinv)?),
            48 => Crt::K3072(CrtKey::new(n, e_value, p, q, dp, dq, qinv)?),
            64 => Crt::K4096(CrtKey::new(n, e_value, p, q, dp, dq, qinv)?),
            96 => Crt::K6144(CrtKey::new(n, e_value, p, q, dp, dq, qinv)?),
            128 => Crt::K8192(CrtKey::new(n, e_value, p, q, dp, dq, qinv)?),
            _ => {
                return Err(Error::Key(format!(
                    "an RSA key of {bits} bits; signing takes 2048, 3072, 4096, 6144 or 8192 bits (keys below 2048 bits are refused)"
                )))
            }
        };
        let trim = |v: &[u8]| v[v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1)..].to_vec();
        let key = RsaSigningKey { crt, public, n: trim(n), e: trim(e), bits, k };
        // one signature now, so that a key whose CRT values do not belong to its modulus is refused here and not at the
        // first handshake
        key.sign_pss(HashAlg::Sha256, b"pratique: a key's first signature")
            .map_err(|_| Error::Key("an RSA private key whose CRT values do not match its modulus".into()))?;
        Ok(key)
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The modulus, big-endian, without leading zeros.
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// The public exponent, big-endian.
    pub fn public_exponent(&self) -> &[u8] {
        &self.e
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// RSASSA-PSS with `alg` for the message, MGF1 with the same hash and a random salt as long as the hash (the
    /// parameters TLS 1.3 requires: rsa_pss_rsae_sha256, _sha384, _sha512).
    pub fn sign_pss(&self, alg: HashAlg, message: &[u8]) -> Result<Vec<u8>> {
        let h_len = alg.output_len();
        let em_bits = self.bits - 1;
        let em_len = (em_bits + 7) / 8;
        if em_len < 2 * h_len + 2 {
            return Err(Error::Key("an RSA key too short for PSS with this hash".into()));
        }
        let mut salt = Zeroizing::new(vec![0u8; h_len]);
        rand::fill(&mut salt)?;
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&alg.digest(message));
        m_prime.extend_from_slice(&salt);
        let h = alg.digest(&m_prime);
        let db_len = em_len - h_len - 1;
        let mut db = vec![0u8; db_len];
        db[db_len - h_len - 1] = 0x01;
        db[db_len - h_len..].copy_from_slice(&salt);
        let mask = rsa::mgf1(alg, &h, db_len);
        for (d, m) in db.iter_mut().zip(&mask) {
            *d ^= m;
        }
        db[0] &= 0xffu8 >> (8 * em_len - em_bits);
        let mut em = vec![0u8; self.k - em_len];
        em.extend_from_slice(&db);
        em.extend_from_slice(&h);
        em.push(0xbc);
        self.crt.sign(&em, &self.public)
    }

    /// RSASSA-PKCS1-v1_5 with `alg` (deterministic: the same key and message give the same signature).
    pub fn sign_pkcs1(&self, alg: HashAlg, message: &[u8]) -> Result<Vec<u8>> {
        let prefix = rsa::digest_info_prefix(alg);
        let digest = alg.digest(message);
        let t_len = prefix.len() + digest.len();
        if self.k < t_len + 11 {
            return Err(Error::Key("an RSA key too short for this hash".into()));
        }
        let mut em = Vec::with_capacity(self.k);
        em.extend_from_slice(&[0x00, 0x01]);
        em.resize(self.k - t_len - 1, 0xff);
        em.push(0x00);
        em.extend_from_slice(prefix);
        em.extend_from_slice(&digest);
        self.crt.sign(&em, &self.public)
    }
}

/// For the timing tests: the constant-time power modulo a secret modulus of 16 limbs (an RSA-2048 prime).
#[cfg(test)]
pub(crate) fn pow_for_timing(m: &[u64; 16], base: &[u64; 16], exp: &[u64; 16]) -> [u64; 16] {
    let _dit = Dit::on();
    let k = Modulus::<16>::new_secret(*m);
    k.pow_secret(&k.to_mont(base), exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;

    const KEYS: &str = include_str!("../../tests/data/rsa_signing_keys.txt");

    /// (bits, PKCS#1 RSAPrivateKey DER, the PKCS#1 v1.5 SHA-256 signature OpenSSL made of "pratique") for each test key.
    fn keys() -> Vec<(usize, Vec<u8>, Vec<u8>)> {
        KEYS.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                (f[0].parse().unwrap(), unhex(f[1]), unhex(f[2]))
            })
            .collect()
    }

    #[test]
    fn pkcs1_signatures_equal_openssls() {
        let keys = keys();
        assert!(keys.len() >= 4);
        for (bits, der, want) in keys.iter().filter(|k| k.0 >= 2048) {
            let key = RsaSigningKey::from_pkcs1_der(der).unwrap();
            assert_eq!(key.bits(), *bits);
            assert_eq!(&key.sign_pkcs1(HashAlg::Sha256, b"pratique").unwrap(), want, "{bits} bits");
            for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                let sig = key.sign_pkcs1(alg, b"another message").unwrap();
                assert!(key.public_key().verify_pkcs1(alg, b"another message", &sig));
                assert_eq!(sig, key.sign_pkcs1(alg, b"another message").unwrap(), "deterministic, whatever the blinding");
            }
        }
    }

    #[test]
    fn pss_signatures_verify_and_differ() {
        for (bits, der, _) in keys().iter().filter(|k| k.0 >= 2048) {
            let key = RsaSigningKey::from_pkcs1_der(der).unwrap();
            for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                let a = key.sign_pss(alg, b"message").unwrap();
                let b = key.sign_pss(alg, b"message").unwrap();
                assert_ne!(a, b, "a random salt each time");
                assert!(key.public_key().verify_pss(alg, b"message", &a), "{bits} {alg:?}");
                assert!(key.public_key().verify_pss(alg, b"message", &b));
                assert!(!key.public_key().verify_pss(alg, b"messagE", &a));
            }
        }
    }

    #[test]
    fn small_and_broken_keys_are_refused() {
        let keys = keys();
        let small = keys.iter().find(|k| k.0 < 2048).expect("a small key in the fixtures");
        let err = RsaSigningKey::from_pkcs1_der(&small.1).unwrap_err().to_string();
        assert!(err.contains("below 2048"), "{err}");
        // a key whose q is changed: the primes no longer multiply to n
        let good = &keys.iter().find(|k| k.0 == 2048).unwrap().1;
        let parsed = parse_fields(good);
        let mut q = parsed[5].clone();
        *q.last_mut().unwrap() ^= 2;
        let err = RsaSigningKey::from_crt(&parsed[1], &parsed[2], &parsed[4], &q, &parsed[6], &parsed[7], &parsed[8]).unwrap_err().to_string();
        assert!(err.contains("multiply"), "{err}");
        // a wrong dp: refused by the first signature's check
        let mut dp = parsed[6].clone();
        *dp.last_mut().unwrap() ^= 4;
        let err = RsaSigningKey::from_crt(&parsed[1], &parsed[2], &parsed[4], &parsed[5], &dp, &parsed[7], &parsed[8]).unwrap_err().to_string();
        assert!(err.contains("CRT values do not match"), "{err}");
        // a wrong qinv
        let mut qinv = parsed[8].clone();
        *qinv.last_mut().unwrap() ^= 1;
        let err = RsaSigningKey::from_crt(&parsed[1], &parsed[2], &parsed[4], &parsed[5], &parsed[6], &parsed[7], &qinv).unwrap_err().to_string();
        assert!(err.contains("inverse of q"), "{err}");
        // not DER, truncated, a multi-prime version
        assert!(RsaSigningKey::from_pkcs1_der(&good[..good.len() - 1]).is_err());
        assert!(RsaSigningKey::from_pkcs1_der(b"garbage").is_err());
        let mut v1 = good.clone();
        let version_at = v1.iter().position(|&b| b == 0x02).unwrap(); // the version INTEGER: 02 01 00
        v1[version_at + 2] = 1;
        assert!(RsaSigningKey::from_pkcs1_der(&v1).unwrap_err().to_string().contains("multi-prime"));
    }

    /// The nine INTEGERs of an RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv.
    fn parse_fields(der: &[u8]) -> Vec<Vec<u8>> {
        use crate::asn1::{self, Der, TAG_INTEGER};
        let mut outer = Der::new(der);
        let mut seq = outer.sequence().unwrap();
        (0..9).map(|_| asn1::unsigned_integer(&seq.expect(TAG_INTEGER).unwrap()).unwrap()).collect()
    }

    #[test]
    fn the_blinding_pair_is_consistent_after_many_uses() {
        let der = &keys().into_iter().find(|k| k.0 == 2048).unwrap().1;
        let key = RsaSigningKey::from_pkcs1_der(der).unwrap();
        // the pair is squared at each use; every signature is checked before it is returned, so 50 good ones in a row
        // mean the pair stayed (r^e, r^-1) through 50 squarings
        for i in 0..50u32 {
            key.sign_pkcs1(HashAlg::Sha256, &i.to_be_bytes()).unwrap();
        }
    }

    #[test]
    fn threads_share_a_key() {
        let der = keys().into_iter().find(|k| k.0 == 2048).unwrap().1;
        let key = std::sync::Arc::new(RsaSigningKey::from_pkcs1_der(&der).unwrap());
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let key = key.clone();
                std::thread::spawn(move || {
                    for i in 0..10u32 {
                        let msg = [t as u8, i as u8];
                        let sig = key.sign_pss(HashAlg::Sha256, &msg).unwrap();
                        assert!(key.public_key().verify_pss(HashAlg::Sha256, &msg, &sig));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
