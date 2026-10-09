//! RSA signature verification: PKCS#1 v1.5 (certificates) and PSS (TLS 1.3 CertificateVerify).
//! Public-key operations only, so no constant-time requirements apply.

use super::bignum::fixed::Field;
use super::bignum::{self, Mont};
use super::sha2::HashAlg;
use crate::asn1::{self, Der};
use crate::verify_error::{Error, Result};
use crate::util::ct_eq;

pub struct RsaPublicKey {
    modulus: Modulus,
    e: u64,
    /// Modulus length in bytes.
    k: usize,
    mod_bits: usize,
}

/// The modulus and its Montgomery constants: of a common size, in fixed-size arithmetic (no allocation, loops unrolled:
/// about twice as fast, and so is making the constants); otherwise the general code.
enum Modulus {
    L16(Box<Field<16>>),
    L24(Box<Field<24>>),
    L32(Box<Field<32>>),
    L48(Box<Field<48>>),
    L64(Box<Field<64>>),
    Other(Mont),
}

impl Modulus {
    fn new(n: &[u64]) -> Modulus {
        fn fixed<const N: usize>(n: &[u64]) -> Box<Field<N>> {
            Box::new(Field::from_modulus(n.try_into().expect("N limbs")))
        }
        match n.len() {
            16 => Modulus::L16(fixed(n)),
            24 => Modulus::L24(fixed(n)),
            32 => Modulus::L32(fixed(n)),
            48 => Modulus::L48(fixed(n)),
            64 => Modulus::L64(fixed(n)),
            _ => Modulus::Other(Mont::new(n)),
        }
    }

    /// s^e mod n, for s below n (as many limbs as n or fewer, the top ones not zero) and an odd e of at least 3.
    fn pow(&self, s: &[u64], e: u64) -> Vec<u64> {
        fn fixed<const N: usize>(f: &Field<N>, s: &[u64], e: u64) -> Vec<u64> {
            let mut b = [0u64; N];
            b[..s.len()].copy_from_slice(s);
            f.pow_odd(&b, e).to_vec()
        }
        match self {
            Modulus::L16(f) => fixed(f, s, e),
            Modulus::L24(f) => fixed(f, s, e),
            Modulus::L32(f) => fixed(f, s, e),
            Modulus::L48(f) => fixed(f, s, e),
            Modulus::L64(f) => fixed(f, s, e),
            Modulus::Other(m) => m.from_mont(&m.pow(&m.to_mont(&m.fit(s)), &[e])),
        }
    }

    fn limbs(&self) -> &[u64] {
        match self {
            Modulus::L16(f) => &f.m,
            Modulus::L24(f) => &f.m,
            Modulus::L32(f) => &f.m,
            Modulus::L48(f) => &f.m,
            Modulus::L64(f) => &f.m,
            Modulus::Other(m) => m.modulus(),
        }
    }
}

impl RsaPublicKey {
    /// Parses `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let mut outer = Der::new(der);
        let mut seq = outer.sequence()?;
        outer.finish()?;
        let n = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER)?)?;
        let e = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER)?)?;
        seq.finish()?;
        Self::from_components(&n, &e)
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self> {
        let n_limbs = bignum::from_be_bytes(n);
        let e_limbs = bignum::from_be_bytes(e);
        let mod_bits = bignum::bit_len(&n_limbs);
        if mod_bits < 1024 {
            return Err(Error::Certificate("RSA modulus is shorter than 1024 bits".into()));
        }
        if mod_bits > 8192 {
            return Err(Error::Certificate("RSA modulus is longer than 8192 bits".into()));
        }
        if n_limbs[0] & 1 == 0 {
            return Err(Error::Certificate("RSA modulus is even".into()));
        }
        let e_bits = bignum::bit_len(&e_limbs);
        if e_bits < 2 || e_bits > 64 || e_limbs[0] & 1 == 0 {
            return Err(Error::Certificate("unsupported RSA public exponent".into()));
        }
        let n_limbs = &n_limbs[..bignum::trimmed_len(&n_limbs)];
        Ok(RsaPublicKey { modulus: Modulus::new(n_limbs), e: e_limbs[0], k: (mod_bits + 7) / 8, mod_bits })
    }

    /// Size of the modulus in bits.
    pub fn bits(&self) -> usize {
        self.mod_bits
    }

    /// Computes sig^e mod n as exactly `k` bytes, or None if the signature is malformed.
    fn raw(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = bignum::from_be_bytes(sig);
        if bignum::cmp(&s, self.modulus.limbs()) != std::cmp::Ordering::Less {
            return None;
        }
        let s = &s[..bignum::trimmed_len(&s)];
        let r = self.modulus.pow(s, self.e);
        Some(bignum::to_be_bytes(&r, self.k))
    }

    /// RSASSA-PKCS1-v1_5 verification (the expected encoding is rebuilt and
    /// compared, never parsed, which rules out padding-parsing bugs).
    pub fn verify_pkcs1(&self, alg: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
        self.verify_pkcs1_digest(digest_info_prefix(alg), &alg.digest(msg), sig)
    }

    /// sig^e mod n as exactly the modulus's length in bytes, or `None` if `sig` is not that long or not below n: the
    /// public operation, for the check a signer makes of its own signature (`rsa_sign`).
    #[allow(dead_code)] // used by rsa_sign (the net part)
    pub(crate) fn public_op(&self, sig: &[u8]) -> Option<Vec<u8>> {
        self.raw(sig)
    }

    /// RSASSA-PKCS1-v1_5 over a SHA-1 hash of `msg`. SHA-1 is broken for signatures; this exists so
    /// that [`crate::cms`] can say that a legacy signature is *genuine but weak* instead of calling
    /// it garbage. Nothing else (certificates, CRLs, OCSP, TLS) accepts a SHA-1 signature.
    pub(crate) fn verify_pkcs1_sha1(&self, msg: &[u8], sig: &[u8]) -> bool {
        const PREFIX: [u8; 15] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
        self.verify_pkcs1_digest(&PREFIX, &super::sha1::digest(msg), sig)
    }

    /// The common part: `prefix` is the DER of the DigestInfo up to the digest itself.
    fn verify_pkcs1_digest(&self, prefix: &[u8], digest: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.raw(sig) else { return false };
        let t_len = prefix.len() + digest.len();
        if self.k < t_len + 11 {
            return false;
        }
        let mut expected = Vec::with_capacity(self.k);
        expected.extend_from_slice(&[0x00, 0x01]);
        expected.extend(std::iter::repeat(0xffu8).take(self.k - t_len - 3));
        expected.push(0x00);
        expected.extend_from_slice(prefix);
        expected.extend_from_slice(digest);
        ct_eq(&em, &expected)
    }

    /// RSASSA-PSS verification with MGF1 using the same hash and salt length = hash length
    /// (the only parameters TLS 1.3 permits).
    pub fn verify_pss(&self, alg: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
        self.verify_pss_with(alg, alg, alg.output_len(), msg, sig)
    }

    /// RSASSA-PSS (RFC 8017 section 8.1.2) with explicit parameters, as an `RSASSA-PSS-params`
    /// structure in a CMS signature algorithm carries them: the message hash, the MGF1 hash and the
    /// salt length. The trailer field is always 0xbc.
    pub fn verify_pss_with(&self, alg: HashAlg, mgf_alg: HashAlg, salt_len: usize, msg: &[u8], sig: &[u8]) -> bool {
        self.pss(alg, mgf_alg, Some(salt_len), msg, sig)
    }

    /// RSASSA-PSS with MGF1 of the same hash and whatever salt length the signature has (read from the encoded message, as
    /// OpenSSL's `RSA_PSS_SALTLEN_AUTO` and Python `cryptography`'s `PSS.AUTO` do): what TUF's `rsassa-pss-sha256` scheme
    /// is verified with, since signers have used both the hash length and the largest salt.
    pub fn verify_pss_any_salt(&self, alg: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
        self.pss(alg, alg, None, msg, sig)
    }

    fn pss(&self, alg: HashAlg, mgf_alg: HashAlg, salt_len: Option<usize>, msg: &[u8], sig: &[u8]) -> bool {
        let Some(raw) = self.raw(sig) else { return false };
        let em_bits = self.mod_bits - 1;
        let em_len = (em_bits + 7) / 8;
        let (lead, em) = raw.split_at(self.k - em_len);
        if lead.iter().any(|&b| b != 0) {
            return false;
        }
        let h_len = alg.output_len();
        if em_len < h_len + salt_len.unwrap_or(0) + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let db_len = em_len - h_len - 1;
        let (masked_db, rest) = em.split_at(db_len);
        let h = &rest[..h_len];
        let top_mask = 0xffu8 >> (8 * em_len - em_bits);
        if masked_db[0] & !top_mask != 0 {
            return false;
        }
        let mask = mgf1(mgf_alg, h, db_len);
        let mut db: Vec<u8> = masked_db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
        db[0] &= top_mask;
        // the salt is what follows the zeros and the 0x01; its length is fixed by the caller, or read here
        let s_len = match salt_len {
            Some(n) => n,
            None => match db.iter().position(|&b| b != 0) {
                Some(i) => db_len - i - 1,
                None => return false,
            },
        };
        let ps_len = db_len - s_len - 1;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return false;
        }
        let salt = &db[ps_len + 1..];
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&alg.digest(msg));
        m_prime.extend_from_slice(salt);
        ct_eq(h, &alg.digest(&m_prime))
    }
}

/// The DER of PKCS#1 v1.5's DigestInfo for `alg`, up to the digest itself (RFC 8017 section 9.2, note 1).
pub(crate) fn digest_info_prefix(alg: HashAlg) -> &'static [u8] {
    match alg {
        HashAlg::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        HashAlg::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        HashAlg::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
    }
}

/// MGF1 (RFC 8017 appendix B.2.1) with `alg`: `len` bytes from `seed`.
pub(crate) fn mgf1(alg: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + alg.output_len());
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&alg.digest(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_vectors as tv;
    use crate::util::unhex;

    fn key() -> RsaPublicKey {
        RsaPublicKey::from_pkcs1_der(&unhex(tv::RSA_PUBKEY_DER)).unwrap()
    }

    #[test]
    fn pkcs1_sha256_verifies() {
        let k = key();
        let sig = unhex(tv::RSA_PKCS1_SHA256_SIG);
        assert!(k.verify_pkcs1(HashAlg::Sha256, tv::RSA_MSG, &sig));
        assert!(!k.verify_pkcs1(HashAlg::Sha256, b"different message", &sig));
        assert!(!k.verify_pkcs1(HashAlg::Sha384, tv::RSA_MSG, &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!k.verify_pkcs1(HashAlg::Sha256, tv::RSA_MSG, &bad));
        assert!(!k.verify_pkcs1(HashAlg::Sha256, tv::RSA_MSG, &sig[1..]));
    }

    #[test]
    fn pkcs1_sha384_and_512_verify() {
        let k = key();
        assert!(k.verify_pkcs1(HashAlg::Sha384, tv::RSA_MSG, &unhex(tv::RSA_PKCS1_SHA384_SIG)));
        assert!(k.verify_pkcs1(HashAlg::Sha512, tv::RSA_MSG, &unhex(tv::RSA_PKCS1_SHA512_SIG)));
    }

    #[test]
    fn pss_verifies() {
        let k = key();
        assert!(k.verify_pss(HashAlg::Sha256, tv::RSA_MSG, &unhex(tv::RSA_PSS_SHA256_SIG)));
        assert!(k.verify_pss(HashAlg::Sha384, tv::RSA_MSG, &unhex(tv::RSA_PSS_SHA384_SIG)));
        assert!(!k.verify_pss(HashAlg::Sha256, b"other", &unhex(tv::RSA_PSS_SHA256_SIG)));
        assert!(!k.verify_pss(HashAlg::Sha256, tv::RSA_MSG, &unhex(tv::RSA_PKCS1_SHA256_SIG)));
    }

    /// Moduli of the common sizes take the fixed-size code and the others the general code, and both give the same
    /// s^e mod n, for signatures with fewer limbs than n, zero and n - 1 among them.
    #[test]
    fn every_size_of_modulus_gives_the_same_powers() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for limbs in [16usize, 17, 24, 31, 32, 33, 48, 64, 65] {
            let mut n: Vec<u64> = (0..limbs).map(|_| next()).collect();
            n[0] |= 1;
            n[limbs - 1] |= 1 << 63;
            let m = Modulus::new(&n);
            assert_eq!(matches!(m, Modulus::Other(_)), ![16, 24, 32, 48, 64].contains(&limbs), "{limbs} limbs");
            let general = Mont::new(&n);
            let mut n_minus_1 = n.clone();
            n_minus_1[0] -= 1;
            for s in [vec![0u64], vec![1], vec![next(), next()], n_minus_1, (0..limbs).map(|i| if i + 1 == limbs { next() >> 1 } else { next() }).collect()] {
                let s = &s[..bignum::trimmed_len(&s)];
                for e in [3u64, 65537] {
                    let want = general.from_mont(&general.pow(&general.to_mont(&general.fit(s)), &[e]));
                    assert_eq!(m.pow(s, e), want, "{limbs} limbs, e = {e}");
                }
            }
        }
    }

    fn alg(name: &str) -> HashAlg {
        match name {
            "sha256" => HashAlg::Sha256,
            "sha384" => HashAlg::Sha384,
            "sha512" => HashAlg::Sha512,
            _ => panic!("hash {name}"),
        }
    }

    /// Signatures made by OpenSSL (tools/gen_rsa_vectors.py): PKCS#1 over SHA-1 (which `cms` reports
    /// as weak) and RSASSA-PSS with the salt length and the MGF1 hash that an RSASSA-PSS-params
    /// structure can set. Each must verify with exactly the parameters it was made with, and with no
    /// other: another salt length, another MGF1 hash, another message hash, a damaged signature.
    #[test]
    fn replays_openssl_vectors() {
        let mut k = None;
        let (mut pkcs1, mut pss) = (0, 0);
        for line in include_str!("../../tests/data/rsa_vectors.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "key" => k = Some(RsaPublicKey::from_components(&unhex(f[1]), &unhex(f[2])).unwrap()),
                "pkcs1" => {
                    let k = k.as_ref().unwrap();
                    let (msg, sig) = (unhex(f[2]), unhex(f[3]));
                    let verify = |m: &[u8], s: &[u8], h: &str| match h {
                        "sha1" => k.verify_pkcs1_sha1(m, s),
                        h => k.verify_pkcs1(alg(h), m, s),
                    };
                    assert!(verify(&msg, &sig, f[1]), "{line:.60}");
                    for other in ["sha1", "sha256", "sha384", "sha512"].into_iter().filter(|o| *o != f[1]) {
                        assert!(!verify(&msg, &sig, other), "{} signature accepted as {other}", f[1]);
                    }
                    assert!(!verify(b"another message", &sig, f[1]));
                    for i in [0, sig.len() / 2, sig.len() - 1] {
                        let mut bad = sig.clone();
                        bad[i] ^= 0x10;
                        assert!(!verify(&msg, &bad, f[1]));
                    }
                    assert!(!verify(&msg, &sig[1..], f[1]));
                    pkcs1 += 1;
                }
                "pss" => {
                    let k = k.as_ref().unwrap();
                    let (hash, mgf, salt) = (alg(f[1]), alg(f[2]), f[3].parse::<usize>().unwrap());
                    let (msg, sig) = (unhex(f[4]), unhex(f[5]));
                    assert!(k.verify_pss_with(hash, mgf, salt, &msg, &sig), "{line:.60}");
                    if hash == mgf {
                        assert!(k.verify_pss_any_salt(hash, &msg, &sig), "{line:.60}");
                        assert!(!k.verify_pss_any_salt(hash, b"another message", &sig));
                    }
                    assert!(!k.verify_pss_with(hash, mgf, salt + 1, &msg, &sig));
                    assert!(salt == 0 || !k.verify_pss_with(hash, mgf, salt - 1, &msg, &sig));
                    for other in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                        if other != mgf {
                            assert!(!k.verify_pss_with(hash, other, salt, &msg, &sig), "{line:.60}");
                        }
                        if other != hash {
                            assert!(!k.verify_pss_with(other, mgf, salt, &msg, &sig), "{line:.60}");
                        }
                    }
                    assert!(!k.verify_pss_with(hash, mgf, salt, b"another message", &sig));
                    let mut bad = sig.clone();
                    bad[sig.len() / 2] ^= 1;
                    assert!(!k.verify_pss_with(hash, mgf, salt, &msg, &bad));
                    // PKCS#1 v1.5 and PSS signatures are not interchangeable
                    assert!(!k.verify_pkcs1(hash, &msg, &sig));
                    pss += 1;
                }
                _ => panic!("{line}"),
            }
        }
        assert_eq!((pkcs1, pss), (4, 8));
    }

    /// A SHA-1 DigestInfo must not be accepted when the verifier expects SHA-2, and the reverse.
    #[test]
    fn sha1_pkcs1_is_its_own_algorithm() {
        let k = key();
        let sig = unhex(tv::RSA_PKCS1_SHA256_SIG);
        assert!(!k.verify_pkcs1_sha1(tv::RSA_MSG, &sig));
    }
}
