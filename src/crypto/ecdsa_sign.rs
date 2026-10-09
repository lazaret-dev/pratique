//! ECDSA signing on P-256 and P-384 (FIPS 186-5, SEC 1 section 4.1.3), in constant time (B-109).
//!
//! A signature is (r, s) with r = x(\[k\]G) mod n and s = k^-1 (z + r d) mod n, for the private key d, the message's
//! hash z and a nonce k that must never repeat or be guessable: the same k for two messages, or a few known bits of
//! k over many, gives the key away. So:
//!
//! * **The nonce** is RFC 6979's: HMAC-DRBG over the key and the hash, which makes it a function of the two and needs
//!   no randomness to be safe, with 32 fresh random bytes added as the "additional data" of section 3.6 ("hedged"
//!   signing): a broken random source still gives RFC 6979's nonce, and the randomness keeps an attacker who can
//!   cause a fault in one signature from getting a second with the same nonce to compare. [`EcdsaSigningKey::sign_deterministic`]
//!   leaves it out, for the RFC's test vectors and for anyone who wants the same signature each time.
//! * **\[k\]G** is `ecdh`'s constant-time scalar multiplication (fixed 4-bit windows, complete formulas, every table
//!   entry read).
//! * **Everything modulo n** (the hash and r brought below n, r d, the sum, the inverse of k, the product) is
//!   `ct_mod`'s: no branch and no memory address depends on k, d or s, and the inverse is Fermat's with the public
//!   exponent n - 2.
//! * What does depend on the data: whether a candidate nonce is rejected (it is 0 or not below n: about 2^-32 of
//!   candidates on P-256, 2^-190 on P-384) and whether r or s came out zero (never, in practice); each just takes the
//!   next nonce, which tells nothing about the key.
//!
//! The data-independent-timing mode of ARM (`crypto::dit`) is held for the whole signature. Not covered: power and
//! electromagnetic analysis, and faults beyond the hedging (a signature is not checked after it is made: an ECDSA
//! fault gives a wrong signature, which the peer refuses, not the key, except in the repeated-nonce case the hedging
//! covers).
//!
//! The tests check the RFC 6979 vectors (P-256 and P-384, SHA-256, SHA-384 and SHA-512, "sample" and "test"), every
//! signature against the verifier in `ecdsa.rs`, and signatures OpenSSL verifies; `crypto::timing` checks the timing.

use super::ct_mod::{self, Modulus};
use super::dit::Dit;
use super::ecdh;
use super::ecdsa::Curve;
use super::hmac::Hmac;
use super::rand;
use super::sha2::{HashAlg, Sha256, Sha384, Sha512};
use crate::error::{Error, Result};
use crate::zeroize::{Zeroize, Zeroizing};
use std::sync::OnceLock;

const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

fn order256() -> &'static Modulus<4> {
    static N: OnceLock<Modulus<4>> = OnceLock::new();
    N.get_or_init(|| Modulus::from_hex(P256_N))
}

fn order384() -> &'static Modulus<6> {
    static N: OnceLock<Modulus<6>> = OnceLock::new();
    N.get_or_init(|| Modulus::from_hex(P384_N))
}

/// Bytes in a scalar of the curve (32 or 48); `None` for P-521, which this module does not sign with.
fn scalar_len(curve: Curve) -> Option<usize> {
    match curve {
        Curve::P256 => Some(32),
        Curve::P384 => Some(48),
        Curve::P521 => None,
    }
}

/// The hash TLS 1.3 pairs with the curve (ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384), which X.509 uses too.
pub fn default_hash(curve: Curve) -> HashAlg {
    match curve {
        Curve::P384 => HashAlg::Sha384,
        _ => HashAlg::Sha256,
    }
}

/// An ECDSA private key on P-256 or P-384, with its public key.
#[derive(Clone)]
pub struct EcdsaSigningKey {
    curve: Curve,
    /// d, big-endian, exactly the curve's scalar length
    d: Zeroizing<Vec<u8>>,
    /// 0x04 || x || y
    public: Vec<u8>,
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcdsaSigningKey({:?}, public {})", self.curve, crate::util::hex(&self.public))
    }
}

impl EcdsaSigningKey {
    /// The key with this private scalar (big-endian; shorter encodings are padded on the left, as SEC 1 allows some
    /// writers to leave the leading zero bytes out). Refused if it is 0 or not below the group order.
    pub fn from_scalar(curve: Curve, d: &[u8]) -> Result<EcdsaSigningKey> {
        let len = scalar_len(curve).ok_or_else(|| Error::Key(format!("ECDSA signing on {curve:?} is not supported (P-256 and P-384 are)")))?;
        if d.len() > len {
            return Err(Error::Key(format!("an ECDSA {curve:?} private key of {} bytes (at most {len})", d.len())));
        }
        let mut padded = Zeroizing::new(vec![0u8; len]);
        padded[len - d.len()..].copy_from_slice(d);
        let public = ecdh::public_key(curve, &padded).ok_or_else(|| Error::Key(format!("an ECDSA {curve:?} private key that is 0 or not below the group order")))?;
        Ok(EcdsaSigningKey { curve, d: padded, public })
    }

    /// A new random key.
    pub fn generate(curve: Curve) -> Result<EcdsaSigningKey> {
        if scalar_len(curve).is_none() {
            return Err(Error::Key(format!("ECDSA signing on {curve:?} is not supported (P-256 and P-384 are)")));
        }
        let (d, public) = ecdh::generate(curve)?;
        Ok(EcdsaSigningKey { curve, d, public })
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// The public key, uncompressed (0x04 || x || y).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The private scalar, big-endian (for writing the key out).
    pub fn scalar(&self) -> &[u8] {
        &self.d
    }

    /// The DER signature (SEQUENCE of two INTEGERs, as TLS and X.509 carry it) of `message` hashed with `alg`, with a
    /// hedged nonce.
    pub fn sign(&self, alg: HashAlg, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_prehashed(alg, &alg.digest(message))
    }

    /// As [`sign`](Self::sign), for a hash already made with `alg`.
    pub fn sign_prehashed(&self, alg: HashAlg, digest: &[u8]) -> Result<Vec<u8>> {
        let mut extra = Zeroizing::new([0u8; 32]);
        rand::fill(&mut extra[..])?;
        let (r, s) = self.sign_raw(alg, digest, &extra[..])?;
        Ok(der_signature(&r, &s))
    }

    /// The signature as the fixed-length r || s of IEEE P1363 (what JWS's ES256 and ES384 carry), hedged.
    pub fn sign_p1363(&self, alg: HashAlg, message: &[u8]) -> Result<Vec<u8>> {
        let mut extra = Zeroizing::new([0u8; 32]);
        rand::fill(&mut extra[..])?;
        let (mut r, s) = self.sign_raw(alg, &alg.digest(message), &extra[..])?;
        r.extend_from_slice(&s);
        Ok(r)
    }

    /// The DER signature with RFC 6979's nonce alone (no added randomness): the same key and message always give the
    /// same signature.
    pub fn sign_deterministic(&self, alg: HashAlg, message: &[u8]) -> Result<Vec<u8>> {
        let (r, s) = self.sign_raw(alg, &alg.digest(message), &[])?;
        Ok(der_signature(&r, &s))
    }

    /// (r, s), each exactly the scalar length, big-endian.
    fn sign_raw(&self, alg: HashAlg, digest: &[u8], extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if digest.len() != alg.output_len() {
            return Err(Error::Key(format!("a {alg:?} digest of {} bytes", digest.len())));
        }
        let _dit = Dit::on(); // data-independent timing while the secrets are in use (crypto::dit)
        match self.curve {
            Curve::P256 => sign_with(order256(), self.curve, &self.d, alg, digest, extra),
            Curve::P384 => sign_with(order384(), self.curve, &self.d, alg, digest, extra),
            Curve::P521 => unreachable!("no P-521 signing key can be made"),
        }
    }
}

/// HMAC with `alg` over the concatenation of `parts`.
fn hmac(alg: HashAlg, key: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    fn run<H: super::sha2::Hash + Zeroize>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut h = Hmac::<H>::new(key);
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }
    Zeroizing::new(match alg {
        HashAlg::Sha256 => run::<Sha256>(key, parts),
        HashAlg::Sha384 => run::<Sha384>(key, parts),
        HashAlg::Sha512 => run::<Sha512>(key, parts),
    })
}

/// bits2int of RFC 6979 section 2.3.2 for a curve whose order has `8 len` bits (P-256 and P-384 do): the leftmost
/// `len` bytes of `h`, or `h` padded on the left if it is shorter.
fn bits2int<const N: usize>(h: &[u8], len: usize) -> [u64; N] {
    if h.len() >= len {
        ct_mod::limbs_from_be(&h[..len])
    } else {
        ct_mod::limbs_from_be(h)
    }
}

/// RFC 6979's nonce generator (section 3.2, with the additional data of section 3.6), over HMAC with the message's
/// hash: [`next`](Self::next) gives the candidates in order.
struct Nonces {
    alg: HashAlg,
    k: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    len: usize,
    first: bool,
}

impl Nonces {
    /// `x` is int2octets(d), `h` is bits2octets(H(m)) (both `len` bytes), `extra` the added randomness (may be empty).
    fn new(alg: HashAlg, x: &[u8], h: &[u8], extra: &[u8], len: usize) -> Nonces {
        let hlen = alg.output_len();
        let v = Zeroizing::new(vec![0x01u8; hlen]);
        let k = Zeroizing::new(vec![0x00u8; hlen]);
        let k = hmac(alg, &k, &[&v, &[0x00], x, h, extra]);
        let v = hmac(alg, &k, &[&v]);
        let k = hmac(alg, &k, &[&v, &[0x01], x, h, extra]);
        let v = hmac(alg, &k, &[&v]);
        Nonces { alg, k, v, len, first: true }
    }

    /// The next candidate: `len` bytes, which the caller checks are in 1..n.
    fn next(&mut self) -> Zeroizing<Vec<u8>> {
        if !self.first {
            self.k = hmac(self.alg, &self.k, &[&self.v, &[0x00]]);
            self.v = hmac(self.alg, &self.k, &[&self.v]);
        }
        self.first = false;
        let mut t = Zeroizing::new(Vec::with_capacity(self.len + 64));
        while t.len() < self.len {
            self.v = hmac(self.alg, &self.k, &[&self.v]);
            t.extend_from_slice(&self.v);
        }
        t.truncate(self.len);
        t
    }
}

fn sign_with<const N: usize>(n: &Modulus<N>, curve: Curve, d: &[u8], alg: HashAlg, digest: &[u8], extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let len = d.len();
    // z = bits2int(H(m)) mod n: below 2^(8 len) < 2 n, so one conditional subtraction
    let z = n.reduce_below_twice(&bits2int::<N>(digest, len));
    let h1 = Zeroizing::new(ct_mod::limbs_to_be(&z, len)); // bits2octets(H(m))
    let mut nonces = Nonces::new(alg, d, &h1, extra, len);
    loop {
        let candidate = nonces.next();
        if let Some(signature) = sign_core(n, curve, d, &z, &candidate) {
            return Ok(signature);
        }
    }
}

/// The signature with nonce `k` (big-endian, the scalar length) for the reduced hash `z`, or `None` if `k` is not in
/// 1..n or r or s came out zero (the caller takes the next nonce).
fn sign_core<const N: usize>(n: &Modulus<N>, curve: Curve, d: &[u8], z: &[u64; N], k_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let len = d.len();
    let mut k = ct_mod::limbs_from_be::<N>(k_bytes);
    // 1 <= k < n, by masks; a candidate outside is passed over (see the module documentation)
    if n.below_mask(&k) & !ct_mod::zero_mask(&k) == 0 {
        k.zeroize();
        return None;
    }
    let point = Zeroizing::new(ecdh::public_key(curve, k_bytes).expect("a nonce in 1..n"));
    // r = x mod n: x < p < 2 n
    let x = ct_mod::limbs_from_be::<N>(&point[1..1 + len]);
    let r = n.reduce_below_twice(&x);
    // s = k^-1 (z + r d) mod n, in the Montgomery domain
    let mut d_limbs = ct_mod::limbs_from_be::<N>(d);
    let mut d_m = n.to_mont(&d_limbs);
    let k_m = n.to_mont(&k);
    let mut k_inv = n.invert(&k_m);
    let r_m = n.to_mont(&r);
    let mut sum = n.add(&n.to_mont(z), &n.mul(&r_m, &d_m));
    let mut s_m = n.mul(&k_inv, &sum);
    let s = n.from_mont(&s_m);
    for v in [&mut k, &mut k_inv, &mut sum, &mut s_m, &mut d_limbs, &mut d_m] {
        v.zeroize();
    }
    // r = 0 or s = 0: take the next nonce (RFC 6979 section 3.4)
    if ct_mod::zero_mask(&r) | ct_mod::zero_mask(&s) != 0 {
        return None;
    }
    Some((ct_mod::limbs_to_be(&r, len), ct_mod::limbs_to_be(&s, len)))
}

/// For the timing tests: one signature of `digest` with the nonce `k` chosen by the caller (in 1..n), as `sign_core`
/// makes it inside every signature.
#[cfg(test)]
pub(crate) fn sign_with_nonce(key: &EcdsaSigningKey, digest: &[u8], k: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let _dit = Dit::on();
    let len = key.d.len();
    match key.curve {
        Curve::P256 => sign_core(order256(), key.curve, &key.d, &order256().reduce_below_twice(&bits2int::<4>(digest, len)), k),
        Curve::P384 => sign_core(order384(), key.curve, &key.d, &order384().reduce_below_twice(&bits2int::<6>(digest, len)), k),
        Curve::P521 => None,
    }
}

/// The DER INTEGER of an unsigned big-endian value: no leading zero bytes, and one zero byte if the top bit is set.
fn der_integer(out: &mut Vec<u8>, v: &[u8]) {
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
    let v = &v[start..];
    let pad = v[0] & 0x80 != 0;
    out.push(0x02);
    out.push((v.len() + pad as usize) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

/// SEQUENCE { INTEGER r, INTEGER s } (at most 2 x 50 bytes of content, so the length is one byte).
pub(crate) fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 * r.len() + 6);
    der_integer(&mut body, r);
    der_integer(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x30);
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        out.push(0x81);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa;
    use crate::util::unhex;

    /// RFC 6979 appendix A.2.5 (P-256) and A.2.6 (P-384): the key, then (hash, message, r, s).
    const P256_KEY: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const P256_PUB: &str = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    const P256: [(HashAlg, &str, &str, &str); 6] = [
        (HashAlg::Sha256, "sample", "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        (HashAlg::Sha384, "sample", "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719", "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954"),
        (HashAlg::Sha512, "sample", "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00", "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"),
        (HashAlg::Sha256, "test", "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        (HashAlg::Sha384, "test", "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6", "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C"),
        (HashAlg::Sha512, "test", "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04", "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"),
    ];
    const P384_KEY: &str = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5";
    const P384_PUB: &str = "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";
    const P384: [(HashAlg, &str, &str, &str); 6] = [
        (HashAlg::Sha256, "sample", "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD", "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"),
        (HashAlg::Sha384, "sample", "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46", "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8"),
        (HashAlg::Sha512, "sample", "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709", "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5"),
        (HashAlg::Sha256, "test", "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B", "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265"),
        (HashAlg::Sha384, "test", "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB", "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5"),
        (HashAlg::Sha512, "test", "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277", "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736"),
    ];

    #[test]
    fn rfc_6979_vectors() {
        for (curve, key, public, cases) in [(Curve::P256, P256_KEY, P256_PUB, &P256[..]), (Curve::P384, P384_KEY, P384_PUB, &P384[..])] {
            let k = EcdsaSigningKey::from_scalar(curve, &unhex(key)).unwrap();
            assert_eq!(k.public_key(), &unhex(public)[..], "{curve:?} public key");
            for (alg, msg, r, s) in cases {
                let got = k.sign_deterministic(*alg, msg.as_bytes()).unwrap();
                assert_eq!(got, der_signature(&unhex(r), &unhex(s)), "{curve:?} {alg:?} {msg:?}");
                assert!(ecdsa::verify_prehashed(curve, k.public_key(), &alg.digest(msg.as_bytes()), &got));
            }
        }
    }

    /// Deterministic signatures made by python-ecdsa (`sign_deterministic`, an independent RFC 6979), for the keys 1 and
    /// n - 1 and random ones, every hash, messages of 0 to 80 bytes: (curve, hash, d, message, r, s).
    const PYTHON_ECDSA: [(Curve, HashAlg, &str, &str, &str, &str); 24] = [
        (Curve::P256, HashAlg::Sha256, "0000000000000000000000000000000000000000000000000000000000000001", "2bc58dc16429996d5c67a26139612bd8", "5ec6fa4a21d3759ab390b27a1fe33333d048f595b5c44ae9ddb965a50780ec81", "6ab7260e9213527d6b1c90c169185257391ee5b625dfb0d2c4ab8613ba97bc0d"),
        (Curve::P256, HashAlg::Sha256, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "a5c76d1ce511b0a97967fa6d0b", "a861f032f9c7f2dc34d2c3db19a7560846f25d459df9ac146d3ac90576bb0644", "15a63747505ce2da73eb6a302541c3a056859dedf79f7aa43ec778966b4bc084"),
        (Curve::P256, HashAlg::Sha256, "90578f8ce27ab853c4b18762e6deb162eaea84197be4c1e1119a6272f8763133", "cf5fad78e005b45d74b95b0d75f7", "530585051b63184511d3be9b355428d52f6e4cc6af86f9a782bcb9f41b586ee8", "a07d9089cecbb7a2d568247f3621f84f5044779716a0c1879e819c9252ac9a9e"),
        (Curve::P256, HashAlg::Sha256, "0f3615072695147aa45e5e7e87fc36dc1b91eb1c30da068a7d78510bda2b6327", "5c45ae810f24a348c917e4cda08df82395c61bc6ef5e5e58634ece790fa22696c038e6246e4e11343622beecdaddc0a53352de0af24dd439f52f2bfc6226d2ce3ccfd258e7395125c209145ac252", "fe21a9cbaafceb55746c10e0912c499c471b4c3a6f2359166ad7829ebc0a4212", "c8c3926afdf81aa9a90311813def17c2cda8285a4c6b24d28a278644ee0e358e"),
        (Curve::P256, HashAlg::Sha384, "0000000000000000000000000000000000000000000000000000000000000001", "258e04199fc31c", "69c2242e1e9738dbfe89b863444c8f7137e63035b25fb093a5e58f972fde80c9", "6bc1eb8ecc4e3b2ffd0d77c8a393ff8edfcb69b8e1fc5e158651aeef1385c556"),
        (Curve::P256, HashAlg::Sha384, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "72e71282e965811071cc98d1ab85145b0148b3410356d3c6e5f8c257a59faa3842926a3eb1b7fa81932ed37008a5deb51962e64ad3faca3eff90e58f08d2a3fe382303740f2cb5d5763944", "afa58410a9dd1bb21943aba96569e1586142fb0bf98ecba47e142eda5301c078", "66b409a606fae063648b86de06013982c925ab8f17093b01f5ab7a9ed81cf184"),
        (Curve::P256, HashAlg::Sha384, "149344e3bcc634a8a3cd42c6512a79c3725161a96690358dce32f5e7b2546452", "8d6b87848797", "6ed7b9b37dd5afa1fb5f6d9b540765f949c03c04b58b0df843912061b49c93fe", "cb64a4130a723117fc9e284e43f4f05a580da809efcfce8c73b1470cb6cccf6f"),
        (Curve::P256, HashAlg::Sha384, "7f06aa95b2124c52e678a1555b28c796076a455c3a11e4ef2f352413750c9727", "ff62331fd59a2b0b6d888c2c43f17154d8d8a377b23595ec3ba7894d5ba11eabf45614", "20a133d03086e6ec8c732176ce3d6c4bcce80c4c6b5f64662b3d377dd274bc5a", "3819f81654744238809a3ce024be4f6f33dee1a728b6ee94aba92874820e1d2a"),
        (Curve::P256, HashAlg::Sha512, "0000000000000000000000000000000000000000000000000000000000000001", "a6e33658c4ca794750f27fd992b3cf4da05f725927e93b7394d4671bb7871b1ab197f6941bd5ad21bba074e2207c9d2e4c7ee7fcdb0c61a59e734a", "8823d5180f8e88932c20ee699467a9355916da0d6a44044a9f4ced9adbcfce90", "2b1492a489aebd9ada2ee7b4616539013369416f8fa3aa51efc81a2324cd2e46"),
        (Curve::P256, HashAlg::Sha512, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "47498cbe629e682bbc5d57cead2aafde6da763874c549ccae31069b2d3ed75383275540293d4fba9db", "bb9d8dc969405d9463982a5eb816e53011f47828b2fa3edb57a85e447a61b3a1", "08ebfd29c6103c76d1713894efd3b0d4e6705d04ec0245e50020397288515132"),
        (Curve::P256, HashAlg::Sha512, "dda58e14f5ebf7fcfb272de936c47a2d01f7b283ba9a343e8519f7791111846b", "e6867e915bb30b9f", "3b012e1a94873053d6ecde451facc610ae1b40bcc1b7f97992260c053e825d6e", "5fd9f4f4d1d3fddf62c39de380a1f2768a4e5672ff5fe58fd76bac3f3e2e4fcc"),
        (Curve::P256, HashAlg::Sha512, "01dd96c92a0b7b2bb2513b18e4f54c03f1952f8d863ca61db1493e8ee51db905", "c541a0d0698360f4320beb445fa173", "1313cba8ec8f95a0328fe1d105c60e117a9c8a9117d03c876189963f9a159ed8", "0e9c0271a67f36c20f8976fd226b8b574ab00a0ccb0aba3df605ebbef4673435"),
        (Curve::P384, HashAlg::Sha256, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "a4ecfd8e9a440be4e7", "afbe131d5dbbc0735ca4c30b3f362d8e63bc519f36846ec5555b722622f92e99e04f3ba3d34963bbe6f35ae4faa4ee78", "e5c1c7d08b7c9de3e79061393cd797c0661f5825a17d67702d19bbd32c8032190545e917989b6fa37a0215f2c4faea39"),
        (Curve::P384, HashAlg::Sha256, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972", "dcb281a28726c1b9d6fb6fdd31aa53e275ab56d6655859174bc2cbfa29498433463d", "84268feea81d892e61393b0ca66888415cb1cb6dc62e069059192a0d7e97566bf3915b92c1fe69a42152eb05862981ca", "35c9e145f17e14a30d5bd53b5dab40e2a05ef59a986f94fe2c2e3ac60e6df3d9d318f7a4c42558b14acfd148ffe75b42"),
        (Curve::P384, HashAlg::Sha256, "5b013aa1d7369ef243c0cc19c35329ff98d498cedf1a1a1e509012edb7f68679d017da2ff283977ef3a24f9b88c35038", "0a7542018c1e32430323e7119154daff9c136d0c8142ba0d219dbba8f255b25b369a55f51ab69006be54453cc513f762916f1daf5c998413b3e97c2476170dc3", "a6a252ec134973e40a4bd55e8e9d079a463c1aeae78e2097105bd2f93402dd6a14fcb4aed490b6f427ac5ddf45b6ff17", "f63e9c39dcac76f2a5d8ff1347ff8df7f739ab7129fa90e9eddbc856c918e60120e02aaf8eb76c88b40a22f764e97073"),
        (Curve::P384, HashAlg::Sha256, "151009a837f0b5c45f9219d9733e2eba881b236a0484b389294e2a20e774913875c3c858b3c35db3dcc81398a514b612", "ba9880cebac85bf3aad1c21a78c167f7f57607eb", "65f4c25147c2705e6eef4a40afc1ab5a6b2c9e8e4ad273c791b32a68625a295b1cf9159ae9ab5f3a71031dce33abed5b", "07cdc46f80398dac04279212f1da4b872bff6a9e90f9f6012a8a3a9321c908b83fb9d536b5ce99d3b98c6220fa4466c5"),
        (Curve::P384, HashAlg::Sha384, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "a78bf4d84405810ca02f3c0b664220312df16e4a8a248220f59206ced81c5cf9c1da9b5bc4e5e1ba0aebc4035d8645c93cef", "e1c2802eec12830405bc80d2c63019c542153be9ca856548e37fa46ba9761256f8d38b28095bcbfa74e1d4170af2ce71", "2f88e891a180cbeb266a9b12757e0658a5f2edb34a043d6523322b37a6e928d0c87d31f2b009d2536bd7f30bfad59dbb"),
        (Curve::P384, HashAlg::Sha384, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972", "595219e88b", "0ec3f6d93e73b4c88974792ac973739b23770e52ff89831259e42049937ed724a36e57e07b2592cbfd7b7671a2fef9dc", "ea0c3bb7ffa7bc69999633f93217356c5370265aca9b3dba9bb2294948456e3f259d39aabac287e0d4ed4de78fb74440"),
        (Curve::P384, HashAlg::Sha384, "2d382231f2f931ce76f3956e0f828359fae72f87ffd424ff22fd4d878ec0235aed2d966c608d9cb62354c96938cc5882", "c373e32a5b0f4d165a", "b1cb4d2489aee26c120d4b7d1595e762d0d2e7d0062a519de6bc7460089ba2aeb583b2a036a60c93c3f23bc98f87c7c0", "1c8aae42d86062861eb1392a5c14bca5c52ca4ea19f9263dc23cc863317b8496e1a41aacc4e5b33390cdc7d992a1cd54"),
        (Curve::P384, HashAlg::Sha384, "27b379fde1677b865ee303ecd31f880857dbb6e76fc9df7a03aac461e050d66649aeacf43723c0f72c285f8389b4301c", "38a12b62db19c9eb80933c02f754181b891aca", "2761fa8c41080544de0a82ce805ffc586980886f1de8c2c1ba2595ea566130f80ab1d7d0f8712899c52a74c77f7add79", "69ee4968f652fe759b2cba1176aba6f730096d19c39c684e5f8ac94f070bc6765cc176166a040f8d0d92be3f136cd61e"),
        (Curve::P384, HashAlg::Sha512, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "9066d5d3c1faa9f6b795f4eb934e1c21a1e3e350342169d5cb2fc6f9eafaa420c4baf7342f00b4f17d2adef347", "a5103043009028bdfee6e3a16d1955e011d00e95ac9ae556436de779e56270ac9345b3d57c0a4c72dffb4e58ab5ff10d", "e7b9926b6ea3ebea150f1ce67d9d9e598ddc4fbb620759f614c66b24d8d2cb5d2819791b33003fc703874edc43a4f846"),
        (Curve::P384, HashAlg::Sha512, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972", "48933485c857aae1223f23fc97a216757857b0c3", "1742a369067898afd865bb1730dd5546aeafed069cce6a5b324041df5febf5272c5264735365ff913d246356c983f2ac", "3b88e9c75d2b41bf2f66574891b6b679ddb28bd0403a7cc99d389126a21fa7b634643fca4617c2bbcbe62b034bbd2e5a"),
        (Curve::P384, HashAlg::Sha512, "875b72627dc602982d2fb3275c5c069cca432c177e9f75c16e6681046946d3f14310becca43d51a922f78cbcdec023d5", "bdb659abe9cef800296e509d301da5e77f9f7a4c1d95c3f54e9152673942e137150977f84b6944cd0c99d969bab0e21a03f2", "49f09601d2c1e15eb7728a33b5f8821561c5470e99b29559acee6ecd15e43bc5130fbbcac9de8662d637b84a7f46627e", "fe2961185deef3f45233ed46affd6b3cb38354dafc7ebbe6a7026afc83b7a726013924fc751c9b4cd92d477af13130e0"),
        (Curve::P384, HashAlg::Sha512, "559ff34ac770605f3aada4d387e7151bfd170feeef28300f553a21b1629052532543d53d3297c77fc933b983b5f8551c", "c24839bac4ca144f374e1272e4aa67721f777b1ac92c48e05e516d82ab6919aabb30f275a443fab413d0daf0b6924607a6e6e0dbf86dcb305350f685422fef08", "0d71e09e0f19c4f96a9811b9e518953ab5ae1ff902a71df4439d2c1f06f329ed50fd1e7ab3901884c896f73656bd4485", "7dc47b4ef534b8478fa1bcb384cbfd9bd30f6a366fd957203c7b30fd780fb18d176605f8048294d84a8391b195c41c6a"),
    ];

    #[test]
    fn python_ecdsa_deterministic_signatures() {
        for (curve, alg, d, msg, r, s) in PYTHON_ECDSA {
            let k = EcdsaSigningKey::from_scalar(curve, &unhex(d)).unwrap();
            let got = k.sign_deterministic(alg, &unhex(msg)).unwrap();
            assert_eq!(got, der_signature(&unhex(r), &unhex(s)), "{curve:?} {alg:?} d = {d}");
        }
    }

    #[test]
    fn hedged_signatures_differ_and_verify() {
        for curve in [Curve::P256, Curve::P384] {
            for _ in 0..8 {
                let k = EcdsaSigningKey::generate(curve).unwrap();
                let alg = default_hash(curve);
                let a = k.sign(alg, b"the same message").unwrap();
                let b = k.sign(alg, b"the same message").unwrap();
                assert_ne!(a, b, "the added randomness changes the nonce");
                for sig in [&a, &b] {
                    assert!(ecdsa::verify_prehashed(curve, k.public_key(), &alg.digest(b"the same message"), sig));
                    assert!(!ecdsa::verify_prehashed(curve, k.public_key(), &alg.digest(b"another message"), sig));
                }
                let raw = k.sign_p1363(alg, b"jws").unwrap();
                let len = scalar_len(curve).unwrap();
                assert_eq!(raw.len(), 2 * len);
                assert!(ecdsa::verify_prehashed(curve, k.public_key(), &alg.digest(b"jws"), &der_signature(&raw[..len], &raw[len..])));
            }
        }
    }

    #[test]
    fn every_hash_with_every_curve_verifies() {
        for curve in [Curve::P256, Curve::P384] {
            let k = EcdsaSigningKey::generate(curve).unwrap();
            for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                for len in [0usize, 1, 55, 56, 64, 1000] {
                    let msg = vec![0xa5u8; len];
                    let sig = k.sign(alg, &msg).unwrap();
                    assert!(ecdsa::verify_prehashed(curve, k.public_key(), &alg.digest(&msg), &sig), "{curve:?} {alg:?} {len}");
                }
            }
        }
    }

    #[test]
    fn keys_out_of_range_are_refused() {
        for curve in [Curve::P256, Curve::P384] {
            let len = scalar_len(curve).unwrap();
            let n = unhex(if len == 32 { P256_N } else { P384_N });
            assert!(EcdsaSigningKey::from_scalar(curve, &vec![0u8; len]).is_err());
            assert!(EcdsaSigningKey::from_scalar(curve, &n).is_err());
            assert!(EcdsaSigningKey::from_scalar(curve, &vec![0xffu8; len]).is_err());
            assert!(EcdsaSigningKey::from_scalar(curve, &vec![1u8; len + 1]).is_err());
            // a short encoding is padded: 1 is a valid key, its public key is G
            let one = EcdsaSigningKey::from_scalar(curve, &[1]).unwrap();
            assert_eq!(one.scalar().len(), len);
            let mut n_minus_1 = n.clone();
            *n_minus_1.last_mut().unwrap() -= 1;
            let k = EcdsaSigningKey::from_scalar(curve, &n_minus_1).unwrap();
            let sig = k.sign(default_hash(curve), b"edge").unwrap();
            assert!(ecdsa::verify_prehashed(curve, k.public_key(), &default_hash(curve).digest(b"edge"), &sig));
        }
        assert!(EcdsaSigningKey::from_scalar(Curve::P521, &[1]).is_err());
        assert!(EcdsaSigningKey::generate(Curve::P521).is_err());
    }

    #[test]
    fn der_integers_are_minimal() {
        assert_eq!(der_signature(&[0, 0, 1], &[0x80, 0]), vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0x80, 0x00]);
        assert_eq!(der_signature(&[0, 0], &[0x7f]), vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x7f]);
    }
}
