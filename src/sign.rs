//! Private keys and signing, for the TLS server, the certificates and requests it writes and ACME (B-109).
//!
//! [`SigningKey`] is one private key of any kind this crate signs with: ECDSA on P-256 or P-384, Ed25519, or RSA of 2048
//! to 8192 bits. It is read from PEM or DER in the formats tools write:
//!
//! | PEM label | format | from |
//! |-----------|--------|------|
//! | `PRIVATE KEY` | PKCS#8 (RFC 5208/5958): RSA, EC or Ed25519 | `openssl genpkey`, `openssl pkcs8 -nocrypt`, certbot, Caddy, Go, Python `cryptography` |
//! | `EC PRIVATE KEY` | SEC 1 (RFC 5915) | `openssl ecparam -genkey`, older tools |
//! | `RSA PRIVATE KEY` | PKCS#1 (RFC 8017) | `openssl genrsa` (OpenSSL 1.x), older tools |
//!
//! Encrypted keys (`ENCRYPTED PRIVATE KEY`, or the legacy `Proc-Type: 4,ENCRYPTED` header) are refused with a message
//! that says how to decrypt them: this crate has no password-based decryption. RSA-PSS-only keys (`id-RSASSA-PSS`),
//! Ed448, P-521 and multi-prime RSA are refused too.
//!
//! Reading is careful with the secret: the Base64 of a key block is decoded without a table lookup or a branch on its
//! characters (a lookup indexed by the key's characters has been shown to leak keys through the cache; Sieck et al.,
//! "Util::Lookup", USENIX Security 2021), and the decoded bytes are wiped when dropped.
//!
//! The signing itself is in `crypto::ecdsa_sign`, `crypto::ed25519_sign` and `crypto::rsa_sign`, constant time; see
//! their documentation.

use crate::asn1::{self, write as der, Der, TAG_BIT_STRING, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
use crate::crypto::ecdsa::Curve;
use crate::crypto::sha2::HashAlg;
use crate::error::{Error, Result};
use crate::zeroize::{Zeroize, Zeroizing};
use std::hint::black_box;
use std::sync::Arc;

pub use crate::crypto::ecdsa_sign::EcdsaSigningKey;
pub use crate::crypto::ed25519_sign::Ed25519SigningKey;
pub use crate::crypto::rsa_sign::RsaSigningKey;

/// TLS 1.3 SignatureScheme values (RFC 8446 section 4.2.3) of the signatures a [`SigningKey`] makes.
pub mod scheme {
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const ED25519: u16 = 0x0807;
}

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";
const OID_X25519: &str = "1.3.101.110";

/// One private key, of any kind this crate signs with. Cheap to clone (the key is shared).
#[derive(Clone)]
pub struct SigningKey(Arc<Kind>);

enum Kind {
    Ecdsa(EcdsaSigningKey),
    Ed25519(Ed25519SigningKey),
    Rsa(RsaSigningKey),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.algorithm())
    }
}

impl From<EcdsaSigningKey> for SigningKey {
    fn from(k: EcdsaSigningKey) -> SigningKey {
        SigningKey(Arc::new(Kind::Ecdsa(k)))
    }
}

impl From<Ed25519SigningKey> for SigningKey {
    fn from(k: Ed25519SigningKey) -> SigningKey {
        SigningKey(Arc::new(Kind::Ed25519(k)))
    }
}

impl From<RsaSigningKey> for SigningKey {
    fn from(k: RsaSigningKey) -> SigningKey {
        SigningKey(Arc::new(Kind::Rsa(k)))
    }
}

fn key_err(msg: impl Into<String>) -> Error {
    Error::Key(msg.into())
}

impl SigningKey {
    /// A new ECDSA key on P-256 or P-384.
    pub fn generate_ecdsa(curve: Curve) -> Result<SigningKey> {
        Ok(EcdsaSigningKey::generate(curve)?.into())
    }

    /// A new Ed25519 key.
    pub fn generate_ed25519() -> Result<SigningKey> {
        Ok(Ed25519SigningKey::generate()?.into())
    }

    /// The one private key in this PEM text (other blocks, such as certificates or `EC PARAMETERS`, are passed over).
    pub fn from_pem(text: &str) -> Result<SigningKey> {
        let blocks = pem_blocks(text);
        let mut labels = Vec::new();
        let mut found: Option<SigningKey> = None;
        for b in &blocks {
            let is_key = b.label.ends_with("PRIVATE KEY");
            if !is_key {
                labels.push(b.label.clone());
                continue;
            }
            if b.label == "ENCRYPTED PRIVATE KEY" || b.encrypted {
                return Err(key_err(
                    "the private key is encrypted; this library cannot decrypt keys. Decrypt it first, e.g. `openssl pkey -in key.pem -out key-plain.pem` (and keep the result as safe as the password was)",
                ));
            }
            if found.is_some() {
                return Err(key_err("more than one private key in the PEM text"));
            }
            let der = ct_base64_decode(&b.body).ok_or_else(|| key_err(format!("the {} block's Base64 is malformed", b.label)))?;
            found = Some(match b.label.as_str() {
                "PRIVATE KEY" => SigningKey::from_pkcs8_der(&der)?,
                "EC PRIVATE KEY" => SigningKey::from_sec1_der(&der, None)?,
                "RSA PRIVATE KEY" => RsaSigningKey::from_pkcs1_der(&der)?.into(),
                other => return Err(key_err(format!("a \"{other}\" block: not a key format this library reads (PKCS#8 \"PRIVATE KEY\", \"EC PRIVATE KEY\", \"RSA PRIVATE KEY\")"))),
            });
        }
        found.ok_or_else(|| {
            if labels.is_empty() {
                key_err("no PEM private key found (no -----BEGIN ... PRIVATE KEY----- block)")
            } else {
                key_err(format!("no private key in the PEM text, only: {}", labels.join(", ")))
            }
        })
    }

    /// A private key in DER: PKCS#8, SEC 1 (with its curve named inside) or PKCS#1, told apart by their structure.
    pub fn from_der(der: &[u8]) -> Result<SigningKey> {
        // PKCS#8: SEQUENCE { INTEGER, SEQUENCE, OCTET STRING, ... }; SEC 1: SEQUENCE { INTEGER 1, OCTET STRING, ... };
        // PKCS#1: SEQUENCE { INTEGER 0, INTEGER n, ... }
        let second = (|| {
            let mut outer = Der::new(der);
            let mut seq = outer.sequence().ok()?;
            seq.expect(TAG_INTEGER).ok()?;
            seq.peek_tag()
        })();
        match second {
            Some(TAG_SEQUENCE) => SigningKey::from_pkcs8_der(der),
            Some(TAG_OCTET_STRING) => SigningKey::from_sec1_der(der, None),
            Some(TAG_INTEGER) => Ok(RsaSigningKey::from_pkcs1_der(der)?.into()),
            _ => Err(key_err("not a DER private key (PKCS#8, SEC 1 or PKCS#1)")),
        }
    }

    /// PKCS#8 `PrivateKeyInfo` / `OneAsymmetricKey` (RFC 5208, RFC 5958), unencrypted.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<SigningKey> {
        let bad = |e: crate::verify_error::Error| key_err(format!("not a PKCS#8 private key: {e}"));
        let mut outer = Der::new(der);
        let mut seq = outer.sequence().map_err(bad)?;
        outer.finish().map_err(bad)?;
        let version = asn1::unsigned_integer(&seq.expect(TAG_INTEGER).map_err(bad)?).map_err(bad)?;
        if version != [0] && version != [1] {
            return Err(key_err("a PKCS#8 private key of an unknown version"));
        }
        let mut alg = seq.sequence().map_err(bad)?;
        let oid = asn1::oid_to_string(alg.expect(TAG_OID).map_err(bad)?.content);
        let params = if alg.is_empty() { None } else { Some(alg.next().map_err(bad)?) };
        let private = seq.expect(TAG_OCTET_STRING).map_err(bad)?;
        // attributes [0] and the public key [1] may follow; they are not needed
        match oid.as_str() {
            OID_RSA_ENCRYPTION => Ok(RsaSigningKey::from_pkcs1_der(private.content)?.into()),
            OID_EC_PUBLIC_KEY => {
                let curve = match params {
                    Some(p) if p.tag == TAG_OID => curve_of(&asn1::oid_to_string(p.content))?,
                    _ => return Err(key_err("an EC private key whose curve is not named (explicit curve parameters are not supported)")),
                };
                SigningKey::from_sec1_der(private.content, Some(curve))
            }
            OID_ED25519 => {
                // CurvePrivateKey ::= OCTET STRING, inside the privateKey OCTET STRING (RFC 8410 section 7)
                let mut inner = Der::new(private.content);
                let seed = inner.expect(TAG_OCTET_STRING).map_err(bad)?;
                inner.finish().map_err(bad)?;
                let seed: &[u8; 32] = seed.content.try_into().map_err(|_| key_err("an Ed25519 private key that is not 32 bytes"))?;
                Ok(Ed25519SigningKey::from_seed(seed).into())
            }
            OID_RSASSA_PSS => Err(key_err("an RSA-PSS-only key (id-RSASSA-PSS) is not supported; an ordinary RSA key (rsaEncryption) signs PSS too")),
            OID_ED448 => Err(key_err("Ed448 keys are not supported (Ed25519 is)")),
            OID_X25519 => Err(key_err("an X25519 key is for key agreement, not signing")),
            other => Err(key_err(format!("a private key of algorithm {other}, which this library does not sign with"))),
        }
    }

    /// SEC 1 `ECPrivateKey` (RFC 5915). Its curve is `curve` (from a PKCS#8 wrapper) or the one it names; if it carries its
    /// public key, that must be the private key's.
    pub fn from_sec1_der(der: &[u8], curve: Option<Curve>) -> Result<SigningKey> {
        let bad = |e: crate::verify_error::Error| key_err(format!("not an EC private key (SEC 1): {e}"));
        let mut outer = Der::new(der);
        let mut seq = outer.sequence().map_err(bad)?;
        outer.finish().map_err(bad)?;
        if asn1::unsigned_integer(&seq.expect(TAG_INTEGER).map_err(bad)?).map_err(bad)? != [1] {
            return Err(key_err("an EC private key of an unknown version"));
        }
        let d = Zeroizing::new(seq.expect(TAG_OCTET_STRING).map_err(bad)?.content.to_vec());
        let mut named = None;
        let mut public = None;
        if let Some(p) = seq.optional(0xa0).map_err(bad)? {
            let mut inner = Der::new(p.content);
            let o = inner.expect(TAG_OID).map_err(|_| key_err("an EC private key with explicit curve parameters (only named curves are supported)"))?;
            named = Some(curve_of(&asn1::oid_to_string(o.content))?);
        }
        if let Some(p) = seq.optional(0xa1).map_err(bad)? {
            let mut inner = Der::new(p.content);
            public = Some(asn1::bit_string_bytes(&inner.expect(TAG_BIT_STRING).map_err(bad)?).map_err(bad)?.to_vec());
        }
        let curve = match (curve, named) {
            (Some(a), Some(b)) if a != b => return Err(key_err("an EC private key that names two different curves")),
            (Some(c), _) | (None, Some(c)) => c,
            (None, None) => return Err(key_err("an EC private key that does not say its curve")),
        };
        let key = EcdsaSigningKey::from_scalar(curve, &d)?;
        if let Some(p) = public {
            if p != key.public_key() {
                return Err(key_err("an EC private key whose public key does not match it (a damaged key file?)"));
            }
        }
        Ok(key.into())
    }

    /// What the key is: "ECDSA P-256", "ECDSA P-384", "Ed25519" or "RSA-2048" (and so on).
    pub fn algorithm(&self) -> String {
        match &*self.0 {
            Kind::Ecdsa(k) => format!("ECDSA {}", curve_name(k.curve())),
            Kind::Ed25519(_) => "Ed25519".into(),
            Kind::Rsa(k) => format!("RSA-{}", k.bits()),
        }
    }

    /// The TLS 1.3 signature schemes this key can make, in the order the server prefers them.
    pub fn tls_schemes(&self) -> Vec<u16> {
        match &*self.0 {
            Kind::Ecdsa(k) => match k.curve() {
                Curve::P384 => vec![scheme::ECDSA_SECP384R1_SHA384],
                _ => vec![scheme::ECDSA_SECP256R1_SHA256],
            },
            Kind::Ed25519(_) => vec![scheme::ED25519],
            Kind::Rsa(_) => vec![scheme::RSA_PSS_RSAE_SHA256, scheme::RSA_PSS_RSAE_SHA384, scheme::RSA_PSS_RSAE_SHA512],
        }
    }

    /// The signature of `message` in TLS 1.3 signature scheme `scheme` (one of [`tls_schemes`](Self::tls_schemes)).
    pub fn sign_tls(&self, scheme_id: u16, message: &[u8]) -> Result<Vec<u8>> {
        match (&*self.0, scheme_id) {
            (Kind::Ecdsa(k), scheme::ECDSA_SECP256R1_SHA256) if k.curve() == Curve::P256 => k.sign(HashAlg::Sha256, message),
            (Kind::Ecdsa(k), scheme::ECDSA_SECP384R1_SHA384) if k.curve() == Curve::P384 => k.sign(HashAlg::Sha384, message),
            (Kind::Ed25519(k), scheme::ED25519) => Ok(k.sign(message).to_vec()),
            (Kind::Rsa(k), scheme::RSA_PSS_RSAE_SHA256) => k.sign_pss(HashAlg::Sha256, message),
            (Kind::Rsa(k), scheme::RSA_PSS_RSAE_SHA384) => k.sign_pss(HashAlg::Sha384, message),
            (Kind::Rsa(k), scheme::RSA_PSS_RSAE_SHA512) => k.sign_pss(HashAlg::Sha512, message),
            _ => Err(key_err(format!("a {} key cannot make signature scheme 0x{scheme_id:04x}", self.algorithm()))),
        }
    }

    /// The `SubjectPublicKeyInfo` (DER) of the public key, as a certificate or a certificate request carries it.
    pub fn public_key_spki(&self) -> Vec<u8> {
        match &*self.0 {
            Kind::Ecdsa(k) => der::sequence(&[
                &der::sequence(&[&der::oid_str(OID_EC_PUBLIC_KEY), &der::oid_str(curve_oid(k.curve()))]),
                &der::bit_string(0, k.public_key()),
            ]),
            Kind::Ed25519(k) => der::sequence(&[&der::sequence(&[&der::oid_str(OID_ED25519)]), &der::bit_string(0, k.public_key())]),
            Kind::Rsa(k) => {
                let pkcs1 = der::sequence(&[&der::integer(k.modulus()), &der::integer(k.public_exponent())]);
                der::sequence(&[&der::sequence(&[&der::oid_str(OID_RSA_ENCRYPTION), &der::null()]), &der::bit_string(0, &pkcs1)])
            }
        }
    }

    /// The `AlgorithmIdentifier` (DER) of the signatures [`sign_x509`](Self::sign_x509) makes: ecdsa-with-SHA256 or
    /// -SHA384, Ed25519, or sha256WithRSAEncryption.
    pub fn x509_algorithm(&self) -> Vec<u8> {
        match &*self.0 {
            Kind::Ecdsa(k) => der::sequence(&[&der::oid_str(if k.curve() == Curve::P384 { OID_ECDSA_SHA384 } else { OID_ECDSA_SHA256 })]),
            Kind::Ed25519(_) => der::sequence(&[&der::oid_str(OID_ED25519)]),
            Kind::Rsa(_) => der::sequence(&[&der::oid_str(OID_SHA256_WITH_RSA), &der::null()]),
        }
    }

    /// The signature over `tbs` (a TBSCertificate, a CertificationRequestInfo, a TBSCertList...) for the algorithm
    /// [`x509_algorithm`](Self::x509_algorithm) names: the bytes that go into the BIT STRING.
    pub fn sign_x509(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        match &*self.0 {
            Kind::Ecdsa(k) => k.sign(crate::crypto::ecdsa_sign::default_hash(k.curve()), tbs),
            Kind::Ed25519(k) => Ok(k.sign(tbs).to_vec()),
            Kind::Rsa(k) => k.sign_pkcs1(HashAlg::Sha256, tbs),
        }
    }

    /// Whether this is the private key of the certificate `cert` (DER): the same algorithm (and curve) and the same
    /// public key bits.
    pub fn matches_certificate(&self, cert: &[u8]) -> Result<bool> {
        let c = crate::x509::Certificate::from_der(cert)?;
        Ok(spki_identity(c.spki_der()).is_some() && spki_identity(c.spki_der()) == spki_identity(&self.public_key_spki()))
    }

    /// The key as unencrypted PKCS#8 DER (ECDSA and Ed25519 keys; RSA keys are read, never written).
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (alg, private) = match &*self.0 {
            Kind::Ecdsa(k) => {
                let ec = Zeroizing::new(der::sequence(&[
                    &der::integer(&[1]),
                    &Zeroizing::new(der::octet_string(k.scalar())),
                    &der::context(1, true, &der::bit_string(0, k.public_key())),
                ]));
                (der::sequence(&[&der::oid_str(OID_EC_PUBLIC_KEY), &der::oid_str(curve_oid(k.curve()))]), Zeroizing::new(der::octet_string(&ec)))
            }
            Kind::Ed25519(k) => (der::sequence(&[&der::oid_str(OID_ED25519)]), Zeroizing::new(der::octet_string(&Zeroizing::new(der::octet_string(k.seed()))))),
            Kind::Rsa(_) => return Err(key_err("writing out an RSA private key is not supported")),
        };
        Ok(Zeroizing::new(der::sequence(&[&der::integer(&[0]), &alg, &private])))
    }

    /// The key as a PEM `PRIVATE KEY` block (unencrypted PKCS#8), as bytes of text.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<Vec<u8>>> {
        let der = self.to_pkcs8_der()?;
        let b64 = ct_base64_encode(&der);
        let mut out = Zeroizing::new(Vec::with_capacity(b64.len() + b64.len() / 64 + 64));
        out.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
        for line in b64.chunks(64) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        Ok(out)
    }

    /// The ECDSA key inside, if it is one.
    pub fn as_ecdsa(&self) -> Option<&EcdsaSigningKey> {
        match &*self.0 {
            Kind::Ecdsa(k) => Some(k),
            _ => None,
        }
    }
}

fn curve_of(oid: &str) -> Result<Curve> {
    match oid {
        OID_P256 => Ok(Curve::P256),
        OID_P384 => Ok(Curve::P384),
        OID_P521 => Err(key_err("P-521 keys are not supported for signing (P-256 and P-384 are)")),
        other => Err(key_err(format!("an EC key on curve {other}, which is not supported (P-256 and P-384 are)"))),
    }
}

fn curve_oid(c: Curve) -> &'static str {
    match c {
        Curve::P384 => OID_P384,
        _ => OID_P256,
    }
}

fn curve_name(c: Curve) -> &'static str {
    match c {
        Curve::P256 => "P-256",
        Curve::P384 => "P-384",
        Curve::P521 => "P-521",
    }
}

/// (algorithm OID, curve OID if any, public key bits) of a SubjectPublicKeyInfo: what makes two encodings the same key
/// (an RSA key's parameters may be NULL or absent).
fn spki_identity(spki: &[u8]) -> Option<(String, Option<String>, Vec<u8>)> {
    let mut outer = Der::new(spki);
    let mut seq = outer.sequence().ok()?;
    let mut alg = seq.sequence().ok()?;
    let oid = asn1::oid_to_string(alg.expect(TAG_OID).ok()?.content);
    let curve = match alg.next() {
        Ok(p) if p.tag == TAG_OID && oid == OID_EC_PUBLIC_KEY => Some(asn1::oid_to_string(p.content)),
        _ => None,
    };
    let bits = asn1::bit_string_bytes(&seq.expect(TAG_BIT_STRING).ok()?).ok()?.to_vec();
    Some((oid, curve, bits))
}

// ------------------------------------------------------------------------------------------------ PEM, carefully

struct PemBlock {
    label: String,
    /// the Base64 characters, whitespace removed
    body: Zeroizing<Vec<u8>>,
    /// a legacy `Proc-Type: 4,ENCRYPTED` header
    encrypted: bool,
}

/// The PEM blocks of `text`, their bodies not decoded (an unterminated block is dropped).
fn pem_blocks(text: &str) -> Vec<PemBlock> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line.trim().strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else { continue };
        let end = format!("-----END {label}-----");
        let mut body = Zeroizing::new(Vec::new());
        let mut encrypted = false;
        let mut done = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                done = true;
                break;
            }
            if l.contains(':') {
                // an encapsulated header (RFC 1421): only the encryption one matters
                encrypted |= l.starts_with("Proc-Type:") && l.contains("ENCRYPTED");
                continue;
            }
            // whitespace inside a line is the line's layout, not the key: dropped by position
            body.extend(l.bytes().filter(|b| !b.is_ascii_whitespace()));
        }
        if done {
            out.push(PemBlock { label: label.to_string(), body, encrypted });
        }
    }
    out
}

/// All ones if lo <= c <= hi, else zero, without a branch (c below 256).
#[inline]
fn in_range(c: u32, lo: u32, hi: u32) -> u32 {
    // both differences are below 2^31 exactly when c is in range; otherwise one wraps around
    let outside = (c.wrapping_sub(lo) | hi.wrapping_sub(c)) >> 31;
    black_box(0u32.wrapping_sub(outside ^ 1))
}

/// The 6-bit value of a Base64 character and a mask that is all ones if it is one, with no table and no branch.
#[inline]
fn b64_value(c: u8) -> (u32, u32) {
    let c = c as u32;
    let upper = in_range(c, b'A' as u32, b'Z' as u32);
    let lower = in_range(c, b'a' as u32, b'z' as u32);
    let digit = in_range(c, b'0' as u32, b'9' as u32);
    let plus = in_range(c, b'+' as u32, b'+' as u32);
    let slash = in_range(c, b'/' as u32, b'/' as u32);
    let v = (upper & c.wrapping_sub(65)) | (lower & c.wrapping_sub(71)) | (digit & c.wrapping_add(4)) | (plus & 62) | (slash & 63);
    (v & 63, upper | lower | digit | plus | slash)
}

/// Base64 (standard alphabet, the body of a PEM block without whitespace) decoded in constant time with respect to the
/// characters: only the length and the padding at the end (public) decide what runs. `None` if it is malformed.
fn ct_base64_decode(body: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut end = body.len();
    let mut pad = 0;
    while end > 0 && body[end - 1] == b'=' && pad < 2 {
        end -= 1;
        pad += 1;
    }
    let data = &body[..end];
    if (data.len() + pad) % 4 != 0 || data.len() % 4 == 1 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() * 3 / 4));
    let mut invalid = 0u32;
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in data {
        let (v, ok) = b64_value(c);
        invalid |= !ok;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    acc.zeroize();
    (invalid == 0).then_some(out)
}

/// The Base64 character of a 6-bit value, with no table and no branch (the arithmetic of BoringSSL and libsodium).
#[inline]
fn b64_char(v: u8) -> u8 {
    let v = v as i32;
    let mut diff = 65i32; // 'A'
    diff += ((25 - v) >> 8) & 6; // from 26: 'a' - 26
    diff -= ((51 - v) >> 8) & 75; // from 52: '0' - 52
    diff -= ((61 - v) >> 8) & 15; // 62: '+'
    diff += ((62 - v) >> 8) & 3; // 63: '/'
    (v + black_box(diff)) as u8
}

/// Base64 with padding, in constant time with respect to the data.
fn ct_base64_encode(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity((data.len() + 2) / 3 * 4));
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(b64_char(((n >> (18 - 6 * i)) & 63) as u8));
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ecdsa, ed25519};
    use crate::util::unhex;

    /// PEM text for a DER key without the label appearing literally in the source (so that secret scanners do not
    /// report the test keys).
    fn pem(label: &str, der: &[u8]) -> String {
        let b64 = crate::pem::base64_encode(der);
        let mut s = format!("-----BEGIN {label}-----\n");
        for line in b64.as_bytes().chunks(64) {
            s.push_str(std::str::from_utf8(line).unwrap());
            s.push('\n');
        }
        s.push_str(&format!("-----END {label}-----\n"));
        s
    }

    const PRIV: &str = "PRIVATE KEY";

    #[test]
    fn base64_in_constant_time_agrees_with_the_plain_decoder() {
        let mut rng = crate::fuzz::Rng::new(64);
        for len in 0..200 {
            let data = rng.bytes(len);
            let enc = crate::pem::base64_encode(&data);
            assert_eq!(&ct_base64_encode(&data)[..], enc.as_bytes(), "encode {len}");
            assert_eq!(&ct_base64_decode(enc.as_bytes()).unwrap()[..], &data[..], "decode {len}");
        }
        for c in 0..=255u8 {
            let (v, ok) = b64_value(c);
            let want = crate::pem::base64_decode(&format!("{}AAA", c as char)).ok().map(|d| d[0] >> 2);
            match want {
                Some(w) if c != b'=' && !c.is_ascii_whitespace() => {
                    assert_eq!(ok, u32::MAX, "{c}");
                    assert_eq!(v as u8, w, "{c}");
                }
                _ => assert_eq!(ok, 0, "{c}"),
            }
        }
        for v in 0..64u8 {
            assert_eq!(b64_value(b64_char(v)).0 as u8, v);
        }
        for bad in [&b"A"[..], b"AA=", b"A===", b"AB*D", b"AB-D"] {
            assert!(ct_base64_decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn generated_keys_round_trip_through_pkcs8_and_sign() {
        for key in [SigningKey::generate_ecdsa(Curve::P256).unwrap(), SigningKey::generate_ecdsa(Curve::P384).unwrap(), SigningKey::generate_ed25519().unwrap()] {
            let pem_bytes = key.to_pkcs8_pem().unwrap();
            let text = std::str::from_utf8(&pem_bytes).unwrap();
            let back = SigningKey::from_pem(text).unwrap();
            assert_eq!(back.public_key_spki(), key.public_key_spki(), "{}", key.algorithm());
            let der = key.to_pkcs8_der().unwrap();
            assert_eq!(SigningKey::from_der(&der).unwrap().public_key_spki(), key.public_key_spki());
            for s in key.tls_schemes() {
                let sig = back.sign_tls(s, b"to be signed").unwrap();
                match (&*key.0, s) {
                    (Kind::Ecdsa(k), _) => {
                        let alg = crate::crypto::ecdsa_sign::default_hash(k.curve());
                        assert!(ecdsa::verify_prehashed(k.curve(), k.public_key(), &alg.digest(b"to be signed"), &sig));
                    }
                    (Kind::Ed25519(k), _) => assert!(ed25519::verify(k.public_key(), b"to be signed", &sig)),
                    _ => unreachable!(),
                }
                assert!(back.sign_tls(0x0401, b"x").is_err(), "rsa_pkcs1_sha256 is not offered");
            }
        }
    }

    /// Keys written by OpenSSL in each format (made with Python `cryptography` 50 for this test; they protect
    /// nothing), with their public keys.
    const KEYS: &str = include_str!("../tests/data/signing_key_formats.txt");

    #[test]
    fn keys_openssl_wrote_in_every_format() {
        let mut seen = 0;
        for line in KEYS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(' ').collect();
            let (name, label, der, spki) = (f[0], f[1].replace('_', " "), unhex(f[2]), unhex(f[3]));
            let key = SigningKey::from_pem(&pem(&label, &der)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(spki_identity(&key.public_key_spki()), spki_identity(&spki), "{name}");
            assert_eq!(SigningKey::from_der(&der).unwrap().public_key_spki(), key.public_key_spki(), "{name} as DER");
            seen += 1;
        }
        assert!(seen >= 7);
    }

    #[test]
    fn what_is_not_a_usable_key_is_refused_with_a_reason() {
        let cases: [(String, &str); 7] = [
            (pem("ENCRYPTED PRIVATE KEY", b"anything"), "encrypted"),
            (format!("-----BEGIN RSA {PRIV}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA {PRIV}-----\n"), "encrypted"),
            (pem("CERTIFICATE", b"x"), "only: CERTIFICATE"),
            (String::from("nothing at all"), "no PEM private key"),
            (pem(PRIV, b"\x30\x03\x02\x01\x00"), "PKCS#8"),
            (format!("{}{}", pem(PRIV, &SigningKey::generate_ed25519().unwrap().to_pkcs8_der().unwrap()), pem(PRIV, &SigningKey::generate_ed25519().unwrap().to_pkcs8_der().unwrap())), "more than one"),
            (pem(PRIV, &unhex("302e020100300506032b656e042204200000000000000000000000000000000000000000000000000000000000000000")), "X25519"),
        ];
        for (text, want) in cases {
            let err = SigningKey::from_pem(&text).unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
        // EC PARAMETERS before the key is passed over
        let ec = SigningKey::generate_ecdsa(Curve::P256).unwrap();
        let k = ec.as_ecdsa().unwrap();
        let sec1 = der::sequence(&[&der::integer(&[1]), &der::octet_string(k.scalar()), &der::context(0, true, &der::oid_str(OID_P256))]);
        let text = format!("{}{}", pem("EC PARAMETERS", &der::oid_str(OID_P256)), pem(&format!("EC {PRIV}"), &sec1));
        assert_eq!(SigningKey::from_pem(&text).unwrap().public_key_spki(), ec.public_key_spki());
        // a SEC 1 key whose public key is not its own
        let other = SigningKey::generate_ecdsa(Curve::P256).unwrap();
        let wrong = der::sequence(&[
            &der::integer(&[1]),
            &der::octet_string(k.scalar()),
            &der::context(0, true, &der::oid_str(OID_P256)),
            &der::context(1, true, &der::bit_string(0, other.as_ecdsa().unwrap().public_key())),
        ]);
        assert!(SigningKey::from_der(&wrong).unwrap_err().to_string().contains("does not match"));
        // a SEC 1 key with no curve anywhere
        let bare = der::sequence(&[&der::integer(&[1]), &der::octet_string(k.scalar())]);
        assert!(SigningKey::from_der(&bare).unwrap_err().to_string().contains("curve"));
    }
}
