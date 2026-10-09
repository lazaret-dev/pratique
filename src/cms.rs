//! CMS / PKCS#7 `SignedData` (RFC 5652, RFC 2315): who signed what, and whether the signer's
//! certificate chains to a root the caller trusts at the time that matters.
//!
//! This is the signature container of Java archives (`META-INF/*.RSA`), Authenticode, Apple code
//! signatures, S/MIME, and RFC 3161 time-stamp tokens. [`SignedData::parse`] reads the BER or DER
//! that those tools write (indefinite lengths included, see [`crate::ber`]);
//! [`SignedData::verify`] checks every signer:
//!
//! 1. the signer's certificate is found (by issuer and serial number or by subject key identifier)
//!    among the certificates in the message and the ones the caller supplies;
//! 2. the signed attributes, if there are any, carry the digest of the content and its content
//!    type, and the signature over them (or over the content itself, with no attributes) is valid
//!    for the certificate's key: RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA over P-256 and P-384, Ed25519
//!    (RFC 8419);
//! 3. the certificate chains to the [`TrustStore`] for the wanted [`Purpose`], at a time that
//!    comes from an RFC 3161 time stamp on the signature when there is one (`Options::timestamps`),
//!    otherwise from the caller.
//!
//! What it deliberately does not do: check revocation (a separate step, [`crate::revocation`]);
//! trust the `signingTime` attribute (which the signer wrote; it is only reported); interpret what
//! was signed. Authenticode's `SpcIndirectDataContent` and the PE image digest, and Apple's
//! signature blobs, are built on top of this and are not here.
//!
//! SHA-1 is handled as a fact and a policy: the arithmetic of a SHA-1 signature is checked like any
//! other, it is listed in [`SignatureCheck::weaknesses`], and [`Options::allow_sha1`] (false unless
//! the caller sets it) decides whether it is accepted. MD5, DSA and the SHA-3 family are not
//! supported and are refused by name.
//!
//! The ESS signing-certificate attribute of a time-stamp token is not checked (the signer is found
//! by its issuer and serial number, and its chain must verify, so substituting a certificate
//! would take a certificate from a trusted issuer with the same serial number), and neither is the
//! requirement that the time-stamping extended key usage be the only one.

use std::borrow::Cow;

use crate::asn1::{self, Der, Tlv};
use crate::ber::{self, Node};
use crate::crypto::ecdsa;
use crate::crypto::ed25519;
use crate::crypto::sha1;
use crate::crypto::sha2::HashAlg;
use crate::verify_error;
use crate::x509::{Certificate, PublicKey, Purpose, TrustStore, VerifiedChain, VerifyOptions};

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
const OID_ALGORITHM_PROTECTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x34];
/// id-aa-timeStampToken (RFC 3161 section 3.4 of RFC 5035): a time stamp on a signature.
const OID_TIMESTAMP_TOKEN: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e];
/// Microsoft's name for the same attribute (RFC 3161 time stamps on Authenticode signatures).
const OID_MS_TIMESTAMP_TOKEN: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
/// id-ct-TSTInfo (RFC 3161): the content type of a time-stamp token.
const OID_TST_INFO: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];

const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// How a message, a signer or a time stamp failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not a well-formed SignedData (or, with the text, something in it that makes no sense).
    Malformed(&'static str),
    /// A ContentInfo, but not of type signedData.
    NotSignedData,
    /// A SignedData or SignerInfo version this code does not know.
    UnsupportedVersion(i64),
    /// The message has no signer, or the signer asked for is not there.
    NoSigner,
    /// The signer's certificate is neither in the message nor among the ones supplied.
    SignerCertificateNotFound,
    /// A digest algorithm that is not SHA-1 or SHA-2 (the OID, dotted).
    UnsupportedDigest(String),
    /// A signature algorithm, its parameters or its key this code does not verify, or one that does
    /// not fit the signer's key.
    UnsupportedSignature(String),
    /// The signed attributes are not what RFC 5652 section 5.3 asks of them.
    Attributes(&'static str),
    /// The content's digest is not the one in the signed attributes.
    DigestMismatch,
    /// The signature is not valid.
    BadSignature,
    /// The signature does not carry its content and none was supplied.
    ContentMissing,
    /// The signature carries its content and another one was supplied.
    ContentGiven,
    /// A SHA-1 signature or digest, and [`Options::allow_sha1`] is not set.
    WeakDigest,
    /// The signer's certificate does not chain to a trusted root for the purpose, at that time.
    Chain(verify_error::Error),
    /// [`Timestamps::Require`], and the signature has none.
    TimestampMissing,
    /// A time stamp that is not valid; the reason is in the inner error.
    Timestamp(Box<Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed CMS message: {m}"),
            Error::NotSignedData => write!(f, "not a CMS SignedData message"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported CMS version {v}"),
            Error::NoSigner => write!(f, "no such signer"),
            Error::SignerCertificateNotFound => write!(f, "the signer's certificate is not in the message"),
            Error::UnsupportedDigest(o) => write!(f, "unsupported digest algorithm {o}"),
            Error::UnsupportedSignature(m) => write!(f, "unsupported signature: {m}"),
            Error::Attributes(m) => write!(f, "signed attributes: {m}"),
            Error::DigestMismatch => write!(f, "the content does not match the digest that was signed"),
            Error::BadSignature => write!(f, "the signature is not valid"),
            Error::ContentMissing => write!(f, "the signature is detached and no content was supplied"),
            Error::ContentGiven => write!(f, "the signature carries its content and content was supplied as well"),
            Error::WeakDigest => write!(f, "the signature uses SHA-1"),
            Error::Chain(e) => write!(f, "signer certificate: {e}"),
            Error::TimestampMissing => write!(f, "the signature has no time stamp"),
            Error::Timestamp(e) => write!(f, "time stamp: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<verify_error::Error> for Error {
    fn from(e: verify_error::Error) -> Error {
        match e {
            verify_error::Error::Asn1(m) => Error::Malformed(m),
            other => Error::Chain(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Something the arithmetic does not say but a caller should know about a signature that checks out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Weakness {
    /// SHA-1 hashes the content, the signed attributes or the time stamp's message: collisions for
    /// it can be made, and a signature over it should not be believed.
    Sha1,
}

/// How a signer's certificate is named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerId {
    /// The DER of the issuer's name and the serial number, as a certificate's own fields give them
    /// (without leading zero bytes).
    IssuerAndSerial { issuer: Vec<u8>, serial: Vec<u8> },
    /// The certificate's subjectKeyIdentifier.
    SubjectKeyId(Vec<u8>),
}

#[derive(Clone, Debug)]
struct AlgId {
    oid: Vec<u8>,
    /// The DER of the parameters, if there are any.
    params: Option<Vec<u8>>,
}

impl AlgId {
    fn parse(n: &Node) -> Result<AlgId> {
        let mut it = n.with_tag(0x30)?.items()?;
        let oid = it.expect(0x06)?.content()?.to_vec();
        let params = if it.is_empty() { None } else { Some(it.next()?.der()?) };
        it.finish()?;
        Ok(AlgId { oid, params })
    }

    fn params_absent_or_null(&self) -> bool {
        self.params.as_deref().map_or(true, |p| p == [0x05, 0x00])
    }
}

#[derive(Clone, Debug)]
struct Attribute {
    oid: Vec<u8>,
    /// The DER of each value.
    values: Vec<Vec<u8>>,
}

impl Attribute {
    fn parse(n: &Node) -> Result<Attribute> {
        let mut it = n.with_tag(0x30)?.items()?;
        let oid = it.expect(0x06)?.content()?.to_vec();
        let values = it.expect(0x31)?.children()?.iter().map(|v| Ok(v.der()?)).collect::<Result<Vec<_>>>()?;
        it.finish()?;
        Ok(Attribute { oid, values })
    }
}

fn parse_attributes(set: &Node) -> Result<Vec<Attribute>> {
    set.children()?.iter().map(Attribute::parse).collect()
}

/// A digest algorithm this code can compute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Digest {
    Sha1,
    Sha2(HashAlg),
}

impl Digest {
    fn from_oid(oid: &[u8]) -> Result<Digest> {
        Ok(match oid {
            OID_SHA1 => Digest::Sha1,
            OID_SHA256 => Digest::Sha2(HashAlg::Sha256),
            OID_SHA384 => Digest::Sha2(HashAlg::Sha384),
            OID_SHA512 => Digest::Sha2(HashAlg::Sha512),
            other => return Err(Error::UnsupportedDigest(asn1::oid_to_string(other))),
        })
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Digest::Sha1 => sha1::digest(data).to_vec(),
            Digest::Sha2(h) => h.digest(data),
        }
    }

    fn is_weak(self) -> bool {
        self == Digest::Sha1
    }
}

/// What a signature algorithm identifier says to do with the signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigKind {
    Rsa(Digest),
    Pss { hash: HashAlg, mgf: HashAlg, salt_len: usize },
    Ecdsa(Digest),
    Ed25519,
}

fn small_int(n: &Node) -> Result<i64> {
    let c = n.with_tag(0x02)?.content()?;
    if c.is_empty() || c.len() > 4 || c[0] & 0x80 != 0 {
        return Err(Error::Malformed("INTEGER out of range"));
    }
    Ok(c.iter().fold(0i64, |a, b| (a << 8) | *b as i64))
}

/// `[n] EXPLICIT X`: the one child.
fn explicit<'n, 'a>(n: &'n Node<'a>) -> Result<&'n Node<'a>> {
    match n.children()? {
        [one] => Ok(one),
        _ => Err(Error::Malformed("an explicitly tagged element must hold exactly one element")),
    }
}

fn sig_kind(alg: &AlgId, digest: Digest) -> Result<SigKind> {
    let plain = |d: Digest| if alg.params_absent_or_null() { Ok(d) } else { Err(Error::UnsupportedSignature("parameters on a signature algorithm that takes none".into())) };
    Ok(match alg.oid.as_slice() {
        OID_RSA => SigKind::Rsa(plain(digest)?),
        OID_SHA1_RSA => SigKind::Rsa(plain(Digest::Sha1)?),
        OID_SHA256_RSA => SigKind::Rsa(plain(Digest::Sha2(HashAlg::Sha256))?),
        OID_SHA384_RSA => SigKind::Rsa(plain(Digest::Sha2(HashAlg::Sha384))?),
        OID_SHA512_RSA => SigKind::Rsa(plain(Digest::Sha2(HashAlg::Sha512))?),
        OID_EC_PUBLIC_KEY => SigKind::Ecdsa(plain(digest)?),
        OID_ECDSA_SHA1 => SigKind::Ecdsa(plain(Digest::Sha1)?),
        OID_ECDSA_SHA256 => SigKind::Ecdsa(plain(Digest::Sha2(HashAlg::Sha256))?),
        OID_ECDSA_SHA384 => SigKind::Ecdsa(plain(Digest::Sha2(HashAlg::Sha384))?),
        OID_ECDSA_SHA512 => SigKind::Ecdsa(plain(Digest::Sha2(HashAlg::Sha512))?),
        OID_ED25519 if alg.params.is_none() => SigKind::Ed25519,
        OID_ED25519 => return Err(Error::UnsupportedSignature("parameters on an Ed25519 signature".into())),
        OID_RSASSA_PSS => pss_kind(alg.params.as_deref())?,
        other => return Err(Error::UnsupportedSignature(format!("algorithm {}", asn1::oid_to_string(other)))),
    })
}

/// RSASSA-PSS-params (RFC 4055 section 3.1). The defaults of that structure are SHA-1, so without
/// parameters, or with SHA-1 in them, there is nothing to verify with.
fn pss_kind(params: Option<&[u8]>) -> Result<SigKind> {
    let sha1_unsupported = || Error::UnsupportedSignature("RSASSA-PSS with SHA-1".into());
    let Some(params) = params else { return Err(sha1_unsupported()) };
    let root = ber::parse_exact(params)?;
    let mut it = root.with_tag(0x30)?.items()?;
    let sha2 = |d: Digest| match d {
        Digest::Sha2(h) => Ok(h),
        Digest::Sha1 => Err(sha1_unsupported()),
    };
    let hash = match it.optional(0xa0) {
        Some(n) => sha2(Digest::from_oid(&AlgId::parse(explicit(n)?)?.oid)?)?,
        None => return Err(sha1_unsupported()),
    };
    let mgf = match it.optional(0xa1) {
        Some(n) => {
            let mut m = explicit(n)?.with_tag(0x30)?.items()?;
            if m.expect(0x06)?.content()? != OID_MGF1 {
                return Err(Error::UnsupportedSignature("RSASSA-PSS with a mask generation function other than MGF1".into()));
            }
            let inner = AlgId::parse(m.next()?)?;
            m.finish()?;
            sha2(Digest::from_oid(&inner.oid)?)?
        }
        None => return Err(sha1_unsupported()),
    };
    let salt_len = match it.optional(0xa2) {
        Some(n) => small_int(explicit(n)?)? as usize,
        None => 20,
    };
    if let Some(n) = it.optional(0xa3) {
        if small_int(explicit(n)?)? != 1 {
            return Err(Error::UnsupportedSignature("RSASSA-PSS trailer field other than 1".into()));
        }
    }
    it.finish()?;
    Ok(SigKind::Pss { hash, mgf, salt_len })
}

fn is_sha1(k: SigKind) -> bool {
    matches!(k, SigKind::Rsa(d) | SigKind::Ecdsa(d) if d.is_weak())
}

/// One signature in a SignedData.
#[derive(Clone, Debug)]
pub struct SignerInfo {
    sid: SignerId,
    digest_alg: AlgId,
    /// The signed attributes as DER with the tag of a SET OF (what is digested), and as a list.
    signed_attrs: Option<(Vec<u8>, Vec<Attribute>)>,
    signature_alg: AlgId,
    signature: Vec<u8>,
    unsigned_attrs: Vec<Attribute>,
}

impl SignerInfo {
    fn parse(n: &Node) -> Result<SignerInfo> {
        let mut it = n.with_tag(0x30)?.items()?;
        let version = small_int(it.next()?)?;
        if version != 1 && version != 3 {
            return Err(Error::UnsupportedVersion(version));
        }
        let sid_node = it.next()?;
        let sid = match sid_node.tag() {
            0x30 => {
                let mut s = sid_node.items()?;
                let issuer = s.expect(0x30)?.der()?;
                let serial = asn1::unsigned_integer(&s.expect(0x02)?.tlv()?)?;
                s.finish()?;
                SignerId::IssuerAndSerial { issuer, serial }
            }
            0x80 | 0xa0 => SignerId::SubjectKeyId(sid_node.octets()?.into_owned()),
            _ => return Err(Error::Malformed("unknown form of signer identifier")),
        };
        let digest_alg = AlgId::parse(it.next()?)?;
        let signed_attrs = match it.optional(0xa0) {
            Some(set) => {
                let attrs = parse_attributes(set)?;
                if attrs.is_empty() {
                    return Err(Error::Attributes("an empty set of signed attributes"));
                }
                Some((set.der_as(0x31)?, attrs))
            }
            None => None,
        };
        let signature_alg = AlgId::parse(it.next()?)?;
        let sig_node = it.next()?;
        if sig_node.tag() != 0x04 && sig_node.tag() != 0x24 {
            return Err(Error::Malformed("the signature is not an OCTET STRING"));
        }
        let signature = sig_node.octets()?.into_owned();
        let unsigned_attrs = match it.optional(0xa1) {
            Some(set) => parse_attributes(set)?,
            None => Vec::new(),
        };
        it.finish()?;
        Ok(SignerInfo { sid, digest_alg, signed_attrs, signature_alg, signature, unsigned_attrs })
    }

    /// How the signer's certificate is named.
    pub fn id(&self) -> &SignerId {
        &self.sid
    }

    /// The signature value (what a time stamp on this signature covers).
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The OID of the digest algorithm, dotted.
    pub fn digest_algorithm(&self) -> String {
        asn1::oid_to_string(&self.digest_alg.oid)
    }

    /// The OID of the signature algorithm, dotted.
    pub fn signature_algorithm(&self) -> String {
        asn1::oid_to_string(&self.signature_alg.oid)
    }

    /// The value (DER) of a signed attribute that occurs once with one value, by OID (content octets).
    /// Signed attributes are covered by the signature, so after [`SignedData::verify_signature`]
    /// they are the signer's; before it they are not anybody's.
    pub fn signed_attribute(&self, oid: &[u8]) -> Option<&[u8]> {
        let (_, attrs) = self.signed_attrs.as_ref()?;
        let mut found = attrs.iter().filter(|a| a.oid == oid);
        match (found.next(), found.next()) {
            (Some(a), None) if a.values.len() == 1 => Some(&a.values[0]),
            _ => None,
        }
    }

    /// The values (DER) of an unsigned attribute, by OID (content octets). Unsigned attributes are
    /// not covered by the signature: anybody can remove them or add them.
    pub fn unsigned_attributes<'s>(&'s self, oid: &'s [u8]) -> impl Iterator<Item = &'s [u8]> + 's {
        self.unsigned_attrs.iter().filter(move |a| a.oid == oid).flat_map(|a| a.values.iter().map(|v| v.as_slice()))
    }

    /// The `signingTime` the signer claims, as Unix seconds. Nothing vouches for it (unless a time
    /// stamp does): a signer can write any date there.
    pub fn claimed_signing_time(&self) -> Option<i64> {
        let v = self.signed_attribute(OID_SIGNING_TIME)?;
        let mut d = Der::new(v);
        let t = d.next().ok()?;
        d.finish().ok()?;
        asn1::parse_time(&t).ok()
    }

    /// The digest algorithm, and what the signature algorithm identifier says to do.
    fn algorithms(&self) -> Result<(Digest, SigKind)> {
        let digest = Digest::from_oid(&self.digest_alg.oid)?;
        let kind = sig_kind(&self.signature_alg, digest)?;
        Ok((digest, kind))
    }

    /// The signature over `content` (the content octets of the signed content) by `key`: checks the
    /// signed attributes and the signature, and says whether SHA-1 was in it.
    fn check(&self, content_type: &[u8], content: &[u8], key: &PublicKey) -> Result<Vec<Weakness>> {
        let (digest, kind) = self.algorithms()?;
        let signed: Cow<[u8]> = match &self.signed_attrs {
            Some((der, attrs)) => {
                check_attributes(attrs, content_type, content, digest, &self.digest_alg, &self.signature_alg)?;
                Cow::Borrowed(der)
            }
            None => Cow::Borrowed(content),
        };
        let ok = match (kind, key) {
            (SigKind::Rsa(Digest::Sha1), PublicKey::Rsa(k)) => k.verify_pkcs1_sha1(&signed, &self.signature),
            (SigKind::Rsa(Digest::Sha2(h)), PublicKey::Rsa(k)) => k.verify_pkcs1(h, &signed, &self.signature),
            (SigKind::Pss { hash, mgf, salt_len }, PublicKey::Rsa(k)) => k.verify_pss_with(hash, mgf, salt_len, &signed, &self.signature),
            (SigKind::Ecdsa(d), PublicKey::Ec { curve, point }) => ecdsa::verify_prehashed(*curve, point, &d.digest(&signed), &self.signature),
            (SigKind::Ed25519, PublicKey::Ed25519(k)) => ed25519::verify(k, &signed, &self.signature),
            _ => return Err(Error::UnsupportedSignature("the signature algorithm does not fit the signer's key".into())),
        };
        if !ok {
            return Err(Error::BadSignature);
        }
        let mut weaknesses = Vec::new();
        if digest.is_weak() || is_sha1(kind) {
            weaknesses.push(Weakness::Sha1);
        }
        Ok(weaknesses)
    }
}

/// RFC 5652 section 5.3: contentType and messageDigest are required, once each with one value, and
/// must say what the content is and what it hashes to; CMSAlgorithmProtection (RFC 6211), when
/// there, must say what the SignerInfo says.
fn check_attributes(attrs: &[Attribute], content_type: &[u8], content: &[u8], digest: Digest, digest_alg: &AlgId, sig_alg: &AlgId) -> Result<()> {
    let once = |oid: &[u8], what: &'static str| -> Result<&Vec<u8>> {
        let mut found = attrs.iter().filter(|a| a.oid == oid);
        match (found.next(), found.next()) {
            (Some(a), None) => match a.values.as_slice() {
                [v] => Ok(v),
                _ => Err(Error::Attributes(what)),
            },
            _ => Err(Error::Attributes(what)),
        }
    };
    let ct = ber::parse_exact(once(OID_CONTENT_TYPE, "contentType must occur exactly once, with one value")?)?;
    if ct.with_tag(0x06)?.content()? != content_type {
        return Err(Error::Attributes("contentType is not the type of the content"));
    }
    if attrs.iter().any(|a| a.oid == OID_ALGORITHM_PROTECTION) {
        let p = ber::parse_exact(once(OID_ALGORITHM_PROTECTION, "CMSAlgorithmProtection must occur once")?)?;
        let mut it = p.with_tag(0x30)?.items()?;
        let protected_digest = AlgId::parse(it.expect(0x30)?)?;
        if protected_digest.oid != digest_alg.oid {
            return Err(Error::Attributes("CMSAlgorithmProtection names another digest algorithm than the signer info"));
        }
        if let Some(sig) = it.optional(0xa1) {
            // [1] IMPLICIT AlgorithmIdentifier: the same elements under another tag
            let as_sequence = sig.der_as(0x30)?;
            let protected_sig = AlgId::parse(&ber::parse_exact(&as_sequence)?)?;
            if protected_sig.oid != sig_alg.oid || (protected_sig.oid == OID_RSASSA_PSS && protected_sig.params != sig_alg.params) {
                return Err(Error::Attributes("CMSAlgorithmProtection names another signature algorithm than the signer info"));
            }
        }
        if it.optional(0xa2).is_some() {
            return Err(Error::Attributes("CMSAlgorithmProtection names a MAC algorithm"));
        }
        it.finish()?;
    }
    let md = ber::parse_exact(once(OID_MESSAGE_DIGEST, "messageDigest must occur exactly once, with one value")?)?;
    if md.with_tag(0x04)?.octets()?.as_ref() != digest.digest(content).as_slice() {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}

/// A parsed SignedData: the content (if it is in the message), the certificates and the signers.
/// Nothing in it is believed until [`verify`](SignedData::verify) or
/// [`verify_signer`](SignedData::verify_signer) says so.
#[derive(Debug)]
pub struct SignedData {
    content_type: Vec<u8>,
    content: Option<Vec<u8>>,
    certificates: Vec<Certificate>,
    skipped_certificates: usize,
    signers: Vec<SignerInfo>,
}

impl SignedData {
    /// Parses a ContentInfo of type signedData, or a bare SignedData, in BER or DER. Trailing zero
    /// bytes are ignored (the entries of a PE file's certificate table are padded with them);
    /// anything else after the message is an error.
    pub fn parse(data: &[u8]) -> Result<SignedData> {
        let (root, rest) = ber::parse(data)?;
        if rest.iter().any(|b| *b != 0) {
            return Err(Error::Malformed("data after the message"));
        }
        let mut top = root.with_tag(0x30)?.items()?;
        let sd = if top.peek_tag() == Some(0x06) {
            if top.next()?.content()? != OID_SIGNED_DATA {
                return Err(Error::NotSignedData);
            }
            let ctx = top.expect(0xa0)?;
            top.finish()?;
            explicit(ctx)?
        } else {
            &root
        };
        SignedData::from_node(sd)
    }

    fn from_node(sd: &Node) -> Result<SignedData> {
        let mut it = sd.with_tag(0x30)?.items()?;
        let version = small_int(it.next()?)?;
        if !matches!(version, 1 | 3 | 4 | 5) {
            return Err(Error::UnsupportedVersion(version));
        }
        for alg in it.expect(0x31)?.children()? {
            AlgId::parse(alg)?;
        }
        let mut eci = it.expect(0x30)?.items()?;
        let content_type = eci.expect(0x06)?.content()?.to_vec();
        let content = match eci.optional(0xa0) {
            // PKCS#7 digests the content octets of whatever the content is, CMS the octets of an OCTET
            // STRING: the same thing. (Plain data is always an OCTET STRING; other types may be anything,
            // Authenticode's is a SEQUENCE, and the signature covers the octets, not the tag.)
            Some(c) => {
                let inner = explicit(c)?;
                if content_type == OID_DATA && !matches!(inner.tag(), 0x04 | 0x24) {
                    return Err(Error::Malformed("the content of a data message is not an OCTET STRING"));
                }
                Some(inner.der_content()?)
            }
            None => None,
        };
        eci.finish()?;

        let mut certificates = Vec::new();
        let mut skipped = 0;
        if let Some(set) = it.optional(0xa0) {
            for c in set.children()? {
                // other kinds of certificate (attribute certificates and so on) are not X.509 certificates
                match (c.tag() == 0x30).then(|| c.der().ok().and_then(|d| Certificate::parse(&d).ok())).flatten() {
                    Some(cert) => certificates.push(cert),
                    None => skipped += 1,
                }
            }
        }
        // revocation information, which is not used here
        it.optional(0xa1);
        let signers = it.expect(0x31)?.children()?.iter().map(SignerInfo::parse).collect::<Result<Vec<_>>>()?;
        it.finish()?;
        Ok(SignedData { content_type, content, certificates, skipped_certificates: skipped, signers })
    }

    /// The content type (dotted OID): `1.2.840.113549.1.7.1` for plain data.
    pub fn content_type(&self) -> String {
        asn1::oid_to_string(&self.content_type)
    }

    /// The content type as content octets.
    pub fn content_type_oid(&self) -> &[u8] {
        &self.content_type
    }

    /// The signed content, if the message carries it (the content octets: for an OCTET STRING its
    /// bytes). It is whatever the sender put there, and is not authentic until a signer verified.
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    /// The certificates in the message, in order. A critical extension this library does not know
    /// does not keep a certificate out of this list (chain verification is what judges it).
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// How many entries of the certificate set were not X.509 certificates this code could read.
    pub fn skipped_certificates(&self) -> usize {
        self.skipped_certificates
    }

    pub fn signers(&self) -> &[SignerInfo] {
        &self.signers
    }

    /// The signed bytes: the carried content, or the detached content the caller supplies.
    fn content_for<'s>(&'s self, detached: Option<&'s [u8]>) -> Result<&'s [u8]> {
        match (&self.content, detached) {
            (Some(c), None) => Ok(c),
            (None, Some(d)) => Ok(d),
            (None, None) => Err(Error::ContentMissing),
            (Some(_), Some(_)) => Err(Error::ContentGiven),
        }
    }

    fn find_certificate<'s>(&'s self, sid: &SignerId, extra: &'s [Certificate]) -> Option<&'s Certificate> {
        self.certificates.iter().chain(extra).find(|c| match sid {
            SignerId::IssuerAndSerial { issuer, serial } => c.issuer_der == *issuer && c.serial == *serial,
            SignerId::SubjectKeyId(id) => c.extension(OID_SKI).is_some_and(|e| {
                let mut d = Der::new(&e.value);
                matches!(d.expect(asn1::TAG_OCTET_STRING), Ok(t) if t.content == id.as_slice()) && d.is_empty()
            }),
        })
    }

    /// Checks one signer's signature, without asking whether the certificate is to be trusted:
    /// the signed attributes, the digest of the content and the signature itself. `detached` is
    /// the content when the message does not carry it (and must be `None` when it does).
    /// `extra_certs` are certificates to look for the signer's in as well, for messages that came
    /// without any.
    pub fn verify_signature(&self, signer: usize, detached: Option<&[u8]>, extra_certs: &[Certificate]) -> Result<SignatureCheck> {
        let info = self.signers.get(signer).ok_or(Error::NoSigner)?;
        let content = self.content_for(detached)?;
        let cert = self.find_certificate(&info.sid, extra_certs).ok_or(Error::SignerCertificateNotFound)?;
        let weaknesses = info.check(&self.content_type, content, &cert.public_key)?;
        Ok(SignatureCheck { certificate_der: cert.der.clone(), weaknesses })
    }

    /// The signer's certificate first, then every other certificate of the message and of
    /// `extra_certs`: what chain building starts from.
    fn chain_input<'s>(&'s self, leaf: &'s [u8], extra: &'s [Certificate]) -> Vec<&'s [u8]> {
        let mut chain = vec![leaf];
        chain.extend(self.certificates.iter().chain(extra).map(|c| c.der.as_slice()).filter(|d| *d != leaf));
        chain
    }

    /// Verifies one signer completely: [`verify_signature`](Self::verify_signature), then the
    /// certificate chain against `options.trust` for `options.purpose`, at the time of a valid time
    /// stamp on the signature or else at `options.time`.
    pub fn verify_signer(&self, signer: usize, detached: Option<&[u8]>, options: &Options) -> Result<VerifiedSigner> {
        let check = self.verify_signature(signer, detached, options.extra_certs)?;
        let info = &self.signers[signer];
        let mut weaknesses = check.weaknesses;
        if !weaknesses.is_empty() && !options.allow_sha1 {
            return Err(Error::WeakDigest);
        }

        let mut timestamp = None;
        if options.timestamps != Timestamps::Ignore {
            let trust = options.timestamp_trust.unwrap_or(options.trust);
            let mut best: Option<Timestamp> = None;
            let mut first_err = None;
            for token in info.unsigned_attributes(OID_TIMESTAMP_TOKEN).chain(info.unsigned_attributes(OID_MS_TIMESTAMP_TOKEN)) {
                match verify_timestamp(token, info.signature(), trust, options.allow_sha1) {
                    Ok(t) if best.as_ref().map_or(true, |b| t.time < b.time) => best = Some(t),
                    Ok(_) => {}
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
            match (best, first_err) {
                (Some(t), _) => timestamp = Some(t),
                (None, Some(e)) => return Err(Error::Timestamp(Box::new(e))),
                (None, None) if options.timestamps == Timestamps::Require => return Err(Error::TimestampMissing),
                (None, None) => {}
            }
        }
        let chain_time = timestamp.as_ref().map_or(options.time, |t| t.time);
        if let Some(t) = &timestamp {
            for w in &t.weaknesses {
                if !weaknesses.contains(w) {
                    weaknesses.push(*w);
                }
            }
        }
        let verify_options = VerifyOptions::new(options.purpose.clone(), chain_time);
        let chain = options.trust.verify_chain(&self.chain_input(&check.certificate_der, options.extra_certs), &verify_options)?;
        Ok(VerifiedSigner { chain, weaknesses, timestamp, claimed_signing_time: info.claimed_signing_time(), chain_time })
    }

    /// Verifies every signer (see [`verify_signer`](Self::verify_signer)); one that does not
    /// verify fails the whole message, as does a message without signers. A caller that accepts a
    /// message with at least one good signature calls `verify_signer` itself.
    pub fn verify(&self, detached: Option<&[u8]>, options: &Options) -> Result<Vec<VerifiedSigner>> {
        if self.signers.is_empty() {
            return Err(Error::NoSigner);
        }
        (0..self.signers.len()).map(|i| self.verify_signer(i, detached, options)).collect()
    }
}

/// What [`SignedData::verify_signature`] found out.
#[derive(Debug)]
pub struct SignatureCheck {
    /// The signer's certificate (DER), found in the message or among the ones supplied.
    pub certificate_der: Vec<u8>,
    /// Empty for a signature that is good in every way this code can tell.
    pub weaknesses: Vec<Weakness>,
}

/// What to do with RFC 3161 time stamps on signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timestamps {
    /// Do not look at them: the chain is verified at [`Options::time`].
    Ignore,
    /// Use a valid one, if there is any, to say when the signature existed (the chain is then
    /// verified at that time, so a certificate that has expired since still counts); a signature
    /// whose time stamps are all invalid fails; one without time stamps is verified at
    /// [`Options::time`].
    Verify,
    /// As `Verify`, and a signature without a valid time stamp fails.
    Require,
}

/// What [`SignedData::verify`] checks a signer against.
#[derive(Clone)]
#[non_exhaustive]
pub struct Options<'a> {
    /// The roots the signer's chain must end in.
    pub trust: &'a TrustStore,
    /// What the signer's certificate is for ([`Purpose::CodeSigning`] for code, and so on).
    pub purpose: Purpose,
    /// The time (Unix seconds) the chain must be valid at when no time stamp says otherwise: the
    /// caller's now. The library reads no clock.
    pub time: i64,
    /// The default is [`Timestamps::Verify`].
    pub timestamps: Timestamps,
    /// The roots that time-stamp authorities must end in, when they are not the same as `trust`.
    pub timestamp_trust: Option<&'a TrustStore>,
    /// Accept SHA-1 (see [`Weakness::Sha1`]); false by default.
    pub allow_sha1: bool,
    /// Certificates to look for the signer's and the intermediates in, besides the message's own.
    pub extra_certs: &'a [Certificate],
}

impl<'a> Options<'a> {
    pub fn new(trust: &'a TrustStore, purpose: Purpose, time: i64) -> Options<'a> {
        Options { trust, purpose, time, timestamps: Timestamps::Verify, timestamp_trust: None, allow_sha1: false, extra_certs: &[] }
    }
}

/// A signer that verified.
#[derive(Debug)]
pub struct VerifiedSigner {
    /// The leaf and the path to the trust anchor.
    pub chain: VerifiedChain,
    /// What is weak about the signature or its time stamp, if the caller let it through.
    pub weaknesses: Vec<Weakness>,
    /// The time stamp that decided [`chain_time`](Self::chain_time), if one did.
    pub timestamp: Option<Timestamp>,
    /// The `signingTime` the signer wrote: unauthenticated.
    pub claimed_signing_time: Option<i64>,
    /// The time the chain was verified at.
    pub chain_time: i64,
}

/// A verified RFC 3161 time stamp.
#[derive(Debug)]
pub struct Timestamp {
    /// genTime, in Unix seconds (any fraction of a second is dropped).
    pub time: i64,
    /// The time-stamping authority's chain, verified at `time`.
    pub chain: VerifiedChain,
    /// The authority's policy (dotted OID).
    pub policy: String,
    /// The serial number of the token (the content octets of the INTEGER).
    pub serial: Vec<u8>,
    pub weaknesses: Vec<Weakness>,
}

/// Verifies an RFC 3161 time-stamp token over `message` (the bytes that were time-stamped: for a
/// signature's time stamp, the signature value): the token's signature, the authority's chain to
/// `trust` for [`Purpose::TimeStamping`] at the token's own time, and that the token's message
/// imprint is the hash of `message`.
pub fn verify_timestamp(token: &[u8], message: &[u8], trust: &TrustStore, allow_sha1: bool) -> Result<Timestamp> {
    verify_timestamp_with(token, message, trust, allow_sha1, &[])
}

/// The time-stamp token in `data`: an RFC 3161 `TimeStampResp` (a status, and for a request that was
/// granted the token), which is what Sigstore bundles carry, or a bare token as in a signature's
/// unsigned attributes. A response that is not a grant is an error.
pub fn timestamp_token(data: &[u8]) -> Result<Vec<u8>> {
    let (root, rest) = ber::parse(data)?;
    if rest.iter().any(|b| *b != 0) {
        return Err(Error::Malformed("data after the message"));
    }
    let mut top = root.with_tag(0x30)?.items()?;
    if top.peek_tag() != Some(0x30) {
        return Ok(data.to_vec());
    }
    let mut status = top.next()?.with_tag(0x30)?.items()?;
    if !matches!(small_int(status.next()?)?, 0 | 1) {
        return Err(Error::Malformed("the time-stamp response is not a grant"));
    }
    let token = top.expect(0x30)?;
    top.finish()?;
    Ok(token.der()?)
}

/// As [`verify_timestamp`], with `extra_certs` to look for the authority's certificate and the
/// intermediates in besides the token's own (a token made without `certReq` carries none).
pub fn verify_timestamp_with(token: &[u8], message: &[u8], trust: &TrustStore, allow_sha1: bool, extra_certs: &[Certificate]) -> Result<Timestamp> {
    let sd = SignedData::parse(token)?;
    if sd.content_type != OID_TST_INFO {
        return Err(Error::Malformed("the token's content is not a TSTInfo"));
    }
    if sd.signers.len() != 1 {
        return Err(Error::Malformed("a time-stamp token has exactly one signer"));
    }
    let check = sd.verify_signature(0, None, extra_certs)?;
    let tst = ber::parse_exact(sd.content().ok_or(Error::ContentMissing)?)?;

    let mut it = tst.with_tag(0x30)?.items()?;
    if small_int(it.next()?)? != 1 {
        return Err(Error::Malformed("unsupported TSTInfo version"));
    }
    let policy = asn1::oid_to_string(it.expect(0x06)?.content()?);
    let mut imprint = it.expect(0x30)?.items()?;
    let digest = Digest::from_oid(&AlgId::parse(imprint.next()?)?.oid)?;
    let hashed = imprint.expect(0x04)?.octets()?;
    imprint.finish()?;
    if hashed.as_ref() != digest.digest(message).as_slice() {
        return Err(Error::Malformed("the time stamp is not for this message"));
    }
    let serial = it.expect(0x02)?.content()?.to_vec();
    let time = gen_time(&it.expect(asn1::TAG_GENERALIZED_TIME)?.tlv()?)?;

    let mut weaknesses = check.weaknesses;
    if digest.is_weak() && !weaknesses.contains(&Weakness::Sha1) {
        weaknesses.push(Weakness::Sha1);
    }
    if !weaknesses.is_empty() && !allow_sha1 {
        return Err(Error::WeakDigest);
    }
    let options = VerifyOptions::new(Purpose::TimeStamping, time);
    let chain = trust.verify_chain(&sd.chain_input(&check.certificate_der, extra_certs), &options)?;
    Ok(Timestamp { time, chain, policy, serial, weaknesses })
}

/// genTime may carry a fraction of a second (`20260401123456.5Z`), which [`asn1::parse_time`] does not read.
fn gen_time(t: &Tlv) -> Result<i64> {
    let c = t.content;
    let whole: Vec<u8> = match c.iter().position(|b| *b == b'.') {
        Some(i) if i == 14 && c.len() > 16 && c.ends_with(b"Z") && c[15..c.len() - 1].iter().all(|b| b.is_ascii_digit()) => {
            let mut v = c[..14].to_vec();
            v.push(b'Z');
            v
        }
        _ => c.to_vec(),
    };
    Ok(asn1::parse_time(&Tlv { tag: t.tag, content: &whole, raw: &whole })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;
    use std::collections::BTreeMap;

    const FIXTURES: &str = include_str!("../tests/data/cms_fixtures.txt");

    /// 2026-10-05 12:00:00 UTC: after the fixtures' certificates became valid and before they expire.
    const NOW: i64 = 1_791_201_600;
    const BEFORE_ALL: i64 = 1_767_139_200; // 2025-12-31
    const AFTER_LEAVES: i64 = 2_082_844_800; // 2036-01-02
    const APRIL_1_2026_9H: i64 = 1_775_034_000;
    const APRIL_1_2026_12H34M56S: i64 = 1_775_046_896;

    /// The fixtures were signed before the crate was renamed from tiny_https to pratique, so the name in them is the old one.
    const HELLO: &[u8] = b"tiny_https cms fixture: the message that is signed\n";

    struct Fx {
        certs: BTreeMap<String, Vec<u8>>,
        contents: BTreeMap<String, Vec<u8>>,
        blobs: BTreeMap<String, Vec<u8>>,
    }

    impl Fx {
        fn load() -> Fx {
            let mut f = Fx { certs: BTreeMap::new(), contents: BTreeMap::new(), blobs: BTreeMap::new() };
            for line in FIXTURES.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
                let p: Vec<&str> = line.split(' ').collect();
                let map = match p[0] {
                    "cert" => &mut f.certs,
                    "content" => &mut f.contents,
                    "blob" => &mut f.blobs,
                    _ => panic!("{line:.40}"),
                };
                map.insert(p[1].to_string(), unhex(p[2]));
            }
            f
        }

        fn store(&self, roots: &[&str]) -> TrustStore {
            let mut t = TrustStore::empty();
            for r in roots {
                t.add_der(&self.certs[*r]).unwrap();
            }
            t
        }

        fn cert(&self, name: &str) -> Certificate {
            Certificate::from_der(&self.certs[name]).unwrap()
        }

        fn parse(&self, blob: &str) -> SignedData {
            SignedData::parse(&self.blobs[blob]).unwrap_or_else(|e| panic!("{blob}: {e}"))
        }
    }

    /// `blob` with one bit flipped in the middle of the first occurrence of `needle`.
    fn flip_in(blob: &[u8], needle: &[u8]) -> Vec<u8> {
        let at = blob.windows(needle.len()).position(|w| w == needle).expect("needle is in the blob");
        let mut b = blob.to_vec();
        b[at + needle.len() / 2] ^= 0x04;
        b
    }

    fn replace_last(blob: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let at = blob.windows(from.len()).rposition(|w| w == from).expect("pattern is in the blob");
        let mut b = blob.to_vec();
        b[at..at + from.len()].copy_from_slice(to);
        b
    }

    fn replace_all(blob: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let mut b = blob.to_vec();
        let mut i = 0;
        while i + from.len() <= b.len() {
            if b[i..i + from.len()] == *from {
                b[i..i + from.len()].copy_from_slice(to);
                i += from.len();
            } else {
                i += 1;
            }
        }
        b
    }

    #[test]
    fn oids_are_what_they_say() {
        for (oid, dotted) in [
            (OID_SIGNED_DATA, "1.2.840.113549.1.7.2"),
            (OID_DATA, "1.2.840.113549.1.7.1"),
            (OID_CONTENT_TYPE, "1.2.840.113549.1.9.3"),
            (OID_MESSAGE_DIGEST, "1.2.840.113549.1.9.4"),
            (OID_SIGNING_TIME, "1.2.840.113549.1.9.5"),
            (OID_ALGORITHM_PROTECTION, "1.2.840.113549.1.9.52"),
            (OID_TIMESTAMP_TOKEN, "1.2.840.113549.1.9.16.2.14"),
            (OID_MS_TIMESTAMP_TOKEN, "1.3.6.1.4.1.311.3.3.1"),
            (OID_TST_INFO, "1.2.840.113549.1.9.16.1.4"),
            (OID_SKI, "2.5.29.14"),
            (OID_SHA1, "1.3.14.3.2.26"),
            (OID_SHA256, "2.16.840.1.101.3.4.2.1"),
            (OID_SHA384, "2.16.840.1.101.3.4.2.2"),
            (OID_SHA512, "2.16.840.1.101.3.4.2.3"),
            (OID_RSA, "1.2.840.113549.1.1.1"),
            (OID_SHA1_RSA, "1.2.840.113549.1.1.5"),
            (OID_SHA256_RSA, "1.2.840.113549.1.1.11"),
            (OID_SHA384_RSA, "1.2.840.113549.1.1.12"),
            (OID_SHA512_RSA, "1.2.840.113549.1.1.13"),
            (OID_RSASSA_PSS, "1.2.840.113549.1.1.10"),
            (OID_MGF1, "1.2.840.113549.1.1.8"),
            (OID_EC_PUBLIC_KEY, "1.2.840.10045.2.1"),
            (OID_ECDSA_SHA1, "1.2.840.10045.4.1"),
            (OID_ECDSA_SHA256, "1.2.840.10045.4.3.2"),
            (OID_ECDSA_SHA384, "1.2.840.10045.4.3.3"),
            (OID_ECDSA_SHA512, "1.2.840.10045.4.3.4"),
            (OID_ED25519, "1.3.101.112"),
        ] {
            assert_eq!(asn1::oid_from_string(dotted).unwrap(), oid, "{dotted}");
        }
    }

    /// Every message here was made by OpenSSL or the JDK; each must verify, with the leaf the
    /// signer's own certificate and the path leaf, intermediate, root.
    #[test]
    fn signatures_made_by_other_implementations_verify() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        let extra = [f.cert("rsa"), f.cert("inter")];
        // (message, detached content, SHA-1 let through, signer)
        let cases: &[(&str, Option<&str>, bool, &str)] = &[
            ("rsa_sha256", None, false, "rsa"),
            ("rsa_sha384", None, false, "rsa"),
            ("rsa_sha512", None, false, "rsa"),
            ("rsa_sha1", None, true, "rsa"),
            ("rsa_sha256_detached", Some("hello"), false, "rsa"),
            ("rsa_noattr", None, false, "rsa"),
            ("rsa_noattr_detached", Some("hello"), false, "rsa"),
            ("rsa_keyid", None, false, "rsa"),
            ("rsa_nocerts", None, false, "rsa"),
            ("rsa_nosmimecap", None, false, "rsa"),
            ("rsa_econtent_type", None, false, "rsa"),
            ("rsa_stream", None, false, "rsa"),
            ("rsa_pss_sha256", None, false, "rsa"),
            ("rsa_pss_sha384", None, false, "rsa"),
            ("p256_sha256", None, false, "p256"),
            ("p256_sha1", None, true, "p256"),
            ("p256_noattr", None, false, "p256"),
            ("p384_sha384", None, false, "p384"),
            ("pkcs7_attached", None, false, "rsa"),
            ("pkcs7_detached", Some("hello"), false, "rsa"),
            ("jar_rsa", Some("jar_rsa"), false, "rsa"),
            ("jar_p256", Some("jar_p256"), false, "p256"),
            ("jar_ed", Some("jar_ed"), false, "ed"),
        ];
        for (name, detached, sha1, signer) in cases {
            let sd = f.parse(name);
            let mut o = Options::new(&trust, Purpose::CodeSigning, NOW);
            o.allow_sha1 = *sha1;
            if *name == "rsa_nocerts" {
                assert!(sd.certificates().is_empty());
                o.extra_certs = &extra;
            }
            let detached = detached.map(|d| f.contents[d].as_slice());
            let verified = sd.verify(detached, &o).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(verified.len(), 1, "{name}");
            let v = &verified[0];
            assert_eq!(v.chain.leaf.der, f.certs[*signer], "{name}");
            assert_eq!(v.chain.path.len(), 3, "{name}");
            assert_eq!(v.chain.anchor(), f.certs["root"], "{name}");
            assert_eq!(v.weaknesses, if *sha1 { vec![Weakness::Sha1] } else { vec![] }, "{name}");
            assert!(v.timestamp.is_none() && v.chain_time == NOW, "{name}");
            // the arithmetic alone, with no chain at all, says the same
            let check = sd.verify_signature(0, detached, &extra).unwrap();
            assert_eq!(check.certificate_der, f.certs[*signer], "{name}");
        }
    }

    #[test]
    fn what_a_message_says_about_itself() {
        let f = Fx::load();
        let sd = f.parse("rsa_sha256");
        assert_eq!(sd.content(), Some(HELLO));
        assert_eq!(sd.content_type(), "1.2.840.113549.1.7.1");
        assert_eq!((sd.certificates().len(), sd.skipped_certificates(), sd.signers().len()), (2, 0, 1));
        let s = &sd.signers()[0];
        assert!(matches!(s.id(), SignerId::IssuerAndSerial { .. }));
        assert_eq!(s.digest_algorithm(), "2.16.840.1.101.3.4.2.1");
        assert_eq!(s.signature_algorithm(), "1.2.840.113549.1.1.1");
        assert!(s.claimed_signing_time().unwrap() > 1_767_225_600);
        assert_eq!(s.signature().len(), 256);
        assert!(s.signed_attribute(OID_CONTENT_TYPE).is_some() && s.signed_attribute(OID_TIMESTAMP_TOKEN).is_none());
        assert_eq!(s.unsigned_attributes(OID_TIMESTAMP_TOKEN).count(), 0);

        // the same message streamed: indefinite lengths and a constructed OCTET STRING
        let streamed = f.parse("rsa_stream");
        assert!(f.blobs["rsa_stream"][1] == 0x80, "the fixture is meant to be BER");
        assert_eq!(streamed.content(), Some(HELLO));
        assert_eq!(streamed.certificates().len(), 2);

        let keyid = f.parse("rsa_keyid");
        let SignerId::SubjectKeyId(id) = keyid.signers()[0].id() else { panic!("{:?}", keyid.signers()[0].id()) };
        assert_eq!(id.len(), 20);
        assert_eq!(f.parse("rsa_econtent_type").content_type(), "1.2.3.4.5");
        assert_eq!(f.parse("two_signers").signers().len(), 2);
        assert!(f.parse("rsa_sha256_detached").content().is_none());
        let ts = f.parse("rsa_ts");
        assert_eq!(ts.signers()[0].unsigned_attributes(OID_TIMESTAMP_TOKEN).count(), 1);
        assert_eq!(f.parse("rsa_ts_ms").signers()[0].unsigned_attributes(OID_MS_TIMESTAMP_TOKEN).count(), 1);
        assert_eq!(f.parse("jar_ed").signers()[0].signature().len(), 64);
        assert_eq!(f.parse("jar_ed").signers()[0].signature_algorithm(), "1.3.101.112");
    }

    #[test]
    fn framing() {
        let f = Fx::load();
        let blob = &f.blobs["rsa_sha256"];
        // a PE certificate table pads its entries with zeros; other trailing data is not tolerated
        let mut padded = blob.clone();
        padded.extend([0u8; 6]);
        assert!(SignedData::parse(&padded).is_ok());
        padded.push(1);
        assert!(matches!(SignedData::parse(&padded), Err(Error::Malformed(_))));
        // a bare SignedData, without the ContentInfo around it
        let root = ber::parse_exact(blob).unwrap();
        let inner = explicit(&root.children().unwrap()[1]).unwrap().der().unwrap();
        assert_eq!(SignedData::parse(&inner).unwrap().content(), Some(HELLO));
        // a ContentInfo of another type
        let other = replace_last(blob, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02], &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
        assert!(matches!(SignedData::parse(&other), Err(Error::NotSignedData)));
        // nothing, and every shorter piece of a message, is an error and not a panic
        assert!(SignedData::parse(&[]).is_err());
        for name in ["rsa_stream", "jar_ed", "two_signers"] {
            let b = &f.blobs[name];
            for n in (0..b.len()).step_by(7) {
                assert!(SignedData::parse(&b[..n]).is_err(), "{name} cut to {n}");
            }
        }
    }

    #[test]
    fn two_signers_are_judged_separately() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        let o = Options::new(&trust, Purpose::CodeSigning, NOW);
        let sd = f.parse("two_signers");
        let verified = sd.verify(None, &o).unwrap();
        // (a SET OF is written in the order of its encodings, so which signer comes first is not up to the signer)
        let mut leaves = vec![verified[0].chain.leaf.der.clone(), verified[1].chain.leaf.der.clone()];
        leaves.sort();
        let mut expected = vec![f.certs["rsa"].clone(), f.certs["p256"].clone()];
        expected.sort();
        assert_eq!(leaves, expected);
        // damage the second signature: the message fails, the first signer still verifies
        let damaged = SignedData::parse(&flip_in(&f.blobs["two_signers"], sd.signers()[1].signature())).unwrap();
        assert!(matches!(damaged.verify(None, &o), Err(Error::BadSignature)));
        assert!(damaged.verify_signer(0, None, &o).is_ok());
        assert!(matches!(damaged.verify_signer(1, None, &o), Err(Error::BadSignature)));
        assert!(matches!(damaged.verify_signer(2, None, &o), Err(Error::NoSigner)));
    }

    #[test]
    fn sha1_is_a_policy_decision() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        for name in ["rsa_sha1", "p256_sha1"] {
            let sd = f.parse(name);
            // the arithmetic is right, and the result says what is wrong with it
            assert_eq!(sd.verify_signature(0, None, &[]).unwrap().weaknesses, [Weakness::Sha1], "{name}");
            // the default is to refuse
            let o = Options::new(&trust, Purpose::CodeSigning, NOW);
            assert!(matches!(sd.verify(None, &o), Err(Error::WeakDigest)), "{name}");
        }
        assert!(f.parse("rsa_sha256").verify_signature(0, None, &[]).unwrap().weaknesses.is_empty());
        // and a damaged SHA-1 signature is a bad signature, not a weak one
        let sd = SignedData::parse(&flip_in(&f.blobs["rsa_sha1"], f.parse("rsa_sha1").signers()[0].signature())).unwrap();
        assert!(matches!(sd.verify_signature(0, None, &[]), Err(Error::BadSignature)));
    }

    #[test]
    fn content_and_detachment() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        let o = Options::new(&trust, Purpose::CodeSigning, NOW);
        let other = b"some other message".as_slice();
        // a detached signature needs its content, and the right one
        let detached = f.parse("rsa_sha256_detached");
        assert!(matches!(detached.verify(None, &o), Err(Error::ContentMissing)));
        assert!(matches!(detached.verify(Some(other), &o), Err(Error::DigestMismatch)));
        assert!(detached.verify(Some(HELLO), &o).is_ok());
        assert!(matches!(f.parse("rsa_noattr_detached").verify(Some(other), &o), Err(Error::BadSignature)));
        // a signature that carries its content is not given another one
        assert!(matches!(f.parse("rsa_sha256").verify(Some(HELLO), &o), Err(Error::ContentGiven)));
        // a message with no signer certificate in it, and none supplied
        assert!(matches!(f.parse("rsa_nocerts").verify(None, &o), Err(Error::SignerCertificateNotFound)));
    }

    #[test]
    fn damage_is_refused() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        let o = Options::new(&trust, Purpose::CodeSigning, NOW);
        let check = |blob: Vec<u8>, detached: Option<&[u8]>| SignedData::parse(&blob).and_then(|sd| sd.verify(detached, &o));

        // the carried content: the digest in the signed attributes no longer matches, or, with no
        // attributes, the signature does not
        for (name, digest) in [("rsa_sha256", true), ("rsa_stream", true), ("p256_sha256", true), ("rsa_noattr", false), ("p256_noattr", false), ("rsa_pss_sha256", true)] {
            let r = check(flip_in(&f.blobs[name], HELLO), None);
            match (digest, r) {
                (true, Err(Error::DigestMismatch)) | (false, Err(Error::BadSignature)) => {}
                (_, r) => panic!("{name}: {r:?}"),
            }
        }
        // the signature value
        for name in ["rsa_sha256", "rsa_keyid", "rsa_pss_sha256", "rsa_pss_sha384", "p256_sha256", "p384_sha384", "rsa_noattr", "pkcs7_attached", "rsa_stream"] {
            let sig = f.parse(name).signers()[0].signature().to_vec();
            let r = check(flip_in(&f.blobs[name], &sig), None);
            assert!(matches!(r, Err(Error::BadSignature)), "{name}: {r:?}");
        }
        for name in ["jar_rsa", "jar_p256", "jar_ed"] {
            let sig = f.parse(name).signers()[0].signature().to_vec();
            let r = check(flip_in(&f.blobs[name], &sig), Some(&f.contents[name]));
            assert!(matches!(r, Err(Error::BadSignature)), "{name}: {r:?}");
        }
        // the last signed attribute of this message is the message digest, 32 bytes that end 4 + 15 bytes
        // (the signature's header and the signature algorithm) before the signature
        let blob = &f.blobs["rsa_nosmimecap"];
        let sig = f.parse("rsa_nosmimecap").signers()[0].signature().to_vec();
        let sig_at = blob.windows(sig.len()).position(|w| w == sig).unwrap();
        let mut b = blob.clone();
        b[sig_at - 4 - 15 - 8] ^= 0x01;
        let r = check(b, None);
        assert!(matches!(r, Err(Error::DigestMismatch)), "{r:?}");
        // the signer's certificate (not covered by the signature): its key changes, so nothing verifies
        let leaf = f.certs["rsa"].clone();
        let r = check(flip_in(&f.blobs["rsa_sha256"], &leaf[leaf.len() / 3..leaf.len() / 3 * 2]), None);
        assert!(r.is_err());
        // the signed attributes taken off: the attribute signature is not a signature of the content
        assert!(matches!(check(f.blobs["rsa_attrs_stripped"].clone(), None), Err(Error::BadSignature)));
    }

    #[test]
    fn attributes_and_algorithms_must_agree() {
        let f = Fx::load();
        let trust = f.store(&["root"]);
        let o = Options::new(&trust, Purpose::CodeSigning, NOW);
        // contentType in the signed attributes says 1.2.3.4.5, the message says 1.2.3.4.6
        let r = f.parse("rsa_econtent_type_swapped").verify(None, &o);
        assert!(matches!(r, Err(Error::Attributes(_))), "{r:?}");
        // the signer info says SHA-384, the signed algorithm protection says SHA-256
        let r = f.parse("jar_rsa_alg_swapped").verify(Some(&f.contents["jar_rsa"]), &o);
        assert!(matches!(r, Err(Error::Attributes(m)) if m.contains("digest algorithm")), "{r:?}");
        // a digest algorithm this code does not have (SHA-224)
        let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let sha224 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
        let sd = SignedData::parse(&replace_all(&f.blobs["rsa_sha256"], &sha256, &sha224)).unwrap();
        assert!(matches!(sd.verify(None, &o), Err(Error::UnsupportedDigest(d)) if d == "2.16.840.1.101.3.4.2.4"));
        // a signature algorithm it does not have: the last rsaEncryption is the signer's
        let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let unknown = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0f];
        let sd = SignedData::parse(&replace_last(&f.blobs["rsa_sha256"], &rsa, &unknown)).unwrap();
        assert!(matches!(sd.verify(None, &o), Err(Error::UnsupportedSignature(m)) if m.contains("1.2.840.113549.1.1.15")));
        // sha256WithRSA over a SHA-384 digest algorithm is two hashes, and each is checked on its own
        let sha256_rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let sd = SignedData::parse(&replace_last(&f.blobs["rsa_sha256"], &rsa, &sha256_rsa)).unwrap();
        // the signature was made with rsaEncryption + SHA-256, which is what sha256WithRSA means
        assert!(sd.verify(None, &o).is_ok());
        let sha384_rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
        let sd = SignedData::parse(&replace_last(&f.blobs["rsa_sha256"], &rsa, &sha384_rsa)).unwrap();
        assert!(matches!(sd.verify(None, &o), Err(Error::BadSignature)));
    }

    fn opts(trust: &TrustStore, time: i64) -> Options<'_> {
        Options::new(trust, Purpose::CodeSigning, time)
    }

    #[test]
    fn trust_purpose_and_time() {
        let f = Fx::load();
        let signed = |name: &str| f.parse(name);
        let root = f.store(&["root"]);
        // a signer under a root nobody trusts, and the same one once the root is trusted
        assert!(matches!(signed("rogue_signed").verify(None, &opts(&root, NOW)), Err(Error::Chain(_))));
        assert!(signed("rogue_signed").verify(None, &opts(&f.store(&["rogue_root"]), NOW)).is_ok());
        assert!(matches!(signed("rsa_sha256").verify(None, &opts(&TrustStore::empty(), NOW)), Err(Error::Chain(_))));
        // a leaf that may sign for TLS but not for code
        assert!(matches!(signed("tls_signed").verify(None, &opts(&root, NOW)), Err(Error::Chain(_))));
        let any = Options::new(&root, Purpose::Any, NOW);
        assert!(signed("tls_signed").verify(None, &any).is_ok());
        // the certificate's validity period
        let sd = signed("rsa_sha256");
        assert!(matches!(sd.verify(None, &opts(&root, BEFORE_ALL)), Err(Error::Chain(_))));
        assert!(matches!(sd.verify(None, &opts(&root, AFTER_LEAVES)), Err(Error::Chain(_))));
        assert!(sd.verify(None, &opts(&root, NOW)).is_ok());
        // a leaf that expired in June 2026 does not verify in October
        assert!(matches!(signed("short_signed").verify(None, &opts(&root, NOW)), Err(Error::Chain(_))));
        assert!(signed("short_signed").verify(None, &opts(&root, APRIL_1_2026_9H)).is_ok());
    }

    #[test]
    fn time_stamps_say_when_the_signature_existed() {
        let f = Fx::load();
        let root = f.store(&["root"]);
        let o = Options::new(&root, Purpose::CodeSigning, NOW);

        // a real token from `openssl ts`, under either attribute name
        for name in ["rsa_ts", "rsa_ts_ms"] {
            let v = &f.parse(name).verify(None, &o).unwrap()[0];
            let t = v.timestamp.as_ref().expect(name);
            assert_eq!((v.chain_time, t.policy.as_str(), t.serial.len(), t.serial[0]), (t.time, "1.2.3.4.1", 2, 0x0a), "{name}");
            assert!(t.time > 1_767_225_600 && t.time <= NOW + 10 * 365 * 86_400, "{name}");
            assert_eq!(t.chain.path.len(), 3);
            assert_eq!(t.chain.leaf.der, f.certs["tsa"]);
        }
        // the short-lived key signed in April and was stamped then: it verifies in October
        let v = &f.parse("short_ts").verify(None, &o).unwrap()[0];
        assert_eq!((v.chain_time, v.timestamp.as_ref().unwrap().time), (APRIL_1_2026_9H, APRIL_1_2026_9H));
        // ... unless the stamp is dated after the certificate expired, or before it began
        for name in ["short_ts_late", "short_ts_early"] {
            let r = f.parse(name).verify(None, &o);
            assert!(matches!(r, Err(Error::Chain(_))), "{name}: {r:?}");
        }
        // and ignoring time stamps puts it back to the caller's time
        let mut ignore = Options::new(&root, Purpose::CodeSigning, NOW);
        ignore.timestamps = Timestamps::Ignore;
        assert!(matches!(f.parse("short_ts").verify(None, &ignore), Err(Error::Chain(_))));
        assert!(f.parse("rsa_ts").verify(None, &ignore).unwrap()[0].timestamp.is_none());

        // requiring one
        let mut require = Options::new(&root, Purpose::CodeSigning, NOW);
        require.timestamps = Timestamps::Require;
        assert!(matches!(f.parse("rsa_sha256").verify(None, &require), Err(Error::TimestampMissing)));
        assert!(f.parse("rsa_ts").verify(None, &require).is_ok());
        assert!(f.parse("rsa_sha256").verify(None, &o).is_ok());

        // a token for some other message, and one from an authority that is not trusted
        for name in ["rsa_ts_wrong_imprint", "rsa_ts_rogue_tsa", "rsa_ts_wrong_eku"] {
            let r = f.parse(name).verify(None, &o);
            assert!(matches!(r, Err(Error::Timestamp(_))), "{name}: {r:?}");
        }
        // time-stamp authorities can have roots of their own
        let rogue = f.store(&["rogue_root"]);
        let mut split = Options::new(&root, Purpose::CodeSigning, NOW);
        split.timestamp_trust = Some(&rogue);
        assert!(f.parse("rsa_ts_rogue_tsa").verify(None, &split).is_ok());
        assert!(matches!(f.parse("rsa_ts").verify(None, &split), Err(Error::Timestamp(_))));
    }

    #[test]
    fn time_stamp_tokens() {
        let f = Fx::load();
        let root = f.store(&["root"]);
        let message = &f.contents["stamped"];
        for name in ["token_sha256", "token_sha384", "token_sha512"] {
            let t = verify_timestamp(&f.blobs[name], message, &root, false).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(t.weaknesses.is_empty() && t.chain.path.len() == 3, "{name}");
        }
        // SHA-1 imprints are weak
        assert!(matches!(verify_timestamp(&f.blobs["token_sha1"], message, &root, false), Err(Error::WeakDigest)));
        assert_eq!(verify_timestamp(&f.blobs["token_sha1"], message, &root, true).unwrap().weaknesses, [Weakness::Sha1]);
        // a token made for a chosen time
        let t = verify_timestamp(&f.blobs["token_custom"], message, &root, false).unwrap();
        assert_eq!(t.time, APRIL_1_2026_12H34M56S);
        // some other message, a damaged token, an authority nobody trusts, no trust at all
        assert!(verify_timestamp(&f.blobs["token_sha256"], b"another message", &root, false).is_err());
        let sd = SignedData::parse(&f.blobs["token_sha256"]).unwrap();
        let damaged = flip_in(&f.blobs["token_sha256"], sd.signers()[0].signature());
        assert!(matches!(verify_timestamp(&damaged, message, &root, false), Err(Error::BadSignature)));
        assert!(matches!(verify_timestamp(&f.blobs["token_rogue_tsa"], message, &root, false), Err(Error::Chain(_))));
        assert!(verify_timestamp(&f.blobs["token_rogue_tsa"], message, &f.store(&["rogue_root"]), false).is_ok());
        assert!(matches!(verify_timestamp(&f.blobs["token_sha256"], message, &TrustStore::empty(), false), Err(Error::Chain(_))));
        // a token signed by a certificate for code signing is not a time stamp
        assert!(matches!(verify_timestamp(&f.blobs["token_wrong_eku"], message, &root, false), Err(Error::Chain(_))));
        // a signature is not a time-stamp token
        assert!(matches!(verify_timestamp(&f.blobs["rsa_sha256"], message, &root, false), Err(Error::Malformed(_))));
    }

    #[test]
    fn generalized_time_may_have_a_fraction() {
        let tlv = |s: &'static [u8]| Tlv { tag: asn1::TAG_GENERALIZED_TIME, content: s, raw: s };
        let whole = gen_time(&tlv(b"20260401123456Z")).unwrap();
        assert_eq!(whole, APRIL_1_2026_12H34M56S);
        assert_eq!(gen_time(&tlv(b"20260401123456.5Z")).unwrap(), whole);
        assert_eq!(gen_time(&tlv(b"20260401123456.123456Z")).unwrap(), whole);
        for bad in [&b"20260401123456.Z"[..], b"20260401123456.5", b"20260401123456.5x", b"2026040112345.65Z", b"20260401123456,5Z", b"20260401123456+0100"] {
            assert!(gen_time(&tlv(bad)).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
