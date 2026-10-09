//! X.509 certificate parsing and chain validation (RFC 5280 subset).
//!
//! The chain checks are not tied to TLS: [`TrustStore::verify_chain`] takes a [`VerifyOptions`] in
//! which the caller chooses the purpose (the extended key usage the leaf and every CA must allow:
//! server or client authentication, code signing, time stamping, e-mail, any other OID, or none),
//! the time to validate at (a signature's time, not necessarily now) and, through the store, the
//! trust anchors; a host name is optional. The result carries the leaf and the path. Everything a
//! leaf says about its holder is readable: [`Certificate::subject_alt_names`] (DNS, IP, e-mail,
//! URI, directory and other names) and [`Certificate::extension`] (any extension by OID, with its
//! critical flag). [`TrustStore::verify_server_chain`] is the TLS server case of the same code.
//!
//! Supported: RSA (PKCS#1 v1.5, SHA-256/384/512), ECDSA (P-256/P-384) and Ed25519 (RFC 8410) signatures; validity
//! periods; basicConstraints (including pathLen); keyUsage; extendedKeyUsage; name constraints on
//! DNS names, e-mail addresses, URIs and IP addresses; subjectAltName hostname and IP matching (no
//! CN fallback, like browsers). Revocation is checked by [`crate::revocation`]. Not supported:
//! policy processing, RSA-PSS certificate signatures, SHA-1 signatures (rejected on
//! purpose), and name constraints on other kinds of name: a certificate that has a name of such a kind in its
//! subjectAltName, or one of any kind that could not be read, under a constraint of that kind is refused, and a
//! CA with a constraint on directory names is refused whatever the names (this code does not compare names). The
//! constraints of a CA hold for the subjectAltName of every certificate below it, intermediates included, and the
//! e-mail addresses in their subject names are held to e-mail constraints.

use crate::asn1::{self, Der, Tlv};
use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::ed25519;
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::sha2::HashAlg;
use crate::verify_error::{cert, Error, Result};
use crate::pem;
use core::net::IpAddr;
use std::collections::HashMap;
use std::sync::OnceLock;

// ----- OIDs (DER content octets) -----
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_CURVE_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_CURVE_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_CURVE_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
/// id-Ed25519 (RFC 8410): both the signature algorithm and the public key algorithm.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const OID_CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
const OID_CERT_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
const OID_POLICY_MAPPINGS: &[u8] = &[0x55, 0x1d, 0x21];
const OID_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x36];
const OID_AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const OID_SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
const OID_EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_EKU_CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const OID_EKU_EMAIL_PROTECTION: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
const OID_EKU_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
pub(crate) const OID_EKU_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
/// id-pe-tlsfeature (RFC 7633), the "must staple" extension.
const OID_TLS_FEATURE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
/// TLS extension code point of status_request, the value that marks must-staple.
const TLS_FEATURE_STATUS_REQUEST: u8 = 5;

/// keyUsage bit positions (bit 0 = digitalSignature).
const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
/// nonRepudiation, also called contentCommitment.
const KU_NON_REPUDIATION: u16 = 1 << 1;
const KU_KEY_CERT_SIGN: u16 = 1 << 5;
pub(crate) const KU_CRL_SIGN: u16 = 1 << 6;

const MAX_CHAIN_DEPTH: usize = 8;

/// How many candidate issuers (each one a signature check) the search for a path tries before it gives up.
/// A real chain needs a handful; the limit is what stops a sender who supplies many certificates that all
/// verify against each other from making the search try every path (8 levels of 20 is 20^8 of them).
const MAX_PATH_ATTEMPTS: usize = 256;

/// A certificate's public key. New key types may be added, so match with a wildcard arm.
#[non_exhaustive]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ec { curve: Curve, point: Vec<u8> },
    /// An Ed25519 key (RFC 8410): the 32 bytes of the encoded point.
    Ed25519([u8; 32]),
    Unsupported,
}

/// A signature algorithm taken from a certificate, CRL or OCSP response. New algorithms may be added, so
/// match with a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigAlg {
    RsaPkcs1(HashAlg),
    /// RSASSA-PSS (RFC 4055) with this hash, MGF1 with the same hash and a salt as long as the hash: the only parameters
    /// the Web PKI allows (Mozilla Root Store Policy section 5.1.1), and the only ones read.
    RsaPss(HashAlg),
    Ecdsa(HashAlg),
    /// Ed25519 (RFC 8032, RFC 8410), which has no separate hash: the parameters of its
    /// AlgorithmIdentifier must be absent, not NULL.
    Ed25519,
}

impl SigAlg {
    /// Reads an AlgorithmIdentifier (the content of its SEQUENCE, which must be exactly an OID and
    /// at most one parameter). For the RSA and ECDSA algorithms the parameter must be absent or
    /// NULL (RFC 4055, RFC 5758), and for Ed25519 it must be absent (RFC 8410 section 3): anything
    /// else is not an algorithm this code knows, so it is `None` and nothing verifies with it,
    /// rather than a detail that is quietly ignored.
    pub(crate) fn from_algorithm_identifier(content: &[u8]) -> Result<Option<SigAlg>> {
        let (oid, params) = parse_algorithm_identifier(content)?;
        if oid == OID_RSASSA_PSS {
            return Ok(pss_params(params).map(SigAlg::RsaPss));
        }
        let Some(alg) = SigAlg::from_oid(oid) else { return Ok(None) };
        Ok(match params {
            None => Some(alg),
            Some(p) if p.tag == asn1::TAG_NULL && p.content.is_empty() && alg != SigAlg::Ed25519 => Some(alg),
            Some(_) => None,
        })
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<SigAlg> {
        Some(match oid {
            OID_SHA256_RSA => SigAlg::RsaPkcs1(HashAlg::Sha256),
            OID_SHA384_RSA => SigAlg::RsaPkcs1(HashAlg::Sha384),
            OID_SHA512_RSA => SigAlg::RsaPkcs1(HashAlg::Sha512),
            OID_ECDSA_SHA256 => SigAlg::Ecdsa(HashAlg::Sha256),
            OID_ECDSA_SHA384 => SigAlg::Ecdsa(HashAlg::Sha384),
            OID_ECDSA_SHA512 => SigAlg::Ecdsa(HashAlg::Sha512),
            OID_ED25519 => SigAlg::Ed25519,
            _ => return None,
        })
    }
}

/// The hash of RSASSA-PSS-params (RFC 4055 section 3.1) in the one shape the Web PKI uses (Mozilla Root Store Policy section
/// 5.1.1, which gives the three encodings byte for byte): hashAlgorithm SHA-256, SHA-384 or SHA-512 (with NULL or absent
/// parameters, RFC 4055 section 2.1), maskGenAlgorithm MGF1 with the same hash, saltLength the length of the hash, and
/// trailerField left at its default (and so absent, in DER). Anything else is `None`: the SHA-1 defaults that an absent
/// field means, a mask hash unlike the message hash, another salt length.
fn pss_params(params: Option<Tlv>) -> Option<HashAlg> {
    let p = params.filter(|p| p.tag == asn1::TAG_SEQUENCE)?;
    let mut d = Der::new(p.content);
    // [0] EXPLICIT hashAlgorithm
    let hash = hash_of(explicit_sequence(d.optional(0xa0).ok()??.content)?)?;
    // [1] EXPLICIT maskGenAlgorithm: MGF1 with an AlgorithmIdentifier of the same hash as its parameter
    let (mgf, mgf_params) = parse_algorithm_identifier(explicit_sequence(d.optional(0xa1).ok()??.content)?).ok()?;
    let mgf_hash = mgf_params.filter(|p| p.tag == asn1::TAG_SEQUENCE).and_then(|p| hash_of(p.content))?;
    if mgf != OID_MGF1 || mgf_hash != hash {
        return None;
    }
    // [2] EXPLICIT saltLength: the hash's length (32, 48 or 64, one content byte)
    let mut salt = Der::new(d.optional(0xa2).ok()??.content);
    if salt.expect(asn1::TAG_INTEGER).ok()?.content != [hash.output_len() as u8] || salt.finish().is_err() {
        return None;
    }
    // [3] trailerField is DEFAULT 1, so in DER it is absent
    d.finish().ok()?;
    Some(hash)
}

/// The content of the one SEQUENCE that an EXPLICIT tag holds.
fn explicit_sequence(content: &[u8]) -> Option<&[u8]> {
    let mut d = Der::new(content);
    let seq = d.expect(asn1::TAG_SEQUENCE).ok()?;
    d.finish().ok()?;
    Some(seq.content)
}

/// A SHA-2 hash named by an AlgorithmIdentifier's content, with NULL or absent parameters.
fn hash_of(algorithm_identifier: &[u8]) -> Option<HashAlg> {
    let (oid, params) = parse_algorithm_identifier(algorithm_identifier).ok()?;
    if params.is_some_and(|p| p.tag != asn1::TAG_NULL || !p.content.is_empty()) {
        return None;
    }
    Some(match oid {
        OID_SHA256 => HashAlg::Sha256,
        OID_SHA384 => HashAlg::Sha384,
        OID_SHA512 => HashAlg::Sha512,
        _ => return None,
    })
}

/// One entry of a subjectAltName extension (RFC 5280 section 4.2.1.6). Entries of the kinds not
/// listed here (x400Address, ediPartyName) are not kept, and neither is an entry whose encoding is
/// malformed (apart from a dNSName that is not ASCII, which makes the whole certificate invalid).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneralName {
    /// dNSName, lower-cased.
    Dns(String),
    /// iPAddress: 4 octets (IPv4) or 16 (IPv6).
    Ip(Vec<u8>),
    /// rfc822Name: an e-mail address, as written in the certificate.
    Email(String),
    /// uniformResourceIdentifier, as written in the certificate.
    Uri(String),
    /// directoryName: the DER of the Name.
    Directory(Vec<u8>),
    /// otherName: the OID of its type, as content octets (see [`crate::asn1::oid_to_string`]), and the
    /// DER of its value (the contents of the `[0]` wrapper: a complete TLV such as a UTF8String).
    Other { type_id: Vec<u8>, value: Vec<u8> },
    /// registeredID: an OID, as content octets.
    RegisteredId(Vec<u8>),
}

impl GeneralName {
    /// The context tag this kind of name has in a GeneralName (and so in a name constraint).
    fn tag(&self) -> u8 {
        match self {
            GeneralName::Dns(_) => 0x82,
            GeneralName::Ip(_) => 0x87,
            GeneralName::Email(_) => 0x81,
            GeneralName::Uri(_) => 0x86,
            GeneralName::Directory(_) => 0xa4,
            GeneralName::Other { .. } => 0xa0,
            GeneralName::RegisteredId(_) => 0x88,
        }
    }
}

/// One extension of a certificate, exactly as encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension's OID, as content octets.
    pub oid: Vec<u8>,
    pub critical: bool,
    /// The contents of the extnValue OCTET STRING: normally the DER of the extension's own
    /// structure. (Sigstore's first-generation Fulcio extensions, 1.3.6.1.4.1.57264.1.1 to .6, hold
    /// raw text here instead; the later ones hold a DER UTF8String, see [`Extension::der_string`].)
    pub value: Vec<u8>,
}

impl Extension {
    /// The OID in dotted form.
    pub fn oid_string(&self) -> String {
        asn1::oid_to_string(&self.oid)
    }

    /// The value as text, if it is exactly one DER UTF8String, IA5String or PrintableString.
    pub fn der_string(&self) -> Option<String> {
        let mut d = Der::new(&self.value);
        let t = d.next().ok()?;
        d.finish().ok()?;
        match t.tag {
            asn1::TAG_UTF8_STRING | asn1::TAG_IA5_STRING | asn1::TAG_PRINTABLE_STRING => {
                core::str::from_utf8(t.content).ok().map(str::to_string)
            }
            _ => None,
        }
    }
}

/// A name constraint subtree (RFC 5280 section 4.2.1.10).
enum Constraint {
    /// A domain: `example.com` also covers its subdomains, `.example.com` only the subdomains.
    Dns(String),
    /// A mailbox, a host (every mailbox at it) or, with a leading dot, the mailboxes in its subdomains.
    Email(String),
    /// A host (exactly) or, with a leading dot, its subdomains.
    Uri(String),
    /// An address and a mask of the same length: 8 octets for IPv4, 32 for IPv6.
    Ip(Vec<u8>),
    /// A kind of name this code does not evaluate, by GeneralName tag.
    Unsupported(u8),
}

impl Constraint {
    /// The GeneralName tag of the kind of name this constrains.
    fn kind(&self) -> u8 {
        match self {
            Constraint::Dns(_) => 0x82,
            Constraint::Email(_) => 0x81,
            Constraint::Uri(_) => 0x86,
            Constraint::Ip(_) => 0x87,
            Constraint::Unsupported(tag) => *tag,
        }
    }
}

#[derive(Default)]
struct NameConstraints {
    permitted: Vec<Constraint>,
    excluded: Vec<Constraint>,
}

pub struct Certificate {
    pub der: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: Option<SigAlg>,
    signature: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    /// The issuer and subject names in the form [`name_key`] gives, which chain building compares.
    issuer_key: Vec<u8>,
    subject_key: Vec<u8>,
    /// Serial number without leading zero bytes (revocation lists and OCSP name certificates by it).
    pub(crate) serial: Vec<u8>,
    /// The serial number's INTEGER content as it is in the certificate (an OCSP request repeats it as it is).
    pub(crate) serial_content: Vec<u8>,
    /// The subjectPublicKey bits, which OCSP hashes to identify an issuer.
    pub(crate) spki_key: Vec<u8>,
    /// The whole `SubjectPublicKeyInfo` (DER), which Certificate Transparency hashes to identify an issuer.
    spki: Vec<u8>,
    /// `http(s)` and other URIs from the CRL distribution points extension.
    pub(crate) crl_uris: Vec<String>,
    /// The OCSP responders the Authority Information Access extension names (`id-ad-ocsp` URIs).
    pub(crate) ocsp_uris: Vec<String>,
    /// The certificate carries the TLS Feature extension asking for a stapled OCSP response.
    pub(crate) must_staple: bool,
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: PublicKey,
    pub dns_names: Vec<String>,
    pub ip_addrs: Vec<Vec<u8>>,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    has_basic_constraints: bool,
    key_usage: Option<u16>,
    ext_key_usage: Option<Vec<Vec<u8>>>,
    name_constraints: Option<NameConstraints>,
    san: Vec<GeneralName>,
    extensions: Vec<Extension>,
    /// OIDs of critical extensions this code does not know. [`Certificate::from_der`] refuses a
    /// certificate that has any; chain verification refuses one unless the caller said it
    /// interprets that extension itself (see [`VerifyOptions::with_critical_extension`]).
    unrecognized_critical: Vec<Vec<u8>>,
    /// The version field: 0 for version 1 (which has no extensions), 1 for version 2, 2 for version 3.
    version: u8,
    /// The tags of the subjectAltName entries that were not kept (a kind this code does not read, or an
    /// entry that is malformed), so that a name constraint of that kind can still refuse the certificate.
    dropped_san: Vec<u8>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("dns_names", &self.dns_names)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("is_ca", &self.is_ca)
            .finish()
    }
}

/// A DER TLV.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// The text of a directory string of one of the types RFC 5280 section 7.1 compares as text, as UTF-8: UTF8String
/// (which must be valid), PrintableString, IA5String and VisibleString (ASCII, read a byte per character), TeletexString
/// (read as Latin-1, as OpenSSL does), BMPString (UTF-16 without surrogates) and UniversalString (UTF-32). `None` for
/// another type, which is compared as it is, and for one that does not decode.
fn directory_string(tag: u8, content: &[u8]) -> Option<Result<String>> {
    let bad = || Err(Error::Asn1("a directory string that does not decode"));
    Some(match tag {
        0x0c => std::str::from_utf8(content).map(str::to_string).or_else(|_| bad()),
        0x13 | 0x16 | 0x1a | 0x14 => Ok(content.iter().map(|&b| b as char).collect()),
        0x1e if content.len() % 2 == 0 => content
            .chunks(2)
            .map(|c| char::from_u32(u16::from_be_bytes([c[0], c[1]]) as u32).ok_or(()))
            .collect::<std::result::Result<String, ()>>()
            .or_else(|_| bad()),
        0x1c if content.len() % 4 == 0 => content
            .chunks(4)
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).ok_or(()))
            .collect::<std::result::Result<String, ()>>()
            .or_else(|_| bad()),
        0x1e | 0x1c => bad(),
        _ => return None,
    })
}

/// The canonical form of a Name (RFC 5280 section 7.1), as OpenSSL makes it to compare names (`x509_name_canon`): every
/// attribute value of a text type becomes a UTF8String with leading and trailing white space removed, inner runs of
/// white space made one space, and ASCII letters lower-cased (other characters are left as they are: no Unicode case
/// folding or normalization); a value of another type is kept as it is; the attributes of a multi-valued RDN are put
/// in DER order. The RDNs keep their order. An error for a name that does not parse or a string that does not decode.
pub(crate) fn canonical_name(der: &[u8]) -> Result<Vec<u8>> {
    let mut outer = Der::new(der);
    let mut rdns = outer.sequence()?;
    outer.finish()?;
    let mut out = Vec::new();
    while !rdns.is_empty() {
        let set = rdns.expect(asn1::TAG_SET)?;
        let mut atvs = Der::new(set.content);
        let mut entries = Vec::new();
        while !atvs.is_empty() {
            let mut atv = atvs.sequence()?;
            let oid = atv.expect(asn1::TAG_OID)?;
            let value = atv.next()?;
            atv.finish()?;
            let value = match directory_string(value.tag, value.content) {
                None => value.raw.to_vec(),
                Some(text) => {
                    let text = text?;
                    let bytes = text.as_bytes();
                    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
                    let start = bytes.iter().position(|b| !space(b)).unwrap_or(bytes.len());
                    let end = bytes.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
                    let mut canon = Vec::with_capacity(end - start);
                    let mut i = start;
                    while i < end {
                        if space(&bytes[i]) {
                            canon.push(b' ');
                            while i < end && space(&bytes[i]) {
                                i += 1;
                            }
                        } else {
                            canon.push(bytes[i].to_ascii_lowercase());
                            i += 1;
                        }
                    }
                    tlv(asn1::TAG_UTF8_STRING, &canon)
                }
            };
            entries.push(tlv(asn1::TAG_SEQUENCE, &[oid.raw, &value].concat()));
        }
        if entries.is_empty() {
            return Err(Error::Asn1("an empty RDN"));
        }
        entries.sort();
        out.extend(tlv(asn1::TAG_SET, &entries.concat()));
    }
    Ok(out)
}

/// What chain building compares a name by: its canonical form, or (for a name that has none) its bytes, marked so that
/// they cannot equal a canonical form (which is empty or starts with a SET tag).
fn name_key(der: &[u8]) -> Vec<u8> {
    canonical_name(der).unwrap_or_else(|_| [&[0xff][..], der].concat())
}

/// A short, log-safe rendering of a Name (`CN=example.com, O=Example Inc`) for error messages.
/// Never fails: an unreadable name is reported as such. Control characters are replaced and each
/// value is cut at 64 characters, so a hostile certificate cannot spam or forge log lines.
pub(crate) fn describe_name(name_der: &[u8]) -> String {
    fn tag_for(oid: &[u8]) -> Option<&'static str> {
        match oid {
            [0x55, 0x04, 0x03] => Some("CN"),
            [0x55, 0x04, 0x0a] => Some("O"),
            [0x55, 0x04, 0x0b] => Some("OU"),
            [0x55, 0x04, 0x06] => Some("C"),
            _ => None,
        }
    }
    fn parse(name_der: &[u8]) -> Result<Vec<String>> {
        let mut outer = Der::new(name_der);
        let mut rdns = outer.sequence()?;
        let mut parts = Vec::new();
        while !rdns.is_empty() && parts.len() < 8 {
            let set = rdns.expect(asn1::TAG_SET)?;
            let mut atvs = Der::new(set.content);
            while !atvs.is_empty() {
                let mut atv = atvs.sequence()?;
                let oid = atv.expect(asn1::TAG_OID)?.content;
                let value = atv.next()?;
                let Some(label) = tag_for(oid) else { continue };
                let text = match value.tag {
                    asn1::TAG_UTF8_STRING | asn1::TAG_PRINTABLE_STRING | asn1::TAG_IA5_STRING | 0x14 => {
                        String::from_utf8_lossy(value.content).into_owned()
                    }
                    _ => "<unsupported string type>".to_string(),
                };
                let clean: String = text.chars().take(64).map(|c| if c.is_control() { '?' } else { c }).collect();
                parts.push(format!("{}={}", label, clean));
            }
        }
        Ok(parts)
    }
    match parse(name_der) {
        Ok(parts) if !parts.is_empty() => parts.join(", "),
        Ok(_) => "<name without common attributes>".to_string(),
        Err(_) => "<unreadable name>".to_string(),
    }
}

fn parse_algorithm_identifier<'a>(content: &'a [u8]) -> Result<(&'a [u8], Option<Tlv<'a>>)> {
    let mut d = Der::new(content);
    let oid = d.expect(asn1::TAG_OID)?.content;
    let params = if d.is_empty() { None } else { Some(d.next()?) };
    d.finish()?;
    Ok((oid, params))
}

/// Reads a DER `SubjectPublicKeyInfo` (RFC 5280 section 4.1.2.7), the form keys take in PEM "PUBLIC KEY" blocks,
/// in Sigstore's trust roots and in npm's registry key list. A well-formed key of a kind this crate does not use
/// (another curve, another algorithm) is `PublicKey::Unsupported`; bytes that are not a SubjectPublicKeyInfo are
/// an error.
pub fn parse_spki(der: &[u8]) -> Result<PublicKey> {
    let mut d = Der::new(der);
    let spki = d.expect(asn1::TAG_SEQUENCE)?;
    d.finish()?;
    parse_public_key(&spki)
}

fn parse_public_key(spki: &Tlv) -> Result<PublicKey> {
    let mut d = Der::new(spki.content);
    let alg = d.expect(asn1::TAG_SEQUENCE)?;
    let bits = d.expect(asn1::TAG_BIT_STRING)?;
    d.finish()?;
    let (oid, params) = parse_algorithm_identifier(alg.content)?;
    let key_bytes = asn1::bit_string_bytes(&bits)?;
    if oid == OID_RSA_ENCRYPTION {
        Ok(PublicKey::Rsa(RsaPublicKey::from_pkcs1_der(key_bytes)?))
    } else if oid == OID_EC_PUBLIC_KEY {
        let curve = match params {
            Some(p) if p.tag == asn1::TAG_OID && p.content == OID_CURVE_P256 => Curve::P256,
            Some(p) if p.tag == asn1::TAG_OID && p.content == OID_CURVE_P384 => Curve::P384,
            Some(p) if p.tag == asn1::TAG_OID && p.content == OID_CURVE_P521 => Curve::P521,
            _ => return Ok(PublicKey::Unsupported),
        };
        Ok(PublicKey::Ec { curve, point: key_bytes.to_vec() })
    } else if oid == OID_ED25519 {
        // RFC 8410 section 3: no parameters, and the key is exactly the 32 bytes of the point
        match (params, <[u8; 32]>::try_from(key_bytes)) {
            (None, Ok(key)) => Ok(PublicKey::Ed25519(key)),
            _ => Ok(PublicKey::Unsupported),
        }
    } else {
        Ok(PublicKey::Unsupported)
    }
}

/// A name constraint on a domain (a DNS name, the host of a URI, the domain of a mailbox) is a host name, with
/// one leading dot to say "its subdomains only"; the empty string is allowed and constrains everything. What
/// could never match anything is refused: an empty label (`a..b`, a trailing dot, a lone dot) or a byte that is
/// not a printable ASCII character. Such a constraint would silently do nothing. (Go refuses these as well.)
fn domain_constraint_is_valid(c: &str) -> bool {
    if c.is_empty() {
        return true;
    }
    let body = c.strip_prefix('.').unwrap_or(c);
    !body.is_empty() && body.split('.').all(|label| !label.is_empty() && label.bytes().all(|b| (0x21..=0x7e).contains(&b)))
}

/// An e-mail constraint is one mailbox (`local@domain`) or a domain as above.
fn mailbox_constraint_is_valid(c: &str) -> bool {
    match c.rsplit_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && domain_constraint_is_valid(domain),
        None => domain_constraint_is_valid(c),
    }
}

fn parse_name_constraints(value: &[u8]) -> Result<NameConstraints> {
    let mut outer = Der::new(value);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let mut nc = NameConstraints::default();
    for (tag, permitted) in [(0xa0u8, true), (0xa1u8, false)] {
        if let Some(t) = seq.optional(tag)? {
            let mut subtrees = Der::new(t.content);
            while !subtrees.is_empty() {
                let mut subtree = subtrees.sequence()?;
                let base = subtree.next()?;
                let text = || core::str::from_utf8(base.content).ok().filter(|s| s.is_ascii());
                let c = match base.tag {
                    0x82 => {
                        let s = text().ok_or(Error::Asn1("bad dNSName constraint"))?.to_ascii_lowercase();
                        if !domain_constraint_is_valid(&s) {
                            return Err(Error::Asn1("bad dNSName constraint"));
                        }
                        Constraint::Dns(s)
                    }
                    0x81 => match text() {
                        None => Constraint::Unsupported(0x81),
                        Some(s) if mailbox_constraint_is_valid(s) => Constraint::Email(s.to_string()),
                        Some(_) => return Err(Error::Asn1("bad rfc822Name constraint")),
                    },
                    0x86 => match text() {
                        None => Constraint::Unsupported(0x86),
                        Some(s) if domain_constraint_is_valid(&s.to_ascii_lowercase()) => Constraint::Uri(s.to_ascii_lowercase()),
                        Some(_) => return Err(Error::Asn1("bad URI constraint")),
                    },
                    0x87 if base.content.len() == 8 || base.content.len() == 32 => Constraint::Ip(base.content.to_vec()),
                    other => Constraint::Unsupported(other),
                };
                if permitted {
                    nc.permitted.push(c);
                } else {
                    nc.excluded.push(c);
                }
            }
        }
    }
    Ok(nc)
}

/// The URIs in a CRLDistributionPoints value (RFC 5280 section 4.2.1.13): each distribution point's
/// `fullName` entries of type uniformResourceIdentifier.
pub(crate) fn parse_crl_uris(value: &[u8]) -> Result<Vec<String>> {
    let mut outer = Der::new(value);
    let mut points = outer.sequence()?;
    outer.finish()?;
    let mut uris = Vec::new();
    while !points.is_empty() {
        let mut dp = points.sequence()?;
        if let Some(name) = dp.optional(0xa0)? {
            // DistributionPointName is a CHOICE: fullName [0] GeneralNames
            let mut inner = Der::new(name.content);
            if let Some(full) = inner.optional(0xa0)? {
                uris.extend(general_name_uris(full.content)?);
            }
        }
    }
    Ok(uris)
}

/// The OCSP responder URIs of an Authority Information Access extension: the `uniformResourceIdentifier` locations of the
/// `id-ad-ocsp` access descriptions (RFC 5280 section 4.2.2.1).
pub(crate) fn parse_ocsp_uris(value: &[u8]) -> Result<Vec<String>> {
    const OID_AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    let mut outer = Der::new(value);
    let mut list = outer.sequence()?;
    outer.finish()?;
    let mut uris = Vec::new();
    while !list.is_empty() {
        let mut ad = list.sequence()?;
        let method = ad.expect(asn1::TAG_OID)?;
        let location = ad.next()?;
        ad.finish()?;
        if method.content == OID_AD_OCSP && location.tag == 0x86 {
            if let Ok(s) = std::str::from_utf8(location.content) {
                if s.is_ascii() {
                    uris.push(s.to_string());
                }
            }
        }
    }
    Ok(uris)
}

/// The uniformResourceIdentifier entries (tag [6]) of a GeneralNames sequence body.
pub(crate) fn general_name_uris(names: &[u8]) -> Result<Vec<String>> {
    let mut d = Der::new(names);
    let mut out = Vec::new();
    while !d.is_empty() {
        let n = d.next()?;
        if n.tag == 0x86 {
            if let Ok(s) = std::str::from_utf8(n.content) {
                if s.is_ascii() {
                    out.push(s.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// True if a TLS Feature value (a SEQUENCE OF INTEGER) lists status_request (5).
fn tls_feature_requires_status_request(value: &[u8]) -> Result<bool> {
    let mut outer = Der::new(value);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let mut found = false;
    while !seq.is_empty() {
        let n = seq.expect(asn1::TAG_INTEGER)?;
        if n.content == [TLS_FEATURE_STATUS_REQUEST] {
            found = true;
        }
    }
    Ok(found)
}

/// Verifies `signature` over `msg` with `key`, for a signature algorithm taken from a certificate,
/// CRL or OCSP response. `None` (an algorithm this library does not support, SHA-1 included) is a
/// failure.
pub(crate) fn verify_signature(alg: Option<SigAlg>, key: &PublicKey, msg: &[u8], signature: &[u8]) -> bool {
    match (alg, key) {
        (Some(SigAlg::RsaPkcs1(h)), PublicKey::Rsa(k)) => k.verify_pkcs1(h, msg, signature),
        (Some(SigAlg::RsaPss(h)), PublicKey::Rsa(k)) => k.verify_pss(h, msg, signature),
        (Some(SigAlg::Ecdsa(h)), PublicKey::Ec { curve, point }) => ecdsa::verify(*curve, point, h, msg, signature),
        (Some(SigAlg::Ed25519), PublicKey::Ed25519(k)) => ed25519::verify(k, msg, signature),
        _ => false,
    }
}

impl Certificate {
    /// Parses a certificate. A critical extension this code does not know makes it fail, as RFC 5280
    /// requires of anything that relies on the certificate; chain verification (which can be told
    /// which critical extensions the caller interprets) parses without that check and applies it
    /// along the path instead.
    pub fn from_der(der: &[u8]) -> Result<Certificate> {
        let c = Certificate::parse(der)?;
        if !c.unrecognized_critical.is_empty() {
            return cert("unrecognized critical extension");
        }
        Ok(c)
    }

    pub(crate) fn parse(der: &[u8]) -> Result<Certificate> {
        let mut top = Der::new(der);
        let mut c = top.sequence()?;
        top.finish()?;
        let tbs_tlv = c.expect(asn1::TAG_SEQUENCE)?;
        let outer_alg = c.expect(asn1::TAG_SEQUENCE)?;
        let sig_bits = c.expect(asn1::TAG_BIT_STRING)?;
        c.finish()?;
        let signature = asn1::bit_string_bytes(&sig_bits)?.to_vec();

        let mut tbs = Der::new(tbs_tlv.content);
        let mut version = 0u8;
        if let Some(v) = tbs.optional(0xa0)? {
            let mut vd = Der::new(v.content);
            let ver = vd.expect(asn1::TAG_INTEGER)?;
            if ver.content.len() != 1 || ver.content[0] > 2 {
                return Err(Error::Certificate("unsupported certificate version".into()));
            }
            version = ver.content[0];
        }
        let serial_tlv = tbs.expect(asn1::TAG_INTEGER)?; // serial number
        let inner_alg = tbs.expect(asn1::TAG_SEQUENCE)?;
        if inner_alg.content != outer_alg.content {
            return cert("signature algorithm mismatch between TBSCertificate and Certificate");
        }
        let sig_alg = SigAlg::from_algorithm_identifier(outer_alg.content)?;
        let issuer = tbs.expect(asn1::TAG_SEQUENCE)?;
        let mut validity = tbs.sequence()?;
        let not_before = asn1::parse_time(&validity.next()?)?;
        let not_after = asn1::parse_time(&validity.next()?)?;
        validity.finish()?;
        let subject = tbs.expect(asn1::TAG_SEQUENCE)?;
        let spki = tbs.expect(asn1::TAG_SEQUENCE)?;
        let public_key = parse_public_key(&spki)?;
        let spki_key = {
            let mut d = Der::new(spki.content);
            d.expect(asn1::TAG_SEQUENCE)?;
            let bits = d.expect(asn1::TAG_BIT_STRING)?;
            asn1::bit_string_bytes(&bits)?.to_vec()
        };
        let serial: Vec<u8> = {
            let c = serial_tlv.content;
            let zeros = c.iter().take_while(|&&b| b == 0).count().min(c.len().saturating_sub(1));
            c[zeros..].to_vec()
        };
        tbs.optional(0x81)?; // issuerUniqueID
        tbs.optional(0x82)?; // subjectUniqueID

        let mut out = Certificate {
            der: der.to_vec(),
            tbs: tbs_tlv.raw.to_vec(),
            sig_alg,
            signature,
            issuer_der: issuer.raw.to_vec(),
            subject_der: subject.raw.to_vec(),
            issuer_key: name_key(issuer.raw),
            subject_key: name_key(subject.raw),
            serial,
            serial_content: serial_tlv.content.to_vec(),
            spki_key,
            spki: spki.raw.to_vec(),
            crl_uris: Vec::new(),
            ocsp_uris: Vec::new(),
            must_staple: false,
            not_before,
            not_after,
            public_key,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            is_ca: false,
            path_len: None,
            has_basic_constraints: false,
            key_usage: None,
            ext_key_usage: None,
            name_constraints: None,
            san: Vec::new(),
            extensions: Vec::new(),
            unrecognized_critical: Vec::new(),
            version,
            dropped_san: Vec::new(),
        };

        if let Some(exts) = tbs.optional(0xa3)? {
            let mut list = Der::new(exts.content).sequence()?;
            let mut seen: Vec<Vec<u8>> = Vec::new();
            while !list.is_empty() {
                let mut ext = list.sequence()?;
                let oid = ext.expect(asn1::TAG_OID)?.content;
                let critical = match ext.optional(asn1::TAG_BOOLEAN)? {
                    Some(b) => asn1::boolean(&b)?,
                    None => false,
                };
                let value = ext.expect(asn1::TAG_OCTET_STRING)?.content;
                ext.finish()?;
                if seen.iter().any(|s| s == oid) {
                    return cert("duplicate extension");
                }
                seen.push(oid.to_vec());
                out.extensions.push(Extension { oid: oid.to_vec(), critical, value: value.to_vec() });
                out.apply_extension(oid, critical, value)?;
            }
        }
        tbs.finish()?;
        Ok(out)
    }

    fn apply_extension(&mut self, oid: &[u8], critical: bool, value: &[u8]) -> Result<()> {
        match oid {
            OID_SAN => {
                let mut outer = Der::new(value);
                let mut names = outer.sequence()?;
                outer.finish()?;
                while !names.is_empty() {
                    let n = names.next()?;
                    // Every arm says whether it kept the entry. The kinds other than DNS names and IP
                    // addresses are advisory for TLS and read by callers that care; an entry that is
                    // malformed, or of a kind this code does not read, is left out rather than failing the
                    // certificate. What is left out is remembered by its tag, because a name constraint of
                    // that kind must still refuse the certificate (see `check_name_constraints`).
                    let kept = match n.tag {
                        0x82 => {
                            let s = std::str::from_utf8(n.content).map_err(|_| Error::Asn1("bad dNSName"))?;
                            if !s.is_ascii() {
                                return cert("non-ASCII dNSName");
                            }
                            // a line feed in a host name would end up in a log line
                            if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
                                return cert("control character in dNSName");
                            }
                            self.dns_names.push(s.to_ascii_lowercase());
                            self.san.push(GeneralName::Dns(s.to_ascii_lowercase()));
                            true
                        }
                        0x87 if n.content.len() == 4 || n.content.len() == 16 => {
                            self.ip_addrs.push(n.content.to_vec());
                            self.san.push(GeneralName::Ip(n.content.to_vec()));
                            true
                        }
                        0x81 | 0x86 => match core::str::from_utf8(n.content).ok().filter(|s| s.is_ascii()) {
                            Some(s) => {
                                self.san.push(if n.tag == 0x81 { GeneralName::Email(s.to_string()) } else { GeneralName::Uri(s.to_string()) });
                                true
                            }
                            None => false,
                        },
                        0xa4 => {
                            let mut d = Der::new(n.content);
                            match d.expect(asn1::TAG_SEQUENCE) {
                                Ok(name) if d.finish().is_ok() => {
                                    self.san.push(GeneralName::Directory(name.raw.to_vec()));
                                    true
                                }
                                _ => false,
                            }
                        }
                        0xa0 => {
                            let mut d = Der::new(n.content);
                            match (d.expect(asn1::TAG_OID), d.expect(0xa0)) {
                                (Ok(oid), Ok(v)) if d.finish().is_ok() => {
                                    self.san.push(GeneralName::Other { type_id: oid.content.to_vec(), value: v.content.to_vec() });
                                    true
                                }
                                _ => false,
                            }
                        }
                        0x88 if !n.content.is_empty() => {
                            self.san.push(GeneralName::RegisteredId(n.content.to_vec()));
                            true
                        }
                        _ => false,
                    };
                    if !kept && !self.dropped_san.contains(&n.tag) {
                        self.dropped_san.push(n.tag);
                    }
                }
            }
            OID_BASIC_CONSTRAINTS => {
                let mut outer = Der::new(value);
                let mut seq = outer.sequence()?;
                outer.finish()?;
                self.has_basic_constraints = true;
                if let Some(b) = seq.optional(asn1::TAG_BOOLEAN)? {
                    self.is_ca = asn1::boolean(&b)?;
                }
                if let Some(p) = seq.optional(asn1::TAG_INTEGER)? {
                    let v = asn1::unsigned_integer(&p)?;
                    if v.len() > 4 {
                        return cert("pathLenConstraint too large");
                    }
                    self.path_len = Some(v.iter().fold(0u32, |a, b| (a << 8) | *b as u32));
                }
            }
            OID_KEY_USAGE => {
                let mut d = Der::new(value);
                let bits = d.expect(asn1::TAG_BIT_STRING)?;
                d.finish()?;
                if bits.content.is_empty() {
                    return cert("empty keyUsage");
                }
                let mut ku = 0u16;
                for i in 0..9usize {
                    if let Some(byte) = bits.content.get(1 + i / 8) {
                        if byte & (0x80 >> (i % 8)) != 0 {
                            ku |= 1 << i;
                        }
                    }
                }
                self.key_usage = Some(ku);
            }
            OID_EKU => {
                let mut outer = Der::new(value);
                let mut seq = outer.sequence()?;
                outer.finish()?;
                let mut oids = Vec::new();
                while !seq.is_empty() {
                    oids.push(seq.expect(asn1::TAG_OID)?.content.to_vec());
                }
                self.ext_key_usage = Some(oids);
            }
            OID_NAME_CONSTRAINTS => self.name_constraints = Some(parse_name_constraints(value)?),
            OID_CRL_DP => {
                // advisory data used only to find and match CRLs: a malformed extension costs
                // nothing but the ability to use it
                self.crl_uris = parse_crl_uris(value).unwrap_or_default();
            }
            OID_TLS_FEATURE => {
                self.must_staple = tls_feature_requires_status_request(value).unwrap_or(false);
            }
            OID_AIA => {
                // advisory, like the CRL distribution points: where to ask about revocation
                self.ocsp_uris = parse_ocsp_uris(value).unwrap_or_default();
            }
            OID_SKI | OID_AKI | OID_SCT_LIST | OID_CERT_POLICIES | OID_POLICY_MAPPINGS
            | OID_POLICY_CONSTRAINTS | OID_INHIBIT_ANY_POLICY => {}
            _ => {
                if critical {
                    self.unrecognized_critical.push(oid.to_vec());
                }
            }
        }
        Ok(())
    }

    /// The OCSP responders this certificate names (Authority Information Access), in the order it gives them.
    pub fn ocsp_uris(&self) -> &[String] {
        &self.ocsp_uris
    }

    /// The URIs of the CRL distribution points this certificate names.
    pub fn crl_uris(&self) -> &[String] {
        &self.crl_uris
    }

    /// Subject name in a short readable form, for diagnostics.
    pub fn subject_summary(&self) -> String {
        describe_name(&self.subject_der)
    }

    /// Issuer name in a short readable form, for diagnostics.
    pub fn issuer_summary(&self) -> String {
        describe_name(&self.issuer_der)
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject_der == self.issuer_der
    }

    /// Verifies this certificate's signature using `issuer`'s public key.
    pub fn verify_signed_by(&self, issuer: &Certificate) -> Result<()> {
        if self.sig_alg.is_none() {
            return Err(Error::Certificate(format!(
                "unsupported certificate signature algorithm [{}]",
                self.subject_summary()
            )));
        }
        if verify_signature(self.sig_alg, &issuer.public_key, &self.tbs, &self.signature) {
            Ok(())
        } else {
            Err(Error::Certificate(format!(
                "signature of certificate [{}] was not made by the key of [{}]",
                self.subject_summary(),
                issuer.subject_summary()
            )))
        }
    }

    /// The keyUsage bits (bit 0 = digitalSignature, 1 = nonRepudiation, 5 = keyCertSign, 6 = cRLSign),
    /// if the extension is present.
    pub fn key_usage_bits(&self) -> Option<u16> {
        self.key_usage
    }

    /// The OIDs (content octets) in the extendedKeyUsage extension, or `None` if there is none.
    pub fn extended_key_usage(&self) -> Option<&[Vec<u8>]> {
        self.ext_key_usage.as_deref()
    }

    /// True if the extendedKeyUsage extension lists `oid`.
    pub(crate) fn has_ext_key_usage(&self, oid: &[u8]) -> bool {
        self.ext_key_usage.as_ref().is_some_and(|l| l.iter().any(|o| o == oid))
    }

    /// Every entry of the subjectAltName extension, in order; empty if there is none.
    pub fn subject_alt_names(&self) -> &[GeneralName] {
        &self.san
    }

    /// The e-mail addresses (rfc822Name entries) in the subjectAltName extension.
    pub fn email_addresses(&self) -> impl Iterator<Item = &str> {
        self.san.iter().filter_map(|n| if let GeneralName::Email(s) = n { Some(s.as_str()) } else { None })
    }

    /// The URIs in the subjectAltName extension. A Sigstore (Fulcio) certificate identifies the
    /// signing workflow or person this way.
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.san.iter().filter_map(|n| if let GeneralName::Uri(s) = n { Some(s.as_str()) } else { None })
    }

    /// The DER of the certificate's `SubjectPublicKeyInfo`, as written.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// The algorithm the issuer signed this certificate with, if it is one this crate knows.
    pub fn signature_algorithm(&self) -> Option<SigAlg> {
        self.sig_alg
    }

    /// The DER of the `TBSCertificate`, the part the issuer signed.
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs
    }

    /// Every extension, in the order the certificate lists them, each with its critical flag.
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The extension with this OID (content octets; [`crate::asn1::oid_from_string`] makes them from
    /// the dotted form), if the certificate has one. Extensions this library does not itself act on
    /// are kept too: Sigstore's OIDC issuer, repository and workflow are under 1.3.6.1.4.1.57264.1.
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// True if this certificate may be used for `purpose`: it has no extendedKeyUsage extension, or
    /// it lists the purpose or anyExtendedKeyUsage.
    fn allows(&self, purpose: &Purpose) -> bool {
        let Some(oid) = purpose.eku_oid() else { return true };
        match &self.ext_key_usage {
            None => true,
            Some(list) => list.iter().any(|o| o == oid || o == OID_EKU_ANY),
        }
    }
}

// ------------------------------------------------------------ purposes and options

/// What a certificate chain is being verified for: the extended key usage (RFC 5280 section
/// 4.2.1.12) that the leaf and every CA above it must permit. A certificate with no
/// extendedKeyUsage extension permits everything, except that the leaf must name the purpose
/// unless [`VerifyOptions::allow_missing_leaf_eku`] is set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// TLS server authentication (id-kp-serverAuth).
    ServerAuth,
    /// TLS client authentication (id-kp-clientAuth).
    ClientAuth,
    /// Code signing (id-kp-codeSigning): Sigstore's Fulcio, Authenticode and Apple Developer ID
    /// certificates carry it.
    CodeSigning,
    /// E-mail protection (id-kp-emailProtection): S/MIME.
    EmailProtection,
    /// Time stamping (id-kp-timeStamping): RFC 3161 time-stamp authorities.
    TimeStamping,
    /// OCSP response signing (id-kp-OCSPSigning).
    OcspSigning,
    /// Any other extended key usage, by OID (content octets), such as Microsoft's lifetime signing
    /// (1.3.6.1.4.1.311.10.3.13; see [`crate::asn1::oid_from_string`]).
    Oid(Vec<u8>),
    /// No extended key usage is required of any certificate in the chain, and the leaf's
    /// extendedKeyUsage, if it has one, is not looked at.
    Any,
}

impl Purpose {
    fn eku_oid(&self) -> Option<&[u8]> {
        match self {
            Purpose::ServerAuth => Some(OID_EKU_SERVER_AUTH),
            Purpose::ClientAuth => Some(OID_EKU_CLIENT_AUTH),
            Purpose::CodeSigning => Some(OID_EKU_CODE_SIGNING),
            Purpose::EmailProtection => Some(OID_EKU_EMAIL_PROTECTION),
            Purpose::TimeStamping => Some(OID_EKU_TIME_STAMPING),
            Purpose::OcspSigning => Some(OID_EKU_OCSP_SIGNING),
            Purpose::Oid(oid) => Some(oid),
            Purpose::Any => None,
        }
    }

    fn description(&self) -> String {
        match self {
            Purpose::ServerAuth => "TLS server authentication".to_string(),
            Purpose::ClientAuth => "TLS client authentication".to_string(),
            Purpose::CodeSigning => "code signing".to_string(),
            Purpose::EmailProtection => "e-mail protection".to_string(),
            Purpose::TimeStamping => "time stamping".to_string(),
            Purpose::OcspSigning => "OCSP signing".to_string(),
            Purpose::Oid(oid) => format!("extended key usage {}", asn1::oid_to_string(oid)),
            Purpose::Any => "any purpose".to_string(),
        }
    }

    /// The keyUsage bits of which the leaf must have at least one, if it has the extension.
    fn leaf_key_usage(&self) -> (u16, &'static str) {
        match self {
            Purpose::ServerAuth | Purpose::ClientAuth | Purpose::CodeSigning | Purpose::OcspSigning => {
                (KU_DIGITAL_SIGNATURE, "digitalSignature")
            }
            _ => (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION, "digitalSignature or nonRepudiation"),
        }
    }
}

/// What [`TrustStore::verify_chain`] checks a chain against. The trust anchors are the store's.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// What the chain is for.
    pub purpose: Purpose,
    /// The moment (Unix seconds) every certificate in the path must be valid at: now for a TLS
    /// connection, the time of the signature for a signature checked later. The caller supplies it;
    /// this code never reads a clock.
    pub time: i64,
    /// If set, the leaf must be valid for this DNS name or IP address (required for
    /// [`Purpose::ServerAuth`], optional otherwise).
    pub hostname: Option<String>,
    /// Accept a leaf that has no extendedKeyUsage extension. When false (the default of
    /// [`VerifyOptions::new`]) the leaf must list the purpose or anyExtendedKeyUsage; CAs without the
    /// extension are always accepted. [`VerifyOptions::tls_server`] sets it, as browsers do.
    pub allow_missing_leaf_eku: bool,
    /// OIDs (content octets) of critical extensions the caller interprets itself, which therefore
    /// do not make the chain unacceptable. Any other critical extension this code does not know
    /// does, in every certificate of the path.
    pub accept_critical: Vec<Vec<u8>>,
}

impl VerifyOptions {
    /// Options for `purpose` at `time`, with no host name check and a leaf that must name the purpose.
    pub fn new(purpose: Purpose, time: i64) -> VerifyOptions {
        VerifyOptions { purpose, time, hostname: None, allow_missing_leaf_eku: false, accept_critical: Vec::new() }
    }

    /// Options for a TLS server certificate for `hostname` at `time`.
    pub fn tls_server(hostname: &str, time: i64) -> VerifyOptions {
        VerifyOptions {
            purpose: Purpose::ServerAuth,
            time,
            hostname: Some(hostname.to_string()),
            allow_missing_leaf_eku: true,
            accept_critical: Vec::new(),
        }
    }

    /// Also requires the leaf to be valid for `hostname` (a DNS name or IP literal).
    pub fn with_hostname(mut self, hostname: &str) -> VerifyOptions {
        self.hostname = Some(hostname.to_string());
        self
    }

    /// Says the caller interprets the critical extension `oid` (content octets) itself.
    pub fn with_critical_extension(mut self, oid: &[u8]) -> VerifyOptions {
        self.accept_critical.push(oid.to_vec());
        self
    }
}

/// A chain that verified: the leaf, parsed, and the path that was built.
#[derive(Debug)]
pub struct VerifiedChain {
    pub leaf: Certificate,
    /// The DER of every certificate from the leaf to the trust anchor, in that order (the anchor is
    /// last, and is the store's copy, not one the sender supplied).
    pub path: Vec<Vec<u8>>,
}

impl VerifiedChain {
    /// The trust anchor the path ends in (DER).
    pub fn anchor(&self) -> &[u8] {
        self.path.last().map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ------------------------------------------------------------ hostname matching

fn normalize_host(host: &str) -> String {
    let h = host.strip_suffix('.').unwrap_or(host);
    h.to_ascii_lowercase()
}

/// RFC 6125-style matching of a DNS name against one SAN pattern (RFC 9525 section 6.3): ASCII only on both sides (an
/// internationalized name is compared as its A-labels, which [`crate::idna::to_ascii`] makes), case-insensitive, and a
/// wildcard only as the whole left-most label of a pattern with at least two labels after it.
pub fn dns_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    if pattern.is_empty() || host.is_empty() || !pattern.is_ascii() || !host.is_ascii() {
        return false;
    }
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(host);
    }
    // wildcard only as the whole left-most label, with at least two labels after it
    let Some(base) = pattern.strip_prefix("*.") else { return false };
    if base.contains('*') || !base.contains('.') {
        return false;
    }
    match host.split_once('.') {
        Some((first, rest)) => !first.is_empty() && rest.eq_ignore_ascii_case(base),
        None => false,
    }
}

fn dns_constraint_matches(constraint: &str, host: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    if let Some(suffix) = constraint.strip_prefix('.') {
        return host.ends_with(&format!(".{}", suffix));
    }
    host == constraint || host.ends_with(&format!(".{}", constraint))
}

impl Certificate {
    /// Checks that this certificate is valid for `host` (a DNS name or IP literal).
    pub fn matches_hostname(&self, host: &str) -> bool {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let octets: Vec<u8> = match ip {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            return self.ip_addrs.iter().any(|a| *a == octets);
        }
        let host = normalize_host(host);
        self.dns_names.iter().any(|p| dns_pattern_matches(p, &host))
    }
}

// ------------------------------------------------------------ trust store & chain validation

/// One trust anchor. Bulk loading only extracts the subject name (so roots can be found by the
/// issuer name of a certificate being checked); the full parse, including the public-key setup
/// that dominates the cost, happens the first time the anchor is actually needed.
struct Root {
    der: Vec<u8>,
    /// Filled on first use; `None` inside means the certificate could not be parsed, in which case
    /// the anchor is simply never used.
    parsed: OnceLock<Option<Certificate>>,
    /// Leaves issued (by their notBefore) after this time are not trusted under the anchor: how a root program winds a
    /// CA down (Mozilla's CKA_NSS_SERVER_DISTRUST_AFTER). See [`TrustStore::add_der_distrusted_after`].
    distrust_after: Option<i64>,
}

impl Root {
    fn certificate(&self) -> Option<&Certificate> {
        self.parsed.get_or_init(|| Certificate::from_der(&self.der).ok()).as_ref()
    }
}

/// What a root program says about a trust anchor beyond what its certificate says (see
/// [`TrustStore::add_der_with_limits`] and the `mozilla-roots` feature).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorLimits {
    /// Leaves issued (by their notBefore) after this time (Unix seconds) are not trusted under the anchor.
    pub distrust_after: Option<i64>,
    /// A NameConstraints extension value (DER) applied as if the anchor carried it, when it carries none of its own (as
    /// NSS does for the few roots it limits in code).
    pub name_constraints: Option<Vec<u8>>,
}

/// The set of trust anchors server certificates are validated against. Safe to share between
/// threads; anchors are parsed on demand and the result is cached.
pub struct TrustStore {
    roots: Vec<Root>,
    /// subject name (DER) -> indices into `roots`
    by_subject: HashMap<Vec<u8>, Vec<usize>>,
    /// Smallest RSA modulus accepted for the keys of the leaf and of intermediates (trust anchors
    /// are exempt: they are trusted explicitly, and some old roots still carry 1024-bit keys).
    min_rsa_bits: usize,
}

/// Default for [`TrustStore::with_min_rsa_bits`]: the CA/Browser Forum baseline.
pub const DEFAULT_MIN_RSA_BITS: usize = 2048;

/// The raw DER of a certificate's subject name, read without parsing the public key or the
/// extensions. Fails on structurally broken certificates.
fn peek_subject(der: &[u8]) -> Result<&[u8]> {
    let mut top = Der::new(der);
    let mut c = top.sequence()?;
    top.finish()?;
    let tbs_tlv = c.expect(asn1::TAG_SEQUENCE)?;
    c.expect(asn1::TAG_SEQUENCE)?;
    c.expect(asn1::TAG_BIT_STRING)?;
    c.finish()?;
    let mut tbs = Der::new(tbs_tlv.content);
    tbs.optional(0xa0)?; // version
    tbs.expect(asn1::TAG_INTEGER)?; // serial number
    tbs.expect(asn1::TAG_SEQUENCE)?; // signature algorithm
    tbs.expect(asn1::TAG_SEQUENCE)?; // issuer
    tbs.expect(asn1::TAG_SEQUENCE)?; // validity
    Ok(tbs.expect(asn1::TAG_SEQUENCE)?.raw)
}

impl TrustStore {
    /// Sets the smallest RSA modulus (in bits) accepted for the leaf and for intermediate
    /// certificates; the default is 2048. Trust anchors are exempt. Keys under 1024 bits are never
    /// parsed at all, whatever this is set to.
    pub fn with_min_rsa_bits(mut self, bits: usize) -> TrustStore {
        self.min_rsa_bits = bits;
        self
    }

    pub fn empty() -> TrustStore {
        TrustStore { roots: Vec::new(), by_subject: HashMap::new(), min_rsa_bits: DEFAULT_MIN_RSA_BITS }
    }

    /// Number of trust anchors in the store.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The trust anchors, DER, in the order they were added (to write them out as a bundle for other software).
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        self.roots.iter().map(|r| r.der.as_slice())
    }

    fn push_root(&mut self, der: &[u8], subject: &[u8], parsed: OnceLock<Option<Certificate>>) {
        let idx = self.roots.len();
        self.roots.push(Root { der: der.to_vec(), parsed, distrust_after: None });
        self.by_subject.entry(name_key(subject)).or_default().push(idx);
    }

    /// Adds one certificate, parsing it completely now so that problems are reported to the caller.
    pub fn add_der(&mut self, der: &[u8]) -> Result<()> {
        let cert = Certificate::from_der(der)?;
        let subject = cert.subject_der.clone();
        let parsed = OnceLock::new();
        let _ = parsed.set(Some(cert));
        self.push_root(der, &subject, parsed);
        Ok(())
    }

    /// Adds one certificate as [`add_der`](TrustStore::add_der) does, as an anchor only for leaves issued (by their
    /// notBefore) at or before `time` (Unix seconds): a chain whose leaf is newer is refused under this anchor. This is
    /// how a root program stops trusting a CA without breaking what it issued before (Mozilla's "distrust after" date,
    /// which the `mozilla-roots` feature carries over).
    pub fn add_der_distrusted_after(&mut self, der: &[u8], time: i64) -> Result<()> {
        self.add_der_with_limits(der, &AnchorLimits { distrust_after: Some(time), name_constraints: None })
    }

    /// Adds one certificate as [`add_der`](TrustStore::add_der) does, with the limits a root program puts on it beyond
    /// what the certificate itself says. An error if the certificate, or the name constraints, do not parse.
    pub fn add_der_with_limits(&mut self, der: &[u8], limits: &AnchorLimits) -> Result<()> {
        let mut cert = Certificate::from_der(der)?;
        if let Some(nc) = &limits.name_constraints {
            let imposed = parse_name_constraints(nc)?;
            if cert.name_constraints.is_none() {
                cert.name_constraints = Some(imposed);
            }
        }
        let subject = cert.subject_der.clone();
        let parsed = OnceLock::new();
        let _ = parsed.set(Some(cert));
        self.push_root(der, &subject, parsed);
        if let Some(root) = self.roots.last_mut() {
            root.distrust_after = limits.distrust_after;
        }
        Ok(())
    }

    /// Adds every certificate in a PEM bundle and returns how many were added. This is the bulk
    /// path used for CA bundles: only the structure and subject name are read here, and each anchor
    /// is fully parsed when it is first needed. An anchor that turns out to be unsupported (an
    /// unknown critical extension, say) is never used, exactly as if it had been skipped here.
    pub fn add_pem(&mut self, text: &str) -> usize {
        let mut added = 0;
        for block in pem::parse(text) {
            if block.label == "CERTIFICATE" || block.label == "TRUSTED CERTIFICATE" {
                if let Ok(subject) = peek_subject(&block.data) {
                    let subject = subject.to_vec();
                    self.push_root(&block.data, &subject, OnceLock::new());
                    added += 1;
                }
            }
        }
        added
    }

    /// The parsed anchors whose subject name matches the name whose [`name_key`] is `key`, with their distrust dates.
    fn anchors_for<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = (&'a Certificate, Option<i64>)> + 'a {
        self.by_subject.get(key).into_iter().flatten().filter_map(move |&i| self.roots[i].certificate().map(|c| (c, self.roots[i].distrust_after)))
    }

    /// Validates a server-presented chain (leaf first, DER encoded) for `hostname` at time `now`
    /// (Unix seconds). Returns the parsed leaf on success. This is [`verify_chain`](TrustStore::verify_chain)
    /// with [`VerifyOptions::tls_server`].
    pub fn verify_server_chain(&self, chain_der: &[Vec<u8>], hostname: &str, now: i64) -> Result<Certificate> {
        self.verify_server_path(chain_der, hostname, now).map(|(leaf, _)| leaf)
    }

    /// Like [`verify_server_chain`](TrustStore::verify_server_chain), and also returns the path it
    /// built: the DER of every certificate from the leaf to the trust anchor, in that order (the
    /// anchor is last). Revocation checking needs each certificate's issuer.
    pub(crate) fn verify_server_path(&self, chain_der: &[Vec<u8>], hostname: &str, now: i64) -> Result<(Certificate, Vec<Vec<u8>>)> {
        let chain: Vec<&[u8]> = chain_der.iter().map(|d| d.as_slice()).collect();
        self.build_path(&chain, &VerifyOptions::tls_server(hostname, now))
    }

    /// Verifies a certificate chain for the purpose, at the time and (if given) for the host name in
    /// `options`, against this store's trust anchors.
    ///
    /// `chain_der` is the leaf first (DER), then whatever intermediates the sender supplied, in any
    /// order; certificates that do not parse, or that lead nowhere, are ignored. The path is built
    /// from the leaf through those intermediates to an anchor in the store, trying every candidate
    /// issuer, and the first path that passes every check is the result. A path passes when every
    /// signature verifies and every certificate in it (anchor included) is valid at
    /// `options.time`, allows `options.purpose`, and has no critical extension that is neither known
    /// here nor listed in `options.accept_critical`; the leaf also has the key usage for signing, the
    /// host name if one was asked for, and (unless `allow_missing_leaf_eku`) an extendedKeyUsage
    /// naming the purpose; every certificate above the leaf is a CA with keyCertSign, within its
    /// pathLenConstraint and name constraints; and RSA keys other than the anchor's are at least
    /// [`with_min_rsa_bits`](TrustStore::with_min_rsa_bits) wide. (A trust anchor of version 1, which has no
    /// extensions and so cannot say it is a CA, is taken to be one; a version 3 anchor must say so.)
    ///
    /// The search for a path stops after a fixed number of signature checks (256), however many certificates
    /// were sent, and refuses the chain with an error that says so.
    ///
    /// Nothing about the leaf's identity is matched except the host name. What it says (e-mail
    /// addresses, URIs, other names, any extension) is for the caller to read and compare; see
    /// [`Certificate::subject_alt_names`] and [`Certificate::extension`]. Revocation is a separate
    /// step ([`crate::revocation`]).
    pub fn verify_chain<D: AsRef<[u8]>>(&self, chain_der: &[D], options: &VerifyOptions) -> Result<VerifiedChain> {
        let chain: Vec<&[u8]> = chain_der.iter().map(|d| d.as_ref()).collect();
        let (leaf, path) = self.build_path(&chain, options)?;
        Ok(VerifiedChain { leaf, path })
    }

    fn build_path(&self, chain_der: &[&[u8]], opts: &VerifyOptions) -> Result<(Certificate, Vec<Vec<u8>>)> {
        if chain_der.is_empty() {
            return cert("server sent no certificates");
        }
        if opts.purpose == Purpose::ServerAuth && opts.hostname.is_none() {
            return cert("a host name is required to verify a certificate for TLS server authentication");
        }
        let leaf = Certificate::parse(chain_der[0])?;
        let mut intermediates = Vec::new();
        // a certificate sent twice (or the leaf sent again) is one candidate, not two
        let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        seen.insert(chain_der[0]);
        for der in &chain_der[1..] {
            if !seen.insert(*der) {
                continue;
            }
            // A malformed extra certificate must not sink an otherwise valid chain.
            if let Ok(c) = Certificate::parse(der) {
                intermediates.push(c);
            }
        }
        let mut path: Vec<&Certificate> = vec![&leaf];
        let mut used = vec![false; intermediates.len()];
        let mut last_err: Option<Error> = None;
        let mut dead_end: Option<String> = None;
        let mut attempts = 0usize;
        if self.search(&mut path, &intermediates, &mut used, opts, &mut last_err, &mut dead_end, &mut attempts) {
            let path_der: Vec<Vec<u8>> = path.iter().map(|c| c.der.clone()).collect();
            drop(path);
            return Ok((leaf, path_der));
        }
        if attempts > MAX_PATH_ATTEMPTS {
            return Err(Error::Certificate(format!(
                "gave up after {} signature checks while building a chain for [{}]: too many certificates that could be each other's issuers",
                MAX_PATH_ATTEMPTS,
                leaf.subject_summary()
            )));
        }
        Err(last_err.unwrap_or_else(|| {
            Error::Certificate(format!(
                "unable to build a chain to a trusted root for [{}]: {}",
                leaf.subject_summary(),
                dead_end.unwrap_or_else(|| "no usable certificate path".to_string())
            ))
        }))
    }

    fn search<'a>(
        &'a self,
        path: &mut Vec<&'a Certificate>,
        inters: &'a [Certificate],
        used: &mut Vec<bool>,
        opts: &VerifyOptions,
        last_err: &mut Option<Error>,
        dead_end: &mut Option<String>,
        attempts: &mut usize,
    ) -> bool {
        let Some(&cur) = path.last() else { return false };
        let mut candidates = 0usize;
        for (root, distrust_after) in self.anchors_for(&cur.issuer_key) {
            *attempts += 1;
            if *attempts > MAX_PATH_ATTEMPTS {
                return false;
            }
            candidates += 1;
            if let Err(e) = cur.verify_signed_by(root) {
                last_err.get_or_insert(e);
                continue;
            }
            path.push(root);
            let distrusted = distrust_after.filter(|&t| path[0].not_before > t).map(|t| {
                path_err(root, &format!("the leaf was issued ({}) after the date ({}) from which certificates are not trusted under the root", utc_date(path[0].not_before), utc_date(t)))
            });
            match distrusted.map_or_else(|| check_path(path, opts, self.min_rsa_bits), Err) {
                Ok(()) => return true,
                Err(e) => *last_err = Some(e),
            }
            path.pop();
        }
        if path.len() > MAX_CHAIN_DEPTH {
            dead_end.get_or_insert_with(|| format!("chain is longer than {} certificates", MAX_CHAIN_DEPTH));
            return false;
        }
        for (i, ic) in inters.iter().enumerate() {
            if used[i] || ic.subject_key != cur.issuer_key || ic.is_self_issued() {
                continue;
            }
            *attempts += 1;
            if *attempts > MAX_PATH_ATTEMPTS {
                return false;
            }
            candidates += 1;
            if let Err(e) = cur.verify_signed_by(ic) {
                last_err.get_or_insert(e);
                continue;
            }
            used[i] = true;
            path.push(ic);
            if self.search(path, inters, used, opts, last_err, dead_end, attempts) {
                return true;
            }
            path.pop();
            used[i] = false;
        }
        if candidates == 0 {
            dead_end.get_or_insert_with(|| {
                format!("the issuer [{}] of certificate [{}] is neither a trusted root nor sent by the server", cur.issuer_summary(), cur.subject_summary())
            });
        }
        false
    }
}

/// A Unix time as a UTC date and time (`2026-04-15T23:59:59Z`), for messages.
fn utc_date(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // civil_from_days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

/// A certificate error that names the certificate it is about.
fn path_err(c: &Certificate, what: &str) -> Error {
    Error::Certificate(format!("{} [{}]", what, c.subject_summary()))
}

// ------------------------------------------------------------ name constraints

/// Does `host` fall under the URI constraint `constraint`? A constraint without a leading dot names
/// one host; with a dot, any subdomain of it (RFC 5280 section 4.2.1.10).
fn uri_host_matches(constraint: &str, host: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    if constraint.starts_with('.') {
        host.len() > constraint.len() && host[host.len() - constraint.len()..].eq_ignore_ascii_case(constraint)
    } else {
        host.eq_ignore_ascii_case(constraint)
    }
}

/// The host of a URI that has an authority with a DNS name for a host. `None` for a URI without an
/// authority and for one whose host is an IP address: no domain constraint matches those.
fn uri_host(uri: &str) -> Option<&str> {
    let rest = uri.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.starts_with('[') {
        return None;
    }
    let host = authority.split(':').next()?;
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

fn email_constraint_matches(constraint: &str, mailbox: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    let Some((local, domain)) = mailbox.rsplit_once('@') else { return false };
    if let Some((c_local, c_domain)) = constraint.rsplit_once('@') {
        return local == c_local && domain.eq_ignore_ascii_case(c_domain);
    }
    if constraint.starts_with('.') {
        domain.len() > constraint.len() && domain[domain.len() - constraint.len()..].eq_ignore_ascii_case(constraint)
    } else {
        domain.eq_ignore_ascii_case(constraint)
    }
}

fn ip_constraint_matches(constraint: &[u8], ip: &[u8]) -> bool {
    if constraint.len() != ip.len() * 2 {
        return false;
    }
    let (addr, mask) = constraint.split_at(ip.len());
    ip.iter().zip(addr).zip(mask).all(|((i, a), m)| i & m == a & m)
}

/// A host name without the one trailing dot that writes it as fully qualified. Matching ignores it
/// (as the host name match does), so `bad.example.com.` cannot slip past an exclusion of `bad.example.com`.
fn without_trailing_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

/// `Some(whether `name` is within `c`)`, or `None` if `c` is about another kind of name.
fn constraint_covers(c: &Constraint, name: &GeneralName) -> Option<bool> {
    match (c, name) {
        (Constraint::Dns(c), GeneralName::Dns(n)) => Some(dns_constraint_matches(c, without_trailing_dot(n))),
        (Constraint::Email(c), GeneralName::Email(n)) => Some(
            c.is_empty()
                || match n.rsplit_once('@') {
                    Some((local, domain)) => email_constraint_matches(c, &format!("{}@{}", local, without_trailing_dot(domain))),
                    None => false,
                },
        ),
        (Constraint::Uri(c), GeneralName::Uri(n)) => {
            Some(c.is_empty() || uri_host(n).is_some_and(|h| uri_host_matches(c, without_trailing_dot(h))))
        }
        (Constraint::Ip(c), GeneralName::Ip(n)) => Some(ip_constraint_matches(c, n)),
        _ => None,
    }
}

fn name_label(name: &GeneralName) -> String {
    match name {
        GeneralName::Dns(n) => format!("DNS name {:?}", n),
        GeneralName::Email(n) => format!("e-mail address {:?}", n),
        GeneralName::Uri(n) => format!("URI {:?}", n),
        GeneralName::Ip(b) if b.len() == 4 => format!("IP address {}", IpAddr::from([b[0], b[1], b[2], b[3]])),
        GeneralName::Ip(b) => match <[u8; 16]>::try_from(b.as_slice()) {
            Ok(a) => format!("IP address {}", IpAddr::from(a)),
            Err(_) => "IP address".to_string(),
        },
        _ => "name".to_string(),
    }
}

/// The e-mail addresses in a subject name (`emailAddress` attributes, which older S/MIME certificates use
/// instead of or beside a subjectAltName).
fn subject_email_addresses(name_der: &[u8]) -> Vec<String> {
    const OID_EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    let mut out = Vec::new();
    let mut outer = Der::new(name_der);
    let Ok(mut rdns) = outer.sequence() else { return out };
    while !rdns.is_empty() {
        let Ok(set) = rdns.expect(asn1::TAG_SET) else { break };
        let mut atvs = Der::new(set.content);
        while !atvs.is_empty() {
            let Ok(mut atv) = atvs.sequence() else { break };
            let (Ok(oid), Ok(value)) = (atv.expect(asn1::TAG_OID), atv.next()) else { break };
            if oid.content == OID_EMAIL_ADDRESS {
                out.push(String::from_utf8_lossy(value.content).into_owned());
            }
        }
    }
    out
}

/// Applies the name constraints of a CA to the names of every certificate below it in the path (`below` is the
/// leaf first, then the intermediates up to the one the CA issued): the subjectAltName and, for e-mail
/// constraints, the e-mail addresses in the subject name (RFC 5280 section 4.2.1.10 asks for that when there
/// is no subjectAltName; OpenSSL does it whether or not there is one, and so does this). A name the
/// certificate reader left out (a kind it does not read, or a malformed entry) cannot be checked, so a
/// constraint of its kind refuses the certificate. A constraint on directory names is refused outright: it
/// applies to the subject name of every certificate below the CA, this code does not compare names, and
/// ignoring the constraint would let the CA issue outside the subtree it was limited to (OpenSSL enforces such
/// a constraint and Go refuses the chain as an unhandled critical extension). Self-issued certificates are not
/// exempt here as RFC 5280 would have it, but none is ever an intermediate of a path (see `search`).
fn check_name_constraints(ca: &Certificate, nc: &NameConstraints, below: &[&Certificate]) -> Result<()> {
    let constraints = || nc.permitted.iter().chain(nc.excluded.iter());
    if constraints().any(|c| c.kind() == 0xa4) {
        return Err(path_err(ca, "directoryName name constraints are not supported, in"));
    }
    for cert in below {
        for name in &cert.san {
            check_one_name(ca, nc, name)?;
        }
        for &kind in &cert.dropped_san {
            if constraints().any(|c| c.kind() == kind) {
                return Err(path_err(ca, "a name that cannot be read is under a name constraint of its kind, in"));
            }
        }
        if constraints().any(|c| matches!(c, Constraint::Email(_))) {
            for mail in subject_email_addresses(&cert.subject_der) {
                check_one_name(ca, nc, &GeneralName::Email(mail))?;
            }
        }
    }
    Ok(())
}

fn check_one_name(ca: &Certificate, nc: &NameConstraints, name: &GeneralName) -> Result<()> {
    let kind = name.tag();
    let unsupported = |c: &Constraint| matches!(c, Constraint::Unsupported(t) if *t == kind);
    if nc.permitted.iter().chain(nc.excluded.iter()).any(unsupported) {
        return Err(path_err(
            ca,
            &format!("{} is under a name constraint of a kind that is not supported, in", name_label(name)),
        ));
    }
    if nc.excluded.iter().any(|c| constraint_covers(c, name) == Some(true)) {
        return Err(path_err(ca, &format!("{} is excluded by a name constraint of", name_label(name))));
    }
    let mut applies = false;
    let mut permitted = false;
    for c in &nc.permitted {
        if let Some(m) = constraint_covers(c, name) {
            applies = true;
            permitted |= m;
        }
    }
    if applies && !permitted {
        return Err(path_err(ca, &format!("{} is not permitted by name constraints of", name_label(name))));
    }
    Ok(())
}

/// Checks everything about a candidate path (leaf first, trust anchor last) except signatures.
fn check_path(path: &[&Certificate], opts: &VerifyOptions, min_rsa_bits: usize) -> Result<()> {
    let leaf = path[0];
    for c in path {
        if opts.time < c.not_before {
            return Err(path_err(c, "certificate is not yet valid"));
        }
        if opts.time > c.not_after {
            return Err(path_err(c, "certificate has expired"));
        }
        if let Some(oid) = c.unrecognized_critical.iter().find(|o| !opts.accept_critical.contains(o)) {
            return Err(path_err(c, &format!("unrecognized critical extension {} in", asn1::oid_to_string(oid))));
        }
    }
    // Key-size policy for everything the server controls; the trust anchor (last) is exempt.
    for c in &path[..path.len() - 1] {
        if let PublicKey::Rsa(k) = &c.public_key {
            if k.bits() < min_rsa_bits {
                return Err(path_err(
                    c,
                    &format!("RSA key of {} bits is below the minimum of {} bits", k.bits(), min_rsa_bits),
                ));
            }
        }
    }
    if let Some(hostname) = &opts.hostname {
        if !leaf.matches_hostname(hostname) {
            let mut names: Vec<String> = leaf.dns_names.iter().take(5).cloned().collect();
            if leaf.dns_names.len() > 5 {
                names.push("...".to_string());
            }
            let valid_for = if names.is_empty() { "it lists no DNS names".to_string() } else { format!("it is valid for: {}", names.join(", ")) };
            return Err(Error::Certificate(format!(
                "certificate [{}] is not valid for host name {:?}; {}",
                leaf.subject_summary(),
                hostname,
                valid_for
            )));
        }
    }
    let purpose = &opts.purpose;
    if !leaf.allows(purpose) {
        return Err(path_err(leaf, &format!("leaf certificate is not valid for {}", purpose.description())));
    }
    if leaf.ext_key_usage.is_none() && !opts.allow_missing_leaf_eku && *purpose != Purpose::Any {
        return Err(path_err(
            leaf,
            &format!("leaf certificate has no extendedKeyUsage, which must name {}:", purpose.description()),
        ));
    }
    if let Some(ku) = leaf.key_usage {
        let (needed, what) = purpose.leaf_key_usage();
        if ku & needed == 0 {
            return Err(path_err(leaf, &format!("leaf certificate keyUsage does not permit {}", what)));
        }
    }
    let last = path.len() - 1;
    for i in 1..path.len() {
        let ca = path[i];
        let is_anchor = i == last;
        // Every issuing certificate must say it is a CA. The one exception is a version 1 (or 2) trust anchor,
        // which has no extensions and so no way to say it: the old roots, and being in the store is what makes
        // one a CA. (OpenSSL and Go make the same exception.) A version 3 anchor with no basicConstraints is an
        // ordinary certificate, and so is one whose basicConstraints says it is not a CA.
        if !ca.is_ca && (!is_anchor || ca.has_basic_constraints || ca.version >= 2) {
            return Err(path_err(ca, "issuing certificate is not a CA"));
        }
        if let Some(ku) = ca.key_usage {
            if ku & KU_KEY_CERT_SIGN == 0 {
                return Err(path_err(ca, "issuing certificate keyUsage does not permit certificate signing"));
            }
        }
        if !ca.allows(purpose) {
            return Err(path_err(ca, &format!("issuing certificate is not valid for {}", purpose.description())));
        }
        if let Some(limit) = ca.path_len {
            // intermediates strictly between the leaf and this CA, excluding self-issued ones
            let below = path[1..i].iter().filter(|c| !c.is_self_issued()).count() as u32;
            if below > limit {
                return Err(path_err(ca, "certificate path exceeds the pathLenConstraint of"));
            }
        }
        if let Some(nc) = &ca.name_constraints {
            check_name_constraints(ca, nc, &path[..i])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-09-15; fixtures are valid 2020..2120 except the deliberately expired one.
    const NOW: i64 = 1_789_430_400;

    fn der(pem_text: &str) -> Vec<u8> {
        pem::parse(pem_text).remove(0).data
    }

    macro_rules! fixture {
        ($name:literal) => {
            der(include_str!(concat!("../tests/data/", $name, ".pem")))
        };
    }

    fn store(names: &[Vec<u8>]) -> TrustStore {
        let mut s = TrustStore::empty();
        for n in names {
            s.add_der(n).unwrap();
        }
        s
    }

    #[test]
    fn rsa_root_p256_intermediate_p384_leaf() {
        let ts = store(&[fixture!("root_rsa")]);
        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        let leaf = ts.verify_server_chain(&chain, "example.test", NOW).unwrap();
        assert_eq!(leaf.dns_names, vec!["example.test", "*.wild.test"]);
        assert!(ts.verify_server_chain(&chain, "foo.wild.test", NOW).is_ok());
        assert!(ts.verify_server_chain(&chain, "127.0.0.1", NOW).is_ok());
    }

    fn pem_of(der: &[u8]) -> String {
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", pem::base64_encode(der))
    }

    fn parsed_count(ts: &TrustStore) -> usize {
        ts.roots.iter().filter(|r| r.parsed.get().is_some()).count()
    }

    #[test]
    fn bulk_loading_is_lazy_and_only_parses_the_anchors_it_uses() {
        // A bundle with several unrelated roots plus junk between the blocks.
        let mut text = String::from("# bundle\n");
        for der in [fixture!("root_p384"), fixture!("inter_nc"), fixture!("root_rsa"), fixture!("leaf_by_leaf")] {
            text.push_str(&pem_of(&der));
            text.push_str("some text between blocks\n");
        }
        let mut ts = TrustStore::empty();
        assert_eq!(ts.add_pem(&text), 4);
        assert_eq!(ts.len(), 4);
        assert_eq!(parsed_count(&ts), 0, "nothing should be parsed at load time");

        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        ts.verify_server_chain(&chain, "example.test", NOW).unwrap();
        assert_eq!(parsed_count(&ts), 1, "only the matching root should have been parsed");
        // A second lookup reuses the cached parse.
        ts.verify_server_chain(&chain, "example.test", NOW).unwrap();
        assert_eq!(parsed_count(&ts), 1);

        // add_der still parses eagerly.
        let mut eager = TrustStore::empty();
        eager.add_der(&fixture!("root_rsa")).unwrap();
        assert_eq!(parsed_count(&eager), 1);
    }

    #[test]
    fn unparsable_anchor_is_never_used_and_add_der_reports_it() {
        // Valid DER structure, but the outer signature algorithm no longer matches the one inside
        // the TBSCertificate, so the full parse fails.
        let mut bad = fixture!("root_rsa");
        let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let pos = bad.windows(oid.len()).rposition(|w| w == oid).unwrap();
        bad[pos + oid.len() - 1] ^= 0x01; // the outer OID no longer matches the inner one
        assert!(Certificate::from_der(&bad).is_err());
        assert!(TrustStore::empty().add_der(&bad).is_err());

        let mut ts = TrustStore::empty();
        assert_eq!(ts.add_pem(&pem_of(&bad)), 1); // structurally fine, so accepted by the bulk loader
        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        assert!(ts.verify_server_chain(&chain, "example.test", NOW).is_err());
        // ... and it does not get in the way of a good copy of the same root.
        assert_eq!(ts.add_pem(&pem_of(&fixture!("root_rsa"))), 1);
        assert!(ts.verify_server_chain(&chain, "example.test", NOW).is_ok());

        // Structurally broken input is skipped by add_pem.
        let mut junk = TrustStore::empty();
        assert_eq!(junk.add_pem(&pem_of(b"not a certificate")), 0);
    }

    #[test]
    fn shared_store_parses_each_anchor_once_across_threads() {
        use std::sync::Arc;
        let mut ts = TrustStore::empty();
        ts.add_pem(&pem_of(&fixture!("root_rsa")));
        ts.add_pem(&pem_of(&fixture!("root_p384")));
        let ts = Arc::new(ts);
        let chain = Arc::new(vec![fixture!("leaf_p384"), fixture!("inter_p256")]);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (ts, chain) = (ts.clone(), chain.clone());
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        ts.verify_server_chain(&chain, "example.test", NOW).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(parsed_count(&ts), 1);
    }

    #[test]
    fn hostname_mismatch_rejected() {
        let ts = store(&[fixture!("root_rsa")]);
        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        assert!(ts.verify_server_chain(&chain, "other.test", NOW).is_err());
        assert!(ts.verify_server_chain(&chain, "a.b.wild.test", NOW).is_err());
        assert!(ts.verify_server_chain(&chain, "wild.test", NOW).is_err());
        assert!(ts.verify_server_chain(&chain, "127.0.0.2", NOW).is_err());
    }

    #[test]
    fn p384_root_rsa_leaf() {
        let ts = store(&[fixture!("root_p384")]);
        let chain = vec![fixture!("leaf_rsa")];
        let leaf = ts.verify_server_chain(&chain, "rsa.test", NOW).unwrap();
        assert!(matches!(leaf.public_key, PublicKey::Rsa(_)));
    }

    #[test]
    fn missing_intermediate_or_wrong_root_rejected() {
        let ts = store(&[fixture!("root_rsa")]);
        assert!(ts.verify_server_chain(&[fixture!("leaf_p384")], "example.test", NOW).is_err());
        let other = store(&[fixture!("root_p384")]);
        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        assert!(other.verify_server_chain(&chain, "example.test", NOW).is_err());
    }

    #[test]
    fn expiry_enforced() {
        let ts = store(&[fixture!("root_rsa")]);
        let chain = vec![fixture!("leaf_expired"), fixture!("inter_p256")];
        let err = ts.verify_server_chain(&chain, "expired.test", NOW).unwrap_err();
        assert!(err.to_string().contains("expired"), "{}", err);
        // same chain is fine back in time
        assert!(ts.verify_server_chain(&chain, "expired.test", 1_600_000_000).is_ok());
        // a not-yet-valid moment
        assert!(ts.verify_server_chain(&chain, "expired.test", 1_000_000_000).is_err());
    }

    #[test]
    fn non_ca_cannot_issue() {
        let ts = store(&[fixture!("root_rsa")]);
        // leaf2 was signed by leaf_p384, which chains to the root but is not a CA
        let chain = vec![fixture!("leaf_by_leaf"), fixture!("leaf_p384"), fixture!("inter_p256")];
        let err = ts.verify_server_chain(&chain, "byleaf.test", NOW).unwrap_err();
        assert!(err.to_string().contains("not a CA"), "{}", err);
    }

    #[test]
    fn path_length_enforced() {
        let ts = store(&[fixture!("root_rsa")]);
        // inter_p256 has pathLen 0, so a second CA below it is not allowed
        let chain = vec![fixture!("leaf_deep"), fixture!("inter2_p256"), fixture!("inter_p256")];
        let err = ts.verify_server_chain(&chain, "deep.test", NOW).unwrap_err();
        assert!(err.to_string().contains("pathLen"), "{}", err);
    }

    #[test]
    fn name_constraints_enforced() {
        let ts = store(&[fixture!("root_rsa")]);
        let ok = vec![fixture!("leaf_nc_ok"), fixture!("inter_nc")];
        assert!(ts.verify_server_chain(&ok, "a.constrained.test", NOW).is_ok());
        let bad = vec![fixture!("leaf_nc_bad"), fixture!("inter_nc")];
        let err = ts.verify_server_chain(&bad, "outside.test", NOW).unwrap_err();
        assert!(err.to_string().contains("name constraints"), "{}", err);
    }

    #[test]
    fn tampered_leaf_rejected() {
        let ts = store(&[fixture!("root_rsa")]);
        let mut leaf = fixture!("leaf_p384");
        let n = leaf.len();
        leaf[n / 2] ^= 1; // flip a bit somewhere inside TBS
        let chain = vec![leaf, fixture!("inter_p256")];
        assert!(ts.verify_server_chain(&chain, "example.test", NOW).is_err());
    }

    #[test]
    fn wildcard_rules() {
        assert!(dns_pattern_matches("*.example.com", "a.example.com"));
        assert!(!dns_pattern_matches("*.example.com", "example.com"));
        assert!(!dns_pattern_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_pattern_matches("*.com", "example.com"));
        assert!(!dns_pattern_matches("f*.example.com", "foo.example.com"));
        assert!(!dns_pattern_matches("a.*.example.com", "a.b.example.com"));
        assert!(dns_pattern_matches("Example.COM", "example.com"));
        assert!(!dns_pattern_matches("", ""));
    }

    #[test]
    fn rsa_key_size_policy_applies_to_leaf_and_intermediates_but_not_to_anchors() {
        let ts = store(&[fixture!("ks_root_p256")]);
        // control: a 2048-bit leaf is fine
        ts.verify_server_chain(&[fixture!("ks_leaf_rsa2048")], "big.test", NOW).unwrap();
        // a 1024-bit leaf is rejected and the error says why and which certificate
        let err = ts.verify_server_chain(&[fixture!("ks_leaf_rsa1024")], "small.test", NOW).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1024 bits is below the minimum of 2048"), "{}", msg);
        assert!(msg.contains("CN=small-rsa-leaf"), "{}", msg);
        // ...unless the caller lowers the floor
        let relaxed = store(&[fixture!("ks_root_p256")]).with_min_rsa_bits(1024);
        relaxed.verify_server_chain(&[fixture!("ks_leaf_rsa1024")], "small.test", NOW).unwrap();
        // a 1024-bit intermediate is rejected too, even though it signed the leaf correctly
        let chain = [fixture!("ks_leaf_by_small_inter"), fixture!("ks_inter_rsa1024")];
        let err = ts.verify_server_chain(&chain, "via.test", NOW).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1024 bits") && msg.contains("CN=KS Small Intermediate"), "{}", msg);
        // an old 1024-bit trust anchor remains usable
        let old = store(&[fixture!("ks_root_rsa1024")]);
        old.verify_server_chain(&[fixture!("ks_leaf_old_root")], "old.test", NOW).unwrap();
    }

    #[test]
    fn errors_name_the_certificate_involved() {
        let ts = store(&[fixture!("root_rsa")]);
        // the intermediate was not sent: the message names the leaf and the missing issuer
        let err = ts.verify_server_chain(&[fixture!("leaf_p384")], "example.test", NOW).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[CN=leaf]") && msg.contains("[CN=Test Intermediate P256]"), "{}", msg);
        // wrong host name: lists what the certificate is valid for
        let chain = vec![fixture!("leaf_p384"), fixture!("inter_p256")];
        let msg = ts.verify_server_chain(&chain, "nope.test", NOW).unwrap_err().to_string();
        assert!(msg.contains("[CN=leaf]") && msg.contains("valid for: example.test, *.wild.test"), "{}", msg);
        // expiry names the expired certificate
        let chain = vec![fixture!("leaf_expired"), fixture!("inter_p256")];
        let msg = ts.verify_server_chain(&chain, "expired.test", NOW).unwrap_err().to_string();
        assert!(msg.contains("has expired [CN=expired]"), "{}", msg);
        // an issuer that is present but did not sign the certificate
        let other = store(&[fixture!("root_p384")]);
        other.verify_server_chain(&[fixture!("leaf_rsa")], "rsa.test", NOW).unwrap(); // control
        let wrong = store(&[fixture!("root_rsa")]);
        let msg = wrong.verify_server_chain(&[fixture!("leaf_rsa")], "rsa.test", NOW).unwrap_err().to_string();
        assert!(msg.contains("[CN=rsaleaf]") && msg.contains("[CN=Test Root P384]"), "{}", msg);
    }

    #[test]
    fn describe_name_is_log_safe() {
        fn name_with_cn(value: &[u8]) -> Vec<u8> {
            let mut atv = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, value.len() as u8];
            atv.extend_from_slice(value);
            let mut seq = vec![0x30, atv.len() as u8];
            seq.extend(atv);
            let mut set = vec![0x31, seq.len() as u8];
            set.extend(seq);
            let mut name = vec![0x30, set.len() as u8];
            name.extend(set);
            name
        }
        assert_eq!(describe_name(&name_with_cn(b"example.com")), "CN=example.com");
        // control characters cannot forge log lines
        assert_eq!(describe_name(&name_with_cn(b"a\nb\x1b[31m")), "CN=a?b?[31m");
        // long values are cut
        let long = vec![b'x'; 100];
        assert_eq!(describe_name(&name_with_cn(&long)).len(), "CN=".len() + 64);
        // garbage never panics and says so
        assert_eq!(describe_name(&[0x30, 0x05, 0x01]), "<unreadable name>");
        assert_eq!(describe_name(&[]), "<unreadable name>");
        assert_eq!(describe_name(&[0x30, 0x00]), "<name without common attributes>");
    }

    // ------------------------------------------------------------ B-69: chains for other purposes

    // The short-lived (ten minute) Fulcio-profile leaves were issued at 2025-03-01 12:00:00 UTC.
    const SIGNED_AT: i64 = 1_740_830_700; // 12:05, in the middle of their validity
    const OID_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
    const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const WORKFLOW: &str = "https://github.com/example-org/example-repo/.github/workflows/release.yml@refs/tags/v1.2.3";

    fn oid(dotted: &str) -> Vec<u8> {
        asn1::oid_from_string(dotted).unwrap()
    }

    fn code_signing(time: i64) -> VerifyOptions {
        VerifyOptions::new(Purpose::CodeSigning, time)
    }

    fn fulcio_store() -> TrustStore {
        store(&[fixture!("cs_root")])
    }

    fn err_text<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_fulcio_profile_chain_verifies_at_the_time_of_the_signature_and_not_at_another() {
        let ts = fulcio_store();
        let chain = [fixture!("cs_leaf_workflow"), fixture!("cs_inter")];
        let ok = ts.verify_chain(&chain, &code_signing(SIGNED_AT)).unwrap();
        // the path is the leaf, the intermediate and the store's own copy of the root
        assert_eq!(ok.path, vec![fixture!("cs_leaf_workflow"), fixture!("cs_inter"), fixture!("cs_root")]);
        assert_eq!(ok.anchor(), &fixture!("cs_root")[..]);
        assert_eq!(ok.leaf.der, ok.path[0]);
        // the leaf lives for ten minutes: valid at both ends, not a minute either side, not now
        assert!(ts.verify_chain(&chain, &code_signing(1_740_830_400)).is_ok());
        assert!(ts.verify_chain(&chain, &code_signing(1_740_831_000)).is_ok());
        assert!(err_text(ts.verify_chain(&chain, &code_signing(1_740_830_399))).contains("not yet valid"));
        assert!(err_text(ts.verify_chain(&chain, &code_signing(1_740_831_001))).contains("has expired"));
        assert!(err_text(ts.verify_chain(&chain, &code_signing(NOW))).contains("has expired"));
        // the intermediate may also be an anchor of the caller's, and then it need not be sent
        let by_inter = store(&[fixture!("cs_inter")]);
        let ok = by_inter.verify_chain(&[fixture!("cs_leaf_workflow")], &code_signing(SIGNED_AT)).unwrap();
        assert_eq!(ok.path.len(), 2);
        // and the chain may be given as slices as well as vectors
        let slices: [&[u8]; 2] = [&chain[0], &chain[1]];
        ts.verify_chain(&slices, &code_signing(SIGNED_AT)).unwrap();
    }

    #[test]
    fn what_the_certificate_says_about_the_signer_is_readable() {
        let ts = fulcio_store();
        let chain = [fixture!("cs_leaf_workflow"), fixture!("cs_inter")];
        let leaf = ts.verify_chain(&chain, &code_signing(SIGNED_AT)).unwrap().leaf;
        assert_eq!(leaf.uris().collect::<Vec<_>>(), vec![WORKFLOW]);
        assert_eq!(leaf.subject_alt_names(), &[GeneralName::Uri(WORKFLOW.to_string())]);
        assert_eq!(leaf.email_addresses().count(), 0);
        let ext = |n: u32| leaf.extension(&oid(&format!("1.3.6.1.4.1.57264.1.{}", n)));
        // the first-generation issuer extension is raw text, the later ones are DER strings
        assert_eq!(ext(1).unwrap().value, GITHUB_ISSUER.as_bytes());
        assert_eq!(ext(1).unwrap().der_string(), None);
        assert_eq!(ext(8).unwrap().der_string().as_deref(), Some(GITHUB_ISSUER));
        assert_eq!(ext(9).unwrap().der_string().as_deref(), Some(WORKFLOW));
        assert_eq!(ext(12).unwrap().der_string().as_deref(), Some("https://github.com/example-org/example-repo"));
        assert_eq!(ext(13).unwrap().der_string().as_deref(), Some("0123456789abcdef0123456789abcdef01234567"));
        assert_eq!(ext(14).unwrap().der_string().as_deref(), Some("refs/tags/v1.2.3"));
        assert_eq!(ext(8).unwrap().oid_string(), "1.3.6.1.4.1.57264.1.8");
        assert!(ext(2).is_none());
        assert!(!ext(8).unwrap().critical);
        // the extensions this code acts on are listed too, with their critical flags
        let san = leaf.extension(&oid("2.5.29.17")).unwrap();
        assert!(san.critical, "an empty subject makes the subjectAltName critical");
        assert!(!leaf.extension(&oid("2.5.29.37")).unwrap().critical);
        assert_eq!(leaf.extended_key_usage().unwrap(), &[oid(OID_CODE_SIGNING)]);
        assert_eq!(leaf.key_usage_bits(), Some(KU_DIGITAL_SIGNATURE));
        let oids: Vec<String> = leaf.extensions().iter().map(|e| e.oid_string()).collect();
        assert_eq!(oids[0], "2.5.29.15");
        assert!(oids.contains(&"1.3.6.1.4.1.57264.1.14".to_string()));

        let email = Certificate::from_der(&fixture!("cs_leaf_email")).unwrap();
        assert_eq!(email.email_addresses().collect::<Vec<_>>(), vec!["dev@example.test"]);
        assert_eq!(email.uris().count(), 0);
        let other = Certificate::from_der(&fixture!("cs_leaf_other")).unwrap();
        assert_eq!(
            other.subject_alt_names(),
            &[GeneralName::Other { type_id: oid("1.3.6.1.4.1.57264.1.7"), value: b"\x0c\x05alice".to_vec() }]
        );
    }

    #[test]
    fn subject_alt_names_of_every_kind_are_kept_in_order() {
        let c = Certificate::from_der(&fixture!("cs_leaf_names")).unwrap();
        let names = c.subject_alt_names();
        assert_eq!(names.len(), 8);
        assert_eq!(names[0], GeneralName::Dns("host.example.test".to_string())); // lower-cased
        assert_eq!(names[1], GeneralName::Ip(vec![192, 0, 2, 7]));
        assert_eq!(names[2], GeneralName::Ip(vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(names[3], GeneralName::Email("Dev@Example.test".to_string())); // as written
        assert_eq!(names[4], GeneralName::Uri("https://example.test/a?b#c".to_string()));
        match &names[5] {
            GeneralName::Directory(name) => assert_eq!(describe_name(name), "O=Some Org, CN=Some Person"),
            other => panic!("{:?}", other),
        }
        assert!(matches!(&names[6], GeneralName::Other { type_id, .. } if *type_id == oid("1.3.6.1.4.1.57264.1.7")));
        assert_eq!(names[7], GeneralName::RegisteredId(oid("1.2.3.4.5")));
        // the fields TLS host name matching uses are unchanged
        assert_eq!(c.dns_names, vec!["host.example.test"]);
        assert_eq!(c.ip_addrs.len(), 2);
        assert!(c.matches_hostname("HOST.example.test") && c.matches_hostname("192.0.2.7"));
    }

    #[test]
    fn the_purpose_has_to_be_allowed_by_the_leaf_and_by_every_ca() {
        let ts = fulcio_store();
        // a leaf for TLS servers under a code-signing intermediate
        let tls = [fixture!("cs_leaf_tls"), fixture!("cs_inter")];
        let msg = err_text(ts.verify_chain(&tls, &code_signing(SIGNED_AT)));
        assert!(msg.contains("leaf certificate is not valid for code signing"), "{}", msg);
        // ...which is not a TLS CA either, though the leaf is fine for TLS
        let server = VerifyOptions::tls_server("tls-only.example.test", SIGNED_AT);
        let msg = err_text(ts.verify_chain(&tls, &server));
        assert!(msg.contains("issuing certificate is not valid for TLS server authentication"), "{}", msg);
        // no purpose, no objection
        ts.verify_chain(&tls, &VerifyOptions::new(Purpose::Any, SIGNED_AT)).unwrap();
        // an anyExtendedKeyUsage leaf is acceptable for any purpose its CAs allow
        let any = [fixture!("cs_leaf_anyeku"), fixture!("cs_inter")];
        ts.verify_chain(&any, &code_signing(SIGNED_AT)).unwrap();
        assert!(ts.verify_chain(&any, &VerifyOptions::new(Purpose::TimeStamping, SIGNED_AT)).is_err());
        // an OID of the caller's choosing
        let a = store(&[fixture!("as_root")]);
        let chain = [fixture!("as_leaf"), fixture!("as_inter")];
        let lifetime = Purpose::Oid(oid("1.3.6.1.4.1.311.10.3.13"));
        let msg = err_text(a.verify_chain(&chain, &VerifyOptions::new(lifetime.clone(), 1_685_577_600)));
        // the leaf allows it but the intermediate lists only code signing
        assert!(msg.contains("issuing certificate is not valid for extended key usage 1.3.6.1.4.1.311.10.3.13"), "{}", msg);
        assert!(err_text(a.verify_chain(&chain, &VerifyOptions::new(Purpose::Oid(oid("1.3.6.1.4.1.311.10.3.14")), 1_685_577_600)))
            .contains("leaf certificate is not valid for extended key usage 1.3.6.1.4.1.311.10.3.14"));
        // TLS server authentication needs a host name, whatever else is in order
        let msg = err_text(ts.verify_chain(&tls, &VerifyOptions::new(Purpose::ServerAuth, SIGNED_AT)));
        assert!(msg.contains("a host name is required"), "{}", msg);
    }

    #[test]
    fn a_leaf_without_extended_key_usage_must_name_the_purpose_unless_told_otherwise() {
        let ts = fulcio_store();
        let chain = [fixture!("cs_leaf_noeku"), fixture!("cs_inter")];
        let msg = err_text(ts.verify_chain(&chain, &code_signing(SIGNED_AT)));
        assert!(msg.contains("leaf certificate has no extendedKeyUsage, which must name code signing"), "{}", msg);
        let mut lenient = code_signing(SIGNED_AT);
        lenient.allow_missing_leaf_eku = true;
        ts.verify_chain(&chain, &lenient).unwrap();
        ts.verify_chain(&chain, &VerifyOptions::new(Purpose::Any, SIGNED_AT)).unwrap();
    }

    #[test]
    fn the_leaf_key_usage_must_fit_the_purpose() {
        let ts = fulcio_store();
        let chain = [fixture!("cs_leaf_noku"), fixture!("cs_inter")];
        let msg = err_text(ts.verify_chain(&chain, &code_signing(SIGNED_AT)));
        assert!(msg.contains("keyUsage does not permit digitalSignature"), "{}", msg);
        // S/MIME: nonRepudiation is as good as digitalSignature for signing; TLS client auth needs the latter
        let em = store(&[fixture!("em_root")]);
        let both = [fixture!("em_leaf")];
        let nr = [fixture!("em_leaf_nr")];
        let email = |t| VerifyOptions::new(Purpose::EmailProtection, t);
        let client = |t| VerifyOptions::new(Purpose::ClientAuth, t);
        em.verify_chain(&both, &email(NOW)).unwrap();
        em.verify_chain(&both, &client(NOW)).unwrap();
        em.verify_chain(&nr, &email(NOW)).unwrap();
        let msg = err_text(em.verify_chain(&nr, &client(NOW)));
        assert!(msg.contains("keyUsage does not permit digitalSignature"), "{}", msg);
        // no purpose still means a leaf that can sign, by either of the two usages
        em.verify_chain(&nr, &VerifyOptions::new(Purpose::Any, NOW)).unwrap();
    }

    #[test]
    fn a_time_stamping_chain_with_a_critical_eku() {
        let ts = store(&[fixture!("ts_root")]);
        let chain = [fixture!("ts_leaf")];
        let stamping = |t| VerifyOptions::new(Purpose::TimeStamping, t);
        let ok = ts.verify_chain(&chain, &stamping(NOW)).unwrap();
        // RFC 3161 asks for the extension to be critical; whether it is, is for the caller to see
        let eku = ok.leaf.extension(&oid("2.5.29.37")).unwrap();
        assert!(eku.critical);
        assert_eq!(ok.leaf.extended_key_usage().unwrap(), &[oid("1.3.6.1.5.5.7.3.8")]);
        assert!(err_text(ts.verify_chain(&chain, &code_signing(NOW))).contains("not valid for code signing"));
        assert!(err_text(ts.verify_chain(&chain, &stamping(1_640_995_199))).contains("not yet valid"));
        // the authority's certificate was valid for ten years from 2022, which is what a stamp
        // made in 2024 is checked against even in 2035
        assert!(ts.verify_chain(&chain, &stamping(1_700_000_000)).is_ok());
        assert!(err_text(ts.verify_chain(&chain, &stamping(2_050_000_000))).contains("has expired"));
    }

    #[test]
    fn an_authenticode_style_rsa_chain_is_valid_for_when_it_signed() {
        let ts = store(&[fixture!("as_root")]);
        let chain = [fixture!("as_leaf"), fixture!("as_inter")];
        let june_2023 = 1_685_577_600;
        let ok = ts.verify_chain(&chain, &code_signing(june_2023)).unwrap();
        assert!(ok.leaf.subject_summary().contains("Example Software Inc"));
        assert!(matches!(ok.leaf.public_key, PublicKey::Rsa(_)));
        assert_eq!(ok.path.len(), 3);
        // the certificate has expired by now, which is why the validation time is a parameter
        assert!(err_text(ts.verify_chain(&chain, &code_signing(NOW))).contains("has expired [C=US, O=Example Software Inc, CN=Example Software Inc]"));
        assert!(err_text(ts.verify_chain(&chain, &code_signing(1_640_995_200))).contains("not yet valid"));
        // lifetime signing and code signing both listed on the leaf
        assert_eq!(ok.leaf.extended_key_usage().unwrap().len(), 2);
        // the same hierarchy's TLS certificate cannot sign code, and its CA is not a TLS CA
        let tls = [fixture!("as_leaf_tls"), fixture!("as_inter")];
        assert!(err_text(ts.verify_chain(&tls, &code_signing(NOW))).contains("not valid for code signing"));
        let server = VerifyOptions::tls_server("tls.example.test", NOW);
        assert!(err_text(ts.verify_chain(&tls, &server)).contains("issuing certificate is not valid for TLS server authentication"));
        // an RSA key under the floor is refused whatever the purpose
        let strict = store(&[fixture!("as_root")]).with_min_rsa_bits(3072);
        assert!(err_text(strict.verify_chain(&chain, &code_signing(june_2023))).contains("2048 bits is below the minimum of 3072"));
    }

    #[test]
    fn the_anchors_are_the_stores_alone() {
        let chain = [fixture!("cs_leaf_workflow"), fixture!("cs_inter")];
        let wrong = store(&[fixture!("as_root"), fixture!("ts_root")]);
        let msg = err_text(wrong.verify_chain(&chain, &code_signing(SIGNED_AT)));
        assert!(msg.contains("neither a trusted root nor sent"), "{}", msg);
        // an empty store trusts nothing
        assert!(TrustStore::empty().verify_chain(&chain, &code_signing(SIGNED_AT)).is_err());
        // several anchors: the one that matches is used
        let both = store(&[fixture!("as_root"), fixture!("cs_root"), fixture!("ts_root")]);
        assert_eq!(both.verify_chain(&chain, &code_signing(SIGNED_AT)).unwrap().anchor(), &fixture!("cs_root")[..]);
        // junk among the chain is ignored, as for TLS
        let junk = [fixture!("cs_leaf_workflow"), b"not a certificate".to_vec(), fixture!("cs_inter")];
        both.verify_chain(&junk, &code_signing(SIGNED_AT)).unwrap();
        assert!(both.verify_chain::<Vec<u8>>(&[], &code_signing(SIGNED_AT)).is_err());
    }

    #[test]
    fn a_critical_extension_nobody_interprets_refuses_the_chain_unless_the_caller_does() {
        let ts = fulcio_store();
        let chain = [fixture!("cs_leaf_critical"), fixture!("cs_inter")];
        let private = oid("1.3.6.1.4.1.99999.1");
        // parsing a certificate on its own refuses it, as before
        assert!(Certificate::from_der(&fixture!("cs_leaf_critical")).is_err());
        let msg = err_text(ts.verify_chain(&chain, &code_signing(SIGNED_AT)));
        assert!(msg.contains("unrecognized critical extension 1.3.6.1.4.1.99999.1 in ["), "{}", msg);
        // a caller that says it interprets that extension gets the chain, and can read the extension
        let ok = ts.verify_chain(&chain, &code_signing(SIGNED_AT).with_critical_extension(&private)).unwrap();
        let ext = ok.leaf.extension(&private).unwrap();
        assert!(ext.critical);
        assert_eq!(ext.der_string().as_deref(), Some("private"));
        // naming some other extension does not help
        assert!(ts.verify_chain(&chain, &code_signing(SIGNED_AT).with_critical_extension(&oid("1.2.3"))).is_err());
        // TLS never accepts it
        let msg = err_text(ts.verify_server_chain(&chain, "x.test", SIGNED_AT));
        assert!(msg.contains("unrecognized critical extension"), "{}", msg);
    }

    #[test]
    fn name_constraints_cover_email_uri_and_ip_names() {
        let ts = fulcio_store();
        let check = |leaf: Vec<u8>| ts.verify_chain(&[leaf, fixture!("cs_inter_nc")], &code_signing(NOW));
        let ok = check(fixture!("cs_nc_ok")).unwrap();
        assert_eq!(ok.leaf.subject_alt_names().len(), 4);
        // a name of a kind the CA does not constrain is not affected
        check(fixture!("cs_nc_other_kind")).unwrap();
        for (leaf, expect) in [
            ("cs_nc_bad_email", "e-mail address \"dev@evil.test\" is not permitted by name constraints of"),
            ("cs_nc_bad_email_sub", "e-mail address \"dev@sub.example.test\" is not permitted by name constraints of"),
            ("cs_nc_excluded_email", "e-mail address \"banned@example.test\" is excluded by a name constraint of"),
            ("cs_nc_bad_uri", "URI \"https://evil.test/x\" is not permitted by name constraints of"),
            ("cs_nc_bad_uri_sub", "URI \"https://api.github.com/x\" is not permitted by name constraints of"),
            ("cs_nc_bad_ip", "IP address 198.51.100.1 is not permitted by name constraints of"),
            ("cs_nc_excluded_dns", "DNS name \"bad.example.test\" is excluded by a name constraint of"),
        ] {
            let der = match leaf {
                "cs_nc_bad_email" => fixture!("cs_nc_bad_email"),
                "cs_nc_bad_email_sub" => fixture!("cs_nc_bad_email_sub"),
                "cs_nc_excluded_email" => fixture!("cs_nc_excluded_email"),
                "cs_nc_bad_uri" => fixture!("cs_nc_bad_uri"),
                "cs_nc_bad_uri_sub" => fixture!("cs_nc_bad_uri_sub"),
                "cs_nc_bad_ip" => fixture!("cs_nc_bad_ip"),
                _ => fixture!("cs_nc_excluded_dns"),
            };
            let msg = err_text(check(der));
            assert!(msg.contains(expect), "{}: {}", leaf, msg);
            assert!(msg.contains("CN=Fulcio-profile Constrained Intermediate"), "{}", msg);
        }
    }

    #[test]
    fn a_constraint_of_a_kind_that_is_not_evaluated_refuses_names_of_that_kind_only() {
        let ts = fulcio_store();
        let under = |leaf: Vec<u8>| ts.verify_chain(&[leaf, fixture!("cs_inter_nc_other")], &code_signing(NOW));
        let msg = err_text(under(fixture!("cs_nco_other")));
        assert!(msg.contains("under a name constraint of a kind that is not supported"), "{}", msg);
        // an e-mail name under a CA whose only constraint is on otherNames is not constrained at all
        under(fixture!("cs_nco_email")).unwrap();
    }

    #[test]
    fn name_constraint_matching_rules() {
        // e-mail: a mailbox, a host, or the subdomains of a domain
        assert!(email_constraint_matches("a@example.com", "a@example.com"));
        assert!(email_constraint_matches("a@example.com", "a@EXAMPLE.com"));
        assert!(!email_constraint_matches("a@example.com", "A@example.com"));
        assert!(email_constraint_matches("example.com", "x@example.com"));
        assert!(!email_constraint_matches("example.com", "x@sub.example.com"));
        assert!(email_constraint_matches(".example.com", "x@sub.example.com"));
        assert!(!email_constraint_matches(".example.com", "x@example.com"));
        assert!(!email_constraint_matches(".example.com", "x@badexample.com"));
        assert!(!email_constraint_matches("example.com", "no-at-sign"));
        // URI: the host, exactly, or the subdomains of a domain
        assert_eq!(uri_host("https://user:pw@Example.com:8443/p?q#f"), Some("Example.com"));
        assert_eq!(uri_host("https://example.com"), Some("example.com"));
        assert_eq!(uri_host("https://example.com?x"), Some("example.com"));
        assert_eq!(uri_host("https://192.0.2.1/x"), None);
        assert_eq!(uri_host("https://[2001:db8::1]/x"), None);
        assert_eq!(uri_host("mailto:a@example.com"), None);
        assert_eq!(uri_host("urn:isbn:1"), None);
        assert!(uri_host_matches("example.com", "EXAMPLE.com"));
        assert!(!uri_host_matches("example.com", "www.example.com"));
        assert!(uri_host_matches(".example.com", "www.example.com"));
        assert!(!uri_host_matches(".example.com", "example.com"));
        // IP: address and mask
        let net = [192, 0, 2, 0, 255, 255, 255, 0];
        assert!(ip_constraint_matches(&net, &[192, 0, 2, 255]));
        assert!(!ip_constraint_matches(&net, &[192, 0, 3, 1]));
        assert!(!ip_constraint_matches(&net, &[0u8; 16])); // an IPv6 address is not in an IPv4 range
        assert!(ip_constraint_matches(&[0u8; 8], &[10, 1, 2, 3])); // 0.0.0.0/0
        // a trailing dot does not get a name past a constraint
        let covers = |c: Constraint, n: GeneralName| constraint_covers(&c, &n);
        assert_eq!(covers(Constraint::Dns("bad.example.test".into()), GeneralName::Dns("bad.example.test.".into())), Some(true));
        assert_eq!(covers(Constraint::Email("example.test".into()), GeneralName::Email("x@example.test.".into())), Some(true));
        assert_eq!(covers(Constraint::Uri("github.com".into()), GeneralName::Uri("https://github.com./x".into())), Some(true));
        assert_eq!(covers(Constraint::Uri("github.com".into()), GeneralName::Uri("https://github.com.evil.test/x".into())), Some(false));
        // and a constraint of one kind says nothing about a name of another
        assert_eq!(covers(Constraint::Dns("example.test".into()), GeneralName::Email("x@example.test".into())), None);
        assert_eq!(covers(Constraint::Unsupported(0xa4), GeneralName::Dns("example.test".into())), None);
    }

    // The signing certificate of the npm provenance attestation of lazaret 0.1.8: real, from Sigstore's
    // public-good Fulcio, and the bundle it came from (tests/data/real_lazaret_0_1_8.sigstore.json).
    const LAZARET_BUNDLE: &str = include_str!("../tests/data/real_lazaret_0_1_8.sigstore.json");
    /// Rekor's integratedTime for it: 2026-10-03 19:30:27 UTC, one second into the certificate's ten minutes.
    const LAZARET_LOGGED_AT: i64 = 1_791_055_827;
    const LAZARET_WORKFLOW: &str = "https://github.com/lazaret-dev/lazaret/.github/workflows/release.yml@refs/tags/v0.1.8";

    #[test]
    fn a_real_fulcio_leaf_verifies_at_the_time_it_was_logged_and_says_where_it_was_built() {
        let leaf_der = fixture!("fulcio_real_leaf");
        // the fixture is the certificate in the bundle it came from, and the bundle says when it was logged
        assert!(LAZARET_BUNDLE.contains(&pem::base64_encode(&leaf_der)));
        assert!(LAZARET_BUNDLE.contains(&format!("\"integratedTime\": \"{}\"", LAZARET_LOGGED_AT)));

        let ts = store(&[fixture!("fulcio_real_root")]);
        let chain = [leaf_der.clone(), fixture!("fulcio_real_inter")];
        let ok = ts.verify_chain(&chain, &code_signing(LAZARET_LOGGED_AT)).unwrap();
        assert_eq!(ok.path, vec![leaf_der.clone(), fixture!("fulcio_real_inter"), fixture!("fulcio_real_root")]);
        // ten minutes of validity, 19:30:26 to 19:40:26: neither a second before nor a second after
        let (from, to) = (LAZARET_LOGGED_AT - 1, LAZARET_LOGGED_AT + 599);
        assert_eq!((ok.leaf.not_before, ok.leaf.not_after), (from, to));
        ts.verify_chain(&chain, &code_signing(from)).unwrap();
        ts.verify_chain(&chain, &code_signing(to)).unwrap();
        assert!(err_text(ts.verify_chain(&chain, &code_signing(from - 1))).contains("not yet valid"));
        assert!(err_text(ts.verify_chain(&chain, &code_signing(to + 1))).contains("has expired"));
        // the certificate did not exist yet when the other tests' clock (NOW) was set
        assert!(err_text(ts.verify_chain(&chain, &code_signing(NOW))).contains("not yet valid"));
        // the intermediate alone is a fine anchor, and the wrong anchors are not
        let by_inter = store(&[fixture!("fulcio_real_inter")]);
        assert_eq!(by_inter.verify_chain(&[leaf_der.clone()], &code_signing(LAZARET_LOGGED_AT)).unwrap().path.len(), 2);
        let wrong = store(&[fixture!("cs_root"), fixture!("as_root")]);
        assert!(err_text(wrong.verify_chain(&chain, &code_signing(LAZARET_LOGGED_AT))).contains("neither a trusted root nor sent"));
        // it is for code signing and nothing else
        let msg = err_text(ts.verify_chain(&chain, &VerifyOptions::new(Purpose::TimeStamping, LAZARET_LOGGED_AT)));
        assert!(msg.contains("leaf certificate is not valid for time stamping"), "{}", msg);
        let msg = err_text(ts.verify_chain(&chain, &VerifyOptions::new(Purpose::EmailProtection, LAZARET_LOGGED_AT)));
        assert!(msg.contains("leaf certificate is not valid for e-mail protection"), "{}", msg);
        // any bit of it changed, and it is not the certificate that was signed
        let mut bad = leaf_der.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(ts.verify_chain(&[bad, fixture!("fulcio_real_inter")], &code_signing(LAZARET_LOGGED_AT)).is_err());

        // what Fulcio put in it: an empty subject and the workflow as a critical subjectAltName URI
        let leaf = &ok.leaf;
        assert_eq!(leaf.subject_der, [0x30, 0x00]);
        assert!(matches!(&leaf.public_key, PublicKey::Ec { curve: Curve::P256, .. }));
        assert_eq!(leaf.subject_alt_names(), &[GeneralName::Uri(LAZARET_WORKFLOW.to_string())]);
        assert_eq!(leaf.uris().collect::<Vec<_>>(), vec![LAZARET_WORKFLOW]);
        assert!(leaf.extension(&oid("2.5.29.17")).unwrap().critical);
        assert_eq!(leaf.key_usage_bits(), Some(KU_DIGITAL_SIGNATURE));
        assert_eq!(leaf.extended_key_usage().unwrap(), &[oid(OID_CODE_SIGNING)]);
        // ...and the claims, under 1.3.6.1.4.1.57264.1: the first six are raw text, the rest DER strings
        let ext = |n: u32| leaf.extension(&oid(&format!("1.3.6.1.4.1.57264.1.{}", n))).unwrap_or_else(|| panic!("no extension .1.{}", n));
        let sha = "562f28618a0c20381f07dffa258391b866f7836e";
        let raw: [(u32, &str); 6] = [
            (1, GITHUB_ISSUER),
            (2, "push"),
            (3, sha),
            (4, "Release"),
            (5, "lazaret-dev/lazaret"),
            (6, "refs/tags/v0.1.8"),
        ];
        for (n, want) in raw {
            assert_eq!(ext(n).value, want.as_bytes(), ".1.{}", n);
            assert_eq!(ext(n).der_string(), None, ".1.{}", n);
        }
        let der_strings: [(u32, &str); 17] = [
            (8, GITHUB_ISSUER),
            (9, LAZARET_WORKFLOW),
            (10, sha),
            (11, "github-hosted"),
            (12, "https://github.com/lazaret-dev/lazaret"),
            (13, sha),
            (14, "refs/tags/v0.1.8"),
            (15, "1386943603"),
            (16, "https://github.com/lazaret-dev"),
            (17, "333496726"),
            (18, LAZARET_WORKFLOW),
            (19, sha),
            (20, "push"),
            (21, "https://github.com/lazaret-dev/lazaret/actions/runs/37144612030/attempts/1"),
            (22, "public"),
            (23, "npm"),
            (24, "repo:lazaret-dev@333496726/lazaret@1386943603:environment:npm"),
        ];
        for (n, want) in der_strings {
            assert_eq!(ext(n).der_string().as_deref(), Some(want), ".1.{}", n);
            assert!(!ext(n).critical);
        }
        assert!(leaf.extension(&oid("1.3.6.1.4.1.57264.1.7")).is_none());
        // every extension is kept: keyUsage, EKU, SKI, AKI, SAN, the 23 claims and the SCT list
        assert_eq!(leaf.extensions().len(), 29);
        assert!(!leaf.extension(&oid("1.3.6.1.4.1.11129.2.4.2")).unwrap().critical);
    }

    #[test]
    fn a_real_apple_code_signing_chain_is_valid_when_it_signed_and_not_now() {
        // From a Mac App Store application (codesign -d --extract-certificates): Apple's "Apple Mac OS
        // Application Signing" leaf, the WWDR G5 intermediate and the Apple Root CA. No signing time
        // is recorded in such a signature, so the times below are only inside or outside the leaf's years.
        let leaf_der = fixture!("apple_mas_leaf");
        let ts = store(&[fixture!("apple_root_ca")]);
        let chain = [leaf_der.clone(), fixture!("apple_wwdr_g5")];
        let (from, to) = (1_720_826_167, 1_786_490_166); // 2024-07-12 23:16:07 and 2026-08-11 23:16:06 UTC
        let ok = ts.verify_chain(&chain, &code_signing(1_748_736_000)).unwrap(); // 2025-06-01
        assert_eq!(ok.path, vec![leaf_der.clone(), fixture!("apple_wwdr_g5"), fixture!("apple_root_ca")]);
        assert_eq!((ok.leaf.not_before, ok.leaf.not_after), (from, to));
        ts.verify_chain(&chain, &code_signing(from)).unwrap();
        ts.verify_chain(&chain, &code_signing(to)).unwrap();
        assert!(err_text(ts.verify_chain(&chain, &code_signing(from - 1))).contains("not yet valid"));
        // it has expired by the clock the other tests use (2026-09-15), which is why the time is a parameter
        let msg = err_text(ts.verify_chain(&chain, &code_signing(NOW)));
        assert!(msg.contains("has expired [CN=Apple Mac OS Application Signing, O=Apple Inc., C=US]"), "{}", msg);
        // the leaf's own profile: RSA, a critical EKU naming code signing, a critical keyUsage, not a CA
        let leaf = &ok.leaf;
        assert!(matches!(leaf.public_key, PublicKey::Rsa(_)));
        assert_eq!(leaf.extended_key_usage().unwrap(), &[oid(OID_CODE_SIGNING)]);
        assert!(leaf.extension(&oid("2.5.29.37")).unwrap().critical);
        assert_eq!(leaf.key_usage_bits(), Some(KU_DIGITAL_SIGNATURE));
        assert!(!leaf.is_ca && leaf.extension(&oid("2.5.29.19")).unwrap().critical);
        assert!(leaf.subject_alt_names().is_empty());
        // Apple's own non-critical extensions are kept and readable (a DER NULL), and do not get in the way
        for (cert, id) in [(leaf, "1.2.840.113635.100.6.1.9")] {
            let e = cert.extension(&oid(id)).unwrap();
            assert!(!e.critical);
            assert_eq!(e.value, [0x05, 0x00]);
        }
        let wwdr = Certificate::from_der(&fixture!("apple_wwdr_g5")).unwrap();
        assert_eq!(wwdr.extension(&oid("1.2.840.113635.100.6.2.1")).unwrap().value, [0x05, 0x00]);
        assert!(wwdr.is_ca && wwdr.path_len == Some(0));
        assert_eq!(leaf.crl_uris, vec!["http://crl.apple.com/wwdrg5.crl"]);
        assert_eq!(wwdr.crl_uris, vec!["http://crl.apple.com/root.crl"]);
        // purposes: any is fine; the EKU rules out everything else
        ts.verify_chain(&chain, &VerifyOptions::new(Purpose::Any, 1_748_736_000)).unwrap();
        let msg = err_text(ts.verify_chain(&chain, &VerifyOptions::new(Purpose::TimeStamping, 1_748_736_000)));
        assert!(msg.contains("leaf certificate is not valid for time stamping"), "{}", msg);
        // the RSA floor applies to the leaf and the intermediate, not to the anchor
        let strict = store(&[fixture!("apple_root_ca")]).with_min_rsa_bits(3072);
        assert!(err_text(strict.verify_chain(&chain, &code_signing(1_748_736_000))).contains("2048 bits is below the minimum of 3072"));
        // the root is self-issued with SHA-1, which is refused as a signature but irrelevant to an anchor
        let root = Certificate::from_der(&fixture!("apple_root_ca")).unwrap();
        assert!(err_text(root.verify_signed_by(&root)).contains("unsupported certificate signature algorithm"));
        // another vendor's anchors do not do
        let other = store(&[fixture!("fulcio_real_root"), fixture!("as_root")]);
        assert!(err_text(other.verify_chain(&chain, &code_signing(1_748_736_000))).contains("neither a trusted root nor sent"));
    }

    #[test]
    fn the_real_fulcio_root_and_intermediate() {
        // Sigstore's public-good CA certificates, copied from its TUF repository: see the comments in the files
        let root = Certificate::from_der(&fixture!("fulcio_real_root")).unwrap();
        let inter = Certificate::from_der(&fixture!("fulcio_real_inter")).unwrap();
        assert_eq!(root.subject_summary(), "O=sigstore.dev, CN=sigstore");
        assert_eq!(inter.subject_summary(), "O=sigstore.dev, CN=sigstore-intermediate");
        assert_eq!(inter.issuer_summary(), root.subject_summary());
        assert!(matches!(&root.public_key, PublicKey::Ec { curve: Curve::P384, .. }));
        root.verify_signed_by(&root).unwrap();
        inter.verify_signed_by(&root).unwrap();
        assert!(root.verify_signed_by(&inter).is_err());
        assert!(inter.verify_signed_by(&inter).is_err());
        // what makes the intermediate a code-signing CA, and nothing else
        assert!(inter.is_ca && inter.path_len == Some(0));
        assert_eq!(inter.key_usage_bits(), Some(KU_KEY_CERT_SIGN | KU_CRL_SIGN));
        assert_eq!(inter.extended_key_usage().unwrap(), &[oid(OID_CODE_SIGNING)]);
        assert!(inter.extension(&oid("2.5.29.19")).unwrap().critical);
        assert!(inter.extension(&oid("2.5.29.15")).unwrap().critical);
        assert!(!inter.extension(&oid("2.5.29.37")).unwrap().critical);
        assert_eq!((inter.not_before, inter.not_after), (1_649_880_375, 1_948_975_018));
        assert_eq!((root.not_before, root.not_after), (1_633_615_019, 1_948_975_018));
        assert!(root.extended_key_usage().is_none());
        // through the chain code: the root's signature on the intermediate is checked on the way, and
        // then a CA certificate is not acceptable as the signing certificate itself
        let ts = store(&[fixture!("fulcio_real_root")]);
        let msg = err_text(ts.verify_chain(&[fixture!("fulcio_real_inter")], &VerifyOptions::new(Purpose::Any, 1_700_000_000)));
        assert!(msg.contains("keyUsage does not permit digitalSignature or nonRepudiation") && msg.contains("sigstore-intermediate"), "{}", msg);
        let msg = err_text(ts.verify_chain(&[fixture!("fulcio_real_inter")], &VerifyOptions::new(Purpose::Any, 1_640_995_200)));
        assert!(msg.contains("not yet valid [O=sigstore.dev, CN=sigstore-intermediate]"), "{}", msg);
    }

    // ---------------------------------------------------------------- Ed25519 (RFC 8410)

    fn is_ed25519(c: &Certificate) -> bool {
        matches!(c.public_key, PublicKey::Ed25519(_))
    }

    #[test]
    fn an_all_ed25519_chain_verifies() {
        let ts = store(&[fixture!("ed_root")]);
        let chain = vec![fixture!("ed_leaf"), fixture!("ed_inter")];
        let leaf = ts.verify_server_chain(&chain, "ed.example.test", NOW).unwrap();
        assert!(is_ed25519(&leaf));
        assert_eq!(leaf.sig_alg, Some(SigAlg::Ed25519));
        assert!(is_ed25519(&Certificate::from_der(&fixture!("ed_inter")).unwrap()));
        assert!(is_ed25519(&Certificate::from_der(&fixture!("ed_root")).unwrap()));
        // the same through the purpose-parameterized entry point
        let opts = VerifyOptions::tls_server("ed.example.test", NOW);
        let verified = ts.verify_chain(&chain, &opts).unwrap();
        assert_eq!(verified.path.len(), 3);
        // the wrong name, the wrong time and a missing intermediate are still refused
        assert!(ts.verify_server_chain(&chain, "other.example.test", NOW).is_err());
        assert!(ts.verify_server_chain(&chain, "ed.example.test", 1_500_000_000).is_err());
        assert!(ts.verify_server_chain(&chain[..1], "ed.example.test", NOW).is_err());
    }

    #[test]
    fn ed25519_and_other_keys_mix_in_one_chain() {
        // a P-256 leaf under an Ed25519 intermediate under an Ed25519 root
        let ts = store(&[fixture!("ed_root")]);
        let chain = vec![fixture!("ed_leaf_p256"), fixture!("ed_inter")];
        let leaf = ts.verify_server_chain(&chain, "ed.example.test", NOW).unwrap();
        assert!(matches!(leaf.public_key, PublicKey::Ec { curve: Curve::P256, .. }));
        assert_eq!(leaf.sig_alg, Some(SigAlg::Ed25519));
        // an Ed25519 leaf under a P-256 root
        let ts = store(&[fixture!("ed_ec_root")]);
        let leaf = ts.verify_server_chain(&[fixture!("ed_leaf_by_ec")], "ed.example.test", NOW).unwrap();
        assert!(is_ed25519(&leaf));
        assert!(matches!(leaf.sig_alg, Some(SigAlg::Ecdsa(HashAlg::Sha256))));
    }

    #[test]
    fn ed25519_signatures_are_checked() {
        let ts = store(&[fixture!("ed_root")]);
        let inter = fixture!("ed_inter");
        // the last byte of a certificate is the last byte of its signature
        let mut damaged = fixture!("ed_leaf");
        *damaged.last_mut().unwrap() ^= 1;
        let msg = err_text(ts.verify_server_chain(&[damaged, inter.clone()], "ed.example.test", NOW));
        assert!(msg.contains("signature"), "{}", msg);
        // a change inside the signed part that nothing else looks at: the CRL distribution point's host
        let mut edited = fixture!("ed_leaf");
        let at = edited.windows(16).position(|w| w == b"crl.example.test").unwrap();
        edited[at] = b'C';
        let msg = err_text(ts.verify_server_chain(&[edited, inter.clone()], "ed.example.test", NOW));
        assert!(msg.contains("signature"), "{}", msg);
        // a certificate signed by another Ed25519 key, under the right issuer name
        let other = store(&[fixture!("ed_ec_root")]);
        assert!(other.verify_server_chain(&[fixture!("ed_leaf"), inter.clone()], "ed.example.test", NOW).is_err());
        assert!(ts.verify_server_chain(&[fixture!("ed_leaf_by_ec"), inter], "ed.example.test", NOW).is_err());
        let ed_leaf = Certificate::from_der(&fixture!("ed_leaf")).unwrap();
        let ed_root = Certificate::from_der(&fixture!("ed_root")).unwrap();
        let ed_inter = Certificate::from_der(&fixture!("ed_inter")).unwrap();
        ed_leaf.verify_signed_by(&ed_inter).unwrap();
        ed_inter.verify_signed_by(&ed_root).unwrap();
        assert!(ed_leaf.verify_signed_by(&ed_root).is_err(), "the root did not sign the leaf");
        assert!(ed_root.verify_signed_by(&ed_inter).is_err());
    }

    // ---- B-34: names (tools/gen_name_fixtures.py) and host names

    /// A Name of RDNs, each a list of (attribute type's last OID byte under 2.5.4, string tag, value).
    fn name_der(rdns: &[&[(u8, u8, &[u8])]]) -> Vec<u8> {
        let sets: Vec<u8> = rdns
            .iter()
            .flat_map(|atvs| {
                let inner: Vec<u8> = atvs.iter().flat_map(|&(t, tag, v)| tlv(0x30, &[tlv(0x06, &[0x55, 0x04, t]), tlv(tag, v)].concat())).collect();
                tlv(0x31, &inner)
            })
            .collect();
        tlv(0x30, &sets)
    }

    #[test]
    fn names_compare_as_rfc_5280_and_openssl_compare_them() {
        const CN: u8 = 3;
        const O: u8 = 10;
        const OU: u8 = 11;
        let same = |a: &[u8], b: &[u8]| canonical_name(a).unwrap() == canonical_name(b).unwrap();
        let base = name_der(&[&[(O, 0x13, b"Example Org")], &[(CN, 0x13, b"Test CA")]]);
        // other string types, case, white space at the ends and inside
        let bmp: Vec<u8> = "test ca".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let universal: Vec<u8> = "TEST CA".chars().flat_map(|c| (c as u32).to_be_bytes()).collect();
        for other in [
            name_der(&[&[(O, 0x0c, b"example org")], &[(CN, 0x0c, b"TEST CA")]]),
            name_der(&[&[(O, 0x0c, b"  Example \t\n Org ")], &[(CN, 0x16, b"Test  CA")]]),
            name_der(&[&[(O, 0x14, b"EXAMPLE ORG")], &[(CN, 0x1e, &bmp)]]),
            name_der(&[&[(O, 0x1a, b"Example Org")], &[(CN, 0x1c, &universal)]]),
        ] {
            assert!(same(&base, &other), "{}", describe_name(&other));
        }
        // the order of RDNs matters; the order inside a multi-valued RDN does not
        assert!(!same(&base, &name_der(&[&[(CN, 0x13, b"Test CA")], &[(O, 0x13, b"Example Org")]])));
        assert!(same(&name_der(&[&[(O, 0x0c, b"A"), (OU, 0x0c, b"B")]]), &name_der(&[&[(OU, 0x0c, b"b"), (O, 0x0c, b"a")]])));
        // different text, a missing RDN, an attribute of another type
        for other in [
            name_der(&[&[(O, 0x13, b"Example Org")], &[(CN, 0x13, b"Test CA 2")]]),
            name_der(&[&[(CN, 0x13, b"Test CA")]]),
            name_der(&[&[(OU, 0x13, b"Example Org")], &[(CN, 0x13, b"Test CA")]]),
            name_der(&[&[(O, 0x13, b"ExampleOrg")], &[(CN, 0x13, b"Test CA")]]),
        ] {
            assert!(!same(&base, &other), "{}", describe_name(&other));
        }
        // only ASCII letters are folded (as OpenSSL does): no Unicode case folding, no normalization
        let upper = name_der(&[&[(CN, 0x0c, "Über".as_bytes())]]);
        assert!(same(&upper, &name_der(&[&[(CN, 0x0c, "ÜBER".as_bytes())]])));
        assert!(!same(&upper, &name_der(&[&[(CN, 0x0c, "über".as_bytes())]])));
        assert!(!same(&upper, &name_der(&[&[(CN, 0x0c, "U\u{308}ber".as_bytes())]])));
        // a type that is not text (NumericString) is compared as it is, its tag included
        assert!(!same(&name_der(&[&[(5, 0x12, b"123")]]), &name_der(&[&[(5, 0x13, b"123")]])));
        // what does not decode has no canonical form, and is then compared by its bytes alone
        assert!(canonical_name(&name_der(&[&[(CN, 0x0c, b"\xff\xfe")]])).is_err());
        assert!(canonical_name(&name_der(&[&[(CN, 0x1e, b"\xd8\x00")]])).is_err(), "a lone surrogate in a BMPString");
        assert!(canonical_name(&name_der(&[&[]])).is_err(), "an empty RDN");
        let broken = name_der(&[&[(CN, 0x0c, b"\xff")]]);
        assert_eq!(name_key(&broken), [&[0xff][..], &broken].concat());
        assert_ne!(name_key(&broken), name_key(&name_der(&[&[(CN, 0x0c, b"\xff\xfe")]])));
        // the empty name is a name
        assert_eq!(canonical_name(&[0x30, 0x00]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_chain_whose_names_are_written_differently_is_built_like_openssl_builds_it() {
        let ts = store(&[fixture!("nm_root")]);
        // issuer names that differ from their issuer's subject in string type, case and white space
        let leaf = ts.verify_server_chain(&[fixture!("nm_leaf"), fixture!("nm_inter")], "name.example.test", NOW).unwrap();
        assert_ne!(leaf.issuer_der, Certificate::from_der(&fixture!("nm_inter")).unwrap().subject_der);
        ts.verify_server_chain(&[fixture!("nm_leaf_u_ascii"), fixture!("nm_inter_u")], "name.example.test", NOW).unwrap();
        // Ü is not ü: refused, as OpenSSL refuses it
        let msg = err_text(ts.verify_server_chain(&[fixture!("nm_leaf_u_lower"), fixture!("nm_inter_u")], "name.example.test", NOW));
        assert!(msg.contains("is neither a trusted root nor sent by the server"), "{msg}");
        // a name that matches does not make a signature: a root with the same name and another key is tried and refused,
        // and with both in the store the right one is found
        let twin = store(&[fixture!("nm_root_twin")]);
        let msg = err_text(twin.verify_server_chain(&[fixture!("nm_leaf"), fixture!("nm_inter")], "name.example.test", NOW));
        assert!(msg.contains("signature"), "{msg}");
        let both = store(&[fixture!("nm_root_twin"), fixture!("nm_root")]);
        both.verify_server_chain(&[fixture!("nm_leaf"), fixture!("nm_inter")], "name.example.test", NOW).unwrap();
        // and the bulk loader, which reads only the subject, finds the anchor the same way
        let mut bulk = TrustStore::empty();
        assert_eq!(bulk.add_pem(include_str!("../tests/data/nm_root.pem")), 1);
        bulk.verify_server_chain(&[fixture!("nm_leaf"), fixture!("nm_inter")], "name.example.test", NOW).unwrap();
    }

    #[test]
    fn a_root_programs_limits_on_an_anchor_apply() {
        let chain = [fixture!("nm_leaf"), fixture!("nm_inter")];
        let root = fixture!("nm_root");
        // name constraints imposed on an anchor that has none of its own (NSS does this for a few roots)
        let nc = |dns: &str| tlv(0x30, &tlv(0xa0, &tlv(0x30, &tlv(0x82, dns.as_bytes()))));
        let with = |limits: AnchorLimits| {
            let mut ts = TrustStore::empty();
            ts.add_der_with_limits(&root, &limits).unwrap();
            ts.verify_server_chain(&chain, "name.example.test", NOW)
        };
        with(AnchorLimits { name_constraints: Some(nc(".example.test")), ..Default::default() }).unwrap();
        let msg = err_text(with(AnchorLimits { name_constraints: Some(nc(".tr")), ..Default::default() }));
        assert!(msg.contains("is not permitted by name constraints of") && msg.contains("Name Test Root"), "{msg}");
        // a distrust date: leaves issued after it are refused, at it or before accepted
        let issued = Certificate::from_der(&chain[0]).unwrap().not_before;
        with(AnchorLimits { distrust_after: Some(issued), ..Default::default() }).unwrap();
        let msg = err_text(with(AnchorLimits { distrust_after: Some(issued - 1), ..Default::default() }));
        assert!(msg.contains("after the date") && msg.contains("2020-01-01T00:00:00Z"), "{msg}");
        // both, and nothing
        assert!(with(AnchorLimits { distrust_after: Some(issued), name_constraints: Some(nc(".tr")) }).is_err());
        with(AnchorLimits::default()).unwrap();
        // constraints that do not parse are an error when the anchor is added
        let mut ts = TrustStore::empty();
        assert!(ts.add_der_with_limits(&root, &AnchorLimits { name_constraints: Some(vec![0x30, 0x03, 0x01]), ..Default::default() }).is_err());
        assert!(ts.is_empty());
        // an anchor with name constraints of its own keeps them, and the imposed ones are not added (as in NSS)
        let mut ts = TrustStore::empty();
        ts.add_der_with_limits(&fixture!("cs_inter_nc"), &AnchorLimits { name_constraints: Some(nc(".tr")), ..Default::default() }).unwrap();
        ts.verify_chain(&[fixture!("cs_nc_ok")], &code_signing(NOW)).unwrap();
        assert!(err_text(ts.verify_chain(&[fixture!("cs_nc_bad_ip")], &code_signing(NOW))).contains("not permitted by name constraints"));
        assert_eq!(utc_date(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_date(1_776_297_599), "2026-04-15T23:59:59Z");
        assert_eq!(utc_date(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn host_name_matching_edge_cases() {
        // (SAN pattern, host, matches): RFC 6125 section 6.4 and RFC 9525 section 6.3, and what this library adds
        for (pattern, host, want) in [
            ("example.com", "example.com", true),
            ("example.com", "EXAMPLE.COM", true),
            ("example.com.", "example.com", true),
            ("*.example.com", "a.example.com", true),
            ("*.example.com", "A.Example.Com", true),
            ("*.example.com", "xn--bcher-kva.example.com", true),
            ("*.example.com", "example.com", false),
            ("*.example.com", ".example.com", false),
            ("*.example.com", "a.b.example.com", false),
            ("*.example.com", "aexample.com", false),
            ("*.example.com", "a.example.com.evil", false),
            ("*.com", "example.com", false),
            ("*", "example", false),
            ("*.*.example.com", "a.b.example.com", false),
            ("a*.example.com", "ab.example.com", false),
            ("*a.example.com", "ba.example.com", false),
            ("xn--*.example.com", "xn--bcher-kva.example.com", false),
            ("a.*.example.com", "a.b.example.com", false),
            ("example.com", "example.com.evil", false),
            ("example.com", "www.example.com", false),
            ("www.example.com", "example.com", false),
            ("", "example.com", false),
            ("example.com", "", false),
            ("bücher.example", "bücher.example", false),
        ] {
            assert_eq!(dns_pattern_matches(pattern, &normalize_host(host)), want, "{pattern:?} for {host:?}");
        }
        // an IP address is matched against iPAddress names only, and only in the same family
        let mut ip_leaf = Certificate::from_der(&fixture!("leaf_p384")).unwrap();
        ip_leaf.dns_names = vec!["127.0.0.1".into(), "*.example.test".into()];
        ip_leaf.ip_addrs = vec![vec![192, 0, 2, 1], [0u8; 15].iter().copied().chain([1]).collect()];
        assert!(!ip_leaf.matches_hostname("127.0.0.1"), "a dNSName that looks like an address is not an address");
        assert!(ip_leaf.matches_hostname("192.0.2.1"));
        assert!(ip_leaf.matches_hostname("::1"));
        assert!(!ip_leaf.matches_hostname("::ffff:192.0.2.1"), "no mapping between the families");
        assert!(ip_leaf.matches_hostname("x.example.test") && !ip_leaf.matches_hostname("192.0.2.1.example"));
        assert!(!ip_leaf.matches_hostname("[::1]"));
        assert!(!ip_leaf.matches_hostname("192.0.2.1."), "an address with a dot after it is not an address, and no name");
    }

    // ---- B-33: ECDSA P-521 and RSASSA-PSS certificate signatures (tools/gen_algorithm_fixtures.py)

    #[test]
    fn a_p521_chain_verifies_and_a_changed_signature_does_not() {
        let ts = store(&[fixture!("alg_p521_root")]);
        let (leaf, inter) = (fixture!("alg_p521_leaf"), fixture!("alg_p521_inter"));
        let got = ts.verify_server_chain(&[leaf.clone(), inter.clone()], "p521.example.test", NOW).unwrap();
        assert!(matches!(got.public_key, PublicKey::Ec { curve: Curve::P521, .. }));
        assert_eq!(got.sig_alg, Some(SigAlg::Ecdsa(HashAlg::Sha384)));
        let root = Certificate::from_der(&fixture!("alg_p521_root")).unwrap();
        let inter_c = Certificate::from_der(&inter).unwrap();
        assert!(matches!(root.public_key, PublicKey::Ec { curve: Curve::P521, .. }));
        assert_eq!(inter_c.sig_alg, Some(SigAlg::Ecdsa(HashAlg::Sha512)));
        inter_c.verify_signed_by(&root).unwrap();
        root.verify_signed_by(&root).unwrap();
        // the P-521 root's signature on the intermediate, damaged in its last byte and in s's first
        for at in [inter.len() - 1, inter.len() - 60] {
            let mut bad = inter.clone();
            bad[at] ^= 1;
            let msg = err_text(ts.verify_server_chain(&[leaf.clone(), bad], "p521.example.test", NOW));
            assert!(msg.contains("signature"), "{at}: {msg}");
        }
        // and the root does not verify what the intermediate signed
        assert!(Certificate::from_der(&leaf).unwrap().verify_signed_by(&root).is_err());
    }

    #[test]
    fn rsa_pss_chains_with_the_web_pki_parameters_verify() {
        let ts = store(&[fixture!("alg_pss_root")]);
        let inter = fixture!("alg_pss_inter");
        assert_eq!(Certificate::from_der(&inter).unwrap().sig_alg, Some(SigAlg::RsaPss(HashAlg::Sha256)));
        for (leaf, hash) in [(fixture!("alg_pss_leaf"), HashAlg::Sha512), (fixture!("alg_pss_leaf_sha384"), HashAlg::Sha384)] {
            let got = ts.verify_server_chain(&[leaf.clone(), inter.clone()], "pss.example.test", NOW).unwrap();
            assert_eq!(got.sig_alg, Some(SigAlg::RsaPss(hash)));
            let mut bad = leaf.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(err_text(ts.verify_server_chain(&[bad, inter.clone()], "pss.example.test", NOW)).contains("signature"));
        }
        // a PKCS#1 v1.5 verification of a PSS signature, and the reverse, fail: the algorithm is the certificate's
        let leaf = Certificate::from_der(&fixture!("alg_pss_leaf")).unwrap();
        let inter_c = Certificate::from_der(&inter).unwrap();
        assert!(verify_signature(Some(SigAlg::RsaPss(HashAlg::Sha512)), &inter_c.public_key, &leaf.tbs, &leaf.signature));
        assert!(!verify_signature(Some(SigAlg::RsaPkcs1(HashAlg::Sha512)), &inter_c.public_key, &leaf.tbs, &leaf.signature));
        assert!(!verify_signature(Some(SigAlg::RsaPss(HashAlg::Sha384)), &inter_c.public_key, &leaf.tbs, &leaf.signature));
        let root = Certificate::from_der(&fixture!("alg_pss_root")).unwrap();
        assert!(!verify_signature(Some(SigAlg::RsaPss(HashAlg::Sha256)), &root.public_key, &root.tbs, &root.signature));
    }

    #[test]
    fn rsa_pss_with_other_parameters_is_not_read() {
        // real signatures (OpenSSL verifies both) with parameters the Web PKI does not allow: no algorithm, so refused
        let ts = store(&[fixture!("alg_pss_root")]);
        for name in ["alg_pss_leaf_salt20", "alg_pss_leaf_mgf_sha512"] {
            let der = match name {
                "alg_pss_leaf_salt20" => fixture!("alg_pss_leaf_salt20"),
                _ => fixture!("alg_pss_leaf_mgf_sha512"),
            };
            assert_eq!(Certificate::from_der(&der).unwrap().sig_alg, None, "{name}");
            let msg = err_text(ts.verify_server_chain(&[der, fixture!("alg_pss_inter")], "pss.example.test", NOW));
            assert!(msg.contains("unsupported certificate signature algorithm"), "{name}: {msg}");
        }
    }

    #[test]
    fn the_rsa_pss_parameters_are_read_only_in_the_web_pki_shapes() {
        let unhex = crate::util::unhex;
        // Mozilla Root Store Policy 5.1.1, byte for byte (the whole AlgorithmIdentifier; its content is from byte 2)
        let mozilla = [
            ("304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120", HashAlg::Sha256),
            ("304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130", HashAlg::Sha384),
            ("304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140", HashAlg::Sha512),
        ];
        for (hex, hash) in mozilla {
            let der = unhex(hex);
            assert_eq!(SigAlg::from_algorithm_identifier(&der[2..]).unwrap(), Some(SigAlg::RsaPss(hash)), "{hex}");
        }
        // the hash AlgorithmIdentifiers without their NULL (RFC 4055 section 2.1 allows both)
        let bare = "06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a203020120";
        assert_eq!(SigAlg::from_algorithm_identifier(&unhex(bare)).unwrap(), Some(SigAlg::RsaPss(HashAlg::Sha256)));
        let content = |hex: &str| unhex(hex)[2..].to_vec();
        let sha256 = content(mozilla[0].0);
        let edits: [(&str, Vec<u8>); 8] = [
            // no parameters, NULL parameters, empty parameters (all the SHA-1 defaults)
            ("absent", unhex("06092a864886f70d01010a")),
            ("NULL", unhex("06092a864886f70d01010a0500")),
            ("the SHA-1 defaults", unhex("06092a864886f70d01010a3000")),
            // salt 20 (the default) and 0
            ("salt 33", { let mut d = sha256.clone(); let n = d.len(); d[n - 1] = 0x21; d }),
            ("salt 0", { let mut d = sha256.clone(); let n = d.len(); d[n - 1] = 0x00; d }),
            // a mask hash of SHA-384 under a message hash of SHA-256
            ("mask hash differs", { let mut d = sha256.clone(); let at = d.windows(9).rposition(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]).unwrap(); d[at + 8] = 0x02; d }),
            // trailerField 1 written out (DER leaves a default out)
            ("trailer field written", unhex("06092a864886f70d01010a3039a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120a303020101")),
            // a mask generation function other than MGF1 (1.2.840.113549.1.1.9)
            ("not MGF1", { let mut d = sha256.clone(); let at = d.windows(9).position(|w| w == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08]).unwrap(); d[at + 8] = 0x09; d }),
        ];
        for (what, der) in edits {
            assert_eq!(SigAlg::from_algorithm_identifier(&der).unwrap(), None, "{what}");
        }
        // a SHA-1 hash: no
        let sha1 = "06092a864886f70d01010a302ca00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500a203020114";
        assert_eq!(SigAlg::from_algorithm_identifier(&unhex(sha1)).unwrap(), None);
    }

    #[test]
    fn a_crl_signed_with_rsa_pss_is_checked() {
        let crl = crate::revocation::Crl::from_der(include_bytes!("../tests/data/alg_pss_crl.der")).unwrap();
        assert_eq!(crl.len(), 1);
        let inter = fixture!("alg_pss_inter");
        let path = vec![fixture!("alg_pss_leaf_sha384"), inter.clone(), fixture!("alg_pss_root")];
        let evidence = crate::revocation::ChainEvidence { sent: &path[..2], staples: &[] };
        let cfg = crate::revocation::Revocation::hard_fail().with_crl(crl);
        let msg = err_text(crate::revocation::check_path(&cfg, &path, &evidence, NOW));
        assert!(msg.contains("certificate_revoked") && msg.contains("a CRL"), "{msg}");
        // the other leaf of the same intermediate is on no list: the PSS-signed list settles it
        let path = vec![fixture!("alg_pss_leaf"), inter, fixture!("alg_pss_root")];
        let cfg = crate::revocation::Revocation::hard_fail().with_crl(crate::revocation::Crl::from_der(include_bytes!("../tests/data/alg_pss_crl.der")).unwrap());
        crate::revocation::check_path(&cfg, &path, &crate::revocation::ChainEvidence { sent: &path[..2], staples: &[] }, NOW).unwrap();
    }

    #[test]
    fn the_algorithm_identifier_of_ed25519_has_no_parameters() {
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        assert_eq!(SigAlg::from_algorithm_identifier(&oid).unwrap(), Some(SigAlg::Ed25519));
        // RFC 8410 section 3: the parameters MUST be absent, so a NULL is not Ed25519 (unlike RSA and ECDSA)
        assert_eq!(SigAlg::from_algorithm_identifier(&[&oid[..], &[0x05, 0x00]].concat()).unwrap(), None);
        assert_eq!(SigAlg::from_algorithm_identifier(&[&oid[..], &[0x04, 0x00]].concat()).unwrap(), None);
        // and Ed448 (1.3.101.113) is not supported
        assert_eq!(SigAlg::from_algorithm_identifier(&[0x06, 0x03, 0x2b, 0x65, 0x71]).unwrap(), None);
    }

    #[test]
    fn an_ed25519_public_key_is_exactly_its_32_bytes() {
        fn spki(alg: &[u8], key: &[u8]) -> Vec<u8> {
            let mut bits = vec![0x03, (key.len() + 1) as u8, 0x00];
            bits.extend_from_slice(key);
            let mut alg_seq = vec![0x30, alg.len() as u8];
            alg_seq.extend_from_slice(alg);
            let mut out = vec![0x30, (alg_seq.len() + bits.len()) as u8];
            out.extend_from_slice(&alg_seq);
            out.extend_from_slice(&bits);
            out
        }
        let parse = |der: &[u8]| parse_public_key(&Der::new(der).next().unwrap()).unwrap();
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let key = [7u8; 32];
        assert!(matches!(parse(&spki(&oid, &key)), PublicKey::Ed25519(k) if k == key));
        // parameters present (even NULL), a short key and a long key are all not an Ed25519 key
        assert!(matches!(parse(&spki(&[&oid[..], &[0x05, 0x00]].concat(), &key)), PublicKey::Unsupported));
        assert!(matches!(parse(&spki(&oid, &key[..31])), PublicKey::Unsupported));
        assert!(matches!(parse(&spki(&oid, &[7u8; 33])), PublicKey::Unsupported));
        assert!(matches!(parse(&spki(&oid, &[])), PublicKey::Unsupported));
    }

    #[test]
    fn an_ed25519_signature_needs_an_ed25519_key() {
        // the fixtures' own keys and signatures, mixed up: an Ed25519 signature checked against an EC key and
        // the reverse are failures, not panics
        let leaf = Certificate::from_der(&fixture!("ed_leaf")).unwrap();
        let ec = Certificate::from_der(&fixture!("ed_leaf_p256")).unwrap();
        let rsa = Certificate::from_der(&fixture!("leaf_rsa")).unwrap();
        for key in [&ec.public_key, &rsa.public_key] {
            assert!(!verify_signature(leaf.sig_alg, key, &leaf.tbs, &leaf.signature));
        }
        assert!(!verify_signature(ec.sig_alg, &leaf.public_key, &ec.tbs, &ec.signature));
        assert!(!verify_signature(None, &leaf.public_key, &leaf.tbs, &leaf.signature));
    }

    // ---- regression tests for the first review of this file (BACKLOG B-93). The certificates are made by
    // tools/gen_review_fixtures.py and live in tests/data/rv_fixtures.txt, one `name base64(DER)` per line.

    fn rv(name: &str) -> Vec<u8> {
        include_str!("../tests/data/rv_fixtures.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| l.split_once(' ').filter(|(n, _)| *n == name))
            .map(|(_, b64)| pem::base64_decode(b64).unwrap())
            .unwrap_or_else(|| panic!("no fixture {name}"))
    }

    /// Verifies `chain` (leaf first) against the one trust anchor `root`, at `NOW`.
    fn rv_verify(root: &str, chain: &[&str], purpose: Purpose, host: Option<&str>) -> Result<VerifiedChain> {
        let ts = store(&[rv(root)]);
        let chain: Vec<Vec<u8>> = chain.iter().map(|n| rv(n)).collect();
        let mut options = VerifyOptions::new(purpose, NOW);
        if let Some(h) = host {
            options = options.with_hostname(h);
        }
        ts.verify_chain(&chain, &options)
    }

    fn rv_server(root: &str, chain: &[&str]) -> Result<VerifiedChain> {
        rv_verify(root, chain, Purpose::ServerAuth, Some("host.test"))
    }

    /// The text of the error, and a failure of the test if there was none.
    fn refused(r: Result<VerifiedChain>) -> String {
        match r {
            Ok(_) => panic!("the chain was accepted"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_ladder_of_lookalike_intermediates_is_given_up_on() {
        // Eight levels of four different certificates each, every one of which verifies against the one
        // above it, and no trust anchor at the top. Trying every path is 4^8 = 65,536 signature checks (ten
        // seconds), and a server that sent 20 per level would hold a client for weeks.
        let mut chain = vec![rv("ladder_leaf")];
        for level in 1..=8 {
            for variant in 0..4 {
                chain.push(rv(&format!("ladder_L{level}_{variant}")));
            }
        }
        let ts = store(&[rv("ladder_unrelated_root")]);
        let err = ts.verify_server_chain(&chain, "host.test", NOW).unwrap_err().to_string();
        assert!(err.contains("gave up after"), "{err}");
    }

    #[test]
    fn decoys_and_repeats_do_not_stop_a_good_chain_from_being_found() {
        // ten certificates with the intermediate's name and the wrong key come first, then the real
        // intermediate, then the real intermediate again 300 times
        let mut chain = vec![rv("decoy_leaf")];
        for i in 0..10 {
            chain.push(rv(&format!("decoy_x{i}")));
        }
        for _ in 0..301 {
            chain.push(rv("decoy_inter"));
        }
        let ts = store(&[rv("decoy_root")]);
        ts.verify_server_chain(&chain, "host.test", NOW).unwrap();
    }

    #[test]
    fn an_anchor_must_be_a_ca_unless_it_is_a_version_1_certificate() {
        // version 3 with no basicConstraints: an end-entity certificate, with or without keyUsage
        for (root, leaf) in [("anchor_v3_nobc", "anchor_v3_nobc_leaf"), ("anchor_v3_nobc_ku", "anchor_v3_nobc_ku_leaf")] {
            let err = refused(rv_server(root, &[leaf]));
            assert!(err.contains("not a CA"), "{root}: {err}");
        }
        // version 1 has no extensions at all, so the old roots of that kind are CAs by being in the store
        rv_server("anchor_v1", &["anchor_v1_leaf"]).unwrap();
    }

    #[test]
    fn a_name_the_reader_leaves_out_does_not_escape_a_constraint_of_its_kind() {
        for (inter, leaf) in [
            ("nm_inter_x400", "nm_leaf_x400"),
            ("nm_inter_dir", "nm_leaf_dir_ok"),
            ("nm_inter_dir", "nm_leaf_dir_malformed"),
            ("nm_inter_email", "nm_leaf_email_nonascii"),
        ] {
            let err = refused(rv_server("nm_root", &[leaf, inter]));
            assert!(err.contains("name constraint"), "{leaf}: {err}");
        }
        // the same odd name under a CA whose constraints are about DNS names only is no problem
        rv_server("nm_root", &["nm_leaf_x400_dns_only", "nm_inter_dns_only"]).unwrap();
    }

    #[test]
    fn a_boolean_is_00_or_ff_and_nothing_else() {
        let err = refused(rv_server("bool_root", &["bool_leaf_ff"]));
        assert!(err.contains("unrecognized critical extension"), "{err}");
        // True written as 0x01 is not DER. OpenSSL reads it as critical and Go refuses the certificate;
        // reading it as "not critical" would let an extension this code ignores through.
        let err = Certificate::from_der(&rv("bool_leaf_01")).unwrap_err().to_string();
        assert!(err.contains("BOOLEAN"), "{err}");
        assert!(rv_server("bool_root", &["bool_leaf_01"]).is_err());
    }

    #[test]
    fn a_dns_name_with_a_control_character_makes_the_certificate_invalid() {
        let err = Certificate::from_der(&rv("nm_leaf_ctl_dns")).unwrap_err().to_string();
        assert!(err.contains("control character"), "{err}");
    }

    #[test]
    fn name_constraints_that_cannot_work_are_refused_not_ignored() {
        for inter in ["nm_inter_trailing_dot", "nm_inter_empty_label"] {
            assert!(Certificate::from_der(&rv(inter)).is_err(), "{inter} parsed");
        }
        for (inter, leaf) in [("nm_inter_trailing_dot", "nm_leaf_bad_host"), ("nm_inter_empty_label", "nm_leaf_bad_host2")] {
            let err = refused(rv_verify("nm_root", &[leaf, inter], Purpose::ServerAuth, Some("bad.example.com")));
            assert!(!err.contains("host name"), "{leaf}: the host name was what stopped it: {err}");
        }
        // an empty constraint holds for everything, as it already did for DNS names: excluded, it excludes every address
        let err = refused(rv_verify("nm_root", &["nm_leaf_email", "nm_inter_empty_email"], Purpose::EmailProtection, None));
        assert!(err.contains("excluded"), "{err}");
        // and an ordinary exclusion keeps working
        let err = refused(rv_verify("nm_root", &["nm_leaf_bad_host3", "nm_inter_excl_plain"], Purpose::ServerAuth, Some("bad.example.com")));
        assert!(err.contains("excluded"), "{err}");
    }

    #[test]
    fn the_e_mail_address_in_the_subject_name_is_held_to_e_mail_constraints() {
        let mail = |leaf: &str| rv_verify("nm_root", &[leaf, "nm_inter_corp_email"], Purpose::EmailProtection, None);
        assert!(mail("nm_leaf_subject_email_in").is_ok());
        // outside the constraint, with no SAN at all or next to a SAN that is inside it
        for leaf in ["nm_leaf_subject_email_out", "nm_leaf_san_in_subject_out"] {
            let err = refused(mail(leaf));
            assert!(err.contains("not permitted"), "{leaf}: {err}");
        }
    }

    #[test]
    fn a_directory_name_constraint_is_refused_not_ignored() {
        // Every certificate has a subject name, so a constraint on directory names applies to all of them. This code
        // does not compare names, and ignoring the constraint lets a CA issue outside the subtree it was limited to
        // (OpenSSL enforces it, Go refuses the chain as an unhandled critical extension).
        for (inter, leaf) in [("nm_inter_dir_perm", "nm_leaf_o_other"), ("nm_inter_dir_excl", "nm_leaf_o_corp")] {
            let err = refused(rv_server("nm_root", &[leaf, inter]));
            assert!(err.contains("directoryName"), "{leaf}: {err}");
        }
    }

    #[test]
    fn the_names_of_an_intermediate_are_held_to_the_constraints_above_it() {
        let under = |sub: &str, leaf: &str, ca: &str| rv_verify("nm_root", &[leaf, sub, ca], Purpose::ServerAuth, Some("www.good.example"));
        // a CA limited to good.example certifies a CA whose own name is evil.test: OpenSSL and Go refuse the chain
        let err = refused(under("nm_sub_san_out", "nm_leaf_under_sub_san_out", "nm_inter_good"));
        assert!(err.contains("not permitted") && err.contains("evil.test"), "{err}");
        // the same with a name inside the limit
        under("nm_sub_san_in", "nm_leaf_under_sub_san_in", "nm_inter_good").unwrap();
        // and the e-mail address in an intermediate's subject name
        let mail = |sub: &str, leaf: &str| rv_verify("nm_root", &[leaf, sub, "nm_inter_corp_email2"], Purpose::EmailProtection, None);
        let err = refused(mail("nm_sub_mail_out", "nm_leaf_under_sub_mail_out"));
        assert!(err.contains("not permitted"), "{err}");
        mail("nm_sub_mail_in", "nm_leaf_under_sub_mail_in").unwrap();
    }
}
