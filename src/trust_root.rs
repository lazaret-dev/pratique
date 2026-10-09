//! The trust material that Sigstore verification starts from, read from JSON: Sigstore's trusted root
//! (`trusted_root.json`, what its TUF repository distributes) and the list of signing keys the npm registry
//! publishes (`https://registry.npmjs.org/-/npm/v1/keys`).
//!
//! Nothing here fetches or refreshes anything: the caller brings the bytes, having got them from wherever
//! it trusts (a pinned copy, a TUF client of its own), and this module only reads them, strictly (see
//! [`crate::json`]: duplicate names, bad UTF-8 and the rest are errors). [`crate::sigstore`] uses what it
//! reads.
//!
//! # The trusted root
//!
//! [`TrustedRoot::parse`] reads the media types `application/vnd.dev.sigstore.trustedroot+json;version=0.1`
//! and `application/vnd.dev.sigstore.trustedroot.v0.2+json` and keeps the four lists a verifier needs:
//!
//! * `tlogs`, the transparency logs (Rekor) with the keys they sign checkpoints and entry timestamps with;
//! * `certificateAuthorities`, Fulcio's certificate chains;
//! * `timestampAuthorities`, the RFC 3161 time-stamp authorities' chains;
//! * `ctlogs`, the Certificate Transparency logs, whose signed certificate timestamps in Fulcio's certificates
//!   [`crate::sigstore`] checks (with [`crate::ct`]).
//!
//! Every key and every authority has a validity period, [`Validity`]: from `start`, to `end` if there is
//! one, both in whole seconds. An end of `2022-12-31T23:59:59.999Z` is read as 23:59:59 (the last whole
//! second it covers) and a start with a fraction as the next whole second, so a time in whole seconds is
//! inside the period exactly when the exact time would be. A key whose type or hash is one this crate
//! does not verify (anything but ECDSA over P-256 with SHA-256, P-384 with SHA-384, Ed25519 and RSA PKCS#1
//! v1.5 with SHA-256) is left out and counted in [`TrustedRoot::skipped_keys`]; an entry of the wrong
//! shape is an error.
//!
//! # The npm registry's keys
//!
//! [`KeyRing::from_npm_keys`] reads the registry's key list. Each key has an id (`SHA256:` and the
//! unpadded Base64 of the SHA-256 of the key in OpenSSH's wire encoding, the fingerprint `ssh-keygen -l`
//! prints; it is checked), a validity that ends
//! at its `expires` if it has one. npm signs its publish attestations with these keys, and Sigstore
//! bundles name the key by that id.

use std::fmt;

use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::ed25519;
use crate::crypto::sha2::{Hash as _, HashAlg, Sha256};
use crate::json::{self, Value};
use crate::pem::{base64_decode_strict, base64_encode};
use crate::x509::{self, Certificate, PublicKey, TrustStore};

/// What can be wrong with trust material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not strict JSON.
    Json(json::Error),
    /// The JSON is not what the file should hold; the string says where.
    Malformed(String),
    /// A media type or key list of a kind this reader does not know.
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(e) => write!(f, "not strict JSON: {e}"),
            Error::Malformed(m) => write!(f, "malformed trust material: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported trust material: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<json::Error> for Error {
    fn from(e: json::Error) -> Error {
        Error::Json(e)
    }
}

fn malformed<T>(path: &str, what: &str) -> Result<T, Error> {
    Err(Error::Malformed(format!("{path}: {what}")))
}

// ================================================================================================ times

/// Reads an RFC 3339 time in the form protobuf's JSON mapping and JavaScript write: `2022-12-31T23:59:59Z`,
/// with a fraction of a second of one to nine digits and a numeric offset also accepted, `T` and `Z` in
/// upper case, years 0001 to 9999, and a real calendar date and time (a leap second, `:60`, is not accepted).
///
/// Returns the whole seconds since 1970-01-01 UTC and the nanoseconds of the fraction.
pub fn parse_rfc3339(s: &str) -> Option<(i64, u32)> {
    let b = s.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = b.get(from..from + n)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(part.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if year < 1 || !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > days_in_month {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if b.get(at) == Some(&b'.') {
        let from = at + 1;
        let mut end = from;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == from || end - from > 9 {
            return None;
        }
        let mut n = digits(from, end - from)?;
        for _ in end - from..9 {
            n *= 10;
        }
        nanos = n as u32;
        at = end;
    }
    let offset = match b.get(at..)? {
        b"Z" => 0,
        rest if rest.len() == 6 && (rest[0] == b'+' || rest[0] == b'-') && rest[3] == b':' => {
            let (h, m) = (digits(at + 1, 2)?, digits(at + 4, 2)?);
            if h > 23 || m > 59 {
                return None;
            }
            let o = h * 3600 + m * 60;
            if rest[0] == b'-' { -o } else { o }
        }
        _ => return None,
    };
    let t = crate::asn1::days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some((t, nanos))
}

/// A period of time, in whole Unix seconds, both ends included. A missing end is no end, a missing start no
/// start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Validity {
    /// The first second inside the period.
    pub start: Option<i64>,
    /// The last second inside the period.
    pub end: Option<i64>,
}

impl Validity {
    /// A period with no limits.
    pub const ALWAYS: Validity = Validity { start: None, end: None };

    /// Whether `time` (Unix seconds) is inside the period.
    pub fn contains(&self, time: i64) -> bool {
        self.start.map_or(true, |s| time >= s) && self.end.map_or(true, |e| time <= e)
    }
}

// ================================================================================================ keys

/// The kinds of public key a Sigstore verification uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// ECDSA over NIST P-256, signatures over SHA-256 (ASN.1 DER).
    EcdsaP256,
    /// ECDSA over NIST P-384, signatures over SHA-384 (ASN.1 DER).
    EcdsaP384,
    /// Ed25519 (RFC 8032, pure).
    Ed25519,
    /// RSA of at least 2048 bits, PKCS#1 v1.5 signatures over SHA-256.
    Rsa,
}

/// Checks `signature` over `message` with a public key out of a certificate or a `SubjectPublicKeyInfo`:
/// the hash is the one the key's type goes with ([`KeyKind`]).
pub(crate) fn verify_signature(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    match key {
        PublicKey::Ec { curve: Curve::P256, point } => ecdsa::verify(Curve::P256, point, HashAlg::Sha256, message, signature),
        PublicKey::Ec { curve: Curve::P384, point } => ecdsa::verify(Curve::P384, point, HashAlg::Sha384, message, signature),
        PublicKey::Ed25519(k) => ed25519::verify(k, message, signature),
        PublicKey::Rsa(k) => k.bits() >= 2048 && k.verify_pkcs1(HashAlg::Sha256, message, signature),
        _ => false,
    }
}

fn kind_of(key: &PublicKey) -> Option<KeyKind> {
    match key {
        PublicKey::Ec { curve: Curve::P256, point } if ecdsa::is_valid_public_key(Curve::P256, point) => Some(KeyKind::EcdsaP256),
        PublicKey::Ec { curve: Curve::P384, point } if ecdsa::is_valid_public_key(Curve::P384, point) => Some(KeyKind::EcdsaP384),
        PublicKey::Ed25519(_) => Some(KeyKind::Ed25519),
        PublicKey::Rsa(k) if k.bits() >= 2048 => Some(KeyKind::Rsa),
        _ => None,
    }
}

/// A public key that signatures can be checked with, kept as the DER of its `SubjectPublicKeyInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    spki: Vec<u8>,
    kind: KeyKind,
}

impl VerificationKey {
    /// Reads a DER `SubjectPublicKeyInfo`. Fails for a key of a kind [`KeyKind`] does not have, for an EC
    /// point that is not on its curve and for an RSA key under 2048 bits.
    pub fn from_spki(der: &[u8]) -> Result<VerificationKey, Error> {
        let key = x509::parse_spki(der).map_err(|e| Error::Malformed(format!("public key: {e}")))?;
        match kind_of(&key) {
            Some(kind) => Ok(VerificationKey { spki: der.to_vec(), kind }),
            None => Err(Error::Unsupported("public key of a kind that is not verified here".into())),
        }
    }

    /// The `SubjectPublicKeyInfo` DER.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The type of the key.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The SHA-256 of the `SubjectPublicKeyInfo`: the identifier Sigstore gives a log key (`logId`) and
    /// npm's key id (as `SHA256:` and Base64) is made from.
    pub fn sha256(&self) -> [u8; 32] {
        let d = Sha256::digest(&self.spki);
        d.try_into().expect("a SHA-256 digest is 32 bytes")
    }

    /// Checks a signature over `message`: ASN.1 DER for ECDSA, the hash that goes with the key type.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match x509::parse_spki(&self.spki) {
            Ok(key) => verify_signature(&key, message, signature),
            Err(_) => false,
        }
    }
}

/// What a `keyDetails` value of a trusted root says about the key, if it is one that is verified here.
fn details_kind(details: &str) -> Option<KeyKind> {
    match details {
        "PKIX_ECDSA_P256_SHA_256" => Some(KeyKind::EcdsaP256),
        "PKIX_ECDSA_P384_SHA_384" => Some(KeyKind::EcdsaP384),
        "PKIX_ED25519" => Some(KeyKind::Ed25519),
        "PKIX_RSA_PKCS1V15_2048_SHA256" | "PKIX_RSA_PKCS1V15_3072_SHA256" | "PKIX_RSA_PKCS1V15_4096_SHA256" => Some(KeyKind::Rsa),
        _ => None,
    }
}

// ================================================================================================ the trusted root

/// A transparency log of the trusted root: where it is, which key it signs with, when that key counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyLog {
    /// The log's address, for example `https://rekor.sigstore.dev`. Its host is the name the log signs
    /// checkpoints under.
    pub base_url: String,
    /// The identifier the log's entries carry (`logId.keyId`); normally the SHA-256 of the key.
    pub log_id: Vec<u8>,
    /// The log's public key.
    pub key: VerificationKey,
    /// When the key may be used to say something about an entry.
    pub valid_for: Validity,
}

impl TransparencyLog {
    /// The host of [`base_url`](Self::base_url) (no scheme, port or path): a Rekor checkpoint is signed
    /// under this name and its origin line starts with it.
    pub fn host(&self) -> &str {
        let rest = self.base_url.split_once("://").map_or(self.base_url.as_str(), |(_, r)| r);
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        &rest[..end]
    }
}

/// A certificate authority of the trusted root, Fulcio's or a time-stamp authority's: a chain of
/// certificates and the period it counts for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// The authority's address, as the root gives it (may be empty).
    pub uri: String,
    /// The subject's common name, for display (may be empty).
    pub common_name: String,
    /// The DER of the certificates, as listed.
    pub chain: Vec<Vec<u8>>,
    /// When the authority counts: a certificate it issued is trusted at a time inside this period.
    pub valid_for: Validity,
}

impl Authority {
    /// The trust anchors of this authority and the certificates to build paths through.
    ///
    /// Anchors are the chain's self-issued certificates (roots); a chain with none anchors at the
    /// certificate no other certificate of the chain issued. Every other certificate, a time-stamp
    /// authority's own leaf included, is an intermediate.
    pub fn trust(&self) -> Result<(TrustStore, Vec<Certificate>), Error> {
        let mut certs = Vec::new();
        for der in &self.chain {
            certs.push(Certificate::from_der(der).map_err(|e| Error::Malformed(format!("certificate of {}: {e}", self.uri)))?);
        }
        let mut anchors: Vec<bool> = certs.iter().map(Certificate::is_self_issued).collect();
        if !anchors.iter().any(|a| *a) {
            let top: Vec<bool> = certs.iter().map(|c| !certs.iter().any(|o| o.subject_der == c.issuer_der)).collect();
            anchors = top;
        }
        if !anchors.iter().any(|a| *a) {
            return Err(Error::Malformed(format!("the chain of {} has no top", self.uri)));
        }
        let mut store = TrustStore::empty();
        let mut others = Vec::new();
        for (cert, anchor) in certs.into_iter().zip(anchors) {
            if anchor {
                store.add_der(&cert.der).map_err(|e| Error::Malformed(format!("anchor of {}: {e}", self.uri)))?;
            } else {
                others.push(cert);
            }
        }
        Ok((store, others))
    }
}

/// Sigstore's trusted root: the keys and authorities a verification trusts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedRoot {
    /// Rekor instances.
    pub tlogs: Vec<TransparencyLog>,
    /// Certificate Transparency logs (not used by this crate).
    pub ctlogs: Vec<TransparencyLog>,
    /// Fulcio certificate authorities.
    pub certificate_authorities: Vec<Authority>,
    /// RFC 3161 time-stamp authorities.
    pub timestamp_authorities: Vec<Authority>,
    /// How many log keys were left out because their type is not verified here.
    pub skipped_keys: usize,
}

const MEDIA_TYPES: [&str; 2] = ["application/vnd.dev.sigstore.trustedroot+json;version=0.1", "application/vnd.dev.sigstore.trustedroot.v0.2+json"];

fn text<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a str, Error> {
    match v.get(name) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => malformed(&format!("{path}.{name}"), "not a string"),
        None => malformed(&format!("{path}.{name}"), "missing"),
    }
}

fn optional_text<'a>(v: &'a Value, name: &str, path: &str) -> Result<Option<&'a str>, Error> {
    match v.get(name) {
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => malformed(&format!("{path}.{name}"), "not a string"),
    }
}

fn bytes(v: &Value, name: &str, path: &str) -> Result<Vec<u8>, Error> {
    match base64_decode_strict(text(v, name, path)?) {
        Some(b) if !b.is_empty() => Ok(b),
        _ => malformed(&format!("{path}.{name}"), "not Base64, or empty"),
    }
}

fn array<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a [Value], Error> {
    match v.get(name) {
        Some(Value::Array(a)) => Ok(a),
        Some(Value::Null) | None => Ok(&[]),
        Some(_) => malformed(&format!("{path}.{name}"), "not an array"),
    }
}

/// `{"start": ..., "end": ...}` with both optional, or nothing at all.
fn validity(v: &Value, path: &str) -> Result<Validity, Error> {
    let Some(range) = v.get("validFor") else { return Ok(Validity::ALWAYS) };
    if range.is_null() {
        return Ok(Validity::ALWAYS);
    }
    let path = format!("{path}.validFor");
    let time = |name: &str| -> Result<Option<(i64, u32)>, Error> {
        match optional_text(range, name, &path)? {
            None => Ok(None),
            Some(s) => parse_rfc3339(s).map(Some).ok_or_else(|| Error::Malformed(format!("{path}.{name}: not an RFC 3339 time: {s:?}"))),
        }
    };
    // a start with a fraction is the next whole second, an end with one is cut to the whole second it is in
    let start = time("start")?.map(|(t, ns)| if ns > 0 { t + 1 } else { t });
    let end = time("end")?.map(|(t, _)| t);
    if let (Some(s), Some(e)) = (start, end) {
        if s > e {
            return malformed(&path, "ends before it starts");
        }
    }
    Ok(Validity { start, end })
}

fn log(v: &Value, path: &str, skipped: &mut usize) -> Result<Option<TransparencyLog>, Error> {
    let key = v.get("publicKey").filter(|k| k.as_object().is_some());
    let Some(key) = key else { return malformed(&format!("{path}.publicKey"), "missing") };
    if let Some(alg) = optional_text(v, "hashAlgorithm", path)? {
        if alg != "SHA2_256" {
            *skipped += 1;
            return Ok(None);
        }
    }
    let kpath = format!("{path}.publicKey");
    let spki = bytes(key, "rawBytes", &kpath)?;
    let details = text(key, "keyDetails", &kpath)?;
    let Some(want) = details_kind(details) else {
        *skipped += 1;
        return Ok(None);
    };
    let Some(id) = v.get("logId") else { return malformed(&format!("{path}.logId"), "missing") };
    let log_id = bytes(id, "keyId", &format!("{path}.logId"))?;
    let key_obj = VerificationKey::from_spki(&spki).map_err(|e| Error::Malformed(format!("{kpath}: {e}")))?;
    if key_obj.kind() != want {
        return malformed(&kpath, &format!("keyDetails {details} does not match the key"));
    }
    Ok(Some(TransparencyLog {
        base_url: optional_text(v, "baseUrl", path)?.unwrap_or("").to_string(),
        log_id,
        key: key_obj,
        valid_for: validity(key, &kpath)?,
    }))
}

fn authority(v: &Value, path: &str) -> Result<Authority, Error> {
    let chain = match v.get("certChain") {
        Some(c) => c,
        None => return malformed(&format!("{path}.certChain"), "missing"),
    };
    let cpath = format!("{path}.certChain");
    let list = array(chain, "certificates", &cpath)?;
    if list.is_empty() {
        return malformed(&format!("{cpath}.certificates"), "empty");
    }
    let mut ders = Vec::new();
    for (i, c) in list.iter().enumerate() {
        let der = bytes(c, "rawBytes", &format!("{cpath}.certificates[{i}]"))?;
        Certificate::from_der(&der).map_err(|e| Error::Malformed(format!("{cpath}.certificates[{i}]: {e}")))?;
        ders.push(der);
    }
    let subject = v.get("subject");
    let common_name = match subject {
        Some(s) => optional_text(s, "commonName", &format!("{path}.subject"))?.unwrap_or("").to_string(),
        None => String::new(),
    };
    let a = Authority { uri: optional_text(v, "uri", path)?.unwrap_or("").to_string(), common_name, chain: ders, valid_for: validity(v, path)? };
    a.trust().map_err(|e| Error::Malformed(format!("{path}: {e}")))?;
    Ok(a)
}

impl TrustedRoot {
    /// Reads a `trusted_root.json`.
    pub fn parse(json_bytes: &[u8]) -> Result<TrustedRoot, Error> {
        let root = json::parse(json_bytes)?;
        if root.as_object().is_none() {
            return malformed("$", "not an object");
        }
        let media = text(&root, "mediaType", "$")?;
        if !MEDIA_TYPES.contains(&media) {
            return Err(Error::Unsupported(format!("trusted root media type {media:?}")));
        }
        let mut out = TrustedRoot::default();
        for (i, v) in array(&root, "tlogs", "$")?.iter().enumerate() {
            if let Some(l) = log(v, &format!("$.tlogs[{i}]"), &mut out.skipped_keys)? {
                out.tlogs.push(l);
            }
        }
        for (i, v) in array(&root, "ctlogs", "$")?.iter().enumerate() {
            if let Some(l) = log(v, &format!("$.ctlogs[{i}]"), &mut out.skipped_keys)? {
                out.ctlogs.push(l);
            }
        }
        for (i, v) in array(&root, "certificateAuthorities", "$")?.iter().enumerate() {
            out.certificate_authorities.push(authority(v, &format!("$.certificateAuthorities[{i}]"))?);
        }
        for (i, v) in array(&root, "timestampAuthorities", "$")?.iter().enumerate() {
            out.timestamp_authorities.push(authority(v, &format!("$.timestampAuthorities[{i}]"))?);
        }
        Ok(out)
    }

    /// The transparency logs with this `logId`.
    pub fn tlogs_with_id<'a>(&'a self, log_id: &'a [u8]) -> impl Iterator<Item = &'a TransparencyLog> + 'a {
        self.tlogs.iter().filter(move |l| l.log_id == log_id)
    }
}

// ================================================================================================ key ring

/// A key with the name it goes by and the period it may be used in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingKey {
    /// The identifier a bundle's `hint` or a DSSE signature's `keyid` names the key by.
    pub id: String,
    /// The public key.
    pub key: VerificationKey,
    /// When a signature by this key counts: it is checked against the time the log or a time-stamp
    /// authority vouched for, not the clock.
    pub valid_for: Validity,
}

/// The OpenSSH fingerprint of an ECDSA P-256 key, `SHA256:` and the unpadded Base64 of the SHA-256 of
/// its wire encoding (the strings `ecdsa-sha2-nistp256` and `nistp256` and the uncompressed point, each
/// with a four-byte length): npm's key ids. `None` for any other key.
pub fn ssh_fingerprint(spki_der: &[u8]) -> Option<String> {
    let Ok(PublicKey::Ec { curve: Curve::P256, point }) = x509::parse_spki(spki_der) else { return None };
    let mut blob = Vec::new();
    for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", &point] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    Some(format!("SHA256:{}", base64_encode(&Sha256::digest(&blob)).trim_end_matches('=')))
}

/// Keys that bundles without a certificate are signed with, such as npm's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyRing {
    keys: Vec<RingKey>,
    /// How many keys of a list were left out because their type is not verified here.
    pub skipped_keys: usize,
}

impl KeyRing {
    /// An empty ring.
    pub fn new() -> KeyRing {
        KeyRing::default()
    }

    /// Adds a key given as a DER `SubjectPublicKeyInfo` under `id`.
    pub fn add(&mut self, id: &str, spki_der: &[u8], valid_for: Validity) -> Result<(), Error> {
        if id.is_empty() {
            return malformed("key id", "empty");
        }
        self.keys.push(RingKey { id: id.to_string(), key: VerificationKey::from_spki(spki_der)?, valid_for });
        Ok(())
    }

    /// The keys, in the order they were added.
    pub fn keys(&self) -> &[RingKey] {
        &self.keys
    }

    /// The keys with this id (there is normally one).
    pub fn with_id<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a RingKey> + 'a {
        self.keys.iter().filter(move |k| k.id == id)
    }

    /// Reads the npm registry's key list, `{"keys": [{"expires", "keyid", "keytype", "scheme", "key"}]}`.
    ///
    /// Only `ecdsa-sha2-nistp256` keys (what npm uses) are read; the key id must be `SHA256:` and the
    /// unpadded Base64 of the SHA-256 of the key in OpenSSH's wire encoding (see [`ssh_fingerprint`]).
    /// `expires`, if not null, is the last moment the key is valid.
    pub fn from_npm_keys(json_bytes: &[u8]) -> Result<KeyRing, Error> {
        let root = json::parse(json_bytes)?;
        if root.as_object().is_none() {
            return malformed("$", "not an object");
        }
        let mut ring = KeyRing::new();
        for (i, k) in array(&root, "keys", "$")?.iter().enumerate() {
            let path = format!("$.keys[{i}]");
            let (keytype, scheme) = (text(k, "keytype", &path)?, text(k, "scheme", &path)?);
            if keytype != "ecdsa-sha2-nistp256" || scheme != "ecdsa-sha2-nistp256" {
                ring.skipped_keys += 1;
                continue;
            }
            let id = text(k, "keyid", &path)?;
            let spki = bytes(k, "key", &path)?;
            let key = VerificationKey::from_spki(&spki).map_err(|e| Error::Malformed(format!("{path}.key: {e}")))?;
            if key.kind() != KeyKind::EcdsaP256 {
                return malformed(&format!("{path}.key"), "not an ECDSA P-256 key");
            }
            if Some(id) != ssh_fingerprint(key.spki()).as_deref() {
                return malformed(&format!("{path}.keyid"), "is not the fingerprint of the key");
            }
            let end = match optional_text(k, "expires", &path)? {
                None => None,
                Some(s) => Some(parse_rfc3339(s).ok_or_else(|| Error::Malformed(format!("{path}.expires: not an RFC 3339 time: {s:?}")))?.0),
            };
            ring.keys.push(RingKey { id: id.to_string(), key, valid_for: Validity { start: None, end } });
        }
        Ok(ring)
    }

    /// Reads npm's keys in the form Sigstore's TUF repository distributes them (the target `registry.npmjs.org/keys.json`,
    /// see [`crate::tuf::NPM_KEYS_TARGET`]): `{"keys": [{"keyId", "keyUsage", "publicKey": {"rawBytes", "keyDetails",
    /// "validFor"}}]}`, keeping the keys whose `keyUsage` is `usage` (`npm:attestations` for publish attestations,
    /// `npm:signatures` for the registry's package signatures). Each key keeps the period that comes with it; the key id
    /// must be the fingerprint of the key (as in [`KeyRing::from_npm_keys`]). A key of a type not verified here is counted
    /// in [`skipped_keys`](KeyRing::skipped_keys).
    pub fn from_tuf_npm_keys(json_bytes: &[u8], usage: &str) -> Result<KeyRing, Error> {
        let root = json::parse(json_bytes)?;
        if root.as_object().is_none() {
            return malformed("$", "not an object");
        }
        let mut ring = KeyRing::new();
        for (i, k) in array(&root, "keys", "$")?.iter().enumerate() {
            let path = format!("$.keys[{i}]");
            if text(k, "keyUsage", &path)? != usage {
                continue;
            }
            let id = text(k, "keyId", &path)?;
            let Some(public) = k.get("publicKey").filter(|p| p.as_object().is_some()) else { return malformed(&format!("{path}.publicKey"), "missing") };
            let ppath = format!("{path}.publicKey");
            let Some(want) = details_kind(text(public, "keyDetails", &ppath)?) else {
                ring.skipped_keys += 1;
                continue;
            };
            let spki = bytes(public, "rawBytes", &ppath)?;
            let key = VerificationKey::from_spki(&spki).map_err(|e| Error::Malformed(format!("{ppath}.rawBytes: {e}")))?;
            if key.kind() != want {
                return malformed(&ppath, "keyDetails does not match the key");
            }
            if Some(id) != ssh_fingerprint(key.spki()).as_deref() {
                return malformed(&format!("{path}.keyId"), "is not the fingerprint of the key");
            }
            ring.keys.push(RingKey { id: id.to_string(), key, valid_for: validity(public, &ppath)? });
        }
        Ok(ring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    const ROOT: &[u8] = include_bytes!("../tests/data/sigstore/trusted_root.json");
    const NPM_KEYS: &[u8] = include_bytes!("../tests/data/sigstore/npm-registry-keys.json");

    #[test]
    fn rfc3339() {
        let t = |s: &str| parse_rfc3339(s);
        assert_eq!(t("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(t("2022-12-31T23:59:59.999Z"), Some((1_672_531_199, 999_000_000)));
        assert_eq!(t("2021-01-12T11:53:27Z"), Some((1_610_452_407, 0)));
        assert_eq!(t("2025-01-29T00:00:00.000Z"), Some((1_738_108_800, 0)));
        assert_eq!(t("2000-02-29T12:00:00Z"), Some((951_825_600, 0)));
        assert_eq!(t("1969-12-31T23:59:59Z"), Some((-1, 0)));
        assert_eq!(t("0001-01-01T00:00:00Z"), Some((-62_135_596_800, 0)));
        assert_eq!(t("9999-12-31T23:59:59.123456789Z"), Some((253_402_300_799, 123_456_789)));
        assert_eq!(t("2022-12-31T23:59:59.5Z"), Some((1_672_531_199, 500_000_000)));
        // numeric offsets
        assert_eq!(t("2022-12-31T23:59:59+01:00"), Some((1_672_531_199 - 3600, 0)));
        assert_eq!(t("2022-12-31T23:59:59-05:30"), Some((1_672_531_199 + 19_800, 0)));
        for bad in [
            "",
            "2022-12-31",
            "2022-12-31T23:59:59",
            "2022-12-31 23:59:59Z",
            "2022-12-31t23:59:59Z",
            "2022-12-31T23:59:59z",
            "2022-12-31T24:00:00Z",
            "2022-12-31T23:60:00Z",
            "2022-12-31T23:59:60Z",
            "2022-13-01T00:00:00Z",
            "2022-00-01T00:00:00Z",
            "2022-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2022-04-31T00:00:00Z",
            "2022-01-00T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "2022-12-31T23:59:59.Z",
            "2022-12-31T23:59:59.1234567890Z",
            "2022-12-31T23:59:59.5",
            "2022-12-31T23:59:59ZZ",
            "2022-12-31T23:59:59 Z",
            "2022-12-31T23:59:59+0100",
            "2022-12-31T23:59:59+24:00",
            "2022-12-31T23:59:59+01:60",
            "2022-12-31T23:59:59+1:00",
            "+022-12-31T23:59:59Z",
            "2022-12-31T23:59:5\u{663}Z",
            " 2022-12-31T23:59:59Z",
            "2022-12-31T23:59:59Z ",
        ] {
            assert_eq!(t(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn validity_includes_both_ends() {
        let v = Validity { start: Some(10), end: Some(20) };
        assert!(!v.contains(9) && v.contains(10) && v.contains(15) && v.contains(20) && !v.contains(21));
        assert!(Validity { start: Some(10), end: None }.contains(i64::MAX));
        assert!(!Validity { start: Some(10), end: None }.contains(9));
        assert!(Validity { start: None, end: Some(20) }.contains(i64::MIN));
        assert!(!Validity { start: None, end: Some(20) }.contains(21));
        assert!(Validity::ALWAYS.contains(0));
    }

    #[test]
    fn the_production_trusted_root_reads() {
        let root = TrustedRoot::parse(ROOT).unwrap();
        assert_eq!(root.skipped_keys, 0);
        // Rekor v1 (ECDSA) and v2 (Ed25519)
        assert_eq!(root.tlogs.len(), 2);
        let (v1, v2) = (&root.tlogs[0], &root.tlogs[1]);
        assert_eq!((v1.base_url.as_str(), v1.host(), v1.key.kind()), ("https://rekor.sigstore.dev", "rekor.sigstore.dev", KeyKind::EcdsaP256));
        assert_eq!((v2.host(), v2.key.kind()), ("log2025-1.rekor.sigstore.dev", KeyKind::Ed25519));
        assert_eq!(v1.valid_for, Validity { start: Some(1_610_452_407), end: None });
        assert_eq!(hex(&v1.log_id), "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");
        // Rekor v1 names its log by the SHA-256 of its key; v2 by the full hash of the signed-note key rule
        // (its first four bytes are the key hash of its checkpoints)
        assert_eq!(v1.key.sha256().to_vec(), v1.log_id);
        let ed: [u8; 32] = v2.key.spki()[12..].try_into().unwrap();
        let note_key = crate::note::Verifier::ed25519(v2.host(), &ed).unwrap();
        assert_eq!(note_key.key_hash().to_be_bytes(), v2.log_id[..4]);
        assert_eq!(root.tlogs_with_id(&v2.log_id).count(), 1);
        assert_eq!(root.tlogs_with_id(&[0; 32]).count(), 0);
        // the Rekor v1 key is the one the checkpoints of tests/data/rekor are signed with
        let pem = crate::pem::parse(include_str!("../tests/data/rekor/v1_key.pem")).remove(0).data;
        assert_eq!(v1.key.spki(), &pem[..]);

        // Fulcio: the first CA ended at 2022-12-31T23:59:59.999Z, the second is open-ended
        assert_eq!(root.certificate_authorities.len(), 2);
        assert_eq!(root.certificate_authorities[0].valid_for.end, Some(1_672_531_199));
        assert_eq!(root.certificate_authorities[1].valid_for.end, None);
        assert!(root.certificate_authorities[0].valid_for.contains(1_672_531_199));
        assert!(!root.certificate_authorities[0].valid_for.contains(1_672_531_200));
        assert_eq!(root.certificate_authorities[1].uri, "https://fulcio.sigstore.dev");
        assert_eq!(root.certificate_authorities[1].common_name, "sigstore");
        assert_eq!(root.certificate_authorities[0].chain.len(), 1);
        assert_eq!(root.certificate_authorities[1].chain.len(), 2);
        assert_eq!(root.timestamp_authorities.len(), 1);
        assert_eq!(root.ctlogs.len(), 2);
        assert_eq!(root.ctlogs[0].valid_for.end, Some(1_667_260_799));
    }

    #[test]
    fn an_authority_anchors_at_its_roots() {
        let root = TrustedRoot::parse(ROOT).unwrap();
        for ca in root.certificate_authorities.iter().chain(&root.timestamp_authorities) {
            let (store, others) = ca.trust().unwrap();
            assert_eq!(store.len() + others.len(), ca.chain.len(), "{}", ca.common_name);
            assert!(!store.is_empty(), "{}", ca.common_name);
        }
        // Fulcio's second CA is an intermediate under a root: one anchor, one intermediate
        let (store, others) = root.certificate_authorities[1].trust().unwrap();
        assert_eq!((store.len(), others.len()), (1, 1));
        assert!(!others[0].is_self_issued());
        // the intermediate chains to the root
        others[0].verify_signed_by(&Certificate::from_der(&root.certificate_authorities[1].chain[1]).unwrap()).unwrap();
        // a chain with no self-issued certificate anchors at its top
        let mut no_root = root.certificate_authorities[1].clone();
        no_root.chain.truncate(1);
        let (store, others) = no_root.trust().unwrap();
        assert_eq!((store.len(), others.len()), (1, 0));
    }

    #[test]
    fn the_npm_keys_read() {
        let ring = KeyRing::from_npm_keys(NPM_KEYS).unwrap();
        assert_eq!(ring.keys().len(), 2);
        assert_eq!(ring.skipped_keys, 0);
        let old = &ring.keys()[0];
        assert_eq!(old.id, "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA");
        assert_eq!(old.valid_for, Validity { start: None, end: Some(1_738_108_800) });
        assert_eq!(old.key.kind(), KeyKind::EcdsaP256);
        let new = &ring.keys()[1];
        assert_eq!(new.id, "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U");
        assert_eq!(new.valid_for, Validity::ALWAYS);
        assert_eq!(ring.with_id(&new.id).count(), 1);
        assert_eq!(ring.with_id("SHA256:nope").count(), 0);
    }

    /// npm's two keys in the form of Sigstore's TUF target `registry.npmjs.org/keys.json` (made here from the registry's
    /// list, with the usages and periods that target gives them: the old key for package signatures from 1999 and for
    /// attestations from December 2022, both to 29 January 2025; the new one for both from 13 January 2025).
    fn tuf_npm_keys() -> String {
        let doc = json::parse(NPM_KEYS).unwrap();
        let keys = doc.get("keys").and_then(Value::as_array).unwrap();
        let raw = |i: usize| keys[i].get("key").and_then(Value::as_str).unwrap().to_string();
        let id = |i: usize| keys[i].get("keyid").and_then(Value::as_str).unwrap().to_string();
        let entry = |i: usize, usage: &str, start: &str, end: Option<&str>| {
            let end = end.map(|e| format!(", \"end\": \"{e}\"")).unwrap_or_default();
            format!(
                "{{\"keyId\": \"{}\", \"keyUsage\": \"{usage}\", \"publicKey\": {{\"rawBytes\": \"{}\", \"keyDetails\": \"PKIX_ECDSA_P256_SHA_256\", \"validFor\": {{\"start\": \"{start}\"{end}}}}}}}",
                id(i),
                raw(i)
            )
        };
        let list = [
            entry(0, "npm:signatures", "1999-01-01T00:00:00.000Z", Some("2025-01-29T00:00:00.000Z")),
            entry(0, "npm:attestations", "2022-12-01T00:00:00.000Z", Some("2025-01-29T00:00:00.000Z")),
            entry(1, "npm:signatures", "2025-01-13T00:00:00.000Z", None),
            entry(1, "npm:attestations", "2025-01-13T00:00:00.000Z", None),
        ];
        format!("{{\"keys\": [{}]}}", list.join(", "))
    }

    #[test]
    fn npm_keys_in_the_tuf_form_are_read_by_usage() {
        let text = tuf_npm_keys();
        let ring = KeyRing::from_tuf_npm_keys(text.as_bytes(), "npm:attestations").unwrap();
        assert_eq!(ring.keys().len(), 2);
        assert_eq!(ring.keys()[0].id, "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA");
        assert_eq!(ring.keys()[0].valid_for, Validity { start: Some(1_669_852_800), end: Some(1_738_108_800) });
        assert_eq!(ring.keys()[1].valid_for, Validity { start: Some(1_736_726_400), end: None });
        // the same keys as the registry's own list
        let registry = KeyRing::from_npm_keys(NPM_KEYS).unwrap();
        for (a, b) in ring.keys().iter().zip(registry.keys()) {
            assert_eq!((&a.id, a.key.spki()), (&b.id, b.key.spki()));
        }
        let signatures = KeyRing::from_tuf_npm_keys(text.as_bytes(), "npm:signatures").unwrap();
        assert_eq!(signatures.keys()[0].valid_for.start, Some(915_148_800));
        assert!(KeyRing::from_tuf_npm_keys(text.as_bytes(), "npm:other").unwrap().keys().is_empty());
        // a key id that is not the key's fingerprint, details that are not the key's, a type not verified here
        let wrong_id = text.replacen("SHA256:jl3bwswu", "SHA256:Jl3bwswu", 2);
        assert!(KeyRing::from_tuf_npm_keys(wrong_id.as_bytes(), "npm:attestations").unwrap_err().to_string().contains("fingerprint"));
        let wrong_details = text.replace("PKIX_ECDSA_P256_SHA_256", "PKIX_ECDSA_P384_SHA_384");
        assert!(KeyRing::from_tuf_npm_keys(wrong_details.as_bytes(), "npm:attestations").unwrap_err().to_string().contains("does not match"));
        let unknown = text.replace("PKIX_ECDSA_P256_SHA_256", "PKIX_SOMETHING_ELSE");
        assert_eq!(KeyRing::from_tuf_npm_keys(unknown.as_bytes(), "npm:attestations").unwrap().skipped_keys, 2);
    }

    fn mutate(from: &[u8], old: &str, new: &str) -> Vec<u8> {
        let s = std::str::from_utf8(from).unwrap();
        assert!(s.contains(old), "{old}");
        s.replacen(old, new, 1).into_bytes()
    }

    #[test]
    fn a_bad_trusted_root_is_refused() {
        assert!(matches!(TrustedRoot::parse(b""), Err(Error::Json(_))));
        assert!(matches!(TrustedRoot::parse(b"[]"), Err(Error::Malformed(_))));
        assert!(matches!(TrustedRoot::parse(b"{}"), Err(Error::Malformed(_))));
        // duplicate names are an error even where the JSON would otherwise be fine
        assert!(matches!(TrustedRoot::parse(&mutate(ROOT, "\"tlogs\"", "\"tlogs\": [], \"tlogs\"")), Err(Error::Json(_))));
        assert!(matches!(
            TrustedRoot::parse(&mutate(ROOT, "version=0.1", "version=0.9")),
            Err(Error::Unsupported(_))
        ));
        let cases: Vec<(&str, &str, &str)> = vec![
            ("\"keyDetails\": \"PKIX_ECDSA_P256_SHA_256\"", "\"keyDetails\": \"PKIX_ED25519\"", "does not match the key"),
            ("\"start\": \"2021-01-12T11:53:27Z\"", "\"start\": \"2021-01-12 11:53:27Z\"", "RFC 3339"),
            ("\"start\": \"2021-01-12T11:53:27Z\"", "\"start\": 1610452407", "not a string"),
            ("\"end\": \"2022-12-31T23:59:59.999Z\"", "\"end\": \"2020-12-31T23:59:59.999Z\"", "ends before it starts"),
            ("\"certificates\": [", "\"certificates\": [], \"x\": [", "empty"),
        ];
        for (old, new, expect) in cases {
            match TrustedRoot::parse(&mutate(ROOT, old, new)) {
                Err(Error::Malformed(m)) => assert!(m.contains(expect), "{m}"),
                other => panic!("{old}: {other:?}"),
            }
        }
        // a key that is not a key
        let s = std::str::from_utf8(ROOT).unwrap();
        let at = s.find("\"rawBytes\": \"MFkw").unwrap() + "\"rawBytes\": \"".len();
        let mut bad = s.to_string();
        bad.replace_range(at..at + 4, "MFkx");
        assert!(matches!(TrustedRoot::parse(bad.as_bytes()), Err(Error::Malformed(_))), "a changed key header");
        let mut bad = s.to_string();
        bad.replace_range(at..at + 4, "MF!w");
        assert!(matches!(TrustedRoot::parse(bad.as_bytes()), Err(Error::Malformed(_))), "not Base64");
    }

    #[test]
    fn an_unknown_key_type_is_left_out_not_an_error() {
        let changed = mutate(ROOT, "\"keyDetails\": \"PKIX_ED25519\"", "\"keyDetails\": \"PKIX_ECDSA_P521_SHA_512\"");
        let root = TrustedRoot::parse(&changed).unwrap();
        assert_eq!((root.tlogs.len(), root.skipped_keys), (1, 1));
        let changed = mutate(ROOT, "\"hashAlgorithm\": \"SHA2_256\"", "\"hashAlgorithm\": \"SHA2_512\"");
        let root = TrustedRoot::parse(&changed).unwrap();
        assert_eq!(root.skipped_keys, 1);
    }

    #[test]
    fn bad_npm_key_lists_are_refused() {
        assert!(matches!(KeyRing::from_npm_keys(b"{\"keys\": 3}"), Err(Error::Malformed(_))));
        assert_eq!(ssh_fingerprint(&[1, 2, 3]), None);
        assert_eq!(ssh_fingerprint(TrustedRoot::parse(ROOT).unwrap().tlogs[1].key.spki()), None, "an Ed25519 key");
        assert!(matches!(KeyRing::from_npm_keys(b"[]"), Err(Error::Malformed(_))));
        assert!(matches!(KeyRing::from_npm_keys(b"{\"keys\": [], \"keys\": []}"), Err(Error::Json(_))));
        assert_eq!(KeyRing::from_npm_keys(b"{\"keys\": []}").unwrap().keys().len(), 0);
        // an id that is not the key's hash
        let wrong = mutate(NPM_KEYS, "SHA256:jl3bwswu", "SHA256:jl3bwswv");
        match KeyRing::from_npm_keys(&wrong) {
            Err(Error::Malformed(m)) => assert!(m.contains("keyid"), "{m}"),
            other => panic!("{other:?}"),
        }
        // another key type is skipped
        let other = mutate(NPM_KEYS, "\"keytype\":\"ecdsa-sha2-nistp256\"", "\"keytype\":\"ed25519\"");
        let ring = KeyRing::from_npm_keys(&other).unwrap();
        assert_eq!((ring.keys().len(), ring.skipped_keys), (1, 1));
        let bad_expiry = mutate(NPM_KEYS, "2025-01-29T00:00:00.000Z", "yesterday");
        assert!(matches!(KeyRing::from_npm_keys(&bad_expiry), Err(Error::Malformed(_))));
    }

    #[test]
    fn keys_verify_the_signatures_made_with_them() {
        let (v1, v2) = {
            let root = TrustedRoot::parse(ROOT).unwrap();
            (root.tlogs[0].clone(), root.tlogs[1].clone())
        };
        // the key of the older head of the Rekor v1 checkpoint (tests/data/rekor) verifies its note's text
        let cp = include_str!("../tests/data/rekor/v1_checkpoint_old.txt");
        let (text, sigs) = cp.split_once("\n\n").unwrap();
        let text = format!("{text}\n");
        let raw = base64_decode_strict(sigs.trim().rsplit(' ').next().unwrap()).unwrap();
        assert!(v1.key.verify(text.as_bytes(), &raw[4..]));
        let mut bad = text.clone().into_bytes();
        bad[3] ^= 1;
        assert!(!v1.key.verify(&bad, &raw[4..]));
        assert!(!v1.key.verify(text.as_bytes(), &raw));
        assert!(!v2.key.verify(text.as_bytes(), &raw[4..]), "another key, another kind");
        assert!(!v1.key.verify(text.as_bytes(), &[]));
        // not a key
        assert!(VerificationKey::from_spki(&[]).is_err());
        assert!(VerificationKey::from_spki(&v1.key.spki()[..90]).is_err());
        let mut off_curve = v1.key.spki().to_vec();
        off_curve[90] ^= 1;
        assert!(VerificationKey::from_spki(&off_curve).is_err());
    }

    #[test]
    fn the_key_ring_takes_keys_by_hand() {
        let root = TrustedRoot::parse(ROOT).unwrap();
        let mut ring = KeyRing::new();
        ring.add("mine", root.tlogs[0].key.spki(), Validity { start: Some(5), end: None }).unwrap();
        assert_eq!(ring.with_id("mine").count(), 1);
        assert!(ring.add("", root.tlogs[0].key.spki(), Validity::ALWAYS).is_err());
        assert!(ring.add("x", &[1, 2, 3], Validity::ALWAYS).is_err());
    }
}
