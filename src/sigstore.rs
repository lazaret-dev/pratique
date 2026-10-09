//! Verification of Sigstore attestations: the bundles that npm serves for a package version, a Sigstore
//! bundle on its own and PyPI's PEP 740 provenance, all checked by one core.
//!
//! The caller brings bytes and the trust to check them against ([`TrustedRoot`], [`KeyRing`]), and the
//! digest of the artifact the attestation is about. Nothing here reads a clock, opens a file or fetches
//! anything. What comes back, [`Verified`], is facts: who signed, which statement they signed, when the
//! log and time-stamp authorities say it existed. Whether that is the signer, repository or workflow
//! that should have published the artifact is the caller's policy, not decided here.
//!
//! # What is verified
//!
//! For a bundle in any of the formats (v0.1, v0.2, v0.3 and PEP 740, see [`BundleFormat`]) the core checks,
//! in this order:
//!
//! 1. The envelope is a DSSE envelope of payload type `application/vnd.in-toto+json` with exactly one
//!    signature, and that signature (over DSSE's pre-authentication encoding of type and payload) is made
//!    by the key of the signer: the key of the bundle's Fulcio certificate, or for a bundle with a key hint
//!    (npm's publish attestations) a key of the [`KeyRing`] with that id.
//! 2. The payload is an in-toto statement ([`Statement`]).
//! 3. Every transparency log entry in the bundle is about this envelope: the entry body (Rekor's canonical
//!    JSON, `intoto` 0.0.2 or `dsse` 0.0.1) holds the same signature, the same certificate or key and the
//!    SHA-256 of the same payload; the log is one the trusted root lists, and the entry is authenticated by
//!    its signed entry timestamp (the log's ECDSA signature over the canonical JSON of body, integration
//!    time, log id and log index), by an inclusion proof to a checkpoint the log signed (a signed note, see
//!    [`crate::note`]), or by both. A promise or proof that is present and wrong is an error even if the
//!    other is right.
//! 4. Every RFC 3161 time stamp in the bundle is over the envelope's signature and made by a time-stamp
//!    authority of the trusted root, at a time inside that authority's validity.
//! 5. The times that were verified, ascending (an entry's integration time when its signed entry timestamp
//!    checks out, a time stamp's time), are the only notion of time here: at least one is needed. The
//!    signer must have been valid at one: the certificate chain verifies to a Fulcio authority that counts
//!    at that time, for code signing, at that time; or the key's validity includes it.
//! 6. For a certificate, the signed certificate timestamps embedded in it (RFC 6962, see [`crate::ct`]) are checked
//!    against the trusted root's CT logs with the issuer of the verified chain: an SCT from a listed log must verify
//!    under a key of that log valid at the SCT's time, and SCTs from [`Trust::sct_threshold`] different logs (one by
//!    default) must have verified. SCTs from logs the root does not list are not checked and do not count.
//! 7. One of the statement's subjects has the digest the caller gave.
//!
//! # What is not verified
//!
//! Bundles that sign an artifact's digest directly (`messageSignature`) rather than a statement; Rekor v2 entries
//! (`kindVersion` other than `intoto` 0.0.2 and `dsse` 0.0.1); the envelope hash that Rekor records. The
//! `integratedTime` of an entry that has no valid signed entry timestamp is not used for anything. Consistency
//! between checkpoints is not looked at (an inclusion proof is to one signed checkpoint).
//!
//! # Inputs the standard leaves open
//!
//! Base64 is the canonical padded form (as protocol buffers' JSON writes it), 64-bit integers are decimal
//! strings or JSON integers, unknown fields are ignored, duplicate names are an error ([`crate::json`]).

use std::fmt;

use crate::asn1::{self, Der};
use crate::cms;
use crate::ct;
use crate::crypto::sha2::{Hash as _, HashAlg, Sha256};
use crate::json::{self, Value};
use crate::note::{self, Verifier};
use crate::pem::{self, base64_decode_strict, base64_encode};
use crate::tlog::{self, Hash};
use crate::trust_root::{self, KeyKind, KeyRing, RingKey, TransparencyLog, TrustedRoot};
use crate::util::hex;
use crate::x509::{Certificate, GeneralName, PublicKey, Purpose, VerifyOptions};

/// The payload type of an in-toto statement in a DSSE envelope.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

const MAX_ENTRIES: usize = 16;
const MAX_TIMESTAMPS: usize = 16;
const MAX_CERTIFICATES: usize = 8;
const MAX_PROOF_HASHES: usize = 64;
const MAX_ATTESTATIONS: usize = 256;

// ================================================================================================ errors

/// Why a bundle is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not strict JSON.
    Json(json::Error),
    /// The JSON is not a bundle (or the other inputs): the string says where and what.
    Malformed(String),
    /// A form of bundle or entry that is not handled here, which is not the same as a bad one.
    Unsupported(String),
    /// The envelope's payload type is not `application/vnd.in-toto+json`.
    PayloadType(String),
    /// The envelope's signature is not by the signer's key.
    Signature,
    /// The bundle names a key (`hint` or `keyid`) that the key ring does not have; or names none.
    UnknownKey(String),
    /// A transparency log entry is not valid for this envelope or not authenticated by a trusted log.
    Entry { log_index: u64, reason: String },
    /// An RFC 3161 time stamp is not valid.
    Timestamp(String),
    /// Nothing in the bundle established a time: no valid signed entry timestamp and no time stamp.
    NoVerifiedTime,
    /// The signer's certificate is unacceptable: the string says why (the chain, the purpose, a
    /// Fulcio extension that is not text).
    Certificate(String),
    /// The signer's certificate does not have enough signed certificate timestamps from the trusted root's CT logs,
    /// or has one from such a log that does not verify: the string says which.
    CertificateTransparency(String),
    /// The signer's key was not valid at any time the bundle established.
    KeyNotValid(String),
    /// The statement is malformed or of a kind not handled.
    Statement(String),
    /// No subject of the statement has the digest of the artifact.
    SubjectMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(e) => write!(f, "not strict JSON: {e}"),
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::PayloadType(t) => write!(f, "payload type {t:?} is not an in-toto statement"),
            Error::Signature => write!(f, "the envelope's signature is not by the signer's key"),
            Error::UnknownKey(k) => write!(f, "no trusted key {k:?}"),
            Error::Entry { log_index, reason } => write!(f, "transparency log entry {log_index}: {reason}"),
            Error::Timestamp(m) => write!(f, "time stamp: {m}"),
            Error::NoVerifiedTime => write!(f, "nothing in the bundle establishes when it was signed"),
            Error::Certificate(m) => write!(f, "signing certificate: {m}"),
            Error::CertificateTransparency(m) => write!(f, "certificate transparency: {m}"),
            Error::KeyNotValid(k) => write!(f, "key {k:?} was not valid when the bundle was signed"),
            Error::Statement(m) => write!(f, "statement: {m}"),
            Error::SubjectMismatch => write!(f, "no subject of the statement has the artifact's digest"),
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

// ================================================================================================ inputs

/// The trust a bundle is checked against.
#[derive(Clone, Copy, Debug)]
pub struct Trust<'a> {
    /// Sigstore's trusted root: logs, Fulcio and time-stamp authorities, CT logs.
    pub root: &'a TrustedRoot,
    /// Keys for bundles that carry a key hint instead of a certificate (npm's publish attestations).
    pub keys: Option<&'a KeyRing>,
    /// How many of the trusted root's CT logs must have signed a timestamp embedded in a signing certificate
    /// (counted once per log). 1 by default, as in sigstore-go, cosign and sigstore-python; 0 accepts a certificate
    /// without one (for a Sigstore that runs no CT log), but an SCT from a listed log is still checked.
    pub sct_threshold: usize,
}

impl<'a> Trust<'a> {
    /// Trust in a trusted root only: bundles signed by a Fulcio certificate that carries a signed certificate
    /// timestamp from one of the root's CT logs.
    pub fn new(root: &'a TrustedRoot) -> Trust<'a> {
        Trust { root, keys: None, sct_threshold: 1 }
    }

    /// Requires signed certificate timestamps from `logs` different CT logs of the root (0: none required).
    pub fn with_sct_threshold(mut self, logs: usize) -> Trust<'a> {
        self.sct_threshold = logs;
        self
    }

    /// Also trust the keys of `keys` for key-signed bundles.
    pub fn with_keys(mut self, keys: &'a KeyRing) -> Trust<'a> {
        self.keys = Some(keys);
        self
    }
}

/// The hash algorithms an in-toto subject digest can be compared in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    /// The name in-toto uses for it in a subject's `digest`.
    pub fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
            DigestAlgorithm::Sha512 => "sha512",
        }
    }

    fn hash(self) -> HashAlg {
        match self {
            DigestAlgorithm::Sha256 => HashAlg::Sha256,
            DigestAlgorithm::Sha384 => HashAlg::Sha384,
            DigestAlgorithm::Sha512 => HashAlg::Sha512,
        }
    }
}

/// The digest of the artifact an attestation is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDigest {
    algorithm: DigestAlgorithm,
    digest: Vec<u8>,
}

impl ArtifactDigest {
    /// A digest the caller already has; its length must be the algorithm's.
    pub fn new(algorithm: DigestAlgorithm, digest: &[u8]) -> Result<ArtifactDigest, Error> {
        if digest.len() != algorithm.hash().output_len() {
            return malformed("artifact digest", &format!("{} bytes is not the length of a {} digest", digest.len(), algorithm.name()));
        }
        Ok(ArtifactDigest { algorithm, digest: digest.to_vec() })
    }

    /// The digest of `data`.
    pub fn of(algorithm: DigestAlgorithm, data: &[u8]) -> ArtifactDigest {
        ArtifactDigest { algorithm, digest: algorithm.hash().digest(data) }
    }

    /// The algorithm.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The digest bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.digest
    }
}

// ================================================================================================ results

/// What a verified bundle says.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The format the bundle was in.
    pub format: BundleFormat,
    /// Who signed.
    pub signer: Signer,
    /// The statement they signed.
    pub statement: Statement,
    /// The index in `statement.subjects` of the subject that has the artifact's digest.
    pub matched_subject: usize,
    /// The time (Unix seconds) the signer's certificate or key was checked at: the earliest verified time
    /// at which it was valid.
    pub verified_time: i64,
    /// Every time the bundle established, ascending.
    pub times: Vec<VerifiedTime>,
    /// The transparency log entries, all authenticated.
    pub entries: Vec<VerifiedEntry>,
    /// The signed certificate timestamps of the signing certificate that verified against the root's CT logs (none
    /// for a key).
    pub scts: Vec<ct::VerifiedSct>,
}

/// Who signed.
#[derive(Clone, Debug)]
pub enum Signer {
    /// A Fulcio certificate: the identity it certifies.
    Certificate(Box<Identity>),
    /// A key from the key ring.
    Key {
        /// The key's id in the ring.
        id: String,
        /// The SHA-256 of the key's `SubjectPublicKeyInfo`.
        spki_sha256: [u8; 32],
    },
}

/// A time the bundle established, and what established it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTime {
    /// Unix seconds.
    pub time: i64,
    /// The signed entry timestamp or the time stamp that says so.
    pub source: TimeSource,
}

/// What established a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeSource {
    /// The log's signed entry timestamp over the entry with this log index.
    LogEntry { log_index: u64 },
    /// An RFC 3161 time stamp by this authority (its common name in the trusted root).
    TimeStamp { authority: String },
}

/// A transparency log entry that was authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEntry {
    /// The entry's index in the log, the global one the entry carries (not the position in a tree). Only a
    /// signed entry timestamp covers it: for an entry that has none, the authenticated position is
    /// [`Inclusion::leaf_index`].
    pub log_index: u64,
    /// The log's id and address in the trusted root.
    pub log_id: Vec<u8>,
    pub log_url: String,
    /// The entry type, `intoto` or `dsse`, and its version.
    pub kind: String,
    pub version: String,
    /// The integration time, if the entry's signed entry timestamp verified.
    pub integrated_time: Option<i64>,
    /// Whether a signed entry timestamp verified.
    pub signed_entry_timestamp: bool,
    /// The size of the tree and the checkpoint's origin line, if an inclusion proof verified.
    pub inclusion: Option<Inclusion>,
}

/// An inclusion proof that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    /// The position of the entry's leaf in the tree: what the inclusion proof proves. In a log that is one tree
    /// it is the entry's log index; Rekor v1 starts a new tree now and then and counts across them.
    pub leaf_index: u64,
    /// The tree size of the checkpoint the proof is to.
    pub tree_size: u64,
    /// The checkpoint's origin line (the log's name and tree).
    pub origin: String,
}

/// The in-toto statement an envelope carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// `_type`: `https://in-toto.io/Statement/v0.1` or `.../v1`.
    pub statement_type: String,
    /// What the statement is about.
    pub subjects: Vec<Subject>,
    /// What kind of predicate it is, for example `https://slsa.dev/provenance/v1`.
    pub predicate_type: String,
    /// The predicate, if there is one.
    pub predicate: Option<Value>,
}

/// One subject of a statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    /// Its name (a file name, a package URL), if the statement gives one.
    pub name: Option<String>,
    /// Its digests as written: algorithm name and hex.
    pub digests: Vec<(String, String)>,
}

/// What a Fulcio certificate certifies about its holder: the identity and the facts about the
/// workflow the issuer attested (see Sigstore's `fulcio/docs/oid-info.md`). Every text is as the
/// certificate has it. The first six are the deprecated `1.3.6.1.4.1.57264.1.1` to `.6` extensions,
/// the rest the current ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// The DER of the signing certificate and of the verified chain from it to the trust anchor.
    pub certificate: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    /// The certificate's validity, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// The OIDC issuer that vouched for the identity (`.8`, or the older `.1`).
    pub issuer: Option<String>,
    /// The subjectAltName entries: URIs (a workflow, for GitHub), e-mail addresses, and `otherName`s of
    /// Sigstore's username type (`1.3.6.1.4.1.57264.1.7`).
    pub uris: Vec<String>,
    pub emails: Vec<String>,
    pub other_names: Vec<String>,
    pub github_workflow_trigger: Option<String>,
    pub github_workflow_sha: Option<String>,
    pub github_workflow_name: Option<String>,
    pub github_workflow_repository: Option<String>,
    pub github_workflow_ref: Option<String>,
    pub build_signer_uri: Option<String>,
    pub build_signer_digest: Option<String>,
    pub runner_environment: Option<String>,
    pub source_repository_uri: Option<String>,
    pub source_repository_digest: Option<String>,
    pub source_repository_ref: Option<String>,
    pub source_repository_identifier: Option<String>,
    pub source_repository_owner_uri: Option<String>,
    pub source_repository_owner_identifier: Option<String>,
    pub build_config_uri: Option<String>,
    pub build_config_digest: Option<String>,
    pub build_trigger: Option<String>,
    pub run_invocation_uri: Option<String>,
    pub source_repository_visibility_at_signing: Option<String>,
}

/// GitHub Actions' OIDC issuer.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

impl Identity {
    /// The source repository: the certificate's source repository URI, or, for a certificate that only has
    /// the older GitHub extensions and was issued for GitHub Actions, `https://github.com/` and its
    /// repository.
    pub fn repository(&self) -> Option<String> {
        match (&self.source_repository_uri, &self.github_workflow_repository) {
            (Some(uri), _) => Some(uri.clone()),
            (None, Some(repo)) if self.issuer.as_deref() == Some(GITHUB_ACTIONS_ISSUER) => Some(format!("https://github.com/{repo}")),
            _ => None,
        }
    }

    /// The Git ref the workflow ran for: the source repository ref, or the older GitHub workflow ref.
    pub fn git_ref(&self) -> Option<&str> {
        self.source_repository_ref.as_deref().or(self.github_workflow_ref.as_deref())
    }
}

// ================================================================================================ bundle

/// The format a bundle was in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleFormat {
    /// `application/vnd.dev.sigstore.bundle+json;version=0.1`: a certificate chain or key hint, entries
    /// with signed entry timestamps.
    V0_1,
    /// `...;version=0.2`: as 0.1, and every entry has an inclusion proof with a checkpoint.
    V0_2,
    /// `application/vnd.dev.sigstore.bundle.v0.3+json`: a single certificate (or key hint).
    V0_3,
    /// PyPI's provenance attestations (PEP 740), whose verification material has the same parts; as in
    /// 0.2 and 0.3 every entry has an inclusion proof.
    Pep740,
}

#[derive(Clone, Debug)]
enum Material {
    /// The leaf first, then whatever else the bundle carried (untrusted: candidates for intermediates).
    Certificates(Vec<Vec<u8>>),
    Key { hint: String },
}

#[derive(Clone, Debug)]
struct Envelope {
    payload_type: String,
    payload: Vec<u8>,
    signatures: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Debug)]
struct InclusionProof {
    log_index: u64,
    root_hash: Hash,
    tree_size: u64,
    hashes: Vec<Hash>,
    checkpoint: String,
}

#[derive(Clone, Debug)]
struct LogEntry {
    log_index: u64,
    log_id: Vec<u8>,
    kind: String,
    version: String,
    integrated_time: Option<i64>,
    promise: Option<Vec<u8>>,
    proof: Option<InclusionProof>,
    body: Vec<u8>,
}

/// A bundle read from JSON: nothing in it is trusted until [`Bundle::verify`] has been through it.
#[derive(Clone, Debug)]
pub struct Bundle {
    format: BundleFormat,
    material: Material,
    entries: Vec<LogEntry>,
    timestamps: Vec<Vec<u8>>,
    envelope: Envelope,
}

/// One attestation of an npm package version (`/-/npm/v1/attestations/<package>@<version>`).
#[derive(Clone, Debug)]
pub struct NpmAttestation {
    /// The `predicateType` the registry's response labels the attestation with: not signed, and checked
    /// against the signed statement's by [`NpmAttestation::verify`].
    pub claimed_predicate_type: String,
    /// The Sigstore bundle.
    pub bundle: Bundle,
}

/// One attestation of a PyPI file (`/integrity/<project>/<version>/<file>/provenance`).
#[derive(Clone, Debug)]
pub struct Pep740Attestation {
    /// The bundle's publisher object as PyPI wrote it (`kind`, `repository`, `workflow`, ...): not signed
    /// and not checked; the certificate's identity is what is verified.
    pub claimed_publisher: Option<Value>,
    /// The attestation as a bundle.
    pub bundle: Bundle,
}

fn get<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a Value, Error> {
    match v.get(name) {
        Some(Value::Null) | None => malformed(&format!("{path}.{name}"), "missing"),
        Some(x) => Ok(x),
    }
}

fn opt<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.get(name).filter(|x| !x.is_null())
}

fn object<'a>(v: &'a Value, path: &str) -> Result<&'a Value, Error> {
    if v.as_object().is_none() {
        return malformed(path, "not an object");
    }
    Ok(v)
}

fn string(v: &Value, name: &str, path: &str) -> Result<String, Error> {
    match get(v, name, path)?.as_str() {
        Some(s) => Ok(s.to_string()),
        None => malformed(&format!("{path}.{name}"), "not a string"),
    }
}

fn b64(v: &Value, name: &str, path: &str) -> Result<Vec<u8>, Error> {
    let s = match get(v, name, path)?.as_str() {
        Some(s) => s,
        None => return malformed(&format!("{path}.{name}"), "not a string"),
    };
    base64_decode_strict(s).ok_or_else(|| Error::Malformed(format!("{path}.{name}: not canonical Base64")))
}

fn array<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a [Value], Error> {
    match opt(v, name) {
        None => Ok(&[]),
        Some(x) => x.as_array().ok_or_else(|| Error::Malformed(format!("{path}.{name}: not an array"))),
    }
}

fn uint64(v: &Value, name: &str, path: &str) -> Result<u64, Error> {
    get(v, name, path)?.as_uint64().ok_or_else(|| Error::Malformed(format!("{path}.{name}: not an unsigned 64-bit integer")))
}

fn hash32(v: &Value, name: &str, path: &str) -> Result<Hash, Error> {
    b64(v, name, path)?.try_into().map_err(|_| Error::Malformed(format!("{path}.{name}: not a 32-byte hash")))
}

fn parse_entry(v: &Value, path: &str) -> Result<LogEntry, Error> {
    object(v, path)?;
    let log_index = uint64(v, "logIndex", path)?;
    let log_id = b64(get(v, "logId", path)?, "keyId", &format!("{path}.logId"))?;
    let kv = get(v, "kindVersion", path)?;
    let (kind, version) = (string(kv, "kind", &format!("{path}.kindVersion"))?, string(kv, "version", &format!("{path}.kindVersion"))?);
    let integrated_time = match opt(v, "integratedTime") {
        None => None,
        Some(t) => match t.as_int64() {
            Some(0) => None,
            Some(n) if n > 0 => Some(n),
            _ => return malformed(&format!("{path}.integratedTime"), "not a positive integer"),
        },
    };
    let promise = match opt(v, "inclusionPromise") {
        None => None,
        Some(p) => Some(b64(p, "signedEntryTimestamp", &format!("{path}.inclusionPromise"))?),
    };
    let proof = match opt(v, "inclusionProof") {
        None => None,
        Some(p) => {
            let pp = format!("{path}.inclusionProof");
            object(p, &pp)?;
            let hashes = array(p, "hashes", &pp)?;
            if hashes.len() > MAX_PROOF_HASHES {
                return malformed(&format!("{pp}.hashes"), "too many");
            }
            let mut list = Vec::new();
            for (i, h) in hashes.iter().enumerate() {
                let s = h.as_str().ok_or_else(|| Error::Malformed(format!("{pp}.hashes[{i}]: not a string")))?;
                let bytes = base64_decode_strict(s).and_then(|b| Hash::try_from(b).ok());
                list.push(bytes.ok_or_else(|| Error::Malformed(format!("{pp}.hashes[{i}]: not a 32-byte hash")))?);
            }
            Some(InclusionProof {
                log_index: uint64(p, "logIndex", &pp)?,
                root_hash: hash32(p, "rootHash", &pp)?,
                tree_size: uint64(p, "treeSize", &pp)?,
                hashes: list,
                checkpoint: string(get(p, "checkpoint", &pp)?, "envelope", &format!("{pp}.checkpoint"))?,
            })
        }
    };
    let body = b64(v, "canonicalizedBody", path)?;
    Ok(LogEntry { log_index, log_id, kind, version, integrated_time, promise, proof, body })
}

fn parse_entries(list: &[Value], path: &str) -> Result<Vec<LogEntry>, Error> {
    if list.len() > MAX_ENTRIES {
        return malformed(path, "too many entries");
    }
    list.iter().enumerate().map(|(i, e)| parse_entry(e, &format!("{path}[{i}]"))).collect()
}

fn parse_bundle(v: &Value, path: &str) -> Result<Bundle, Error> {
    object(v, path)?;
    let media = string(v, "mediaType", path)?;
    let format = match media.as_str() {
        "application/vnd.dev.sigstore.bundle+json;version=0.1" => BundleFormat::V0_1,
        "application/vnd.dev.sigstore.bundle+json;version=0.2" => BundleFormat::V0_2,
        "application/vnd.dev.sigstore.bundle.v0.3+json" => BundleFormat::V0_3,
        _ => return Err(Error::Unsupported(format!("bundle media type {media:?}"))),
    };
    let vm = get(v, "verificationMaterial", path)?;
    let vpath = format!("{path}.verificationMaterial");
    object(vm, &vpath)?;

    let material = match (opt(vm, "publicKey"), opt(vm, "x509CertificateChain"), opt(vm, "certificate")) {
        (Some(k), None, None) => Material::Key { hint: string(k, "hint", &format!("{vpath}.publicKey"))? },
        (None, Some(chain), None) if format != BundleFormat::V0_3 => {
            let cp = format!("{vpath}.x509CertificateChain");
            let list = array(chain, "certificates", &cp)?;
            if list.is_empty() || list.len() > MAX_CERTIFICATES {
                return malformed(&format!("{cp}.certificates"), "empty or too long");
            }
            let mut ders = Vec::new();
            for (i, c) in list.iter().enumerate() {
                ders.push(b64(c, "rawBytes", &format!("{cp}.certificates[{i}]"))?);
            }
            Material::Certificates(ders)
        }
        (None, None, Some(c)) if format == BundleFormat::V0_3 => Material::Certificates(vec![b64(c, "rawBytes", &format!("{vpath}.certificate"))?]),
        (None, None, None) => return malformed(&vpath, "no certificate, certificate chain or public key"),
        _ => return malformed(&vpath, "the signer's material is not one thing, or not the kind this version of the format has"),
    };

    let entries = parse_entries(array(vm, "tlogEntries", &vpath)?, &format!("{vpath}.tlogEntries"))?;
    for (i, e) in entries.iter().enumerate() {
        let missing = match format {
            BundleFormat::V0_1 => e.promise.is_none().then_some("a signed entry timestamp"),
            BundleFormat::V0_2 | BundleFormat::V0_3 => e.proof.is_none().then_some("an inclusion proof"),
            BundleFormat::Pep740 => None,
        };
        if let Some(what) = missing {
            return malformed(&format!("{vpath}.tlogEntries[{i}]"), &format!("this version of the format needs {what}"));
        }
    }
    let mut timestamps = Vec::new();
    if let Some(tvd) = opt(vm, "timestampVerificationData") {
        let list = array(tvd, "rfc3161Timestamps", &format!("{vpath}.timestampVerificationData"))?;
        if list.len() > MAX_TIMESTAMPS {
            return malformed(&format!("{vpath}.timestampVerificationData.rfc3161Timestamps"), "too many");
        }
        for (i, t) in list.iter().enumerate() {
            timestamps.push(b64(t, "signedTimestamp", &format!("{vpath}.timestampVerificationData.rfc3161Timestamps[{i}]"))?);
        }
    }

    let envelope = match (opt(v, "dsseEnvelope"), opt(v, "messageSignature")) {
        (Some(e), None) => {
            let ep = format!("{path}.dsseEnvelope");
            object(e, &ep)?;
            let mut signatures = Vec::new();
            for (i, s) in array(e, "signatures", &ep)?.iter().enumerate() {
                let sp = format!("{ep}.signatures[{i}]");
                let keyid = match opt(s, "keyid") {
                    None => String::new(),
                    Some(k) => k.as_str().ok_or_else(|| Error::Malformed(format!("{sp}.keyid: not a string")))?.to_string(),
                };
                signatures.push((keyid, b64(s, "sig", &sp)?));
            }
            Envelope { payload_type: string(e, "payloadType", &ep)?, payload: b64(e, "payload", &ep)?, signatures }
        }
        (None, Some(_)) => return Err(Error::Unsupported("a bundle that signs an artifact's digest (messageSignature) instead of a statement".into())),
        _ => return malformed(path, "not exactly one of dsseEnvelope and messageSignature"),
    };
    Ok(Bundle { format, material, entries, timestamps, envelope })
}

impl Bundle {
    /// Reads one Sigstore bundle (v0.1, v0.2 or v0.3).
    pub fn parse(json_bytes: &[u8]) -> Result<Bundle, Error> {
        parse_bundle(&json::parse(json_bytes)?, "$")
    }

    /// Reads the response of the npm registry for a package version's attestations,
    /// `{"attestations": [{"predicateType": ..., "bundle": {...}}, ...]}`.
    pub fn parse_npm_attestations(json_bytes: &[u8]) -> Result<Vec<NpmAttestation>, Error> {
        let root = json::parse(json_bytes)?;
        object(&root, "$")?;
        let list = array(&root, "attestations", "$")?;
        if list.len() > MAX_ATTESTATIONS {
            return malformed("$.attestations", "too many");
        }
        let mut out = Vec::new();
        for (i, a) in list.iter().enumerate() {
            let path = format!("$.attestations[{i}]");
            object(a, &path)?;
            out.push(NpmAttestation { claimed_predicate_type: string(a, "predicateType", &path)?, bundle: parse_bundle(get(a, "bundle", &path)?, &format!("{path}.bundle"))? });
        }
        Ok(out)
    }

    /// Reads PyPI's provenance object (PEP 740): `attestation_bundles`, each with a publisher and its
    /// attestations. Every attestation comes back as a bundle, in the order of the file.
    pub fn parse_pep740(json_bytes: &[u8]) -> Result<Vec<Pep740Attestation>, Error> {
        let root = json::parse(json_bytes)?;
        object(&root, "$")?;
        match root.get("version").map(Value::as_int64) {
            Some(Some(1)) => {}
            _ => return Err(Error::Unsupported("provenance version other than 1".into())),
        }
        let mut out = Vec::new();
        for (i, group) in array(&root, "attestation_bundles", "$")?.iter().enumerate() {
            let gp = format!("$.attestation_bundles[{i}]");
            object(group, &gp)?;
            let publisher = opt(group, "publisher").cloned();
            for (j, a) in array(group, "attestations", &gp)?.iter().enumerate() {
                let path = format!("{gp}.attestations[{j}]");
                object(a, &path)?;
                if a.get("version").and_then(Value::as_int64) != Some(1) {
                    return Err(Error::Unsupported(format!("{path}: attestation version other than 1")));
                }
                if out.len() >= MAX_ATTESTATIONS {
                    return malformed("$", "too many attestations");
                }
                let vm = get(a, "verification_material", &path)?;
                let vpath = format!("{path}.verification_material");
                object(vm, &vpath)?;
                let cert = b64(vm, "certificate", &vpath)?;
                let entries = parse_entries(array(vm, "transparency_entries", &vpath)?, &format!("{vpath}.transparency_entries"))?;
                if let Some(i) = entries.iter().position(|e| e.proof.is_none()) {
                    return malformed(&format!("{vpath}.transparency_entries[{i}]"), "an entry without an inclusion proof");
                }
                let env = get(a, "envelope", &path)?;
                let epath = format!("{path}.envelope");
                let bundle = Bundle {
                    format: BundleFormat::Pep740,
                    material: Material::Certificates(vec![cert]),
                    entries,
                    timestamps: Vec::new(),
                    envelope: Envelope { payload_type: PAYLOAD_TYPE.to_string(), payload: b64(env, "statement", &epath)?, signatures: vec![(String::new(), b64(env, "signature", &epath)?)] },
                };
                out.push(Pep740Attestation { claimed_publisher: publisher.clone(), bundle });
            }
        }
        Ok(out)
    }

    /// The format.
    pub fn format(&self) -> BundleFormat {
        self.format
    }
}

impl NpmAttestation {
    /// Verifies the bundle ([`Bundle::verify`]) and that the label the registry put on it is the
    /// predicate type of the statement that was signed.
    pub fn verify(&self, trust: &Trust, artifact: &ArtifactDigest) -> Result<Verified, Error> {
        let v = self.bundle.verify(trust, artifact)?;
        if v.statement.predicate_type != self.claimed_predicate_type {
            return Err(Error::Statement(format!(
                "the registry labels the attestation {:?} but the signed statement is {:?}",
                self.claimed_predicate_type, v.statement.predicate_type
            )));
        }
        Ok(v)
    }
}

impl Pep740Attestation {
    /// Verifies the bundle ([`Bundle::verify`]).
    pub fn verify(&self, trust: &Trust, artifact: &ArtifactDigest) -> Result<Verified, Error> {
        self.bundle.verify(trust, artifact)
    }
}

// ================================================================================================ the statement

fn parse_statement(payload: &[u8]) -> Result<Statement, Error> {
    let bad = |m: &str| Error::Statement(m.to_string());
    let v = json::parse(payload).map_err(|e| Error::Statement(format!("not strict JSON: {e}")))?;
    if v.as_object().is_none() {
        return Err(bad("not an object"));
    }
    let statement_type = v.get("_type").and_then(Value::as_str).ok_or_else(|| bad("no _type"))?;
    if statement_type != "https://in-toto.io/Statement/v0.1" && statement_type != "https://in-toto.io/Statement/v1" {
        return Err(Error::Statement(format!("statement type {statement_type:?} is not known")));
    }
    let predicate_type = v.get("predicateType").and_then(Value::as_str).ok_or_else(|| bad("no predicateType"))?;
    let list = v.get("subject").and_then(Value::as_array).ok_or_else(|| bad("no subject list"))?;
    if list.is_empty() {
        return Err(bad("the subject list is empty"));
    }
    let mut subjects = Vec::new();
    for s in list {
        let name = match s.get("name") {
            None | Some(Value::Null) => None,
            Some(Value::String(n)) => Some(n.clone()),
            Some(_) => return Err(bad("a subject name is not a string")),
        };
        let digest = s.get("digest").and_then(Value::as_object).ok_or_else(|| bad("a subject has no digest"))?;
        let mut digests = Vec::new();
        for (alg, value) in digest.iter() {
            digests.push((alg.to_string(), value.as_str().ok_or_else(|| bad("a digest is not a string"))?.to_string()));
        }
        subjects.push(Subject { name, digests });
    }
    let predicate = opt(&v, "predicate").cloned();
    Ok(Statement { statement_type: statement_type.to_string(), subjects, predicate_type: predicate_type.to_string(), predicate })
}

fn hex_matches(text: &str, bytes: &[u8]) -> bool {
    text.len() == bytes.len() * 2 && text.bytes().zip(hex(bytes).bytes()).all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

// ================================================================================================ DSSE

/// DSSE's pre-authentication encoding (`DSSEv1`, the lengths in decimal), what the signature is over.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

// ================================================================================================ identity

fn fulcio_oid(n: u8) -> Vec<u8> {
    asn1::oid_from_string(&format!("1.3.6.1.4.1.57264.1.{n}")).expect("a valid OID")
}

/// A Fulcio extension's text: the first six hold raw text, the later ones a DER UTF8String.
fn fulcio_text(cert: &Certificate, n: u8) -> Result<Option<String>, Error> {
    let Some(ext) = cert.extension(&fulcio_oid(n)) else { return Ok(None) };
    let text = if n <= 6 { String::from_utf8(ext.value.clone()).ok() } else { ext.der_string() };
    match text {
        Some(t) => Ok(Some(t)),
        None => Err(Error::Certificate(format!("extension 1.3.6.1.4.1.57264.1.{n} is not text"))),
    }
}

fn identity(cert: &Certificate, chain: Vec<Vec<u8>>) -> Result<Identity, Error> {
    let username = asn1::oid_from_string("1.3.6.1.4.1.57264.1.7").expect("a valid OID");
    let mut other_names = Vec::new();
    for n in cert.subject_alt_names() {
        if let GeneralName::Other { type_id, value } = n {
            if *type_id == username {
                let mut d = Der::new(value);
                match d.next() {
                    Ok(t) if t.tag == asn1::TAG_UTF8_STRING && d.is_empty() => {
                        other_names.push(String::from_utf8(t.content.to_vec()).map_err(|_| Error::Certificate("a username in the subjectAltName is not UTF-8".into()))?)
                    }
                    _ => return Err(Error::Certificate("a username in the subjectAltName is not a UTF8String".into())),
                }
            }
        }
    }
    let issuer = match fulcio_text(cert, 8)? {
        Some(i) => Some(i),
        None => fulcio_text(cert, 1)?,
    };
    Ok(Identity {
        certificate: cert.der.clone(),
        chain,
        not_before: cert.not_before,
        not_after: cert.not_after,
        issuer,
        uris: cert.uris().map(str::to_string).collect(),
        emails: cert.email_addresses().map(str::to_string).collect(),
        other_names,
        github_workflow_trigger: fulcio_text(cert, 2)?,
        github_workflow_sha: fulcio_text(cert, 3)?,
        github_workflow_name: fulcio_text(cert, 4)?,
        github_workflow_repository: fulcio_text(cert, 5)?,
        github_workflow_ref: fulcio_text(cert, 6)?,
        build_signer_uri: fulcio_text(cert, 9)?,
        build_signer_digest: fulcio_text(cert, 10)?,
        runner_environment: fulcio_text(cert, 11)?,
        source_repository_uri: fulcio_text(cert, 12)?,
        source_repository_digest: fulcio_text(cert, 13)?,
        source_repository_ref: fulcio_text(cert, 14)?,
        source_repository_identifier: fulcio_text(cert, 15)?,
        source_repository_owner_uri: fulcio_text(cert, 16)?,
        source_repository_owner_identifier: fulcio_text(cert, 17)?,
        build_config_uri: fulcio_text(cert, 18)?,
        build_config_digest: fulcio_text(cert, 19)?,
        build_trigger: fulcio_text(cert, 20)?,
        run_invocation_uri: fulcio_text(cert, 21)?,
        source_repository_visibility_at_signing: fulcio_text(cert, 22)?,
    })
}

// ================================================================================================ log entries

/// What the entry body must say about the envelope. `signer_ders` are the DER of the certificate, or of the
/// `SubjectPublicKeyInfo` of each key that verified the signature: the body must name one of them.
fn check_body(entry: &LogEntry, env: &Envelope, signer_ders: &[&[u8]]) -> Result<(), String> {
    let body = json::parse(&entry.body).map_err(|e| format!("the entry body is not strict JSON: {e}"))?;
    if body.get("kind").and_then(Value::as_str) != Some(entry.kind.as_str()) || body.get("apiVersion").and_then(Value::as_str) != Some(entry.version.as_str()) {
        return Err("the body's kind and version are not the entry's".into());
    }
    let sig = &env.signatures[0].1;
    let spec = body.get("spec").ok_or("the body has no spec")?;
    let (payload_hash, signature, verifier, payload_type) = match (entry.kind.as_str(), entry.version.as_str()) {
        ("intoto", "0.0.2") => {
            let content = spec.get("content").ok_or("no spec.content")?;
            let envelope = content.get("envelope").ok_or("no spec.content.envelope")?;
            let sigs = envelope.get("signatures").and_then(Value::as_array).ok_or("no signatures")?;
            if sigs.len() != 1 {
                return Err("the body does not have exactly one signature".into());
            }
            // Rekor holds the signature as the Base64 text of the DSSE envelope, Base64-encoded again
            let twice = sigs[0].get("sig").and_then(Value::as_str).and_then(base64_decode_strict).and_then(|t| String::from_utf8(t).ok()).and_then(|t| base64_decode_strict(&t));
            let key = sigs[0].get("publicKey").and_then(Value::as_str).and_then(base64_decode_strict);
            (content.get("payloadHash"), twice, key, envelope.get("payloadType").and_then(Value::as_str).map(str::to_string))
        }
        ("dsse", "0.0.1") => {
            let sigs = spec.get("signatures").and_then(Value::as_array).ok_or("no signatures")?;
            if sigs.len() != 1 {
                return Err("the body does not have exactly one signature".into());
            }
            let once = sigs[0].get("signature").and_then(Value::as_str).and_then(base64_decode_strict);
            let key = sigs[0].get("verifier").and_then(Value::as_str).and_then(base64_decode_strict);
            (spec.get("payloadHash"), once, key, Some(env.payload_type.clone()))
        }
        (kind, version) => return Err(format!("entries of kind {kind} {version} are not handled")),
    };
    if payload_type.as_deref() != Some(env.payload_type.as_str()) {
        return Err("the body's payload type is not the envelope's".into());
    }
    match payload_hash {
        Some(h) if h.get("algorithm").and_then(Value::as_str) == Some("sha256") => {
            if !h.get("value").and_then(Value::as_str).is_some_and(|v| hex_matches(v, &Sha256::digest(&env.payload))) {
                return Err("the body's payload hash is not the SHA-256 of the envelope's payload".into());
            }
        }
        _ => return Err("the body has no SHA-256 payload hash".into()),
    }
    if signature.as_deref() != Some(sig.as_slice()) {
        return Err("the body's signature is not the envelope's".into());
    }
    let pem_text = verifier.and_then(|v| String::from_utf8(v).ok()).ok_or("the body has no certificate or key")?;
    let blocks = pem::parse(&pem_text);
    if blocks.len() != 1 || (blocks[0].label != "CERTIFICATE" && blocks[0].label != "PUBLIC KEY") {
        return Err("the body's certificate or key is not one PEM certificate or public key".into());
    }
    if !signer_ders.iter().any(|d| *d == blocks[0].data.as_slice()) {
        return Err("the body's certificate or key is not the signer's".into());
    }
    Ok(())
}

/// The payload a log's signed entry timestamp is over: the canonical JSON of the entry's body (as Base64),
/// integration time, log id (hex) and log index.
fn set_payload(entry: &LogEntry, integrated_time: i64) -> Result<Vec<u8>, String> {
    let mut o = json::Object::new();
    o.insert("body", Value::string(&base64_encode(&entry.body)));
    o.insert("integratedTime", Value::int(integrated_time));
    o.insert("logID", Value::string(&hex(&entry.log_id)));
    o.insert("logIndex", Value::int(i64::try_from(entry.log_index).map_err(|_| "log index too large".to_string())?));
    json::canonical(&Value::Object(o)).map_err(|e| e.to_string())
}

/// The verifier of a log's checkpoints: its key under the host name of the log.
fn checkpoint_verifier(log: &TransparencyLog) -> Result<Verifier, String> {
    let host = log.host();
    let r = match log.key.kind() {
        KeyKind::EcdsaP256 => Verifier::ecdsa_p256_spki(host, log.key.spki()),
        KeyKind::Ed25519 => match crate::x509::parse_spki(log.key.spki()) {
            Ok(PublicKey::Ed25519(k)) => Verifier::ed25519(host, &k),
            _ => return Err("the log's key is not an Ed25519 key".into()),
        },
        _ => return Err("checkpoints signed with this kind of key are not handled".into()),
    };
    r.map_err(|e| format!("the log's name {host:?} cannot name a checkpoint signer: {e}"))
}

/// Checks the inclusion proof against a checkpoint signed by `log`; returns the checkpoint's origin.
fn check_inclusion(entry: &LogEntry, proof: &InclusionProof, log: &TransparencyLog) -> Result<Inclusion, String> {
    let verifier = checkpoint_verifier(log)?;
    let opened = note::open(proof.checkpoint.as_bytes(), &[verifier]).map_err(|e| format!("the checkpoint: {e}"))?;
    let mut lines = opened.text.lines();
    let origin = lines.next().ok_or("the checkpoint has no origin")?;
    let size: u64 = lines.next().and_then(|l| l.parse().ok()).ok_or("the checkpoint's tree size is not a number")?;
    let root: Hash = lines.next().and_then(base64_decode_strict).and_then(|b| b.try_into().ok()).ok_or("the checkpoint's root hash is not a 32-byte hash")?;
    let host = log.host();
    if origin != host && !origin.strip_prefix(host).is_some_and(|r| r.starts_with(" - ")) {
        return Err(format!("the checkpoint's origin {origin:?} is not the log's ({host})"));
    }
    if size != proof.tree_size || root != proof.root_hash {
        return Err("the inclusion proof is to a tree other than the checkpoint's".into());
    }
    tlog::verify_inclusion(&proof.hashes, proof.tree_size, &proof.root_hash, proof.log_index, &tlog::record_hash(&entry.body)).map_err(|e| format!("the inclusion proof: {e}"))?;
    Ok(Inclusion { leaf_index: proof.log_index, tree_size: size, origin: origin.to_string() })
}

// ================================================================================================ time stamps

fn verify_timestamps(tokens: &[Vec<u8>], signature: &[u8], root: &TrustedRoot) -> Result<Vec<VerifiedTime>, Error> {
    let mut out = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let mut why = "the trusted root has no time-stamp authority".to_string();
        let mut found = None;
        let token = cms::timestamp_token(token).map_err(|e| Error::Timestamp(format!("time stamp {i}: {e}")))?;
        for authority in &root.timestamp_authorities {
            let (store, others) = authority.trust().map_err(|e| Error::Timestamp(e.to_string()))?;
            match cms::verify_timestamp_with(&token, signature, &store, false, &others) {
                Ok(t) if authority.valid_for.contains(t.time) => {
                    found = Some(VerifiedTime { time: t.time, source: TimeSource::TimeStamp { authority: authority.common_name.clone() } });
                    break;
                }
                Ok(t) => why = format!("made at {} by {}, outside its validity", t.time, authority.common_name),
                Err(e) => why = e.to_string(),
            }
        }
        match found {
            Some(t) => out.push(t),
            None => return Err(Error::Timestamp(format!("time stamp {i}: {why}"))),
        }
    }
    Ok(out)
}

// ================================================================================================ verification

enum Signing {
    Certificate(Box<Certificate>),
    Keys(Vec<RingKey>),
}

impl Bundle {
    /// Verifies the bundle against `trust` and checks that it is about `artifact`. See the module
    /// documentation for exactly what that means.
    pub fn verify(&self, trust: &Trust, artifact: &ArtifactDigest) -> Result<Verified, Error> {
        let env = &self.envelope;
        if env.payload_type != PAYLOAD_TYPE {
            return Err(Error::PayloadType(env.payload_type.clone()));
        }
        if env.signatures.len() != 1 {
            return Err(Error::Malformed("the envelope does not have exactly one signature".into()));
        }
        let (keyid, signature) = &env.signatures[0];
        let signed = pae(&env.payload_type, &env.payload);

        // 1. the signature, by the key of the certificate or of the ring
        let signing = match &self.material {
            Material::Certificates(chain) => {
                let leaf = Certificate::from_der(&chain[0]).map_err(|e| Error::Certificate(e.to_string()))?;
                if !trust_root::verify_signature(&leaf.public_key, &signed, signature) {
                    return Err(Error::Signature);
                }
                Signing::Certificate(Box::new(leaf))
            }
            Material::Key { hint } => {
                let id = if hint.is_empty() { keyid } else { hint };
                if id.is_empty() {
                    return Err(Error::UnknownKey(String::new()));
                }
                let candidates: Vec<&RingKey> = trust.keys.map(|k| k.with_id(id).collect()).unwrap_or_default();
                if candidates.is_empty() {
                    return Err(Error::UnknownKey(id.clone()));
                }
                let good: Vec<RingKey> = candidates.into_iter().filter(|k| k.key.verify(&signed, signature)).cloned().collect();
                if good.is_empty() {
                    return Err(Error::Signature);
                }
                Signing::Keys(good)
            }
        };

        // 2. the statement
        let statement = parse_statement(&env.payload)?;

        // 3. the entries: bound to this envelope, authenticated by a signed entry timestamp where there is one
        let signer_ders: Vec<&[u8]> = match &signing {
            Signing::Certificate(c) => vec![c.der.as_slice()],
            Signing::Keys(keys) => keys.iter().map(|k| k.key.spki()).collect(),
        };
        if self.entries.is_empty() {
            return Err(Error::Entry { log_index: 0, reason: "the bundle has no transparency log entry".into() });
        }
        let mut times: Vec<VerifiedTime> = Vec::new();
        let mut set_verified = vec![false; self.entries.len()];
        for (i, entry) in self.entries.iter().enumerate() {
            let fail = |reason: String| Error::Entry { log_index: entry.log_index, reason };
            check_body(entry, env, &signer_ders).map_err(fail)?;
            if self.entries[..i].iter().any(|e| e.body == entry.body && e.log_id == entry.log_id) {
                return Err(fail("the same entry is in the bundle twice".into()));
            }
            let logs: Vec<&TransparencyLog> = trust.root.tlogs_with_id(&entry.log_id).collect();
            if logs.is_empty() {
                return Err(fail(format!("no log with id {} in the trusted root", hex(&entry.log_id))));
            }
            if let Some(promise) = &entry.promise {
                let t = entry.integrated_time.ok_or_else(|| fail("a signed entry timestamp but no integration time".into()))?;
                let payload = set_payload(entry, t).map_err(fail)?;
                if !logs.iter().any(|l| l.valid_for.contains(t) && l.key.verify(&payload, promise)) {
                    return Err(fail("the signed entry timestamp is not by a trusted key of the log valid at the integration time".into()));
                }
                set_verified[i] = true;
                times.push(VerifiedTime { time: t, source: TimeSource::LogEntry { log_index: entry.log_index } });
            }
            if entry.promise.is_none() && entry.proof.is_none() {
                return Err(fail("neither a signed entry timestamp nor an inclusion proof".into()));
            }
        }

        // 4. time stamps
        times.extend(verify_timestamps(&self.timestamps, signature, trust.root)?);
        if times.is_empty() {
            return Err(Error::NoVerifiedTime);
        }
        times.sort_by_key(|t| t.time);

        // 5a. the inclusion proofs, now that there are times to check the logs' keys at
        let mut entries = Vec::new();
        for (i, entry) in self.entries.iter().enumerate() {
            let fail = |reason: String| Error::Entry { log_index: entry.log_index, reason };
            let logs: Vec<&TransparencyLog> = trust.root.tlogs_with_id(&entry.log_id).collect();
            let mut inclusion = None;
            let mut used = logs[0];
            if let Some(proof) = &entry.proof {
                let mut last = String::from("no key of the log was valid when the bundle was signed");
                for log in logs.iter().filter(|l| times.iter().any(|t| l.valid_for.contains(t.time))) {
                    match check_inclusion(entry, proof, log) {
                        Ok(i) => {
                            inclusion = Some(i);
                            used = log;
                            break;
                        }
                        Err(e) => last = e,
                    }
                }
                if inclusion.is_none() {
                    return Err(fail(last));
                }
            }
            entries.push(VerifiedEntry {
                log_index: entry.log_index,
                log_id: entry.log_id.clone(),
                log_url: used.base_url.clone(),
                kind: entry.kind.clone(),
                version: entry.version.clone(),
                integrated_time: if set_verified[i] { entry.integrated_time } else { None },
                signed_entry_timestamp: set_verified[i],
                inclusion,
            });
        }

        // 5b. the signer, at a time that was established
        let (signer, verified_time) = match &signing {
            Signing::Certificate(leaf) => {
                let Material::Certificates(chain) = &self.material else { unreachable!("a certificate was read from certificates") };
                let (id, t) = verify_certificate(leaf, &chain[1..], trust.root, &times)?;
                (Signer::Certificate(Box::new(id)), t)
            }
            Signing::Keys(keys) => {
                let found = times.iter().find_map(|t| keys.iter().find(|k| k.valid_for.contains(t.time)).map(|k| (k, t.time)));
                match found {
                    Some((k, t)) => (Signer::Key { id: k.id.clone(), spki_sha256: k.key.sha256() }, t),
                    None => return Err(Error::KeyNotValid(keys[0].id.clone())),
                }
            }
        };

        // 5c. the certificate's signed certificate timestamps, with the issuer the chain was built through
        let scts = match &signer {
            Signer::Certificate(id) => check_scts(&id.certificate, &id.chain, trust)?,
            Signer::Key { .. } => Vec::new(),
        };

        // 6. the subject
        let matched_subject = statement
            .subjects
            .iter()
            .position(|s| s.digests.iter().any(|(alg, value)| alg == artifact.algorithm.name() && hex_matches(value, &artifact.digest)))
            .ok_or(Error::SubjectMismatch)?;

        Ok(Verified { format: self.format, signer, statement, matched_subject, verified_time, times, entries, scts })
    }
}

/// Checks the SCTs embedded in a signing certificate (`chain` is the verified path from it, the issuer second) against
/// the root's CT logs and requires them from `trust.sct_threshold` logs.
fn check_scts(leaf: &[u8], chain: &[Vec<u8>], trust: &Trust) -> Result<Vec<ct::VerifiedSct>, Error> {
    let fail = |m: String| Error::CertificateTransparency(m);
    let leaf = Certificate::parse(leaf).map_err(|e| fail(e.to_string()))?;
    let Some(issuer) = chain.get(1) else { return Err(fail("the certificate is itself a trust anchor: it has no issuer to check SCTs with".into())) };
    let issuer = Certificate::parse(issuer).map_err(|e| fail(e.to_string()))?;
    let report = ct::verify_embedded(&leaf, &issuer, &trust.root.ctlogs).map_err(|e| fail(e.to_string()))?;
    let logs = report.distinct_logs();
    if logs < trust.sct_threshold {
        let seen = ct::embedded(&leaf).map(|l| l.scts.len() + l.other_versions).unwrap_or(0);
        return Err(fail(format!(
            "signed certificate timestamps from {logs} of the trusted root's CT logs verified and {} are required (the certificate has {seen}, {} from logs the root does not list)",
            trust.sct_threshold,
            report.unknown_logs.len()
        )));
    }
    Ok(report.verified)
}

/// Finds the earliest of `times` at which the certificate verifies under some Fulcio authority that counts
/// then, and describes it.
fn verify_certificate(leaf: &Certificate, bundle_extra: &[Vec<u8>], root: &TrustedRoot, times: &[VerifiedTime]) -> Result<(Identity, i64), Error> {
    if root.certificate_authorities.is_empty() {
        return Err(Error::Certificate("the trusted root has no certificate authority".into()));
    }
    let mut why = String::from("no certificate authority of the trusted root counts at any time the bundle established");
    for t in times {
        for ca in root.certificate_authorities.iter().filter(|c| c.valid_for.contains(t.time)) {
            let (store, others) = ca.trust().map_err(|e| Error::Certificate(e.to_string()))?;
            let mut chain: Vec<&[u8]> = vec![&leaf.der];
            chain.extend(bundle_extra.iter().map(Vec::as_slice));
            chain.extend(others.iter().map(|c| c.der.as_slice()));
            match store.verify_chain(&chain, &VerifyOptions::new(Purpose::CodeSigning, t.time)) {
                Ok(v) => return Ok((identity(leaf, v.path)?, t.time)),
                Err(e) => why = format!("at {}: {e}", t.time),
            }
        }
    }
    Err(Error::Certificate(why))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 zero bytes.
    const HASH32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn entry_json() -> String {
        format!(
            r#"{{"logIndex":"7","logId":{{"keyId":"AQID"}},"kindVersion":{{"kind":"dsse","version":"0.0.1"}},"integratedTime":"1700000000","canonicalizedBody":"AQID","inclusionProof":{{"logIndex":"3","rootHash":"{HASH32}","treeSize":"9","hashes":[],"checkpoint":{{"envelope":"x"}}}}}}"#
        )
    }

    fn bundle_json(media: &str, material: &str, entries: &[String], envelope: &str) -> String {
        format!(r#"{{"mediaType":"{media}","verificationMaterial":{{{material},"tlogEntries":[{}]}},{envelope}}}"#, entries.join(","))
    }

    const V03: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
    const CERT: &str = r#""certificate":{"rawBytes":"AQID"}"#;
    const ENVELOPE: &str = r#""dsseEnvelope":{"payload":"AQID","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AQID"}]}"#;

    fn v03(entries: &[String]) -> String {
        bundle_json(V03, CERT, entries, ENVELOPE)
    }

    fn parse(text: &str) -> Result<Bundle, Error> {
        Bundle::parse(text.as_bytes())
    }

    fn parse_error(text: &str) -> String {
        match parse(text) {
            Ok(_) => panic!("{text} was accepted"),
            Err(e) => e.to_string(),
        }
    }

    fn entry_error(text: &str) -> String {
        match parse_entry(&json::parse(text.as_bytes()).unwrap(), "$") {
            Ok(_) => panic!("{text} was accepted"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn the_pre_authentication_encoding_is_the_one_in_the_dsse_specification() {
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
        // lengths count bytes, not characters
        assert_eq!(pae("é", "ü".as_bytes()), "DSSEv1 2 é 2 ü".as_bytes());
    }

    #[test]
    fn the_smallest_bundle_is_read_into_its_parts() {
        let b = parse(&v03(&[entry_json()])).unwrap();
        assert_eq!(b.format(), BundleFormat::V0_3);
        assert_eq!(b.entries.len(), 1);
        let e = &b.entries[0];
        assert_eq!((e.log_index, e.integrated_time, e.kind.as_str(), e.version.as_str()), (7, Some(1_700_000_000), "dsse", "0.0.1"));
        assert_eq!((e.log_id.as_slice(), e.body.as_slice()), (&[1u8, 2, 3][..], &[1u8, 2, 3][..]));
        let p = e.proof.as_ref().unwrap();
        assert_eq!((p.log_index, p.tree_size, p.hashes.len(), p.checkpoint.as_str()), (3, 9, 0, "x"));
        assert_eq!(b.envelope.signatures, [(String::new(), vec![1, 2, 3])]);
        assert!(b.timestamps.is_empty());
        assert!(matches!(b.material, Material::Certificates(ref c) if c.len() == 1));
    }

    #[test]
    fn integers_are_json_numbers_or_decimal_strings() {
        let with = |idx: &str| entry_json().replace(r#""logIndex":"7""#, &format!(r#""logIndex":{idx}"#));
        assert_eq!(parse_entry(&json::parse(with("7").as_bytes()).unwrap(), "$").unwrap().log_index, 7);
        assert_eq!(parse_entry(&json::parse(with(r#""7""#).as_bytes()).unwrap(), "$").unwrap().log_index, 7);
        assert_eq!(parse_entry(&json::parse(with(r#""18446744073709551615""#).as_bytes()).unwrap(), "$").unwrap().log_index, u64::MAX);
        for bad in ["-1", "1.5", "1e2", r#""07""#, r#""+7""#, r#""-1""#, r#"" 7""#, r#""18446744073709551616""#, r#""""#, "true", "null", "[]", r#""0x7""#] {
            let m = entry_error(&with(bad));
            assert!(m.contains("logIndex"), "{bad}: {m}");
        }
    }

    #[test]
    fn an_integration_time_is_a_positive_integer_and_zero_is_none() {
        let with = |t: &str| entry_json().replace(r#""integratedTime":"1700000000""#, &format!(r#""integratedTime":{t}"#));
        let time = |t: &str| parse_entry(&json::parse(with(t).as_bytes()).unwrap(), "$").map(|e| e.integrated_time);
        assert_eq!(time(r#""1700000000""#), Ok(Some(1_700_000_000)));
        assert_eq!(time("1700000000"), Ok(Some(1_700_000_000)));
        assert_eq!(time(r#""0""#), Ok(None));
        assert_eq!(time("null"), Ok(None));
        for bad in [r#""-5""#, "-5", r#""x""#, "1.5", "[]"] {
            assert!(time(bad).unwrap_err().to_string().contains("integratedTime"), "{bad}");
        }
        let without = entry_json().replace(r#""integratedTime":"1700000000","#, "");
        assert_eq!(parse_entry(&json::parse(without.as_bytes()).unwrap(), "$").unwrap().integrated_time, None);
    }

    #[test]
    fn null_is_the_same_as_absent() {
        let with_null = entry_json().replace(r#""inclusionProof":{"#, r#""inclusionPromise":null,"inclusionProof":null,"x":{"#);
        let e = parse_entry(&json::parse(with_null.as_bytes()).unwrap(), "$").unwrap();
        assert!(e.proof.is_none() && e.promise.is_none());
        // and a bundle whose time stamp data is null has none
        let text = v03(&[entry_json()]).replace(r#""tlogEntries""#, r#""timestampVerificationData":null,"tlogEntries""#);
        assert!(parse(&text).unwrap().timestamps.is_empty());
    }

    #[test]
    fn base64_must_be_the_canonical_padded_form() {
        let with = |b: &str| entry_json().replace(r#""canonicalizedBody":"AQID""#, &format!(r#""canonicalizedBody":"{b}""#));
        let body = |b: &str| parse_entry(&json::parse(with(b).as_bytes()).unwrap(), "$");
        assert_eq!(body("AQI=").unwrap().body, [1, 2]);
        assert_eq!(body("AQ==").unwrap().body, [1]);
        assert_eq!(body("").unwrap().body, Vec::<u8>::new());
        for bad in ["AQI", "AQ", "A", "AQID\\n", "AQ ID", "AQ-_", "AQJ=", "AR==", "AQI==", "====", "AQID AQID", "AQ\\u0000D", "ÀQID"] {
            let m = body(bad).unwrap_err().to_string();
            assert!(m.contains("canonicalizedBody"), "{bad}: {m}");
        }
    }

    #[test]
    fn a_hash_has_32_bytes() {
        let with = |h: &str| entry_json().replace(HASH32, h);
        let m = entry_error(&with("AQID"));
        assert!(m.contains("rootHash") && m.contains("32-byte"), "{m}");
        let m = entry_error(&entry_json().replace(r#""hashes":[]"#, r#""hashes":["AQID"]"#));
        assert!(m.contains("hashes[0]"), "{m}");
        let m = entry_error(&entry_json().replace(r#""hashes":[]"#, r#""hashes":[7]"#));
        assert!(m.contains("hashes[0]"), "{m}");
        let ok = entry_json().replace(r#""hashes":[]"#, &format!(r#""hashes":["{HASH32}","{HASH32}"]"#));
        assert_eq!(parse_entry(&json::parse(ok.as_bytes()).unwrap(), "$").unwrap().proof.unwrap().hashes.len(), 2);
    }

    #[test]
    fn the_numbers_of_things_in_a_bundle_are_limited() {
        let entries: Vec<String> = (0..MAX_ENTRIES).map(|_| entry_json()).collect();
        assert_eq!(parse(&v03(&entries)).unwrap().entries.len(), MAX_ENTRIES);
        let entries: Vec<String> = (0..=MAX_ENTRIES).map(|_| entry_json()).collect();
        assert!(parse_error(&v03(&entries)).contains("too many"));

        let hashes = vec![format!("\"{HASH32}\""); MAX_PROOF_HASHES + 1].join(",");
        let m = entry_error(&entry_json().replace(r#""hashes":[]"#, &format!(r#""hashes":[{hashes}]"#)));
        assert!(m.contains("too many"), "{m}");

        let stamps = vec![r#"{"signedTimestamp":"AQID"}"#; MAX_TIMESTAMPS + 1].join(",");
        let text = v03(&[entry_json()]).replace(r#""tlogEntries""#, &format!(r#""timestampVerificationData":{{"rfc3161Timestamps":[{stamps}]}},"tlogEntries""#));
        assert!(parse_error(&text).contains("too many"));

        let certs = vec![r#"{"rawBytes":"AQID"}"#; MAX_CERTIFICATES + 1].join(",");
        let text = bundle_json("application/vnd.dev.sigstore.bundle+json;version=0.2", &format!(r#""x509CertificateChain":{{"certificates":[{certs}]}}"#), &[entry_json()], ENVELOPE);
        assert!(parse_error(&text).contains("empty or too long"));
        let text = bundle_json("application/vnd.dev.sigstore.bundle+json;version=0.2", r#""x509CertificateChain":{"certificates":[]}"#, &[entry_json()], ENVELOPE);
        assert!(parse_error(&text).contains("empty or too long"));
    }

    #[test]
    fn a_bundle_is_strict_json_with_unique_names() {
        let m = parse_error(&v03(&[entry_json()]).replacen(r#""mediaType""#, r#""mediaType":"x","mediaType""#, 1));
        assert!(m.contains("not strict JSON") && m.contains("twice"), "{m}");
        assert!(matches!(parse("").unwrap_err(), Error::Json(_)));
        assert!(matches!(parse("{").unwrap_err(), Error::Json(_)));
        assert!(matches!(parse("{} {}").unwrap_err(), Error::Json(_)));
        assert!(parse_error("[]").contains("not an object"));
        assert!(parse_error("{}").contains("mediaType"));
        // a lone surrogate in a string is not text
        assert!(matches!(parse(r#"{"mediaType":"\ud800"}"#).unwrap_err(), Error::Json(_)));
        // unknown members are ignored
        let text = v03(&[entry_json()]).replacen('{', r#"{"future":{"anything":[1,2,3]},"#, 1);
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_bundle_has_one_kind_of_signer_and_the_kind_its_version_allows() {
        let media = |v: &str| format!("application/vnd.dev.sigstore.bundle+json;version={v}");
        let chain = r#""x509CertificateChain":{"certificates":[{"rawBytes":"AQID"}]}"#;
        let key = r#""publicKey":{"hint":"abc"}"#;
        let e = [entry_json()];
        let proof_less = [entry_json().replace(r#""inclusionProof":"#, r#""inclusionPromise":{"signedEntryTimestamp":"AQID"},"x":"#)];
        assert!(matches!(parse(&bundle_json(&media("0.1"), chain, &proof_less, ENVELOPE)).unwrap().material, Material::Certificates(_)));
        assert!(matches!(parse(&bundle_json(&media("0.2"), key, &e, ENVELOPE)).unwrap().material, Material::Key { ref hint } if hint == "abc"));
        assert!(matches!(parse(&bundle_json(V03, key, &e, ENVELOPE)).unwrap().material, Material::Key { .. }));
        for (media, material) in [(media("0.2"), CERT), (V03.to_string(), chain), (media("0.2"), r#""x":1"#), (V03.to_string(), &format!("{CERT},{key}")[..])] {
            let m = parse_error(&bundle_json(&media, material, &e, ENVELOPE));
            assert!(m.contains("verificationMaterial"), "{m}");
        }
        assert!(parse_error(&bundle_json("application/vnd.dev.sigstore.bundle+json;version=0.4", CERT, &e, ENVELOPE)).contains("unsupported"));
        assert!(parse_error(&bundle_json("", CERT, &e, ENVELOPE)).contains("unsupported"));
    }

    #[test]
    fn a_bundle_has_an_envelope_or_it_is_not_handled() {
        let e = [entry_json()];
        let msg = parse_error(&bundle_json(V03, CERT, &e, r#""messageSignature":{}"#));
        assert!(msg.contains("messageSignature"), "{msg}");
        let msg = parse_error(&bundle_json(V03, CERT, &e, r#""x":1"#));
        assert!(msg.contains("exactly one"), "{msg}");
        let both = format!("{ENVELOPE},\"messageSignature\":{{}}");
        assert!(parse_error(&bundle_json(V03, CERT, &e, &both)).contains("exactly one"));
        // an envelope with no signatures reads, and is refused by verification
        let none = ENVELOPE.replace(r#"[{"sig":"AQID"}]"#, "[]");
        assert!(parse(&bundle_json(V03, CERT, &e, &none)).unwrap().envelope.signatures.is_empty());
        let bad = ENVELOPE.replace(r#"{"sig":"AQID"}"#, r#"{"sig":"AQID","keyid":5}"#);
        assert!(parse_error(&bundle_json(V03, CERT, &e, &bad)).contains("keyid"));
        let keyed = ENVELOPE.replace(r#"{"sig":"AQID"}"#, r#"{"sig":"AQID","keyid":"SHA256:x"}"#);
        assert_eq!(parse(&bundle_json(V03, CERT, &e, &keyed)).unwrap().envelope.signatures[0].0, "SHA256:x");
    }

    #[test]
    fn the_npm_response_is_a_list_of_labelled_bundles() {
        let bundle = v03(&[entry_json()]);
        let list = |s: &str| Bundle::parse_npm_attestations(s.as_bytes());
        let ok = list(&format!(r#"{{"attestations":[{{"predicateType":"https://slsa.dev/provenance/v1","bundle":{bundle}}}]}}"#)).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].claimed_predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(ok[0].bundle.format(), BundleFormat::V0_3);
        assert!(list(r#"{"attestations":[]}"#).unwrap().is_empty());
        assert!(list("{}").unwrap().is_empty());
        for bad in [r#"{"attestations":{}}"#, r#"{"attestations":[1]}"#, "[]", r#"{"attestations":[{"bundle":{}}]}"#] {
            assert!(matches!(list(bad), Err(Error::Malformed(_))), "{bad}");
        }
        assert!(matches!(list(r#"{"attestations":[{"predicateType":"x"}]}"#), Err(Error::Malformed(_))));
        assert!(matches!(list(&format!(r#"{{"attestations":[{{"predicateType":7,"bundle":{bundle}}}]}}"#)), Err(Error::Malformed(_))));
        let many = vec![format!(r#"{{"predicateType":"x","bundle":{bundle}}}"#); MAX_ATTESTATIONS + 1].join(",");
        assert!(matches!(list(&format!(r#"{{"attestations":[{many}]}}"#)), Err(Error::Malformed(m)) if m.contains("too many")));
    }

    fn pep740(attestation: &str) -> String {
        format!(r#"{{"version":1,"attestation_bundles":[{{"publisher":{{"kind":"GitHub"}},"attestations":[{attestation}]}}]}}"#)
    }

    fn pep740_attestation() -> String {
        format!(
            r#"{{"version":1,"verification_material":{{"certificate":"AQID","transparency_entries":[{}]}},"envelope":{{"statement":"AQID","signature":"AQID"}}}}"#,
            entry_json()
        )
    }

    #[test]
    fn pep_740_provenance_is_read_into_bundles_with_the_publisher_kept_as_a_claim() {
        let list = Bundle::parse_pep740(pep740(&pep740_attestation()).as_bytes()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].bundle.format(), BundleFormat::Pep740);
        assert_eq!(list[0].bundle.envelope.payload_type, PAYLOAD_TYPE);
        assert_eq!(list[0].claimed_publisher.as_ref().and_then(|p| p.get("kind")).and_then(Value::as_str), Some("GitHub"));
        assert!(Bundle::parse_pep740(br#"{"version":1,"attestation_bundles":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn pep_740_provenance_of_another_version_or_without_proofs_is_refused() {
        let ok = pep740_attestation();
        let parse = |s: String| Bundle::parse_pep740(s.as_bytes());
        assert!(matches!(parse(pep740(&ok).replace(r#""version":1,"attestation_bundles""#, r#""version":2,"attestation_bundles""#)), Err(Error::Unsupported(_))));
        assert!(matches!(parse(r#"{"attestation_bundles":[]}"#.to_string()), Err(Error::Unsupported(_))));
        assert!(matches!(parse(pep740(&ok.replacen(r#""version":1"#, r#""version":2"#, 1))), Err(Error::Unsupported(_))));
        // an entry without its inclusion proof has nothing to be authenticated by here
        let no_proof = ok.replace(r#""inclusionProof":{"logIndex":"3""#, r#""x":{"logIndex":"3""#);
        assert!(matches!(parse(pep740(&no_proof)), Err(Error::Malformed(m)) if m.contains("inclusion proof")));
        assert!(matches!(parse(pep740(&ok.replace(r#""certificate":"AQID""#, r#""certificate":"AQI""#))), Err(Error::Malformed(_))));
        assert!(matches!(parse(pep740(&ok.replace(r#""statement":"AQID""#, r#""statement":7"#))), Err(Error::Malformed(_))));
        assert!(matches!(parse("[]".to_string()), Err(Error::Malformed(_))));
    }

    #[test]
    fn a_statement_is_in_toto_with_subjects_that_have_digests() {
        let s = parse_statement(br#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"ab","sha512":"cd"}},{"digest":{"sha1":"ef"}}],"predicateType":"https://example.test/p","predicate":{"x":1}}"#).unwrap();
        assert_eq!(s.statement_type, "https://in-toto.io/Statement/v1");
        assert_eq!(s.predicate_type, "https://example.test/p");
        assert_eq!(s.subjects.len(), 2);
        assert_eq!(s.subjects[0].name.as_deref(), Some("a"));
        assert_eq!(s.subjects[0].digests, [("sha256".to_string(), "ab".to_string()), ("sha512".to_string(), "cd".to_string())]);
        assert_eq!(s.subjects[1].name, None);
        assert!(s.predicate.is_some());
        let none = parse_statement(br#"{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"digest":{}}],"predicateType":"p","predicate":null}"#).unwrap();
        assert!(none.predicate.is_none() && none.subjects[0].digests.is_empty());
        for bad in [
            "[]",
            r#"{"subject":[{"digest":{}}],"predicateType":"p"}"#,
            r#"{"_type":7,"subject":[{"digest":{}}],"predicateType":"p"}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"p"}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{}}]}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":{},"predicateType":"p"}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":5,"digest":{}}],"predicateType":"p"}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":[]}],"predicateType":"p"}"#,
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"a","sha256":"b"}}],"predicateType":"p"}"#,
        ] {
            assert!(matches!(parse_statement(bad.as_bytes()), Err(Error::Statement(_))), "{bad}");
        }
    }

    #[test]
    fn digests_compare_as_hex_without_regard_to_case() {
        assert!(hex_matches("00ff", &[0, 255]));
        assert!(hex_matches("00FF", &[0, 255]));
        assert!(hex_matches("", &[]));
        assert!(!hex_matches("00f", &[0, 255]));
        assert!(!hex_matches("00ff00", &[0, 255]));
        assert!(!hex_matches("00fe", &[0, 255]));
        assert!(!hex_matches("00fg", &[0, 255]));
        assert!(!hex_matches("0 ff", &[0, 255]));
        // not the same bytes in another spelling: the multi-byte letter
        assert!(!hex_matches("00ｆｆ", &[0, 255]));
    }

    #[test]
    fn an_artifact_digest_has_the_length_of_its_algorithm() {
        for (alg, len) in [(DigestAlgorithm::Sha256, 32), (DigestAlgorithm::Sha384, 48), (DigestAlgorithm::Sha512, 64)] {
            assert!(ArtifactDigest::new(alg, &vec![0; len]).is_ok());
            assert!(ArtifactDigest::new(alg, &vec![0; len - 1]).is_err());
            assert!(ArtifactDigest::new(alg, &vec![0; len + 1]).is_err());
            let d = ArtifactDigest::of(alg, b"abc");
            assert_eq!((d.algorithm(), d.bytes().len()), (alg, len));
        }
        let sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex(ArtifactDigest::of(DigestAlgorithm::Sha256, b"abc").bytes()), sha256_abc);
        assert_eq!(DigestAlgorithm::Sha384.name(), "sha384");
    }

    #[test]
    fn the_repository_and_ref_of_an_identity_fall_back_to_the_old_github_extensions_only_for_github() {
        let mut id = Identity::default();
        assert_eq!((id.repository(), id.git_ref()), (None, None));
        id.github_workflow_repository = Some("o/r".into());
        id.github_workflow_ref = Some("refs/heads/main".into());
        assert_eq!(id.repository(), None, "the old extensions mean GitHub only when GitHub's issuer says so");
        id.issuer = Some("https://accounts.example.test".into());
        assert_eq!(id.repository(), None);
        id.issuer = Some(GITHUB_ACTIONS_ISSUER.into());
        assert_eq!(id.repository().as_deref(), Some("https://github.com/o/r"));
        assert_eq!(id.git_ref(), Some("refs/heads/main"));
        id.source_repository_uri = Some("https://github.com/x/y".into());
        id.source_repository_ref = Some("refs/tags/v1".into());
        assert_eq!(id.repository().as_deref(), Some("https://github.com/x/y"));
        assert_eq!(id.git_ref(), Some("refs/tags/v1"));
    }

    #[test]
    fn every_error_says_what_it_is() {
        let errors = [
            Error::Json(json::Error { offset: 0, kind: json::ErrorKind::Eof }),
            Error::Malformed("a".into()),
            Error::Unsupported("b".into()),
            Error::PayloadType("c".into()),
            Error::Signature,
            Error::UnknownKey("d".into()),
            Error::Entry { log_index: 5, reason: "e".into() },
            Error::Timestamp("f".into()),
            Error::NoVerifiedTime,
            Error::Certificate("g".into()),
            Error::KeyNotValid("h".into()),
            Error::Statement("i".into()),
            Error::SubjectMismatch,
        ];
        let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
        for (i, t) in texts.iter().enumerate() {
            assert!(!t.is_empty());
            assert!(texts.iter().enumerate().all(|(j, o)| i == j || o != t), "{t}");
        }
        assert!(texts[6].contains("5") && texts[6].contains('e'));
    }
}
