//! Certificate revocation: OCSP stapling (RFC 6960, and RFC 8446 section 4.4.2.1 for how TLS 1.3
//! carries it) and certificate revocation lists (RFC 5280 section 5).
//!
//! # Policy
//!
//! The TLS client's `ClientConfig::revocation` (with the `net` feature) holds a [`Revocation`], whose
//! [`RevocationMode`] says what to do with the evidence there is:
//!
//! * [`Off`](RevocationMode::Off): nothing is checked and the server is not asked for a staple.
//! * [`SoftFail`](RevocationMode::SoftFail) (the default): the ClientHello asks for a stapled OCSP
//!   response, and the staple, any CRLs the caller supplied and any CRL fetched through a
//!   [`CrlSource`] are used. A certificate they show to be revoked fails the handshake. Evidence
//!   that is missing, malformed, unsigned by the right key or out of date is ignored, because the
//!   server (or the network) cannot be trusted to supply it, except that a leaf certificate marked
//!   *must-staple* (RFC 7633) fails the handshake if its staple is not a valid one.
//! * [`HardFail`](RevocationMode::HardFail): as soft-fail, and in addition the leaf must be shown
//!   *not* revoked by a valid OCSP staple saying "good" or by a valid CRL that covers it and does
//!   not list it. Without that the handshake fails. Use it where connections to hosts that staple
//!   nothing and publish no CRL may be refused.
//!
//! Where the evidence comes from: what the server staples, the CRLs the caller supplies, and two kinds of source that are
//! asked when those do not settle a certificate: an [`OcspSource`] (asked first, at the responders the certificate's
//! Authority Information Access names, with a request from [`ocsp_request`]) and a [`CrlSource`] (at its CRL distribution
//! points). Plain `http://` URLs only, and whatever a source returns is verified like the rest.
//!
//! By default the sources are asked about the leaf only, and hard-fail requires evidence for the leaf only;
//! [`Revocation::whole_chain`] extends both to every certificate below the trust anchor. Evidence for an intermediate that
//! is there anyway (a per-certificate staple, a CRL the caller supplied) is always used: a revoked intermediate always fails.
//!
//! What is verified: an OCSP response must be signed by the certificate's issuer, or by a
//! responder certificate the issuer signed that carries the OCSP-signing extended key usage;
//! it must name this certificate (issuer name hash, issuer key hash and serial number) and be
//! within its `thisUpdate` / `nextUpdate` window (five minutes of clock skew allowed). A CRL must
//! be signed by the issuer, in its window, and its issuing-distribution-point scope must cover the
//! certificate; CRLs this library cannot interpret (delta, indirect, partial-reason) are never
//! used. SHA-1 signatures are rejected; SHA-1 is used only to compare the hashes OCSP uses to name
//! a certificate.
//!
//! This module does no I/O: the sources are the caller's (with the `net` feature, `http::HttpOcspSource` and
//! `http::HttpCrlSource`, which keep what they fetched until it goes out of date). Delta CRLs, indirect CRLs and CRLs
//! partitioned by reason are not interpreted and never used (public CAs do not issue them; one that a source returns counts
//! as no evidence).

use crate::asn1::{self, Der};
use crate::crypto::sha1;
use crate::crypto::sha2::HashAlg;
use crate::verify_error::{Error, Result};
use crate::pem;
use crate::x509::{self, Certificate, SigAlg, KU_CRL_SIGN, OID_EKU_OCSP_SIGNING};
use std::collections::HashMap;
use std::sync::Arc;

/// How much a clock may differ from a response's `thisUpdate` before it counts as from the future.
const CLOCK_SKEW: i64 = 300;
/// With no `nextUpdate` (which RFC 5280 and RFC 6960 profiles require), evidence is trusted for this
/// long after `thisUpdate`.
const MAX_AGE_WITHOUT_NEXT_UPDATE: i64 = 7 * 86_400;

const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OID_HASH_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_HASH_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_HASH_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_HASH_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

const OID_CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
const OID_REASON_CODE: &[u8] = &[0x55, 0x1d, 0x15];
const OID_INVALIDITY_DATE: &[u8] = &[0x55, 0x1d, 0x18];
const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
const OID_CERTIFICATE_ISSUER: &[u8] = &[0x55, 0x1d, 0x1d];
const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
const OID_FRESHEST_CRL: &[u8] = &[0x55, 0x1d, 0x2e];
const OID_AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

/// What to do about revocation. See the [module documentation](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationMode {
    /// Do not check, and do not ask for a stapled OCSP response.
    Off,
    /// Fail on evidence of revocation (and on a missing must-staple staple); ignore absent or
    /// unusable evidence. The default.
    SoftFail,
    /// Also require valid evidence that the leaf is not revoked.
    HardFail,
}

/// A source of CRLs for certificates the caller did not supply one for: given the URL from a
/// certificate's CRL distribution points, returns the list.
///
/// `fetch` is called synchronously during the TLS handshake of the blocking client, on the thread that drives it, for the
/// leaf certificate (and the intermediates, with [`Revocation::whole_chain`]) and only if no valid evidence for it has been
/// found yet; the async client asks its sources on its worker pool after the handshake instead, so that the executor's
/// thread never waits for them. Whatever `fetch` returns is verified (signature, window, scope) like any other CRL, so it
/// does not have to come over a trusted channel.
pub trait CrlSource: Send + Sync {
    fn fetch(&self, url: &str) -> Result<Arc<Crl>>;
}

/// A way to ask an OCSP responder (RFC 6960): given the responder's URL (from the certificate's Authority Information Access)
/// and a DER `OCSPRequest` (see [`ocsp_request`]), returns the DER `OCSPResponse`. Asked when and where a [`CrlSource`] is,
/// and before it. The response is verified like a staple (signed by the issuer or by a responder it authorized, about this
/// certificate, in its window), so the channel does not have to be a trusted one.
pub trait OcspSource: Send + Sync {
    fn fetch(&self, url: &str, request: &[u8]) -> Result<Vec<u8>>;
}

/// Revocation settings for a connection.
#[derive(Clone)]
pub struct Revocation {
    pub mode: RevocationMode,
    crls: Vec<Arc<Crl>>,
    source: Option<Arc<dyn CrlSource>>,
    ocsp: Option<Arc<dyn OcspSource>>,
    /// The sources are asked about every certificate below the anchor, and hard-fail requires evidence for each.
    chain: bool,
    /// The sources are not asked now and missing evidence is not held against the chain: a later [`check_path`] with the
    /// sources will do both (the async client, which asks them on a worker after the handshake).
    deferred: bool,
}

impl Default for Revocation {
    fn default() -> Revocation {
        Revocation::new(RevocationMode::SoftFail)
    }
}

impl std::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revocation")
            .field("mode", &self.mode)
            .field("crls", &self.crls.len())
            .field("source", &self.source.is_some())
            .field("ocsp", &self.ocsp.is_some())
            .field("whole_chain", &self.chain)
            .finish()
    }
}

impl Revocation {
    pub fn new(mode: RevocationMode) -> Revocation {
        Revocation { mode, crls: Vec::new(), source: None, ocsp: None, chain: false, deferred: false }
    }

    pub fn off() -> Revocation {
        Revocation::new(RevocationMode::Off)
    }

    pub fn soft_fail() -> Revocation {
        Revocation::new(RevocationMode::SoftFail)
    }

    pub fn hard_fail() -> Revocation {
        Revocation::new(RevocationMode::HardFail)
    }

    /// Adds a CRL to consult for every certificate its issuer signed.
    pub fn with_crl(mut self, crl: Crl) -> Revocation {
        self.crls.push(Arc::new(crl));
        self
    }

    /// Uses `source` to find a CRL for the leaf when nothing else has settled it.
    pub fn with_crl_source(mut self, source: Arc<dyn CrlSource>) -> Revocation {
        self.source = Some(source);
        self
    }

    /// Uses `source` to ask the leaf's OCSP responder when nothing else has settled it (before any [`CrlSource`]).
    pub fn with_ocsp_source(mut self, source: Arc<dyn OcspSource>) -> Revocation {
        self.ocsp = Some(source);
        self
    }

    /// Asks the sources about every certificate below the trust anchor, not the leaf alone, and in hard-fail mode requires
    /// valid evidence for each of them.
    pub fn whole_chain(mut self) -> Revocation {
        self.chain = true;
        self
    }

    /// Whether a check would ask a source (and so may wait for the network).
    pub fn fetches(&self) -> bool {
        self.mode != RevocationMode::Off && (self.source.is_some() || self.ocsp.is_some())
    }

    /// The same settings with the sources left for later: a check with them asks no source and holds no missing evidence
    /// against the chain (revocation that the staples or the supplied CRLs show still fails it), and the TLS handshake hands
    /// out an [`Unchecked`] to be finished with the original settings where waiting is not a problem (the async client does
    /// this on its worker pool, so that the executor's thread never waits for a responder).
    pub fn deferred(&self) -> Revocation {
        Revocation { deferred: true, ..self.clone() }
    }

    /// Whether the sources are left for later (see [`deferred`](Revocation::deferred)).
    pub fn is_deferred(&self) -> bool {
        self.deferred && self.fetches()
    }
}

// ------------------------------------------------------------------------------ verdicts

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Good,
    Revoked { when: i64, reason: Option<u8> },
    /// An OCSP responder that does not know the certificate.
    Unknown,
    /// A CRL that does not cover this certificate (another issuer or scope).
    NotApplicable,
    /// Evidence that cannot be used, with the reason.
    Invalid(String),
}

fn reason_name(code: u8) -> &'static str {
    match code {
        0 => "unspecified",
        1 => "key compromise",
        2 => "CA compromise",
        3 => "affiliation changed",
        4 => "superseded",
        5 => "cessation of operation",
        6 => "certificate hold",
        8 => "removed from CRL",
        9 => "privilege withdrawn",
        10 => "AA compromise",
        _ => "unknown reason",
    }
}

fn normalize_serial(content: &[u8]) -> Vec<u8> {
    let zeros = content.iter().take_while(|&&b| b == 0).count().min(content.len().saturating_sub(1));
    content[zeros..].to_vec()
}

// ------------------------------------------------------------------------------ CRLs

/// A parsed certificate revocation list. Build one with [`Crl::from_der`] or [`Crl::from_pem`] and
/// hand it to [`Revocation::with_crl`]; it is checked against a certificate only when a handshake
/// needs it.
pub struct Crl {
    issuer_der: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: Option<SigAlg>,
    signature: Vec<u8>,
    this_update: i64,
    next_update: Option<i64>,
    /// serial number -> (revocation date, reason code)
    revoked: HashMap<Vec<u8>, (i64, u8)>,
    scope: Scope,
}

impl std::fmt::Debug for Crl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crl")
            .field("issuer", &x509::describe_name(&self.issuer_der))
            .field("this_update", &self.this_update)
            .field("next_update", &self.next_update)
            .field("revoked", &self.revoked.len())
            .finish()
    }
}

/// The issuingDistributionPoint extension, reduced to what decides whether a CRL covers a certificate.
#[derive(Default)]
struct Scope {
    /// URIs of the distribution point the CRL is for; empty if it names none.
    uris: Vec<String>,
    only_user_certs: bool,
    only_ca_certs: bool,
    /// Partial-reason, attribute-certificate or relative-name CRLs: not interpreted, never applied.
    unusable: bool,
}

fn unsupported_crl<T>(why: &str) -> Result<T> {
    Err(Error::Certificate(format!("unsupported CRL: {}", why)))
}

impl Crl {
    /// Parses a DER encoded CertificateList. Fails on a malformed list and on one using something
    /// this library does not implement and that a CRL must not be used without understanding: a
    /// critical extension it does not know, a delta CRL, an indirect CRL.
    pub fn from_der(der: &[u8]) -> Result<Crl> {
        let mut top = Der::new(der);
        let mut c = top.sequence()?;
        top.finish()?;
        let tbs_tlv = c.expect(asn1::TAG_SEQUENCE)?;
        let outer_alg = c.expect(asn1::TAG_SEQUENCE)?;
        let sig_bits = c.expect(asn1::TAG_BIT_STRING)?;
        c.finish()?;
        let signature = asn1::bit_string_bytes(&sig_bits)?.to_vec();

        let mut tbs = Der::new(tbs_tlv.content);
        if let Some(v) = tbs.optional(asn1::TAG_INTEGER)? {
            if v.content != [1] {
                return unsupported_crl("version");
            }
        }
        let inner_alg = tbs.expect(asn1::TAG_SEQUENCE)?;
        if inner_alg.content != outer_alg.content {
            return Err(Error::Certificate("signature algorithm mismatch between TBSCertList and CertificateList".into()));
        }
        let sig_alg = SigAlg::from_algorithm_identifier(outer_alg.content)?;
        let issuer = tbs.expect(asn1::TAG_SEQUENCE)?;
        let this_update = asn1::parse_time(&tbs.next()?)?;
        let next_update = match tbs.peek_tag() {
            Some(asn1::TAG_UTC_TIME) | Some(asn1::TAG_GENERALIZED_TIME) => Some(asn1::parse_time(&tbs.next()?)?),
            _ => None,
        };

        let mut revoked = HashMap::new();
        if let Some(list) = tbs.optional(asn1::TAG_SEQUENCE)? {
            let mut entries = Der::new(list.content);
            while !entries.is_empty() {
                let mut e = entries.sequence()?;
                let serial = normalize_serial(e.expect(asn1::TAG_INTEGER)?.content);
                let date = asn1::parse_time(&e.next()?)?;
                let mut reason = 0u8;
                if let Some(exts) = e.optional(asn1::TAG_SEQUENCE)? {
                    for_each_extension(exts.content, |oid, critical, value| {
                        match oid {
                            OID_REASON_CODE => {
                                let r = Der::new(value).expect(0x0a)?;
                                if r.content.len() != 1 {
                                    return Err(Error::Asn1("bad CRL reason code"));
                                }
                                reason = r.content[0];
                            }
                            OID_INVALIDITY_DATE => {}
                            // the entry belongs to a certificate of another issuer: an indirect CRL
                            OID_CERTIFICATE_ISSUER => return unsupported_crl("indirect CRL (certificateIssuer entry extension)"),
                            _ if critical => return unsupported_crl("critical CRL entry extension"),
                            _ => {}
                        }
                        Ok(())
                    })?;
                }
                e.finish()?;
                revoked.insert(serial, (date, reason));
            }
        }

        let mut scope = Scope::default();
        if let Some(exts) = tbs.optional(0xa0)? {
            let mut inner = Der::new(exts.content);
            let list = inner.expect(asn1::TAG_SEQUENCE)?;
            inner.finish()?;
            for_each_extension(list.content, |oid, critical, value| {
                match oid {
                    OID_CRL_NUMBER | OID_AUTHORITY_KEY_IDENTIFIER | OID_FRESHEST_CRL | OID_AUTHORITY_INFO_ACCESS => {}
                    OID_DELTA_CRL_INDICATOR => return unsupported_crl("delta CRL"),
                    OID_ISSUING_DISTRIBUTION_POINT => scope = parse_scope(value)?,
                    _ if critical => return unsupported_crl("critical CRL extension"),
                    _ => {}
                }
                Ok(())
            })?;
        }
        tbs.finish()?;

        Ok(Crl {
            issuer_der: issuer.raw.to_vec(),
            tbs: tbs_tlv.raw.to_vec(),
            sig_alg,
            signature,
            this_update,
            next_update,
            revoked,
            scope,
        })
    }

    /// Parses the first `X509 CRL` block of a PEM text.
    pub fn from_pem(text: &str) -> Result<Crl> {
        match pem::parse(text).into_iter().find(|b| b.label == "X509 CRL") {
            Some(b) => Crl::from_der(&b.data),
            None => Err(Error::Certificate("no X509 CRL block in the PEM text".into())),
        }
    }

    /// When the CRL was issued (Unix seconds).
    pub fn this_update(&self) -> i64 {
        self.this_update
    }

    /// When the next CRL is due, if the list says (Unix seconds).
    pub fn next_update(&self) -> Option<i64> {
        self.next_update
    }

    /// Number of certificates listed.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// The end of the list's window: `nextUpdate`, or a week after `thisUpdate` if it has none.
    pub fn valid_until(&self) -> i64 {
        self.next_update.unwrap_or(self.this_update + MAX_AGE_WITHOUT_NEXT_UPDATE)
    }

    /// True if the list's window has ended at `now` (or, with no `nextUpdate`, is older than a week).
    pub fn is_stale(&self, now: i64) -> bool {
        match self.next_update {
            Some(n) => now > n,
            None => now > self.this_update + MAX_AGE_WITHOUT_NEXT_UPDATE,
        }
    }

    /// Decides what this list says about `cert`, whose issuer is `issuer`.
    fn check(&self, cert: &Certificate, issuer: &Certificate, now: i64) -> Verdict {
        if self.issuer_der != cert.issuer_der {
            return Verdict::NotApplicable;
        }
        if let Some(ku) = issuer.key_usage_bits() {
            if ku & KU_CRL_SIGN == 0 {
                return Verdict::Invalid("the issuer's keyUsage does not permit signing CRLs".into());
            }
        }
        if self.sig_alg.is_none() {
            return Verdict::Invalid("unsupported CRL signature algorithm".into());
        }
        if !x509::verify_signature(self.sig_alg, &issuer.public_key, &self.tbs, &self.signature) {
            return Verdict::Invalid("CRL signature does not verify with the issuer's key".into());
        }
        if self.this_update > now + CLOCK_SKEW {
            return Verdict::Invalid("CRL is not yet valid".into());
        }
        if self.is_stale(now) {
            return Verdict::Invalid("CRL is out of date".into());
        }
        // does this list's scope cover this certificate?
        let s = &self.scope;
        if s.unusable {
            return Verdict::Invalid("CRL scope (partial reasons, attribute or relative-name distribution point) is not supported".into());
        }
        if s.only_user_certs && cert.is_ca || s.only_ca_certs && !cert.is_ca {
            return Verdict::NotApplicable;
        }
        if !s.uris.is_empty() && !s.uris.iter().any(|u| cert.crl_uris.contains(u)) {
            return Verdict::NotApplicable;
        }
        match self.revoked.get(&cert.serial) {
            // removeFromCRL is only meaningful in a delta CRL
            Some(&(when, reason)) if reason != 8 => Verdict::Revoked { when, reason: Some(reason) },
            _ => Verdict::Good,
        }
    }
}

/// Calls `f(oid, critical, value)` for each extension in an Extensions SEQUENCE body.
fn for_each_extension(list: &[u8], mut f: impl FnMut(&[u8], bool, &[u8]) -> Result<()>) -> Result<()> {
    let mut d = Der::new(list);
    while !d.is_empty() {
        let mut ext = d.sequence()?;
        let oid = ext.expect(asn1::TAG_OID)?.content;
        let critical = match ext.optional(asn1::TAG_BOOLEAN)? {
            Some(b) => asn1::boolean(&b)?,
            None => false,
        };
        let value = ext.expect(asn1::TAG_OCTET_STRING)?.content;
        ext.finish()?;
        f(oid, critical, value)?;
    }
    Ok(())
}

/// IssuingDistributionPoint (RFC 5280 section 5.2.5). Every field is IMPLICIT-tagged.
fn parse_scope(value: &[u8]) -> Result<Scope> {
    let mut outer = Der::new(value);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let mut s = Scope::default();
    if let Some(dp) = seq.optional(0xa0)? {
        // DistributionPointName: fullName [0] GeneralNames, or nameRelativeToCRLIssuer [1]
        let mut inner = Der::new(dp.content);
        match inner.peek_tag() {
            Some(0xa0) => s.uris = x509::general_name_uris(inner.next()?.content)?,
            _ => s.unusable = true,
        }
    }
    // the flags are IMPLICIT BOOLEANs: a value other than 00 or ff is an error, not "false"
    let flag = |t: Option<asn1::Tlv>| -> Result<bool> { t.map_or(Ok(false), |b| asn1::boolean_content(b.content)) };
    s.only_user_certs = flag(seq.optional(0x81)?)?;
    s.only_ca_certs = flag(seq.optional(0x82)?)?;
    if seq.optional(0x83)?.is_some() {
        s.unusable = true; // onlySomeReasons
    }
    if flag(seq.optional(0x84)?)? {
        s.unusable = true; // indirectCRL
    }
    if flag(seq.optional(0x85)?)? {
        s.unusable = true; // onlyContainsAttributeCerts
    }
    seq.finish()?;
    Ok(s)
}

// ------------------------------------------------------------------------------ OCSP

/// A DER TLV.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// A DER `OCSPRequest` (RFC 6960 section 4.1.1) about `cert`, whose issuer is `issuer`: one request whose `CertID` uses
/// SHA-1 (the hash of the issuer's name and of its key, which every responder takes and some take alone: RFC 5019), the
/// certificate's serial number as it is written in it, no signature and no extensions. The same bytes as
/// `openssl ocsp -no_nonce -reqout`.
pub fn ocsp_request(cert: &Certificate, issuer: &Certificate) -> Vec<u8> {
    let alg = der(asn1::TAG_SEQUENCE, &[der(asn1::TAG_OID, OID_HASH_SHA1), vec![0x05, 0x00]].concat());
    let cert_id = der(
        asn1::TAG_SEQUENCE,
        &[alg, der(asn1::TAG_OCTET_STRING, &sha1::digest(&cert.issuer_der)), der(asn1::TAG_OCTET_STRING, &sha1::digest(&issuer.spki_key)), der(asn1::TAG_INTEGER, &cert.serial_content)]
            .concat(),
    );
    let request = der(asn1::TAG_SEQUENCE, &cert_id);
    let request_list = der(asn1::TAG_SEQUENCE, &request);
    let tbs_request = der(asn1::TAG_SEQUENCE, &request_list);
    der(asn1::TAG_SEQUENCE, &tbs_request)
}

fn ocsp_hash(oid: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    Some(match oid {
        OID_HASH_SHA1 => sha1::digest(data).to_vec(),
        OID_HASH_SHA256 => HashAlg::Sha256.digest(data),
        OID_HASH_SHA384 => HashAlg::Sha384.digest(data),
        OID_HASH_SHA512 => HashAlg::Sha512.digest(data),
        _ => return None,
    })
}

/// How an OCSP response names the key that signed it.
enum ResponderId<'a> {
    Name(&'a [u8]),
    KeyHash(&'a [u8]),
}

impl ResponderId<'_> {
    fn is(&self, cert: &Certificate) -> bool {
        match self {
            ResponderId::Name(n) => *n == cert.subject_der.as_slice(),
            ResponderId::KeyHash(h) => *h == sha1::digest(&cert.spki_key).as_slice(),
        }
    }
}

/// The end of the window of the first single response in an OCSP response (its `nextUpdate`, or a week after its
/// `thisUpdate`), read without verifying anything: for a cache that keeps a response until then (it is verified again,
/// window included, every time it is used). `None` if it does not parse or is not a successful basic response.
pub fn ocsp_response_valid_until(response: &[u8]) -> Option<i64> {
    let mut top = Der::new(response);
    let mut resp = top.sequence().ok()?;
    if resp.expect(0x0a).ok()?.content != [0] {
        return None;
    }
    let response_bytes = resp.expect(0xa0).ok()?;
    let mut rb = Der::new(response_bytes.content).sequence().ok()?;
    if rb.expect(asn1::TAG_OID).ok()?.content != OID_OCSP_BASIC {
        return None;
    }
    let basic = rb.expect(asn1::TAG_OCTET_STRING).ok()?.content;
    let tbs = Der::new(basic).sequence().ok()?.expect(asn1::TAG_SEQUENCE).ok()?;
    let mut data = Der::new(tbs.content);
    data.optional(0xa0).ok()?;
    data.next().ok()?; // responderID
    data.next().ok()?; // producedAt
    let mut singles = data.sequence().ok()?;
    let mut sr = singles.sequence().ok()?;
    sr.expect(asn1::TAG_SEQUENCE).ok()?; // certID
    sr.next().ok()?; // certStatus
    let this_update = asn1::parse_time(&sr.next().ok()?).ok()?;
    match sr.optional(0xa0).ok()? {
        Some(t) => asn1::parse_time(&Der::new(t.content).next().ok()?).ok(),
        None => Some(this_update + MAX_AGE_WITHOUT_NEXT_UPDATE),
    }
}

/// Decides what the OCSP response `response` (DER) says about `cert`, whose issuer is `issuer`.
fn check_ocsp(response: &[u8], cert: &Certificate, issuer: &Certificate, now: i64) -> Verdict {
    match check_ocsp_inner(response, cert, issuer, now) {
        Ok(v) => v,
        Err(e) => Verdict::Invalid(format!("malformed OCSP response ({})", e)),
    }
}

fn check_ocsp_inner(response: &[u8], cert: &Certificate, issuer: &Certificate, now: i64) -> Result<Verdict> {
    let mut top = Der::new(response);
    let mut resp = top.sequence()?;
    top.finish()?;
    let status = resp.expect(0x0a)?;
    if status.content != [0] {
        let code = status.content.first().copied().unwrap_or(255);
        return Ok(Verdict::Invalid(format!("the responder answered with status {} instead of successful", code)));
    }
    let response_bytes = resp.expect(0xa0)?;
    resp.finish()?;
    let mut rb = Der::new(response_bytes.content).sequence()?;
    if rb.expect(asn1::TAG_OID)?.content != OID_OCSP_BASIC {
        return Ok(Verdict::Invalid("the response is not a basic OCSP response".into()));
    }
    let basic_der = rb.expect(asn1::TAG_OCTET_STRING)?.content;
    rb.finish()?;

    let mut outer = Der::new(basic_der);
    let mut basic = outer.sequence()?;
    outer.finish()?;
    let tbs = basic.expect(asn1::TAG_SEQUENCE)?;
    let alg = basic.expect(asn1::TAG_SEQUENCE)?;
    let sig_bits = basic.expect(asn1::TAG_BIT_STRING)?;
    let certs = basic.optional(0xa0)?;
    basic.finish()?;
    let signature = asn1::bit_string_bytes(&sig_bits)?;
    let sig_alg = SigAlg::from_algorithm_identifier(alg.content)?;

    // ResponseData
    let mut data = Der::new(tbs.content);
    data.optional(0xa0)?; // version
    let rid_tlv = data.next()?;
    let responder = match rid_tlv.tag {
        0xa1 => ResponderId::Name(Der::new(rid_tlv.content).expect(asn1::TAG_SEQUENCE)?.raw),
        0xa2 => ResponderId::KeyHash(Der::new(rid_tlv.content).expect(asn1::TAG_OCTET_STRING)?.content),
        _ => return Err(Error::Asn1("bad responderID")),
    };
    asn1::parse_time(&data.next()?)?; // producedAt
    let mut singles = data.sequence()?;
    data.optional(0xa1)?; // responseExtensions
    data.finish()?;

    // the single response for this certificate
    let name_hash_input = &cert.issuer_der;
    let mut found: Option<(Verdict, i64, Option<i64>)> = None;
    while !singles.is_empty() {
        let mut sr = singles.sequence()?;
        let mut id = Der::new(sr.expect(asn1::TAG_SEQUENCE)?.content);
        let hash_oid = Der::new(id.expect(asn1::TAG_SEQUENCE)?.content).expect(asn1::TAG_OID)?.content;
        let name_hash = id.expect(asn1::TAG_OCTET_STRING)?.content;
        let key_hash = id.expect(asn1::TAG_OCTET_STRING)?.content;
        let serial = normalize_serial(id.expect(asn1::TAG_INTEGER)?.content);
        id.finish()?;
        let cert_status = sr.next()?;
        let this_update = asn1::parse_time(&sr.next()?)?;
        let next_update = match sr.optional(0xa0)? {
            Some(t) => Some(asn1::parse_time(&Der::new(t.content).next()?)?),
            None => None,
        };
        sr.optional(0xa1)?; // singleExtensions
        sr.finish()?;

        let verdict = match cert_status.tag {
            0x80 => Verdict::Good,
            0x82 => Verdict::Unknown,
            0xa1 => {
                let mut info = Der::new(cert_status.content);
                let when = asn1::parse_time(&info.next()?)?;
                let reason = match info.optional(0xa0)? {
                    Some(r) => Some(*Der::new(r.content).expect(0x0a)?.content.first().ok_or(Error::Asn1("empty reason"))?),
                    None => None,
                };
                Verdict::Revoked { when, reason }
            }
            _ => return Err(Error::Asn1("bad certStatus")),
        };
        let names_this_cert = serial == cert.serial
            && ocsp_hash(hash_oid, name_hash_input).is_some_and(|h| h == name_hash)
            && ocsp_hash(hash_oid, &issuer.spki_key).is_some_and(|h| h == key_hash);
        if names_this_cert && found.is_none() {
            found = Some((verdict, this_update, next_update));
        }
    }
    let Some((verdict, this_update, next_update)) = found else {
        return Ok(Verdict::Invalid("the response is not about this certificate".into()));
    };

    // who signed it
    let delegated;
    let signer: &Certificate = if responder.is(issuer) {
        issuer
    } else {
        let Some(list) = certs else {
            return Ok(Verdict::Invalid("signed by a responder that is not the issuer, and no responder certificate was sent".into()));
        };
        let mut candidates = Der::new(Der::new(list.content).expect(asn1::TAG_SEQUENCE)?.content);
        let mut chosen = None;
        while !candidates.is_empty() {
            let raw = candidates.next()?.raw;
            if let Ok(c) = Certificate::from_der(raw) {
                if responder.is(&c) {
                    chosen = Some(c);
                    break;
                }
            }
        }
        let Some(c) = chosen else {
            return Ok(Verdict::Invalid("the responder named in the response is neither the issuer nor in the certificates it sent".into()));
        };
        if c.verify_signed_by(issuer).is_err() {
            return Ok(Verdict::Invalid("the responder certificate was not signed by the certificate's issuer".into()));
        }
        if !c.has_ext_key_usage(OID_EKU_OCSP_SIGNING) {
            return Ok(Verdict::Invalid("the responder certificate may not sign OCSP responses (no OCSP-signing extended key usage)".into()));
        }
        if now < c.not_before || now > c.not_after {
            return Ok(Verdict::Invalid("the responder certificate is not valid at this time".into()));
        }
        delegated = c;
        &delegated
    };
    if !x509::verify_signature(sig_alg, &signer.public_key, tbs.raw, signature) {
        return Ok(Verdict::Invalid("OCSP response signature does not verify (or uses an unsupported algorithm)".into()));
    }

    if this_update > now + CLOCK_SKEW {
        return Ok(Verdict::Invalid("OCSP response is not yet valid".into()));
    }
    let expired = match next_update {
        Some(n) => now > n,
        None => now > this_update + MAX_AGE_WITHOUT_NEXT_UPDATE,
    };
    if expired {
        return Ok(Verdict::Invalid("OCSP response is out of date".into()));
    }
    Ok(verdict)
}

// ------------------------------------------------------------------------------ policy

fn revoked_error(cert: &Certificate, via: &str, when: i64, reason: Option<u8>) -> Error {
    let why = match reason {
        Some(r) => format!(", reason: {}", reason_name(r)),
        None => String::new(),
    };
    Error::Certificate(format!(
        "certificate_revoked: certificate [{}] was revoked (according to {}, at Unix time {}{})",
        cert.subject_summary(),
        via,
        when,
        why
    ))
}

/// A verified chain whose check was deferred ([`Revocation::deferred`]), with what it needs to be finished later: the
/// path (leaf to anchor), the certificates as sent, and the staples that came with them. A TLS connection hands it out
/// after its handshake (`ClientConnection::take_unchecked`, with the `net` feature).
#[derive(Clone, Debug, Default)]
pub struct Unchecked {
    pub(crate) path: Vec<Vec<u8>>,
    pub(crate) sent: Vec<Vec<u8>>,
    pub(crate) staples: Vec<Option<Vec<u8>>>,
}

impl Unchecked {
    /// Finishes the check with `cfg` (its sources asked now, so this may wait for the network) at `now` (Unix seconds).
    pub fn check(&self, cfg: &Revocation, now: i64) -> Result<()> {
        check_path(cfg, &self.path, &ChainEvidence { sent: &self.sent, staples: &self.staples }, now)
    }
}

/// What the caller has about revocation of a certificate chain it has just verified (a TLS
/// handshake, a code-signing chain): the certificates as they were sent, and the OCSP responses that
/// came with them.
pub struct ChainEvidence<'a> {
    /// The certificates the server sent (leaf first), as sent.
    pub sent: &'a [Vec<u8>],
    /// The stapled OCSP response of each entry of `sent`, where the server sent one.
    pub staples: &'a [Option<Vec<u8>>],
}

/// Applies the revocation policy to a verified path (`path` is the DER of each certificate from the
/// leaf to the trust anchor). Returns an error that starts with `certificate_revoked:` or
/// `bad_certificate_status_response:` (the TLS alerts it is answered with).
pub fn check_path(cfg: &Revocation, path: &[Vec<u8>], evidence: &ChainEvidence, now: i64) -> Result<()> {
    if cfg.mode == RevocationMode::Off || path.len() < 2 {
        return Ok(());
    }
    let certs = path.iter().map(|d| Certificate::from_der(d)).collect::<Result<Vec<_>>>()?;
    // each certificate except the anchor is checked against the one that issued it
    for k in 0..certs.len() - 1 {
        let (cert, issuer) = (&certs[k], &certs[k + 1]);
        let is_leaf = k == 0;
        // the certificates the sources are asked about, and that hard-fail wants evidence for
        let asked = is_leaf || cfg.chain;
        let mut good_by: Option<&'static str> = None;
        let mut staple_good = false;
        let mut problems: Vec<String> = Vec::new();

        let staple = evidence
            .sent
            .iter()
            .position(|d| *d == path[k])
            .and_then(|i| evidence.staples.get(i))
            .and_then(|s| s.as_deref());
        if let Some(response) = staple {
            match check_ocsp(response, cert, issuer, now) {
                Verdict::Good => {
                    good_by = Some("a stapled OCSP response");
                    staple_good = true;
                }
                Verdict::Revoked { when, reason } => return Err(revoked_error(cert, "a stapled OCSP response", when, reason)),
                Verdict::Unknown => problems.push("the stapled OCSP response says the responder does not know the certificate".into()),
                Verdict::NotApplicable => {}
                Verdict::Invalid(why) => problems.push(format!("stapled OCSP response rejected: {}", why)),
            }
        }

        for crl in &cfg.crls {
            match crl.check(cert, issuer, now) {
                Verdict::Good => good_by = good_by.or(Some("a CRL")),
                Verdict::Revoked { when, reason } => return Err(revoked_error(cert, "a CRL", when, reason)),
                Verdict::Invalid(why) => problems.push(format!("supplied CRL rejected: {}", why)),
                Verdict::Unknown | Verdict::NotApplicable => {}
            }
        }

        if asked && good_by.is_none() && !cfg.deferred {
            good_by = ask_sources(cfg, cert, issuer, now, &mut problems)?;
        }

        let detail = if problems.is_empty() { String::new() } else { format!(" ({})", problems.join("; ")) };
        if is_leaf && cert.must_staple && !staple_good {
            return Err(Error::Certificate(format!(
                "bad_certificate_status_response: certificate [{}] requires a stapled OCSP response (TLS Feature: status_request) but the server did not send a valid one{}",
                cert.subject_summary(),
                detail
            )));
        }
        if asked && cfg.mode == RevocationMode::HardFail && good_by.is_none() && !cfg.deferred {
            return Err(Error::Certificate(format!(
                "bad_certificate_status_response: no valid evidence that certificate [{}] has not been revoked (no good OCSP response, no covering CRL){}",
                cert.subject_summary(),
                detail
            )));
        }
    }
    Ok(())
}

/// Asks the configured sources about `cert`: its OCSP responders first, then its CRL distribution points (plain `http://`
/// only, two of each at most). What settled it, if anything; an error if the evidence says it is revoked.
fn ask_sources(cfg: &Revocation, cert: &Certificate, issuer: &Certificate, now: i64, problems: &mut Vec<String>) -> Result<Option<&'static str>> {
    if let Some(source) = &cfg.ocsp {
        let urls: Vec<&String> = cert.ocsp_uris.iter().filter(|u| u.starts_with("http://")).take(2).collect();
        if !urls.is_empty() {
            let request = ocsp_request(cert, issuer);
            for url in urls {
                match source.fetch(url, &request) {
                    Ok(response) => match check_ocsp(&response, cert, issuer, now) {
                        Verdict::Good => return Ok(Some("the certificate's OCSP responder")),
                        Verdict::Revoked { when, reason } => return Err(revoked_error(cert, "the certificate's OCSP responder", when, reason)),
                        Verdict::Unknown => problems.push(format!("the OCSP responder at {} does not know the certificate", url)),
                        Verdict::NotApplicable => {}
                        Verdict::Invalid(why) => problems.push(format!("OCSP response from {} rejected: {}", url, why)),
                    },
                    Err(e) => problems.push(format!("could not ask the OCSP responder at {}: {}", url, e)),
                }
            }
        }
    }
    if let Some(source) = &cfg.source {
        for url in cert.crl_uris.iter().filter(|u| u.starts_with("http://")).take(2) {
            match source.fetch(url) {
                Ok(crl) => match crl.check(cert, issuer, now) {
                    Verdict::Good => return Ok(Some("a fetched CRL")),
                    Verdict::Revoked { when, reason } => return Err(revoked_error(cert, "a fetched CRL", when, reason)),
                    Verdict::Invalid(why) => problems.push(format!("CRL from {} rejected: {}", url, why)),
                    Verdict::Unknown | Verdict::NotApplicable => problems.push(format!("CRL from {} does not cover the certificate", url)),
                },
                Err(e) => problems.push(format!("could not get the CRL at {}: {}", url, e)),
            }
        }
    }
    Ok(None)
}

// ------------------------------------------------------------------------------ fetching CRLs

/// Entry points for the coverage-guided fuzzer in `fuzz/`; compiled only with
/// `--cfg pratique_fuzzing`. Not part of the API.
#[cfg(pratique_fuzzing)]
#[doc(hidden)]
pub mod fuzz_hooks {
    use super::*;

    fn code(v: Verdict) -> u8 {
        match v {
            Verdict::Good => 0,
            Verdict::Revoked { .. } => 1,
            Verdict::Unknown => 2,
            Verdict::NotApplicable => 3,
            Verdict::Invalid(_) => 4,
        }
    }

    /// The verdict code (0 good, 1 revoked, 2 unknown, 3 not applicable, 4 unusable, 5 the
    /// certificates do not parse) of an OCSP response for `leaf` issued by `issuer`.
    pub fn ocsp(response: &[u8], leaf: &[u8], issuer: &[u8], now: i64) -> u8 {
        match (Certificate::from_der(leaf), Certificate::from_der(issuer)) {
            (Ok(l), Ok(i)) => code(check_ocsp(response, &l, &i, now)),
            _ => 5,
        }
    }

    /// The same for a CRL given as DER (6 if the list itself does not parse).
    pub fn crl(crl_der: &[u8], leaf: &[u8], issuer: &[u8], now: i64) -> u8 {
        let Ok(crl) = Crl::from_der(crl_der) else { return 6 };
        match (Certificate::from_der(leaf), Certificate::from_der(issuer)) {
            (Ok(l), Ok(i)) => code(crl.check(&l, &i, now)),
            _ => 5,
        }
    }

    /// The whole policy over a path (leaf first, anchor last) with a stapled response for the
    /// leaf and a CRL, in each of the three modes: `Ok(mode index)` results are folded into a
    /// bit set of the modes that accepted.
    pub fn path(path: &[Vec<u8>], staple: &[u8], crl_der: &[u8], now: i64) -> u8 {
        let mut accepted = 0u8;
        for (bit, mode) in [RevocationMode::Off, RevocationMode::SoftFail, RevocationMode::HardFail].into_iter().enumerate() {
            let mut cfg = Revocation::new(mode);
            if let Ok(c) = Crl::from_der(crl_der) {
                cfg = cfg.with_crl(c);
            }
            let staples = vec![Some(staple.to_vec()); 1];
            let evidence = ChainEvidence { sent: &path[..1.min(path.len())], staples: &staples };
            if check_path(&cfg, path, &evidence, now).is_ok() {
                accepted |= 1 << bit;
            }
        }
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 2026-09-15 00:00:00 UTC, the clock the fixtures in tests/data/rev_* are built around:
    /// responses and lists were issued two days earlier and are due in five.
    const NOW: i64 = 1_789_430_400;
    const DAY: i64 = 86_400;

    macro_rules! der {
        ($name:literal) => {
            include_bytes!(concat!("../tests/data/", $name, ".der")).as_slice()
        };
    }
    macro_rules! pem_cert {
        ($name:literal) => {
            pem::parse(include_str!(concat!("../tests/data/", $name, ".pem"))).remove(0).data
        };
    }

    struct Pki {
        root: Vec<u8>,
        inter: Vec<u8>,
        leaf: Vec<u8>,
        leaf_ms: Vec<u8>,
    }

    fn pki() -> Pki {
        Pki { root: pem_cert!("rev_root"), inter: pem_cert!("rev_inter"), leaf: pem_cert!("rev_leaf"), leaf_ms: pem_cert!("rev_leaf_ms") }
    }

    fn parsed(der: &[u8]) -> Certificate {
        Certificate::from_der(der).unwrap()
    }

    fn ocsp(resp: &[u8]) -> Verdict {
        let p = pki();
        check_ocsp(resp, &parsed(&p.leaf), &parsed(&p.inter), NOW)
    }

    fn ocsp_at(resp: &[u8], now: i64) -> Verdict {
        let p = pki();
        check_ocsp(resp, &parsed(&p.leaf), &parsed(&p.inter), now)
    }

    fn invalid_with(v: Verdict, needle: &str) {
        match v {
            Verdict::Invalid(why) => assert!(why.contains(needle), "wanted {:?} in {:?}", needle, why),
            other => panic!("wanted Invalid({:?}), got {:?}", needle, other),
        }
    }

    // ---------------------------------------------------------------- OCSP verdicts

    #[test]
    fn good_responses_in_every_accepted_form() {
        for (name, resp) in [
            ("issuer, SHA-1 certID, responder by name", der!("rev_ocsp_good")),
            ("SHA-256 certID", der!("rev_ocsp_good_sha256")),
            ("responder by key hash", der!("rev_ocsp_good_byhash")),
            ("no nextUpdate, issued recently", der!("rev_ocsp_good_nonext")),
            ("delegated responder by name", der!("rev_ocsp_good_delegated")),
            ("delegated responder by key hash", der!("rev_ocsp_good_delegated_byhash")),
        ] {
            assert_eq!(ocsp(resp), Verdict::Good, "{}", name);
        }
    }

    #[test]
    fn revoked_and_unknown_statuses() {
        assert_eq!(ocsp(der!("rev_ocsp_revoked")), Verdict::Revoked { when: NOW - 3 * DAY, reason: Some(1) });
        assert_eq!(ocsp(der!("rev_ocsp_unknown")), Verdict::Unknown);
    }

    #[test]
    fn responses_that_must_not_be_trusted() {
        invalid_with(ocsp(der!("rev_ocsp_forged")), "signature");
        invalid_with(ocsp(der!("rev_ocsp_other_cert")), "not about this certificate");
        invalid_with(ocsp(der!("rev_ocsp_wrong_issuer")), "not about this certificate");
        invalid_with(ocsp(der!("rev_ocsp_unauthorized")), "status");
        invalid_with(ocsp(der!("rev_ocsp_delegated_nocert")), "no responder certificate");
        invalid_with(ocsp(der!("rev_ocsp_delegated_noeku")), "OCSP-signing");
        invalid_with(ocsp(der!("rev_ocsp_expired")), "out of date");
        invalid_with(ocsp(der!("rev_ocsp_future")), "not yet valid");
        invalid_with(ocsp(der!("rev_ocsp_nonext_old")), "out of date");
    }

    /// `rev_ocsp_forged` is a genuine response with the last bit of its signature flipped (see
    /// tools/gen_revocation_fixtures.py), so flipping that bit back gives a genuine response that is
    /// not among the fixtures. The fuzzer found exactly that after about 5 million inputs; the library
    /// is right to accept it, and the fuzz oracle (`is_known_good`) has to know about it.
    #[test]
    fn a_forged_response_is_one_bit_from_a_genuine_one() {
        let forged = der!("rev_ocsp_forged");
        invalid_with(ocsp(forged), "signature");
        let mut repaired = forged.to_vec();
        *repaired.last_mut().unwrap() ^= 0x01;
        assert_ne!(repaired, der!("rev_ocsp_good"), "ECDSA signatures are randomized, so this is a different response");
        assert_eq!(ocsp(&repaired), Verdict::Good);
        // and any other change to the last byte is still a bad signature
        for flip in [0x02u8, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff] {
            let mut damaged = forged.to_vec();
            *damaged.last_mut().unwrap() ^= flip;
            invalid_with(ocsp(&damaged), "signature");
        }
    }

    #[test]
    fn response_window_edges_and_clock_skew() {
        let good = der!("rev_ocsp_good"); // thisUpdate NOW - 2 days, nextUpdate NOW + 5 days
        let (this, next) = (NOW - 2 * DAY, NOW + 5 * DAY);
        assert_eq!(ocsp_at(good, this), Verdict::Good);
        assert_eq!(ocsp_at(good, next), Verdict::Good);
        invalid_with(ocsp_at(good, next + 1), "out of date");
        // five minutes of skew are allowed before thisUpdate
        assert_eq!(ocsp_at(good, this - 299), Verdict::Good);
        invalid_with(ocsp_at(good, this - 301), "not yet valid");
        // without nextUpdate: seven days from thisUpdate
        let nonext = der!("rev_ocsp_good_nonext");
        assert_eq!(ocsp_at(nonext, this + 7 * DAY), Verdict::Good);
        invalid_with(ocsp_at(nonext, this + 7 * DAY + 1), "out of date");
    }

    #[test]
    fn a_response_for_the_intermediate_is_checked_against_the_root() {
        let p = pki();
        let (inter, root) = (parsed(&p.inter), parsed(&p.root));
        assert_eq!(check_ocsp(der!("rev_ocsp_inter_good"), &inter, &root, NOW), Verdict::Good);
        assert_eq!(
            check_ocsp(der!("rev_ocsp_inter_revoked"), &inter, &root, NOW),
            Verdict::Revoked { when: NOW - DAY, reason: Some(2) }
        );
        // and not as an answer about the leaf
        invalid_with(check_ocsp(der!("rev_ocsp_inter_good"), &parsed(&p.leaf), &inter, NOW), "not about this certificate");
    }

    #[test]
    fn the_unsigned_signature_algorithm_of_a_response_is_read_strictly() {
        // found by the fuzzer: only the algorithm's OID was read, so anything after it (outside
        // what the signature covers) was accepted. 241 is the length byte of the NULL parameter
        // of the BasicOCSPResponse's own signatureAlgorithm.
        let p = pki();
        let (inter, root) = (parsed(&p.inter), parsed(&p.root));
        let mut r = der!("rev_ocsp_inter_revoked").to_vec();
        assert_eq!(&r[239..242], &[0x0b, 0x05, 0x00], "the fixture's layout changed");
        r[241] = 0x29;
        invalid_with(check_ocsp(&r, &inter, &root, NOW), "");
        // an explicit NULL and an absent parameter are both fine, anything else is not an algorithm we know
        let rsa_sha256 = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        for (params, known) in [(&[][..], true), (&[0x05, 0x00][..], true), (&[0x05, 0x01, 0x00][..], false), (&[0x02, 0x01, 0x00][..], false), (&[0x30, 0x00][..], false)] {
            let got = SigAlg::from_algorithm_identifier(&[&rsa_sha256[..], params].concat()).unwrap();
            assert_eq!(got.is_some(), known, "parameters {params:02x?}");
        }
        assert!(SigAlg::from_algorithm_identifier(&[&rsa_sha256[..], &[0x05, 0x00, 0x05, 0x00]].concat()).is_err(), "two parameters");
        assert!(SigAlg::from_algorithm_identifier(&[&rsa_sha256[..], &[0x05, 0x29]].concat()).is_err(), "a parameter that runs past the end");
        assert!(SigAlg::from_algorithm_identifier(&[0x05, 0x00]).is_err(), "not an OID");
    }

    #[test]
    fn damaged_responses_are_never_accepted_and_never_panic() {
        let good = der!("rev_ocsp_good");
        for len in 0..good.len() {
            assert!(matches!(ocsp(&good[..len]), Verdict::Invalid(_)), "truncated to {}", len);
        }
        let mut accepted_after_change = Vec::new();
        for i in 0..good.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut m = good.to_vec();
                m[i] ^= flip;
                if ocsp(&m) == Verdict::Good {
                    accepted_after_change.push((i, flip));
                }
            }
        }
        assert!(accepted_after_change.is_empty(), "bytes whose change was still accepted: {:?}", accepted_after_change);
        // garbage of several shapes
        for junk in [&b""[..], &[0x30][..], &[0x30, 0x80][..], &[0xff; 64][..], &[0x30, 0x03, 0x0a, 0x01, 0x00][..]] {
            assert!(matches!(ocsp(junk), Verdict::Invalid(_)));
        }
    }

    #[test]
    fn ocsp_ids_hash_with_each_supported_algorithm() {
        assert_eq!(ocsp_hash(OID_HASH_SHA1, b"abc").unwrap().len(), 20);
        assert_eq!(ocsp_hash(OID_HASH_SHA256, b"abc").unwrap().len(), 32);
        assert_eq!(ocsp_hash(OID_HASH_SHA384, b"abc").unwrap().len(), 48);
        assert_eq!(ocsp_hash(OID_HASH_SHA512, b"abc").unwrap().len(), 64);
        assert!(ocsp_hash(&[1, 2, 3], b"abc").is_none());
    }

    // ---------------------------------------------------------------- CRL verdicts

    fn crl(der: &[u8]) -> Crl {
        Crl::from_der(der).unwrap()
    }

    fn crl_verdict(der: &[u8]) -> Verdict {
        let p = pki();
        crl(der).check(&parsed(&p.leaf), &parsed(&p.inter), NOW)
    }

    #[test]
    fn crl_verdicts() {
        assert_eq!(crl_verdict(der!("rev_crl_empty")), Verdict::Good);
        assert_eq!(crl_verdict(der!("rev_crl_revoked")), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(1) });
        // a certificate on hold is not valid while it is on hold
        assert_eq!(crl_verdict(der!("rev_crl_revoked_hold")), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(6) });
        // removeFromCRL is a delta CRL entry; in a full list it un-revokes nothing and revokes nothing
        assert_eq!(crl_verdict(der!("rev_crl_revoked_removefromcrl")), Verdict::Good);
        invalid_with(crl_verdict(der!("rev_crl_stale")), "out of date");
        invalid_with(crl_verdict(der!("rev_crl_future")), "not yet valid");
        invalid_with(crl_verdict(der!("rev_crl_forged")), "signature");
        assert_eq!(crl_verdict(der!("rev_crl_other_issuer")), Verdict::NotApplicable);
    }

    #[test]
    fn crl_scope_decides_whether_a_list_covers_the_certificate() {
        // the leaf's CRL distribution point is http://crl.example.test/inter.crl
        assert_eq!(crl_verdict(der!("rev_crl_idp_dp")), Verdict::Good);
        assert_eq!(crl_verdict(der!("rev_crl_idp_dp_revoked")), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(0) });
        assert_eq!(crl_verdict(der!("rev_crl_idp_other_dp")), Verdict::NotApplicable);
        assert_eq!(crl_verdict(der!("rev_crl_idp_ca_only")), Verdict::NotApplicable);
        assert_eq!(crl_verdict(der!("rev_crl_idp_user_only")), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(0) });
        invalid_with(crl_verdict(der!("rev_crl_idp_some_reasons")), "scope");
    }

    #[test]
    fn crls_this_library_cannot_interpret_are_refused_when_parsed() {
        let err = Crl::from_der(der!("rev_crl_delta")).unwrap_err().to_string();
        assert!(err.contains("delta"), "{}", err);
        let err = Crl::from_der(der!("rev_crl_unknown_critical")).unwrap_err().to_string();
        assert!(err.contains("critical"), "{}", err);
        assert!(Crl::from_der(b"").is_err());
        assert!(Crl::from_der(&[0x30, 0x00]).is_err());
        assert!(Crl::from_pem("no pem here").is_err());
    }

    #[test]
    fn a_crl_lists_the_intermediate_for_the_root() {
        let p = pki();
        let (inter, root) = (parsed(&p.inter), parsed(&p.root));
        let revoking = crl(der!("rev_crl_root_revokes_inter"));
        assert_eq!(revoking.check(&inter, &root, NOW), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(2) });
        assert_eq!(crl(der!("rev_crl_root_empty")).check(&inter, &root, NOW), Verdict::Good);
        // it says nothing about certificates the intermediate issued
        assert_eq!(revoking.check(&parsed(&p.leaf), &inter, NOW), Verdict::NotApplicable);
    }

    #[test]
    fn crl_accessors_and_staleness() {
        let c = crl(der!("rev_crl_revoked"));
        assert_eq!(c.len(), 2);
        assert!(!c.is_empty());
        assert_eq!(c.this_update(), NOW - 2 * DAY);
        assert_eq!(c.next_update(), Some(NOW + 5 * DAY));
        assert!(!c.is_stale(NOW + 5 * DAY));
        assert!(c.is_stale(NOW + 5 * DAY + 1));
        assert!(format!("{:?}", c).contains("revoked"));
    }

    #[test]
    fn damaged_crls_never_flip_a_revocation_into_good() {
        let p = pki();
        let (leaf, inter) = (parsed(&p.leaf), parsed(&p.inter));
        let revoked = der!("rev_crl_revoked");
        for len in 0..revoked.len() {
            assert!(Crl::from_der(&revoked[..len]).is_err(), "truncated to {}", len);
        }
        for i in 0..revoked.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut m = revoked.to_vec();
                m[i] ^= flip;
                if let Ok(c) = Crl::from_der(&m) {
                    assert_ne!(c.check(&leaf, &inter, NOW), Verdict::Good, "byte {} ^ {:#x}", i, flip);
                }
            }
        }
    }

    // ---------------------------------------------------------------- policy

    struct Scenario {
        mode: RevocationMode,
        crls: Vec<&'static [u8]>,
        leaf_staple: Option<&'static [u8]>,
        inter_staple: Option<&'static [u8]>,
        must_staple_leaf: bool,
        source: Option<Arc<dyn CrlSource>>,
    }

    impl Scenario {
        fn new(mode: RevocationMode) -> Scenario {
            Scenario { mode, crls: vec![], leaf_staple: None, inter_staple: None, must_staple_leaf: false, source: None }
        }

        fn run(&self) -> Result<()> {
            let p = pki();
            let leaf = if self.must_staple_leaf { p.leaf_ms.clone() } else { p.leaf.clone() };
            let path = vec![leaf.clone(), p.inter.clone(), p.root.clone()];
            let sent = vec![leaf, p.inter.clone()];
            let staples = vec![self.leaf_staple.map(|s| s.to_vec()), self.inter_staple.map(|s| s.to_vec())];
            let mut cfg = Revocation::new(self.mode);
            for c in &self.crls {
                cfg = cfg.with_crl(crl(c));
            }
            if let Some(s) = &self.source {
                cfg = cfg.with_crl_source(s.clone());
            }
            check_path(&cfg, &path, &ChainEvidence { sent: &sent, staples: &staples }, NOW)
        }

        fn err(&self) -> String {
            self.run().unwrap_err().to_string()
        }
    }

    use RevocationMode::{HardFail, Off, SoftFail};

    #[test]
    fn off_checks_nothing() {
        let mut s = Scenario::new(Off);
        s.leaf_staple = Some(der!("rev_ocsp_revoked"));
        s.crls = vec![der!("rev_crl_revoked")];
        s.must_staple_leaf = true;
        assert!(s.run().is_ok());
    }

    #[test]
    fn soft_fail_rejects_revocation_and_forgives_missing_or_unusable_evidence() {
        // nothing at all
        assert!(Scenario::new(SoftFail).run().is_ok());
        // good evidence
        let mut s = Scenario::new(SoftFail);
        s.leaf_staple = Some(der!("rev_ocsp_good"));
        assert!(s.run().is_ok());
        // revoked, by a staple and by a list
        s.leaf_staple = Some(der!("rev_ocsp_revoked"));
        let e = s.err();
        assert!(e.contains("certificate_revoked") && e.contains("OCSP") && e.contains("key compromise"), "{}", e);
        let mut s = Scenario::new(SoftFail);
        s.crls = vec![der!("rev_crl_revoked")];
        let e = s.err();
        assert!(e.contains("certificate_revoked") && e.contains("CRL"), "{}", e);
        // unusable evidence is ignored: out of date, forged, about another certificate, unknown, garbage
        for staple in [der!("rev_ocsp_expired"), der!("rev_ocsp_forged"), der!("rev_ocsp_other_cert"), der!("rev_ocsp_unknown"), &[0xde, 0xad][..]] {
            let mut s = Scenario::new(SoftFail);
            s.leaf_staple = Some(staple);
            assert!(s.run().is_ok());
        }
        for list in [der!("rev_crl_stale"), der!("rev_crl_forged"), der!("rev_crl_other_issuer"), der!("rev_crl_idp_other_dp")] {
            let mut s = Scenario::new(SoftFail);
            s.crls = vec![list];
            assert!(s.run().is_ok());
        }
    }

    #[test]
    fn a_revoked_verdict_wins_over_a_good_one() {
        let mut s = Scenario::new(SoftFail);
        s.leaf_staple = Some(der!("rev_ocsp_good"));
        s.crls = vec![der!("rev_crl_empty"), der!("rev_crl_revoked")];
        assert!(s.err().contains("certificate_revoked"));
        let mut s = Scenario::new(HardFail);
        s.leaf_staple = Some(der!("rev_ocsp_revoked"));
        s.crls = vec![der!("rev_crl_empty")];
        assert!(s.err().contains("certificate_revoked"));
    }

    #[test]
    fn hard_fail_needs_valid_positive_evidence_for_the_leaf() {
        let e = Scenario::new(HardFail).err();
        assert!(e.contains("bad_certificate_status_response") && e.contains("no valid evidence"), "{}", e);
        // a good staple, or a covering CRL that does not list it
        let mut s = Scenario::new(HardFail);
        s.leaf_staple = Some(der!("rev_ocsp_good"));
        assert!(s.run().is_ok());
        for list in [der!("rev_crl_empty"), der!("rev_crl_idp_dp")] {
            let mut s = Scenario::new(HardFail);
            s.crls = vec![list];
            assert!(s.run().is_ok());
        }
        // unusable evidence is not evidence, and the reason is reported
        for (staple, why) in [(der!("rev_ocsp_expired"), "out of date"), (der!("rev_ocsp_forged"), "signature"), (der!("rev_ocsp_unknown"), "does not know")] {
            let mut s = Scenario::new(HardFail);
            s.leaf_staple = Some(staple);
            let e = s.err();
            assert!(e.contains("bad_certificate_status_response") && e.contains(why), "{}: {}", why, e);
        }
        for list in [der!("rev_crl_stale"), der!("rev_crl_other_issuer"), der!("rev_crl_idp_other_dp")] {
            let mut s = Scenario::new(HardFail);
            s.crls = vec![list];
            assert!(s.err().contains("bad_certificate_status_response"));
        }
    }

    #[test]
    fn must_staple_demands_a_valid_staple_in_either_checking_mode() {
        for mode in [SoftFail, HardFail] {
            let mut s = Scenario::new(mode);
            s.must_staple_leaf = true;
            let e = s.err();
            assert!(e.contains("bad_certificate_status_response") && e.contains("status_request"), "{}", e);
            // a bad staple does not do
            s.leaf_staple = Some(der!("rev_ocsp_expired"));
            assert!(s.err().contains("bad_certificate_status_response"));
            // a CRL does not do either: the certificate promised a staple
            s.leaf_staple = None;
            s.crls = vec![der!("rev_crl_empty")];
            assert!(s.err().contains("bad_certificate_status_response"));
            // the right staple does
            s.crls = vec![];
            s.leaf_staple = Some(der!("rev_ocsp_ms_good"));
            assert!(s.run().is_ok(), "{:?}", mode);
        }
        // ... but not when checking is off
        let mut s = Scenario::new(Off);
        s.must_staple_leaf = true;
        assert!(s.run().is_ok());
    }

    #[test]
    fn intermediates_are_checked_with_the_evidence_there_is() {
        // a per-certificate staple for the intermediate (it is entry 1 of what the server sent)
        let mut s = Scenario::new(SoftFail);
        s.inter_staple = Some(der!("rev_ocsp_inter_revoked"));
        let e = s.err();
        assert!(e.contains("certificate_revoked") && e.contains("Intermediate"), "{}", e);
        s.inter_staple = Some(der!("rev_ocsp_inter_good"));
        assert!(s.run().is_ok());
        // a list the caller supplied that revokes the intermediate
        let mut s = Scenario::new(SoftFail);
        s.crls = vec![der!("rev_crl_root_revokes_inter")];
        assert!(s.err().contains("certificate_revoked"));
        // hard-fail asks nothing more of an intermediate than of soft-fail
        let mut s = Scenario::new(HardFail);
        s.leaf_staple = Some(der!("rev_ocsp_good"));
        assert!(s.run().is_ok());
        // a staple attached to the wrong entry says nothing about the leaf
        let mut s = Scenario::new(HardFail);
        s.inter_staple = Some(der!("rev_ocsp_good"));
        assert!(s.err().contains("bad_certificate_status_response"));
    }

    struct CountingSource {
        asked: AtomicUsize,
        urls: Mutex<Vec<String>>,
        answer: fn() -> Result<Arc<Crl>>,
    }

    impl CrlSource for CountingSource {
        fn fetch(&self, url: &str) -> Result<Arc<Crl>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.urls.lock().unwrap().push(url.to_string());
            (self.answer)()
        }
    }

    fn source(answer: fn() -> Result<Arc<Crl>>) -> Arc<CountingSource> {
        Arc::new(CountingSource { asked: AtomicUsize::new(0), urls: Mutex::new(Vec::new()), answer })
    }

    #[test]
    fn a_crl_source_is_asked_for_the_leaf_when_nothing_else_settled_it() {
        let empty = source(|| Ok(Arc::new(crl(der!("rev_crl_empty")))));
        let mut s = Scenario::new(HardFail);
        s.source = Some(empty.clone());
        assert!(s.run().is_ok());
        assert_eq!(empty.asked.load(Ordering::SeqCst), 1);
        assert_eq!(empty.urls.lock().unwrap().as_slice(), ["http://crl.example.test/inter.crl"]);

        let revoked = source(|| Ok(Arc::new(crl(der!("rev_crl_revoked")))));
        let mut s = Scenario::new(SoftFail);
        s.source = Some(revoked);
        assert!(s.err().contains("certificate_revoked") && s.err().contains("fetched CRL"));

        // a failing source: soft-fail goes on, hard-fail refuses and says why
        let failing = source(|| Err(Error::Unavailable("connection refused".into())));
        let mut s = Scenario::new(SoftFail);
        s.source = Some(failing.clone());
        assert!(s.run().is_ok());
        s.mode = HardFail;
        let e = s.err();
        assert!(e.contains("could not get the CRL") && e.contains("connection refused"), "{}", e);

        // a fetched list that is no good is no evidence
        let stale = source(|| Ok(Arc::new(crl(der!("rev_crl_stale")))));
        let mut s = Scenario::new(HardFail);
        s.source = Some(stale);
        assert!(s.err().contains("out of date"));
    }

    #[test]
    fn a_crl_source_is_left_alone_when_it_is_not_needed() {
        let spy = source(|| Ok(Arc::new(crl(der!("rev_crl_empty")))));
        // already settled by a good staple
        let mut s = Scenario::new(HardFail);
        s.source = Some(spy.clone());
        s.leaf_staple = Some(der!("rev_ocsp_good"));
        assert!(s.run().is_ok());
        // already settled by a supplied list
        let mut s = Scenario::new(HardFail);
        s.source = Some(spy.clone());
        s.crls = vec![der!("rev_crl_empty")];
        assert!(s.run().is_ok());
        // checking is off
        let mut s = Scenario::new(Off);
        s.source = Some(spy.clone());
        assert!(s.run().is_ok());
        assert_eq!(spy.asked.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_crl_from_a_source_is_verified_like_any_other() {
        // what a source returns is not trusted: a list signed by another key is refused when it is used
        let forged = source(|| Ok(Arc::new(crl(der!("rev_crl_forged")))));
        let mut s = Scenario::new(HardFail);
        s.source = Some(forged.clone());
        let err = s.err();
        assert!(err.contains("signature") && err.contains("bad_certificate_status_response"), "{}", err);
        assert_eq!(forged.asked.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn configuration_builders() {
        assert_eq!(Revocation::default().mode, SoftFail);
        assert_eq!(Revocation::off().mode, Off);
        assert_eq!(Revocation::hard_fail().mode, HardFail);
        let r = Revocation::soft_fail().with_crl(crl(der!("rev_crl_empty"))).with_crl_source(source(|| Err(Error::Unavailable("x".into()))));
        let text = format!("{:?}", r);
        assert!(text.contains("SoftFail") && text.contains("crls: 1") && text.contains("source: true"), "{}", text);
        // a path with no issuer (a self-signed leaf trusted directly) has nothing to check
        let p = pki();
        let ev = ChainEvidence { sent: &[], staples: &[] };
        assert!(check_path(&Revocation::hard_fail(), &[p.root.clone()], &ev, NOW).is_ok());
    }

    // ---------------------------------------------------------------- Ed25519 issuers (RFC 8410)

    fn ed_pki() -> (Certificate, Certificate) {
        (parsed(&pem_cert!("ed_leaf")), parsed(&pem_cert!("ed_inter")))
    }

    #[test]
    fn ocsp_responses_signed_with_ed25519() {
        let (leaf, inter) = ed_pki();
        assert_eq!(check_ocsp(der!("ed_ocsp_good"), &leaf, &inter, NOW), Verdict::Good);
        assert_eq!(check_ocsp(der!("ed_ocsp_revoked"), &leaf, &inter, NOW), Verdict::Revoked { when: NOW - 3 * DAY, reason: Some(1) });
        invalid_with(check_ocsp(der!("ed_ocsp_forged"), &leaf, &inter, NOW), "signature");
        // the response is signed by the intermediate: another issuer's key does not make it good
        let other = parsed(&pem_cert!("ed_root"));
        assert!(!matches!(check_ocsp(der!("ed_ocsp_good"), &leaf, &other, NOW), Verdict::Good));
        invalid_with(check_ocsp(der!("ed_ocsp_good"), &leaf, &inter, NOW + 30 * DAY), "out of date");
    }

    #[test]
    fn crls_signed_with_ed25519() {
        let (leaf, inter) = ed_pki();
        assert_eq!(crl(der!("ed_crl_empty")).check(&leaf, &inter, NOW), Verdict::Good);
        assert_eq!(crl(der!("ed_crl_revoked")).check(&leaf, &inter, NOW), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(1) });
        invalid_with(crl(der!("ed_crl_revoked")).check(&leaf, &inter, NOW + 30 * DAY), "out of date");
        // a list by the intermediate says nothing about a certificate the root issued, and is not signed by the root
        let root = parsed(&pem_cert!("ed_root"));
        assert_ne!(crl(der!("ed_crl_revoked")).check(&parsed(&pem_cert!("ed_inter")), &root, NOW), Verdict::Revoked { when: NOW - 4 * DAY, reason: Some(1) });
        // damage to the signature (the last byte of the DER) is found
        let mut damaged = der!("ed_crl_revoked").to_vec();
        *damaged.last_mut().unwrap() ^= 1;
        invalid_with(crl(&damaged).check(&leaf, &inter, NOW), "signature");
    }
}
