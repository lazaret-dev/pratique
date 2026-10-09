//! Certificate Transparency: the signed certificate timestamps (SCTs) that a certificate authority embeds in a
//! certificate (RFC 6962, section 3.3), read and checked against the keys of the logs that signed them.
//!
//! A CT log signs a promise to publish a certificate, the SCT. A certificate authority that embeds SCTs sends the logs a
//! precertificate first (the certificate with a critical "poison" extension, so that nobody can use it) and puts the SCTs
//! it gets back into the certificate it issues, in the extension `1.3.6.1.4.1.11129.2.4.2`. What a log signed is
//! therefore the issued certificate's `TBSCertificate` without that extension ([`precertificate_tbs`]), with the SHA-256
//! of the issuer's `SubjectPublicKeyInfo`, the time and the SCT's own extensions ([`signed_data`]).
//!
//! Sigstore's Fulcio embeds an SCT in every certificate it issues, from the CT logs its trusted root lists (`ctlogs`);
//! [`crate::sigstore`] checks them with [`verify_embedded`]. Nothing in the TLS client checks SCTs.
//!
//! Only SCTs embedded in a certificate are read: those a server sends in the handshake or in a stapled OCSP response
//! (RFC 6962's other two ways) sign the certificate itself (an `x509_entry`) and are not handled. An SCT of a version
//! other than 1 is counted and not checked, as RFC 6962 (section 5.2) asks of clients. Nothing here reads a clock:
//! whether a log's key counted at an SCT's time is decided by the period that comes with the key.

use crate::asn1::{self, Der};
use crate::crypto::sha2::{Hash as _, Sha256};
use crate::trust_root::{KeyKind, TransparencyLog};
use crate::util::hex;
use crate::x509::{self, Certificate};
use std::fmt;

/// The extension that holds the embedded SCT list, `1.3.6.1.4.1.11129.2.4.2` (content octets).
pub const OID_SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// The precertificate poison extension, `1.3.6.1.4.1.11129.2.4.3`: a certificate that has it was made only to be logged.
pub const OID_POISON: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03];

/// At most this many SCTs are read from one certificate. Browsers ask for two or three; Fulcio embeds one.
pub const MAX_SCTS: usize = 32;

/// Why SCTs were not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The SCT list, or the certificate around it, is not well formed: the string says where and what.
    Malformed(String),
    /// An SCT names a log of the list the caller gave, and it does not verify under that log's key at its time (or it
    /// is of an algorithm that does not go with the key).
    Signature {
        /// The log's id (the SHA-256 of its key).
        log_id: [u8; 32],
        /// The SCT's time, in milliseconds since the Unix epoch.
        timestamp_ms: u64,
        /// What did not hold.
        reason: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed signed certificate timestamps: {m}"),
            Error::Signature { log_id, timestamp_ms, reason } => {
                write!(f, "the signed certificate timestamp of log {} at {timestamp_ms} ms does not verify: {reason}", hex(log_id))
            }
        }
    }
}

impl std::error::Error for Error {}

fn malformed<T>(what: &str) -> Result<T, Error> {
    Err(Error::Malformed(what.to_string()))
}

/// One SCT of version 1 (RFC 6962 section 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sct {
    /// The SHA-256 of the log's `SubjectPublicKeyInfo`.
    pub log_id: [u8; 32],
    /// When the log signed it, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The SCT's extensions (none are defined; they are signed as they are).
    pub extensions: Vec<u8>,
    /// The `DigitallySigned` hash algorithm (TLS 1.2's numbers: 4 is SHA-256, 5 is SHA-384).
    pub hash_algorithm: u8,
    /// The `DigitallySigned` signature algorithm (1 is RSA, 3 is ECDSA).
    pub signature_algorithm: u8,
    /// The signature: ASN.1 DER for ECDSA, PKCS#1 v1.5 for RSA.
    pub signature: Vec<u8>,
}

/// The SCTs of a list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SctList {
    /// The SCTs of version 1, in the order of the list.
    pub scts: Vec<Sct>,
    /// How many SCTs had another version (not read further).
    pub other_versions: usize,
}

/// The next `n` bytes of `b` from `*at`, which moves past them.
fn take<'a>(b: &'a [u8], at: &mut usize, n: usize, what: &str) -> Result<&'a [u8], Error> {
    let end = at.checked_add(n).filter(|&e| e <= b.len()).ok_or_else(|| Error::Malformed(format!("{what} is cut short")))?;
    let out = &b[*at..end];
    *at = end;
    Ok(out)
}

fn take_u16(b: &[u8], at: &mut usize, what: &str) -> Result<usize, Error> {
    let s = take(b, at, 2, what)?;
    Ok(u16::from_be_bytes([s[0], s[1]]) as usize)
}

/// A `<lo..2^16-1>` vector: its length, then that many bytes.
fn vector16<'a>(b: &'a [u8], at: &mut usize, min: usize, what: &str) -> Result<&'a [u8], Error> {
    let n = take_u16(b, at, what)?;
    if n < min {
        return malformed(&format!("{what} is empty"));
    }
    take(b, at, n, what)
}

fn parse_sct(b: &[u8]) -> Result<Option<Sct>, Error> {
    let mut at = 0;
    let version = take(b, &mut at, 1, "an SCT")?[0];
    if version != 0 {
        return Ok(None);
    }
    let log_id: [u8; 32] = take(b, &mut at, 32, "an SCT's log id")?.try_into().expect("32 bytes");
    let ts = take(b, &mut at, 8, "an SCT's timestamp")?;
    let timestamp_ms = u64::from_be_bytes(ts.try_into().expect("8 bytes"));
    let extensions = vector16(b, &mut at, 0, "an SCT's extensions")?.to_vec();
    let algs = take(b, &mut at, 2, "an SCT's signature algorithm")?;
    let signature = vector16(b, &mut at, 1, "an SCT's signature")?.to_vec();
    if at != b.len() {
        return malformed("an SCT has bytes after its signature");
    }
    Ok(Some(Sct { log_id, timestamp_ms, extensions, hash_algorithm: algs[0], signature_algorithm: algs[1], signature }))
}

/// Reads the value of the SCT list extension (the content of its `extnValue`): an OCTET STRING that holds the TLS
/// encoding of a `SignedCertificateTimestampList`, which must not be empty, nor any SCT in it.
pub fn parse_list(extension_value: &[u8]) -> Result<SctList, Error> {
    let mut d = Der::new(extension_value);
    let octets = d.expect(asn1::TAG_OCTET_STRING).map_err(|e| Error::Malformed(format!("the extension is not an OCTET STRING: {e}")))?;
    if d.finish().is_err() {
        return malformed("the extension has bytes after its OCTET STRING");
    }
    let b = octets.content;
    let mut at = 0;
    let list = vector16(b, &mut at, 1, "the SCT list")?;
    if at != b.len() {
        return malformed("the SCT list has bytes after it");
    }
    let mut out = SctList::default();
    let mut at = 0;
    while at < list.len() {
        if out.scts.len() + out.other_versions == MAX_SCTS {
            return malformed(&format!("more than {MAX_SCTS} SCTs"));
        }
        match parse_sct(vector16(list, &mut at, 1, "an SCT")?)? {
            Some(sct) => out.scts.push(sct),
            None => out.other_versions += 1,
        }
    }
    Ok(out)
}

/// The SCTs embedded in `cert`; an empty list if it has none.
pub fn embedded(cert: &Certificate) -> Result<SctList, Error> {
    match cert.extension(OID_SCT_LIST) {
        Some(ext) => parse_list(&ext.value),
        None => Ok(SctList::default()),
    }
}

/// The `TBSCertificate` a log signed for a certificate with embedded SCTs: the certificate's own (`tbs`, DER) without
/// the SCT list extension, every other byte as it was. If that leaves no extension, the extensions field goes too.
/// An error if `tbs` does not have the extension.
pub fn precertificate_tbs(tbs: &[u8]) -> Result<Vec<u8>, Error> {
    let bad = |e: crate::verify_error::Error| Error::Malformed(format!("the certificate: {e}"));
    let mut top = Der::new(tbs);
    let mut fields = top.sequence().map_err(bad)?;
    top.finish().map_err(bad)?;
    let mut content = Vec::with_capacity(tbs.len());
    let mut removed = 0;
    while !fields.is_empty() {
        let field = fields.next().map_err(bad)?;
        if field.tag != 0xa3 {
            content.extend_from_slice(field.raw);
            continue;
        }
        let mut outer = Der::new(field.content);
        let mut list = outer.sequence().map_err(bad)?;
        outer.finish().map_err(bad)?;
        let mut kept = Vec::with_capacity(field.content.len());
        while !list.is_empty() {
            let ext = list.expect(asn1::TAG_SEQUENCE).map_err(bad)?;
            let oid = Der::new(ext.content).expect(asn1::TAG_OID).map_err(bad)?;
            if oid.content == OID_SCT_LIST {
                removed += 1;
            } else {
                kept.extend_from_slice(ext.raw);
            }
        }
        if !kept.is_empty() {
            content.extend_from_slice(&x509::tlv(0xa3, &x509::tlv(asn1::TAG_SEQUENCE, &kept)));
        }
    }
    match removed {
        1 => Ok(x509::tlv(asn1::TAG_SEQUENCE, &content)),
        0 => malformed("the certificate has no SCT list extension"),
        _ => malformed("the certificate has the SCT list extension more than once"),
    }
}

/// What a log signs for an embedded SCT of version 1 (RFC 6962 section 3.2, a `precert_entry`): the version, the
/// signature type (a certificate timestamp), the time, the entry type, the SHA-256 of the issuer's
/// `SubjectPublicKeyInfo`, the precertificate's `TBSCertificate` ([`precertificate_tbs`]) and the SCT's extensions.
pub fn signed_data(sct: &Sct, issuer_key_hash: &[u8; 32], precert_tbs: &[u8]) -> Result<Vec<u8>, Error> {
    if precert_tbs.len() >= 1 << 24 || sct.extensions.len() > u16::MAX as usize {
        return malformed("too long to be signed");
    }
    let mut out = Vec::with_capacity(precert_tbs.len() + 60);
    out.extend_from_slice(&[0, 0]); // version v1, signature type certificate_timestamp
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&[0, 1]); // entry type precert_entry
    out.extend_from_slice(issuer_key_hash);
    out.extend_from_slice(&(precert_tbs.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(precert_tbs);
    out.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

/// The `DigitallySigned` algorithms (hash, signature) that go with a log key of this kind. RFC 6962 has logs sign with
/// ECDSA or RSA; an Ed25519 key is not a CT log key.
fn algorithms_for(kind: KeyKind) -> Option<(u8, u8)> {
    match kind {
        KeyKind::EcdsaP256 => Some((4, 3)),
        KeyKind::EcdsaP384 => Some((5, 3)),
        KeyKind::Rsa => Some((4, 1)),
        KeyKind::Ed25519 => None,
    }
}

/// An SCT that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSct {
    /// The log's id, as the SCT and the trusted list give it.
    pub log_id: Vec<u8>,
    /// The log's address, from the list.
    pub log_url: String,
    /// When the log signed it, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// What [`verify_embedded`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The SCTs that verified, in the order of the certificate.
    pub verified: Vec<VerifiedSct>,
    /// The log ids of the SCTs from logs that are not in the list (not checked).
    pub unknown_logs: Vec<[u8; 32]>,
    /// How many SCTs had a version other than 1 (not checked).
    pub other_versions: usize,
}

impl Report {
    /// How many different logs the verified SCTs come from: what a policy of "SCTs from N logs" counts.
    pub fn distinct_logs(&self) -> usize {
        let mut ids: Vec<&[u8]> = self.verified.iter().map(|v| v.log_id.as_slice()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }
}

/// Checks the SCTs embedded in `cert`, which `issuer` issued, against `logs`. An SCT from a log that is not in `logs`
/// is reported and not checked; an SCT from a log that is must verify under a key of that log whose period includes
/// the SCT's time, or the whole check fails: a log that is trusted does not sign wrong SCTs, so one is a sign that
/// something was altered. A certificate without SCTs gives an empty report; how many SCTs are enough is the caller's
/// policy ([`Report::distinct_logs`]).
///
/// `issuer` must be the certificate that issued `cert` (the caller has verified the chain): the SCTs sign the hash of
/// its key, so an SCT is only as good as the path it was checked with.
pub fn verify_embedded(cert: &Certificate, issuer: &Certificate, logs: &[TransparencyLog]) -> Result<Report, Error> {
    let list = embedded(cert)?;
    let mut report = Report { other_versions: list.other_versions, ..Report::default() };
    if list.scts.is_empty() {
        return Ok(report);
    }
    let tbs = precertificate_tbs(cert.tbs_der())?;
    let issuer_key_hash: [u8; 32] = Sha256::digest(issuer.spki_der()).try_into().expect("a SHA-256 digest is 32 bytes");
    for sct in &list.scts {
        let candidates: Vec<&TransparencyLog> = logs.iter().filter(|l| l.log_id == sct.log_id).collect();
        if candidates.is_empty() {
            report.unknown_logs.push(sct.log_id);
            continue;
        }
        let fail = |reason: String| Error::Signature { log_id: sct.log_id, timestamp_ms: sct.timestamp_ms, reason };
        let time = (sct.timestamp_ms / 1000) as i64;
        let message = signed_data(sct, &issuer_key_hash, &tbs)?;
        let mut why = format!("no key of the log was valid at {time}");
        let mut good = None;
        for log in candidates.iter().filter(|l| l.valid_for.contains(time)) {
            match algorithms_for(log.key.kind()) {
                Some(algs) if algs == (sct.hash_algorithm, sct.signature_algorithm) => {}
                Some((h, s)) => {
                    why = format!("signed with algorithms ({}, {}), and the log's key goes with ({h}, {s})", sct.hash_algorithm, sct.signature_algorithm);
                    continue;
                }
                None => {
                    why = "the log's key is of a kind that does not sign SCTs".into();
                    continue;
                }
            }
            if log.key.verify(&message, &sct.signature) {
                good = Some(log);
                break;
            }
            why = "the signature is not the log's".into();
        }
        let log = good.ok_or_else(|| fail(why))?;
        report.verified.push(VerifiedSct { log_id: log.log_id.clone(), log_url: log.base_url.clone(), timestamp_ms: sct.timestamp_ms });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sct_bytes(version: u8, log_id: [u8; 32], ts: u64, ext: &[u8], algs: (u8, u8), sig: &[u8]) -> Vec<u8> {
        let mut b = vec![version];
        b.extend_from_slice(&log_id);
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        b.extend_from_slice(ext);
        b.extend_from_slice(&[algs.0, algs.1]);
        b.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        b.extend_from_slice(sig);
        b
    }

    fn list_value(scts: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = Vec::new();
        for s in scts {
            inner.extend_from_slice(&(s.len() as u16).to_be_bytes());
            inner.extend_from_slice(s);
        }
        let mut tls = (inner.len() as u16).to_be_bytes().to_vec();
        tls.extend_from_slice(&inner);
        x509::tlv(asn1::TAG_OCTET_STRING, &tls)
    }

    #[test]
    fn the_oids_are_rfc_6962s() {
        assert_eq!(asn1::oid_to_string(OID_SCT_LIST), "1.3.6.1.4.1.11129.2.4.2");
        assert_eq!(asn1::oid_to_string(OID_POISON), "1.3.6.1.4.1.11129.2.4.3");
    }

    #[test]
    fn a_list_is_read_with_its_fields_and_other_versions_counted() {
        let a = sct_bytes(0, [7; 32], 1_700_000_000_123, b"", (4, 3), &[0x30, 0x00]);
        let b = sct_bytes(0, [8; 32], 1, b"xy", (4, 1), &[1, 2, 3]);
        let v2 = vec![1, 2, 3, 4];
        let list = parse_list(&list_value(&[a, v2, b])).unwrap();
        assert_eq!(list.other_versions, 1);
        assert_eq!(list.scts.len(), 2);
        assert_eq!(list.scts[0], Sct { log_id: [7; 32], timestamp_ms: 1_700_000_000_123, extensions: vec![], hash_algorithm: 4, signature_algorithm: 3, signature: vec![0x30, 0] });
        assert_eq!(list.scts[1].extensions, b"xy");
        assert_eq!(list.scts[1].signature, [1, 2, 3]);
    }

    #[test]
    fn a_malformed_list_is_refused() {
        let good = sct_bytes(0, [7; 32], 5, b"", (4, 3), &[1]);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![], "OCTET STRING"),
            (x509::tlv(asn1::TAG_SEQUENCE, &[0, 0]), "OCTET STRING"),
            ([list_value(std::slice::from_ref(&good)), vec![0]].concat(), "after its OCTET STRING"),
            (x509::tlv(asn1::TAG_OCTET_STRING, &[0, 0]), "the SCT list is empty"),
            (x509::tlv(asn1::TAG_OCTET_STRING, &[0, 5, 0, 1, 0]), "cut short"),
            (x509::tlv(asn1::TAG_OCTET_STRING, &[0, 2, 0, 0, 9]), "the SCT list has bytes after it"),
            (list_value(&[vec![]]), "an SCT is empty"),
            (list_value(&[good[..40].to_vec()]), "an SCT's timestamp is cut short"),
            (list_value(&[[&good[..], &[0]].concat()]), "bytes after its signature"),
            (list_value(&[sct_bytes(0, [7; 32], 5, b"", (4, 3), &[])]), "an SCT's signature is empty"),
        ];
        for (value, want) in cases {
            let e = parse_list(&value).unwrap_err().to_string();
            assert!(e.contains(want), "{e} / {want}");
        }
        let many: Vec<Vec<u8>> = (0..=MAX_SCTS).map(|_| good.clone()).collect();
        assert!(parse_list(&list_value(&many)).unwrap_err().to_string().contains("more than 32"));
        assert_eq!(parse_list(&list_value(&many[..MAX_SCTS])).unwrap().scts.len(), MAX_SCTS);
    }

    /// A TBSCertificate with these extensions (each `(oid, value)`), for the precertificate tests.
    fn tbs_with(exts: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut c = x509::tlv(0xa0, &[2, 1, 2]);
        c.extend_from_slice(&[2, 1, 9]);
        c.extend_from_slice(&x509::tlv(asn1::TAG_SEQUENCE, &[6, 3, 0x2a, 0x86, 0x48]));
        if !exts.is_empty() {
            let mut list = Vec::new();
            for (oid, value) in exts {
                let mut e = x509::tlv(asn1::TAG_OID, oid);
                e.extend_from_slice(&x509::tlv(asn1::TAG_OCTET_STRING, value));
                list.extend_from_slice(&x509::tlv(asn1::TAG_SEQUENCE, &e));
            }
            c.extend_from_slice(&x509::tlv(0xa3, &x509::tlv(asn1::TAG_SEQUENCE, &list)));
        }
        x509::tlv(asn1::TAG_SEQUENCE, &c)
    }

    #[test]
    fn the_precertificate_is_the_certificate_without_the_list() {
        let other: &[u8] = &[0x55, 0x1d, 0x0f];
        let long = vec![0x41; 300];
        // in the middle, first, last, with lengths that change their own size
        assert_eq!(precertificate_tbs(&tbs_with(&[(other, b"a"), (OID_SCT_LIST, &long), (other, b"b")])).unwrap(), tbs_with(&[(other, b"a"), (other, b"b")]));
        assert_eq!(precertificate_tbs(&tbs_with(&[(OID_SCT_LIST, b"x"), (other, &long)])).unwrap(), tbs_with(&[(other, &long)]));
        assert_eq!(precertificate_tbs(&tbs_with(&[(other, &long), (OID_SCT_LIST, b"x")])).unwrap(), tbs_with(&[(other, &long)]));
        // the only extension: the field goes
        assert_eq!(precertificate_tbs(&tbs_with(&[(OID_SCT_LIST, b"x")])).unwrap(), tbs_with(&[]));
        // without it, twice, or not a certificate
        assert!(precertificate_tbs(&tbs_with(&[(other, b"a")])).unwrap_err().to_string().contains("no SCT list"));
        assert!(precertificate_tbs(&tbs_with(&[(OID_SCT_LIST, b"x"), (OID_SCT_LIST, b"y")])).unwrap_err().to_string().contains("more than once"));
        assert!(precertificate_tbs(&tbs_with(&[])).is_err());
        assert!(precertificate_tbs(&[0x30, 0x03, 0xa3, 0x01, 0x30]).is_err());
        assert!(precertificate_tbs(&[&tbs_with(&[(OID_SCT_LIST, b"x")])[..], &[0]].concat()).is_err());
    }

    #[test]
    fn the_signed_data_is_rfc_6962s_precert_entry() {
        let sct = Sct { log_id: [0; 32], timestamp_ms: 0x0102030405060708, extensions: vec![0xee], hash_algorithm: 4, signature_algorithm: 3, signature: vec![1] };
        let d = signed_data(&sct, &[9; 32], b"TBS").unwrap();
        let mut want = vec![0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1];
        want.extend_from_slice(&[9; 32]);
        want.extend_from_slice(&[0, 0, 3, b'T', b'B', b'S', 0, 1, 0xee]);
        assert_eq!(d, want);
    }

    #[test]
    fn the_algorithms_go_with_the_key() {
        assert_eq!(algorithms_for(KeyKind::EcdsaP256), Some((4, 3)));
        assert_eq!(algorithms_for(KeyKind::EcdsaP384), Some((5, 3)));
        assert_eq!(algorithms_for(KeyKind::Rsa), Some((4, 1)));
        assert_eq!(algorithms_for(KeyKind::Ed25519), None);
    }

    #[test]
    fn a_report_counts_distinct_logs() {
        let v = |id: u8| VerifiedSct { log_id: vec![id; 32], log_url: String::new(), timestamp_ms: 0 };
        let r = Report { verified: vec![v(1), v(2), v(1)], ..Report::default() };
        assert_eq!(r.distinct_logs(), 2);
        assert_eq!(Report::default().distinct_logs(), 0);
    }

    #[test]
    fn errors_say_which_log_and_why() {
        let e = Error::Signature { log_id: [0xab; 32], timestamp_ms: 7, reason: "because".into() };
        let s = e.to_string();
        assert!(s.contains("abababab") && s.contains("at 7 ms") && s.contains("because"), "{s}");
    }
}
