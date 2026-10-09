//! Revocation evidence from real public CAs (BACKLOG B-65): OCSP responses and CRLs that GlobalSign, Sectigo, Amazon,
//! DigiCert, Apple, Microsoft, Google Trust Services and Let's Encrypt served on 2026-10-07 and 2026-10-08 about the
//! certificates of real hosts. `tools/mac_field_check.sh capture` asked each certificate's own responder (`openssl ocsp`) and
//! downloaded its own distribution point, writing down the time; `field_check revocation` checked every one of them (48
//! responses and 100 lists over the two runs, up to 14 MB) and wrote the candidates, of which `tests/data/real_revocation/` keeps a mix: responses
//! signed by the CA and by a delegated responder, with RSA (SHA-256 and SHA-384) and ECDSA signatures; lists scoped by an
//! issuing distribution point (Let's Encrypt and Google shards, a Microsoft partition) and lists that cover everything
//! the CA issued, empty ones and one of 4,874 entries.
//!
//! Every one is replayed at the moment it was fetched: it must settle its certificate under hard-fail, through the
//! sources as well as handed over, and the request the library would have sent must name the certificate exactly as the
//! real responder's answer does. Then the ways it must stop counting: a second outside its window, any changed byte,
//! another certificate (same CA, another shard of the same CA), the wrong issuer; and the entries real lists carry must
//! revoke a certificate with their serial, with the date and reason the list gives (cross-checked with Python
//! `cryptography`).
//!
//! Every response here uses a SHA-1 certificate ID, because that is what the request asked for and what every responder
//! answers to (RFC 5019); SHA-256 IDs are covered by the generated fixtures of the unit tests only. Five say revoked (the
//! `expect` column of `fixtures.tsv`): what DigiCert's responders and lists and a Let's Encrypt shard said on 2026-10-08
//! about the certificates of their revoked test sites (the `revoked` group of `tools/field_hosts.txt`, BACKLOG B-100,
//! B-102). Those must be refused as revoked where the others are settled as good, and are refused like the others, as
//! no evidence, once altered.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use pratique::asn1::{self, Der};
use pratique::revocation::{self, ChainEvidence, Crl, CrlSource, OcspSource, Revocation};
use pratique::verify_error::{Error, Result as VResult};
use pratique::x509::Certificate;
use pratique::pem;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/real_revocation");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Ocsp,
    Crl,
}

/// One line of `fixtures.tsv` with its files read.
struct Fixture {
    kind: Kind,
    name: String,
    /// When it was fetched (Unix seconds).
    time: i64,
    file: String,
    evidence: Vec<u8>,
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    /// Where it was fetched from.
    url: String,
    this_update: i64,
    /// nextUpdate.
    valid_until: i64,
    /// What `field_check` read it to be, checked again here.
    shape: String,
    /// What it says about the certificate: `Ok` for good, `Err` for revoked (a certificate of the `revoked` group of
    /// `tools/field_hosts.txt`, which the capture of 2026-10-07 did not have yet).
    revoked: bool,
}

fn fixtures() -> Vec<Fixture> {
    let text = std::fs::read_to_string(format!("{DIR}/fixtures.tsv")).expect("fixtures.tsv");
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let c: Vec<&str> = line.split('\t').collect();
        assert_eq!(c.len(), 10, "{line}");
        let pem_text = std::fs::read_to_string(format!("{DIR}/{}", c[4])).expect(c[4]);
        let certs: Vec<Vec<u8>> = pem::parse(&pem_text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect();
        assert_eq!(certs.len(), 2, "{}: the leaf and its issuer", c[4]);
        out.push(Fixture {
            kind: match c[0] {
                "ocsp" => Kind::Ocsp,
                "crl" => Kind::Crl,
                k => panic!("unknown kind {k}"),
            },
            name: c[1].to_string(),
            time: c[2].parse().unwrap(),
            file: c[3].to_string(),
            evidence: std::fs::read(format!("{DIR}/{}", c[3])).expect(c[3]),
            leaf: certs[0].clone(),
            issuer: certs[1].clone(),
            url: c[5].to_string(),
            this_update: c[6].parse().unwrap(),
            valid_until: c[7].parse().unwrap(),
            shape: c[8].to_string(),
            revoked: match c[9] {
                "good" => false,
                "revoked" => true,
                e => panic!("unknown expectation {e}"),
            },
        });
    }
    out
}

/// Hard-fail checking of `leaf` (issued by `issuer`) at `now` with `evidence` as a stapled response or a supplied list.
fn settle(kind: Kind, evidence: &[u8], leaf: &[u8], issuer: &[u8], now: i64) -> Result<(), String> {
    let mut cfg = Revocation::hard_fail();
    if kind == Kind::Crl {
        cfg = cfg.with_crl(Crl::from_der(evidence).map_err(|e| format!("the list does not parse: {e}"))?);
    }
    let path = vec![leaf.to_vec(), issuer.to_vec()];
    let staples = vec![(kind == Kind::Ocsp).then(|| evidence.to_vec())];
    revocation::check_path(&cfg, &path, &ChainEvidence { sent: &path[..1], staples: &staples }, now).map_err(|e| match e {
        Error::Certificate(m) => m,
        other => other.to_string(),
    })
}

fn check(f: &Fixture, evidence: &[u8], now: i64) -> Result<(), String> {
    settle(f.kind, evidence, &f.leaf, &f.issuer, now)
}

/// That `r` is what `f`'s evidence says: settled as good, or refused as revoked.
fn assert_says(f: &Fixture, r: Result<(), String>, what: &str) {
    match (f.revoked, r) {
        (false, Ok(())) => {}
        (true, Err(e)) if e.starts_with("certificate_revoked:") => {}
        (_, r) => panic!("{} {:?} {what}: {r:?} (expected {})", f.name, f.kind, if f.revoked { "revoked" } else { "good" }),
    }
}

/// Refused as missing evidence (or as a list that does not parse), never as a revocation.
fn assert_refused(r: Result<(), String>, what: &str) {
    match r {
        Ok(()) => panic!("{what}: accepted"),
        Err(e) => assert!(e.starts_with("bad_certificate_status_response:") || e.starts_with("the list does not parse"), "{what}: {e}"),
    }
}

// ------------------------------------------------------------------------------------------------ reading DER

fn sig_alg_name(alg: &[u8]) -> String {
    let oid = asn1::oid_to_string(Der::new(alg).expect(asn1::TAG_OID).unwrap().content);
    match oid.as_str() {
        "1.2.840.113549.1.1.11" => "RSA-SHA256",
        "1.2.840.113549.1.1.12" => "RSA-SHA384",
        "1.2.840.113549.1.1.13" => "RSA-SHA512",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        other => panic!("unexpected signature algorithm {other}"),
    }
    .to_string()
}

/// The parts of an OCSP response this file looks at, read without verifying anything.
struct OcspParts {
    /// The CertID of the first single response, as written.
    cert_id: Vec<u8>,
    /// Signed by the issuer (the responder named by the issuer key hash of a SHA-1 CertID) or by a responder whose
    /// certificate it carries.
    delegated: bool,
    id_hash: &'static str,
    sig: String,
    this_update: i64,
    next_update: i64,
    /// The status says revoked (and not good: nothing else is kept).
    revoked: bool,
}

fn ocsp_parts(der: &[u8]) -> OcspParts {
    use asn1::{TAG_BIT_STRING, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
    let mut resp = Der::new(der).sequence().unwrap();
    assert_eq!(resp.expect(0x0a).unwrap().content, [0]);
    let mut rb = Der::new(resp.expect(0xa0).unwrap().content).sequence().unwrap();
    rb.expect(TAG_OID).unwrap();
    let mut basic = Der::new(rb.expect(TAG_OCTET_STRING).unwrap().content).sequence().unwrap();
    let tbs = basic.expect(TAG_SEQUENCE).unwrap();
    let alg = basic.expect(TAG_SEQUENCE).unwrap();
    basic.expect(TAG_BIT_STRING).unwrap();
    let certs = basic.optional(0xa0).unwrap().is_some();
    let mut data = Der::new(tbs.content);
    data.optional(0xa0).unwrap();
    let rid = data.next().unwrap();
    data.next().unwrap();
    let mut singles = data.sequence().unwrap();
    let mut sr = singles.sequence().unwrap();
    assert!(singles.is_empty(), "one answer per response");
    let id_tlv = sr.expect(TAG_SEQUENCE).unwrap();
    let mut id = Der::new(id_tlv.content);
    let hash = asn1::oid_to_string(Der::new(id.expect(TAG_SEQUENCE).unwrap().content).expect(TAG_OID).unwrap().content);
    id.expect(TAG_OCTET_STRING).unwrap();
    let issuer_key_hash = id.expect(TAG_OCTET_STRING).unwrap().content;
    let revoked = match sr.next().unwrap().tag {
        0x80 => false,
        0xa1 => true,
        t => panic!("a status that is neither good nor revoked: {t:#x}"),
    };
    let this_update = asn1::parse_time(&sr.next().unwrap()).unwrap();
    let next_update = asn1::parse_time(&Der::new(sr.expect(0xa0).unwrap().content).next().unwrap()).unwrap();
    let id_hash = if hash == "1.3.14.3.2.26" { "SHA-1" } else { "other" };
    let by_issuer_key = rid.tag == 0xa2 && Der::new(rid.content).expect(TAG_OCTET_STRING).unwrap().content == issuer_key_hash;
    assert!(by_issuer_key || certs, "a response not signed by the issuer carries its responder's certificate");
    OcspParts { cert_id: id_tlv.raw.to_vec(), delegated: !by_issuer_key, id_hash, sig: sig_alg_name(alg.content), this_update, next_update, revoked }
}

/// A list's signature algorithm and whether it has an issuingDistributionPoint.
fn crl_parts(der: &[u8]) -> (String, bool) {
    let mut list = Der::new(der).sequence().unwrap();
    let mut tbs = Der::new(list.expect(asn1::TAG_SEQUENCE).unwrap().content);
    tbs.optional(asn1::TAG_INTEGER).unwrap();
    let alg = tbs.expect(asn1::TAG_SEQUENCE).unwrap();
    let mut scoped = false;
    while !tbs.is_empty() {
        let t = tbs.next().unwrap();
        if t.tag == 0xa0 {
            let mut exts = Der::new(Der::new(t.content).expect(asn1::TAG_SEQUENCE).unwrap().content);
            while !exts.is_empty() {
                scoped |= exts.sequence().unwrap().expect(asn1::TAG_OID).unwrap().content == [0x55, 0x1d, 0x1c];
            }
        }
    }
    (sig_alg_name(alg.content), scoped)
}

/// The CertID of the single request in a DER OCSPRequest.
fn request_cert_id(der: &[u8]) -> Vec<u8> {
    let mut tbs = Der::new(Der::new(der).sequence().unwrap().expect(asn1::TAG_SEQUENCE).unwrap().content);
    let mut list = tbs.sequence().unwrap();
    let mut request = list.sequence().unwrap();
    assert!(list.is_empty());
    request.expect(asn1::TAG_SEQUENCE).unwrap().raw.to_vec()
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// `cert` with its serial number replaced (and so its signature no longer valid, which revocation checking does not look
/// at: it is handed a path that has been verified).
fn with_serial(cert: &[u8], serial_hex: &str) -> Vec<u8> {
    let hex = if serial_hex.len() % 2 == 1 { format!("0{serial_hex}") } else { serial_hex.to_string() };
    let mut serial: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    if serial[0] & 0x80 != 0 {
        serial.insert(0, 0);
    }
    let mut outer = Der::new(cert).sequence().unwrap();
    let tbs = outer.expect(asn1::TAG_SEQUENCE).unwrap();
    let rest: Vec<u8> = std::iter::from_fn(|| (!outer.is_empty()).then(|| outer.next().unwrap().raw.to_vec())).flatten().collect();
    let mut t = Der::new(tbs.content);
    let mut body = t.optional(0xa0).unwrap().map(|v| v.raw.to_vec()).unwrap_or_default();
    t.expect(asn1::TAG_INTEGER).unwrap();
    body.extend(tlv(asn1::TAG_INTEGER, &serial));
    while !t.is_empty() {
        body.extend_from_slice(t.next().unwrap().raw);
    }
    tlv(asn1::TAG_SEQUENCE, &[tlv(asn1::TAG_SEQUENCE, &body), rest].concat())
}

// ------------------------------------------------------------------------------------------------ tests

#[test]
fn each_real_response_and_list_settles_its_certificate_when_it_was_fetched() {
    let all = fixtures();
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    let mut cas = BTreeSet::new();
    let mut leaves_per_list: BTreeMap<&str, usize> = BTreeMap::new();
    let mut largest = 0;
    for f in &all {
        assert_says(f, check(f, &f.evidence, f.time), "at its fetch time");
        let leaf = Certificate::from_der(&f.leaf).unwrap();
        cas.insert(Certificate::from_der(&f.issuer).unwrap().subject_summary());
        match f.kind {
            Kind::Ocsp => {
                assert!(leaf.ocsp_uris().contains(&f.url), "{}: the certificate names {:?}", f.name, leaf.ocsp_uris());
                let p = ocsp_parts(&f.evidence);
                let shape = format!("{} {}-id {}", if p.delegated { "delegated" } else { "issuer" }, p.id_hash, p.sig);
                assert_eq!(shape, f.shape, "{}", f.name);
                assert_eq!((p.this_update, p.next_update, p.revoked), (f.this_update, f.valid_until, f.revoked), "{}", f.name);
                *shapes.entry(format!("OCSP {shape}")).or_insert(0) += 1;
            }
            Kind::Crl => {
                assert!(leaf.crl_uris().contains(&f.url), "{}: the certificate names {:?}", f.name, leaf.crl_uris());
                let crl = Crl::from_der(&f.evidence).unwrap();
                let (sig, scoped) = crl_parts(&f.evidence);
                let shape = format!("{} entries, {}, {sig}", crl.len(), if scoped { "scoped" } else { "unscoped" });
                assert_eq!(shape, f.shape, "{}", f.name);
                assert_eq!((crl.this_update(), crl.valid_until()), (f.this_update, f.valid_until), "{}", f.name);
                largest = largest.max(crl.len());
                *leaves_per_list.entry(&f.file).or_insert(0) += 1;
                *shapes.entry(format!("CRL {}{sig}{}", if scoped { "scoped " } else { "" }, if crl.is_empty() { " empty" } else { "" })).or_insert(0) += 1;
            }
        }
    }
    // the mix this file promises
    let count = |p: &str| shapes.iter().filter(|(k, _)| k.contains(p)).map(|(_, n)| n).sum::<usize>();
    assert!(count("OCSP issuer") >= 5 && count("OCSP delegated") >= 5, "{shapes:?}");
    assert!(count("OCSP issuer SHA-1-id ECDSA") >= 1 && count("OCSP delegated SHA-1-id RSA-SHA384") >= 1, "{shapes:?}");
    assert!(count("CRL scoped ECDSA-SHA256") >= 3 && count("CRL scoped ECDSA-SHA384") >= 1, "{shapes:?}");
    assert!(count("CRL RSA") >= 3 && count("CRL scoped RSA-SHA384") >= 1 && count("empty") >= 2, "{shapes:?}");
    assert!(largest >= 4000, "a large list: {largest}");
    assert!(leaves_per_list.values().any(|&n| n >= 2), "a list that settles more than one certificate");
    assert!(cas.len() >= 15, "{} issuing CAs: {cas:?}", cas.len());
    // real evidence of revocation (the CAs' revoked test sites, field run of 2026-10-08): responses and lists
    let revoked = |k: Kind| all.iter().filter(|f| f.revoked && f.kind == k).count();
    assert!(revoked(Kind::Ocsp) >= 3 && revoked(Kind::Crl) >= 2, "{} responses, {} lists", revoked(Kind::Ocsp), revoked(Kind::Crl));
}

/// Serves each fixture at its own URL only, and answers an OCSP request only if it is the one the library should send.
#[derive(Default)]
struct Served {
    ocsp: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    crl: BTreeMap<String, Arc<Crl>>,
    asked: Mutex<Vec<String>>,
}

impl OcspSource for Served {
    fn fetch(&self, url: &str, request: &[u8]) -> VResult<Vec<u8>> {
        self.asked.lock().unwrap().push(url.to_string());
        match self.ocsp.get(url) {
            Some((expected, response)) if expected == request => Ok(response.clone()),
            Some(_) => Err(Error::Unavailable("not the request the certificate calls for".into())),
            None => Err(Error::Unavailable(format!("nothing at {url}"))),
        }
    }
}

impl CrlSource for Served {
    fn fetch(&self, url: &str) -> VResult<Arc<Crl>> {
        self.asked.lock().unwrap().push(url.to_string());
        self.crl.get(url).cloned().ok_or_else(|| Error::Unavailable(format!("nothing at {url}")))
    }
}

#[test]
fn the_sources_ask_where_the_certificate_says_and_the_request_names_it_as_the_real_responder_did() {
    for f in fixtures() {
        let leaf = Certificate::from_der(&f.leaf).unwrap();
        let issuer = Certificate::from_der(&f.issuer).unwrap();
        let mut served = Served::default();
        let request = revocation::ocsp_request(&leaf, &issuer);
        match f.kind {
            Kind::Ocsp => {
                // the CertID we would send is the one the CA's responder answered about, byte for byte
                assert_eq!(request_cert_id(&request), ocsp_parts(&f.evidence).cert_id, "{}", f.name);
                served.ocsp.insert(f.url.clone(), (request, f.evidence.clone()));
            }
            Kind::Crl => {
                served.crl.insert(f.url.clone(), Arc::new(Crl::from_der(&f.evidence).unwrap()));
            }
        }
        let served = Arc::new(served);
        let cfg = Revocation::hard_fail().with_ocsp_source(served.clone()).with_crl_source(served.clone());
        let path = vec![f.leaf.clone(), f.issuer.clone()];
        let staples = vec![None];
        let r = revocation::check_path(&cfg, &path, &ChainEvidence { sent: &path[..1], staples: &staples }, f.time).map_err(|e| match e {
            Error::Certificate(m) => m,
            other => other.to_string(),
        });
        assert_says(&f, r, "through the sources");
        let asked = served.asked.lock().unwrap().clone();
        assert_eq!(asked.last(), Some(&f.url), "{}: {asked:?}", f.name);
        // OCSP is asked first; a list is fetched only after the responders the certificate names (if any) had nothing
        let responders = leaf.ocsp_uris().iter().filter(|u| u.starts_with("http://")).take(2).count();
        assert_eq!(asked.len(), if f.kind == Kind::Ocsp { 1 } else { responders + 1 }, "{}: {asked:?}", f.name);
    }
}

#[test]
fn each_counts_to_the_second_of_its_window_and_not_after() {
    for f in fixtures() {
        let at = |now| check(&f, &f.evidence, now);
        assert_says(&f, at(f.valid_until), "at nextUpdate");
        assert_says(&f, at(f.this_update - 300), "five minutes before thisUpdate");
        let late = at(f.valid_until + 1).unwrap_err();
        assert!(late.starts_with("bad_certificate_status_response:") && late.contains("out of date"), "{}: {late}", f.name);
        let early = at(f.this_update - 301).unwrap_err();
        assert!(early.starts_with("bad_certificate_status_response:") && early.contains("not yet valid"), "{}: {early}", f.name);
    }
}

#[test]
fn no_changed_byte_is_accepted() {
    let all = fixtures();
    let mut seen = BTreeSet::new();
    let unique: Vec<&Fixture> = all.iter().filter(|f| seen.insert(f.file.clone())).collect();
    // one thread per piece of evidence: about 60,000 checks
    let tried: usize = std::thread::scope(|s| {
        let handles: Vec<_> = unique
            .iter()
            .map(|f| {
                s.spawn(move || {
                    let n = f.evidence.len();
                    // every byte of the small ones, two ways; of a big list, its start and end (header, signature) and a
                    // spread through the entries
                    let (positions, flips): (Vec<usize>, &[u8]) = if n <= 8 << 10 {
                        ((0..n).collect(), &[0x01, 0x80])
                    } else {
                        let mut p: BTreeSet<usize> = (0..128).chain(n - 512..n).collect();
                        p.extend((0..128).map(|k| 128 + k * (n - 640) / 128));
                        (p.into_iter().collect(), &[0x01])
                    };
                    let mut tried = 0;
                    for at in positions {
                        for &bits in flips {
                            let mut altered = f.evidence.clone();
                            altered[at] ^= bits;
                            assert_refused(check(f, &altered, f.time), &format!("{} with byte {at} of {n} xor {bits:#04x}", f.file));
                            tried += 1;
                        }
                    }
                    // cut short anywhere, it is not evidence either
                    for len in [0, 1, n / 3, n - 1] {
                        assert_refused(check(f, &f.evidence[..len], f.time), &format!("{} cut to {len} bytes", f.file));
                    }
                    tried
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    assert!(tried > 50_000, "{tried}");
}

#[test]
fn evidence_about_one_certificate_settles_no_other() {
    let all = fixtures();
    // each certificate once, with its issuer
    let mut seen = BTreeSet::new();
    let certs: Vec<&Fixture> = all.iter().filter(|f| seen.insert(f.leaf.clone())).collect();
    let (mut same_ca_other_cert, mut same_ca_other_shard, mut same_ca_covered) = (0, 0, 0);
    for f in &all {
        for g in certs.iter().filter(|g| g.leaf != f.leaf) {
            let what = format!("the {:?} evidence of {} for {}", f.kind, f.name, g.name);
            let r = settle(f.kind, &f.evidence, &g.leaf, &g.issuer, f.time);
            let same_ca = g.issuer == f.issuer;
            match f.kind {
                // a response is about one serial number
                Kind::Ocsp => {
                    same_ca_other_cert += same_ca as usize;
                    assert_refused(r, &what);
                }
                Kind::Crl if !same_ca => assert_refused(r, &what),
                // a list scoped to one distribution point does not cover the CA's certificates that name another
                Kind::Crl if crl_parts(&f.evidence).1 && !Certificate::from_der(&g.leaf).unwrap().crl_uris().contains(&f.url) => {
                    same_ca_other_shard += 1;
                    assert_refused(r, &what);
                }
                // and a list that covers it settles it: good, unless it is a certificate its CA revoked (one of the CAs'
                // revoked test sites), which is then on the list
                Kind::Crl => {
                    same_ca_covered += 1;
                    let revoked = all.iter().any(|h| h.leaf == g.leaf && h.revoked);
                    match r {
                        Ok(()) if !revoked => {}
                        Err(e) if revoked && e.starts_with("certificate_revoked:") => {}
                        r => panic!("{what}: {r:?} (the certificate is {})", if revoked { "revoked" } else { "good" }),
                    }
                }
            }
        }
        // the right certificate with the wrong issuer
        let other = all.iter().find(|g| g.issuer != f.issuer).unwrap();
        assert_refused(settle(f.kind, &f.evidence, &f.leaf, &other.issuer, f.time), &format!("{} with the issuer of {}", f.name, other.name));
    }
    assert!(same_ca_other_cert >= 4, "OCSP responses tried on another certificate of the same CA: {same_ca_other_cert}");
    assert!(same_ca_other_shard >= 6, "scoped lists tried on another shard of the same CA: {same_ca_other_shard}");
    assert!(same_ca_covered >= 4, "lists tried on another certificate they cover: {same_ca_covered}");
}

#[test]
fn a_certificate_a_real_list_names_is_refused_with_the_date_and_reason_it_gives() {
    // (a certificate the list covers, an entry of the list: serial, revocationDate, reason), read with Python
    // `cryptography`; an entry with no reasonCode is "unspecified" (RFC 5280 section 5.3.1)
    let cases = [
        ("www.microsoft.com", "43001136c4b1c099de9ad7d2970000001136c4", 1787713972, "key compromise"),
        ("letsencrypt.org", "57d0ce900eec77c01256dd3177d346b20df", 1786926346, "key compromise"),
        ("www.rust-lang.org", "5fbbf9d808a968ac88290bbf4316dc8bf8d", 1783563017, "cessation of operation"),
        ("www.rust-lang.org", "5ab8e4c1ffeae85d7e671d609b97d398d8d", 1791385403, "unspecified"),
        ("www.rust-lang.org", "555a190eb9e5c04f921481dc69ce21d720d", 1783615327, "unspecified"),
        ("crates.io", "137bfeccfca2c569ecfabb6b1797689", 1764340507, "key compromise"),
        ("www.globalsign.com", "6fffc23b3ebf0f6fdfa97c15", 1786698214, "privilege withdrawn"),
        ("www.kernel.org", "14e48fa246850f33f73102d5889cc00", 1764315546, "affiliation changed"),
        ("www.apple.com", "5f8d07e72b7af072282cad553b77105b", 1790587585, "superseded"),
    ];
    let all = fixtures();
    for (name, serial, when, reason) in cases {
        let f = all.iter().find(|f| f.kind == Kind::Crl && f.name == name).unwrap_or_else(|| panic!("a list for {name}"));
        let revoked = with_serial(&f.leaf, serial);
        assert_ne!(revoked, f.leaf);
        let e = settle(Kind::Crl, &f.evidence, &revoked, &f.issuer, f.time).unwrap_err();
        assert!(e.starts_with("certificate_revoked:"), "{name} {serial}: {e}");
        assert!(e.contains(&format!("at Unix time {when}")) && e.contains(&format!("reason: {reason}")), "{name} {serial}: {e}");
        // revocation is forever: long after the list's window the certificate is still refused, now for want of evidence
        assert_refused(settle(Kind::Crl, &f.evidence, &revoked, &f.issuer, f.valid_until + 1), name);
        // and the rewritten certificate, with its own serial put back, is the real one
        assert_eq!(with_serial(&revoked, &hex(&serial_of(&f.leaf))), f.leaf, "{name}");
    }
}

/// The content of a certificate's serialNumber INTEGER.
fn serial_of(cert: &[u8]) -> Vec<u8> {
    let mut tbs = Der::new(Der::new(cert).sequence().unwrap().expect(asn1::TAG_SEQUENCE).unwrap().content);
    tbs.optional(0xa0).unwrap();
    tbs.expect(asn1::TAG_INTEGER).unwrap().content.to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
