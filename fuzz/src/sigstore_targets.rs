//! The fuzz targets of the Sigstore side: `json` (the strict JSON reader of B-71), `sigstore` (bundles) and
//! `trust_root` (the trusted root, key ring and times). Each asserts a property of the answer, not just
//! "no panic":
//!
//! | target | what must hold |
//! |--------|----------------|
//! | `sigstore` | the first byte chooses what the rest is (a bundle checked against a synthetic Sigstore of ours, an npm response or a PEP 740 file against Sigstore's root); a bundle that verifies has the facts (signer, statement, matched subject, times, entries) of one that verified in the seeds: damaging a bundle never makes it say something no good bundle says |
//! | `trust_root` | a trusted root or key list that parses parses again, equal, from its canonical JSON; the keys, logs and authorities in it are consistent; npm key ids are the fingerprints of their keys; an RFC 3339 time that parses is the same calendar time as its digits say (checked with a second implementation of the calendar) |
//! | `sct` | the SCT list of a real Fulcio certificate replaced by the input: the certificate still parses and its precertificate is the original's; a list that parses has at most 32 SCTs and is written back as the same bytes; an SCT that verifies against Sigstore's CT logs has the log, time and extensions of the one the log signed, and none verifies with another certificate as the issuer |
//! | `tuf` | one file of a TUF repository made with python-tuf (`tests/data/tuf/synthetic.json`) replaced by the input: the client (`pratique::tuf`) gives the case's own target or refuses, never other bytes; what parses as JSON has a canonical form that is its own canonical form |
//! | `json` | what parses has no object with a name twice, only numbers of the RFC 8259 grammar and nesting within the default limit; a string that reads as a 64-bit integer is its canonical decimal spelling; the canonical form of a value parses again, is the canonical form of what it parses to, and does not depend on the order of the object members; a canonical form is refused only for a number that is not an integer within 2^53 - 1; leading and trailing white space change nothing and any other trailing byte is refused; a value that parses within a depth limit parses, equal, within every larger one |

use std::collections::HashSet;
use std::sync::OnceLock;

use pratique::asn1::{self, Der};
use pratique::ct;
use pratique::json::{self, ErrorKind, Value};
use pratique::sigstore::{ArtifactDigest, Bundle, DigestAlgorithm, Signer, Trust, Verified};
use pratique::x509::Certificate;
use pratique::trust_root::{self, KeyRing, TrustedRoot};
use pratique::util::unhex;

const VECTORS: &str = include_str!("../../tests/data/json_vectors.txt");

pub const JSON_DICT: &[&[u8]] = &[
    b"{", b"}", b"[", b"]", b":", b",", b"\"", b"\\u", b"\\ud83d", b"\\ude00", b"\\ud800", b"\\udc00", b"\\\\", b"\\\"",
    b"null", b"true", b"false", b"-0", b"1e5", b"1E+2", b"0.5", b"9007199254740993", b"9223372036854775807",
    b"-9223372036854775808", b"\"9223372036854775808\"", b"\"-0\"", b"\"007\"", b"\xef\xbb\xbf", b"\xed\xa0\x80", b"\xc0\xaf",
    b"{\"a\":1,\"a\":2}", b"[[[[[[[[", b"]]]]]]]]", b" \t\r\n",
];

/// The cases of the differential vectors, accepted ones first: the grammar's corners are the seeds.
pub fn seeds_json() -> Vec<Vec<u8>> {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("case ")) {
        let mut p = line.split(' ');
        let (_, hex, verdict) = (p.next(), p.next().unwrap(), p.next().unwrap());
        let bytes = unhex(hex);
        if bytes.len() > 256 {
            continue;
        }
        if verdict == "ok" { ok.push(bytes) } else { bad.push(bytes) }
    }
    ok.extend(bad.into_iter().step_by(4));
    ok
}

fn is_rfc8259_number(t: &str) -> bool {
    let b = t.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let from = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == from {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let from = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == from {
            return false;
        }
    }
    i == b.len()
}

/// Walks a value, checking what every value must satisfy; returns whether a number outside the
/// canonical writer's range occurs and the greatest nesting depth.
fn walk(v: &Value, depth: usize, unsafe_number: &mut bool) {
    assert!(depth <= json::DEFAULT_MAX_DEPTH + 1, "nesting beyond the limit");
    match v {
        Value::Null | Value::Bool(_) => {}
        Value::Number(n) => {
            assert!(is_rfc8259_number(n.text()), "number text {:?} is not in the RFC 8259 grammar", n.text());
            match n.as_i64() {
                Some(i) => {
                    assert!(n.is_integer() && i.to_string() == n.text(), "{:?} read as {i}", n.text());
                    if !(-(1i64 << 53) + 1..(1i64 << 53)).contains(&i) {
                        *unsafe_number = true;
                    }
                }
                None => {
                    if n.text() != "-0" {
                        *unsafe_number = true;
                    }
                }
            }
            if let Some(u) = n.as_u64() {
                assert_eq!(u.to_string(), n.text());
            }
        }
        Value::String(s) => {
            if let Some(i) = v.as_int64() {
                assert_eq!(i.to_string(), *s, "a string that is not the decimal spelling read as an integer");
            }
            if let Some(u) = v.as_uint64() {
                assert_eq!(u.to_string(), *s);
            }
        }
        Value::Array(a) => {
            for x in a {
                walk(x, depth + 1, unsafe_number);
            }
        }
        Value::Object(o) => {
            let mut names: Vec<&str> = o.iter().map(|(n, _)| n).collect();
            assert_eq!(names.len(), o.len());
            names.sort_unstable();
            assert!(names.windows(2).all(|w| w[0] != w[1]), "a name occurs twice");
            for (name, x) in o.iter() {
                assert_eq!(o.get(name), Some(x));
                walk(x, depth + 1, unsafe_number);
            }
        }
    }
}

/// The same value with the members of every object in the opposite order.
fn reversed(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(reversed).collect()),
        Value::Object(o) => {
            let mut members: Vec<(&str, &Value)> = o.iter().collect();
            members.reverse();
            let mut out = json::Object::new();
            for (name, x) in members {
                out.insert(name, reversed(x));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn json(data: &[u8]) {
    let parsed = json::parse(data);
    if let Err(e) = &parsed {
        assert!(e.offset <= data.len(), "an error beyond the end of the input");
    }

    // white space around a value is nothing, and anything else after it is an error
    let padded = [&b" \t\r\n"[..], data, b"\n "].concat();
    assert_eq!(json::parse(&padded).ok(), parsed.as_ref().ok().cloned(), "white space around the value changed the result");
    if parsed.is_ok() {
        for junk in [&b"x"[..], b",", b"\0", b"{}", b"\xef\xbb\xbf"] {
            let with = [data, junk].concat();
            assert!(json::parse(&with).is_err(), "trailing {junk:?} accepted");
        }
    }

    // a limit on the nesting only ever takes values away
    let mut accepted_at = None;
    for depth in [1usize, 2, 3, 5, 8, 16, 32, 64, 256] {
        match (json::parse_with_depth(data, depth), &accepted_at) {
            (Ok(v), None) => accepted_at = Some(v),
            (Ok(v), Some(first)) => assert_eq!(&v, first, "depth {depth}"),
            (Err(_), Some(_)) => panic!("accepted within a smaller limit and refused within {depth}"),
            (Err(_), None) => {}
        }
    }

    let Ok(v) = parsed else { return };
    let mut unsafe_number = false;
    walk(&v, 1, &mut unsafe_number);
    match json::canonical(&v) {
        Ok(c) => {
            assert!(!unsafe_number, "a canonical form was written for a number outside the range");
            assert!(std::str::from_utf8(&c).is_ok());
            let again = json::parse(&c).expect("the canonical form does not parse");
            assert_eq!(json::canonical(&again).as_ref(), Ok(&c), "the canonical form is not its own canonical form");
            assert_eq!(json::canonical(&reversed(&v)).as_ref(), Ok(&c), "the canonical form depends on member order");
        }
        Err(e) => {
            assert_eq!(e.kind, ErrorKind::NotCanonical);
            assert!(unsafe_number, "no canonical form for a value of integers within 2^53 - 1");
        }
    }
}

// ========================================================================================== sigstore

const SYNTHETIC: &[u8] = include_bytes!("../../tests/data/sigstore/synthetic.json");
const REAL_ROOT: &[u8] = include_bytes!("../../tests/data/sigstore/trusted_root.json");
const NPM_KEYS: &[u8] = include_bytes!("../../tests/data/sigstore/npm-registry-keys.json");
const WHEEL: &[u8] = include_bytes!("../../tests/data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl");
const PROVENANCE: &[u8] = include_bytes!("../../tests/data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl.provenance.json");
const RELEASES: [(&[u8], &[u8]); 3] = [
    (include_bytes!("../../tests/data/sigstore/sigstore-0.2.0.attestations.json"), include_bytes!("../../tests/data/sigstore/sigstore-0.2.0.tgz")),
    (include_bytes!("../../tests/data/sigstore/sigstore-2.2.0.attestations.json"), include_bytes!("../../tests/data/sigstore/sigstore-2.2.0.tgz")),
    (include_bytes!("../../tests/data/sigstore/sigstore-4.0.0.attestations.json"), include_bytes!("../../tests/data/sigstore/sigstore-4.0.0.tgz")),
];

pub const SIGSTORE_DICT: &[&[u8]] = &[
    b"\"mediaType\"", b"\"application/vnd.dev.sigstore.bundle+json;version=0.1\"", b"\"application/vnd.dev.sigstore.bundle+json;version=0.2\"",
    b"\"application/vnd.dev.sigstore.bundle.v0.3+json\"", b"\"verificationMaterial\"", b"\"x509CertificateChain\"", b"\"certificate\"",
    b"\"publicKey\"", b"\"hint\"", b"\"tlogEntries\"", b"\"logIndex\"", b"\"logId\"", b"\"keyId\"", b"\"kindVersion\"", b"\"kind\"",
    b"\"version\"", b"\"dsse\"", b"\"intoto\"", b"\"hashedrekord\"", b"\"0.0.1\"", b"\"0.0.2\"", b"\"integratedTime\"",
    b"\"inclusionPromise\"", b"\"signedEntryTimestamp\"", b"\"inclusionProof\"", b"\"rootHash\"", b"\"treeSize\"", b"\"hashes\"",
    b"\"checkpoint\"", b"\"envelope\"", b"\"canonicalizedBody\"", b"\"timestampVerificationData\"", b"\"rfc3161Timestamps\"",
    b"\"signedTimestamp\"", b"\"dsseEnvelope\"", b"\"payload\"", b"\"payloadType\"", b"\"application/vnd.in-toto+json\"",
    b"\"signatures\"", b"\"sig\"", b"\"keyid\"", b"\"messageSignature\"", b"\"rawBytes\"", b"\"attestations\"", b"\"predicateType\"",
    b"\"bundle\"", b"\"attestation_bundles\"", b"\"publisher\"", b"\"verification_material\"", b"\"transparency_entries\"",
    b"\"statement\"", b"\"signature\"", b"null", b"\"0\"", b"\"AQID\"", b"\"AQI=\"", b"\"\"", b"[]", b"{}", b"{\"a\":1,\"a\":2}",
    b"\\n\\n\xe2\x80\x94 ", b"\xe2\x80\x94",
];

/// What the first byte of a `sigstore` input chooses: how the rest is read and what it is checked against.
#[derive(Clone, Copy)]
enum Form {
    /// One Sigstore bundle, checked against the synthetic root.
    Bundle,
    /// The npm registry's response, against Sigstore's root and npm's keys; the number is the release.
    Npm(usize),
    /// PyPI's provenance, against Sigstore's root.
    Pep740,
}

const FORMS: [Form; 5] = [Form::Bundle, Form::Npm(0), Form::Npm(1), Form::Npm(2), Form::Pep740];

struct World {
    synthetic: TrustedRoot,
    synthetic_digest: ArtifactDigest,
    real: TrustedRoot,
    npm: KeyRing,
    /// The facts of every seed that verifies, per form.
    good: Vec<Known>,
}

/// What a verification says, in three parts: the core (who signed, what they signed, which subject is the
/// artifact), and the evidence (every time and every log entry), each as text. The bundle's format is not part of the
/// core: the bundle declares it and nothing signs it, and a bundle whose evidence meets the rules of two versions may
/// carry either label (found by fuzzing on the Mac: npm's v0.2 attestations relabelled v0.1, which they also meet, as
/// they carry signed entry timestamps as well as inclusion proofs; the library applies each version's own rules). Evidence is compared as a
/// set, without the order, and without what nothing authenticated: the log index of an entry that has no signed
/// entry timestamp.
struct Facts {
    core: String,
    times: Vec<String>,
    entries: Vec<String>,
    scts: Vec<String>,
}

fn facts(v: &Verified) -> Facts {
    let entries = v
        .entries
        .iter()
        .map(|e| {
            let mut e = e.clone();
            if !e.signed_entry_timestamp {
                e.log_index = 0;
            }
            format!("{e:?}")
        })
        .collect();
    assert!(v.times.iter().any(|t| t.time == v.verified_time), "the verified time is not one of the times");
    assert!(v.times.windows(2).all(|w| w[0].time <= w[1].time), "the times are not ascending");
    Facts {
        core: format!("{:?} {:?} {}", v.signer, v.statement, v.matched_subject),
        times: v.times.iter().map(|t| format!("{t:?}")).collect(),
        entries,
        scts: v.scts.iter().map(|s| format!("{s:?}")).collect(),
    }
}

/// What the seeds that verify say, per form: bundles are changed by dropping or damaging parts, and a bundle that
/// has lost some of its evidence (a time stamp, an entry) still says something true, less of it. So the core must be
/// one a seed has, and every time and entry must be one that a seed with that core has.
#[derive(Default)]
struct Known {
    cores: std::collections::HashMap<String, (HashSet<String>, HashSet<String>, HashSet<String>)>,
}

impl Known {
    fn learn(&mut self, f: Facts) {
        let e = self.cores.entry(f.core).or_default();
        e.0.extend(f.times);
        e.1.extend(f.entries);
        e.2.extend(f.scts);
    }

    fn check(&self, f: &Facts, what: &str) {
        let Some((times, entries, scts)) = self.cores.get(&f.core) else { panic!("a bundle was accepted that says something no good bundle says: {what}") };
        for t in &f.times {
            assert!(times.contains(t), "a time no good bundle with this signer and statement has: {t}");
        }
        for e in &f.entries {
            assert!(entries.contains(e), "a log entry no good bundle with this signer and statement has: {e}");
        }
        for s in &f.scts {
            assert!(scts.contains(s), "a signed certificate timestamp no good bundle with this signer and statement has: {s}");
        }
    }
}

fn verify_all(world: &World, form: Form, bytes: &[u8]) -> Vec<Result<Verified, pratique::sigstore::Error>> {
    match form {
        Form::Bundle => match Bundle::parse(bytes) {
            Ok(b) => vec![b.verify(&Trust::new(&world.synthetic), &world.synthetic_digest)],
            Err(_) => vec![],
        },
        Form::Npm(i) => {
            let digest = ArtifactDigest::of(DigestAlgorithm::Sha512, RELEASES[i].1);
            let trust = Trust::new(&world.real).with_keys(&world.npm);
            match Bundle::parse_npm_attestations(bytes) {
                Ok(list) => list.iter().map(|a| a.verify(&trust, &digest)).collect(),
                Err(_) => vec![],
            }
        }
        Form::Pep740 => {
            let digest = ArtifactDigest::of(DigestAlgorithm::Sha256, WHEEL);
            let trust = Trust::new(&world.real);
            match Bundle::parse_pep740(bytes) {
                Ok(list) => list.iter().map(|a| a.verify(&trust, &digest)).collect(),
                Err(_) => vec![],
            }
        }
    }
}

/// The seed inputs: the selector byte and a document, and whether the document is meant to verify.
fn seed_documents() -> Vec<(u8, Vec<u8>, bool)> {
    let mut out = Vec::new();
    let doc = json::parse(SYNTHETIC).unwrap();
    for case in doc.get("cases").and_then(Value::as_array).unwrap() {
        let on_base = case.get("root").and_then(Value::as_str) == Some("base");
        let sha256 = matches!(case.get("algorithm").and_then(Value::as_str), None | Some("sha256"));
        // the target checks with the default trust: a case judged with another SCT threshold is not a seed
        let default_trust = case.get("sct_threshold").is_none();
        if on_base && sha256 && default_trust {
            let verifies = case.get("expect").and_then(Value::as_str) == Some("ok");
            out.push((0u8, json::canonical(case.get("bundle").unwrap()).unwrap(), verifies));
        }
    }
    for (i, (att, _)) in RELEASES.iter().enumerate() {
        out.push((1 + i as u8, att.to_vec(), true));
    }
    out.push((4, PROVENANCE.to_vec(), true));
    out
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let doc = json::parse(SYNTHETIC).unwrap();
        let root = doc.get("roots").and_then(|r| r.get("base")).unwrap();
        let artifact = pratique::pem::base64_decode_strict(doc.get("artifact").and_then(Value::as_str).unwrap()).unwrap();
        let mut w = World {
            synthetic: TrustedRoot::parse(&json::canonical(root).unwrap()).unwrap(),
            synthetic_digest: ArtifactDigest::of(DigestAlgorithm::Sha256, &artifact),
            real: TrustedRoot::parse(REAL_ROOT).unwrap(),
            npm: KeyRing::from_npm_keys(NPM_KEYS).unwrap(),
            good: Vec::new(),
        };
        // What verifies is taken from the library, only from the documents that are meant to verify: a flaw that
        // accepted one that is not would otherwise teach the target that its facts are good.
        let mut good: Vec<Known> = (0..FORMS.len()).map(|_| Known::default()).collect();
        for (sel, doc, verifies) in seed_documents() {
            let results = verify_all(&w, FORMS[sel as usize], &doc);
            for r in results {
                match (r, verifies) {
                    (Ok(v), true) => good[sel as usize].learn(facts(&v)),
                    (Ok(_), false) => panic!("a bundle that is meant to be refused verified"),
                    _ => {}
                }
            }
        }
        assert!(good.iter().all(|g| !g.cores.is_empty()) && good[0].cores.len() >= 10, "the seeds do not verify");
        w.good = good;
        w
    })
}

pub fn seeds_sigstore() -> Vec<Vec<u8>> {
    world();
    seed_documents().into_iter().map(|(sel, doc, _)| [&[sel][..], &doc].concat()).collect()
}

pub fn sigstore(data: &[u8]) {
    let w = world();
    let Some((&sel, rest)) = data.split_first() else { return };
    let sel = sel as usize % FORMS.len();
    for r in verify_all(w, FORMS[sel], rest) {
        if let Ok(v) = r {
            w.good[sel].check(&facts(&v), &format!("{:?} {:?}", v.signer, v.statement));
        }
    }
}

// ========================================================================================== trust_root

pub const TRUST_ROOT_DICT: &[&[u8]] = &[
    b"\"tlogs\"", b"\"ctlogs\"", b"\"certificateAuthorities\"", b"\"timestampAuthorities\"", b"\"baseUrl\"", b"\"hashAlgorithm\"",
    b"\"SHA2_256\"", b"\"publicKey\"", b"\"rawBytes\"", b"\"keyDetails\"", b"\"PKIX_ECDSA_P256_SHA_256\"", b"\"PKIX_ED25519\"",
    b"\"PKIX_ECDSA_P384_SHA_384\"", b"\"PKIX_RSA_PKCS1V15_2048_SHA256\"", b"\"validFor\"", b"\"start\"", b"\"end\"", b"\"logId\"",
    b"\"keyId\"", b"\"subject\"", b"\"commonName\"", b"\"uri\"", b"\"certChain\"", b"\"certificates\"", b"\"keys\"", b"\"keyid\"",
    b"\"keytype\"", b"\"ecdsa-sha2-nistp256\"", b"\"scheme\"", b"\"key\"", b"\"expires\"", b"null", b"[]", b"{}",
    b"2022-12-31T23:59:59Z", b"2022-12-31T23:59:59.999Z", b"2024-02-29T00:00:00+01:00", b"9999-12-31T23:59:59Z", b"0001-01-01T00:00:00Z",
    b"2023-02-29T00:00:00Z", b"2022-12-31T23:59:60Z", b"2022-12-31t23:59:59z", b"1.123456789", b"+23:59", b"-00:00",
];

pub fn seeds_trust_root() -> Vec<Vec<u8>> {
    let mut out = vec![[&[0u8][..], REAL_ROOT].concat(), [&[1u8][..], NPM_KEYS].concat()];
    let doc = json::parse(SYNTHETIC).unwrap();
    for (name, root) in doc.get("roots").and_then(Value::as_object).unwrap().iter() {
        if matches!(name, "base" | "ca ended" | "no tsa" | "tsa root only" | "no fulcio") {
            out.push([&[0u8][..], &json::canonical(root).unwrap()].concat());
        }
    }
    for t in ["2022-12-31T23:59:59Z", "2022-12-31T23:59:59.999Z", "2024-02-29T00:00:00+01:00", "2024-02-29T23:59:59.123456789-23:59", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"] {
        out.push([&[2u8][..], t.as_bytes()].concat());
    }
    out
}

/// Days since 1970-01-01 to a calendar date: Howard Hinnant's `civil_from_days`, a second implementation of the
/// calendar next to the one in the library.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn check_time(text: &str) {
    let Some((secs, nanos)) = trust_root::parse_rfc3339(text) else { return };
    assert!(nanos < 1_000_000_000);
    // the digits say a date and a time; with the offset taken off, that is `secs`
    let b = text.as_bytes();
    assert!(b.is_ascii() && b.len() >= 20, "a time that is not ASCII was accepted");
    let tail = &text[19..];
    let fraction_len = if tail.starts_with('.') { 1 + tail[1..].bytes().take_while(u8::is_ascii_digit).count() } else { 0 };
    let zone = &tail[fraction_len..];
    let offset: i64 = match zone {
        "Z" => 0,
        z if z.len() == 6 => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            sign * (z[1..3].parse::<i64>().unwrap() * 3600 + z[4..6].parse::<i64>().unwrap() * 60)
        }
        other => panic!("accepted a zone {other:?}"),
    };
    let local = secs + offset;
    let (days, rest) = (local.div_euclid(86_400), local.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    let canonical = format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60);
    assert_eq!(&text[..19], canonical, "{text} is not the time it was read as ({secs})");
    if fraction_len > 0 {
        let digits = &tail[1..fraction_len];
        assert!(digits.len() <= 9);
        let n: u64 = digits.parse().unwrap();
        assert_eq!(u64::from(nanos), n * 10u64.pow(9 - digits.len() as u32), "fraction of {text}");
    } else {
        assert_eq!(nanos, 0);
    }
}

pub fn trust_root(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    match sel % 3 {
        0 => {
            let Ok(root) = TrustedRoot::parse(rest) else { return };
            // the same document written canonically is the same root
            let v = json::parse(rest).expect("a root parsed from what is not strict JSON");
            let again = TrustedRoot::parse(&json::canonical(&v).unwrap_or_else(|_| rest.to_vec()));
            if json::canonical(&v).is_ok() {
                assert_eq!(again.as_ref(), Ok(&root), "the canonical form of a root is another root");
            }
            for log in root.tlogs.iter().chain(&root.ctlogs) {
                let key = trust_root::VerificationKey::from_spki(log.key.spki()).expect("a log key that does not read again");
                assert_eq!(key, log.key);
                assert_eq!(key.sha256().len(), 32);
                assert!(root.tlogs.iter().chain(&root.ctlogs).any(|l| l.log_id == log.log_id));
                let _ = log.host();
                if let (Some(s), Some(e)) = (log.valid_for.start, log.valid_for.end) {
                    assert!(s <= e);
                }
            }
            for log in &root.tlogs {
                assert!(root.tlogs_with_id(&log.log_id).any(|l| l == log));
            }
            for a in root.certificate_authorities.iter().chain(&root.timestamp_authorities) {
                if let (Some(s), Some(e)) = (a.valid_for.start, a.valid_for.end) {
                    assert!(s <= e);
                    assert!(a.valid_for.contains(s) && a.valid_for.contains(e) && !a.valid_for.contains(e + 1) && !a.valid_for.contains(s - 1));
                }
                if let Ok((_, others)) = a.trust() {
                    assert!(others.len() <= a.chain.len());
                }
            }
        }
        1 => {
            let Ok(ring) = KeyRing::from_npm_keys(rest) else { return };
            for k in ring.keys() {
                assert_eq!(trust_root::ssh_fingerprint(k.key.spki()).as_deref(), Some(k.id.as_str()), "an npm key id that is not its key's fingerprint");
                assert!(ring.with_id(&k.id).any(|o| o == k));
                assert!(k.valid_for.start.is_none());
            }
        }
        _ => {
            if let Ok(text) = std::str::from_utf8(rest) {
                check_time(text);
            }
        }
    }
}

// ========================================================================================== sct

/// A real Fulcio certificate (from npm's provenance and PyPI's) and what its SCT check needs.
struct RealLeaf {
    /// The certificate's TBSCertificate without its SCT list: what the log signed.
    precert: Vec<u8>,
    /// The certificate's signature algorithm and signature (DER), to make a whole certificate again.
    tail: Vec<u8>,
    /// The issuer that the chain verified through, and another certificate of the chain (the root).
    issuer: Certificate,
    other: Certificate,
    /// The SCT list's TLS bytes, and the SCTs in it.
    list: Vec<u8>,
    scts: Vec<ct::Sct>,
}

pub const SCT_DICT: &[&[u8]] = &[b"\x00\x00", b"\x04\x03", b"\x04\x01", b"\x05\x03", b"\x08\x07", b"\x00\x01", b"\xff\xff", b"\x30\x45\x02\x20", b"\x30\x46\x02\x21\x00"];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = (n as u64).to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// `precert` (a TBSCertificate with extensions) with an SCT list extension of value `list` (TLS bytes) added last.
fn with_sct_list(precert: &[u8], list: &[u8]) -> Vec<u8> {
    let mut top = Der::new(precert);
    let mut fields = top.sequence().unwrap();
    let mut content = Vec::new();
    while !fields.is_empty() {
        let f = fields.next().unwrap();
        if f.tag == 0xa3 {
            let mut exts = Der::new(f.content).sequence().unwrap();
            let mut all = Vec::new();
            while !exts.is_empty() {
                all.extend_from_slice(exts.next().unwrap().raw);
            }
            let ext = [tlv(asn1::TAG_OID, ct::OID_SCT_LIST), tlv(asn1::TAG_OCTET_STRING, &tlv(asn1::TAG_OCTET_STRING, list))].concat();
            all.extend_from_slice(&tlv(asn1::TAG_SEQUENCE, &ext));
            content.extend_from_slice(&tlv(0xa3, &tlv(asn1::TAG_SEQUENCE, &all)));
        } else {
            content.extend_from_slice(f.raw);
        }
    }
    tlv(asn1::TAG_SEQUENCE, &content)
}

fn real_leaves() -> &'static [RealLeaf] {
    static L: OnceLock<Vec<RealLeaf>> = OnceLock::new();
    L.get_or_init(|| {
        let w = world();
        let mut out = Vec::new();
        for (sel, doc, _) in seed_documents().into_iter().filter(|d| d.0 != 0) {
            for v in verify_all(w, FORMS[sel as usize], &doc).into_iter().flatten() {
                let Signer::Certificate(id) = &v.signer else { continue };
                let leaf = Certificate::from_der(&id.certificate).unwrap();
                let mut top = Der::new(&id.certificate);
                let mut c = top.sequence().unwrap();
                c.next().unwrap();
                let tail = [c.next().unwrap().raw, c.next().unwrap().raw].concat();
                let ext = leaf.extension(ct::OID_SCT_LIST).expect("a real Fulcio certificate has SCTs");
                let list = Der::new(&ext.value).expect(asn1::TAG_OCTET_STRING).unwrap().content.to_vec();
                let precert = ct::precertificate_tbs(leaf.tbs_der()).unwrap();
                // the parts make the certificate again, byte for byte
                assert_eq!(tlv(asn1::TAG_SEQUENCE, &[with_sct_list(&precert, &list), tail.clone()].concat()).len(), id.certificate.len());
                out.push(RealLeaf {
                    precert,
                    tail,
                    issuer: Certificate::from_der(&id.chain[1]).unwrap(),
                    other: Certificate::from_der(id.chain.last().unwrap()).unwrap(),
                    scts: ct::parse_list(&ext.value).unwrap().scts,
                    list,
                });
            }
        }
        assert_eq!(out.len(), 4, "the four real Fulcio certificates");
        out
    })
}

/// The TLS encoding of an SCT list of version 1 SCTs.
fn encode_list(scts: &[ct::Sct]) -> Vec<u8> {
    let mut inner = Vec::new();
    for s in scts {
        let mut b = vec![0u8];
        b.extend_from_slice(&s.log_id);
        b.extend_from_slice(&s.timestamp_ms.to_be_bytes());
        b.extend_from_slice(&(s.extensions.len() as u16).to_be_bytes());
        b.extend_from_slice(&s.extensions);
        b.extend_from_slice(&[s.hash_algorithm, s.signature_algorithm]);
        b.extend_from_slice(&(s.signature.len() as u16).to_be_bytes());
        b.extend_from_slice(&s.signature);
        inner.extend_from_slice(&(b.len() as u16).to_be_bytes());
        inner.extend_from_slice(&b);
    }
    [(inner.len() as u16).to_be_bytes().to_vec(), inner].concat()
}

pub fn seeds_sct() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (i, l) in real_leaves().iter().enumerate() {
        out.push([&[i as u8][..], &l.list].concat());
        out.push([&[i as u8 | 4][..], &l.list].concat());
        let twice = encode_list(&[l.scts.clone(), l.scts.clone()].concat());
        out.push([&[i as u8][..], &twice].concat());
    }
    out
}

/// The first byte chooses the certificate (bits 0 and 1) and whether the SCTs are checked with its issuer or with
/// another certificate of its chain (bit 2); the rest is the SCT list, in place of the certificate's own.
pub fn sct(data: &[u8]) {
    let w = world();
    let Some((&sel, list)) = data.split_first() else { return };
    let real = &real_leaves()[(sel & 3) as usize];
    let der = tlv(asn1::TAG_SEQUENCE, &[with_sct_list(&real.precert, list), real.tail.clone()].concat());
    let cert = Certificate::from_der(&der).expect("an extension's value does not decide whether a certificate parses");
    assert_eq!(ct::precertificate_tbs(cert.tbs_der()).unwrap(), real.precert, "the precertificate is not the one the log signed");
    let parsed = ct::embedded(&cert);
    if let Ok(l) = &parsed {
        assert!(l.scts.len() + l.other_versions <= ct::MAX_SCTS);
        if l.other_versions == 0 {
            assert_eq!(encode_list(&l.scts), list, "a list that parsed is not its own bytes");
        }
    }
    let issuer = if sel & 4 == 0 { &real.issuer } else { &real.other };
    let Ok(report) = ct::verify_embedded(&cert, issuer, &w.real.ctlogs) else { return };
    let l = parsed.expect("a list that verified did not parse");
    assert_eq!(report.verified.len() + report.unknown_logs.len(), l.scts.len());
    assert_eq!(report.other_versions, l.other_versions);
    assert!(report.verified.is_empty() || sel & 4 == 0, "an SCT verified with the wrong issuer");
    for v in &report.verified {
        let signed = real.scts.iter().any(|s| s.log_id.as_slice() == v.log_id && s.timestamp_ms == v.timestamp_ms);
        assert!(signed, "an SCT verified that the log did not sign: {v:?}");
    }
    for s in l.scts.iter().filter(|s| !report.unknown_logs.contains(&s.log_id)) {
        assert!(real.scts.iter().any(|r| r.log_id == s.log_id && r.timestamp_ms == s.timestamp_ms && r.extensions == s.extensions), "an SCT verified with a changed log id, time or extensions");
    }
}

// ========================================================================================== tuf

const TUF_SYNTHETIC: &[u8] = include_bytes!("../../tests/data/tuf/synthetic.json");

/// A case of tests/data/tuf/synthetic.json that gives its target: the time, the bootstrap root, the files by path, the
/// target and its bytes.
struct TufCase {
    bootstrap: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
    target: String,
    content: Vec<u8>,
}

fn tuf_world() -> &'static (i64, Vec<TufCase>) {
    static W: OnceLock<(i64, Vec<TufCase>)> = OnceLock::new();
    W.get_or_init(|| {
        let doc = json::parse(TUF_SYNTHETIC).unwrap();
        let blobs = doc.get("blobs").and_then(Value::as_object).unwrap();
        let blob = |h: &Value| pratique::pem::base64_decode_strict(blobs.get(h.as_str().unwrap()).and_then(Value::as_str).unwrap()).unwrap();
        let cases = doc
            .get("cases")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter(|c| c.get("expect").and_then(Value::as_str) == Some("ok") && c.get("local").and_then(Value::as_object).is_some_and(|l| l.is_empty()))
            .map(|c| TufCase {
                bootstrap: blob(c.get("bootstrap").unwrap()),
                files: c.get("files").and_then(Value::as_object).unwrap().iter().map(|(p, h)| (p.to_string(), blob(h))).collect(),
                target: c.get("target").and_then(Value::as_str).unwrap().to_string(),
                content: blob(c.get("content").unwrap()),
            })
            .collect::<Vec<_>>();
        let now = doc.get("now").and_then(Value::as_int64).unwrap();
        // the cases verify to begin with, or the target checks nothing
        for c in &cases {
            assert_eq!(tuf_run(now, &c.bootstrap, &c.files, &c.target).as_deref(), Ok(c.content.as_slice()));
        }
        assert!(cases.len() >= 15);
        (now, cases)
    })
}

fn tuf_run(now: i64, bootstrap: &[u8], files: &[(String, Vec<u8>)], target: &str) -> Result<Vec<u8>, pratique::tuf::Error> {
    use pratique::tuf::{self, Fetched, Local, Request, Updater};
    let serve = |prefix: &'static str| {
        move |r: &Request| -> Result<Fetched, String> {
            let p = format!("{prefix}/{}", r.path);
            Ok(files.iter().find(|(q, _)| *q == p).map_or(Fetched::NotFound, |(_, d)| Fetched::Data(d.clone())))
        }
    };
    let mut u = Updater::new(bootstrap, now)?;
    tuf::refresh(&mut u, Local::default(), &mut serve("metadata"))?;
    tuf::fetch_target(&mut u, target, &mut serve("metadata"), &mut serve("targets")).map(|(_, d)| d)
}

pub const TUF_DICT: &[&[u8]] = &[
    b"\"signed\"", b"\"signatures\"", b"\"keyid\"", b"\"sig\"", b"\"_type\"", b"\"root\"", b"\"timestamp\"", b"\"snapshot\"",
    b"\"targets\"", b"\"spec_version\"", b"\"1.0\"", b"\"2.0\"", b"\"version\"", b"\"expires\"", b"\"2036-01-01T00:00:00Z\"",
    b"\"consistent_snapshot\"", b"\"keys\"", b"\"roles\"", b"\"keyids\"", b"\"threshold\"", b"\"keytype\"", b"\"scheme\"",
    b"\"keyval\"", b"\"public\"", b"\"ecdsa\"", b"\"ed25519\"", b"\"rsa\"", b"\"ecdsa-sha2-nistp256\"", b"\"rsassa-pss-sha256\"",
    b"\"meta\"", b"\"snapshot.json\"", b"\"targets.json\"", b"\"length\"", b"\"hashes\"", b"\"sha256\"", b"\"sha512\"",
    b"\"delegations\"", b"\"name\"", b"\"terminating\"", b"\"paths\"", b"\"path_hash_prefixes\"", b"\"succinct_roles\"",
    b"\"custom\"", b"true", b"false", b"null", b"0", b"1", b"2", b"[]", b"{}", b"\"*\"", b"\"[!a-z]\"",
];

/// The input's first byte chooses a good case and the second one of its files; the rest replaces that file. Whatever the
/// file becomes, the client gives the case's own target or refuses: never other bytes.
pub fn seeds_tuf() -> Vec<Vec<u8>> {
    let (_, cases) = tuf_world();
    let mut out = Vec::new();
    for (i, c) in cases.iter().enumerate().take(8) {
        for (j, (_, data)) in c.files.iter().enumerate() {
            if data.len() <= 4096 {
                out.push([&[i as u8, j as u8][..], data].concat());
            }
        }
    }
    out
}

pub fn tuf(data: &[u8]) {
    let (now, cases) = tuf_world();
    let [ci, fi, rest @ ..] = data else { return };
    let c = &cases[*ci as usize % cases.len()];
    let mut files = c.files.clone();
    let k = *fi as usize % files.len();
    files[k].1 = rest.to_vec();
    if let Ok(got) = tuf_run(*now, &c.bootstrap, &files, &c.target) {
        assert_eq!(got, c.content, "a damaged repository gave other bytes for {} (file {})", c.target, files[k].0);
    }
    // the canonical form TUF signs: what parses is written the same way however it was spelled. OLPC's canonical JSON
    // writes control characters in strings as they are (a PEM key's line feeds, say), which strict JSON does not read back;
    // without them it is JSON, and its own canonical form
    if let Ok(v) = json::parse(rest) {
        if let Ok(once) = pratique::tuf::canonical_json(&v) {
            match json::parse(&once) {
                Ok(again) => assert_eq!(pratique::tuf::canonical_json(&again).unwrap(), once, "canonical JSON is not its own canonical form"),
                Err(e) => assert!(once.iter().any(|&b| b < 0x20), "canonical JSON without control characters does not parse: {e:?}"),
            }
        }
    }
}
