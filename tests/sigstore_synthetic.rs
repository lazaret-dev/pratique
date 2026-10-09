//! Bundles from a Sigstore of our own (tests/data/sigstore/synthetic.json, made by
//! tools/gen_sigstore_fixtures.py), for what the real attestations do not reach: RFC 3161 time stamps, a log that
//! signs with Ed25519 and gives proofs only, every key type for the signing certificate, identities from an
//! e-mail address or a username; and for what a real signer never makes: an entry body that binds another
//! signature, a checkpoint from another key, a time stamp from a rogue authority.
//!
//! Each case says whether it verifies or which kind of error it is refused with (and, for a refusal, a part of
//! the message that names the reason, so that a case cannot be refused for a reason it was not made for). The
//! last tests damage the cases that verify, every string one at a time.

use pratique::json::{self, Value};
use pratique::sigstore::{ArtifactDigest, Bundle, DigestAlgorithm, Error, Signer, TimeSource, Trust, Verified};
use pratique::trust_root::TrustedRoot;

#[path = "common/json_edit.rs"]
mod json_edit;
use json_edit::{damage_every_part, Step};

const DATA: &[u8] = include_bytes!("data/sigstore/synthetic.json");

struct Fixtures {
    doc: Value,
    artifact: Vec<u8>,
}

fn fixtures() -> Fixtures {
    let doc = json::parse(DATA).unwrap();
    let artifact = pratique::pem::base64_decode_strict(doc.get("artifact").and_then(Value::as_str).unwrap()).unwrap();
    Fixtures { doc, artifact }
}

impl Fixtures {
    fn cases(&self) -> &[Value] {
        self.doc.get("cases").and_then(Value::as_array).unwrap()
    }

    fn case(&self, name: &str) -> &Value {
        self.cases().iter().find(|c| c.get("name").and_then(Value::as_str) == Some(name)).unwrap_or_else(|| panic!("no case {name:?}"))
    }

    fn root(&self, name: &str) -> TrustedRoot {
        let v = self.doc.get("roots").and_then(|r| r.get(name)).unwrap_or_else(|| panic!("no root {name:?}"));
        TrustedRoot::parse(&json::canonical(v).unwrap()).unwrap_or_else(|e| panic!("root {name:?}: {e}"))
    }

    fn digest(&self, case: &Value) -> ArtifactDigest {
        let alg = match case.get("algorithm").and_then(Value::as_str) {
            None | Some("sha256") => DigestAlgorithm::Sha256,
            Some("sha384") => DigestAlgorithm::Sha384,
            Some("sha512") => DigestAlgorithm::Sha512,
            Some(other) => panic!("{other}"),
        };
        ArtifactDigest::of(alg, &self.artifact)
    }

    fn run(&self, case: &Value) -> Result<Verified, Error> {
        let root = self.root(case.get("root").and_then(Value::as_str).unwrap());
        let bundle = Bundle::parse(&json::canonical(case.get("bundle").unwrap()).unwrap())?;
        let mut trust = Trust::new(&root);
        if let Some(n) = case.get("sct_threshold").and_then(Value::as_int64) {
            trust = trust.with_sct_threshold(n as usize);
        }
        bundle.verify(&trust, &self.digest(case))
    }
}

/// The variant of an error, by name.
fn kind(e: &Error) -> String {
    format!("{e:?}").chars().take_while(|c| c.is_ascii_alphanumeric()).collect()
}

fn text(v: &Value, name: &str) -> String {
    v.get(name).and_then(Value::as_str).unwrap_or_else(|| panic!("no {name}")).to_string()
}

// ------------------------------------------------------------------------------------ the verdicts

#[test]
fn every_case_is_judged_as_the_generator_expected() {
    let fx = fixtures();
    let mut wrong = Vec::new();
    let (mut ok, mut refused) = (0, 0);
    for case in fx.cases() {
        let name = text(case, "name");
        let expect = text(case, "expect");
        match (fx.run(case), expect.as_str()) {
            (Ok(v), "ok") => {
                ok += 1;
                if let Err(m) = check_facts(case, &v) {
                    wrong.push(format!("{name}: {m}"));
                }
            }
            (Ok(v), _) => wrong.push(format!("{name}: verified (at {}) but was expected to be refused with {expect}", v.verified_time)),
            (Err(e), "ok") => wrong.push(format!("{name}: refused, but was expected to verify: {e}")),
            (Err(e), _) => {
                refused += 1;
                if kind(&e) != expect {
                    wrong.push(format!("{name}: refused with {}, expected {expect}: {e}", kind(&e)));
                } else if let Some(reason) = case.get("reason").and_then(Value::as_str) {
                    if !e.to_string().contains(reason) {
                        wrong.push(format!("{name}: refused, but not for the reason {reason:?}: {e}"));
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases:\n{}", wrong.len(), fx.cases().len(), wrong.join("\n"));
    assert!(ok >= 20 && refused >= 55, "{ok} verified, {refused} refused");
}

fn check_facts(case: &Value, v: &Verified) -> Result<(), String> {
    let Some(f) = case.get("facts") else { return Ok(()) };
    let int = |name: &str| f.get(name).and_then(Value::as_int64);
    let mut problems = Vec::new();
    let mut want = |what: &str, ok: bool, got: String| {
        if !ok {
            problems.push(format!("{what}: {got}"));
        }
    };
    if let Some(t) = int("verified_time") {
        want("verified_time", v.verified_time == t, format!("{} is not {t}", v.verified_time));
    }
    if let Some(list) = f.get("sources").and_then(Value::as_array) {
        let got: Vec<&str> = v.times.iter().map(|t| match t.source {
            TimeSource::LogEntry { .. } => "entry",
            TimeSource::TimeStamp { .. } => "tsa",
        }).collect();
        let wanted: Vec<&str> = list.iter().map(|s| s.as_str().unwrap()).collect();
        want("time sources", got == wanted, format!("{got:?} is not {wanted:?}"));
        want("times ascending", v.times.windows(2).all(|w| w[0].time <= w[1].time), format!("{:?}", v.times));
    }
    if let Some(list) = f.get("entries").and_then(Value::as_array) {
        want("entry count", list.len() == v.entries.len(), format!("{} entries", v.entries.len()));
        for (want_e, got) in list.iter().zip(&v.entries) {
            let set = want_e.get("set").and_then(Value::as_bool).unwrap();
            want("signed entry timestamp", got.signed_entry_timestamp == set, format!("{} is not {set}", got.signed_entry_timestamp));
            let inclusion = want_e.get("inclusion").and_then(Value::as_int64).map(|n| n as u64);
            want("inclusion", got.inclusion.as_ref().map(|i| i.tree_size) == inclusion, format!("{:?} is not {inclusion:?}", got.inclusion));
            let it = want_e.get("integrated_time").and_then(Value::as_int64);
            want("integrated time", got.integrated_time == it, format!("{:?} is not {it:?}", got.integrated_time));
        }
    }
    if let Some(list) = f.get("scts").and_then(Value::as_array) {
        let wanted: Vec<(String, u64)> = list.iter().map(|p| {
            let p = p.as_array().unwrap();
            (p[0].as_str().unwrap().to_string(), p[1].as_int64().unwrap() as u64)
        }).collect();
        let got: Vec<(String, u64)> = v.scts.iter().map(|s| (s.log_url.clone(), s.timestamp_ms)).collect();
        want("signed certificate timestamps", got == wanted, format!("{got:?} is not {wanted:?}"));
    }
    if let Some(m) = int("matched_subject") {
        want("matched subject", v.matched_subject as i64 == m, format!("{}", v.matched_subject));
    }
    let id = match &v.signer {
        Signer::Certificate(id) => Some(id),
        _ => None,
    };
    let mut string_fact = |name: &str, got: Option<String>| {
        if let Some(w) = f.get(name).and_then(Value::as_str) {
            want(name, got.as_deref() == Some(w), format!("{got:?} is not {w:?}"));
        }
    };
    string_fact("uri", id.and_then(|i| i.uris.first().cloned()));
    string_fact("email", id.and_then(|i| i.emails.first().cloned()));
    string_fact("username", id.and_then(|i| i.other_names.first().cloned()));
    string_fact("issuer", id.and_then(|i| i.issuer.clone()));
    string_fact("repository", id.and_then(|i| i.repository()));
    string_fact("ref", id.and_then(|i| i.git_ref().map(str::to_string)));
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

// ------------------------------------------------------------------------------------ damage

/// Parts of a bundle that nothing authenticates when the entry has no signed entry timestamp: what a log
/// reports about the entry as a whole. Only the inclusion proof, the body and the checkpoint are covered then.
fn unauthenticated_in_proof_only(path: &str) -> bool {
    path.ends_with("].integratedTime") || (path.ends_with("].logIndex") && !path.contains("inclusionProof"))
}

/// A hint or an id the bundle repeats where the key is found by other means.
fn envelope_keyid(path: &str) -> bool {
    path.contains("dsseEnvelope.signatures[0].keyid")
}

/// Time stamps that are not needed when the log's promise gives a time: not in these bundles.
fn no_time_stamps(path: &str) -> bool {
    path.ends_with("timestampVerificationData") || path.ends_with("rfc3161Timestamps")
}

/// Certificates after the leaf are candidates for intermediates, and the trusted root has the intermediate.
fn spare_certificate(path: &str) -> bool {
    path.contains("x509CertificateChain.certificates[1]")
}

/// `"hashes": []` and no `hashes` are the same proof.
fn empty_list_removed(path: &str, original: &Value, new: Option<&Value>) -> bool {
    path.ends_with(".hashes") && new.is_none() && original.as_array().is_some_and(|a| a.is_empty())
}

fn run_damage(case_name: &str, allowed: &dyn Fn(&str, &Value, Option<&Value>) -> bool, floor: usize) {
    let fx = fixtures();
    let case = fx.case(case_name);
    let root = fx.root(case.get("root").and_then(Value::as_str).unwrap());
    let digest = fx.digest(case);
    let bundle = case.get("bundle").unwrap();
    let doc = json::canonical(bundle).unwrap();
    assert!(Bundle::parse(&doc).unwrap().verify(&Trust::new(&root), &digest).is_ok(), "{case_name} does not verify to begin with");
    let verify_one = |bytes: &[u8], _: usize| -> Option<Result<Verified, Error>> { Some(Bundle::parse(bytes).ok()?.verify(&Trust::new(&root), &digest)) };
    let tried = damage_every_part(&doc, &|_: &[Step]| 0, &verify_one, &allowed);
    println!("{case_name}: {tried} changes tried");
    assert!(tried >= floor, "{case_name}: only {tried} changes tried");
}

#[test]
fn nothing_a_v0_1_bundle_authenticates_can_change() {
    // certificate chain and a signed entry timestamp: the certificates after the leaf are candidates only
    run_damage(
        "v01 chain, SET only",
        &|p, _, _| spare_certificate(p) || envelope_keyid(p) || no_time_stamps(p),
        100,
    );
}

#[test]
fn nothing_a_v0_2_bundle_authenticates_can_change() {
    // a signed entry timestamp and an inclusion proof: either one authenticates the entry, so the promise could be dropped
    // and the proof (with no time) refused: both are checked when present
    run_damage(
        "v02 chain, SET and proof",
        &|p, _, _| spare_certificate(p) || envelope_keyid(p) || no_time_stamps(p),
        150,
    );
}

#[test]
fn nothing_a_v0_3_bundle_with_a_time_stamp_and_a_proof_authenticates_can_change() {
    run_damage(
        "v03 proof only, time stamp",
        &|p, o, n| unauthenticated_in_proof_only(p) || envelope_keyid(p) || empty_list_removed(p, o, n),
        150,
    );
}

#[test]
fn nothing_a_bundle_with_an_ed25519_log_authenticates_can_change() {
    run_damage(
        "ed25519 log, proof only, time stamp",
        &|p, o, n| unauthenticated_in_proof_only(p) || envelope_keyid(p) || empty_list_removed(p, o, n),
        120,
    );
}
