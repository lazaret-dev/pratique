//! The generated chains of `tests/data/chain_cases` (made by `tools/gen_chain_cases.py`; BACKLOG B-92, part 3): each differs
//! from a good chain in one thing, and `tools/chain_judges.sh` puts them before OpenSSL, Go and Apple as well as this library.
//! Here they are a regression test of the library alone:
//!
//! * a case marked `ok` or `refuse` (what RFC 5280 and the CA/Browser Forum's rules for TLS servers both say) must come out
//!   that way;
//! * a case marked `either` (left to the verifier, or where verifiers differ on purpose) must come out as `DECIDED` below
//!   says, which is the library's choice, written down with its reason, so that a change of it is a decision and not an
//!   accident. Every `either` case has to be in the table, and every entry of the table has to be a case.

use pratique::pem;
use pratique::x509::TrustStore;
use std::path::{Path, PathBuf};

/// The library's choice for each case the standards leave open (true: it accepts), and why. Since 2026-10-10 a TLS server's
/// chain is held to the CA/Browser Forum's rules where they bind a client (`VerifyOptions::web_pki`), which closed the five
/// cases where the library had been looser than Apple's verifier.
const DECIDED: &[(&str, bool, &str)] = &[
    // (in brackets what the other three judges of tools/chain_judges.sh do: OpenSSL 3 with -x509_strict, Go's crypto/x509 and
    // Apple's `security verify-cert` under the ssl policy, as run on 2026-10-09 and 2026-10-10)
    ("ok_ed25519", false, "the CA/B Forum's rules allow RSA and ECDSA only (Apple agrees; OpenSSL and Go accept); a store of private anchors accepts it, TrustStore::with_web_pki_rules(false)"),
    ("either_anchor_expired", false, "a trust anchor's certificate is held to its own validity (all three agree)"),
    ("either_generalized_time_before_2050", true, "a time in the other encoding is read for what it says (all three agree)"),
    ("either_wildcard_partial_label", false, "a wildcard is a whole leftmost label, as the CA/B Forum says (Go and Apple agree; OpenSSL accepts)"),
    ("either_wildcard_public_suffix", false, "a wildcard needs two labels after it (OpenSSL and Apple agree; Go accepts *.test)"),
    ("either_common_name_only", false, "the common name is not a host name (Go and Apple agree; OpenSSL falls back to it)"),
    ("either_host_trailing_dot", true, "the root's dot at the end of the host asked for is ignored (Go and Apple agree; OpenSSL refuses)"),
    ("either_intermediate_basic_constraints_not_critical", true, "RFC 5280's validation does not look at the flag (Go and Apple agree; OpenSSL's strict mode refuses)"),
    ("either_anchor_path_length_zero", false, "an anchor's pathLenConstraint is applied (all three agree)"),
    ("either_leaf_is_ca", true, "a CA certificate may be a server's, as RFC 5280 allows (all three agree)"),
    ("either_intermediate_without_key_usage", true, "keyUsage is optional in RFC 5280 (Go and Apple agree; OpenSSL's strict mode refuses)"),
    ("either_leaf_key_usage_cert_sign_only", false, "a TLS server's key must be allowed to sign, digitalSignature (OpenSSL agrees; Go and Apple accept)"),
    ("either_leaf_without_eku", false, "the CA/B Forum's rules require serverAuth in the leaf's extendedKeyUsage (Apple agrees; OpenSSL and Go accept, as RFC 5280 would)"),
    ("either_leaf_eku_any", false, "the CA/B Forum's rules require serverAuth and forbid anyExtendedKeyUsage in the leaf (OpenSSL and Apple agree; Go accepts)"),
    ("either_leaf_eku_server_and_any", false, "the same: anyExtendedKeyUsage is forbidden beside serverAuth too (not yet judged by the others)"),
    ("either_intermediate_eku_client_only", false, "an intermediate's extendedKeyUsage limits what it issues, as browsers have it (all three agree)"),
    ("either_nc_common_name_only", false, "the common name is not a host name, so it cannot slip past a constraint (all three refuse)"),
    ("either_nc_on_anchor", false, "an anchor's nameConstraints are applied (all three agree)"),
    ("either_nc_not_critical", false, "a constraint is applied whatever its criticality says (all three agree)"),
    ("either_leaf_signed_sha1", false, "SHA-1 signatures are refused (Go and Apple agree; OpenSSL accepts)"),
    ("either_leaf_rsa_1024", false, "RSA keys under 2,048 bits are refused; TrustStore::with_min_rsa_bits changes it (Apple agrees; OpenSSL and Go accept)"),
    ("either_intermediate_rsa_1024", false, "the same minimum for every certificate of the path (Apple agrees; OpenSSL and Go accept)"),
    ("either_issuer_name_case", false, "an issuer name is byte for byte the issuer's subject name, CA/B Forum rule 7.1.4.1 (Go and Apple agree; OpenSSL compares without case, as RFC 5280 7.1 would)"),
    ("either_issuer_name_printable_string", false, "the same: another string type is another name (Go and Apple agree; OpenSSL does not)"),
    ("either_issuer_name_spaces", false, "the same: spaces are not folded (Go and Apple agree; OpenSSL folds them, as RFC 4518 would)"),
    ("either_authority_key_id_mismatch", false, "an authorityKeyIdentifier must be the issuer's subjectKeyIdentifier, as the CA/B Forum's rules say (OpenSSL and Apple agree; Go accepts)"),
    ("either_no_authority_key_id", true, "its absence is a CA's fault the CA/B Forum leaves to CAs, and no browser refuses it (Go and Apple agree; OpenSSL's strict mode refuses)"),
    ("either_self_signed_leaf_is_the_anchor", false, "an anchor issues only if it is a CA, and a self-signed end-entity certificate is not one (all three accept it as a pin)"),
    ("either_serial_zero", true, "a non-positive serial number is tolerated, as RFC 5280 4.1.2.2 asks of users (all three agree)"),
    ("either_serial_negative", true, "the same (OpenSSL and Apple agree; Go refuses to parse it)"),
    ("either_serial_21_bytes", true, "the same for a serial number longer than 20 bytes (all three agree)"),
    ("either_basic_constraints_false_written", true, "a default value written out is read for what it says (all three agree)"),
];

struct Case {
    name: String,
    host: String,
    time: i64,
    expect: String,
    anchor: String,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/chain_cases")
}

fn certs_in(path: &Path) -> Vec<Vec<u8>> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect()
}

fn cases() -> Vec<Case> {
    let text = std::fs::read_to_string(dir().join("fixtures.tsv")).expect("tests/data/chain_cases/fixtures.tsv (python3 tools/gen_chain_cases.py)");
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            Case { name: c[0].into(), host: c[1].into(), time: c[2].parse().unwrap(), expect: c[3].into(), anchor: c[4].into() }
        })
        .collect()
}

fn accepted(case: &Case) -> Result<(), String> {
    let chain = certs_in(&dir().join("chains").join(format!("{}.pem", case.name)));
    let mut store = TrustStore::empty();
    for der in certs_in(&dir().join(&case.anchor)) {
        store.add_der(&der).map_err(|e| format!("anchor: {e}"))?;
    }
    store.verify_server_chain(&chain, &case.host, case.time).map(|_| ()).map_err(|e| e.to_string())
}

#[test]
fn every_generated_chain_comes_out_as_the_standards_or_the_librarys_choice_say() {
    let cases = cases();
    assert!(cases.len() >= 80, "{} cases", cases.len());
    let mut wrong = Vec::new();
    for case in &cases {
        let got = accepted(case);
        let want = match case.expect.as_str() {
            "ok" => true,
            "refuse" => false,
            "either" => match DECIDED.iter().find(|d| d.0 == case.name) {
                Some(d) => d.1,
                None => panic!("{}: a case left to the verifier with no decision in DECIDED", case.name),
            },
            other => panic!("{}: expect {other}?", case.name),
        };
        if got.is_ok() != want {
            wrong.push(format!("{}: wanted {}, got {:?}", case.name, if want { "accepted" } else { "refused" }, got));
        }
    }
    assert!(wrong.is_empty(), "{} case(s) came out otherwise:\n{}", wrong.len(), wrong.join("\n"));
    // and the table names cases that exist and are left open
    for (name, _, _) in DECIDED {
        assert!(cases.iter().any(|c| c.name == *name && c.expect == "either"), "DECIDED names {name}, which is not a case left open");
    }
}

#[test]
fn a_store_of_private_anchors_is_held_to_rfc_5280_alone() {
    // the cases the CA/Browser Forum's rules close, accepted again under a store that turns them off (and the rest as before)
    let relaxed = ["ok_ed25519", "either_leaf_without_eku", "either_leaf_eku_any", "either_leaf_eku_server_and_any", "either_issuer_name_case", "either_issuer_name_printable_string", "either_issuer_name_spaces", "either_authority_key_id_mismatch"];
    for case in cases() {
        let chain = certs_in(&dir().join("chains").join(format!("{}.pem", case.name)));
        let mut store = TrustStore::empty().with_web_pki_rules(false);
        for der in certs_in(&dir().join(&case.anchor)) {
            store.add_der(&der).unwrap();
        }
        let private = store.verify_server_chain(&chain, &case.host, case.time).is_ok();
        let default = accepted(&case).is_ok();
        if relaxed.contains(&case.name.as_str()) {
            assert!(private && !default, "{}: private {private}, default {default}", case.name);
        } else {
            assert_eq!(private, default, "{}: only the CA/Browser Forum's cases differ", case.name);
        }
    }
}
