//! Real Sigstore attestations (tests/data/sigstore, see the README there): the three npm releases of the
//! `sigstore` package, one in each bundle format with the two attestations npm serves for it (the publish
//! attestation signed with npm's key, and SLSA provenance signed with a Fulcio certificate), and PyPI's
//! PEP 740 provenance of a wheel, verified against Sigstore's production trusted root and npm's keys.
//!
//! The positive tests say what each attestation proves. The negative ones damage the real data: every
//! string of every attestation is changed or removed, one at a time, and none may verify unless the
//! change is to something the format does not authenticate, which the test lists.

use pratique::json::{self, Value};
use pratique::sigstore::{ArtifactDigest, Bundle, BundleFormat, DigestAlgorithm, Error, Signer, TimeSource, Trust, Verified};
use pratique::trust_root::{KeyRing, TrustedRoot, Validity};

#[path = "common/json_edit.rs"]
mod json_edit;
use json_edit::{damage_every_part, edit, Index, Key, Step};

const ROOT: &[u8] = include_bytes!("data/sigstore/trusted_root.json");
const NPM_KEYS: &[u8] = include_bytes!("data/sigstore/npm-registry-keys.json");
const WHEEL: &[u8] = include_bytes!("data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl");
const PROVENANCE: &[u8] = include_bytes!("data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl.provenance.json");

const RELEASES: [(&str, &[u8], &[u8]); 3] = [
    ("0.2.0", include_bytes!("data/sigstore/sigstore-0.2.0.attestations.json"), include_bytes!("data/sigstore/sigstore-0.2.0.tgz")),
    ("2.2.0", include_bytes!("data/sigstore/sigstore-2.2.0.attestations.json"), include_bytes!("data/sigstore/sigstore-2.2.0.tgz")),
    ("4.0.0", include_bytes!("data/sigstore/sigstore-4.0.0.attestations.json"), include_bytes!("data/sigstore/sigstore-4.0.0.tgz")),
];

const OLD_KEY: &str = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA";
const NEW_KEY: &str = "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U";
const PUBLISH: &str = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";
const GITHUB: &str = "https://token.actions.githubusercontent.com";

fn trust_material() -> (TrustedRoot, KeyRing) {
    (TrustedRoot::parse(ROOT).unwrap(), KeyRing::from_npm_keys(NPM_KEYS).unwrap())
}

fn sha512(tgz: &[u8]) -> ArtifactDigest {
    ArtifactDigest::of(DigestAlgorithm::Sha512, tgz)
}

fn verify_release(i: usize, trust: &Trust) -> Vec<Result<Verified, Error>> {
    let (_, att, tgz) = RELEASES[i];
    Bundle::parse_npm_attestations(att).unwrap().iter().map(|a| a.verify(trust, &sha512(tgz))).collect()
}

/// A short description of a result, for failure messages (a `Verified` is large).
fn brief(r: &Result<Verified, Error>) -> String {
    match r {
        Ok(v) => format!("verified {} at {}", v.statement.predicate_type, v.verified_time),
        Err(e) => format!("error: {e}"),
    }
}

fn identity(v: &Verified) -> &pratique::sigstore::Identity {
    match &v.signer {
        Signer::Certificate(id) => id,
        other => panic!("{other:?}"),
    }
}

// ------------------------------------------------------------------------------------ what verifies

#[test]
fn npm_0_2_0_bundle_format_0_1_a_key_and_a_certificate_chain_with_signed_entry_timestamps() {
    let (root, ring) = trust_material();
    let results = verify_release(0, &Trust::new(&root).with_keys(&ring));
    let (publish, provenance) = (results[0].as_ref().unwrap(), results[1].as_ref().unwrap());

    // npm's publish attestation: signed by the registry's first key, which has since expired, and logged in 2022
    assert_eq!(publish.format, BundleFormat::V0_1);
    match &publish.signer {
        Signer::Key { id, spki_sha256 } => {
            assert_eq!(id, OLD_KEY);
            assert_eq!(spki_sha256, &ring.keys()[0].key.sha256());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(publish.verified_time, 1_670_516_322);
    assert!(publish.verified_time < 1_738_108_800, "the key expired in 2025, after the signing");
    assert_eq!(publish.statement.predicate_type, PUBLISH);
    assert_eq!(publish.statement.statement_type, "https://in-toto.io/Statement/v0.1");
    assert_eq!(publish.statement.subjects.len(), 1);
    assert_eq!(publish.statement.subjects[0].name.as_deref(), Some("pkg:npm/sigstore@0.2.0"));
    assert_eq!(publish.matched_subject, 0);
    let predicate = publish.statement.predicate.as_ref().unwrap();
    assert_eq!(predicate.get("name").and_then(Value::as_str), Some("sigstore"));
    assert_eq!(predicate.get("version").and_then(Value::as_str), Some("0.2.0"));
    assert_eq!(publish.entries.len(), 1);
    let e = &publish.entries[0];
    assert_eq!((e.log_index, e.kind.as_str(), e.version.as_str()), (8_668_626, "intoto", "0.0.2"));
    assert_eq!((e.integrated_time, e.signed_entry_timestamp, e.inclusion.is_some()), (Some(1_670_516_322), true, false));
    assert_eq!(e.log_url, "https://rekor.sigstore.dev");
    assert_eq!(publish.times.len(), 1);
    assert_eq!(publish.times[0].source, TimeSource::LogEntry { log_index: 8_668_626 });

    // the SLSA provenance: a Fulcio certificate that lived ten minutes, from GitHub Actions
    assert_eq!(provenance.format, BundleFormat::V0_1);
    let id = identity(provenance);
    assert_eq!((id.not_before, id.not_after), (1_670_516_319, 1_670_516_919));
    assert_eq!(provenance.verified_time, 1_670_516_319);
    assert_eq!(id.issuer.as_deref(), Some(GITHUB));
    assert_eq!(id.uris, ["https://github.com/sigstore/sigstore-js/.github/workflows/publish.yml@refs/tags/v0.2.0"]);
    assert!(id.emails.is_empty() && id.other_names.is_empty());
    // a certificate of the first generation has only the GitHub extensions
    assert_eq!(id.github_workflow_trigger.as_deref(), Some("release"));
    assert_eq!(id.github_workflow_sha.as_deref(), Some("83811fedfd89fabec5408ccca5faff8631b23255"));
    assert_eq!(id.github_workflow_name.as_deref(), Some("publish"));
    assert_eq!(id.github_workflow_repository.as_deref(), Some("sigstore/sigstore-js"));
    assert_eq!(id.github_workflow_ref.as_deref(), Some("refs/tags/v0.2.0"));
    assert_eq!((id.source_repository_uri.as_deref(), id.source_repository_ref.as_deref(), id.build_config_uri.as_deref()), (None, None, None));
    // so the repository and ref come from those
    assert_eq!(id.repository().as_deref(), Some("https://github.com/sigstore/sigstore-js"));
    assert_eq!(id.git_ref(), Some("refs/tags/v0.2.0"));
    assert_eq!(provenance.statement.predicate_type, "https://slsa.dev/provenance/v0.2");
    let predicate = provenance.statement.predicate.as_ref().unwrap();
    assert_eq!(predicate.get("builder").and_then(|b| b.get("id")).and_then(Value::as_str), Some("https://github.com/npm/cli@9.1.3"));
    assert_eq!(provenance.entries[0].log_index, 8_668_623);
    assert_eq!(provenance.entries[0].integrated_time, Some(1_670_516_319));
    // the chain is the verified path: leaf, intermediate, root
    assert_eq!(id.chain.len(), 3);
    assert_eq!(id.chain[0], id.certificate);
}

#[test]
fn npm_2_2_0_bundle_format_0_2_with_inclusion_proofs_to_a_closed_shard() {
    let (root, ring) = trust_material();
    let results = verify_release(1, &Trust::new(&root).with_keys(&ring));
    let (publish, provenance) = (results[0].as_ref().unwrap(), results[1].as_ref().unwrap());
    for v in [publish, provenance] {
        assert_eq!(v.format, BundleFormat::V0_2);
        let e = &v.entries[0];
        assert!(e.signed_entry_timestamp);
        let inc = e.inclusion.as_ref().expect("a v0.2 entry has an inclusion proof");
        assert_eq!(inc.origin, "rekor.sigstore.dev - 2605736670972794746", "the shard that was current in January 2024");
    }
    assert_eq!(publish.entries[0].inclusion.as_ref().unwrap().tree_size, 59_121_088);
    assert_eq!(provenance.entries[0].inclusion.as_ref().unwrap().tree_size, 59_121_073);
    assert_eq!(publish.verified_time, 1_705_092_996);
    assert!(matches!(&publish.signer, Signer::Key { id, .. } if id == OLD_KEY));
    // the provenance certificate has the current extensions: the repository and ref come from them
    let id = identity(provenance);
    assert_eq!(provenance.verified_time, 1_705_092_994);
    assert_eq!(id.uris, ["https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"]);
    assert_eq!(id.source_repository_uri.as_deref(), Some("https://github.com/sigstore/sigstore-js"));
    assert_eq!(id.source_repository_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!(id.source_repository_digest.as_deref(), Some("d9093d4b3b99d9ee446633ac7074e43cea78c727"));
    assert_eq!(id.source_repository_identifier.as_deref(), Some("495574555"));
    assert_eq!(id.source_repository_owner_uri.as_deref(), Some("https://github.com/sigstore"));
    assert_eq!(id.source_repository_owner_identifier.as_deref(), Some("71096353"));
    assert_eq!(id.build_signer_uri.as_deref(), Some("https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"));
    assert_eq!(id.build_config_uri, id.build_signer_uri);
    assert_eq!(id.runner_environment.as_deref(), Some("github-hosted"));
    assert_eq!(id.build_trigger.as_deref(), Some("push"));
    assert_eq!(id.run_invocation_uri.as_deref(), Some("https://github.com/sigstore/sigstore-js/actions/runs/7507343033/attempts/1"));
    assert_eq!(id.source_repository_visibility_at_signing.as_deref(), Some("public"));
    assert_eq!(id.repository().as_deref(), Some("https://github.com/sigstore/sigstore-js"));
    assert_eq!(id.git_ref(), Some("refs/heads/main"));
    assert_eq!(provenance.statement.statement_type, "https://in-toto.io/Statement/v1");
    assert_eq!(provenance.statement.predicate_type, "https://slsa.dev/provenance/v1");
    let predicate = provenance.statement.predicate.as_ref().unwrap();
    let workflow = predicate.get("buildDefinition").and_then(|b| b.get("externalParameters")).and_then(|p| p.get("workflow")).unwrap();
    assert_eq!(workflow.get("repository").and_then(Value::as_str), Some("https://github.com/sigstore/sigstore-js"));
    assert_eq!(workflow.get("ref").and_then(Value::as_str), Some("refs/heads/main"));
}

#[test]
fn npm_4_0_0_bundle_format_0_3_a_single_certificate_and_a_dsse_entry_and_the_current_key() {
    let (root, ring) = trust_material();
    let results = verify_release(2, &Trust::new(&root).with_keys(&ring));
    let (publish, provenance) = (results[0].as_ref().unwrap(), results[1].as_ref().unwrap());
    assert_eq!(publish.format, BundleFormat::V0_2);
    assert!(matches!(&publish.signer, Signer::Key { id, .. } if id == NEW_KEY));
    assert_eq!(publish.entries[0].log_index, 327_695_335);
    assert_eq!(publish.entries[0].inclusion.as_ref().unwrap().origin, "rekor.sigstore.dev - 1193050959916656506");

    assert_eq!(provenance.format, BundleFormat::V0_3);
    let e = &provenance.entries[0];
    assert_eq!((e.log_index, e.kind.as_str(), e.version.as_str()), (327_695_169, "dsse", "0.0.1"));
    assert_eq!(e.inclusion.as_ref().unwrap().tree_size, 205_790_912);
    assert_eq!(provenance.verified_time, 1_753_831_006);
    assert_eq!(identity(provenance).run_invocation_uri.as_deref(), Some("https://github.com/sigstore/sigstore-js/actions/runs/16609504990/attempts/1"));
    assert_eq!(identity(provenance).chain.len(), 3);
}

#[test]
fn a_lone_bundle_parses_the_same_as_in_the_npm_response() {
    let (root, ring) = trust_material();
    let trust = Trust::new(&root).with_keys(&ring);
    for (i, (_, att, tgz)) in RELEASES.iter().enumerate() {
        let doc = json::parse(att).unwrap();
        for (j, a) in doc.get("attestations").unwrap().as_array().unwrap().iter().enumerate() {
            let alone = json::canonical(a.get("bundle").unwrap()).unwrap();
            let bundle = Bundle::parse(&alone).unwrap();
            let from_bundle = bundle.verify(&trust, &sha512(tgz)).unwrap();
            let from_response = verify_release(i, &trust).remove(j).unwrap();
            assert_eq!(format!("{from_bundle:?}"), format!("{from_response:?}"));
        }
    }
}

#[test]
fn pypi_pep_740_provenance_of_a_wheel() {
    let (root, _) = trust_material();
    let trust = Trust::new(&root);
    let list = Bundle::parse_pep740(PROVENANCE).unwrap();
    assert_eq!(list.len(), 1);
    // the publisher object is what PyPI says, not something that is verified
    let publisher = list[0].claimed_publisher.as_ref().unwrap();
    assert_eq!(publisher.get("repository").and_then(Value::as_str), Some("pypi/pypi-attestations"));
    let v = list[0].verify(&trust, &ArtifactDigest::of(DigestAlgorithm::Sha256, WHEEL)).unwrap();
    assert_eq!(v.format, BundleFormat::Pep740);
    assert_eq!(v.statement.predicate_type, "https://docs.pypi.org/attestations/publish/v1");
    assert_eq!(v.statement.subjects[0].name.as_deref(), Some("pypi_attestations-0.0.30-py3-none-any.whl"));
    let id = identity(&v);
    assert_eq!(id.uris, ["https://github.com/pypi/pypi-attestations/.github/workflows/release.yml@refs/tags/v0.0.30"]);
    assert_eq!(id.issuer.as_deref(), Some(GITHUB));
    assert_eq!(id.repository().as_deref(), Some("https://github.com/pypi/pypi-attestations"));
    assert_eq!(id.git_ref(), Some("refs/tags/v0.0.30"));
    assert_eq!(v.verified_time, 1_785_247_712);
    assert_eq!(v.entries[0].log_index, 2_272_775_063);
    assert_eq!(v.entries[0].inclusion.as_ref().unwrap().tree_size, 2_150_870_804);
    // the certificate was valid for ten minutes around the log time
    assert!(id.not_before <= v.verified_time && v.verified_time <= id.not_after);
}

// ------------------------------------------------------------------------------------ the artifact

#[test]
fn only_the_artifact_that_was_signed_matches() {
    let (root, ring) = trust_material();
    let trust = Trust::new(&root).with_keys(&ring);
    let (_, att, tgz) = RELEASES[2];
    let list = Bundle::parse_npm_attestations(att).unwrap();
    // the right digest in each algorithm the statement has (sha512 only) and the same bytes under others
    for a in &list {
        assert!(a.verify(&trust, &sha512(tgz)).is_ok());
        for alg in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha384] {
            assert_eq!(a.verify(&trust, &ArtifactDigest::of(alg, tgz)).unwrap_err(), Error::SubjectMismatch, "{alg:?}");
        }
        // another artifact (another release's tarball, an empty file, one byte changed)
        for other in [RELEASES[0].2, RELEASES[1].2, &b""[..]] {
            assert_eq!(a.verify(&trust, &sha512(other)).unwrap_err(), Error::SubjectMismatch);
        }
        let mut changed = tgz.to_vec();
        changed[100] ^= 1;
        assert_eq!(a.verify(&trust, &sha512(&changed)).unwrap_err(), Error::SubjectMismatch);
        let mut longer = tgz.to_vec();
        longer.push(0);
        assert_eq!(a.verify(&trust, &sha512(&longer)).unwrap_err(), Error::SubjectMismatch);
    }
    // the digest given by hand
    let digest = sha512(tgz);
    assert_eq!(ArtifactDigest::new(DigestAlgorithm::Sha512, digest.bytes()).unwrap(), digest);
    assert!(list[1].verify(&trust, &ArtifactDigest::new(DigestAlgorithm::Sha512, digest.bytes()).unwrap()).is_ok());
    assert!(ArtifactDigest::new(DigestAlgorithm::Sha512, &digest.bytes()[..63]).is_err());
    assert!(ArtifactDigest::new(DigestAlgorithm::Sha256, digest.bytes()).is_err());
    assert!(ArtifactDigest::new(DigestAlgorithm::Sha384, &[]).is_err());
    assert_eq!(digest.algorithm(), DigestAlgorithm::Sha512);
    assert_eq!(DigestAlgorithm::Sha384.name(), "sha384");
    // the wrong release's attestations for these bytes
    let (_, att_old, _) = RELEASES[0];
    for a in Bundle::parse_npm_attestations(att_old).unwrap() {
        assert_eq!(a.verify(&trust, &sha512(tgz)).unwrap_err(), Error::SubjectMismatch);
    }
    // PyPI: the wheel's sha256 only
    let list = Bundle::parse_pep740(PROVENANCE).unwrap();
    assert_eq!(list[0].verify(&trust, &sha512(WHEEL)).unwrap_err(), Error::SubjectMismatch);
    assert_eq!(list[0].verify(&trust, &ArtifactDigest::of(DigestAlgorithm::Sha256, b"other")).unwrap_err(), Error::SubjectMismatch);
}

#[test]
fn the_label_the_registry_puts_on_an_attestation_is_checked() {
    let (root, ring) = trust_material();
    let trust = Trust::new(&root).with_keys(&ring);
    let (_, att, tgz) = RELEASES[1];
    let doc = json::parse(att).unwrap();
    let relabeled = edit(&doc, &[Key("attestations"), Index(0), Key("predicateType")], Some(Value::string("https://slsa.dev/provenance/v1")));
    let list = Bundle::parse_npm_attestations(&json::canonical(&relabeled).unwrap()).unwrap();
    match list[0].verify(&trust, &sha512(tgz)) {
        Err(Error::Statement(m)) => assert!(m.contains("labels the attestation"), "{m}"),
        other => panic!("{other:?}"),
    }
    // the label is not the point of the other one: the bundle itself still verifies
    assert!(list[0].bundle.verify(&trust, &sha512(tgz)).is_ok());
    assert!(list[1].verify(&trust, &sha512(tgz)).is_ok());
}

// ------------------------------------------------------------------------------------ the trust

#[test]
fn bundles_signed_with_a_key_need_that_key_in_the_ring() {
    let (root, ring) = trust_material();
    // no ring at all, an empty one, one with only the other key
    for trust in [Trust::new(&root), Trust::new(&root).with_keys(&KeyRing::new())] {
        for i in 0..3 {
            let results = verify_release(i, &trust);
            assert_eq!(results[0].as_ref().unwrap_err(), &Error::UnknownKey(if i == 2 { NEW_KEY } else { OLD_KEY }.to_string()), "release {i}");
            assert!(results[1].is_ok(), "the certificate-signed attestation does not need the ring");
        }
    }
    let mut only_new = KeyRing::new();
    only_new.add(NEW_KEY, ring.keys()[1].key.spki(), Validity::ALWAYS).unwrap();
    assert!(verify_release(2, &Trust::new(&root).with_keys(&only_new))[0].is_ok());
    assert!(matches!(verify_release(0, &Trust::new(&root).with_keys(&only_new))[0], Err(Error::UnknownKey(_))));

    // the right name on the wrong key: the signature does not verify
    let mut swapped = KeyRing::new();
    swapped.add(OLD_KEY, ring.keys()[1].key.spki(), Validity::ALWAYS).unwrap();
    assert_eq!(verify_release(0, &Trust::new(&root).with_keys(&swapped))[0].as_ref().unwrap_err(), &Error::Signature);
    // a ring that has the name twice, the wrong key first: the one that verifies is used
    let mut twice = KeyRing::new();
    twice.add(OLD_KEY, ring.keys()[1].key.spki(), Validity::ALWAYS).unwrap();
    twice.add(OLD_KEY, ring.keys()[0].key.spki(), Validity::ALWAYS).unwrap();
    assert!(verify_release(0, &Trust::new(&root).with_keys(&twice))[0].is_ok());
}

#[test]
fn a_key_counts_only_when_it_was_valid_at_a_time_the_log_vouches_for() {
    let (root, ring) = trust_material();
    let spki = ring.keys()[0].key.spki().to_vec();
    let signed_at = 1_670_516_322i64;
    let with = |valid_for: Validity| {
        let mut r = KeyRing::new();
        r.add(OLD_KEY, &spki, valid_for).unwrap();
        verify_release(0, &Trust::new(&root).with_keys(&r)).remove(0)
    };
    assert!(with(Validity { start: Some(signed_at), end: Some(signed_at) }).is_ok(), "both ends are inside");
    assert!(with(Validity { start: Some(signed_at - 1000), end: None }).is_ok());
    assert!(with(Validity { start: None, end: Some(signed_at + 1000) }).is_ok());
    assert_eq!(with(Validity { start: Some(signed_at + 1), end: None }).unwrap_err(), Error::KeyNotValid(OLD_KEY.into()), "not yet valid");
    assert_eq!(with(Validity { start: None, end: Some(signed_at - 1) }).unwrap_err(), Error::KeyNotValid(OLD_KEY.into()), "already expired");
    // a clock would say this key (expired 2025-01-29) is expired today; the log says it was fine then
    assert!(ring.keys()[0].valid_for.end.unwrap() < 1_791_201_600);
    assert!(verify_release(0, &Trust::new(&root).with_keys(&ring))[0].is_ok());
}

#[test]
fn the_transparency_log_must_be_one_the_root_trusts_with_a_key_valid_then() {
    let (root, ring) = trust_material();
    let at = |r: &TrustedRoot| verify_release(1, &Trust::new(r).with_keys(&ring)); // 2.2.0: SET and inclusion proof
    assert!(at(&root).iter().all(Result::is_ok));

    let mut none = root.clone();
    none.tlogs.clear();
    for r in at(&none) {
        match r {
            Err(Error::Entry { reason, .. }) => assert!(reason.contains("no log with id"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
    // only Rekor v2's log: wrong id
    let mut v2_only = root.clone();
    v2_only.tlogs.remove(0);
    assert!(at(&v2_only).iter().all(|r| matches!(r, Err(Error::Entry { .. }))));

    // the key was not valid yet / any more at the integration time (2024-01-12)
    for valid_for in [Validity { start: Some(1_705_092_995 + 10), end: None }, Validity { start: None, end: Some(1_705_092_990) }] {
        let mut r = root.clone();
        r.tlogs[0].valid_for = valid_for;
        for res in at(&r) {
            match res {
                Err(Error::Entry { reason, .. }) => assert!(reason.contains("signed entry timestamp"), "{reason}"),
                other => panic!("{other:?}"),
            }
        }
    }
    // the key's validity covers the integration time of one entry and not of the other
    let mut r = root.clone();
    r.tlogs[0].valid_for = Validity { start: None, end: Some(1_705_092_994) };
    let res = at(&r);
    assert!(res[1].is_ok() && matches!(res[0], Err(Error::Entry { .. })));
    // the log's id with another key: the signed entry timestamp and the checkpoint are not by it
    let mut r = root.clone();
    r.tlogs[0].key = r.tlogs[1].key.clone();
    assert!(at(&r).iter().all(|x| matches!(x, Err(Error::Entry { .. }))));
    // a key that the log has under the same id twice: either may be the one
    let mut r = root.clone();
    let wrong = {
        let mut w = r.tlogs[0].clone();
        w.key = r.tlogs[1].key.clone();
        w
    };
    r.tlogs.insert(0, wrong);
    assert!(at(&r).iter().all(Result::is_ok));
}

#[test]
fn a_certificate_must_chain_to_an_authority_that_counts_at_the_time() {
    let (root, ring) = trust_material();
    let trust_of = |r: &TrustedRoot, i: usize| verify_release(i, &Trust::new(r).with_keys(&ring)).remove(1);
    for i in 0..3 {
        assert!(trust_of(&root, i).is_ok());
    }
    let mut none = root.clone();
    none.certificate_authorities.clear();
    for i in 0..3 {
        match trust_of(&none, i) {
            Err(Error::Certificate(m)) => assert!(m.contains("no certificate authority"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
    // the first CA ended on 2022-12-31 and has only its own root; the certificates of 2022-12 and later
    // were issued below the second one's intermediate
    let mut first_only = root.clone();
    first_only.certificate_authorities.remove(1);
    for i in 0..3 {
        assert!(matches!(trust_of(&first_only, i), Err(Error::Certificate(_))), "release {i}");
    }
    // the second CA before it started: the 2022 and January 2024 signatures are before it; the 2025 one is after
    let mut late = root.clone();
    late.certificate_authorities[1].valid_for = Validity { start: Some(1_705_092_999), end: None };
    assert!(matches!(trust_of(&late, 0), Err(Error::Certificate(_))), "{}", brief(&trust_of(&late, 0)));
    assert!(matches!(trust_of(&late, 1), Err(Error::Certificate(_))));
    assert!(trust_of(&late, 2).is_ok());
    // ... and after it ended
    let mut ended = root.clone();
    ended.certificate_authorities[1].valid_for = Validity { start: None, end: Some(1_670_516_000) };
    for i in 0..3 {
        assert!(matches!(trust_of(&ended, i), Err(Error::Certificate(_))), "release {i}: {}", brief(&trust_of(&ended, i)));
    }
    // a chain that lists only the intermediate anchors there
    let mut only_intermediate = root.clone();
    only_intermediate.certificate_authorities[1].chain.truncate(1);
    for i in 0..3 {
        assert!(trust_of(&only_intermediate, i).is_ok(), "release {i}");
    }
    // a chain that lists only the root: the intermediate has to come from the bundle. The first release's
    // bundle carries the whole chain; the others carry the leaf alone (the 0.3 format has no place for more)
    let mut only_root = root.clone();
    only_root.certificate_authorities[1].chain.remove(0);
    assert!(trust_of(&only_root, 0).is_ok(), "{}", brief(&trust_of(&only_root, 0)));
    for i in 1..3 {
        assert!(matches!(trust_of(&only_root, i), Err(Error::Certificate(_))), "release {i}: {}", brief(&trust_of(&only_root, i)));
    }
    let mut ts_only = root.clone();
    ts_only.certificate_authorities = ts_only.timestamp_authorities.clone();
    for i in 0..3 {
        assert!(matches!(trust_of(&ts_only, i), Err(Error::Certificate(_))), "a time-stamp authority's chain is not Fulcio");
    }
}

/// Every Fulcio certificate here carries one signed certificate timestamp (RFC 6962), from Sigstore's 2022 CT log,
/// signed within a second of the certificate's notBefore; npm's key-signed publish attestations have none. The SCT is
/// checked against the root's `ctlogs` (B-81).
#[test]
fn the_certificate_carries_a_timestamp_from_a_ct_log_of_the_root() {
    let (root, ring) = trust_material();
    let trust = Trust::new(&root).with_keys(&ring);
    let pypi = || Bundle::parse_pep740(PROVENANCE).unwrap().remove(0);
    let wheel = ArtifactDigest::of(DigestAlgorithm::Sha256, WHEEL);
    let mut provenance: Vec<Verified> = (0..3).map(|i| verify_release(i, &trust).remove(1).unwrap()).collect();
    provenance.push(pypi().verify(&trust, &wheel).unwrap());
    let want = [1_670_516_319_542u64, 1_705_092_993_994, 1_753_831_006_550, 1_785_247_711_104];
    for (v, ms) in provenance.iter().zip(want) {
        assert_eq!(v.scts.len(), 1, "{:?}", v.scts);
        assert_eq!(v.scts[0].log_url, "https://ctfe.sigstore.dev/2022");
        assert_eq!(v.scts[0].log_id, root.ctlogs[1].log_id);
        assert_eq!(v.scts[0].timestamp_ms, ms);
        let nb = identity(v).not_before;
        assert!((ms / 1000) as i64 - nb <= 1 && (ms / 1000) as i64 >= nb, "{ms} {nb}");
    }
    for i in 0..3 {
        assert!(verify_release(i, &trust).remove(0).unwrap().scts.is_empty(), "a key has no SCTs");
    }

    let ct_error = |r: Result<Verified, Error>| match r {
        Err(Error::CertificateTransparency(m)) => m,
        other => panic!("{}", brief(&other)),
    };
    let check = |r: &TrustedRoot, threshold: usize| -> Vec<Result<Verified, Error>> {
        let t = Trust::new(r).with_keys(&ring).with_sct_threshold(threshold);
        let mut out: Vec<_> = (0..3).map(|i| verify_release(i, &t).remove(1)).collect();
        out.push(pypi().verify(&t, &wheel));
        out
    };
    // a root without the CT logs: the SCT is from a log it does not list, so nothing counts; unless none is required
    let mut no_ct = root.clone();
    no_ct.ctlogs.clear();
    for r in check(&no_ct, 1) {
        let m = ct_error(r);
        assert!(m.contains("from 0 of the trusted root's CT logs verified and 1 are required") && m.contains("has 1, 1 from logs the root does not list"), "{m}");
    }
    assert!(check(&no_ct, 0).into_iter().all(|r| r.unwrap().scts.is_empty()));
    // two logs required: there is one
    for r in check(&root, 2) {
        assert!(ct_error(r).contains("from 1 of the trusted root's CT logs verified and 2 are required"));
    }
    // the log's key was not valid at the SCT's time: before 2022-12-08 16:18:39 / from after it
    for (valid_for, ok_from) in [(Validity { start: None, end: Some(1_670_516_318) }, 0), (Validity { start: Some(1_670_516_320), end: None }, 1)] {
        let mut r = root.clone();
        r.ctlogs[1].valid_for = valid_for;
        for (i, res) in check(&r, 0).into_iter().enumerate() {
            if i < ok_from || valid_for.end.is_some() {
                let m = ct_error(res);
                assert!(m.contains("does not verify: no key of the log was valid at"), "{m}");
            } else {
                res.unwrap();
            }
        }
    }
    // the last second of the key's validity is inside it
    let mut r = root.clone();
    r.ctlogs[1].valid_for = Validity { start: Some(1_670_516_319), end: Some(1_670_516_319) };
    assert!(check(&r, 1)[0].is_ok());
    // the log's id with another key (Rekor's, also P-256): the signature is not by it; even with the threshold at 0
    let mut r = root.clone();
    r.ctlogs[1].key = r.tlogs[0].key.clone();
    for res in check(&r, 0) {
        assert!(ct_error(res).contains("the signature is not the log's"));
    }
    // ... and a P-384 key: the SCT's algorithms are not the key's
    let mut r = root.clone();
    let p384 = root.certificate_authorities.iter().flat_map(|a| &a.chain).find_map(|der| {
        let c = pratique::x509::Certificate::from_der(der).unwrap();
        pratique::trust_root::VerificationKey::from_spki(c.spki_der()).ok().filter(|k| k.kind() == pratique::trust_root::KeyKind::EcdsaP384)
    });
    r.ctlogs[1].key = p384.expect("Fulcio's CA keys are P-384");
    for res in check(&r, 0) {
        assert!(ct_error(res).contains("signed with algorithms (4, 3), and the log's key goes with (5, 3)"));
    }
    // the same log listed twice, once with a wrong key: the right one is found
    let mut r = root.clone();
    let mut wrong = r.ctlogs[1].clone();
    wrong.key = r.tlogs[0].key.clone();
    r.ctlogs.insert(1, wrong);
    assert!(check(&r, 1).into_iter().all(|x| x.unwrap().scts.len() == 1));
}

/// The SCT reader on its own, on the real certificates: every byte of the SCT list changed in turn makes it either
/// unreadable or not verify (or, for the log id, from a log that is not listed); the precertificate is the certificate
/// without the extension.
#[test]
fn every_byte_of_a_real_sct_counts() {
    use pratique::ct;
    use pratique::x509::Certificate;
    let (root, ring) = trust_material();
    let v = verify_release(2, &Trust::new(&root).with_keys(&ring)).remove(1).unwrap();
    let id = identity(&v);
    let (leaf, issuer) = (Certificate::from_der(&id.certificate).unwrap(), Certificate::from_der(&id.chain[1]).unwrap());
    let report = ct::verify_embedded(&leaf, &issuer, &root.ctlogs).unwrap();
    assert_eq!((report.verified.len(), report.unknown_logs.len(), report.other_versions, report.distinct_logs()), (1, 0, 0, 1));
    // the issuer is part of what was signed: the root above it is not the issuer
    let anchor = Certificate::from_der(id.chain.last().unwrap()).unwrap();
    assert!(ct::verify_embedded(&leaf, &anchor, &root.ctlogs).unwrap_err().to_string().contains("the signature is not the log's"));
    // the precertificate: one extension fewer, otherwise the same bytes (the lengths are what Python's `cryptography`
    // gives for `tbs_certificate_bytes` and `tbs_precertificate_bytes` of this certificate)
    let pre = ct::precertificate_tbs(leaf.tbs_der()).unwrap();
    assert_eq!((leaf.tbs_der().len(), pre.len()), (1599, 1459));
    let ext = leaf.extension(ct::OID_SCT_LIST).unwrap();
    let list = ct::parse_list(&ext.value).unwrap();
    assert_eq!(list.scts.len(), 1);
    assert_eq!((list.scts[0].hash_algorithm, list.scts[0].signature_algorithm), (4, 3));
    // change each byte of the extension's value inside the certificate (the certificate's own signature is not what
    // is checked here)
    let at = id.certificate.windows(ext.value.len()).position(|w| w == ext.value.as_slice()).unwrap();
    let (mut unreadable, mut refused, mut unknown) = (0, 0, 0);
    for i in 0..ext.value.len() {
        let mut der = id.certificate.clone();
        der[at + i] ^= 0x01;
        let Ok(c) = Certificate::from_der(&der) else {
            unreadable += 1;
            continue;
        };
        match ct::verify_embedded(&c, &issuer, &root.ctlogs) {
            Err(_) => refused += 1,
            Ok(r) if r.verified.is_empty() && (r.unknown_logs.len() == 1 || r.other_versions == 1) => unknown += 1,
            Ok(r) => panic!("byte {i} of the SCT extension changed and it still verified: {r:?}"),
        }
    }
    assert_eq!(unreadable + refused + unknown, ext.value.len());
    // 32 log id bytes and the version byte make an SCT that is not checked; the rest is refused
    assert_eq!(unknown, 33, "{unreadable} {refused} {unknown}");
}

// the JSON editing helpers are in tests/common/json_edit.rs

// ------------------------------------------------------------------------------------ damage

/// Paths (as `show` writes them, without the leading `attestations[i].`) whose change leaves a bundle verifying,
/// because nothing authenticates them: what a verifier must not rely on.
fn unauthenticated(path: &str, original: &Value, new: Option<&Value>) -> bool {
    let p = path.split_once("].").map_or(path, |(_, rest)| rest);
    if p == "signedAccessSignatureUrl" {
        return true; // a URL the registry adds
    }
    if p.starts_with("bundle.verificationMaterial.timestampVerificationData") {
        return true; // no time stamps in these bundles
    }
    if p == "bundle.dsseEnvelope.signatures[0].keyid" {
        return true; // a hint: the key is found by the bundle's own hint
    }
    if p == "bundle.verificationMaterial.publicKey.hint" && new == Some(&Value::string("")) {
        return true; // an empty hint falls back to the signature's keyid, the same name; keys are found by name and then must verify
    }
    // certificates after the leaf are candidates for intermediates; the trusted root has them
    if let Some(rest) = p.strip_prefix("bundle.verificationMaterial.x509CertificateChain.certificates[") {
        if !rest.starts_with("0]") {
            return true;
        }
    }
    // `"inclusionProof": null` and an absent one are the same
    if p.ends_with(".inclusionProof") && original.is_null() {
        return true;
    }
    false
}

fn npm_target(path: &[Step]) -> usize {
    match (path.first(), path.get(1)) {
        (Some(Step::KeyOwned(k)), Some(Index(i))) if k == "attestations" => *i,
        _ => 0,
    }
}

#[test]
fn nothing_the_npm_attestations_authenticate_can_change() {
    let (root, ring) = trust_material();
    let trust = Trust::new(&root).with_keys(&ring);
    let mut total = 0;
    for (version, att, tgz) in RELEASES {
        let digest = sha512(tgz);
        let verify_one = |doc: &[u8], which: usize| -> Option<Result<Verified, Error>> {
            let list = Bundle::parse_npm_attestations(doc).ok()?;
            Some(list.get(which)?.verify(&trust, &digest))
        };
        let tried = damage_every_part(att, &npm_target, &verify_one, &unauthenticated);
        println!("{version}: {tried} changes tried");
        assert!(tried > 200, "{version}: {tried}");
        total += tried;
    }
    assert!(total > 700, "{total}");
}

#[test]
fn nothing_the_pep_740_provenance_authenticates_can_change() {
    let (root, _) = trust_material();
    let trust = Trust::new(&root);
    let digest = ArtifactDigest::of(DigestAlgorithm::Sha256, WHEEL);
    let verify_one = |doc: &[u8], _: usize| -> Option<Result<Verified, Error>> {
        let list = Bundle::parse_pep740(doc).ok()?;
        Some(list.first()?.verify(&trust, &digest))
    };
    // the publisher is a claim: changing it changes nothing that is verified, and the claim is returned as written
    let doc = json::parse(PROVENANCE).unwrap();
    let publisher = [Step::KeyOwned("attestation_bundles".into()), Index(0), Step::KeyOwned("publisher".into())];
    let claimed = edit(&doc, &publisher, Some(Value::string("somebody else")));
    let list = Bundle::parse_pep740(&json::canonical(&claimed).unwrap()).unwrap();
    assert_eq!(list[0].claimed_publisher, Some(Value::string("somebody else")));
    assert!(list[0].verify(&trust, &digest).is_ok(), "the publisher object is not what is verified");

    let allowed = |path: &str, _: &Value, _: Option<&Value>| path.starts_with("attestation_bundles[0].publisher");
    let tried = damage_every_part(PROVENANCE, &|_| 0, &verify_one, &allowed);
    println!("PEP 740 provenance: {tried} changes tried");
    assert!(tried > 250, "{tried}");
}
