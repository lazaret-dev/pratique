//! Verifies Sigstore attestations of a file (an npm package tarball, a PyPI wheel, anything with a bundle)
//! against a trusted root, and prints what they prove: who signed, what they signed and when the logs and
//! time-stamp authorities say it was. Whether that is the signer you expect is for you to decide.
//!
//! ```text
//! cargo run --release --example sigstore_verify -- --root trusted_root.json [--npm-keys KEYS] [--digest sha256|sha384|sha512]
//!                                                  (--npm | --pep740 | --bundle) ATTESTATIONS ARTIFACT
//!
//! # the npm package `sigstore` 2.2.0, from the files in tests/data/sigstore
//! cargo run --release --example sigstore_verify -- --root tests/data/sigstore/trusted_root.json \
//!     --npm-keys tests/data/sigstore/npm-registry-keys.json --npm --digest sha512 \
//!     tests/data/sigstore/sigstore-2.2.0.attestations.json tests/data/sigstore/sigstore-2.2.0.tgz
//! ```
//!
//! `--npm` reads the registry's answer for `/-/npm/v1/attestations/PACKAGE@VERSION` (npm's subject digest is
//! SHA-512 of the tarball), `--pep740` PyPI's `/integrity/PROJECT/VERSION/FILE/provenance` (SHA-256), `--bundle`
//! a single Sigstore bundle (v0.1 to v0.3, SHA-256 unless `--digest` says otherwise). The trusted root is
//! Sigstore's `trusted_root.json` (from its TUF repository; this program does not fetch it) and the key list
//! npm's `/-/npm/v1/keys`. Nothing here reads the clock. The exit status is 0 when every attestation verified,
//! 1 when one was refused and 2 for a usage or file error.

use std::error::Error;

use pratique::sigstore::{ArtifactDigest, Bundle, DigestAlgorithm, Signer, TimeSource, Trust, Verified};
use pratique::trust_root::{KeyRing, TrustedRoot};

fn usage() -> ! {
    eprintln!("usage: sigstore_verify --root FILE [--npm-keys FILE] [--digest sha256|sha384|sha512] (--npm | --pep740 | --bundle) ATTESTATIONS ARTIFACT");
    std::process::exit(2);
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn when(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn show(v: &Verified) {
    println!("  format {:?}, statement {}", v.format, v.statement.statement_type);
    println!("  predicate {}", v.statement.predicate_type);
    let subject = &v.statement.subjects[v.matched_subject];
    println!("  subject {} ({} of {})", subject.name.as_deref().unwrap_or("(unnamed)"), v.matched_subject + 1, v.statement.subjects.len());
    match &v.signer {
        Signer::Certificate(id) => {
            println!("  signed with a Fulcio certificate valid {} to {}", when(id.not_before), when(id.not_after));
            println!("    issuer      {}", id.issuer.as_deref().unwrap_or("-"));
            for uri in &id.uris {
                println!("    identity    {uri}");
            }
            for mail in &id.emails {
                println!("    identity    {mail}");
            }
            for name in &id.other_names {
                println!("    identity    {name}");
            }
            println!("    repository  {}", id.repository().as_deref().unwrap_or("-"));
            println!("    ref         {}", id.git_ref().unwrap_or("-"));
            println!("    commit      {}", id.source_repository_digest.as_deref().or(id.github_workflow_sha.as_deref()).unwrap_or("-"));
            println!("    trigger     {}", id.build_trigger.as_deref().or(id.github_workflow_trigger.as_deref()).unwrap_or("-"));
            println!("    workflow    {}", id.build_config_uri.as_deref().or(id.build_signer_uri.as_deref()).unwrap_or("-"));
        }
        Signer::Key { id, .. } => println!("  signed with the key {id}"),
    }
    println!("  the certificate or key was checked at {}", when(v.verified_time));
    for t in &v.times {
        match &t.source {
            TimeSource::LogEntry { log_index } => println!("  time {}: signed entry timestamp of log entry {log_index}", when(t.time)),
            TimeSource::TimeStamp { authority } => println!("  time {}: time stamp by {authority}", when(t.time)),
        }
    }
    for e in &v.entries {
        let proof = e.inclusion.as_ref().map_or("no inclusion proof".to_string(), |i| format!("leaf {} of {} in {}", i.leaf_index, i.tree_size, i.origin));
        println!("  log entry {} ({} {}) of {}: {}{}", e.log_index, e.kind, e.version, e.log_url, if e.signed_entry_timestamp { "signed entry timestamp, " } else { "" }, proof);
    }
    for s in &v.scts {
        let at = when((s.timestamp_ms / 1000) as i64).replace(" UTC", &format!(".{:03} UTC", s.timestamp_ms % 1000));
        println!("  certificate logged by the CT log {} at {at} (signed certificate timestamp)", s.log_url);
    }
}

fn run() -> Result<bool, Box<dyn Error>> {
    let (mut root, mut keys, mut digest, mut form) = (None::<String>, None::<String>, None::<DigestAlgorithm>, None::<&'static str>);
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => root = args.next(),
            "--npm-keys" => keys = args.next(),
            "--digest" => {
                digest = Some(match args.next().as_deref() {
                    Some("sha256") => DigestAlgorithm::Sha256,
                    Some("sha384") => DigestAlgorithm::Sha384,
                    Some("sha512") => DigestAlgorithm::Sha512,
                    _ => usage(),
                })
            }
            "--npm" => form = Some("npm"),
            "--pep740" => form = Some("pep740"),
            "--bundle" => form = Some("bundle"),
            "-h" | "--help" => usage(),
            _ => files.push(a),
        }
    }
    let (Some(root), Some(form), [attestations, artifact]) = (root, form, files.as_slice()) else { usage() };
    let root = TrustedRoot::parse(&std::fs::read(root)?)?;
    let ring = keys.map(|k| std::fs::read(k).map_err(Box::<dyn Error>::from).and_then(|b| KeyRing::from_npm_keys(&b).map_err(Into::into))).transpose()?;
    let mut trust = Trust::new(&root);
    if let Some(r) = &ring {
        trust = trust.with_keys(r);
    }
    let digest = digest.unwrap_or(match form {
        "npm" => DigestAlgorithm::Sha512,
        _ => DigestAlgorithm::Sha256,
    });
    let artifact = ArtifactDigest::of(digest, &std::fs::read(artifact)?);
    let bytes = std::fs::read(attestations)?;

    let results: Vec<(String, Result<Verified, pratique::sigstore::Error>)> = match form {
        "npm" => Bundle::parse_npm_attestations(&bytes)?.iter().map(|a| (a.claimed_predicate_type.clone(), a.verify(&trust, &artifact))).collect(),
        "pep740" => Bundle::parse_pep740(&bytes)?.iter().map(|a| ("attestation".to_string(), a.verify(&trust, &artifact))).collect(),
        _ => vec![("bundle".to_string(), Bundle::parse(&bytes)?.verify(&trust, &artifact))],
    };
    if results.is_empty() {
        println!("no attestations");
        return Ok(false);
    }
    let mut all = true;
    for (i, (label, r)) in results.iter().enumerate() {
        match r {
            Ok(v) => {
                println!("attestation {} ({label}): verified", i + 1);
                show(v);
            }
            Err(e) => {
                all = false;
                println!("attestation {} ({label}): REFUSED: {e}", i + 1);
            }
        }
    }
    Ok(all)
}
