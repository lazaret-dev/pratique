//! Sigstore's real TUF repository, as `tools/mac_field_check.sh tuf` captured it (`examples/tuf_refresh --save`), replayed
//! offline at the time it was captured (BACKLOG B-82): the root rotates from the one built into the crate, everything
//! verifies, and the two targets are Sigstore's trusted root and npm's keys.
//!
//! Ignored until a capture is in `tests/data/tuf/sigstore/` (this sandbox cannot reach the repository; a field run can).
//! `cargo test --test tuf_sigstore -- --ignored` then runs it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pratique::trust_root::{KeyRing, TrustedRoot};
use pratique::tuf::{self, Fetched, Local, Request, Updater};

fn capture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/tuf/sigstore")
}

fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(p.strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

fn replay(now: i64, bootstrap: &[u8], files: &BTreeMap<String, Vec<u8>>) -> Result<(Updater, Vec<u8>, Vec<u8>), tuf::Error> {
    let serve = |prefix: &'static str| move |r: &Request| -> Result<Fetched, String> { Ok(files.get(&format!("{prefix}/{}", r.path)).map_or(Fetched::NotFound, |d| Fetched::Data(d.clone()))) };
    let mut u = Updater::new(bootstrap, now)?;
    tuf::refresh(&mut u, Local::default(), &mut serve("metadata"))?;
    let (_, trusted_root) = tuf::fetch_target(&mut u, tuf::SIGSTORE_TRUSTED_ROOT_TARGET, &mut serve("metadata"), &mut serve("targets"))?;
    let (_, npm) = tuf::fetch_target(&mut u, tuf::NPM_KEYS_TARGET, &mut serve("metadata"), &mut serve("targets"))?;
    Ok((u, trusted_root, npm))
}

#[test]
#[ignore = "needs a capture of Sigstore's TUF repository in tests/data/tuf/sigstore/ (tools/mac_field_check.sh tuf)"]
fn the_captured_repository_verifies_from_the_built_in_root() {
    let dir = capture();
    let now: i64 = std::fs::read_to_string(dir.join("now")).unwrap().trim().parse().unwrap();
    let bootstrap = std::fs::read(dir.join("bootstrap.json")).unwrap();
    assert_eq!(bootstrap, tuf::SIGSTORE_ROOT, "the capture started from the root built into the crate");
    let all = files(&dir);
    let (u, trusted_root, npm) = replay(now, &bootstrap, &all).unwrap();
    assert!(u.root().common.version >= 15);
    let root = TrustedRoot::parse(&trusted_root).unwrap();
    assert!(!root.ctlogs.is_empty() && !root.certificate_authorities.is_empty() && !root.tlogs.is_empty());
    let ring = KeyRing::from_tuf_npm_keys(&npm, "npm:attestations").unwrap();
    let ids: Vec<&str> = ring.keys().iter().map(|k| k.id.as_str()).collect();
    assert!(ids.contains(&"SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"), "{ids:?}");
    // the real attestations of tests/data/sigstore verify against what the repository gives (the trust a client gets this
    // way is the trust the tests use)
    let att = include_bytes!("data/sigstore/sigstore-4.0.0.attestations.json");
    let tgz = include_bytes!("data/sigstore/sigstore-4.0.0.tgz");
    let trust = pratique::sigstore::Trust::new(&root).with_keys(&ring);
    let digest = pratique::sigstore::ArtifactDigest::of(pratique::sigstore::DigestAlgorithm::Sha512, tgz);
    for a in pratique::sigstore::Bundle::parse_npm_attestations(att).unwrap() {
        a.verify(&trust, &digest).unwrap();
    }
    // at the second the timestamp expires, the same files are refused
    let (t, _) = u.timestamp().unwrap();
    assert!(matches!(replay(t.common.expires, &bootstrap, &all), Err(tuf::Error::Expired { .. })));
    // every metadata file and target damaged in one byte (a sample of each) is refused
    for (path, data) in &all {
        if !(path.starts_with("metadata/") || path.starts_with("targets/")) {
            continue;
        }
        for i in (0..data.len()).step_by(data.len() / 50 + 1) {
            let mut f = all.clone();
            f.get_mut(path).unwrap()[i] ^= 0x01;
            if let Ok((_, tr, n)) = replay(now, &bootstrap, &f) {
                // only a root the rotation never needed, or a file nothing asked for, can change unnoticed
                assert_eq!((tr, n), (trusted_root.clone(), npm.clone()), "byte {i} of {path}");
            }
        }
    }
}
