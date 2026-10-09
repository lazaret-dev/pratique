//! Real data from Sigstore's Rekor transparency log (tests/data/rekor, see tools/gen_rekor_fixtures.py
//! and tools/rekor_capture.sh), replayed against the pure parts of the crate:
//!
//! * the log's checkpoints (signed tree heads) are signed notes with an ECDSA P-256 signature and Rekor's own
//!   key-hash rule, which `note::Verifier::ecdsa_p256_spki` reads: the current head, the older head from the
//!   Lazaret npm provenance bundle, and the heads of the two shards the log has closed;
//! * a real consistency proof of 29 hashes from the older head (2,953,640,305 entries) to the current
//!   one (2,976,019,742) verifies with `tlog::verify_consistency`, and does not once anything in it changes;
//! * the newer Rekor v2 log signs with Ed25519 and its checkpoint is cosigned by witnesses: `note::open`
//!   verifies the log's signature and sets the three witness lines aside as signatures it has no key for.

use pratique::note::{self, Verifier};
use pratique::pem;
use pratique::tlog::{self, Hash};
use pratique::util::unhex;

const KEY_PEM: &str = include_str!("data/rekor/v1_key.pem");
const NEW: &str = include_str!("data/rekor/v1_checkpoint_new.txt");
const OLD: &str = include_str!("data/rekor/v1_checkpoint_old.txt");
const SHARD_A: &str = include_str!("data/rekor/v1_shard_4163431.txt");
const SHARD_B: &str = include_str!("data/rekor/v1_shard_117740831.txt");
const PROOF: &str = include_str!("data/rekor/v1_consistency_proof.txt");
const V2: &str = include_str!("data/rekor/v2_checkpoint.txt");
const V2_KEY: &str = include_str!("data/rekor/v2_key.txt");

fn rekor_key() -> Vec<u8> {
    pem::parse(KEY_PEM).remove(0).data
}

fn rekor() -> Verifier {
    Verifier::ecdsa_p256_spki("rekor.sigstore.dev", &rekor_key()).unwrap()
}

/// The origin, size and root of a checkpoint's text.
struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
}

fn checkpoint(note: &str) -> Checkpoint {
    let opened = note::open(note.as_bytes(), &[rekor()]).unwrap();
    assert_eq!(opened.signatures.len(), 1);
    assert!(opened.unverified.is_empty());
    let mut lines = opened.text.lines();
    let origin = lines.next().unwrap().to_string();
    let size: u64 = lines.next().unwrap().parse().unwrap();
    let root: Hash = pem::base64_decode_strict(lines.next().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(lines.next(), None);
    Checkpoint { origin, size, root }
}

#[test]
fn rekor_v1_checkpoints_verify_with_the_logs_ecdsa_key() {
    for (note, size) in [(NEW, 2_976_019_742u64), (OLD, 2_953_640_305), (SHARD_A, 4_163_431), (SHARD_B, 117_740_831)] {
        let cp = checkpoint(note);
        assert!(cp.origin.starts_with("rekor.sigstore.dev - "), "{}", cp.origin);
        assert_eq!(cp.size, size);

        // no change to the note goes unnoticed (a bit in every byte, the signature line included)
        for i in 0..note.len() {
            let mut t = note.as_bytes().to_vec();
            t[i] ^= 1;
            assert!(note::open(&t, &[rekor()]).is_err(), "{} byte {i}", cp.origin);
        }
    }
    // the log has been sharded: the three trees have three origins
    let origins: Vec<String> = [NEW, SHARD_A, SHARD_B].iter().map(|n| checkpoint(n).origin).collect();
    assert!(origins[0] != origins[1] && origins[1] != origins[2] && origins[0] != origins[2]);
    // a signature of one head is not one of another (same log, same key)
    let (a, b) = (checkpoint(NEW), checkpoint(OLD));
    assert_eq!(a.origin, b.origin);
    let spliced = format!("{}{}", &NEW[..NEW.rfind("\n\n").unwrap()], &OLD[OLD.rfind("\n\n").unwrap()..]);
    assert!(matches!(note::open(spliced.as_bytes(), &[rekor()]), Err(note::Error::InvalidSignature { .. })));
}

fn proof() -> Vec<Hash> {
    PROOF.lines().map(|l| unhex(l).try_into().unwrap()).collect()
}

#[test]
fn the_real_consistency_proof_from_the_older_head_to_the_current_one() {
    let (old, new) = (checkpoint(OLD), checkpoint(NEW));
    assert_eq!(old.origin, new.origin);
    let p = proof();
    assert_eq!(p.len(), 29);
    tlog::verify_consistency(&p, old.size, &old.root, new.size, &new.root).unwrap();

    // every hash, bit of the first byte and last byte, the roots, the sizes, the length: any change is refused
    for i in 0..p.len() {
        for byte in [0usize, 31] {
            let mut q = p.clone();
            q[i][byte] ^= 0x10;
            assert!(tlog::verify_consistency(&q, old.size, &old.root, new.size, &new.root).is_err(), "hash {i}");
        }
    }
    let mut r = old.root;
    r[7] ^= 1;
    assert!(tlog::verify_consistency(&p, old.size, &r, new.size, &new.root).is_err());
    let mut r = new.root;
    r[7] ^= 1;
    assert!(tlog::verify_consistency(&p, old.size, &old.root, new.size, &r).is_err());
    assert!(tlog::verify_consistency(&p, old.size + 1, &old.root, new.size, &new.root).is_err());
    // A proof does not pin the new size: the same 29 hashes verify for other new sizes that walk the same path
    // (the right-edge hashes are combined the same way whatever the higher bits of the size are). It is the signed
    // head that ties a size to its root, so a verifier must take the sizes from heads it has verified, as B-71 does.
    assert!(tlog::verify_consistency(&p, old.size, &old.root, new.size + 1, &new.root).is_ok());
    assert!(tlog::verify_consistency(&p[1..], old.size, &old.root, new.size, &new.root).is_err());
    assert!(tlog::verify_consistency(&p[..28], old.size, &old.root, new.size, &new.root).is_err());
    let mut longer = p.clone();
    longer.push([0; 32]);
    assert!(tlog::verify_consistency(&longer, old.size, &old.root, new.size, &new.root).is_err());
    // the other way round
    assert!(tlog::verify_consistency(&p, new.size, &new.root, old.size, &old.root).is_err());
}

#[test]
fn rekor_v2_checkpoint_has_an_ed25519_signature_and_witness_cosignatures() {
    let (name, spki_b64) = V2_KEY.trim().split_once('\n').unwrap();
    let spki = pem::base64_decode_strict(spki_b64).unwrap();
    assert_eq!(spki.len(), 44);
    assert_eq!(spki[..12], [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    let key: [u8; 32] = spki[12..].try_into().unwrap();
    let verifier = Verifier::ed25519(name, &key).unwrap();

    let opened = note::open(V2.as_bytes(), &[verifier.clone()]).unwrap();
    assert_eq!(opened.signatures.len(), 1);
    assert_eq!(opened.signatures[0].name, "log2025-1.rekor.sigstore.dev");
    // the three witnesses' cosignatures are kept aside: this key is not theirs
    let witnesses: Vec<&str> = opened.unverified.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(witnesses, ["staging.witness.transparency.goog/ring-any-bells", "witness.stagemole.eu", "witness.navigli.sunlight.geomys.org"]);
    let mut lines = opened.text.lines();
    assert_eq!(lines.next(), Some(name));
    assert_eq!(lines.next(), Some("139792683"));
    assert_eq!(lines.next(), Some("N3l8Cl0M364zobtnGGMUwFswMriGT7xefzOuB/wMBFA="));
    assert_eq!(lines.next(), None);

    // a change to the text or to the log's own signature is refused
    for i in 0..opened.text.len() {
        let mut m = V2.as_bytes().to_vec();
        m[i] ^= 1;
        assert!(note::open(&m, &[verifier.clone()]).is_err(), "byte {i}");
    }
    // the Rekor v1 key is not the v2 key
    let spki = rekor_key();
    assert_ne!(&spki[27..59], &key[..]);
}
