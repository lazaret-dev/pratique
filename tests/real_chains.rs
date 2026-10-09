//! Replays certificate chains that were captured from real servers (BACKLOG B-08).
//!
//! `tools/mac_field_check.sh capture` fetches the chains with OpenSSL (not with this library, so that a bug here cannot
//! also have shaped the data), verifies each with the library at the moment it was captured, and writes
//! `real_chains/`: `fixtures.tsv`, `chains/NAME.pem` (the chain as the server sent it) and `anchors/NAME.pem` (the trust
//! anchor the path ended in). Copy that directory to `tests/data/real_chains/` and this test replays it on any machine, at
//! the recorded time, so a certificate that has expired since still counts. Without the directory every test here passes
//! by saying it skipped (the sandbox the library was written in has no way to reach real servers).
//!
//! Each fixture has an expectation:
//!
//! * `ok`: the chain verifies for the host at the recorded time against a store that holds only its anchor, through both
//!   entry points; and every alteration of it (another host name, a second outside the validity, a flipped bit in the
//!   signature or in the body of the leaf, the intermediates left out, the wrong anchor) is refused, while a different
//!   order of the intermediates or a repeated one is not a reason to refuse;
//! * `refuse-time`, `refuse-host`, `refuse-path`: a real chain that must be refused (expired; for another name; to a root
//!   nobody trusts or self-signed), refused here against the anchors of all the other fixtures, and where the reason is the
//!   time or the host name, accepted when that is put right (so that it was that, and nothing else, that was refused).
//!
//! `PRATIQUE_REAL_CHAINS=DIR` replays another directory.

use std::path::{Path, PathBuf};
use pratique::pem;
use pratique::x509::{Certificate, TrustStore, VerifyOptions};

struct Fixture {
    name: String,
    host: String,
    time: i64,
    expect: String,
    chain: Vec<Vec<u8>>,
    anchor: Option<Vec<u8>>,
}

fn dir() -> PathBuf {
    match std::env::var_os("PRATIQUE_REAL_CHAINS") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/real_chains"),
    }
}

fn certs_in(path: &Path) -> Vec<Vec<u8>> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect()
}

/// The fixtures, or none if there is no directory of them.
fn load() -> Vec<Fixture> {
    let dir = dir();
    let Ok(text) = std::fs::read_to_string(dir.join("fixtures.tsv")) else {
        eprintln!("skipped: no {}/fixtures.tsv (see the header of tests/real_chains.rs)", dir.display());
        return Vec::new();
    };
    let mut fixtures = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let c: Vec<&str> = line.split('\t').collect();
        assert!(c.len() >= 5, "fixtures.tsv: a line with fewer than 5 columns: {line}");
        let chain = certs_in(&dir.join("chains").join(format!("{}.pem", c[0])));
        assert!(!chain.is_empty(), "{}: the chain file holds no certificate", c[0]);
        let anchor = (c[4] != "-").then(|| {
            let mut v = certs_in(&dir.join(c[4]));
            assert_eq!(v.len(), 1, "{}: an anchor file holds exactly one certificate", c[0]);
            v.remove(0)
        });
        fixtures.push(Fixture {
            name: c[0].to_string(),
            host: c[1].to_string(),
            time: c[2].parse().unwrap_or_else(|_| panic!("{}: bad time {}", c[0], c[2])),
            expect: c[3].to_string(),
            chain,
            anchor,
        });
    }
    fixtures
}

fn store_of(anchors: &[&[u8]]) -> TrustStore {
    let mut store = TrustStore::empty();
    for a in anchors {
        store.add_der(a).expect("an anchor of the fixtures parses");
    }
    store
}

fn accepts(store: &TrustStore, chain: &[Vec<u8>], host: &str, time: i64) -> bool {
    store.verify_chain(chain, &VerifyOptions::tls_server(host, time)).is_ok()
}

fn a_name_of(leaf: &Certificate) -> Option<String> {
    leaf.dns_names.first().map(|n| n.strip_prefix("*.").map_or(n.clone(), |rest| format!("www.{rest}")))
}

#[test]
fn every_real_chain_verifies_at_the_time_it_was_captured() {
    let fixtures = load();
    let mut checked = 0;
    for f in fixtures.iter().filter(|f| f.expect == "ok") {
        let anchor = f.anchor.as_ref().unwrap_or_else(|| panic!("{}: an ok fixture without an anchor", f.name));
        let store = store_of(&[anchor]);
        let v = store
            .verify_chain(&f.chain, &VerifyOptions::tls_server(&f.host, f.time))
            .unwrap_or_else(|e| panic!("{} ({}) at {}: {e}", f.name, f.host, f.time));
        assert_eq!(v.anchor(), anchor.as_slice(), "{}: the path ends in the anchor of the fixture", f.name);
        assert!(v.path.len() >= 2, "{}: a path holds the leaf and the anchor at least", f.name);
        assert_eq!(v.path[0], f.chain[0], "{}: the path starts with the leaf that was sent", f.name);
        assert_eq!(v.leaf.der, f.chain[0]);
        // the other entry point (the one the TLS client uses) says the same
        let leaf = store.verify_server_chain(&f.chain, &f.host, f.time).unwrap_or_else(|e| panic!("{}: verify_server_chain: {e}", f.name));
        assert_eq!(leaf.der, f.chain[0]);
        assert!(leaf.matches_hostname(&f.host), "{}: the leaf names the host", f.name);
        checked += 1;
    }
    eprintln!("{checked} real chains verified at their capture times");
}

#[test]
fn an_altered_real_chain_is_refused() {
    let fixtures = load();
    for f in fixtures.iter().filter(|f| f.expect == "ok") {
        let anchor = f.anchor.as_ref().expect("an anchor");
        let store = store_of(&[anchor]);
        let leaf = Certificate::from_der(&f.chain[0]).unwrap();
        assert!(!accepts(&store, &f.chain, &format!("{}.invalid", f.host), f.time), "{}: another host name", f.name);
        assert!(!accepts(&store, &f.chain, &f.host, leaf.not_after + 1), "{}: one second after the leaf expires", f.name);
        assert!(!accepts(&store, &f.chain, &f.host, leaf.not_before - 1), "{}: one second before the leaf is valid", f.name);
        for at in [f.chain[0].len() - 1, f.chain[0].len() - 40, f.chain[0].len() / 2, f.chain[0].len() / 4] {
            let mut altered = f.chain.clone();
            altered[0][at] ^= 0x01;
            assert!(!accepts(&store, &altered, &f.host, f.time), "{}: a flipped bit at byte {at} of {} in the leaf", f.name, f.chain[0].len());
        }
        // an intermediate with a flipped bit in its signature cannot carry the path (unless the leaf is signed by the anchor itself)
        if f.chain.len() > 1 {
            let mut altered = f.chain.clone();
            let last = altered[1].len() - 1;
            altered[1][last] ^= 0x01;
            let v = store.verify_chain(&f.chain, &VerifyOptions::tls_server(&f.host, f.time)).unwrap();
            if v.path.len() > 2 && v.path[1] == f.chain[1] {
                assert!(!accepts(&store, &altered, &f.host, f.time), "{}: an intermediate with a flipped bit in its signature", f.name);
            }
        }
    }
}

#[test]
fn a_real_chain_needs_its_intermediates_and_does_not_mind_their_order() {
    let fixtures = load();
    for f in fixtures.iter().filter(|f| f.expect == "ok") {
        let anchor = f.anchor.as_ref().expect("an anchor");
        let store = store_of(&[anchor]);
        let v = store.verify_chain(&f.chain, &VerifyOptions::tls_server(&f.host, f.time)).unwrap();
        let intermediates_needed = v.path.len() > 2;
        // the leaf alone: a path that needs an intermediate is not found, and this library does not go and fetch one
        if intermediates_needed {
            assert!(!accepts(&store, &f.chain[..1], &f.host, f.time), "{}: the leaf alone reaches an anchor that is two or more certificates away", f.name);
        }
        // any order, and a repeated certificate
        let mut reversed: Vec<Vec<u8>> = vec![f.chain[0].clone()];
        reversed.extend(f.chain[1..].iter().rev().cloned());
        assert!(accepts(&store, &reversed, &f.host, f.time), "{}: the intermediates in the reverse order", f.name);
        let mut twice = f.chain.clone();
        twice.extend(f.chain[1..].iter().cloned());
        assert!(accepts(&store, &twice, &f.host, f.time), "{}: the intermediates sent twice", f.name);
        // the anchor sent along with the chain is not the same as the store having it
        let mut with_anchor = f.chain.clone();
        with_anchor.push(anchor.clone());
        assert!(accepts(&store, &with_anchor, &f.host, f.time), "{}: the anchor sent too", f.name);
        let empty = TrustStore::empty();
        assert!(!accepts(&empty, &with_anchor, &f.host, f.time), "{}: a chain that carries its own anchor is not trusted for that", f.name);
    }
}

#[test]
fn a_real_chain_is_refused_under_the_anchors_of_the_others() {
    let fixtures = load();
    for f in fixtures.iter().filter(|f| f.expect == "ok") {
        let own = f.anchor.as_ref().expect("an anchor");
        let own_subject = Certificate::from_der(own).unwrap().subject_der;
        // The root a server's last certificate points at is not "somebody else's" even when it is not the one the capture ended at:
        // servers send cross-signed roots (the real chains of Google's hosts send GTS Root R1 as signed by GlobalSign Root CA, so
        // GlobalSign's root alone is a second, legitimate way to the same host). Roots that any certificate of the chain names as
        // its issuer are left out; what is left has nothing to do with the chain.
        let issuers: Vec<Vec<u8>> = f.chain.iter().map(|c| Certificate::from_der(c).unwrap().issuer_der).collect();
        let others: Vec<&[u8]> = fixtures
            .iter()
            .filter_map(|g| g.anchor.as_deref())
            .filter(|a| Certificate::from_der(a).map(|c| c.subject_der != own_subject && !issuers.contains(&c.subject_der)).unwrap_or(false))
            .collect();
        if others.is_empty() {
            continue;
        }
        assert!(!accepts(&store_of(&others), &f.chain, &f.host, f.time), "{}: accepted under anchors that are not its own", f.name);
    }
}

#[test]
fn a_real_chain_that_must_be_refused_stays_refused_for_the_reason_it_was() {
    let fixtures = load();
    let all: Vec<&[u8]> = fixtures.iter().filter_map(|g| g.anchor.as_deref()).collect();
    let everyone = store_of(&all);
    for f in fixtures.iter().filter(|f| f.expect.starts_with("refuse")) {
        assert!(!accepts(&everyone, &f.chain, &f.host, f.time), "{} ({}): accepted, and it must be refused", f.name, f.expect);
        let leaf = Certificate::from_der(&f.chain[0]).unwrap();
        match (f.expect.as_str(), &f.anchor) {
            ("refuse-time", Some(anchor)) => {
                let store = store_of(&[anchor]);
                let middle = (leaf.not_before + leaf.not_after) / 2;
                assert!(accepts(&store, &f.chain, &f.host, middle), "{}: refused for its time, so it must be accepted in the middle of its validity", f.name);
                assert!(!accepts(&store, &f.chain, &f.host, f.time), "{}: refused at the capture time", f.name);
            }
            ("refuse-host", Some(anchor)) => {
                let store = store_of(&[anchor]);
                let name = a_name_of(&leaf).expect("a leaf that is refused for its host name names another");
                assert!(accepts(&store, &f.chain, &name, f.time), "{}: refused for its host name, so it must be accepted for {name}", f.name);
                assert!(!accepts(&store, &f.chain, &f.host, f.time), "{}: refused for {}", f.name, f.host);
            }
            ("refuse-path", _) => {}
            (other, _) => panic!("{}: unknown expectation {other} (or no anchor to check it against)", f.name),
        }
    }
}

#[test]
fn the_fixtures_say_what_they_cover() {
    let fixtures = load();
    if fixtures.is_empty() {
        return;
    }
    let ok = fixtures.iter().filter(|f| f.expect == "ok").count();
    let (mut rsa, mut ec) = (0, 0);
    let mut lengths = std::collections::BTreeMap::new();
    for f in fixtures.iter().filter(|f| f.expect == "ok") {
        match Certificate::from_der(&f.chain[0]).unwrap().public_key {
            pratique::x509::PublicKey::Rsa(_) => rsa += 1,
            pratique::x509::PublicKey::Ec { .. } => ec += 1,
            _ => {}
        }
        *lengths.entry(f.chain.len()).or_insert(0) += 1;
    }
    eprintln!("{ok} chains that verify (leaf keys: RSA {rsa}, EC {ec}; certificates sent: {lengths:?}), {} that are refused", fixtures.len() - ok);
}
