//! The built-in Mozilla root store (feature `mozilla-roots`, BACKLOG B-31): every root is there as NSS lists it, parses,
//! and signed itself where the algorithm allows checking; the roots the field run missed are in it; the real chains
//! that verified on the Mac (`tests/data/real_chains/`) verify against it alone, at the time they were captured; a
//! root's distrust date applies to leaves issued after it; and the name constraints NSS imposes on a root are carried.
//!
//! `cargo test --features mozilla-roots --test mozilla_roots`

use std::collections::BTreeMap;
use pratique::crypto::sha2::HashAlg;
use pratique::mozilla_roots::{roots, trust_store, version};
use pratique::pem;
use pratique::x509::{Certificate, TrustStore, VerifyOptions};

#[test]
fn every_root_is_there_parses_and_signed_itself() {
    let all = roots();
    let text = include_str!("../roots/mozilla.pem");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# roots: ")).unwrap().parse().unwrap();
    assert_eq!(all.len(), declared);
    assert!(all.len() > 100, "{}", all.len());
    assert!(version().starts_with("2."), "{}", version());
    // the hash line above each certificate is the certificate's
    let hashes: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("# sha256: ")).collect();
    assert_eq!(hashes.len(), all.len());
    let (mut verified, mut skipped) = (0, Vec::new());
    for (root, hash) in all.iter().zip(&hashes) {
        let got: String = HashAlg::Sha256.digest(&root.der).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(&got, hash, "{}", root.label);
        assert!(!root.label.is_empty());
        let cert = Certificate::from_der(&root.der).unwrap_or_else(|e| panic!("{}: {e}", root.label));
        assert!(cert.is_ca, "{}", root.label);
        match cert.verify_signed_by(&cert) {
            Ok(()) => verified += 1,
            // SHA-1 self-signatures are refused on purpose; an anchor's own signature is never checked in a chain
            Err(e) if e.to_string().contains("unsupported certificate signature algorithm") => skipped.push(root.label.clone()),
            Err(e) => panic!("{}: {e}", root.label),
        }
    }
    assert!(verified + skipped.len() == all.len() && skipped.len() < 10, "{skipped:?}");
    assert_eq!(trust_store().len(), all.len());
    eprintln!("NSS builtins {}: {} roots, {verified} self-signatures verified, {} with SHA-1 ({skipped:?})", version(), all.len(), skipped.len());
}

#[test]
fn the_roots_the_field_run_needed_are_in_it() {
    let labels: Vec<String> = roots().into_iter().map(|r| r.label).collect();
    // ISRG Root X2 was missing from macOS's /etc/ssl/cert.pem (B-97); e-Szigno TLS Root CA 2023 is the P-521 root (B-33)
    for want in ["ISRG Root X1", "ISRG Root X2", "e-Szigno TLS Root CA 2023", "DigiCert Global Root G2", "GTS Root R1"] {
        assert!(labels.iter().any(|l| l == want), "{want} is not in the store: {labels:?}");
    }
    // distrust dates are carried: every one that the file states is on its root
    let dated: Vec<_> = roots().into_iter().filter(|r| r.distrust_tls_after.is_some()).collect();
    let stated = include_str!("../roots/mozilla.pem").lines().filter(|l| l.starts_with("# distrust-tls-after: ")).count();
    assert_eq!(dated.len(), stated);
    // and so are the name constraints NSS imposes in code: the Turkish government root is for .tr names only
    let constrained: Vec<_> = roots().into_iter().filter(|r| r.name_constraints.is_some()).collect();
    let stated = include_str!("../roots/mozilla.pem").lines().filter(|l| l.starts_with("# name-constraints: ")).count();
    assert_eq!(constrained.len(), stated);
    let tubitak = roots().into_iter().find(|r| r.label == "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1").expect("in NSS 2.90");
    assert_eq!(tubitak.name_constraints.as_deref(), Some(&[0x30, 0x09, 0xa0, 0x07, 0x30, 0x05, 0x82, 0x03, b'.', b't', b'r'][..]));
}

/// The real chains captured on the Mac (B-08, B-97) that verified there verify against the built-in store alone.
#[test]
fn the_real_chains_verify_against_it() {
    let store = trust_store();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/real_chains");
    let index = std::fs::read_to_string(format!("{dir}/fixtures.tsv")).unwrap();
    let mut anchors: BTreeMap<String, usize> = BTreeMap::new();
    let mut checked = 0;
    for line in index.lines().filter(|l| !l.starts_with('#')) {
        let c: Vec<&str> = line.split('\t').collect();
        if c[3] != "ok" {
            continue;
        }
        let chain: Vec<Vec<u8>> = pem::parse(&std::fs::read_to_string(format!("{dir}/chains/{}.pem", c[0])).unwrap()).into_iter().map(|b| b.data).collect();
        let time: i64 = c[2].parse().unwrap();
        let v = store.verify_chain(&chain, &VerifyOptions::tls_server(c[1], time)).unwrap_or_else(|e| panic!("{}: {e}", c[0]));
        *anchors.entry(Certificate::from_der(v.anchor()).unwrap().subject_summary()).or_insert(0) += 1;
        checked += 1;
    }
    // every chain that verified on the Mac (55 from the field run of 2026-10-08), none left out
    assert_eq!(checked, index.lines().filter(|l| l.split('\t').nth(3) == Some("ok")).count());
    assert!(checked >= 47, "{checked}");
    eprintln!("{checked} real chains verified, anchors: {anchors:?}");
}

/// A distrust date refuses the leaves issued after it, and only those (the rule is the trust store's; the Mozilla store
/// gives it the dates).
#[test]
fn a_distrust_date_refuses_leaves_issued_after_it() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/real_chains");
    let index = std::fs::read_to_string(format!("{dir}/fixtures.tsv")).unwrap();
    let line = index.lines().find(|l| l.starts_with("crates.io\t")).unwrap();
    let c: Vec<&str> = line.split('\t').collect();
    let chain: Vec<Vec<u8>> = pem::parse(&std::fs::read_to_string(format!("{dir}/chains/{}.pem", c[0])).unwrap()).into_iter().map(|b| b.data).collect();
    let anchor = pem::parse(&std::fs::read_to_string(format!("{dir}/{}", c[4])).unwrap()).remove(0).data;
    let time: i64 = c[2].parse().unwrap();
    let issued = Certificate::from_der(&chain[0]).unwrap().not_before;
    for (after, ok) in [(issued, true), (issued - 1, false), (i64::MAX, true), (0, false)] {
        let mut store = TrustStore::empty();
        store.add_der_distrusted_after(&anchor, after).unwrap();
        let r = store.verify_chain(&chain, &VerifyOptions::tls_server(c[1], time));
        assert_eq!(r.is_ok(), ok, "distrusted after {after}, issued {issued}: {:?}", r.err());
        if !ok {
            let e = r.err().unwrap().to_string();
            assert!(e.contains("after the date") && e.contains("from which certificates are not trusted under the root"), "{e}");
        }
    }
    // an anchor without a date is not affected, and the same anchor added both ways is found without the date
    let mut store = TrustStore::empty();
    store.add_der_distrusted_after(&anchor, 0).unwrap();
    store.add_der(&anchor).unwrap();
    store.verify_chain(&chain, &VerifyOptions::tls_server(c[1], time)).unwrap();
}
