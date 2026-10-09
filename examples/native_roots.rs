//! What the operating system's own store of roots holds (BACKLOG B-101), as `pratique::native_roots` reads it: the roots
//! it trusts for TLS servers, those it leaves out and why, and how that compares with a CA bundle file.
//!
//! ```text
//! cargo run --example native_roots -- [--compare FILE] [--pem OUT]
//! ```
//!
//! `--compare FILE` lists the roots that are in one and not the other (a PEM bundle, such as macOS's `/etc/ssl/cert.pem`, or
//! what `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain` prints). `--pem OUT`
//! writes the trusted roots as a PEM bundle. The exit status is 1 if the store could not be read or has no root.

use std::collections::BTreeSet;
use pratique::native_roots::native_roots;
use pratique::x509::Certificate;

fn name(der: &[u8]) -> String {
    Certificate::from_der(der).map(|c| c.subject_summary()).unwrap_or_else(|_| "(does not parse)".to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let option = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let mut roots = match native_roots() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("native store: {e}");
            std::process::exit(1);
        }
    };
    let store = roots.trust_store();
    println!("native store: {} roots trusted for TLS servers, {} left out", store.len(), roots.excluded.len());
    for (der, why) in &roots.excluded {
        println!("  left out: [{}]: {why}", name(der));
    }
    if let Some(path) = option("--pem") {
        let mut out = String::new();
        for der in &roots.trusted {
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            for line in pratique::pem::base64_encode(der).as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(line).unwrap_or(""));
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
        }
        if let Err(e) = std::fs::write(&path, out) {
            eprintln!("cannot write {path}: {e}");
            std::process::exit(1);
        }
        println!("wrote {} roots to {path}", roots.trusted.len());
    }
    if let Some(path) = option("--compare") {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot read {path}: {e}");
                std::process::exit(1);
            }
        };
        let file: BTreeSet<Vec<u8>> = pratique::pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect();
        let native: BTreeSet<Vec<u8>> = roots.trusted.iter().cloned().collect();
        let excluded: BTreeSet<Vec<u8>> = roots.excluded.iter().map(|(d, _)| d.clone()).collect();
        println!("compared with {path} ({} certificates): {} in both", file.len(), file.intersection(&native).count());
        for der in native.difference(&file) {
            println!("  only in the native store: [{}]", name(der));
        }
        for der in file.difference(&native) {
            let note = if excluded.contains(der) { " (the native store has it and leaves it out)" } else { "" };
            println!("  only in {path}: [{}]{note}", name(der));
        }
    }
    if store.is_empty() {
        std::process::exit(1);
    }
}
