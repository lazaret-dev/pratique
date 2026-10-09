//! Parses every root certificate in the system CA bundle and verifies each self-signature with our
//! own RSA/ECDSA code. Real roots exercise many certificate shapes (RSA 2048/3072/4096, P-256/P-384,
//! assorted extensions and name encodings) that the synthetic fixtures do not.

use std::path::Path;
use pratique::pem;
use pratique::x509::{Certificate, PublicKey};

fn bundle_paths() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        v.push(p);
    }
    for p in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"] {
        v.push(p.to_string());
    }
    v
}

#[test]
fn real_world_roots_parse_and_self_verify() {
    let mut total_checked = 0;
    for path in bundle_paths().into_iter().filter(|p| Path::new(p).exists()) {
        let text = std::fs::read_to_string(&path).unwrap();
        let (mut blocks, mut parsed, mut rsa, mut ec, mut ed, mut other_key) = (0, 0, 0, 0, 0, 0);
        let (mut verified, mut unsupported_sig, mut failed) = (0, 0, Vec::new());
        for block in pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE") {
            blocks += 1;
            let Ok(cert) = Certificate::from_der(&block.data) else { continue };
            parsed += 1;
            match cert.public_key {
                PublicKey::Rsa(_) => rsa += 1,
                PublicKey::Ec { .. } => ec += 1,
                PublicKey::Ed25519(_) => ed += 1,
                _ => {
                    other_key += 1;
                    continue;
                }
            }
            if !cert.is_self_issued() {
                continue; // cross-signed or proxy-issued entries cannot be checked against themselves
            }
            match cert.verify_signed_by(&cert) {
                Ok(()) => verified += 1,
                Err(e) if e.to_string().contains("unsupported certificate signature algorithm") => unsupported_sig += 1,
                Err(e) => failed.push(format!("{:?}: {}", cert, e)),
            }
        }
        eprintln!(
            "{}: {} certs, {} parsed (RSA {}, EC {}, Ed25519 {}, other-key {}), self-signatures verified {}, unsupported alg {}, FAILED {}",
            path, blocks, parsed, rsa, ec, ed, other_key, verified, unsupported_sig, failed.len()
        );
        assert!(failed.is_empty(), "self-signature failures (these are bugs, the signatures are genuine):\n{}", failed.join("\n"));
        assert!(parsed * 10 >= blocks * 9, "fewer than 90% of real certificates parsed");
        total_checked += verified;
    }
    if total_checked == 0 {
        eprintln!("no system CA bundle found; nothing was checked");
    }
}
