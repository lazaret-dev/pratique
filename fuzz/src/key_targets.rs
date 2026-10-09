//! The fuzz target of private-key reading (B-109): `signing_key`.
//!
//! | target | what must hold |
//! |--------|----------------|
//! | `signing_key` | `SigningKey::from_pem` and `from_der` never panic on any input; a key that is read signs, and every signature it makes for each TLS scheme it offers verifies with the crate's verifiers under its own public key; an ECDSA or Ed25519 key written out as PKCS#8 (DER and PEM) reads back as the same key |
//!
//! The first byte chooses how the rest is read: 0 as PEM text, 1 as DER (any format), 2 as PKCS#8, 3 as SEC 1.

use pratique::crypto::ecdsa::{self, Curve};
use pratique::crypto::{ed25519, sha2::HashAlg};
use pratique::sign::{scheme, SigningKey};
use pratique::util::unhex;
use pratique::x509::{parse_spki, PublicKey};

const KEYS: &str = include_str!("../../tests/data/signing_key_formats.txt");

pub const KEY_DICT: &[&[u8]] = &[
    b"-----BEGIN PRIVATE KEY-----\n",
    b"-----END PRIVATE KEY-----\n",
    b"-----BEGIN EC PRIVATE KEY-----\n",
    b"-----END EC PRIVATE KEY-----\n",
    b"-----BEGIN RSA PRIVATE KEY-----\n",
    b"-----END RSA PRIVATE KEY-----\n",
    b"Proc-Type: 4,ENCRYPTED\n",
    b"\x06\x03\x2b\x65\x70",
    b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01",
    b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
    b"\x06\x05\x2b\x81\x04\x00\x22",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
    b"\x02\x01\x00",
    b"\x02\x01\x01",
    b"\x04\x20",
    b"\xa0\x0a",
    b"\xa1\x44\x03\x42\x00\x04",
];

pub fn seeds_signing_key() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for line in KEYS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        let (label, der) = (f[1].replace('_', " "), unhex(f[2]));
        let b64 = pratique::pem::base64_encode(&der);
        let mut text = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            text.push_str(std::str::from_utf8(chunk).unwrap());
            text.push('\n');
        }
        text.push_str(&format!("-----END {label}-----\n"));
        out.push([&[0u8][..], text.as_bytes()].concat());
        out.push([&[1u8][..], &der].concat());
        if label == "PRIVATE KEY" {
            out.push([&[2u8][..], &der].concat());
        }
        if label == "EC PRIVATE KEY" {
            out.push([&[3u8][..], &der].concat());
        }
    }
    out
}

pub fn signing_key(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else { return };
    let key = match selector % 4 {
        0 => SigningKey::from_pem(&String::from_utf8_lossy(rest)),
        1 => SigningKey::from_der(rest),
        2 => SigningKey::from_pkcs8_der(rest),
        _ => SigningKey::from_sec1_der(rest, None),
    };
    let Ok(key) = key else { return };
    let spki = key.public_key_spki();
    let public = parse_spki(&spki).expect("a key's own SubjectPublicKeyInfo parses");
    let message = b"pratique fuzz: a message to sign";
    for s in key.tls_schemes() {
        let sig = key.sign_tls(s, message).expect("a key signs with a scheme it offers");
        let ok = match (&public, s) {
            (PublicKey::Ec { curve: Curve::P256, point }, scheme::ECDSA_SECP256R1_SHA256) => ecdsa::verify_prehashed(Curve::P256, point, &HashAlg::Sha256.digest(message), &sig),
            (PublicKey::Ec { curve: Curve::P384, point }, scheme::ECDSA_SECP384R1_SHA384) => ecdsa::verify_prehashed(Curve::P384, point, &HashAlg::Sha384.digest(message), &sig),
            (PublicKey::Ed25519(k), scheme::ED25519) => ed25519::verify(k, message, &sig),
            (PublicKey::Rsa(k), scheme::RSA_PSS_RSAE_SHA256) => k.verify_pss(HashAlg::Sha256, message, &sig),
            (PublicKey::Rsa(k), scheme::RSA_PSS_RSAE_SHA384) => k.verify_pss(HashAlg::Sha384, message, &sig),
            (PublicKey::Rsa(k), scheme::RSA_PSS_RSAE_SHA512) => k.verify_pss(HashAlg::Sha512, message, &sig),
            _ => panic!("scheme {s:#06x} offered by a {} key", key.algorithm()),
        };
        assert!(ok, "a {} signature (scheme {s:#06x}) does not verify under the key's own public key", key.algorithm());
    }
    if let Ok(der) = key.to_pkcs8_der() {
        assert_eq!(SigningKey::from_der(&der).expect("our own PKCS#8 reads").public_key_spki(), spki);
        let pem = key.to_pkcs8_pem().unwrap();
        assert_eq!(SigningKey::from_pem(std::str::from_utf8(&pem).unwrap()).expect("our own PEM reads").public_key_spki(), spki);
    }
}
