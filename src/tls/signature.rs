//! The TLS 1.3 CertificateVerify check, on top of the certificate's public key. It lives with the
//! TLS code because it speaks in TLS SignatureScheme code points; the verification itself is the
//! pure ECDSA, RSA-PSS and Ed25519 code.

use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::ed25519;
use crate::crypto::sha2::HashAlg;
use crate::error::{Error, Result};
use crate::x509::{Certificate, PublicKey};

/// Verifies a TLS 1.3 CertificateVerify signature made with the key of `cert` (`scheme` is the
/// SignatureScheme code point).
pub fn verify_tls13_signature(cert: &Certificate, scheme: u16, signed_content: &[u8], signature: &[u8]) -> Result<()> {
    let ok = match (scheme, &cert.public_key) {
        (0x0403, PublicKey::Ec { curve: Curve::P256, point }) => ecdsa::verify(Curve::P256, point, HashAlg::Sha256, signed_content, signature),
        (0x0503, PublicKey::Ec { curve: Curve::P384, point }) => ecdsa::verify(Curve::P384, point, HashAlg::Sha384, signed_content, signature),
        (0x0603, PublicKey::Ec { curve: Curve::P521, point }) => ecdsa::verify(Curve::P521, point, HashAlg::Sha512, signed_content, signature),
        (0x0807, PublicKey::Ed25519(k)) => ed25519::verify(k, signed_content, signature),
        (0x0804, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha256, signed_content, signature),
        (0x0805, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha384, signed_content, signature),
        (0x0806, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha512, signed_content, signature),
        // a scheme that does not go with the key is the peer's mistake, not a failed check (as OpenSSL answers it)
        _ => return Err(Error::Tls(format!("illegal_parameter: signature scheme {scheme:#06x} does not go with the certificate's key"))),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Tls("decrypt_error: the CertificateVerify signature is invalid".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem;
    use crate::util::unhex;

    fn cert(pem_text: &str) -> Certificate {
        Certificate::from_der(&pem::parse(pem_text).remove(0).data).unwrap()
    }

    /// (signed content, signature) made with the key of ed_leaf.pem; see tools/gen_ed25519_fixtures.py.
    fn signed() -> (Vec<u8>, Vec<u8>) {
        let text = include_str!("../../tests/data/ed_leaf_certverify.txt");
        let mut lines = text.lines().filter(|l| !l.starts_with('#'));
        (unhex(lines.next().unwrap()), unhex(lines.next().unwrap()))
    }

    #[test]
    fn ed25519_certificate_verify() {
        let leaf = cert(include_str!("../../tests/data/ed_leaf.pem"));
        let (content, sig) = signed();
        verify_tls13_signature(&leaf, 0x0807, &content, &sig).unwrap();
        // not with another scheme, not with a damaged signature or content, not with another key
        assert!(verify_tls13_signature(&leaf, 0x0403, &content, &sig).is_err());
        assert!(verify_tls13_signature(&leaf, 0x0804, &content, &sig).is_err());
        let mut bad = sig.clone();
        bad[10] ^= 4;
        assert!(verify_tls13_signature(&leaf, 0x0807, &content, &bad).is_err());
        let mut other = content.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(verify_tls13_signature(&leaf, 0x0807, &other, &sig).is_err());
        assert!(verify_tls13_signature(&leaf, 0x0807, &content, &sig[..63]).is_err());
        let p256 = cert(include_str!("../../tests/data/ed_leaf_p256.pem"));
        assert!(verify_tls13_signature(&p256, 0x0807, &content, &sig).is_err());
        let rsa = cert(include_str!("../../tests/data/leaf_rsa.pem"));
        assert!(verify_tls13_signature(&rsa, 0x0807, &content, &sig).is_err());
        // and a key that is Ed25519 does not take the ECDSA or RSA-PSS schemes
        for scheme in [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0807 + 1] {
            assert!(verify_tls13_signature(&leaf, scheme, &content, &sig).is_err(), "{scheme:#06x}");
        }
    }

    #[test]
    fn ed25519_is_advertised() {
        assert!(super::super::messages::SIGNATURE_SCHEMES.contains(&0x0807));
    }

    /// ecdsa_secp521r1_sha512 (B-33): the P-521 leaf of tools/gen_algorithm_fixtures.py signed CertificateVerify content.
    #[test]
    fn p521_certificate_verify() {
        let text = include_str!("../../tests/data/alg_p521_leaf_certverify.txt");
        let mut lines = text.lines().filter(|l| !l.starts_with('#')).map(unhex);
        let (content, sig, p256_point, p256_sig) = (lines.next().unwrap(), lines.next().unwrap(), lines.next().unwrap(), lines.next().unwrap());
        let leaf = cert(include_str!("../../tests/data/alg_p521_leaf.pem"));
        verify_tls13_signature(&leaf, 0x0603, &content, &sig).unwrap();
        // only with its own scheme (TLS 1.3 ties the curve to the scheme), and not when anything is changed
        for scheme in [0x0403, 0x0503, 0x0804, 0x0806, 0x0807, 0x0601, 0x0604] {
            assert!(verify_tls13_signature(&leaf, scheme, &content, &sig).is_err(), "{scheme:#06x}");
        }
        let mut bad = sig.clone();
        bad[20] ^= 1;
        assert!(verify_tls13_signature(&leaf, 0x0603, &content, &bad).is_err());
        let mut other = content.clone();
        other[70] ^= 1;
        assert!(verify_tls13_signature(&leaf, 0x0603, &other, &sig).is_err());
        // a P-256 key that signed with SHA-512 may not use the P-521 scheme in TLS 1.3 (its signature is real)
        assert!(ecdsa::verify(Curve::P256, &p256_point, HashAlg::Sha512, &content, &p256_sig));
        let mut p256_leaf = cert(include_str!("../../tests/data/ed_leaf_p256.pem"));
        p256_leaf.public_key = PublicKey::Ec { curve: Curve::P256, point: p256_point };
        assert!(verify_tls13_signature(&p256_leaf, 0x0603, &content, &p256_sig).is_err());
        assert!(super::super::messages::SIGNATURE_SCHEMES.contains(&0x0603));
    }
}
