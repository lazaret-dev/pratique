//! Certificates with their private keys: which chain and key a server's handshake gets, and the one a client
//! presents when a server asks for it (B-110).
//!
//! A [`CertifiedKey`] is a chain (leaf first) with the leaf's private key and, optionally, an OCSP response to staple.
//! A [`ResolvesServerCert`] picks one for each ClientHello; [`CertStore`], the default, holds any number and picks by
//!
//! 1. the name the client asked for (`server_name`): a certificate whose names match it exactly before one whose
//!    wildcard does; with no name, or a name none matches, the first certificate (the default) unless the store is
//!    strict, in which case the handshake fails with `unrecognized_name`;
//! 2. the signatures the client can verify: the leaf's key must be able to sign in one of the client's
//!    `signature_algorithms` (an ECDSA certificate for a client that only takes RSA-PSS, say, is passed over);
//! 3. among those left, one whose chain the client says it can check (`signature_algorithms_cert`, or
//!    `signature_algorithms` when that is absent), then the order the certificates were added in.
//!
//! The store can be changed while the server runs ([`CertStore::replace`], [`CertStore::set_ocsp_staple`]): a new
//! certificate from ACME, a refreshed staple. A handshake under way keeps what it picked. The scanning proxy (B-78)
//! brings a resolver of its own that makes a certificate for each host.

use crate::error::{Error, Result};
use crate::sign::{scheme, SigningKey};
use crate::x509::{dns_pattern_matches, Certificate, SigAlg};
use crate::crypto::sha2::HashAlg;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// A certificate chain with the private key of its leaf: what a server presents, or a client asked for a certificate
/// (`ClientConfig::with_client_certificate`).
#[derive(Clone)]
pub struct CertifiedKey {
    chain: Vec<Vec<u8>>,
    key: SigningKey,
    ocsp_staple: Option<Vec<u8>>,
    /// the leaf's DNS names (lower case) and IP addresses
    dns_names: Vec<String>,
    ip_addrs: Vec<Vec<u8>>,
    /// the TLS signature schemes of the signatures in the chain, below its top (a self-signed top is not checked by
    /// clients)
    chain_schemes: Vec<u16>,
    not_after: i64,
}

impl std::fmt::Debug for CertifiedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertifiedKey({:?}, {}, {} certificates)", self.dns_names, self.key.algorithm(), self.chain.len())
    }
}

/// The TLS SignatureScheme that stands for a certificate's signature algorithm, as `signature_algorithms_cert` names
/// them (an ECDSA signature by its hash: the curve is the issuer's, which the scheme names only loosely).
fn scheme_of(alg: SigAlg) -> Option<u16> {
    #[allow(unreachable_patterns)] // SigAlg may gain variants
    Some(match alg {
        SigAlg::RsaPkcs1(HashAlg::Sha256) => 0x0401,
        SigAlg::RsaPkcs1(HashAlg::Sha384) => 0x0501,
        SigAlg::RsaPkcs1(HashAlg::Sha512) => 0x0601,
        SigAlg::RsaPss(HashAlg::Sha256) => scheme::RSA_PSS_RSAE_SHA256,
        SigAlg::RsaPss(HashAlg::Sha384) => scheme::RSA_PSS_RSAE_SHA384,
        SigAlg::RsaPss(HashAlg::Sha512) => scheme::RSA_PSS_RSAE_SHA512,
        SigAlg::Ecdsa(HashAlg::Sha256) => scheme::ECDSA_SECP256R1_SHA256,
        SigAlg::Ecdsa(HashAlg::Sha384) => scheme::ECDSA_SECP384R1_SHA384,
        SigAlg::Ecdsa(HashAlg::Sha512) => 0x0603,
        SigAlg::Ed25519 => scheme::ED25519,
        _ => return None,
    })
}

impl CertifiedKey {
    /// The chain (DER, leaf first) and the leaf's key. Refused if the chain is empty, a certificate does not parse, or
    /// the key is not the leaf's.
    pub fn new(chain: Vec<Vec<u8>>, key: SigningKey) -> Result<CertifiedKey> {
        let Some(leaf_der) = chain.first() else {
            return Err(Error::Key("an empty certificate chain".into()));
        };
        if !key.matches_certificate(leaf_der)? {
            return Err(Error::Key(format!("the {} private key is not the key of the first certificate in the chain", key.algorithm())));
        }
        Self::build(chain, key)
    }

    /// As [`new`](Self::new), without checking that the key is the leaf's (for tests that want a server that signs
    /// with the wrong key).
    pub fn new_unchecked(chain: Vec<Vec<u8>>, key: SigningKey) -> Result<CertifiedKey> {
        if chain.is_empty() {
            return Err(Error::Key("an empty certificate chain".into()));
        }
        Self::build(chain, key)
    }

    fn build(chain: Vec<Vec<u8>>, key: SigningKey) -> Result<CertifiedKey> {
        let certs = chain.iter().map(|d| Certificate::from_der(d)).collect::<std::result::Result<Vec<_>, _>>()?;
        let leaf = &certs[0];
        let chain_schemes = certs
            .iter()
            .filter(|c| c.issuer_der != c.subject_der)
            .filter_map(|c| c.signature_algorithm().and_then(scheme_of))
            .collect();
        Ok(CertifiedKey {
            dns_names: leaf.dns_names.iter().map(|n| n.to_ascii_lowercase()).collect(),
            ip_addrs: leaf.ip_addrs.clone(),
            not_after: leaf.not_after,
            chain_schemes,
            chain,
            key,
            ocsp_staple: None,
        })
    }

    /// A CA's "fullchain" PEM (the leaf first, then the intermediates) and the leaf's private key in PEM (see
    /// [`SigningKey::from_pem`]).
    pub fn from_pem(chain_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
        let chain: Vec<Vec<u8>> = crate::pem::parse(chain_pem).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect();
        if chain.is_empty() {
            return Err(Error::Key("no CERTIFICATE block in the certificate chain's PEM".into()));
        }
        CertifiedKey::new(chain, SigningKey::from_pem(key_pem)?)
    }

    /// The same with an OCSP response (DER) to staple for clients that ask (`status_request`).
    pub fn with_ocsp_staple(mut self, response: Vec<u8>) -> CertifiedKey {
        self.ocsp_staple = Some(response);
        self
    }

    pub fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    pub fn ocsp_staple(&self) -> Option<&[u8]> {
        self.ocsp_staple.as_deref()
    }

    /// The leaf's DNS names, lower case.
    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    /// When the leaf expires (Unix seconds).
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// 2 if a name of the leaf is exactly `name` (or the IP address it spells), 1 if a wildcard covers it, 0 if neither.
    pub fn name_match(&self, name: &str) -> u8 {
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        if let Ok(ip) = name.parse::<IpAddr>() {
            let octets = match ip {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            return if self.ip_addrs.contains(&octets) { 2 } else { 0 };
        }
        if self.dns_names.iter().any(|n| *n == name) {
            2
        } else if self.dns_names.iter().any(|n| n.starts_with("*.") && dns_pattern_matches(n, &name)) {
            1
        } else {
            0
        }
    }
}

/// What a resolver is told about the ClientHello.
#[derive(Debug)]
pub struct ClientHelloInfo<'a> {
    /// The `server_name` the client sent, if any.
    pub server_name: Option<&'a str>,
    /// The signature schemes the client takes for the handshake (`signature_algorithms`).
    pub signature_schemes: &'a [u16],
    /// The ones it takes in certificates (`signature_algorithms_cert`), if it sent the extension.
    pub signature_schemes_cert: Option<&'a [u16]>,
    /// The ALPN protocols it offered.
    pub alpn: Option<&'a [Vec<u8>]>,
}

/// Picks the certificate for a handshake. `None` ends the handshake: with `unrecognized_name` when the client named a
/// host, `handshake_failure` otherwise.
pub trait ResolvesServerCert: Send + Sync {
    fn resolve(&self, hello: &ClientHelloInfo) -> Option<Arc<CertifiedKey>>;
}

/// The default resolver: a list of certificates, chosen as the module documentation says.
#[derive(Default)]
pub struct CertStore {
    certs: RwLock<Vec<Arc<CertifiedKey>>>,
    /// a name that matches no certificate ends the handshake instead of getting the default one
    strict: bool,
}

impl CertStore {
    pub fn new() -> CertStore {
        CertStore::default()
    }

    /// A store holding `cert`.
    pub fn single(cert: CertifiedKey) -> CertStore {
        let s = CertStore::new();
        s.add(cert);
        s
    }

    /// A store that refuses (`unrecognized_name`) a client that names a host none of its certificates is for, instead
    /// of answering with the default certificate.
    pub fn strict(mut self) -> CertStore {
        self.strict = true;
        self
    }

    /// Adds a certificate; the first one added is the default.
    pub fn add(&self, cert: CertifiedKey) {
        self.certs.write().unwrap_or_else(|e| e.into_inner()).push(Arc::new(cert));
    }

    /// Replaces all the certificates (a renewal, a reload): handshakes from now on use the new ones.
    pub fn replace(&self, certs: Vec<CertifiedKey>) {
        *self.certs.write().unwrap_or_else(|e| e.into_inner()) = certs.into_iter().map(Arc::new).collect();
    }

    /// Sets the OCSP response stapled for the certificate at `index` (in the order added).
    pub fn set_ocsp_staple(&self, index: usize, response: Option<Vec<u8>>) {
        let mut certs = self.certs.write().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = certs.get_mut(index) {
            let mut updated = (**c).clone();
            updated.ocsp_staple = response;
            *c = Arc::new(updated);
        }
    }

    /// The certificates now held, in order.
    pub fn certificates(&self) -> Vec<Arc<CertifiedKey>> {
        self.certs.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: &ClientHelloInfo) -> Option<Arc<CertifiedKey>> {
        let certs = self.certs.read().unwrap_or_else(|e| e.into_inner());
        // the client must be able to verify the key's signature
        let usable: Vec<&Arc<CertifiedKey>> = certs.iter().filter(|c| c.key.tls_schemes().iter().any(|s| hello.signature_schemes.contains(s))).collect();
        // by name: exact before wildcard; nothing matching: the default (all of them, in order), unless strict
        let candidates: Vec<&Arc<CertifiedKey>> = match hello.server_name {
            Some(name) => {
                let best = usable.iter().map(|c| c.name_match(name)).max().unwrap_or(0);
                if best > 0 {
                    usable.iter().copied().filter(|c| c.name_match(name) == best).collect()
                } else if self.strict {
                    return None;
                } else {
                    usable
                }
            }
            None => usable,
        };
        // a chain the client says it can check, then the order of addition
        let cert_schemes = hello.signature_schemes_cert.unwrap_or(hello.signature_schemes);
        candidates
            .iter()
            .find(|c| c.chain_schemes.iter().all(|s| cert_schemes.contains(s)))
            .or_else(|| candidates.first())
            .map(|c| Arc::clone(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa::Curve;
    use crate::tls::pki::{issue, CertSpec, KeyPair};

    fn cert(names: &[&str], key: &KeyPair, root: &KeyPair) -> CertifiedKey {
        let der = issue(&CertSpec::server(names), key, Some(("root", root)));
        CertifiedKey::new(vec![der], key.signing_key().clone()).unwrap()
    }

    fn hello<'a>(name: Option<&'a str>, schemes: &'a [u16]) -> ClientHelloInfo<'a> {
        ClientHelloInfo { server_name: name, signature_schemes: schemes, signature_schemes_cert: None, alpn: None }
    }

    const ALL: [u16; 6] = [0x0403, 0x0503, 0x0807, 0x0804, 0x0805, 0x0806];

    #[test]
    fn names_choose_exact_then_wildcard_then_the_default() {
        let root = KeyPair::generate().unwrap();
        let store = CertStore::new();
        store.add(cert(&["default.test"], &KeyPair::generate().unwrap(), &root));
        store.add(cert(&["*.wild.test"], &KeyPair::generate().unwrap(), &root));
        store.add(cert(&["a.wild.test", "127.0.0.1"], &KeyPair::generate().unwrap(), &root));
        let pick = |name: Option<&str>| store.resolve(&hello(name, &ALL)).unwrap().dns_names()[0].clone();
        assert_eq!(pick(Some("a.wild.test")), "a.wild.test");
        assert_eq!(pick(Some("A.Wild.Test.")), "a.wild.test", "case and a trailing dot do not matter");
        assert_eq!(pick(Some("b.wild.test")), "*.wild.test");
        assert_eq!(pick(Some("x.b.wild.test")), "default.test", "a wildcard covers one label");
        assert_eq!(pick(Some("nothing.test")), "default.test");
        assert_eq!(pick(None), "default.test");
        assert_eq!(pick(Some("127.0.0.1")), "a.wild.test");
        let strict = CertStore::single(cert(&["only.test"], &KeyPair::generate().unwrap(), &root)).strict();
        assert!(strict.resolve(&hello(Some("other.test"), &ALL)).is_none());
        assert!(strict.resolve(&hello(Some("only.test"), &ALL)).is_some());
        assert!(strict.resolve(&hello(None, &ALL)).is_some(), "no name: the default, even when strict");
    }

    #[test]
    fn the_client_must_be_able_to_verify_the_key_and_should_the_chain() {
        let ec_root = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        let ed_root = KeyPair::generate().unwrap();
        let store = CertStore::new();
        store.add(cert(&["s.test"], &KeyPair::generate_ecdsa(Curve::P384).unwrap(), &ec_root)); // ECDSA P-384 key, ECDSA chain
        store.add(cert(&["s.test"], &KeyPair::generate().unwrap(), &ed_root)); // Ed25519 key, Ed25519 chain
        store.add(cert(&["s.test"], &KeyPair::generate().unwrap(), &ec_root)); // Ed25519 key, ECDSA chain
        let alg = |schemes: &[u16], cert_schemes: Option<&[u16]>| {
            store
                .resolve(&ClientHelloInfo { server_name: Some("s.test"), signature_schemes: schemes, signature_schemes_cert: cert_schemes, alpn: None })
                .map(|c| (c.key().algorithm(), c.chain_schemes.clone()))
        };
        assert_eq!(alg(&ALL, None).unwrap().0, "ECDSA P-384");
        // only Ed25519 signatures: the second, whose chain is Ed25519 too
        assert_eq!(alg(&[0x0807], None).unwrap(), ("Ed25519".to_string(), vec![0x0807]));
        // Ed25519 handshake signatures, ECDSA SHA-256 chains only
        assert_eq!(alg(&[0x0807, 0x0403], Some(&[0x0403])).unwrap(), ("Ed25519".to_string(), vec![0x0403]));
        // nothing the keys can make: none
        assert!(alg(&[0x0804], None).is_none());
    }

    #[test]
    fn the_key_must_be_the_leafs_and_the_store_can_change() {
        let root = KeyPair::generate().unwrap();
        let k = KeyPair::generate().unwrap();
        let der = issue(&CertSpec::server(&["k.test"]), &k, Some(("root", &root)));
        let err = CertifiedKey::new(vec![der.clone()], KeyPair::generate().unwrap().signing_key().clone()).unwrap_err().to_string();
        assert!(err.contains("not the key"), "{err}");
        assert!(CertifiedKey::new(vec![], k.signing_key().clone()).is_err());
        let store = CertStore::single(CertifiedKey::new(vec![der], k.signing_key().clone()).unwrap());
        store.set_ocsp_staple(0, Some(vec![1, 2, 3]));
        assert_eq!(store.resolve(&hello(None, &ALL)).unwrap().ocsp_staple(), Some(&[1u8, 2, 3][..]));
        store.replace(vec![cert(&["new.test"], &KeyPair::generate().unwrap(), &root)]);
        assert_eq!(store.resolve(&hello(Some("k.test"), &ALL)).unwrap().dns_names(), ["new.test"]);
    }
}
