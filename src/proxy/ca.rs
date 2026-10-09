//! The scanning proxy's certificate authority (B-78): made in memory when the proxy is built, its private key never
//! written anywhere and gone when the proxy is, valid for a short time (a day by default), and limited by a critical
//! name constraint (RFC 5280 section 4.2.1.10) to the DNS names of the hosts the proxy opens, with every IP address
//! excluded. A client that trusts it for the proxy's sake trusts it for those names and nothing else: should its key
//! leak while it lives, it could not vouch for any other site.
//!
//! The leaf certificates it signs, one per host, are made when a client first asks for the host and kept for the CA's
//! life; they share one P-256 key, made with the CA's (a leaf is then a signature, not a key generation).

use crate::asn1::write as der;
use crate::crypto::ecdsa::Curve;
use crate::crypto::sha2::{Hash, Sha256};
use crate::error::{Error, Result};
use crate::sign::SigningKey;
use crate::tls::certs::{CertifiedKey, ClientHelloInfo, ResolvesServerCert};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANIZATION: &str = "2.5.4.10";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
const OID_SAN: &str = "2.5.29.17";
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";
const OID_SKI: &str = "2.5.29.14";
const OID_AKI: &str = "2.5.29.35";
const OID_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

/// How far back certificates are dated, for clients whose clocks are a little behind.
const BACKDATE: i64 = 3600;

/// A certificate authority for one run of the proxy.
pub struct ProxyCa {
    key: SigningKey,
    der: Vec<u8>,
    /// the DER of its name, the issuer of every leaf
    name: Vec<u8>,
    key_id: Vec<u8>,
    not_before: i64,
    not_after: i64,
    /// the DNS names it may vouch for (and the names below them), lower case
    permitted: Vec<String>,
    leaf_key: SigningKey,
    leaf_key_id: Vec<u8>,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for ProxyCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyCa({:?}, until {})", self.permitted, self.not_after)
    }
}

fn key_id(key: &SigningKey) -> Vec<u8> {
    let ec = key.as_ecdsa().expect("an ECDSA key");
    Sha256::digest(ec.public_key())[..20].to_vec()
}

fn serial() -> Result<Vec<u8>> {
    let mut s = crate::crypto::rand::bytes::<16>()?;
    s[0] = (s[0] & 0x7f) | 0x40; // positive, and sixteen bytes long
    Ok(s.to_vec())
}

fn extension(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        der::sequence(&[&der::oid_str(oid), &der::boolean(true), &der::octet_string(value)])
    } else {
        der::sequence(&[&der::oid_str(oid), &der::octet_string(value)])
    }
}

fn attribute(oid: &str, value: &str) -> Vec<u8> {
    der::set(&[&der::sequence(&[&der::oid_str(oid), &der::utf8_string(value)])])
}

/// Whether `name` is a DNS name this module writes into a certificate: ASCII letters, digits and hyphens in labels of 1
/// to 63, at least two labels, 253 characters in all, no label starting or ending with a hyphen, and a last label that
/// is not all digits (which would be an IPv4 address).
pub(crate) fn is_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').count() >= 2
        && !name.rsplit('.').next().unwrap_or("").bytes().all(|b| b.is_ascii_digit())
        && name.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !l.starts_with('-') && !l.ends_with('-')
        })
}

/// Whether the name constraint `base` covers `host` (RFC 5280: the name itself, or any name made by adding labels on
/// its left).
fn covered(base: &str, host: &str) -> bool {
    host == base || host.strip_suffix(base).is_some_and(|rest| rest.ends_with('.'))
}

impl ProxyCa {
    /// A new authority named `common_name`, valid from an hour ago for `lifetime`, for the DNS names `permitted` (a
    /// `*.example.com` entry permits the names under example.com, as the constraint `example.com` does). Refused if a
    /// name is not a DNS name or there is none.
    pub fn new(common_name: &str, permitted: &[&str], lifetime: Duration) -> Result<ProxyCa> {
        let mut bases: Vec<String> = Vec::new();
        for p in permitted {
            let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
            let base = p.strip_prefix("*.").unwrap_or(&p).to_string();
            if !is_dns_name(&base) {
                return Err(Error::Key(format!("{p:?} is not a DNS name the proxy's CA can be limited to")));
            }
            if !bases.iter().any(|b| covered(b, &base)) {
                bases.retain(|b| !covered(&base, b));
                bases.push(base);
            }
        }
        if bases.is_empty() {
            return Err(Error::Key("a proxy CA for no names".into()));
        }
        let key = SigningKey::generate_ecdsa(Curve::P256)?;
        let leaf_key = SigningKey::generate_ecdsa(Curve::P256)?;
        let now = crate::sys::now_unix();
        let (not_before, not_after) = (now - BACKDATE, now + lifetime.as_secs().clamp(60, 398 * 86_400) as i64);
        let name = der::sequence(&[&attribute(OID_ORGANIZATION, "pratique scanning proxy"), &attribute(OID_COMMON_NAME, common_name)]);
        let key_id = key_id(&key);
        // permitted: each DNS name; excluded: every IPv4 and IPv6 address (address and mask, all zero)
        let permitted_subtrees: Vec<Vec<u8>> = bases.iter().map(|b| der::sequence(&[&der::context(2, false, b.as_bytes())])).collect();
        let excluded_subtrees = [der::sequence(&[&der::context(7, false, &[0; 8])]), der::sequence(&[&der::context(7, false, &[0; 32])])];
        let constraints = der::sequence(&[
            &der::context(0, true, &permitted_subtrees.concat()),
            &der::context(1, true, &excluded_subtrees.concat()),
        ]);
        let extensions = der::sequence(&[
            &extension(OID_BASIC_CONSTRAINTS, true, &der::sequence(&[&der::boolean(true), &der::integer(&[0])])),
            &extension(OID_KEY_USAGE, true, &der::bit_string(1, &[0x06])), // keyCertSign, cRLSign
            &extension(OID_NAME_CONSTRAINTS, true, &constraints),
            &extension(OID_SKI, false, &der::octet_string(&key_id)),
        ]);
        let der = sign(&key, &der::sequence(&[
            &der::context(0, true, &der::integer(&[2])),
            &der::integer(&serial()?),
            &key.x509_algorithm(),
            &name,
            &validity(not_before, not_after),
            &name,
            &key.public_key_spki(),
            &der::context(3, true, &extensions),
        ]))?;
        let leaf_key_id = self::key_id(&leaf_key);
        Ok(ProxyCa { key, der, name, key_id, not_before, not_after, permitted: bases, leaf_key, leaf_key_id, leaves: Mutex::new(HashMap::new()) })
    }

    /// The authority's certificate, DER: what a client is told to trust.
    pub fn certificate(&self) -> &[u8] {
        &self.der
    }

    /// The same as PEM.
    pub fn certificate_pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }

    /// When it expires (Unix seconds); every leaf expires with it.
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// The DNS names its constraint permits (each with the names below it).
    pub fn permitted(&self) -> &[String] {
        &self.permitted
    }

    /// Whether it may vouch for `host`.
    pub fn permits(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        is_dns_name(&host) && self.permitted.iter().any(|b| covered(b, &host))
    }

    /// The certificate for `host` (made the first time, then kept): refused for a name its constraint does not permit.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !self.permits(&host) {
            return Err(Error::Key(format!("the proxy's CA does not vouch for {host:?}")));
        }
        let mut leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = leaves.get(&host) {
            return Ok(c.clone());
        }
        let cert = Arc::new(CertifiedKey::new(vec![self.issue(&host)?], self.leaf_key.clone())?);
        leaves.insert(host, cert.clone());
        Ok(cert)
    }

    /// A leaf for `host`, whatever the constraint says (for the tests that show clients refuse one it does not permit).
    #[cfg(test)]
    pub(crate) fn issue_unchecked(&self, host: &str) -> Vec<u8> {
        self.issue(host).expect("signing works")
    }

    fn issue(&self, host: &str) -> Result<Vec<u8>> {
        // the name in the subject too, for the clients that still look there; a name too long for a common name goes
        // in the critical subjectAltName alone
        let (subject, san_critical) = if host.len() <= 64 { (der::sequence(&[&attribute(OID_COMMON_NAME, host)]), false) } else { (der::sequence(&[]), true) };
        let extensions = der::sequence(&[
            &extension(OID_BASIC_CONSTRAINTS, true, &der::sequence(&[])),
            &extension(OID_KEY_USAGE, true, &der::bit_string(7, &[0x80])), // digitalSignature
            &extension(OID_EXT_KEY_USAGE, false, &der::sequence(&[&der::oid_str(OID_SERVER_AUTH)])),
            &extension(OID_SAN, san_critical, &der::sequence(&[&der::context(2, false, host.as_bytes())])),
            &extension(OID_SKI, false, &der::octet_string(&self.leaf_key_id)),
            &extension(OID_AKI, false, &der::sequence(&[&der::context(0, false, &self.key_id)])),
        ]);
        sign(&self.key, &der::sequence(&[
            &der::context(0, true, &der::integer(&[2])),
            &der::integer(&serial()?),
            &self.key.x509_algorithm(),
            &self.name,
            &validity(self.not_before, self.not_after),
            &subject,
            &self.leaf_key.public_key_spki(),
            &der::context(3, true, &extensions),
        ]))
    }
}

fn validity(not_before: i64, not_after: i64) -> Vec<u8> {
    der::sequence(&[&crate::tls::pki::time(not_before), &crate::tls::pki::time(not_after)])
}

/// The certificate whose TBSCertificate is `tbs`, signed by `key`.
fn sign(key: &SigningKey, tbs: &[u8]) -> Result<Vec<u8>> {
    let signature = key.sign_x509(tbs)?;
    Ok(der::sequence(&[tbs, &key.x509_algorithm(), &der::bit_string(0, &signature)]))
}

pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let b64 = crate::pem::base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The certificate of one tunnel: the leaf for the host the client asked the proxy for, given only to a ClientHello that
/// names that host.
pub(crate) struct TunnelCert {
    pub(crate) ca: Arc<ProxyCa>,
    pub(crate) host: String,
}

impl ResolvesServerCert for TunnelCert {
    fn resolve(&self, hello: &ClientHelloInfo) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name?.trim_end_matches('.');
        if !name.eq_ignore_ascii_case(&self.host) {
            return None;
        }
        self.ca.leaf(&self.host).ok()
    }
}
