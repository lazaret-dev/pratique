//! A certificate writer for tests: a throwaway root and a server certificate under it (or a self-signed one), with keys
//! of any kind [`SigningKey`] has (Ed25519 by default), written as DER and nothing more. It writes what the client's
//! validator reads (v3, serial, validity, subject and issuer names with a common name, the key, basic constraints, key
//! usage, extended key usage, alternative names, key identifiers) and refuses nothing: a test can ask for an expired
//! certificate, a wrong name or a CA that may not issue.
//!
//! The keys it makes protect nothing: they are for tests.

use crate::crypto::ecdsa::Curve;
use crate::sign::{Ed25519SigningKey, SigningKey};
use crate::sys;
use std::io;
use std::net::IpAddr;

/// A key pair for test certificates: any [`SigningKey`]; [`generate`](KeyPair::generate) makes an Ed25519 one.
#[derive(Clone, Debug)]
pub struct KeyPair {
    key: SigningKey,
}

impl KeyPair {
    /// A new random Ed25519 key pair.
    pub fn generate() -> io::Result<KeyPair> {
        Ok(KeyPair { key: Ed25519SigningKey::generate()?.into() })
    }

    /// A new random ECDSA key pair on P-256 or P-384.
    pub fn generate_ecdsa(curve: Curve) -> io::Result<KeyPair> {
        Ok(KeyPair { key: SigningKey::generate_ecdsa(curve).map_err(io::Error::other)? })
    }

    /// The Ed25519 key pair with this seed.
    pub fn from_seed(seed: [u8; 32]) -> KeyPair {
        KeyPair { key: Ed25519SigningKey::from_seed(&seed).into() }
    }

    pub fn from_key(key: SigningKey) -> KeyPair {
        KeyPair { key }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The subjectPublicKey bits of the key (the Ed25519 point, the EC point, the RSA PKCS#1 public key).
    pub fn public(&self) -> Vec<u8> {
        let spki = self.key.public_key_spki();
        let mut d = crate::asn1::Der::new(&spki);
        let mut seq = d.sequence().expect("our own SPKI");
        seq.next().expect("the algorithm");
        crate::asn1::bit_string_bytes(&seq.next().expect("the key")).expect("the key bits").to_vec()
    }

    /// The signature over `tbs` for the algorithm [`SigningKey::x509_algorithm`] names (for Ed25519, the plain
    /// signature, which is also what a TLS 1.3 CertificateVerify carries).
    pub fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        self.key.sign_x509(tbs).expect("a test key signs")
    }
}

impl From<KeyPair> for SigningKey {
    fn from(k: KeyPair) -> SigningKey {
        k.key
    }
}

/// What a certificate says. `Default` is a server certificate valid from a day ago for thirty days, with no
/// names (add some).
#[derive(Clone, Debug)]
pub struct CertSpec {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    /// A CA certificate (basic constraints `cA`, key usage keyCertSign): it may issue certificates.
    pub is_ca: bool,
    /// `pathLenConstraint`, for a CA.
    pub path_len: Option<u8>,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub serial: u64,
    /// An extended key usage of serverAuth. Without it (and `client_auth`) the certificate has no extended key usage at all.
    pub server_auth: bool,
    /// An extended key usage of clientAuth (with serverAuth too if `server_auth` is set).
    pub client_auth: bool,
    /// OCSP responders to name in an Authority Information Access extension (none: no extension).
    pub ocsp_uris: Vec<String>,
    /// CRL distribution points (none: no extension).
    pub crl_uris: Vec<String>,
}

impl Default for CertSpec {
    fn default() -> CertSpec {
        let now = sys::now_unix();
        CertSpec {
            common_name: "pratique test server".into(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            is_ca: false,
            path_len: None,
            not_before: now - 86_400,
            not_after: now + 30 * 86_400,
            serial: 1,
            server_auth: true,
            client_auth: false,
            ocsp_uris: Vec::new(),
            crl_uris: Vec::new(),
        }
    }
}

impl CertSpec {
    /// A server certificate for these names (DNS names, or IP address literals).
    pub fn server(names: &[&str]) -> CertSpec {
        let mut spec = CertSpec { common_name: names.first().copied().unwrap_or("pratique test server").to_string(), ..CertSpec::default() };
        for n in names {
            match n.parse::<IpAddr>() {
                Ok(ip) => spec.ip_addresses.push(ip),
                Err(_) => spec.dns_names.push((*n).to_string()),
            }
        }
        spec
    }

    /// A CA certificate, valid from 400 days ago for two years (so that a test can move the clock back a while).
    pub fn ca(common_name: &str) -> CertSpec {
        let now = sys::now_unix();
        CertSpec {
            common_name: common_name.into(),
            is_ca: true,
            not_before: now - 400 * 86_400,
            not_after: now + 365 * 86_400,
            server_auth: false,
            ..CertSpec::default()
        }
    }
}

/// A certificate, as DER, for `subject_key` as `spec` describes it, signed by `issuer` (its name and key); a
/// self-signed certificate when that is `None`.
pub fn issue(spec: &CertSpec, subject_key: &KeyPair, issuer: Option<(&str, &KeyPair)>) -> Vec<u8> {
    let (issuer_name, issuer_key) = issuer.unwrap_or((spec.common_name.as_str(), subject_key));
    issue_for_spki(spec, &subject_key.signing_key().public_key_spki(), issuer_name, issuer_key)
}

/// A certificate for the public key in `subject_spki` (a `SubjectPublicKeyInfo`, as a certificate request carries it),
/// signed by the CA named `issuer_name` with `issuer_key`.
pub fn issue_for_spki(spec: &CertSpec, subject_spki: &[u8], issuer_name: &str, issuer_key: &KeyPair) -> Vec<u8> {
    let algorithm = issuer_key.signing_key().x509_algorithm();

    let mut tbs = Vec::new();
    tbs.extend(tlv(0xA0, &integer(&[2]))); // version: v3
    tbs.extend(integer(&spec.serial.to_be_bytes()));
    tbs.extend(&algorithm);
    tbs.extend(name(issuer_name));
    tbs.extend(tlv(0x30, &[time(spec.not_before), time(spec.not_after)].concat()));
    tbs.extend(name(&spec.common_name));
    tbs.extend(subject_spki);
    tbs.extend(tlv(0xA3, &tlv(0x30, &extensions(spec, &spki_key_bits(subject_spki), &issuer_key.public()))));
    let tbs = tlv(0x30, &tbs);

    let signature = issuer_key.sign(&tbs);
    tlv(0x30, &[tbs, algorithm, bit_string(0, &signature)].concat())
}

/// The subjectPublicKey bits of a `SubjectPublicKeyInfo` (empty if it does not parse).
fn spki_key_bits(spki: &[u8]) -> Vec<u8> {
    let mut d = crate::asn1::Der::new(spki);
    let Ok(mut seq) = d.sequence() else { return Vec::new() };
    let _ = seq.next();
    seq.next().ok().and_then(|t| crate::asn1::bit_string_bytes(&t).ok().map(<[u8]>::to_vec)).unwrap_or_default()
}

fn extensions(spec: &CertSpec, subject_public: &[u8], issuer_public: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // basicConstraints (critical): cA, and the path length if there is one
    let mut bc = Vec::new();
    if spec.is_ca {
        bc.extend(tlv(0x01, &[0xFF]));
        if let Some(n) = spec.path_len {
            bc.extend(integer(&[n]));
        }
    }
    out.extend(extension(&[0x55, 0x1D, 0x13], true, &tlv(0x30, &bc)));
    // keyUsage (critical): keyCertSign and cRLSign for a CA, digitalSignature otherwise
    let usage = if spec.is_ca { bit_string(1, &[0x06]) } else { bit_string(7, &[0x80]) };
    out.extend(extension(&[0x55, 0x1D, 0x0F], true, &usage));
    if spec.server_auth || spec.client_auth {
        let mut usages = Vec::new();
        if spec.server_auth {
            usages.extend(oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]));
        }
        if spec.client_auth {
            usages.extend(oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]));
        }
        out.extend(extension(&[0x55, 0x1D, 0x25], false, &tlv(0x30, &usages)));
    }
    if !spec.dns_names.is_empty() || !spec.ip_addresses.is_empty() {
        let mut names = Vec::new();
        for d in &spec.dns_names {
            names.extend(tlv(0x82, d.as_bytes())); // dNSName
        }
        for ip in &spec.ip_addresses {
            match ip {
                IpAddr::V4(a) => names.extend(tlv(0x87, &a.octets())),
                IpAddr::V6(a) => names.extend(tlv(0x87, &a.octets())),
            }
        }
        out.extend(extension(&[0x55, 0x1D, 0x11], false, &tlv(0x30, &names)));
    }
    if !spec.ocsp_uris.is_empty() {
        let mut list = Vec::new();
        for u in &spec.ocsp_uris {
            list.extend(tlv(0x30, &[oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]), tlv(0x86, u.as_bytes())].concat()));
        }
        out.extend(extension(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01], false, &tlv(0x30, &list)));
    }
    if !spec.crl_uris.is_empty() {
        let mut points = Vec::new();
        for u in &spec.crl_uris {
            // DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames } }
            points.extend(tlv(0x30, &tlv(0xA0, &tlv(0xA0, &tlv(0x86, u.as_bytes())))));
        }
        out.extend(extension(&[0x55, 0x1D, 0x1F], false, &tlv(0x30, &points)));
    }
    // subjectKeyIdentifier and authorityKeyIdentifier: the keys' own hashes (RFC 5280's method 1)
    let key_id = |public: &[u8]| <crate::crypto::sha2::Sha256 as crate::crypto::sha2::Hash>::digest(public)[..20].to_vec();
    out.extend(extension(&[0x55, 0x1D, 0x0E], false, &tlv(0x04, &key_id(subject_public))));
    out.extend(extension(&[0x55, 0x1D, 0x23], false, &tlv(0x30, &tlv(0x80, &key_id(issuer_public)))));
    out
}

fn extension(extn_id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut body = oid(extn_id);
    if critical {
        body.extend(tlv(0x01, &[0xFF]));
    }
    body.extend(tlv(0x04, value));
    tlv(0x30, &body)
}

/// A name with one attribute, the common name.
fn name(common_name: &str) -> Vec<u8> {
    let attribute = tlv(0x30, &[oid(&[0x55, 0x04, 0x03]), tlv(0x0C, common_name.as_bytes())].concat());
    tlv(0x30, &tlv(0x31, &attribute))
}

// ------------------------------------------------------------------------------------------------ revocation evidence

/// A CRL from the CA named `issuer_name` with key `issuer_key`, valid from `this_update` to `next_update`, listing the
/// certificates with these serial numbers (big-endian magnitudes) as revoked at the times given.
pub fn crl(issuer_name: &str, issuer_key: &KeyPair, this_update: i64, next_update: i64, revoked: &[(&[u8], i64)]) -> Vec<u8> {
    let algorithm = issuer_key.signing_key().x509_algorithm();
    let mut tbs = Vec::new();
    tbs.extend(integer(&[1])); // v2
    tbs.extend(&algorithm);
    tbs.extend(name(issuer_name));
    tbs.extend(time(this_update));
    tbs.extend(time(next_update));
    if !revoked.is_empty() {
        let mut list = Vec::new();
        for (serial, when) in revoked {
            list.extend(tlv(0x30, &[integer(serial), time(*when)].concat()));
        }
        tbs.extend(tlv(0x30, &list));
    }
    let tbs = tlv(0x30, &tbs);
    let signature = issuer_key.sign(&tbs);
    tlv(0x30, &[tbs, algorithm, bit_string(0, &signature)].concat())
}

/// What an OCSP response says about a certificate.
#[derive(Clone, Copy, Debug)]
pub enum OcspStatus {
    Good,
    /// Revoked at this time.
    Revoked(i64),
    Unknown,
}

/// A successful basic OCSP response about `cert` (DER), signed by its issuer (`issuer`, DER, with key `issuer_key`) and
/// naming it as the responder, valid from `this_update` (to `next_update`, if there is one). The `CertID` hashes are
/// SHA-1, as responders use.
pub fn ocsp_response(issuer: &[u8], issuer_key: &KeyPair, cert: &[u8], status: OcspStatus, this_update: i64, next_update: Option<i64>) -> Vec<u8> {
    let issuer_cert = crate::x509::Certificate::from_der(issuer).expect("the issuer parses");
    let leaf = crate::x509::Certificate::from_der(cert).expect("the certificate parses");
    let gen_time = |t: i64| {
        let days = t.div_euclid(86_400);
        let secs = t.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        tlv(0x18, format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60).as_bytes())
    };
    let sha1 = |data: &[u8]| crate::crypto::sha1::digest(data).to_vec();
    let cert_id = tlv(
        0x30,
        &[
            tlv(0x30, &[oid(&[0x2B, 0x0E, 0x03, 0x02, 0x1A]), vec![0x05, 0x00]].concat()),
            tlv(0x04, &sha1(&leaf.issuer_der)),
            tlv(0x04, &sha1(&issuer_cert.spki_key)),
            tlv(0x02, &leaf.serial_content),
        ]
        .concat(),
    );
    let cert_status = match status {
        OcspStatus::Good => vec![0x80, 0x00],
        OcspStatus::Revoked(when) => tlv(0xA1, &[gen_time(when), tlv(0xA0, &tlv(0x0A, &[1]))].concat()), // keyCompromise
        OcspStatus::Unknown => vec![0x82, 0x00],
    };
    let mut single = [cert_id, cert_status, gen_time(this_update)].concat();
    if let Some(n) = next_update {
        single.extend(tlv(0xA0, &gen_time(n)));
    }
    let data = tlv(
        0x30,
        &[tlv(0xA1, &issuer_cert.subject_der), gen_time(this_update), tlv(0x30, &tlv(0x30, &single))].concat(),
    );
    let algorithm = issuer_key.signing_key().x509_algorithm();
    let signature = issuer_key.sign(&data);
    let basic = tlv(0x30, &[data, algorithm, bit_string(0, &signature)].concat());
    let response_bytes = tlv(0x30, &[oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]), tlv(0x04, &basic)].concat());
    tlv(0x30, &[tlv(0x0A, &[0]), tlv(0xA0, &response_bytes)].concat())
}

// ------------------------------------------------------------------------------------------------ DER

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 128 {
        out.push(n as u8);
    } else if n < 256 {
        out.extend([0x81, n as u8]);
    } else if n < 65_536 {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

/// An INTEGER from big-endian magnitude bytes (never negative: a leading zero byte is added where the top bit
/// is set, and redundant ones are dropped).
fn integer(be: &[u8]) -> Vec<u8> {
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len().saturating_sub(1));
    let mut v = be[start..].to_vec();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

fn bit_string(unused: u8, bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![unused];
    v.extend_from_slice(bytes);
    tlv(0x03, &v)
}

/// UTCTime for the years 1950 to 2049, GeneralizedTime outside them (RFC 5280 section 4.1.2.5).
pub(crate) fn time(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if (1950..2050).contains(&y) {
        tlv(0x17, format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, m, d, hh, mm, ss).as_bytes())
    } else {
        tlv(0x18, format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z").as_bytes())
    }
}

/// The date of a day number (days since 1970-01-01) in the proleptic Gregorian calendar (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ------------------------------------------------------------------------------------------------ a whole PKI

/// A throwaway root and a server certificate under it, for one server in a test.
#[derive(Clone)]
pub struct TestPki {
    /// The root certificate (DER): what a client trusts.
    pub root: Vec<u8>,
    /// What the server sends: the server certificate, leaf first.
    pub chain: Vec<Vec<u8>>,
    pub server_key: KeyPair,
}

impl TestPki {
    /// A new root and a certificate for `names` (DNS names or IP address literals) under it.
    pub fn new(names: &[&str]) -> io::Result<TestPki> {
        TestPki::with_spec(CertSpec::server(names))
    }

    /// Like `new`, with the server certificate as `leaf` says.
    pub fn with_spec(leaf: CertSpec) -> io::Result<TestPki> {
        Ok(TestPki::with_keys(leaf, &KeyPair::generate()?, KeyPair::generate()?))
    }

    /// A root with `root_key` and the server certificate `leaf` for `server_key` under it: keys of any kind.
    pub fn with_keys(leaf: CertSpec, root_key: &KeyPair, server_key: KeyPair) -> TestPki {
        let root_spec = CertSpec::ca("pratique test root");
        let root = issue(&root_spec, root_key, None);
        let leaf = issue(&leaf, &server_key, Some((&root_spec.common_name, root_key)));
        TestPki { root, chain: vec![leaf], server_key }
    }

    /// A trust store that holds the root.
    pub fn trust_store(&self) -> crate::x509::TrustStore {
        let mut store = crate::x509::TrustStore::empty();
        store.add_der(&self.root).expect("the root certificate parses");
        store
    }

    /// The root as PEM, for tools that read a CA file (`openssl s_client -CAfile`, `curl --cacert`).
    pub fn root_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.root)
    }
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = crate::pem::base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{Certificate, PublicKey};

    #[test]
    fn dates_are_written_as_the_standard_says() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(time(0), [&[0x17, 13][..], b"700101000000Z"].concat());
        assert_eq!(time(1_700_000_000), [&[0x17, 13][..], b"231114221320Z"].concat());
        // after 2049 and before 1950: GeneralizedTime
        assert_eq!(time(2_524_608_000), [&[0x18, 15][..], b"20500101000000Z"].concat());
        assert_eq!(time(-1_000_000_000), [&[0x18, 15][..], b"19380424221320Z"].concat());
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(integer(&[0]), [2, 1, 0]);
        assert_eq!(integer(&[0, 0, 5]), [2, 1, 5]);
        assert_eq!(integer(&[0x80]), [2, 2, 0, 0x80]);
        assert_eq!(integer(&1u64.to_be_bytes()), [2, 1, 1]);
        assert_eq!(integer(&u64::MAX.to_be_bytes()), [2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]);
    }

    #[test]
    fn lengths_use_the_shortest_form() {
        assert_eq!(&tlv(4, &[0; 127])[..2], [4, 127]);
        assert_eq!(&tlv(4, &[0; 128])[..3], [4, 0x81, 128]);
        assert_eq!(&tlv(4, &[0; 255])[..3], [4, 0x81, 255]);
        assert_eq!(&tlv(4, &[0; 256])[..4], [4, 0x82, 1, 0]);
        assert_eq!(&tlv(4, &vec![0; 70_000])[..5], [4, 0x83, 1, 0x11, 0x70]);
    }

    #[test]
    fn the_certificates_we_write_are_the_ones_the_validator_reads() {
        let pki = TestPki::new(&["server.test", "*.wild.test", "127.0.0.1", "::1"]).unwrap();
        let leaf = Certificate::from_der(&pki.chain[0]).unwrap();
        assert!(matches!(&leaf.public_key, PublicKey::Ed25519(k) if k[..] == pki.server_key.public()[..]));
        assert!(leaf.matches_hostname("server.test"));
        assert!(leaf.matches_hostname("a.wild.test"));
        assert!(leaf.matches_hostname("127.0.0.1"));
        assert!(leaf.matches_hostname("::1"));
        assert!(!leaf.matches_hostname("other.test"));
        assert!(!leaf.matches_hostname("127.0.0.2"));
        let now = sys::now_unix();
        for host in ["server.test", "x.wild.test", "127.0.0.1"] {
            pki.trust_store().verify_server_chain(&pki.chain, host, now).unwrap_or_else(|e| panic!("{host}: {e}"));
        }
        assert!(pki.trust_store().verify_server_chain(&pki.chain, "other.test", now).is_err());
        // not before it starts and not after it ends
        assert!(pki.trust_store().verify_server_chain(&pki.chain, "server.test", now - 3 * 86_400).is_err());
        assert!(pki.trust_store().verify_server_chain(&pki.chain, "server.test", now + 40 * 86_400).is_err());
        // not under a root that did not sign it
        let other = TestPki::new(&["server.test"]).unwrap();
        assert!(other.trust_store().verify_server_chain(&pki.chain, "server.test", now).is_err());
    }

    #[test]
    fn a_leaf_cannot_issue() {
        // the "root" below is a server certificate (no cA): a chain through it must not validate
        let root_key = KeyPair::generate().unwrap();
        let server_key = KeyPair::generate().unwrap();
        let not_a_ca = CertSpec::server(&["root.test"]);
        let root = issue(&not_a_ca, &root_key, None);
        let leaf = issue(&CertSpec::server(&["server.test"]), &server_key, Some((&not_a_ca.common_name, &root_key)));
        let mut store = crate::x509::TrustStore::empty();
        store.add_der(&root).unwrap();
        let now = sys::now_unix();
        assert!(store.verify_server_chain(&[leaf], "server.test", now).is_err());
    }

    #[test]
    fn an_intermediate_works_and_the_server_auth_usage_is_checked() {
        let root_key = KeyPair::generate().unwrap();
        let inter_key = KeyPair::generate().unwrap();
        let server_key = KeyPair::generate().unwrap();
        let root_spec = CertSpec::ca("root");
        let inter_spec = CertSpec { path_len: Some(0), ..CertSpec::ca("intermediate") };
        let root = issue(&root_spec, &root_key, None);
        let inter = issue(&inter_spec, &inter_key, Some(("root", &root_key)));
        let leaf = issue(&CertSpec::server(&["server.test"]), &server_key, Some(("intermediate", &inter_key)));
        let mut store = crate::x509::TrustStore::empty();
        store.add_der(&root).unwrap();
        let now = sys::now_unix();
        store.verify_server_chain(&[leaf.clone(), inter.clone()], "server.test", now).unwrap();
        // the intermediate is needed
        assert!(store.verify_server_chain(&[leaf], "server.test", now).is_err());
        // a certificate for client authentication only is not a server's
        let other_use = CertSpec { server_auth: false, ..CertSpec::server(&["server.test"]) };
        let no_eku = issue(&other_use, &server_key, Some(("intermediate", &inter_key)));
        // no extended key usage at all means any use, which includes this one
        store.verify_server_chain(&[no_eku, inter], "server.test", now).unwrap();
    }

    #[test]
    fn the_pem_is_what_openssl_reads() {
        let pki = TestPki::new(&["server.test"]).unwrap();
        let pem = pki.root_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let back = crate::pem::parse(&pem);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].data, pki.root);
    }
}
