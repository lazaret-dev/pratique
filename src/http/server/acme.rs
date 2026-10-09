//! ACME (RFC 8555): certificates from Let's Encrypt, or any other ACME CA, got and renewed while the server runs
//! (B-113).
//!
//! [`Acme`] is the client: an account (its key kept in a state directory), orders, the challenges that prove control of
//! each name, the certificate request, and the certificate, saved in the state directory too. [`manage`] keeps a
//! [`CertStore`] full of current certificates: it loads the ones saved, gets those missing, and renews each when the
//! CA's renewal information says to (ARI, RFC 9773: a window the CA picks, earlier if it is about to revoke), or two
//! thirds of the way through its lifetime (half, for certificates of less than ten days) when the CA gives none.
//!
//! The challenges, one of which the CA must be able to check for every name:
//!
//! * TLS-ALPN-01 ([`AcmeTlsAlpn01`], RFC 8737): the CA connects to port 443 offering the ALPN protocol `acme-tls/1`, and
//!   the TLS server answers with a challenge certificate. Wrap the server's certificate resolver with
//!   [`AcmeTlsAlpn01::wrap`]. Needs nothing but port 443.
//! * HTTP-01 ([`AcmeHttp01`]): the CA fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80, which the
//!   server's plain listener answers through [`AcmeHttp01::wrap`].
//! * DNS-01 ([`Dns01`]): a TXT record at `_acme-challenge.<name>` that the caller's DNS provider publishes. The only one
//!   for wildcard names (`*.example.com`).
//!
//! With more than one set up, the first of these that the CA offers for a name is used. IP addresses (RFC 8738) can be
//! validated with the first two.
//!
//! ```no_run
//! use pratique::http::server::acme::{self, Acme, AcmeConfig, AcmeTlsAlpn01};
//! use pratique::http::server::{redirect_to_https, AcmeHttp01, Request, Response, ServerBuilder};
//! use pratique::tls::certs::CertStore;
//! use pratique::tls::server::ServerConfig;
//! use std::sync::Arc;
//!
//! let (http01, tls_alpn01) = (AcmeHttp01::new(), AcmeTlsAlpn01::new());
//! let mut tls = ServerConfig::with_certificates(CertStore::new()).with_alpn(&["h2", "http/1.1"]);
//! let store = tls.store.clone().expect("a configuration made with a store");
//! tls.certs = tls_alpn01.wrap(tls.certs.clone());
//! let acme = Acme::new(
//!     AcmeConfig::new(acme::LETS_ENCRYPT, "/var/lib/example/acme")
//!         .contact("mailto:admin@example.com")
//!         .agree_to_terms()
//!         .tls_alpn01(&tls_alpn01)
//!         .http01(&http01),
//! )?;
//! let server = ServerBuilder::new(|req: Request| Response::text(200, format!("hello, {}\n", req.path())))
//!     .tls("[::]:443", Arc::new(tls))
//!     .plain_with("[::]:80", http01.wrap(redirect_to_https(None)))
//!     .start()?;
//! let _renewals = acme::manage(acme, vec![vec!["example.com".into(), "www.example.com".into()]], store, |m| eprintln!("acme: {m}"));
//! server.wait();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The state directory holds, for each CA (by its directory URL), the account key (`account.key`) and the certificates
//! (`certificates/<name>/fullchain.pem` and `key.pem`; see [`Acme::certificate_dir`]); the keys are written readable by
//! their owner only. One process at a time should use a state directory. Test against a CA's staging service first
//! ([`LETS_ENCRYPT_STAGING`]): the production one has rate limits that a misconfigured server reaches quickly.

use super::helpers::AcmeHttp01;
use super::runtime::Reloader;
use crate::asn1::write as der;
use crate::crypto::ecdsa::Curve;
use crate::crypto::hmac::Hmac;
use crate::crypto::sha2::{Hash, HashAlg, Sha256};
use crate::http::{Client, Response};
use crate::json::{self, Object, Value};
use crate::sign::SigningKey;
use crate::tls::certs::{CertStore, CertifiedKey, ClientHelloInfo, ResolvesServerCert};
use crate::tls::server::ACME_TLS_1;
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt's staging directory: the same service with far higher rate limits, issuing certificates that nothing
/// trusts. Use it to try a configuration out.
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

const OID_SAN: &str = "2.5.29.17";
const OID_AKI: &str = "2.5.29.35";
const OID_ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";
const OID_EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
const OID_COMMON_NAME: &str = "2.5.4.3";
const ERROR_PREFIX: &str = "urn:ietf:params:acme:error:";

// ------------------------------------------------------------------------------------------------ errors

/// What went wrong: a problem document from the CA (RFC 8555 section 6.7) or a failure on the way to it.
#[derive(Clone, Debug)]
pub struct AcmeError {
    /// The problem's type (`urn:ietf:params:acme:error:rateLimited`, ...), if the CA sent one.
    pub kind: Option<String>,
    /// What the CA (or this client) said, with the problems of each name the CA listed.
    pub detail: String,
    /// When the CA says to try again (its `Retry-After`), in Unix seconds.
    pub retry_after: Option<i64>,
}

impl AcmeError {
    fn new(detail: impl Into<String>) -> AcmeError {
        AcmeError { kind: None, detail: detail.into(), retry_after: None }
    }

    /// Whether the problem's type is `urn:ietf:params:acme:error:<short>` (`"badNonce"`, `"rateLimited"`, ...).
    pub fn is(&self, short: &str) -> bool {
        self.kind.as_deref().and_then(|k| k.strip_prefix(ERROR_PREFIX)) == Some(short)
    }
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Some(k) => write!(f, "{}: {}", k.strip_prefix(ERROR_PREFIX).unwrap_or(k), self.detail),
            None => f.write_str(&self.detail),
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<crate::error::Error> for AcmeError {
    fn from(e: crate::error::Error) -> AcmeError {
        AcmeError::new(e.to_string())
    }
}

impl From<crate::verify_error::Error> for AcmeError {
    fn from(e: crate::verify_error::Error) -> AcmeError {
        AcmeError::new(e.to_string())
    }
}

impl From<std::io::Error> for AcmeError {
    fn from(e: std::io::Error) -> AcmeError {
        AcmeError::new(e.to_string())
    }
}

/// What the functions of this module return.
pub type Result<T> = std::result::Result<T, AcmeError>;

/// Text from the CA, for a message: printable, and not too long.
fn clean(text: &str) -> String {
    let mut out: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(500).collect();
    if text.chars().count() > 500 {
        out.push('…');
    }
    out
}

/// The error a response that is not a success stands for: its problem document, or its status.
fn problem(resp: &Response) -> AcmeError {
    let retry_after = retry_after(resp).map(|s| crate::sys::now_unix() + s as i64);
    let doc = json::parse(&resp.body).ok();
    let kind = doc.as_ref().and_then(|d| str_field(d, "type")).map(clean);
    let mut detail = doc.as_ref().and_then(|d| str_field(d, "detail")).map(clean).unwrap_or_default();
    if detail.is_empty() {
        detail = format!("HTTP {} from {}", resp.status, resp.url);
    }
    for sub in doc.as_ref().and_then(|d| d.get("subproblems")).and_then(Value::as_array).unwrap_or(&[]) {
        let id = sub.get("identifier").and_then(|i| str_field(i, "value")).unwrap_or("?");
        let kind = str_field(sub, "type").map(|k| k.strip_prefix(ERROR_PREFIX).unwrap_or(k)).unwrap_or("error");
        detail.push_str(&format!("; {}: {}: {}", clean(id), clean(kind), clean(str_field(sub, "detail").unwrap_or(""))));
    }
    AcmeError { kind, detail, retry_after }
}

/// The problem document inside an object (a challenge's `error`).
fn embedded_problem(doc: &Value) -> Option<AcmeError> {
    let kind = str_field(doc, "type").map(clean);
    let detail = clean(str_field(doc, "detail").unwrap_or("no detail"));
    Some(AcmeError { kind, detail, retry_after: None })
}

/// `Retry-After` in seconds (the CA's HTTP-date form is not read).
fn retry_after(resp: &Response) -> Option<u64> {
    resp.header("retry-after")?.trim().parse::<u64>().ok().map(|s| s.min(86_400 * 7))
}

fn str_field<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v.get(name).and_then(Value::as_str)
}

fn parse_json(resp: &Response) -> Result<Value> {
    json::parse(&resp.body).map_err(|e| AcmeError::new(format!("the CA's answer from {} is not JSON: {e}", resp.url)))
}

fn canonical(v: &Value) -> Result<Vec<u8>> {
    json::canonical(v).map_err(|e| AcmeError::new(format!("internal: JSON: {e}")))
}

// ------------------------------------------------------------------------------------------------ base64url

/// Base64url without padding (RFC 7515 section 2), as JWS and ACME use it.
pub(crate) fn b64url(data: &[u8]) -> String {
    crate::pem::base64_encode(data).trim_end_matches('=').chars().map(|c| match c {
        '+' => '-',
        '/' => '_',
        c => c,
    }).collect()
}

pub(crate) fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    let mut std: String = s.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();
    while !std.len().is_multiple_of(4) {
        std.push('=');
    }
    crate::pem::base64_decode_strict(&std)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// ------------------------------------------------------------------------------------------------ the account key

/// The account key and what is made from it: its JWK (RFC 7517) and thumbprint (RFC 7638), and JWS signatures (RFC
/// 7515, flattened JSON serialization).
struct AccountKey {
    key: SigningKey,
    alg: &'static str,
    hash: HashAlg,
    jwk: Value,
    thumbprint: String,
}

impl AccountKey {
    fn new(key: SigningKey) -> Result<AccountKey> {
        let ec = key.as_ecdsa().ok_or_else(|| AcmeError::new(format!("an account key must be ECDSA P-256 or P-384, not {}", key.algorithm())))?;
        let (crv, alg, hash) = match ec.curve() {
            Curve::P256 => ("P-256", "ES256", HashAlg::Sha256),
            Curve::P384 => ("P-384", "ES384", HashAlg::Sha384),
            #[allow(unreachable_patterns)]
            _ => return Err(AcmeError::new("an account key must be ECDSA P-256 or P-384")),
        };
        let n = ec.curve().coord_len();
        let point = ec.public_key();
        let mut jwk = Object::new();
        jwk.insert("crv", Value::string(crv));
        jwk.insert("kty", Value::string("EC"));
        jwk.insert("x", Value::string(&b64url(&point[1..1 + n])));
        jwk.insert("y", Value::string(&b64url(&point[1 + n..1 + 2 * n])));
        let jwk = Value::Object(jwk);
        // the thumbprint hashes the required members in lexicographic order with no white space, which is what the
        // canonical form (RFC 8785) of this object is
        let thumbprint = b64url(&sha256(&canonical(&jwk)?));
        Ok(AccountKey { key, alg, hash, jwk, thumbprint })
    }

    fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint)
    }

    /// The JWS of `payload` (`None`: the empty payload of a POST-as-GET) under `protected`.
    fn sign(&self, protected: Object, payload: Option<&Value>) -> Result<Vec<u8>> {
        let protected = b64url(&canonical(&Value::Object(protected))?);
        let payload = match payload {
            Some(p) => b64url(&canonical(p)?),
            None => String::new(),
        };
        let ec = self.key.as_ecdsa().expect("an ECDSA account key");
        let signature = ec.sign_p1363(self.hash, format!("{protected}.{payload}").as_bytes())?;
        let mut jws = Object::new();
        jws.insert("protected", Value::String(protected));
        jws.insert("payload", Value::String(payload));
        jws.insert("signature", Value::string(&b64url(&signature)));
        canonical(&Value::Object(jws))
    }
}

/// An external account binding (RFC 8555 section 7.3.4): the account key, signed with the MAC key the CA gave out of band.
fn external_account_binding(key_id: &str, mac_key: &[u8], url: &str, jwk: &Value) -> Result<Value> {
    let mut protected = Object::new();
    protected.insert("alg", Value::string("HS256"));
    protected.insert("kid", Value::string(key_id));
    protected.insert("url", Value::string(url));
    let protected = b64url(&canonical(&Value::Object(protected))?);
    let payload = b64url(&canonical(jwk)?);
    let mac = Hmac::<Sha256>::mac(mac_key, format!("{protected}.{payload}").as_bytes());
    let mut jws = Object::new();
    jws.insert("protected", Value::String(protected));
    jws.insert("payload", Value::String(payload));
    jws.insert("signature", Value::string(&b64url(&mac)));
    Ok(Value::Object(jws))
}

// ------------------------------------------------------------------------------------------------ configuration

/// Publishes the TXT records of DNS-01 challenges, through the caller's DNS provider.
pub trait Dns01: Send + Sync {
    /// Adds a TXT record with `value` at `name` (`_acme-challenge.example.com`, with no final dot), next to any others
    /// there (a name and its wildcard have two records at the same name at once), and returns once the domain's
    /// authoritative servers answer with it: the CA asks them as soon as this returns.
    fn present(&self, name: &str, value: &str) -> std::result::Result<(), String>;
    /// Removes the record that `present` added.
    fn cleanup(&self, name: &str, value: &str);
}

/// How [`Acme`] works: the CA, where its state is kept, the account's contacts, and the challenges it can answer.
#[derive(Clone)]
pub struct AcmeConfig {
    /// The CA's directory URL ([`LETS_ENCRYPT`], [`LETS_ENCRYPT_STAGING`], or another CA's).
    pub directory: String,
    /// Where the account key and the certificates are kept (made if missing).
    pub state_dir: PathBuf,
    /// The account's contact URLs (`mailto:admin@example.com`), for the CA's notices.
    pub contact: Vec<String>,
    /// Agreement to the CA's terms of service, which a CA that has them requires.
    pub agree_to_terms: bool,
    pub tls_alpn01: Option<AcmeTlsAlpn01>,
    pub http01: Option<AcmeHttp01>,
    pub dns01: Option<Arc<dyn Dns01>>,
    /// The HTTP client the CA is reached with (default: one that trusts the system's CAs).
    pub client: Option<Client>,
    /// The curve of the certificates' keys (default P-256; each certificate gets a new key).
    pub key_curve: Curve,
    /// An external account binding's key identifier and MAC key (base64url), for a CA that requires one (ZeroSSL,
    /// Google Trust Services, ...).
    pub external_account: Option<(String, String)>,
    /// The certificate profile to ask for, for a CA that has them (Let's Encrypt: `classic`, `tlsserver`, `shortlived`).
    pub profile: Option<String>,
    /// How long the CA may take to validate the names of an order, and then to issue its certificate.
    pub validation_timeout: Duration,
    /// For [`manage`]: the wait after a failure, doubled after each one that follows (to at most six hours), when the
    /// CA does not say how long to wait.
    pub retry_after_failure: Duration,
}

impl AcmeConfig {
    pub fn new(directory: &str, state_dir: impl Into<PathBuf>) -> AcmeConfig {
        AcmeConfig {
            directory: directory.to_string(),
            state_dir: state_dir.into(),
            contact: Vec::new(),
            agree_to_terms: false,
            tls_alpn01: None,
            http01: None,
            dns01: None,
            client: None,
            key_curve: Curve::P256,
            external_account: None,
            profile: None,
            validation_timeout: Duration::from_secs(180),
            retry_after_failure: Duration::from_secs(300),
        }
    }

    /// Adds a contact URL (`mailto:...`).
    pub fn contact(mut self, url: &str) -> AcmeConfig {
        self.contact.push(url.to_string());
        self
    }

    /// Agrees to the CA's terms of service.
    pub fn agree_to_terms(mut self) -> AcmeConfig {
        self.agree_to_terms = true;
        self
    }

    pub fn tls_alpn01(mut self, challenges: &AcmeTlsAlpn01) -> AcmeConfig {
        self.tls_alpn01 = Some(challenges.clone());
        self
    }

    pub fn http01(mut self, challenges: &AcmeHttp01) -> AcmeConfig {
        self.http01 = Some(challenges.clone());
        self
    }

    pub fn dns01(mut self, hook: impl Dns01 + 'static) -> AcmeConfig {
        self.dns01 = Some(Arc::new(hook));
        self
    }

    pub fn client(mut self, client: Client) -> AcmeConfig {
        self.client = Some(client);
        self
    }

    pub fn key_curve(mut self, curve: Curve) -> AcmeConfig {
        self.key_curve = curve;
        self
    }

    /// The external account binding a CA gave: its key identifier and MAC key (base64url, as CAs hand it out).
    pub fn external_account(mut self, key_id: &str, mac_key: &str) -> AcmeConfig {
        self.external_account = Some((key_id.to_string(), mac_key.to_string()));
        self
    }

    pub fn profile(mut self, name: &str) -> AcmeConfig {
        self.profile = Some(name.to_string());
        self
    }

    pub fn validation_timeout(mut self, t: Duration) -> AcmeConfig {
        self.validation_timeout = t;
        self
    }
}

// ------------------------------------------------------------------------------------------------ TLS-ALPN-01

/// The TLS-ALPN-01 challenges (RFC 8737) waiting for the CA: a challenge certificate for each name. Clones share the
/// same set; the TLS server answers them through a resolver made with [`wrap`](AcmeTlsAlpn01::wrap).
#[derive(Clone, Default)]
pub struct AcmeTlsAlpn01 {
    certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl fmt::Debug for AcmeTlsAlpn01 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.certs.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();
        write!(f, "AcmeTlsAlpn01({names:?})")
    }
}

impl AcmeTlsAlpn01 {
    pub fn new() -> AcmeTlsAlpn01 {
        AcmeTlsAlpn01::default()
    }

    /// Starts answering for `identifier` (a DNS name, or an IP address) with a challenge certificate for
    /// `key_authorization`.
    pub fn insert(&self, identifier: &str, key_authorization: &str) -> Result<()> {
        let cert = challenge_certificate(identifier, key_authorization)?;
        self.certs.write().unwrap_or_else(|e| e.into_inner()).insert(server_name_for(identifier), Arc::new(cert));
        Ok(())
    }

    /// Stops answering for it.
    pub fn remove(&self, identifier: &str) {
        self.certs.write().unwrap_or_else(|e| e.into_inner()).remove(&server_name_for(identifier));
    }

    /// A resolver that answers a client offering `acme-tls/1` for a name with a challenge waiting with its challenge
    /// certificate, and passes every other handshake to `inner`.
    pub fn wrap(&self, inner: Arc<dyn ResolvesServerCert>) -> Arc<dyn ResolvesServerCert> {
        Arc::new(AlpnResolver { challenges: self.clone(), inner })
    }
}

struct AlpnResolver {
    challenges: AcmeTlsAlpn01,
    inner: Arc<dyn ResolvesServerCert>,
}

impl ResolvesServerCert for AlpnResolver {
    fn resolve(&self, hello: &ClientHelloInfo) -> Option<Arc<CertifiedKey>> {
        if hello.alpn.is_some_and(|offered| offered.iter().any(|p| p == ACME_TLS_1)) {
            if let Some(name) = hello.server_name {
                let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
                if let Some(cert) = self.challenges.certs.read().unwrap_or_else(|e| e.into_inner()).get(&name) {
                    return Some(cert.clone());
                }
            }
        }
        self.inner.resolve(hello)
    }
}

/// The name a validator sends (SNI) for an identifier: a DNS name as it is, lower case; an IP address as its reverse
/// DNS name (RFC 8738 section 6).
pub(crate) fn server_name_for(identifier: &str) -> String {
    match identifier.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        Ok(IpAddr::V6(a)) => {
            let mut out = String::new();
            for b in a.octets().iter().rev() {
                out.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            out + "ip6.arpa"
        }
        Err(_) => identifier.strip_suffix('.').unwrap_or(identifier).to_ascii_lowercase(),
    }
}

fn extension(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        der::sequence(&[&der::oid_str(oid), &der::boolean(true), &der::octet_string(value)])
    } else {
        der::sequence(&[&der::oid_str(oid), &der::octet_string(value)])
    }
}

/// A subjectAltName's GeneralNames: dNSName or iPAddress for each name.
fn general_names(names: &[String]) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = names
        .iter()
        .map(|n| match n.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => der::context(7, false, &a.octets()),
            Ok(IpAddr::V6(a)) => der::context(7, false, &a.octets()),
            Err(_) => der::context(2, false, n.as_bytes()),
        })
        .collect();
    der::sequence(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn common_name(cn: &str) -> Vec<u8> {
    der::sequence(&[&der::set(&[&der::sequence(&[&der::oid_str(OID_COMMON_NAME), &der::utf8_string(cn)])])])
}

/// A self-signed certificate for `identifier` with the critical acmeIdentifier extension holding the SHA-256 of the key
/// authorization (RFC 8737 section 3), on a new P-256 key, valid for a week.
pub(crate) fn challenge_certificate(identifier: &str, key_authorization: &str) -> Result<CertifiedKey> {
    let key = SigningKey::generate_ecdsa(Curve::P256)?;
    let now = crate::sys::now_unix();
    let name = identifier.strip_suffix('.').unwrap_or(identifier).to_ascii_lowercase();
    let extensions = der::sequence(&[
        &extension(OID_SAN, false, &general_names(std::slice::from_ref(&name))),
        &extension(OID_ACME_IDENTIFIER, true, &der::octet_string(&sha256(key_authorization.as_bytes()))),
    ]);
    let mut serial = crate::crypto::rand::bytes::<16>()?;
    serial[0] &= 0x7f;
    let subject = common_name("ACME challenge");
    let algorithm = key.x509_algorithm();
    let not_after = now + 7 * 86_400;
    let tbs = der::sequence(&[
        &der::context(0, true, &der::integer(&[2])),
        &der::integer(&serial),
        &algorithm,
        &subject,
        &der::sequence(&[&crate::tls::pki::time(now - 86_400), &crate::tls::pki::time(not_after)]),
        &subject,
        &key.public_key_spki(),
        &der::context(3, true, &extensions),
    ]);
    let signature = key.sign_x509(&tbs)?;
    let cert = der::sequence(&[&tbs, &algorithm, &der::bit_string(0, &signature)]);
    Ok(CertifiedKey::acme_tls_alpn_challenge(cert, key)?)
}

/// A certificate request (PKCS #10, RFC 2986) for `names`, signed with `key`: the names in a subjectAltName extension,
/// and the first DNS name as the common name if it fits one (64 characters).
pub(crate) fn certificate_request(key: &SigningKey, names: &[String]) -> Result<Vec<u8>> {
    let extensions = der::sequence(&[&extension(OID_SAN, false, &general_names(names))]);
    let attribute = der::sequence(&[&der::oid_str(OID_EXTENSION_REQUEST), &der::set(&[&extensions])]);
    let subject = match names.iter().find(|n| n.parse::<IpAddr>().is_err() && n.len() <= 64) {
        Some(cn) => common_name(cn),
        None => der::sequence(&[]),
    };
    let info = der::sequence(&[&der::integer(&[0]), &subject, &key.public_key_spki(), &der::context(0, true, &attribute)]);
    let signature = key.sign_x509(&info)?;
    Ok(der::sequence(&[&info, &key.x509_algorithm(), &der::bit_string(0, &signature)]))
}

// ------------------------------------------------------------------------------------------------ the client

#[derive(Clone, Debug)]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    revoke_cert: Option<String>,
    renewal_info: Option<String>,
    terms: Option<String>,
    eab_required: bool,
    profiles: Vec<String>,
}

/// An ACME client for one CA and one account. Cheap to clone; clones share the account, and get certificates one at a
/// time.
#[derive(Clone)]
pub struct Acme(Arc<Inner>);

struct Inner {
    config: AcmeConfig,
    client: Client,
    key: AccountKey,
    /// `state_dir/<the CA>`
    dir: PathBuf,
    directory: Mutex<Option<Directory>>,
    nonces: Mutex<Vec<String>>,
    account: Mutex<Option<String>>,
    /// one order at a time
    ordering: Mutex<()>,
}

/// The CA's suggested window for renewing a certificate (ARI, RFC 9773).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalWindow {
    /// Unix seconds.
    pub start: i64,
    pub end: i64,
    /// A page about why, when the CA moved the window (to revoke early, say).
    pub explanation: Option<String>,
    /// When to ask again (Unix seconds).
    pub check_again: i64,
}

/// Lock a mutex, whatever another thread did while holding it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a step of polling found.
enum Poll {
    Again,
    Done,
    Fail(AcmeError),
}

/// A challenge answer that is taken back when it is dropped, however the order ends.
enum Answer {
    TlsAlpn(AcmeTlsAlpn01, String),
    Http(AcmeHttp01, String),
    Dns(Arc<dyn Dns01>, String, String),
}

impl Drop for Answer {
    fn drop(&mut self) {
        match self {
            Answer::TlsAlpn(c, id) => c.remove(id),
            Answer::Http(c, token) => c.remove(token),
            Answer::Dns(hook, name, value) => hook.cleanup(name, value),
        }
    }
}

impl Acme {
    /// A client for the CA of `config`, with the account key saved in its state directory (made, and saved, the first
    /// time). Nothing is sent until it is needed.
    pub fn new(config: AcmeConfig) -> Result<Acme> {
        let client = match &config.client {
            Some(c) => c.clone(),
            None => Client::new()?.user_agent(concat!("pratique/", env!("CARGO_PKG_VERSION"), " acme")),
        };
        let dir = config.state_dir.join(ca_dir_name(&config.directory));
        make_private_dir(&dir)?;
        let key_path = dir.join("account.key");
        let key = match std::fs::read_to_string(&key_path) {
            Ok(pem) => SigningKey::from_pem(&pem).map_err(|e| AcmeError::new(format!("{}: {e}", key_path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::generate_ecdsa(Curve::P256)?;
                write_file(&key_path, &key.to_pkcs8_pem()?, true)?;
                key
            }
            Err(e) => return Err(AcmeError::new(format!("{}: {e}", key_path.display()))),
        };
        let key = AccountKey::new(key)?;
        Ok(Acme(Arc::new(Inner {
            config,
            client,
            key,
            dir,
            directory: Mutex::new(None),
            nonces: Mutex::new(Vec::new()),
            account: Mutex::new(None),
            ordering: Mutex::new(()),
        })))
    }

    /// The account key's thumbprint (RFC 7638), which every key authorization ends with.
    pub fn thumbprint(&self) -> &str {
        &self.0.key.thumbprint
    }

    /// Where this CA's account key and certificates are kept.
    pub fn state_dir(&self) -> &Path {
        &self.0.dir
    }

    fn directory(&self) -> Result<Directory> {
        let mut d = lock(&self.0.directory);
        if let Some(dir) = &*d {
            return Ok(dir.clone());
        }
        let url = &self.0.config.directory;
        let resp = self.0.client.get(url)?;
        if resp.status != 200 {
            return Err(problem(&resp));
        }
        let v = parse_json(&resp)?;
        let need = |name: &str| str_field(&v, name).map(str::to_string).ok_or_else(|| AcmeError::new(format!("the directory at {url} has no {name}")));
        let meta = v.get("meta");
        let dir = Directory {
            new_nonce: need("newNonce")?,
            new_account: need("newAccount")?,
            new_order: need("newOrder")?,
            revoke_cert: str_field(&v, "revokeCert").map(str::to_string),
            renewal_info: str_field(&v, "renewalInfo").map(str::to_string),
            terms: meta.and_then(|m| str_field(m, "termsOfService")).map(str::to_string),
            eab_required: meta.and_then(|m| m.get("externalAccountRequired")).and_then(Value::as_bool).unwrap_or(false),
            profiles: meta.and_then(|m| m.get("profiles")).and_then(Value::as_object).map(|o| o.iter().map(|(k, _)| k.to_string()).collect()).unwrap_or_default(),
        };
        *d = Some(dir.clone());
        Ok(dir)
    }

    fn nonce(&self) -> Result<String> {
        if let Some(n) = lock(&self.0.nonces).pop() {
            return Ok(n);
        }
        let dir = self.directory()?;
        let resp = self.0.client.head(&dir.new_nonce)?;
        if !resp.is_success() {
            return Err(problem(&resp));
        }
        resp.header("replay-nonce").filter(|n| valid_nonce(n)).map(str::to_string).ok_or_else(|| AcmeError::new(format!("no Replay-Nonce from {}", dir.new_nonce)))
    }

    fn keep_nonce(&self, resp: &Response) {
        if let Some(n) = resp.header("replay-nonce").filter(|n| valid_nonce(n)) {
            let mut nonces = lock(&self.0.nonces);
            if nonces.len() >= 16 {
                nonces.remove(0);
            }
            nonces.push(n.to_string());
        }
    }

    /// A signed POST: with the account's URL as `kid` (`jwk` false), or the key itself (`jwk` true: only for a new
    /// account). A refused nonce is replaced and the request sent again, a few times.
    fn post_signed(&self, url: &str, payload: Option<&Value>, jwk: bool, accept: Option<&str>) -> Result<Response> {
        let mut kid = if jwk { None } else { Some(self.account_url()?) };
        let mut registered_again = false;
        for attempt in 0.. {
            let mut protected = Object::new();
            protected.insert("alg", Value::string(self.0.key.alg));
            match &kid {
                Some(k) => protected.insert("kid", Value::string(k)),
                None => protected.insert("jwk", self.0.key.jwk.clone()),
            }
            protected.insert("nonce", Value::String(self.nonce()?));
            protected.insert("url", Value::string(url));
            let body = self.0.key.sign(protected, payload)?;
            let mut req = self.0.client.request("POST", url).header("content-type", "application/jose+json").body(body);
            if let Some(a) = accept {
                req = req.header("accept", a);
            }
            let resp = req.send()?;
            self.keep_nonce(&resp);
            if resp.is_success() {
                return Ok(resp);
            }
            let err = problem(&resp);
            if err.is("badNonce") && attempt < 4 {
                continue;
            }
            // a CA that lost the account (a test CA restarted, say): registered again, once
            if err.is("accountDoesNotExist") && kid.is_some() && !registered_again {
                *lock(&self.0.account) = None;
                kid = Some(self.account_url()?);
                registered_again = true;
                continue;
            }
            return Err(err);
        }
        unreachable!()
    }

    fn post(&self, url: &str, payload: Option<&Value>) -> Result<Response> {
        self.post_signed(url, payload, false, None)
    }

    /// The account's URL: registered with the CA the first time (or found again, for a key it knows).
    pub fn account_url(&self) -> Result<String> {
        let mut account = lock(&self.0.account);
        if let Some(url) = &*account {
            return Ok(url.clone());
        }
        let config = &self.0.config;
        let dir = self.directory()?;
        if let (Some(terms), false) = (&dir.terms, config.agree_to_terms) {
            return Err(AcmeError::new(format!("the CA's terms of service ({}) must be agreed to first (AcmeConfig::agree_to_terms)", clean(terms))));
        }
        let mut payload = Object::new();
        if config.agree_to_terms {
            payload.insert("termsOfServiceAgreed", Value::Bool(true));
        }
        if !config.contact.is_empty() {
            payload.insert("contact", Value::Array(config.contact.iter().map(|c| Value::string(c)).collect()));
        }
        match &config.external_account {
            Some((kid, mac)) => {
                let mac = b64url_decode(mac).filter(|m| !m.is_empty()).ok_or_else(|| AcmeError::new("the external account's MAC key is not base64url"))?;
                payload.insert("externalAccountBinding", external_account_binding(kid, &mac, &dir.new_account, &self.0.key.jwk)?);
            }
            None if dir.eab_required => return Err(AcmeError::new("the CA requires an external account binding (AcmeConfig::external_account)")),
            None => {}
        }
        let resp = self.post_signed(&dir.new_account, Some(&Value::Object(payload)), true, None)?;
        let url = resp.header("location").map(str::to_string).ok_or_else(|| AcmeError::new("the CA gave the new account no URL"))?;
        let status = parse_json(&resp).ok().and_then(|v| str_field(&v, "status").map(str::to_string));
        if status.as_deref().is_some_and(|s| s != "valid") {
            return Err(AcmeError::new(format!("the account {url} is {}", status.unwrap_or_default())));
        }
        *account = Some(url.clone());
        Ok(url)
    }

    /// A certificate for `names` (DNS names, `*.` wildcards, or IP addresses), on a new key: ordered, validated by the
    /// challenges set up, issued, and saved in the state directory.
    pub fn obtain(&self, names: &[&str]) -> Result<CertifiedKey> {
        self.order(&normalize(names)?, None)
    }

    /// The certificate for exactly `names` saved in the state directory, if there is one, it reads, and it has not
    /// expired.
    pub fn load(&self, names: &[&str]) -> Option<CertifiedKey> {
        self.load_names(&normalize(names).ok()?)
    }

    fn load_names(&self, names: &[String]) -> Option<CertifiedKey> {
        let dir = self.cert_dir(names);
        let chain = std::fs::read_to_string(dir.join("fullchain.pem")).ok()?;
        let key = std::fs::read_to_string(dir.join("key.pem")).ok()?;
        let cert = CertifiedKey::from_pem(&chain, &key).ok()?;
        (covers_exactly(&cert, names) && cert.not_after() > crate::sys::now_unix()).then_some(cert)
    }

    /// Where the certificate for `names` is saved, its chain (`fullchain.pem`) and key (`key.pem`): `certificates/<name>`
    /// in the CA's state directory for one name; for several, the first in alphabetical order and a hash of them all
    /// (`certificates/example.com-1a2b3c4d`), so that the order they are given in does not matter.
    pub fn certificate_dir(&self, names: &[&str]) -> Option<PathBuf> {
        Some(self.cert_dir(&normalize(names).ok()?))
    }

    fn cert_dir(&self, names: &[String]) -> PathBuf {
        let mut sorted = names.to_vec();
        sorted.sort();
        let mut dir: String = sorted[0].replace('*', "wildcard_").chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
        if sorted.len() > 1 {
            dir.push('-');
            dir.push_str(&crate::util::hex(&sha256(sorted.join("\n").as_bytes())[..4]));
        }
        self.0.dir.join("certificates").join(dir)
    }

    fn order(&self, names: &[String], replaces: Option<&str>) -> Result<CertifiedKey> {
        let config = &self.0.config;
        if config.tls_alpn01.is_none() && config.http01.is_none() && config.dns01.is_none() {
            return Err(AcmeError::new("no challenge is set up (AcmeConfig::tls_alpn01, http01 or dns01)"));
        }
        if let Some(w) = names.iter().find(|n| n.starts_with("*.")) {
            if config.dns01.is_none() {
                return Err(AcmeError::new(format!("{w} is a wildcard name, which only DNS-01 can validate (AcmeConfig::dns01)")));
            }
        }
        let _one_at_a_time = lock(&self.0.ordering);
        let dir = self.directory()?;
        let mut payload = Object::new();
        payload.insert("identifiers", Value::Array(names.iter().map(|n| identifier(n)).collect()));
        if let Some(p) = &config.profile {
            if !dir.profiles.is_empty() && !dir.profiles.iter().any(|q| q == p) {
                return Err(AcmeError::new(format!("the CA has no profile {p:?} (it has {})", dir.profiles.join(", "))));
            }
            payload.insert("profile", Value::string(p));
        }
        let without_replaces = Value::Object(payload.clone());
        if let Some(r) = replaces {
            payload.insert("replaces", Value::string(r));
        }
        let resp = match self.post(&dir.new_order, Some(&Value::Object(payload))) {
            // a CA that will not take the replacement (it was replaced already, or it does not know the certificate)
            Err(e) if replaces.is_some() && (e.is("alreadyReplaced") || e.is("malformed") || e.is("conflict")) => self.post(&dir.new_order, Some(&without_replaces))?,
            other => other?,
        };
        let order_url = resp.header("location").map(str::to_string).ok_or_else(|| AcmeError::new("the CA gave the new order no URL"))?;
        let order = parse_json(&resp)?;
        let deadline = Instant::now() + config.validation_timeout;

        // set up an answer for each authorization still pending
        let mut answers = Vec::new();
        let mut pending = Vec::new();
        for authz_url in order.get("authorizations").and_then(Value::as_array).unwrap_or(&[]) {
            let authz_url = authz_url.as_str().ok_or_else(|| AcmeError::new("an authorization URL that is not a string"))?;
            let authz = parse_json(&self.post(authz_url, None)?)?;
            let id = authz.get("identifier").and_then(|i| str_field(i, "value")).unwrap_or("?").to_string();
            match str_field(&authz, "status") {
                Some("valid") => continue,
                Some("pending") => {}
                other => return Err(AcmeError::new(format!("the authorization for {} is {}", clean(&id), other.unwrap_or("of no status")))),
            }
            let wildcard = authz.get("wildcard").and_then(Value::as_bool).unwrap_or(false);
            let challenges = authz.get("challenges").and_then(Value::as_array).unwrap_or(&[]);
            let (kind, challenge) = self.choose(challenges, wildcard).ok_or_else(|| {
                let offered: Vec<&str> = challenges.iter().filter_map(|c| str_field(c, "type")).collect();
                AcmeError::new(format!("the CA offers no challenge for {} that is set up here (it offers {})", clean(&id), clean(&offered.join(", "))))
            })?;
            let token = str_field(challenge, "token").filter(|t| b64url_decode(t).is_some_and(|b| b.len() >= 16)).ok_or_else(|| AcmeError::new("a challenge token that is not base64url of 128 bits or more"))?;
            let chall_url = str_field(challenge, "url").ok_or_else(|| AcmeError::new("a challenge with no URL"))?.to_string();
            let key_auth = self.0.key.key_authorization(token);
            answers.push(match kind {
                "tls-alpn-01" => {
                    let c = config.tls_alpn01.clone().expect("chosen because it is set up");
                    c.insert(&id, &key_auth)?;
                    Answer::TlsAlpn(c, id.clone())
                }
                "http-01" => {
                    let c = config.http01.clone().expect("chosen because it is set up");
                    c.insert(token, &key_auth);
                    Answer::Http(c, token.to_string())
                }
                _ => {
                    let hook = config.dns01.clone().expect("chosen because it is set up");
                    let (name, value) = (format!("_acme-challenge.{id}"), b64url(&sha256(key_auth.as_bytes())));
                    hook.present(&name, &value).map_err(|e| AcmeError::new(format!("the DNS-01 record for {}: {e}", clean(&id))))?;
                    Answer::Dns(hook, name, value)
                }
            });
            pending.push((authz_url.to_string(), chall_url, id, kind));
        }

        // tell the CA to check them, and wait for its verdicts
        for (_, chall_url, _, _) in &pending {
            self.post(chall_url, Some(&Value::Object(Object::new())))?;
        }
        for (authz_url, _, id, kind) in &pending {
            self.poll(authz_url, deadline, &format!("the validation of {id}"), |a| match str_field(a, "status") {
                Some("pending") => Poll::Again,
                Some("valid") => Poll::Done,
                status => {
                    let why = a
                        .get("challenges")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                        .iter()
                        .filter_map(|c| c.get("error"))
                        .find_map(embedded_problem)
                        .unwrap_or_else(|| AcmeError::new(format!("the authorization is {}", status.unwrap_or("of no status"))));
                    Poll::Fail(AcmeError { detail: format!("{} could not be validated with {kind}: {}", clean(id), why.detail), ..why })
                }
            })?;
        }
        drop(answers);

        // the order is ready once every authorization is valid: finalize it with a request for a new key
        let order = self.poll(&order_url, deadline, "the order", |o| match str_field(o, "status") {
            Some("pending") => Poll::Again,
            Some("ready") => Poll::Done,
            other => Poll::Fail(order_failure(o, other)),
        })?;
        let finalize = str_field(&order, "finalize").ok_or_else(|| AcmeError::new("an order with no finalize URL"))?;
        let key = SigningKey::generate_ecdsa(config.key_curve)?;
        let mut csr = Object::new();
        csr.insert("csr", Value::string(&b64url(&certificate_request(&key, names)?)));
        self.post(finalize, Some(&Value::Object(csr)))?;
        let order = self.poll(&order_url, Instant::now() + config.validation_timeout, "the issuance", |o| match str_field(o, "status") {
            Some("processing") | Some("ready") => Poll::Again,
            Some("valid") => Poll::Done,
            other => Poll::Fail(order_failure(o, other)),
        })?;
        let cert_url = str_field(&order, "certificate").ok_or_else(|| AcmeError::new("a valid order with no certificate URL"))?;
        let resp = self.post_signed(cert_url, None, false, Some("application/pem-certificate-chain"))?;
        let chain = resp.text();
        let key_pem = key.to_pkcs8_pem()?;
        let key_text = std::str::from_utf8(&key_pem).expect("PEM is ASCII");
        let cert = CertifiedKey::from_pem(&chain, key_text).map_err(|e| AcmeError::new(format!("the certificate the CA issued: {e}")))?;
        if !covers_exactly(&cert, names) {
            return Err(AcmeError::new(format!("the certificate the CA issued is for {:?}, not the names ordered", cert.dns_names())));
        }
        let dir = self.cert_dir(names);
        make_private_dir(&dir)?;
        write_file(&dir.join("key.pem"), &key_pem, true)?;
        write_file(&dir.join("fullchain.pem"), chain.as_bytes(), false)?;
        Ok(cert)
    }

    /// The challenge to answer: the first set up of TLS-ALPN-01, HTTP-01 and DNS-01 that the CA offers (for a wildcard,
    /// only DNS-01).
    fn choose<'a>(&self, challenges: &'a [Value], wildcard: bool) -> Option<(&'static str, &'a Value)> {
        let config = &self.0.config;
        let mut kinds = Vec::new();
        if config.tls_alpn01.is_some() && !wildcard {
            kinds.push("tls-alpn-01");
        }
        if config.http01.is_some() && !wildcard {
            kinds.push("http-01");
        }
        if config.dns01.is_some() {
            kinds.push("dns-01");
        }
        kinds.into_iter().find_map(|k| challenges.iter().find(|c| str_field(c, "type") == Some(k)).map(|c| (k, c)))
    }

    /// POST-as-GET `url` until `check` says it is done (or failed), waiting as the CA's `Retry-After` says (from a
    /// twentieth of a second to ten seconds), or a second growing to five, until `deadline`.
    fn poll(&self, url: &str, deadline: Instant, what: &str, check: impl Fn(&Value) -> Poll) -> Result<Value> {
        let mut wait = Duration::from_secs(1);
        loop {
            let resp = self.post(url, None)?;
            let v = parse_json(&resp)?;
            match check(&v) {
                Poll::Done => return Ok(v),
                Poll::Fail(e) => return Err(e),
                Poll::Again => {}
            }
            let pause = retry_after(&resp).map(Duration::from_secs).unwrap_or(wait).clamp(Duration::from_millis(50), Duration::from_secs(10));
            if Instant::now() + pause > deadline {
                return Err(AcmeError::new(format!("{what} is still {} at the end of the time allowed", str_field(&v, "status").unwrap_or("unfinished"))));
            }
            thread::sleep(pause);
            wait = (wait * 2).min(Duration::from_secs(5));
        }
    }

    /// The CA's renewal window for `cert` (ARI, RFC 9773), if the CA has renewal information.
    pub fn renewal_info(&self, cert: &CertifiedKey) -> Result<Option<RenewalWindow>> {
        let Some(base) = self.directory()?.renewal_info else { return Ok(None) };
        let id = cert_id(cert)?;
        let resp = self.0.client.get(&format!("{}/{id}", base.trim_end_matches('/')))?;
        if resp.status != 200 {
            return Err(problem(&resp));
        }
        let v = parse_json(&resp)?;
        let window = v.get("suggestedWindow");
        let time = |name: &str| window.and_then(|w| str_field(w, name)).and_then(crate::trust_root::parse_rfc3339).map(|(s, _)| s);
        let (Some(start), Some(end)) = (time("start"), time("end")) else {
            return Err(AcmeError::new("renewal information with no suggested window"));
        };
        if end <= start {
            return Err(AcmeError::new("renewal information whose window ends before it starts"));
        }
        let now = crate::sys::now_unix();
        // ask again when the CA says to, within an hour and a day; six hours when it does not say
        let again = retry_after(&resp).map_or(6 * 3600, |s| (s as i64).clamp(3600, 86_400));
        Ok(Some(RenewalWindow { start, end, explanation: str_field(&v, "explanationURL").map(clean), check_again: now + again }))
    }

    /// Revokes `cert` (signed with the account that got it), with a reason code of RFC 5280 (1 is key compromise).
    pub fn revoke(&self, cert: &CertifiedKey, reason: Option<u8>) -> Result<()> {
        let url = self.directory()?.revoke_cert.ok_or_else(|| AcmeError::new("the CA has no revokeCert endpoint"))?;
        let mut payload = Object::new();
        payload.insert("certificate", Value::string(&b64url(&cert.chain()[0])));
        if let Some(r) = reason {
            payload.insert("reason", Value::int(r as i64));
        }
        self.post(&url, Some(&Value::Object(payload)))?;
        Ok(())
    }
}

fn order_failure(order: &Value, status: Option<&str>) -> AcmeError {
    order.get("error").and_then(embedded_problem).unwrap_or_else(|| AcmeError::new(format!("the order is {}", status.unwrap_or("of no status"))))
}

fn valid_nonce(n: &str) -> bool {
    !n.is_empty() && n.len() <= 256 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The names of an order: trimmed, without a final dot, lower case, internationalized names as A-labels, IP addresses
/// in their usual form, without repeats.
pub(crate) fn normalize(names: &[&str]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim();
        let n = n.strip_suffix('.').unwrap_or(n);
        let name = if let Ok(ip) = n.parse::<IpAddr>() {
            ip.to_string()
        } else {
            let (wild, rest) = match n.strip_prefix("*.") {
                Some(rest) => ("*.", rest),
                None => ("", n),
            };
            let ascii = crate::idna::to_ascii(rest).map_err(|e| AcmeError::new(format!("{n:?} is not a name a certificate can have: {e:?}")))?;
            if ascii.is_empty() || ascii.contains('*') {
                return Err(AcmeError::new(format!("{n:?} is not a name a certificate can have")));
            }
            format!("{wild}{}", ascii.to_ascii_lowercase())
        };
        if !out.contains(&name) {
            out.push(name);
        }
    }
    if out.is_empty() {
        return Err(AcmeError::new("no names to order a certificate for"));
    }
    Ok(out)
}

fn identifier(name: &str) -> Value {
    let mut id = Object::new();
    id.insert("type", Value::string(if name.parse::<IpAddr>().is_ok() { "ip" } else { "dns" }));
    id.insert("value", Value::string(name));
    Value::Object(id)
}

/// Whether the certificate's names are exactly `names`.
fn covers_exactly(cert: &CertifiedKey, names: &[String]) -> bool {
    let Ok(leaf) = crate::x509::Certificate::parse(&cert.chain()[0]) else { return false };
    let mut have: Vec<String> = leaf.dns_names.iter().map(|n| n.to_ascii_lowercase()).collect();
    for ip in &leaf.ip_addrs {
        match ip.len() {
            4 => have.push(IpAddr::from(<[u8; 4]>::try_from(&ip[..]).expect("4 bytes")).to_string()),
            16 => have.push(IpAddr::from(<[u8; 16]>::try_from(&ip[..]).expect("16 bytes")).to_string()),
            _ => return false,
        }
    }
    let mut want = names.to_vec();
    have.sort();
    have.dedup();
    want.sort();
    have == want
}

/// The certificate's ARI identifier (RFC 9773 section 4.1): its authority key identifier and serial number, base64url.
pub(crate) fn cert_id(cert: &CertifiedKey) -> Result<String> {
    let leaf = crate::x509::Certificate::parse(&cert.chain()[0])?;
    let oid = crate::asn1::oid_from_string(OID_AKI).expect("a valid OID");
    let aki = leaf.extension(&oid).ok_or_else(|| AcmeError::new("the certificate has no authority key identifier"))?;
    let mut d = crate::asn1::Der::new(&aki.value);
    let mut seq = d.sequence()?;
    let key_id = seq.optional(0x80)?.ok_or_else(|| AcmeError::new("the certificate's authority key identifier has no key identifier"))?;
    Ok(format!("{}.{}", b64url(key_id.content), b64url(&leaf.serial_content)))
}

/// When to renew without the CA's word: two thirds of the way through the certificate's lifetime, or half of the way
/// for one of less than ten days.
pub fn default_renewal_time(cert: &CertifiedKey) -> i64 {
    let not_after = cert.not_after();
    let not_before = crate::x509::Certificate::parse(&cert.chain()[0]).map_or(not_after - 90 * 86_400, |c| c.not_before);
    let lifetime = (not_after - not_before).max(0);
    if lifetime < 10 * 86_400 {
        not_before + lifetime / 2
    } else {
        not_before + lifetime * 2 / 3
    }
}

/// A time in the window, chosen at random (RFC 9773 section 4.2); now if the window has started already and the time
/// chosen has passed.
fn time_in(window: &RenewalWindow) -> i64 {
    let span = (window.end - window.start).max(1) as u64;
    let r = crate::crypto::rand::bytes::<8>().map(u64::from_be_bytes).unwrap_or(0);
    window.start + (r % span) as i64
}

// ------------------------------------------------------------------------------------------------ files

/// The directory of a CA's state: its directory URL's host, port and path, in characters a file name can have.
pub(crate) fn ca_dir_name(directory: &str) -> String {
    let rest = directory.split_once("://").map_or(directory, |(_, r)| r);
    let name: String = rest.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') { c.to_ascii_lowercase() } else { '_' }).collect();
    name.trim_matches('_').to_string()
}

/// Makes a directory (and its parents) that only its owner can enter, and makes it so if it was there already.
fn make_private_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let made = builder.create(dir);
    #[cfg(unix)]
    let made = made.and_then(|_| std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)));
    made.map_err(|e| AcmeError::new(format!("{}: {e}", dir.display())))
}

/// Writes a file whole or not at all (a temporary file renamed over it), readable by its owner only if `secret`.
fn write_file(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let result = options.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    let result = result.and_then(|_| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| AcmeError::new(format!("{}: {e}", path.display())))
}

// ------------------------------------------------------------------------------------------------ the manager

/// Keeps `store` full of current certificates for each set of names in `certificates` (in order: the first is the
/// default certificate): the ones saved in the state directory at once, the others as soon as the CA issues them, and
/// each renewed at the time the CA's renewal information (checked every few hours) or, without it, its lifetime says
/// (see the module documentation). The store holds these certificates and no others. A failure is tried again after
/// [`AcmeConfig::retry_after_failure`], doubled after each one that follows (or when the CA says), while the
/// certificate in the store, if any, is served until it expires. What happens is given to `report`. Stops when the
/// returned handle is dropped.
pub fn manage(acme: Acme, certificates: Vec<Vec<String>>, store: Arc<CertStore>, report: impl Fn(&str) + Send + 'static) -> Reloader {
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let stop2 = stop.clone();
    let thread = thread::spawn(move || {
        struct Slot {
            names: Vec<String>,
            cert: Option<CertifiedKey>,
            renew_at: i64,
            window: Option<RenewalWindow>,
            ari_next: i64,
            failures: u32,
            retry_at: i64,
        }
        let now = crate::sys::now_unix();
        let mut slots: Vec<Slot> = Vec::new();
        for names in &certificates {
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            match normalize(&refs) {
                Ok(names) => {
                    let cert = acme.load_names(&names);
                    let renew_at = cert.as_ref().map_or(now, default_renewal_time);
                    slots.push(Slot { names, cert, renew_at, window: None, ari_next: now, failures: 0, retry_at: now });
                }
                Err(e) => report(&format!("{names:?}: {e}")),
            }
        }
        let publish = |slots: &[Slot]| store.replace(slots.iter().filter_map(|s| s.cert.clone()).collect());
        publish(&slots);
        for s in slots.iter().filter(|s| s.cert.is_some()) {
            report(&format!("certificate for {} loaded from {}", s.names.join(", "), acme.cert_dir(&s.names).display()));
        }
        let base = acme.0.config.retry_after_failure.as_secs().max(1) as i64;
        loop {
            let mut changed = false;
            for s in slots.iter_mut() {
                let now = crate::sys::now_unix();
                // the CA's renewal window
                if let (Some(cert), true) = (&s.cert, now >= s.ari_next) {
                    match acme.renewal_info(cert) {
                        Ok(Some(w)) => {
                            if s.window.as_ref().map(|o| (o.start, o.end)) != Some((w.start, w.end)) {
                                s.renew_at = time_in(&w);
                                let why = w.explanation.as_ref().map(|url| format!(" (the CA says why: {url})")).unwrap_or_default();
                                report(&format!(
                                    "renewal of the certificate for {} set for {}, in the CA's window{why}",
                                    s.names.join(", "),
                                    super::date::format(s.renew_at.max(0) as u64)
                                ));
                            }
                            s.ari_next = w.check_again;
                            s.window = Some(w);
                        }
                        Ok(None) => s.ari_next = i64::MAX,
                        Err(e) => {
                            report(&format!("renewal information for {}: {e}", s.names.join(", ")));
                            s.ari_next = now + 3600;
                        }
                    }
                }
                if (s.cert.is_none() || now >= s.renew_at) && now >= s.retry_at {
                    let replaces = s.cert.as_ref().filter(|_| s.window.is_some()).and_then(|c| cert_id(c).ok());
                    match acme.order(&s.names, replaces.as_deref()) {
                        Ok(cert) => {
                            report(&format!(
                                "certificate for {} {}, valid until {}",
                                s.names.join(", "),
                                if s.cert.is_some() { "renewed" } else { "obtained" },
                                super::date::format(cert.not_after().max(0) as u64)
                            ));
                            s.renew_at = default_renewal_time(&cert);
                            s.cert = Some(cert);
                            s.window = None;
                            s.ari_next = now;
                            s.failures = 0;
                            changed = true;
                        }
                        Err(e) => {
                            s.failures += 1;
                            let backoff = base.saturating_mul(1i64 << (s.failures - 1).min(20)).min(6 * 3600);
                            s.retry_at = e.retry_after.filter(|t| *t > now).unwrap_or(now + backoff);
                            report(&format!("certificate for {}: {e} (trying again at {})", s.names.join(", "), super::date::format(s.retry_at.max(0) as u64)));
                        }
                    }
                }
                if s.cert.as_ref().is_some_and(|c| c.not_after() <= crate::sys::now_unix()) {
                    report(&format!("the certificate for {} has expired and is no longer served", s.names.join(", ")));
                    s.cert = None;
                    changed = true;
                }
            }
            if changed {
                publish(&slots);
            }
            let now = crate::sys::now_unix();
            let next = slots
                .iter()
                .map(|s| {
                    let mut t = s.ari_next;
                    if let Some(c) = &s.cert {
                        t = t.min(c.not_after());
                    }
                    t.min(s.renew_at.max(s.retry_at))
                })
                .min()
                .unwrap_or(now + 3600);
            let wait = Duration::from_secs((next - now).clamp(1, 3600) as u64);
            let (lock_, cond) = &*stop2;
            let stopped = lock(lock_);
            let (stopped, _) = cond.wait_timeout_while(stopped, wait, |s| !*s).unwrap_or_else(|e| e.into_inner());
            if *stopped {
                return;
            }
        }
    });
    Reloader::new(stop, thread)
}
