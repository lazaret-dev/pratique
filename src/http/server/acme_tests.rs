//! ACME (B-113) against a CA of its own, served by this crate's HTTP server: the whole of RFC 8555's flow, each kind of
//! challenge validated for real (HTTP-01 over a socket, TLS-ALPN-01 with a handshake that offers `acme-tls/1`, DNS-01
//! through the hook), the CA's errors and refused nonces, external account binding, renewal information (ARI) and
//! replacement, the state directory, and the manager.

use super::acme::{
    b64url, b64url_decode, ca_dir_name, cert_id, certificate_request, challenge_certificate, default_renewal_time, manage, normalize,
    server_name_for, Acme, AcmeConfig, AcmeTlsAlpn01, Dns01,
};
use super::{AcmeHttp01, Request, Response, Server, ServerBuilder};
use crate::asn1::{self, write as der, Der};
use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::hmac::Hmac;
use crate::crypto::sha2::{Hash, HashAlg, Sha256};
use crate::http::Client;
use crate::json::{self, Object, Value};
use crate::sign::{EcdsaSigningKey, SigningKey};
use crate::tls::certs::{CertStore, CertifiedKey, ClientHelloInfo};
use crate::tls::pki::{issue, issue_for_spki, CertSpec, KeyPair, TestPki};
use crate::tls::server::ServerConfig;
use crate::tls::{ClientConfig, TlsStream};
use crate::x509::{parse_spki, Certificate, PublicKey, SigAlg, TrustStore};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn str_of<'a>(v: &'a Value, name: &str) -> &'a str {
    v.get(name).and_then(Value::as_str).unwrap_or("")
}

fn obj(members: &[(&str, Value)]) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v.clone());
    }
    Value::Object(o)
}

fn s(text: &str) -> Value {
    Value::string(text)
}

/// The RFC 7638 thumbprint of an EC JWK, computed here on its own.
fn thumbprint(jwk: &Value) -> String {
    let text = format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, str_of(jwk, "crv"), str_of(jwk, "x"), str_of(jwk, "y"));
    b64url(&sha256(text.as_bytes()))
}

/// A directory for one test's state, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!("pratique-acme-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&p);
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------------------------------------------ the CA

struct Order {
    ids: Vec<(String, String)>,
    authzs: Vec<usize>,
    cert: Option<usize>,
    /// polls that still answer "processing" after the finalization
    processing: usize,
    account: usize,
}

struct Authz {
    id: (String, String),
    wildcard: bool,
    challenges: Vec<(String, String)>,
    /// the validation's result: the challenge that passed, or the problem
    outcome: Option<Result<usize, Value>>,
    /// polls that still answer "pending" after the validation
    polls_left: usize,
}

#[derive(Default)]
struct CaState {
    nonce_counter: u64,
    nonces: HashSet<String>,
    /// good nonces to refuse anyway (badNonce), as a CA does after it restarts
    refuse_nonces: usize,
    /// (thumbprint, JWK) of each account; its URL is /acct/<index>
    accounts: Vec<(String, Value)>,
    orders: Vec<Order>,
    authzs: Vec<Authz>,
    /// (PEM chain, ARI identifier) of each certificate issued
    certs: Vec<(String, String)>,
    /// problems to answer the next new orders with: (status, type, Retry-After)
    reject_orders: VecDeque<(u16, &'static str, Option<u64>)>,
    /// the ARI identifiers of certificates whose renewal window has passed
    ari_past: HashSet<String>,
    /// the `replaces` of each new order
    replaces: Vec<Option<String>>,
    profiles: Vec<Option<String>>,
    eab: Option<(String, Vec<u8>)>,
    terms: bool,
    polls_before_valid: usize,
    lifetime: i64,
    revoked: Vec<Vec<u8>>,
    validations: Vec<String>,
    http_port: u16,
    tls_port: u16,
}

struct Ca {
    base: Mutex<String>,
    state: Mutex<CaState>,
    root: Vec<u8>,
    inter_key: KeyPair,
    inter: Vec<u8>,
    dns: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

const INTER_NAME: &str = "pratique test ACME intermediate";

impl Ca {
    fn start() -> (Arc<Ca>, Server) {
        let root_key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        let root = issue(&CertSpec::ca("pratique test ACME root"), &root_key, None);
        let inter_key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        let inter = issue(&CertSpec::ca(INTER_NAME), &inter_key, Some(("pratique test ACME root", &root_key)));
        let ca = Arc::new(Ca {
            base: Mutex::new(String::new()),
            state: Mutex::new(CaState { terms: true, lifetime: 90 * 86_400, ..CaState::default() }),
            root,
            inter_key,
            inter,
            dns: Arc::new(Mutex::new(HashMap::new())),
        });
        let c = ca.clone();
        let server = ServerBuilder::new(move |req: Request| c.handle(req)).plain("127.0.0.1:0").start().unwrap();
        *ca.base.lock().unwrap() = format!("http://{}", server.local_addrs()[0]);
        (ca, server)
    }

    fn base(&self) -> String {
        self.base.lock().unwrap().clone()
    }

    fn directory(&self) -> String {
        format!("{}/dir", self.base())
    }

    fn trust_store(&self) -> TrustStore {
        let mut t = TrustStore::empty();
        t.add_der(&self.root).unwrap();
        t
    }

    fn st(&self) -> std::sync::MutexGuard<'_, CaState> {
        self.state.lock().unwrap()
    }

    fn nonce(st: &mut CaState) -> String {
        st.nonce_counter += 1;
        let n = b64url(&[&st.nonce_counter.to_be_bytes()[..], &crate::crypto::rand::bytes::<8>().unwrap()].concat());
        st.nonces.insert(n.clone());
        n
    }

    fn reply(&self, st: &mut CaState, status: u16, body: &Value, location: Option<String>) -> Response {
        let mut r = Response::bytes(status, "application/json", json::canonical(body).unwrap()).with_header("replay-nonce", &Ca::nonce(st));
        if let Some(l) = location {
            r = r.with_header("location", &l);
        }
        r.with_header("retry-after", "0")
    }

    fn problem(&self, st: &mut CaState, status: u16, kind: &str, detail: &str) -> Response {
        let body = obj(&[("type", s(&format!("urn:ietf:params:acme:error:{kind}"))), ("detail", s(detail)), ("status", Value::int(status as i64))]);
        Response::bytes(status, "application/problem+json", json::canonical(&body).unwrap()).with_header("replay-nonce", &Ca::nonce(st))
    }

    fn handle(&self, mut req: Request) -> Response {
        let path = req.path().to_string();
        let base = self.base();
        let method = req.method().to_string();
        let body = req.read_body(1 << 20).unwrap_or_default();
        let mut st = self.st();
        match (method.as_str(), path.as_str()) {
            ("GET", "/dir") => {
                let mut meta = vec![("externalAccountRequired", Value::Bool(st.eab.is_some()))];
                if st.terms {
                    meta.push(("termsOfService", s(&format!("{base}/terms"))));
                }
                meta.push(("profiles", obj(&[("classic", s("90 days")), ("shortlived", s("6 days"))])));
                let d = obj(&[
                    ("newNonce", s(&format!("{base}/nonce"))),
                    ("newAccount", s(&format!("{base}/new-account"))),
                    ("newOrder", s(&format!("{base}/new-order"))),
                    ("revokeCert", s(&format!("{base}/revoke"))),
                    ("renewalInfo", s(&format!("{base}/renewal-info"))),
                    ("meta", obj(&meta)),
                ]);
                Response::bytes(200, "application/json", json::canonical(&d).unwrap())
            }
            ("HEAD", "/nonce") | ("GET", "/nonce") => Response::new(200).with_header("replay-nonce", &Ca::nonce(&mut st)).with_header("cache-control", "no-store"),
            ("GET", p) if p.starts_with("/renewal-info/") => {
                let id = &p["/renewal-info/".len()..];
                if !st.certs.iter().any(|(_, i)| i == id) {
                    return Response::new(404);
                }
                let now = crate::sys::now_unix();
                let (start, end) = if st.ari_past.contains(id) { (now - 7200, now - 3600) } else { (now + 30 * 86_400, now + 31 * 86_400) };
                let window = obj(&[("start", s(&rfc3339(start))), ("end", s(&rfc3339(end)))]);
                Response::bytes(200, "application/json", json::canonical(&obj(&[("suggestedWindow", window)])).unwrap()).with_header("retry-after", "21600")
            }
            ("POST", _) => match self.verify(&mut st, &path, &body) {
                Ok((account, jwk, payload)) => self.route(&mut st, &path, account, &jwk, payload, req.header("accept").map(str::to_string)),
                Err(r) => r,
            },
            _ => Response::new(404),
        }
    }

    /// Checks a JWS as RFC 8555 section 6.2 says: ES256, a nonce of ours (used once), the URL it was sent to, a JWK for
    /// a new account and a known account's URL otherwise, and the signature.
    fn verify(&self, st: &mut CaState, path: &str, body: &[u8]) -> Result<(Option<usize>, Value, Option<Value>), Response> {
        let Ok(jws) = json::parse(body) else { return Err(self.problem(st, 400, "malformed", "not JSON")) };
        let (p64, pl64, sig64) = (str_of(&jws, "protected"), str_of(&jws, "payload"), str_of(&jws, "signature"));
        let Some(protected) = b64url_decode(p64).and_then(|b| json::parse(&b).ok()) else { return Err(self.problem(st, 400, "malformed", "protected")) };
        if str_of(&protected, "alg") != "ES256" {
            return Err(self.problem(st, 400, "badSignatureAlgorithm", "ES256 only"));
        }
        if !st.nonces.remove(str_of(&protected, "nonce")) {
            return Err(self.problem(st, 400, "badNonce", "not a nonce of ours"));
        }
        if st.refuse_nonces > 0 {
            st.refuse_nonces -= 1;
            return Err(self.problem(st, 400, "badNonce", "refused for the test"));
        }
        if str_of(&protected, "url") != format!("{}{path}", self.base()) {
            return Err(self.problem(st, 401, "unauthorized", "the wrong url"));
        }
        let (account, jwk) = match (protected.get("jwk"), protected.get("kid")) {
            (Some(jwk), None) if path == "/new-account" => (None, jwk.clone()),
            (None, Some(kid)) if path != "/new-account" => {
                let i = kid.as_str().and_then(|k| k.strip_prefix(&format!("{}/acct/", self.base()))).and_then(|i| i.parse::<usize>().ok());
                match i.filter(|i| *i < st.accounts.len()) {
                    Some(i) => (Some(i), st.accounts[i].1.clone()),
                    None => return Err(self.problem(st, 400, "accountDoesNotExist", "no such account")),
                }
            }
            _ => return Err(self.problem(st, 400, "malformed", "jwk for a new account, kid otherwise")),
        };
        let point = [&[4u8][..], &b64url_decode(str_of(&jwk, "x")).unwrap_or_default(), &b64url_decode(str_of(&jwk, "y")).unwrap_or_default()].concat();
        let sig = b64url_decode(sig64).unwrap_or_default();
        let good = sig.len() == 64 && {
            let der_sig = der::sequence(&[&der::integer(&sig[..32]), &der::integer(&sig[32..])]);
            ecdsa::verify(Curve::P256, &point, HashAlg::Sha256, format!("{p64}.{pl64}").as_bytes(), &der_sig)
        };
        if !good {
            return Err(self.problem(st, 400, "malformed", "the signature does not verify"));
        }
        let payload = if pl64.is_empty() {
            None
        } else {
            match b64url_decode(pl64).and_then(|b| json::parse(&b).ok()) {
                Some(v) => Some(v),
                None => return Err(self.problem(st, 400, "malformed", "payload")),
            }
        };
        Ok((account, jwk, payload))
    }

    fn route(&self, st: &mut CaState, path: &str, account: Option<usize>, jwk: &Value, payload: Option<Value>, accept: Option<String>) -> Response {
        let base = self.base();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let index = |i: usize| parts.get(i).and_then(|p| p.parse::<usize>().ok());
        match parts[0] {
            "new-account" => {
                let payload = payload.unwrap_or(Value::Null);
                let thumb = thumbprint(jwk);
                if let Some(i) = st.accounts.iter().position(|(t, _)| *t == thumb) {
                    return self.reply(st, 200, &obj(&[("status", s("valid"))]), Some(format!("{base}/acct/{i}")));
                }
                if st.terms && payload.get("termsOfServiceAgreed").and_then(Value::as_bool) != Some(true) {
                    return self.problem(st, 400, "malformed", "the terms of service must be agreed to");
                }
                if let Some((kid, key)) = st.eab.clone() {
                    let Some(eab) = payload.get("externalAccountBinding") else { return self.problem(st, 400, "externalAccountRequired", "no binding") };
                    let (p64, pl64) = (str_of(eab, "protected"), str_of(eab, "payload"));
                    let protected = b64url_decode(p64).and_then(|b| json::parse(&b).ok()).unwrap_or(Value::Null);
                    let bound = b64url_decode(pl64).and_then(|b| json::parse(&b).ok());
                    let mac = Hmac::<Sha256>::mac(&key, format!("{p64}.{pl64}").as_bytes());
                    if str_of(&protected, "alg") != "HS256"
                        || str_of(&protected, "kid") != kid
                        || str_of(&protected, "url") != format!("{base}/new-account")
                        || bound.as_ref() != Some(jwk)
                        || b64url_decode(str_of(eab, "signature")) != Some(mac)
                    {
                        return self.problem(st, 400, "unauthorized", "the external account binding does not verify");
                    }
                }
                st.accounts.push((thumb, jwk.clone()));
                let i = st.accounts.len() - 1;
                self.reply(st, 201, &obj(&[("status", s("valid"))]), Some(format!("{base}/acct/{i}")))
            }
            "new-order" => {
                if let Some((status, kind, retry)) = st.reject_orders.pop_front() {
                    let mut r = self.problem(st, status, kind, "refused for the test");
                    if kind == "rejectedIdentifier" {
                        let body = obj(&[
                            ("type", s("urn:ietf:params:acme:error:rejectedIdentifier")),
                            ("detail", s("Error creating new order")),
                            (
                                "subproblems",
                                Value::Array(vec![obj(&[
                                    ("type", s("urn:ietf:params:acme:error:rejectedIdentifier")),
                                    ("detail", s("the policy forbids it")),
                                    ("identifier", obj(&[("type", s("dns")), ("value", s("bad.test"))])),
                                ])]),
                            ),
                        ]);
                        r = Response::bytes(status, "application/problem+json", json::canonical(&body).unwrap()).with_header("replay-nonce", &Ca::nonce(st));
                    }
                    if let Some(secs) = retry {
                        r = r.with_header("retry-after", &secs.to_string());
                    }
                    return r;
                }
                let payload = payload.unwrap_or(Value::Null);
                let mut ids = Vec::new();
                let mut authzs = Vec::new();
                for id in payload.get("identifiers").and_then(Value::as_array).unwrap_or(&[]) {
                    let (kind, value) = (str_of(id, "type").to_string(), str_of(id, "value").to_string());
                    let wildcard = value.starts_with("*.");
                    let kinds: &[&str] = if kind == "ip" {
                        &["http-01", "tls-alpn-01"]
                    } else if wildcard {
                        &["dns-01"]
                    } else {
                        &["http-01", "dns-01", "tls-alpn-01"]
                    };
                    let challenges = kinds.iter().map(|k| (k.to_string(), b64url(&crate::crypto::rand::bytes::<32>().unwrap()))).collect();
                    let polls_left = st.polls_before_valid;
                    st.authzs.push(Authz { id: (kind.clone(), value.trim_start_matches("*.").to_string()), wildcard, challenges, outcome: None, polls_left });
                    authzs.push(st.authzs.len() - 1);
                    ids.push((kind, value));
                }
                st.replaces.push(payload.get("replaces").and_then(Value::as_str).map(str::to_string));
                st.profiles.push(payload.get("profile").and_then(Value::as_str).map(str::to_string));
                st.orders.push(Order { ids, authzs, cert: None, processing: 0, account: account.unwrap() });
                let i = st.orders.len() - 1;
                let body = self.order_json(st, i);
                self.reply(st, 201, &body, Some(format!("{base}/order/{i}")))
            }
            "order" => {
                let Some(i) = index(1).filter(|i| *i < st.orders.len() && st.orders[*i].account == account.unwrap()) else { return Response::new(404) };
                let body = self.order_json(st, i);
                if st.orders[i].processing > 0 {
                    st.orders[i].processing -= 1;
                }
                self.reply(st, 200, &body, None)
            }
            "authz" => {
                let Some(k) = index(1).filter(|k| *k < st.authzs.len()) else { return Response::new(404) };
                let body = self.authz_json(st, k);
                if st.authzs[k].outcome.is_some() && st.authzs[k].polls_left > 0 {
                    st.authzs[k].polls_left -= 1;
                }
                self.reply(st, 200, &body, None)
            }
            "chall" => {
                let (Some(k), Some(j)) = (index(1), index(2)) else { return Response::new(404) };
                let Some((kind, token)) = st.authzs.get(k).and_then(|a| a.challenges.get(j)).cloned() else { return Response::new(404) };
                let key_auth = format!("{token}.{}", thumbprint(jwk));
                let (id_kind, name) = st.authzs[k].id.clone();
                let result = match kind.as_str() {
                    "http-01" => self.check_http(st.http_port, &name, &token, &key_auth),
                    "tls-alpn-01" => self.check_tls(st.tls_port, &id_kind, &name, &key_auth),
                    _ => self.check_dns(&name, &key_auth),
                };
                st.validations.push(format!("{kind} {name}: {}", if result.is_ok() { "ok" } else { "failed" }));
                st.authzs[k].outcome = Some(match result {
                    Ok(()) => Ok(j),
                    Err((t, d)) => Err(obj(&[("type", s(&format!("urn:ietf:params:acme:error:{t}"))), ("detail", s(&d))])),
                });
                let body = obj(&[("type", s(&kind)), ("url", s(&format!("{base}/chall/{k}/{j}"))), ("token", s(&token)), ("status", s("processing"))]);
                self.reply(st, 200, &body, None)
            }
            "finalize" => {
                let Some(i) = index(1).filter(|i| *i < st.orders.len()) else { return Response::new(404) };
                if str_of(&self.order_json(st, i), "status") != "ready" {
                    return self.problem(st, 403, "orderNotReady", "not ready");
                }
                let csr = payload.as_ref().map(|p| str_of(p, "csr")).and_then(b64url_decode).unwrap_or_default();
                let Some((spki, names)) = parse_csr(&csr) else { return self.problem(st, 400, "badCSR", "the request does not verify") };
                let mut want: Vec<String> = st.orders[i].ids.iter().map(|(_, v)| v.clone()).collect();
                let mut got = names.clone();
                want.sort();
                got.sort();
                if want != got {
                    return self.problem(st, 400, "badCSR", "the request's names are not the order's");
                }
                let now = crate::sys::now_unix();
                let serial = u64::from_be_bytes(crate::crypto::rand::bytes::<8>().unwrap()) >> 1;
                let mut spec = CertSpec::server(&names.iter().map(String::as_str).collect::<Vec<_>>());
                spec.not_before = now - 60;
                spec.not_after = now + st.lifetime;
                spec.serial = serial;
                let leaf = issue_for_spki(&spec, &spki, INTER_NAME, &self.inter_key);
                let chain = format!("{}{}", pem("CERTIFICATE", &leaf), pem("CERTIFICATE", &self.inter));
                // ARI's identifier, made here from what the CA knows: its key identifier (pki's: the first 20 bytes of the
                // SHA-256 of the key) and the serial number's INTEGER content
                let serial_content = der::integer(&serial.to_be_bytes())[2..].to_vec();
                let id = format!("{}.{}", b64url(&sha256(&self.inter_key.public())[..20]), b64url(&serial_content));
                st.certs.push((chain, id));
                st.orders[i].cert = Some(st.certs.len() - 1);
                st.orders[i].processing = 1;
                let body = self.order_json(st, i);
                self.reply(st, 200, &body, None)
            }
            "cert" => {
                let Some(c) = index(1).filter(|c| *c < st.certs.len()) else { return Response::new(404) };
                if accept.as_deref() != Some("application/pem-certificate-chain") {
                    return self.problem(st, 406, "malformed", "accept");
                }
                let chain = st.certs[c].0.clone();
                Response::bytes(200, "application/pem-certificate-chain", chain.into_bytes()).with_header("replay-nonce", &Ca::nonce(st))
            }
            "revoke" => {
                let der_cert = payload.as_ref().map(|p| str_of(p, "certificate")).and_then(b64url_decode).unwrap_or_default();
                st.revoked.push(der_cert);
                self.reply(st, 200, &Value::Object(Object::new()), None)
            }
            _ => self.problem(st, 404, "malformed", "no such resource"),
        }
    }

    fn order_json(&self, st: &CaState, i: usize) -> Value {
        let base = self.base();
        let o = &st.orders[i];
        let outcomes: Vec<Option<bool>> = o.authzs.iter().map(|k| st.authzs[*k].outcome.as_ref().map(|r| r.is_ok())).collect();
        let status = match o.cert {
            Some(_) if o.processing > 0 => "processing",
            Some(_) => "valid",
            None if outcomes.contains(&Some(false)) => "invalid",
            None if outcomes.iter().all(|r| *r == Some(true)) && o.authzs.iter().all(|k| st.authzs[*k].polls_left == 0) => "ready",
            None => "pending",
        };
        let mut members = vec![
            ("status", s(status)),
            ("identifiers", Value::Array(o.ids.iter().map(|(t, v)| obj(&[("type", s(t)), ("value", s(v))])).collect())),
            ("authorizations", Value::Array(o.authzs.iter().map(|k| s(&format!("{base}/authz/{k}"))).collect())),
            ("finalize", s(&format!("{base}/finalize/{i}"))),
        ];
        if let (Some(c), "valid") = (o.cert, status) {
            members.push(("certificate", s(&format!("{base}/cert/{c}"))));
        }
        obj(&members)
    }

    fn authz_json(&self, st: &CaState, k: usize) -> Value {
        let base = self.base();
        let a = &st.authzs[k];
        let status = match &a.outcome {
            None => "pending",
            Some(_) if a.polls_left > 0 => "pending",
            Some(Ok(_)) => "valid",
            Some(Err(_)) => "invalid",
        };
        let challenges = a
            .challenges
            .iter()
            .enumerate()
            .map(|(j, (kind, token))| {
                let mut m = vec![("type", s(kind)), ("url", s(&format!("{base}/chall/{k}/{j}"))), ("token", s(token))];
                match (&a.outcome, status) {
                    (Some(Ok(passed)), "valid") if *passed == j => m.push(("status", s("valid"))),
                    (Some(Err(e)), "invalid") => {
                        m.push(("status", s("invalid")));
                        m.push(("error", e.clone()));
                    }
                    _ => m.push(("status", s("pending"))),
                }
                obj(&m)
            })
            .collect();
        let mut members = vec![("status", s(status)), ("identifier", obj(&[("type", s(&a.id.0)), ("value", s(&a.id.1))])), ("challenges", Value::Array(challenges))];
        if a.wildcard {
            members.push(("wildcard", Value::Bool(true)));
        }
        obj(&members)
    }

    /// HTTP-01: a GET for the token, as a validator sends it (to the test's port rather than 80).
    fn check_http(&self, port: u16, name: &str, token: &str, key_auth: &str) -> Result<(), (&'static str, String)> {
        let mut c = TcpStream::connect(("127.0.0.1", port)).map_err(|e| ("connection", e.to_string()))?;
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(c, "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let text = String::from_utf8_lossy(&out);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        if !head.starts_with("HTTP/1.1 200") {
            return Err(("unauthorized", format!("the answer was {:?}", head.lines().next().unwrap_or(""))));
        }
        if body != key_auth {
            return Err(("incorrectResponse", "the key authorization is wrong".into()));
        }
        Ok(())
    }

    /// TLS-ALPN-01 (RFC 8737 section 3): a handshake offering only `acme-tls/1`, for the identifier's name (an IP
    /// address's reverse name), that must choose it and present a certificate for the identifier alone with the critical
    /// acmeIdentifier extension holding the SHA-256 of the key authorization; the server then ends the connection.
    fn check_tls(&self, port: u16, kind: &str, name: &str, key_auth: &str) -> Result<(), (&'static str, String)> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| ("connection", e.to_string()))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut config = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
        let sni = if kind == "ip" { server_name_for(name) } else { name.to_string() };
        let mut tls = TlsStream::connect(tcp, &sni, &config).map_err(|e| ("tls", e.to_string()))?;
        if tls.alpn_protocol() != Some(&b"acme-tls/1"[..]) {
            return Err(("tls", "acme-tls/1 was not chosen".into()));
        }
        let leaf = Certificate::parse(&tls.peer_certificates()[0]).map_err(|e| ("tls", e.to_string()))?;
        let oid = asn1::oid_from_string(ACME_IDENTIFIER).unwrap();
        let ext = leaf.extension(&oid).ok_or(("tls", "no acmeIdentifier extension".to_string()))?;
        if !ext.critical || ext.value != der::octet_string(&sha256(key_auth.as_bytes())) {
            return Err(("incorrectResponse", "the acmeIdentifier is wrong".into()));
        }
        let names_right = match kind {
            "ip" => leaf.dns_names.is_empty() && leaf.ip_addrs.len() == 1 && IpAddr::from(<[u8; 4]>::try_from(&leaf.ip_addrs[0][..]).unwrap()).to_string() == name,
            _ => leaf.dns_names == [name.to_string()] && leaf.ip_addrs.is_empty(),
        };
        if !names_right {
            return Err(("incorrectResponse", "the certificate is not for the identifier alone".into()));
        }
        // nothing follows the handshake but the end of the connection
        let mut buf = [0u8; 16];
        match tls.read(&mut buf) {
            Ok(0) => Ok(()),
            other => Err(("tls", format!("the server did not end the connection: {other:?}"))),
        }
    }

    fn check_dns(&self, name: &str, key_auth: &str) -> Result<(), (&'static str, String)> {
        let want = b64url(&sha256(key_auth.as_bytes()));
        let records = self.dns.lock().unwrap();
        match records.get(&format!("_acme-challenge.{name}")) {
            Some(values) if values.contains(&want) => Ok(()),
            _ => Err(("unauthorized", "no TXT record with the value".into())),
        }
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = crate::pem::base64_encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// The public key and the names of a certificate request, if its signature (ECDSA) verifies.
fn parse_csr(csr: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let mut d = Der::new(csr);
    let mut outer = d.sequence().ok()?;
    let info = outer.next().ok()?;
    outer.next().ok()?; // the algorithm
    let sig = asn1::bit_string_bytes(&outer.next().ok()?).ok()?.to_vec();
    let mut i = Der::new(info.content);
    i.next().ok()?; // version
    i.next().ok()?; // subject
    let spki = i.next().ok()?.raw.to_vec();
    let attrs = i.next().ok()?;
    let key = parse_spki(&spki).ok()?;
    let hash = match &key {
        PublicKey::Ec { curve: Curve::P384, .. } => HashAlg::Sha384,
        _ => HashAlg::Sha256,
    };
    if !crate::x509::verify_signature(Some(SigAlg::Ecdsa(hash)), &key, info.raw, &sig) {
        return None;
    }
    // [0] { Attribute { extensionRequest, SET { Extensions { Extension { subjectAltName, OCTET STRING { GeneralNames } } } } } }
    let mut a = Der::new(attrs.content);
    let mut attr = a.sequence().ok()?;
    attr.next().ok()?;
    let mut set = Der::new(attr.next().ok()?.content);
    let mut exts = set.sequence().ok()?;
    let mut ext = exts.sequence().ok()?;
    ext.next().ok()?;
    let value = ext.next().ok()?;
    let mut gn = Der::new(value.content);
    let mut names_seq = gn.sequence().ok()?;
    let mut names = Vec::new();
    while !names_seq.is_empty() {
        let n = names_seq.next().ok()?;
        match n.tag {
            0x82 => names.push(String::from_utf8(n.content.to_vec()).ok()?),
            0x87 if n.content.len() == 4 => names.push(IpAddr::from(<[u8; 4]>::try_from(n.content).ok()?).to_string()),
            0x87 => names.push(IpAddr::from(<[u8; 16]>::try_from(n.content).ok()?).to_string()),
            _ => return None,
        }
    }
    Some((spki, names))
}

// ------------------------------------------------------------------------------------------------ the server side

fn client() -> Client {
    Client::with_tls_config(ClientConfig::new(TrustStore::empty())).allow_insecure_http(true).timeout(Duration::from_secs(5))
}

fn config(ca: &Ca, dir: &Path) -> AcmeConfig {
    AcmeConfig::new(&ca.directory(), dir).client(client()).contact("mailto:admin@example.test").agree_to_terms().validation_timeout(Duration::from_secs(20))
}

/// A plain server that answers HTTP-01 challenges (and a page otherwise), as port 80 would.
fn http01_server(ca: &Ca) -> (AcmeHttp01, Server) {
    let http01 = AcmeHttp01::new();
    let server = ServerBuilder::new(http01.wrap(|_req: Request| Response::text(200, "the site\n"))).plain("127.0.0.1:0").start().unwrap();
    ca.st().http_port = server.local_addrs()[0].port();
    (http01, server)
}

/// A TLS server whose certificates are in a store that starts empty, answering TLS-ALPN-01 challenges, as port 443 would.
fn tls_server(ca: &Ca) -> (AcmeTlsAlpn01, Arc<CertStore>, Server) {
    let challenges = AcmeTlsAlpn01::new();
    let mut tls = ServerConfig::with_certificates(CertStore::new()).with_alpn(&["h2", "http/1.1"]);
    let store = tls.store.clone().unwrap();
    tls.certs = challenges.wrap(tls.certs.clone());
    let server = ServerBuilder::new(|req: Request| Response::text(200, format!("hello {}\n", req.path()))).tls("127.0.0.1:0", Arc::new(tls)).start().unwrap();
    ca.st().tls_port = server.local_addrs()[0].port();
    (challenges, store, server)
}

/// A handshake with the TLS server for `name`, trusting the CA's root: the ALPN protocol it chose.
fn handshake(server: &Server, name: &str, trust: TrustStore, alpn: &[&str]) -> crate::error::Result<Option<Vec<u8>>> {
    let tcp = TcpStream::connect(server.local_addrs()[0]).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut config = ClientConfig::new(trust);
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let tls = TlsStream::connect(tcp, name, &config)?;
    Ok(tls.alpn_protocol().map(<[u8]>::to_vec))
}

struct Dns(Arc<Mutex<HashMap<String, Vec<String>>>>, Arc<Mutex<usize>>);

impl Dns01 for Dns {
    fn present(&self, name: &str, value: &str) -> Result<(), String> {
        let mut records = self.0.lock().unwrap();
        let values = records.entry(name.to_string()).or_default();
        values.push(value.to_string());
        let mut most = self.1.lock().unwrap();
        *most = (*most).max(values.len());
        Ok(())
    }
    fn cleanup(&self, name: &str, value: &str) {
        if let Some(values) = self.0.lock().unwrap().get_mut(name) {
            values.retain(|v| v != value);
        }
    }
}

// ------------------------------------------------------------------------------------------------ the tests

#[test]
fn the_account_key_its_jwk_and_its_thumbprint_are_as_the_rfcs_say() {
    // RFC 7517 appendix A.2's P-256 key: its public point is A.1's x and y, and its thumbprint (RFC 7638) is the SHA-256
    // of the JWK's required members in order, computed independently
    let d = b64url_decode("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE").unwrap();
    let key = EcdsaSigningKey::from_scalar(Curve::P256, &d).unwrap();
    let x = b64url_decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4").unwrap();
    let y = b64url_decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM").unwrap();
    assert_eq!(key.public_key(), [&[4u8][..], &x, &y].concat());
    let tmp = TempDir::new();
    let dir = tmp.0.join(ca_dir_name("https://acme.example/directory"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("account.key"), &SigningKey::from(key).to_pkcs8_pem().unwrap()[..]).unwrap();
    let acme = Acme::new(AcmeConfig::new("https://acme.example/directory", &tmp.0).client(client())).unwrap();
    assert_eq!(acme.state_dir(), dir.as_path());
    assert_eq!(acme.thumbprint(), "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");

    assert_eq!(b64url(&[0xfb, 0xff, 0xfe]), "-__-");
    assert_eq!(b64url(b"a"), "YQ");
    assert_eq!(b64url_decode("-__-"), Some(vec![0xfb, 0xff, 0xfe]));
    assert_eq!(b64url_decode("YQ=="), None, "base64url is unpadded");
    assert_eq!(b64url_decode("Y+Q"), None);
    assert_eq!(ca_dir_name("https://acme-v02.api.letsencrypt.org/directory"), "acme-v02.api.letsencrypt.org_directory");
    assert_eq!(ca_dir_name("https://localhost:14000/dir"), "localhost_14000_dir");
}

#[test]
fn names_are_normalized_and_requests_and_challenge_certificates_are_well_formed() {
    let n = normalize(&["Example.COM.", "www.example.com", "example.com", " bücher.example ", "*.Wild.example", "::FFFF:1.2.3.4", "127.0.0.1"]).unwrap();
    assert_eq!(n, ["example.com", "www.example.com", "xn--bcher-kva.example", "*.wild.example", "::ffff:1.2.3.4", "127.0.0.1"]);
    assert!(normalize(&[]).is_err());
    assert!(normalize(&["a.*.example"]).is_err());
    assert!(normalize(&[""]).is_err());

    // the request: the names in subjectAltName (DNS names and IP addresses), signed by the key
    let key = SigningKey::generate_ecdsa(Curve::P256).unwrap();
    let names: Vec<String> = ["a.example", "*.b.example", "192.0.2.1", "2001:db8::1"].iter().map(|s| s.to_string()).collect();
    let csr = certificate_request(&key, &names).unwrap();
    let (spki, got) = parse_csr(&csr).expect("the request verifies");
    assert_eq!(spki, key.public_key_spki());
    assert_eq!(got, names);
    let mut broken = csr.clone();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert!(parse_csr(&broken).is_none(), "a damaged signature is refused");

    // a challenge certificate: self-signed, the identifier alone, the critical acmeIdentifier extension; X.509 refuses
    // it (as anything but an ACME validator must), the TLS server presents it only for acme-tls/1
    let key_auth = "token.thumbprint";
    for (id, ip) in [("a.example", None), ("192.0.2.1", Some(vec![192, 0, 2, 1]))] {
        let c = challenge_certificate(id, key_auth).unwrap();
        assert!(c.is_acme_challenge());
        assert!(Certificate::from_der(&c.chain()[0]).is_err(), "an unknown critical extension");
        let leaf = Certificate::parse(&c.chain()[0]).unwrap();
        let ext = leaf.extension(&asn1::oid_from_string(ACME_IDENTIFIER).unwrap()).unwrap();
        assert!(ext.critical);
        assert_eq!(ext.value, der::octet_string(&sha256(key_auth.as_bytes())));
        match ip {
            Some(ip) => assert_eq!((leaf.dns_names.len(), leaf.ip_addrs.clone()), (0, vec![ip])),
            None => assert_eq!(leaf.dns_names, [id]),
        }
        assert!(leaf.verify_signed_by(&leaf).is_ok());
    }
    // only a certificate with the extension, and only with its own key
    let pki = TestPki::new(&["a.example"]).unwrap();
    assert!(CertifiedKey::acme_tls_alpn_challenge(pki.chain[0].clone(), pki.server_key.signing_key().clone()).is_err());
    let c = challenge_certificate("a.example", key_auth).unwrap();
    assert!(CertifiedKey::acme_tls_alpn_challenge(c.chain()[0].clone(), SigningKey::generate_ecdsa(Curve::P256).unwrap()).is_err());
    assert!(CertifiedKey::acme_tls_alpn_challenge(c.chain()[0].clone(), c.key().clone()).is_ok());
    // the reverse names a validator sends for an IP address (RFC 8738 section 6)
    assert_eq!(server_name_for("192.0.2.1"), "1.2.0.192.in-addr.arpa");
    assert_eq!(server_name_for("2001:db8::1"), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    assert_eq!(server_name_for("A.Example."), "a.example");
}

#[test]
fn a_challenge_certificate_goes_only_to_a_client_offering_acme_tls_and_the_connection_then_ends() {
    let pki = TestPki::new(&["a.test"]).unwrap();
    let challenges = AcmeTlsAlpn01::new();
    let mut tls = ServerConfig::from_pki(&pki).with_alpn(&["h2", "http/1.1"]);
    tls.certs = challenges.wrap(tls.certs.clone());
    let resolver = tls.certs.clone();
    let server = ServerBuilder::new(|_req: Request| Response::text(200, "site\n")).tls("127.0.0.1:0", Arc::new(tls)).start().unwrap();
    challenges.insert("a.test", "tok.thumb").unwrap();

    // a browser gets the site's certificate and h2, whatever challenge is waiting
    assert_eq!(handshake(&server, "a.test", pki.trust_store(), &["h2", "http/1.1"]).unwrap(), Some(b"h2".to_vec()));
    // a validator gets the challenge certificate and acme-tls/1, and then the end of the connection
    let tcp = TcpStream::connect(server.local_addrs()[0]).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut config = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let mut v = TlsStream::connect(tcp, "a.test", &config).unwrap();
    assert_eq!(v.alpn_protocol(), Some(&b"acme-tls/1"[..]));
    let leaf = Certificate::parse(&v.peer_certificates()[0]).unwrap();
    assert!(leaf.extension(&asn1::oid_from_string(ACME_IDENTIFIER).unwrap()).is_some(), "the challenge certificate");
    assert!(!v.is_resumed());
    let mut buf = [0u8; 8];
    assert_eq!(v.read(&mut buf).unwrap(), 0, "closed after the handshake");
    // a name with no challenge, or one taken back: no acme-tls/1 (the site's certificate is not for it)
    let refused = |name: &str| {
        let tcp = TcpStream::connect(server.local_addrs()[0]).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        TlsStream::connect(tcp, name, &config).is_err()
    };
    assert!(refused("b.test"));
    challenges.remove("a.test");
    assert!(refused("a.test"));
    // the resolver: the challenge only for a hello offering acme-tls/1 for its name
    challenges.insert("a.test", "tok.thumb").unwrap();
    let schemes = [0x0403, 0x0807];
    let pick = |name: &str, alpn: &[&[u8]]| {
        let alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
        resolver.resolve(&ClientHelloInfo { server_name: Some(name), signature_schemes: &schemes, signature_schemes_cert: None, alpn: Some(&alpn) }).unwrap().is_acme_challenge()
    };
    assert!(pick("a.test", &[b"acme-tls/1"]));
    assert!(pick("A.TEST.", &[b"acme-tls/1"]));
    assert!(!pick("a.test", &[b"h2"]));
    assert!(!pick("b.test", &[b"acme-tls/1"]));
}

#[test]
fn http01_gets_a_certificate_that_the_server_can_serve_and_saves_it() {
    let (ca, _ca_server) = Ca::start();
    let (http01, _web) = http01_server(&ca);
    let tmp = TempDir::new();
    ca.st().polls_before_valid = 2;
    let acme = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap();
    let cert = acme.obtain(&["a.test", "B.test", "a.test"]).unwrap();
    assert_eq!(cert.dns_names(), ["a.test", "b.test"]);
    assert_eq!(cert.chain().len(), 2, "the leaf and the intermediate");
    assert_eq!(cert.key().algorithm(), "ECDSA P-256");
    {
        let st = ca.st();
        assert_eq!(st.validations, ["http-01 a.test: ok", "http-01 b.test: ok"]);
        assert_eq!(st.accounts.len(), 1);
        assert_eq!(st.replaces, [None]);
    }
    // the challenge answers were taken back
    let token = ca.st().authzs[0].challenges[0].1.clone();
    assert!(ca.check_http(ca.st().http_port, "a.test", &token, "x").is_err());

    // what a client that trusts the CA sees
    let store = CertStore::single(cert.clone());
    let server = ServerBuilder::new(|_req: Request| Response::text(200, "ok\n"))
        .tls("127.0.0.1:0", Arc::new(ServerConfig::with_certificates(store).with_alpn(&["http/1.1"])))
        .start()
        .unwrap();
    assert_eq!(handshake(&server, "b.test", ca.trust_store(), &["http/1.1"]).unwrap(), Some(b"http/1.1".to_vec()));

    // saved: the key readable by its owner only
    let dir = acme.certificate_dir(&["a.test", "b.test"]).unwrap();
    assert!(dir.join("fullchain.pem").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.join("key.pem")), 0o600);
        assert_eq!(mode(acme.state_dir().join("account.key")), 0o600);
        assert_eq!(mode(acme.state_dir().to_path_buf()), 0o700);
    }
    // and found again, by a new client with the same state: the same account, the same certificate
    let again = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap();
    assert_eq!(again.thumbprint(), acme.thumbprint());
    assert_eq!(again.account_url().unwrap(), acme.account_url().unwrap());
    assert_eq!(ca.st().accounts.len(), 1);
    assert_eq!(again.load(&["b.test", "a.test."]).unwrap().chain(), cert.chain());
    assert!(again.load(&["a.test"]).is_none(), "not for exactly these names");

    // revocation, signed by the account
    acme.revoke(&cert, Some(4)).unwrap();
    assert_eq!(ca.st().revoked, [cert.chain()[0].clone()]);
}

#[test]
fn tls_alpn01_validates_names_and_ip_addresses_through_the_running_server() {
    let (ca, _ca_server) = Ca::start();
    let (challenges, store, server) = tls_server(&ca);
    let tmp = TempDir::new();
    let acme = Acme::new(config(&ca, &tmp.0).tls_alpn01(&challenges).profile("shortlived")).unwrap();
    // before: no certificate at all
    assert!(handshake(&server, "a.test", ca.trust_store(), &["http/1.1"]).is_err());
    let cert = acme.obtain(&["a.test", "127.0.0.1"]).unwrap();
    assert_eq!(ca.st().validations, ["tls-alpn-01 a.test: ok", "tls-alpn-01 127.0.0.1: ok"]);
    assert_eq!(ca.st().profiles, [Some("shortlived".to_string())]);
    store.replace(vec![cert]);
    assert_eq!(handshake(&server, "a.test", ca.trust_store(), &["h2", "http/1.1"]).unwrap(), Some(b"h2".to_vec()));
    assert!(format!("{challenges:?}").ends_with("([])"), "the challenges were taken back: {challenges:?}");
    // a profile the CA does not have is refused before ordering
    let err = Acme::new(config(&ca, &tmp.0).tls_alpn01(&challenges).profile("forever")).unwrap().obtain(&["a.test"]).unwrap_err();
    assert!(err.detail.contains("no profile \"forever\""), "{err}");
}

#[test]
fn dns01_gets_a_wildcard_with_both_records_at_once() {
    let (ca, _ca_server) = Ca::start();
    let tmp = TempDir::new();
    let most = Arc::new(Mutex::new(0));
    let (http01, _web) = http01_server(&ca);
    // a wildcard needs DNS-01: refused before anything is sent
    let err = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap().obtain(&["*.w.test"]).unwrap_err();
    assert!(err.detail.contains("only DNS-01"), "{err}");
    assert!(ca.st().orders.is_empty());

    let acme = Acme::new(config(&ca, &tmp.0).http01(&http01).dns01(Dns(ca.dns.clone(), most.clone()))).unwrap();
    let cert = acme.obtain(&["*.w.test", "w.test"]).unwrap();
    assert_eq!(cert.dns_names(), ["*.w.test", "w.test"]);
    // the wildcard by DNS-01; the plain name by HTTP-01, which comes first when both are set up
    assert_eq!(ca.st().validations, ["dns-01 w.test: ok", "http-01 w.test: ok"]);
    let acme = Acme::new(config(&ca, &tmp.0).dns01(Dns(ca.dns.clone(), most.clone()))).unwrap();
    acme.obtain(&["*.v.test", "v.test"]).unwrap();
    assert_eq!(*most.lock().unwrap(), 2, "a name and its wildcard: two records at once");
    assert!(ca.dns.lock().unwrap().values().all(Vec::is_empty), "the records were taken back");
}

#[test]
fn the_cas_problems_are_reported_and_refused_nonces_are_replaced() {
    let (ca, _ca_server) = Ca::start();
    let (http01, _web) = http01_server(&ca);
    let tmp = TempDir::new();

    // terms of service that were not agreed to
    let mut c = config(&ca, &tmp.0).http01(&http01);
    c.agree_to_terms = false;
    let err = Acme::new(c).unwrap().obtain(&["a.test"]).unwrap_err();
    assert!(err.detail.contains("terms of service"), "{err}");

    let acme = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap();
    // nonces the CA refuses are replaced by the ones it sends with the refusal
    ca.st().refuse_nonces = 3;
    acme.obtain(&["a.test"]).unwrap();
    assert_eq!(ca.st().refuse_nonces, 0);

    // a CA that lost the account: registered again
    ca.st().accounts.clear();
    acme.obtain(&["a.test"]).unwrap();
    assert_eq!(ca.st().accounts.len(), 1);

    // a problem with subproblems, and one with Retry-After
    ca.st().reject_orders.push_back((400, "rejectedIdentifier", None));
    let err = acme.obtain(&["bad.test"]).unwrap_err();
    assert!(err.is("rejectedIdentifier"), "{err:?}");
    assert!(err.to_string().contains("bad.test: rejectedIdentifier: the policy forbids it"), "{err}");
    ca.st().reject_orders.push_back((429, "rateLimited", Some(120)));
    let err = acme.obtain(&["a.test"]).unwrap_err();
    assert!(err.is("rateLimited"));
    let wait = err.retry_after.unwrap() - crate::sys::now_unix();
    assert!((115..=120).contains(&wait), "{wait}");

    // a failed validation: the challenge's error, for the name
    let elsewhere = AcmeHttp01::new(); // answers on no server
    let err = Acme::new(config(&ca, &tmp.0).http01(&elsewhere)).unwrap().obtain(&["c.test"]).unwrap_err();
    assert!(err.is("unauthorized"), "{err:?}");
    assert!(err.detail.starts_with("c.test could not be validated with http-01"), "{err}");

    // no challenge set up at all
    let err = Acme::new(config(&ca, &tmp.0)).unwrap().obtain(&["a.test"]).unwrap_err();
    assert!(err.detail.contains("no challenge is set up"), "{err}");
    // a CA that is not there
    let err = Acme::new(AcmeConfig::new("http://127.0.0.1:9/dir", &tmp.0).client(client()).http01(&http01)).unwrap().obtain(&["a.test"]).unwrap_err();
    assert!(!err.detail.is_empty());
}

#[test]
fn an_external_account_binding_is_signed_with_the_cas_mac_key() {
    let (ca, _ca_server) = Ca::start();
    let (http01, _web) = http01_server(&ca);
    let tmp = TempDir::new();
    let mac = crate::crypto::rand::bytes::<32>().unwrap().to_vec();
    ca.st().eab = Some(("kid-1".into(), mac.clone()));
    let err = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap().account_url().unwrap_err();
    assert!(err.detail.contains("external account binding"), "{err}");
    let wrong = Acme::new(config(&ca, &tmp.0).http01(&http01).external_account("kid-1", &b64url(&[7; 32]))).unwrap().account_url().unwrap_err();
    assert!(wrong.is("unauthorized"), "{wrong:?}");
    let acme = Acme::new(config(&ca, &tmp.0).http01(&http01).external_account("kid-1", &b64url(&mac))).unwrap();
    assert!(acme.account_url().unwrap().ends_with("/acct/0"));
    acme.obtain(&["a.test"]).unwrap();
}

#[test]
fn renewal_information_moves_the_renewal_and_the_new_order_says_what_it_replaces() {
    let (ca, _ca_server) = Ca::start();
    let (http01, _web) = http01_server(&ca);
    let tmp = TempDir::new();
    let acme = Acme::new(config(&ca, &tmp.0).http01(&http01)).unwrap();
    let cert = acme.obtain(&["a.test"]).unwrap();
    let id = cert_id(&cert).unwrap();
    assert_eq!(id, ca.st().certs[0].1, "the ARI identifier: the issuer's key identifier and the serial number");
    let w = acme.renewal_info(&cert).unwrap().unwrap();
    let now = crate::sys::now_unix();
    assert!(w.start > now + 29 * 86_400 && w.end > w.start, "{w:?}");
    assert!((w.check_again - now - 21_600).abs() < 5);
    // without the CA's word: two thirds of the way through 90 days, half of the way through 6
    let t = default_renewal_time(&cert);
    assert!((t - (now - 60 + 60 * 86_400)).abs() < 120, "{}", t - now);
    ca.st().lifetime = 6 * 86_400;
    let short = acme.obtain(&["s.test"]).unwrap();
    assert!((default_renewal_time(&short) - (now - 60 + 3 * 86_400)).abs() < 120);
    ca.st().lifetime = 90 * 86_400;

    // the manager: a certificate due now (its window has passed) is renewed, the order naming it
    ca.st().ari_past.insert(id.clone());
    let store = Arc::new(CertStore::new());
    let reports = Arc::new(Mutex::new(Vec::<String>::new()));
    let r = reports.clone();
    let orders_before = ca.st().orders.len();
    let manager = manage(acme.clone(), vec![vec!["a.test".into()], vec!["b.test".into()]], store.clone(), move |m| r.lock().unwrap().push(m.to_string()));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let certs = store.certificates();
        if certs.len() == 2 && certs[0].chain() != cert.chain() {
            break;
        }
        assert!(Instant::now() < deadline, "the store: {certs:?}; reports: {:?}", reports.lock().unwrap());
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(manager);
    let st = ca.st();
    assert_eq!(st.orders.len(), orders_before + 2, "a.test renewed and b.test obtained, once each");
    assert_eq!(st.replaces[orders_before..], [Some(id.clone()), None]);
    let reports = reports.lock().unwrap();
    assert!(reports.iter().any(|m| m.starts_with("certificate for a.test loaded from")), "{reports:?}");
    assert!(reports.iter().any(|m| m.starts_with("certificate for a.test renewed")), "{reports:?}");
    assert!(reports.iter().any(|m| m.starts_with("certificate for b.test obtained")), "{reports:?}");
    assert!(reports.iter().any(|m| m.starts_with("renewal of the certificate for a.test set for") && m.ends_with("in the CA's window")), "{reports:?}");
    assert_eq!(store.certificates()[0].dns_names(), ["a.test"], "the order of the sets is kept");
}

#[test]
fn the_manager_serves_what_is_saved_at_once_and_tries_again_after_a_failure() {
    let (ca, _ca_server) = Ca::start();
    let (http01, _web) = http01_server(&ca);
    let tmp = TempDir::new();
    let mut c = config(&ca, &tmp.0).http01(&http01);
    c.retry_after_failure = Duration::from_millis(10);
    let acme = Acme::new(c).unwrap();
    // the CA fails the first order
    ca.st().reject_orders.push_back((500, "serverInternal", None));
    let store = Arc::new(CertStore::new());
    let reports = Arc::new(Mutex::new(Vec::<String>::new()));
    let r = reports.clone();
    let manager = manage(acme.clone(), vec![vec!["a.test".into()]], store.clone(), move |m| r.lock().unwrap().push(m.to_string()));
    let deadline = Instant::now() + Duration::from_secs(20);
    while store.certificates().is_empty() {
        assert!(Instant::now() < deadline, "reports: {:?}", reports.lock().unwrap());
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(manager);
    assert!(reports.lock().unwrap()[0].contains("serverInternal"), "{:?}", reports.lock().unwrap());
    assert_eq!(ca.st().orders.len(), 1);
    // a manager started again finds it saved, and orders nothing
    let store2 = Arc::new(CertStore::new());
    let manager = manage(acme, vec![vec!["a.test".into()]], store2.clone(), |_| {});
    let deadline = Instant::now() + Duration::from_secs(5);
    while store2.certificates().is_empty() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(300));
    drop(manager);
    assert_eq!(ca.st().orders.len(), 1);
}
