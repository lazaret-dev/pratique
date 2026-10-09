//! The Update Framework (TUF, specification 1.0): the client side, as a pure state machine over bytes (BACKLOG B-82).
//!
//! A TUF repository publishes four kinds of signed metadata: `root` (the keys of every top-level role, and the root's own,
//! rotated by signing each new root with the old keys and the new), `timestamp` (the current snapshot, short-lived),
//! `snapshot` (the version of every targets metadata file) and `targets` (the files, by length and hash, and delegations of
//! parts of the namespace to other roles with keys of their own). Sigstore distributes its trusted root
//! (`trusted_root.json`) and npm's registry keys this way, from `https://tuf-repo-cdn.sigstore.dev`
//! ([`SIGSTORE_REPOSITORY`], bootstrapped from [`SIGSTORE_ROOT`]).
//!
//! [`Updater`] follows section 5 of the specification ("Detailed client workflow") and the reference client
//! (`python-tuf`'s `ngclient`), step by step, without doing any I/O and without reading the clock: the caller gives the
//! time once, asks what to fetch next and hands over the bytes. [`refresh`] and [`fetch_target`] drive it with any
//! fetching function (the `net` feature has one over HTTPS, `http::TufSource`). What it checks:
//!
//! * **root**: the trusted root signs itself (a threshold of its own root keys); each new root `N+1.root.json` has
//!   version N+1 and is signed by a threshold of the previous root's root keys *and* of its own; at most 256 rotations;
//!   the last one must not have expired (earlier ones may have);
//! * **timestamp**: signed by a threshold of the root's timestamp keys; not older than a timestamp the caller trusted
//!   before ([`Updater::load_local_timestamp`]), nor naming an older snapshot; not expired;
//! * **snapshot**: the length and hashes the timestamp gives; signed by the snapshot keys; no targets metadata older than,
//!   or missing from, a snapshot the caller trusted before; the version the timestamp names; not expired;
//! * **targets** and delegated roles: the length, hashes and version the snapshot gives; signed by a threshold of the keys
//!   the root (for `targets`) or the delegating role gives; not expired; a target is looked up by a preorder depth-first
//!   walk of the delegations whose paths (shell patterns per path segment, or SHA-256 prefixes of the path) cover it,
//!   stopping at a terminating one, visiting at most 32 roles;
//! * **target files**: exactly the length and every hash (`sha256`, `sha384`, `sha512`) the metadata gives.
//!
//! Signatures are over the OLPC canonical JSON of the `signed` object ([`canonical_json`]), which is what TUF repositories
//! sign. Keys: ECDSA over P-256, P-384 and P-521 with the matching SHA-2 (`ecdsa-sha2-nistp256` and so on, PEM public keys),
//! Ed25519 (hex), and RSA of 2048 bits or more with `rsassa-pss-sha256/384/512` (any salt length) or
//! `rsa-pkcs1v15-sha256/384/512`. A key of another type is kept and never verifies.
//!
//! Stricter than python-tuf, on purpose: a threshold counts distinct keys, not key ids (the same key listed under two ids
//! counts once; the specification says "unique keys"); JSON is read strictly ([`crate::json`]: duplicate names are an error,
//! where Python keeps the last); `expires` must be exactly `YYYY-MM-DDTHH:MM:SSZ`. More tolerant: a key of a type this does
//! not know does not make the metadata unreadable (python-tuf refuses the whole file), it just never verifies.
//! Not supported: `succinct_roles` (hash-bin delegations; an error), and the DSSE envelope form of metadata.

use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::ed25519;
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::sha2::HashAlg;
use crate::json::{self, Value};
use crate::pem;
use crate::trust_root::parse_rfc3339;
use crate::util::hex;
use crate::x509::{self, PublicKey};

/// Sigstore's public TUF repository: metadata at its root, target files under `targets/`.
pub const SIGSTORE_REPOSITORY: &str = "https://tuf-repo-cdn.sigstore.dev";

/// A root of Sigstore's TUF repository to start from (version 15, as `sigstore-python` 4.5.0 embeds it; it signs itself
/// with three of five keys). A client keeps the newest root it has verified and starts from that the next time; this one is
/// only the first link of the chain. It has expired by the time a newer one is out, which does not matter: only the last
/// root of a chain must be current.
pub const SIGSTORE_ROOT: &[u8] = include_bytes!("../roots/sigstore_tuf_root.json");

/// The path of Sigstore's trusted root among the repository's targets.
pub const SIGSTORE_TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

/// The path of npm's registry keys among the repository's targets (in the delegated role `registry.npmjs.org`).
pub const NPM_KEYS_TARGET: &str = "registry.npmjs.org/keys.json";

/// Upper limits on what is fetched, python-tuf's defaults.
pub mod limits {
    /// Longest root metadata file.
    pub const ROOT: u64 = 512_000;
    /// Longest timestamp metadata file.
    pub const TIMESTAMP: u64 = 16_384;
    /// Longest snapshot metadata file when the timestamp does not give its length.
    pub const SNAPSHOT: u64 = 2_000_000;
    /// Longest targets metadata file when the snapshot does not give its length.
    pub const TARGETS: u64 = 5_000_000;
    /// Most root rotations in one refresh.
    pub const ROOT_ROTATIONS: u64 = 256;
    /// Most targets roles visited to find one target.
    pub const DELEGATIONS: usize = 32;
}

const TOP_LEVEL: [&str; 4] = ["root", "timestamp", "snapshot", "targets"];

// ================================================================================================ errors

/// Why metadata or a target was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not strict JSON.
    Json(json::Error),
    /// The JSON is not TUF metadata of the kind expected: the string says where and what.
    Malformed(String),
    /// A form this client does not handle (another major specification version, `succinct_roles`).
    Unsupported(String),
    /// Fewer distinct keys of the role signed than its threshold.
    Signature { role: String, verified: usize, threshold: u64 },
    /// Not the version that was expected.
    Version { role: String, expected: u64, got: u64 },
    /// Older than what was trusted before, or missing what it had.
    Rollback(String),
    /// Expired at the time the update runs at (Unix seconds of `expires`).
    Expired { role: String, expires: i64 },
    /// A file is not the length, or does not have the hash, its metadata gives.
    LengthOrHash(String),
    /// The target is in no role that may say where it is.
    NotFound(String),
    /// A step was taken out of order (a program error of the caller).
    State(String),
    /// The fetching function failed (its message), or a file that must exist was not there.
    Fetch(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(e) => write!(f, "TUF metadata is not strict JSON: {e}"),
            Error::Malformed(m) => write!(f, "malformed TUF metadata: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported TUF metadata: {m}"),
            Error::Signature { role, verified, threshold } => {
                write!(f, "{role} metadata is signed by {verified} of its keys and needs {threshold}")
            }
            Error::Version { role, expected, got } => write!(f, "{role} metadata has version {got}, expected {expected}"),
            Error::Rollback(m) => write!(f, "TUF rollback: {m}"),
            Error::Expired { role, expires } => write!(f, "{role} metadata expired at {expires}"),
            Error::LengthOrHash(m) => write!(f, "TUF length or hash mismatch: {m}"),
            Error::NotFound(p) => write!(f, "no TUF target {p:?}"),
            Error::State(m) => write!(f, "TUF update out of order: {m}"),
            Error::Fetch(m) => write!(f, "fetching TUF data: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<json::Error> for Error {
    fn from(e: json::Error) -> Error {
        Error::Json(e)
    }
}

fn malformed<T>(path: &str, what: &str) -> Result<T, Error> {
    Err(Error::Malformed(format!("{path}: {what}")))
}

// ================================================================================================ canonical JSON

/// The OLPC canonical form of a JSON value, as securesystemslib's `encode_canonical` writes it and TUF signs it: object
/// members sorted by name (code point order), no white space, strings with only `"` and `\` escaped (every other
/// character, control characters included, as its UTF-8 bytes), integers in decimal. A number that is not an integer is
/// an error.
pub fn canonical_json(v: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if !n.is_integer() {
                return Err(Error::Malformed(format!("the number {} is not an integer, which canonical JSON cannot write", n.text())));
            }
            // a JSON integer has no leading zeros; Python reads "-0" as 0
            out.extend_from_slice(if n.text() == "-0" { "0" } else { n.text() }.as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(o) => {
            let mut members: Vec<(&str, &Value)> = o.iter().collect();
            members.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (name, x)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(name, out);
                out.push(b':');
                write_canonical(x, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for b in s.bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
}

// ================================================================================================ keys

/// A public key of TUF metadata.
pub struct Key {
    /// `keytype` and `scheme`, as written.
    pub keytype: String,
    pub scheme: String,
    /// The key, and what tells it apart from other keys whatever ids it goes by (the point, the Ed25519 key, the RSA
    /// `SubjectPublicKeyInfo`); `None` for a key this client does not verify with.
    material: Option<(Material, Vec<u8>)>,
}

enum Material {
    Ecdsa(Curve, Vec<u8>, HashAlg),
    Ed25519([u8; 32]),
    RsaPss(RsaPublicKey, HashAlg),
    RsaPkcs1(RsaPublicKey, HashAlg),
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key").field("keytype", &self.keytype).field("scheme", &self.scheme).field("usable", &self.material.is_some()).finish()
    }
}

impl Key {
    fn parse(v: &Value, path: &str) -> Result<Key, Error> {
        let keytype = text(v, "keytype", path)?;
        let scheme = text(v, "scheme", path)?;
        let Some(keyval) = v.get("keyval").filter(|k| k.as_object().is_some()) else { return malformed(path, "no keyval object") };
        let public = keyval.get("public").and_then(Value::as_str);
        let material = public.and_then(|p| material(&keytype, &scheme, p));
        Ok(Key { keytype, scheme, material })
    }

    /// Whether the key is of a type and scheme this client verifies.
    pub fn usable(&self) -> bool {
        self.material.is_some()
    }

    fn identity(&self) -> Option<&[u8]> {
        self.material.as_ref().map(|(_, id)| id.as_slice())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Some((Material::Ecdsa(curve, point, hash), _)) => ecdsa::verify(*curve, point, *hash, message, signature),
            Some((Material::Ed25519(k), _)) => ed25519::verify(k, message, signature),
            Some((Material::RsaPss(k, hash), _)) => k.verify_pss_any_salt(*hash, message, signature),
            Some((Material::RsaPkcs1(k, hash), _)) => k.verify_pkcs1(*hash, message, signature),
            None => false,
        }
    }
}

/// The `SubjectPublicKeyInfo` of a PEM `PUBLIC KEY` block, and the key in it.
fn spki_from_pem(text: &str) -> Option<(Vec<u8>, PublicKey)> {
    let block = pem::parse(text).into_iter().find(|b| b.label == "PUBLIC KEY")?;
    let key = x509::parse_spki(&block.data).ok()?;
    Some((block.data, key))
}

fn material(keytype: &str, scheme: &str, public: &str) -> Option<(Material, Vec<u8>)> {
    let hash_of = |s: &str| match s {
        "sha256" => Some(HashAlg::Sha256),
        "sha384" => Some(HashAlg::Sha384),
        "sha512" => Some(HashAlg::Sha512),
        _ => None,
    };
    match (keytype, scheme) {
        ("ecdsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521", _) if scheme.starts_with("ecdsa-sha2-nistp") => {
            // the legacy keytypes name the scheme too, and must name the same one
            if keytype != "ecdsa" && keytype != scheme {
                return None;
            }
            let (want, hash) = match scheme {
                "ecdsa-sha2-nistp256" => (Curve::P256, HashAlg::Sha256),
                "ecdsa-sha2-nistp384" => (Curve::P384, HashAlg::Sha384),
                "ecdsa-sha2-nistp521" => (Curve::P521, HashAlg::Sha512),
                _ => return None,
            };
            match spki_from_pem(public)?.1 {
                PublicKey::Ec { curve, point } if curve == want && ecdsa::is_valid_public_key(curve, &point) => Some((Material::Ecdsa(curve, point.clone(), hash), point)),
                _ => None,
            }
        }
        ("ed25519", "ed25519") => {
            let b = public.as_bytes();
            if b.len() != 64 || !b.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let k: [u8; 32] = crate::util::unhex(public).try_into().ok()?;
            Some((Material::Ed25519(k), k.to_vec()))
        }
        ("rsa", _) => {
            let (pss, hash) = match (scheme.strip_prefix("rsassa-pss-"), scheme.strip_prefix("rsa-pkcs1v15-")) {
                (Some(h), _) => (true, hash_of(h)?),
                (_, Some(h)) => (false, hash_of(h)?),
                _ => return None,
            };
            match spki_from_pem(public)? {
                (spki, PublicKey::Rsa(k)) if k.bits() >= 2048 => Some((if pss { Material::RsaPss(k, hash) } else { Material::RsaPkcs1(k, hash) }, spki)),
                _ => None,
            }
        }
        _ => None,
    }
}

// ================================================================================================ reading JSON

fn text(v: &Value, name: &str, path: &str) -> Result<String, Error> {
    match v.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => malformed(&format!("{path}.{name}"), "not a string"),
        None => malformed(&format!("{path}.{name}"), "missing"),
    }
}

fn object<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a json::Object, Error> {
    match v.get(name) {
        Some(Value::Object(o)) => Ok(o),
        Some(_) => malformed(&format!("{path}.{name}"), "not an object"),
        None => malformed(&format!("{path}.{name}"), "missing"),
    }
}

fn array<'a>(v: &'a Value, name: &str, path: &str) -> Result<&'a [Value], Error> {
    match v.get(name) {
        Some(Value::Array(a)) => Ok(a),
        Some(_) => malformed(&format!("{path}.{name}"), "not an array"),
        None => malformed(&format!("{path}.{name}"), "missing"),
    }
}

/// A JSON integer (not a string of digits), at least `min`.
fn integer(v: &Value, name: &str, path: &str, min: u64) -> Result<u64, Error> {
    match v.get(name) {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(x) if x >= min => Ok(x),
            _ => malformed(&format!("{path}.{name}"), &format!("not an integer of at least {min}")),
        },
        Some(_) => malformed(&format!("{path}.{name}"), "not a number"),
        None => malformed(&format!("{path}.{name}"), "missing"),
    }
}

fn strings(v: &Value, path: &str) -> Result<Vec<String>, Error> {
    let Some(a) = v.as_array() else { return malformed(path, "not an array") };
    a.iter().enumerate().map(|(i, s)| s.as_str().map(str::to_string).ok_or_else(|| Error::Malformed(format!("{path}[{i}]: not a string")))).collect()
}

/// `YYYY-MM-DDTHH:MM:SSZ`, exactly.
fn expires(v: &Value, path: &str) -> Result<i64, Error> {
    let s = text(v, "expires", path)?;
    let b = s.as_bytes();
    if b.len() != 20 || b[19] != b'Z' {
        return malformed(&format!("{path}.expires"), "not of the form YYYY-MM-DDTHH:MM:SSZ");
    }
    match parse_rfc3339(&s) {
        Some((t, 0)) => Ok(t),
        _ => malformed(&format!("{path}.expires"), "not a date and time"),
    }
}

/// The fields every kind of metadata has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Common {
    /// `spec_version`, as written (major version 1).
    pub spec_version: String,
    /// The metadata's version, from 1.
    pub version: u64,
    /// When it expires, Unix seconds: it is expired from that second on.
    pub expires: i64,
}

fn common(signed: &Value, kind: &str) -> Result<Common, Error> {
    let path = "signed";
    if signed.as_object().is_none() {
        return malformed(path, "not an object");
    }
    let t = text(signed, "_type", path)?;
    if t != kind {
        return malformed(&format!("{path}._type"), &format!("is {t:?}, expected {kind:?}"));
    }
    let spec_version = text(signed, "spec_version", path)?;
    let parts: Vec<&str> = spec_version.split('.').collect();
    if !(2..=3).contains(&parts.len()) || !parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        return malformed(&format!("{path}.spec_version"), &format!("{spec_version:?} is not a version"));
    }
    if parts[0] != "1" {
        return Err(Error::Unsupported(format!("specification version {spec_version}")));
    }
    Ok(Common { spec_version, version: integer(signed, "version", path, 1)?, expires: expires(signed, path)? })
}

/// Metadata as it arrived: the `signed` value, its canonical bytes, and the signatures by key id.
struct Envelope {
    signed: Value,
    payload: Vec<u8>,
    signatures: Vec<(String, Vec<u8>)>,
}

fn envelope(bytes: &[u8]) -> Result<Envelope, Error> {
    let doc = json::parse(bytes)?;
    if doc.as_object().is_none() {
        return malformed("$", "not an object");
    }
    let Some(signed) = doc.get("signed").cloned() else { return malformed("$.signed", "missing") };
    let mut signatures: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, s) in array(&doc, "signatures", "$")?.iter().enumerate() {
        let path = format!("$.signatures[{i}]");
        if s.as_object().is_none() {
            return malformed(&path, "not an object");
        }
        let keyid = text(s, "keyid", &path)?;
        let sig = text(s, "sig", &path)?;
        if sig.len() % 2 != 0 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
            return malformed(&format!("{path}.sig"), "not hex");
        }
        if signatures.iter().any(|(k, _)| *k == keyid) {
            return malformed(&path, &format!("a second signature by key id {keyid}"));
        }
        signatures.push((keyid, crate::util::unhex(&sig)));
    }
    let payload = canonical_json(&signed)?;
    Ok(Envelope { signed, payload, signatures })
}

/// The keys a role may sign with, and how many must.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleKeys {
    pub keyids: Vec<String>,
    pub threshold: u64,
}

fn role_keys(v: &Value, path: &str) -> Result<RoleKeys, Error> {
    let keyids = strings(v.get("keyids").unwrap_or(&Value::Null), &format!("{path}.keyids"))?;
    for (i, k) in keyids.iter().enumerate() {
        if keyids[..i].contains(k) {
            return malformed(&format!("{path}.keyids"), &format!("{k} twice"));
        }
    }
    Ok(RoleKeys { keyids, threshold: integer(v, "threshold", path, 1)? })
}

fn keys(o: &json::Object, path: &str) -> Result<BTreeMap<String, Key>, Error> {
    o.iter().map(|(id, k)| Ok((id.to_string(), Key::parse(k, &format!("{path}.{id}"))?))).collect()
}

/// Checks that distinct keys of `role` (as many as its threshold) signed `env`.
fn verify_role(name: &str, keys: &BTreeMap<String, Key>, role: &RoleKeys, env: &Envelope) -> Result<(), Error> {
    let mut good: Vec<Vec<u8>> = Vec::new();
    for keyid in &role.keyids {
        let (Some(key), Some((_, sig))) = (keys.get(keyid), env.signatures.iter().find(|(k, _)| k == keyid)) else { continue };
        if key.verify(&env.payload, sig) {
            let id = key.identity().expect("a key that verifies has material").to_vec();
            if !good.contains(&id) {
                good.push(id);
            }
        }
    }
    if (good.len() as u64) < role.threshold {
        return Err(Error::Signature { role: name.to_string(), verified: good.len(), threshold: role.threshold });
    }
    Ok(())
}

// ================================================================================================ metadata

/// Root metadata.
#[derive(Debug)]
pub struct Root {
    pub common: Common,
    pub consistent_snapshot: bool,
    pub keys: BTreeMap<String, Key>,
    /// The keys of `root`, `timestamp`, `snapshot` and `targets`, in that order.
    pub roles: [RoleKeys; 4],
}

impl Root {
    fn parse(signed: &Value) -> Result<Root, Error> {
        let common = common(signed, "root")?;
        let consistent_snapshot = match signed.get("consistent_snapshot") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return malformed("signed.consistent_snapshot", "not a boolean"),
        };
        let keys = keys(object(signed, "keys", "signed")?, "signed.keys")?;
        let roles = object(signed, "roles", "signed")?;
        if roles.len() != 4 || TOP_LEVEL.iter().any(|r| roles.get(r).is_none()) {
            return malformed("signed.roles", "must be exactly root, timestamp, snapshot and targets");
        }
        let role = |n: &str| role_keys(roles.get(n).expect("checked"), &format!("signed.roles.{n}"));
        Ok(Root { common, consistent_snapshot, keys, roles: [role("root")?, role("timestamp")?, role("snapshot")?, role("targets")?] })
    }

    fn role(&self, name: &str) -> &RoleKeys {
        &self.roles[TOP_LEVEL.iter().position(|r| *r == name).expect("a top-level role")]
    }

    fn verify(&self, name: &str, env: &Envelope) -> Result<(), Error> {
        verify_role(name, &self.keys, self.role(name), env)
    }
}

/// The version, length and hashes a timestamp gives for the snapshot, or a snapshot for a targets file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaFile {
    pub version: u64,
    pub length: Option<u64>,
    /// `(algorithm, lower-case hex)`, as written.
    pub hashes: Option<Vec<(String, String)>>,
}

fn hashes(v: &Value, path: &str) -> Result<Vec<(String, String)>, Error> {
    let Some(o) = v.as_object() else { return malformed(path, "not an object") };
    if o.is_empty() {
        return malformed(path, "empty");
    }
    o.iter().map(|(alg, h)| h.as_str().map(|h| (alg.to_string(), h.to_string())).ok_or_else(|| Error::Malformed(format!("{path}.{alg}: not a string")))).collect()
}

impl MetaFile {
    fn parse(v: &Value, path: &str) -> Result<MetaFile, Error> {
        if v.as_object().is_none() {
            return malformed(path, "not an object");
        }
        let length = match v.get("length") {
            None => None,
            Some(_) => Some(integer(v, "length", path, 0)?),
        };
        let hashes = match v.get("hashes") {
            None => None,
            Some(h) => Some(hashes(h, &format!("{path}.hashes"))?),
        };
        Ok(MetaFile { version: integer(v, "version", path, 1)?, length, hashes })
    }

    fn check(&self, what: &str, data: &[u8]) -> Result<(), Error> {
        if let Some(n) = self.length {
            check_length(what, data, n)?;
        }
        if let Some(h) = &self.hashes {
            check_hashes(what, data, h)?;
        }
        Ok(())
    }
}

fn check_length(what: &str, data: &[u8], length: u64) -> Result<(), Error> {
    if data.len() as u64 != length {
        return Err(Error::LengthOrHash(format!("{what} is {} bytes, not {length}", data.len())));
    }
    Ok(())
}

fn check_hashes(what: &str, data: &[u8], hashes: &[(String, String)]) -> Result<(), Error> {
    for (alg, want) in hashes {
        let h = match alg.as_str() {
            "sha256" => HashAlg::Sha256,
            "sha384" => HashAlg::Sha384,
            "sha512" => HashAlg::Sha512,
            other => return Err(Error::LengthOrHash(format!("{what}: unsupported hash algorithm {other:?}"))),
        };
        // compared as python-tuf compares them: the lower-case hex digest, as a string
        if hex(&h.digest(data)) != *want {
            return Err(Error::LengthOrHash(format!("{what}: the {alg} is not {want}")));
        }
    }
    Ok(())
}

/// Timestamp metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub common: Common,
    /// What it says of `snapshot.json`.
    pub snapshot: MetaFile,
}

impl Timestamp {
    fn parse(signed: &Value) -> Result<Timestamp, Error> {
        let common = common(signed, "timestamp")?;
        let meta = object(signed, "meta", "signed")?;
        let Some(s) = meta.get("snapshot.json") else { return malformed("signed.meta", "no snapshot.json") };
        Ok(Timestamp { common, snapshot: MetaFile::parse(s, "signed.meta.snapshot.json")? })
    }
}

/// Snapshot metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub common: Common,
    /// `ROLE.json` and what it says of it.
    pub meta: BTreeMap<String, MetaFile>,
}

impl Snapshot {
    fn parse(signed: &Value) -> Result<Snapshot, Error> {
        let common = common(signed, "snapshot")?;
        let meta = object(signed, "meta", "signed")?;
        let meta = meta.iter().map(|(n, m)| Ok((n.to_string(), MetaFile::parse(m, &format!("signed.meta.{n}"))?))).collect::<Result<_, Error>>()?;
        Ok(Snapshot { common, meta })
    }
}

/// A target file: its length, hashes and custom data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetFile {
    /// Its path, relative to the targets URL.
    pub path: String,
    pub length: u64,
    /// `(algorithm, lower-case hex)`, in the order written.
    pub hashes: Vec<(String, String)>,
    /// The `custom` member, if there is one.
    pub custom: Option<Value>,
}

impl TargetFile {
    /// Checks that `data` is this file: its length and every hash.
    pub fn verify(&self, data: &[u8]) -> Result<(), Error> {
        check_length(&self.path, data, self.length)?;
        check_hashes(&self.path, data, &self.hashes)
    }
}

/// A delegation to another targets role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedRole {
    pub name: String,
    pub keys: RoleKeys,
    pub terminating: bool,
    /// Shell patterns, per path segment.
    pub paths: Option<Vec<String>>,
    /// Hex prefixes of the SHA-256 of a target's path.
    pub path_hash_prefixes: Option<Vec<String>>,
}

impl DelegatedRole {
    /// Whether `target` is one of the paths this role may speak for.
    pub fn covers(&self, target: &str) -> bool {
        if let Some(prefixes) = &self.path_hash_prefixes {
            let h = hex(&HashAlg::Sha256.digest(target.as_bytes()));
            if prefixes.iter().any(|p| h.starts_with(p.as_str())) {
                return true;
            }
        }
        if let Some(paths) = &self.paths {
            return paths.iter().any(|p| path_matches(target, p));
        }
        false
    }
}

/// python-tuf's rule: the same number of `/`-separated segments, each matching its pattern with `fnmatch` (`*`, `?`,
/// `[...]` and `[!...]`, case-sensitive, so that `*` never crosses a `/`).
pub fn path_matches(target: &str, pattern: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (target.split('/').collect(), pattern.split('/').collect());
    t.len() == p.len() && t.iter().zip(&p).all(|(t, p)| fnmatch(&t.chars().collect::<Vec<_>>(), &p.chars().collect::<Vec<_>>()))
}

/// One element of a pattern.
enum Pat {
    Char(char),
    Any,
    Star,
    Set { negated: bool, items: Vec<(char, char)> },
}

fn compile(p: &[char]) -> Vec<Pat> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            '*' => {
                if !matches!(out.last(), Some(Pat::Star)) {
                    out.push(Pat::Star);
                }
                i += 1;
            }
            '?' => {
                out.push(Pat::Any);
                i += 1;
            }
            '[' => {
                // as Python's fnmatch.translate: `]` first (after an optional `!`) is a member; no closing `]` makes `[` a
                // plain character
                let mut j = i + 1;
                if j < p.len() && p[j] == '!' {
                    j += 1;
                }
                if j < p.len() && p[j] == ']' {
                    j += 1;
                }
                while j < p.len() && p[j] != ']' {
                    j += 1;
                }
                if j >= p.len() {
                    out.push(Pat::Char('['));
                    i += 1;
                    continue;
                }
                let mut k = i + 1;
                let negated = p[k] == '!';
                if negated {
                    k += 1;
                }
                let mut items = Vec::new();
                while k < j {
                    if k + 2 < j && p[k + 1] == '-' {
                        // a range with its ends the wrong way round is empty
                        if p[k] <= p[k + 2] {
                            items.push((p[k], p[k + 2]));
                        }
                        k += 3;
                    } else {
                        items.push((p[k], p[k]));
                        k += 1;
                    }
                }
                out.push(Pat::Set { negated, items });
                i = j + 1;
            }
            c => {
                out.push(Pat::Char(c));
                i += 1;
            }
        }
    }
    out
}

fn fnmatch(text: &[char], pattern: &[char]) -> bool {
    let pat = compile(pattern);
    // the classic two-pointer match with a single backtrack point for the last star
    let one = |p: &Pat, c: char| match p {
        Pat::Char(x) => *x == c,
        Pat::Any => true,
        Pat::Set { negated, items } => items.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)) != *negated,
        Pat::Star => false,
    };
    let (mut t, mut p) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pat.len() && matches!(pat[p], Pat::Star) {
            star = Some((p, t));
            p += 1;
        } else if p < pat.len() && one(&pat[p], text[t]) {
            p += 1;
            t += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|x| matches!(x, Pat::Star))
}

/// The delegations of a targets role.
#[derive(Debug)]
pub struct Delegations {
    pub keys: BTreeMap<String, Key>,
    /// In order: the order is the order of trust.
    pub roles: Vec<DelegatedRole>,
}

/// Targets metadata, top-level or delegated.
#[derive(Debug)]
pub struct Targets {
    pub common: Common,
    pub targets: BTreeMap<String, TargetFile>,
    pub delegations: Option<Delegations>,
}

impl Targets {
    fn parse(signed: &Value) -> Result<Targets, Error> {
        let common = common(signed, "targets")?;
        let mut targets = BTreeMap::new();
        for (path, t) in object(signed, "targets", "signed")?.iter() {
            let p = format!("signed.targets.{path}");
            if t.as_object().is_none() {
                return malformed(&p, "not an object");
            }
            let Some(h) = t.get("hashes") else { return malformed(&format!("{p}.hashes"), "missing") };
            targets.insert(
                path.to_string(),
                TargetFile { path: path.to_string(), length: integer(t, "length", &p, 0)?, hashes: hashes(h, &format!("{p}.hashes"))?, custom: t.get("custom").cloned() },
            );
        }
        let delegations = match signed.get("delegations") {
            None => None,
            Some(d) => Some(Delegations::parse(d)?),
        };
        Ok(Targets { common, targets, delegations })
    }
}

impl Delegations {
    fn parse(d: &Value) -> Result<Delegations, Error> {
        let path = "signed.delegations";
        if d.as_object().is_none() {
            return malformed(path, "not an object");
        }
        if d.get("succinct_roles").is_some() {
            return Err(Error::Unsupported("succinct_roles (hash-bin delegations)".into()));
        }
        let keys = keys(object(d, "keys", path)?, &format!("{path}.keys"))?;
        let mut roles: Vec<DelegatedRole> = Vec::new();
        for (i, r) in array(d, "roles", path)?.iter().enumerate() {
            let p = format!("{path}.roles[{i}]");
            if r.as_object().is_none() {
                return malformed(&p, "not an object");
            }
            let name = text(r, "name", &p)?;
            if name.is_empty() || TOP_LEVEL.contains(&name.as_str()) {
                return malformed(&format!("{p}.name"), "empty or the name of a top-level role");
            }
            if roles.iter().any(|x| x.name == name) {
                return malformed(&format!("{p}.name"), &format!("{name:?} twice"));
            }
            let terminating = match r.get("terminating") {
                Some(Value::Bool(b)) => *b,
                _ => return malformed(&format!("{p}.terminating"), "missing or not a boolean"),
            };
            let paths = r.get("paths").map(|v| strings(v, &format!("{p}.paths"))).transpose()?;
            let path_hash_prefixes = r.get("path_hash_prefixes").map(|v| strings(v, &format!("{p}.path_hash_prefixes"))).transpose()?;
            if paths.is_some() == path_hash_prefixes.is_some() {
                return malformed(&p, "must have exactly one of paths and path_hash_prefixes");
            }
            roles.push(DelegatedRole { name, keys: role_keys(r, &p)?, terminating, paths, path_hash_prefixes });
        }
        Ok(Delegations { keys, roles })
    }
}

// ================================================================================================ the updater

/// What [`Updater::find_target`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The target, as the most trusted role that has it describes it.
    Found(TargetFile),
    /// The walk needs this delegated role, delegated by `delegator`: fetch it ([`Updater::targets_request`]),
    /// [`Updater::update_delegated`] it, and look again.
    Load { role: String, delegator: String },
    /// No role that may speak for the path has it.
    NotFound,
}

/// What to fetch: a path relative to the metadata URL (or the targets URL, for a target), and the most bytes to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub path: String,
    pub max_length: u64,
}

/// What [`Updater::update_timestamp`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampUpdate {
    /// A newer timestamp is trusted now.
    New,
    /// It is the version already trusted, which stays.
    Unchanged,
}

struct Trusted<T> {
    meta: T,
    bytes: Vec<u8>,
}

/// The client's state for one refresh: the trusted metadata so far, and the time it is checked at. See the module
/// documentation for the rules, and [`refresh`] for the order of the steps.
pub struct Updater {
    now: i64,
    root: Trusted<Root>,
    rotations: u64,
    timestamp: Option<Trusted<Timestamp>>,
    snapshot: Option<Trusted<Snapshot>>,
    targets: BTreeMap<String, Targets>,
}

impl Updater {
    /// Starts from a root the caller trusts (one it got with the software, or the newest it verified before), at `now` (Unix
    /// seconds). The root must sign itself; it may have expired (a newer one will be fetched).
    pub fn new(trusted_root: &[u8], now: i64) -> Result<Updater, Error> {
        let env = envelope(trusted_root)?;
        let root = Root::parse(&env.signed)?;
        root.verify("root", &env)?;
        Ok(Updater { now, root: Trusted { meta: root, bytes: trusted_root.to_vec() }, rotations: 0, timestamp: None, snapshot: None, targets: BTreeMap::new() })
    }

    /// The time the update checks expiry at.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// The newest trusted root: what to keep and start from next time.
    pub fn root(&self) -> &Root {
        &self.root.meta
    }

    /// Its bytes, as fetched.
    pub fn root_bytes(&self) -> &[u8] {
        &self.root.bytes
    }

    /// The trusted timestamp and its bytes (to keep for rollback protection), once there is one.
    pub fn timestamp(&self) -> Option<(&Timestamp, &[u8])> {
        self.timestamp.as_ref().map(|t| (&t.meta, t.bytes.as_slice()))
    }

    /// The trusted snapshot and its bytes, once there is one.
    pub fn snapshot(&self) -> Option<(&Snapshot, &[u8])> {
        self.snapshot.as_ref().map(|t| (&t.meta, t.bytes.as_slice()))
    }

    /// The trusted targets metadata of a role (`targets` or a delegated one), once loaded.
    pub fn targets(&self, role: &str) -> Option<&Targets> {
        self.targets.get(role)
    }

    // ---------------------------------------------------------------------------------------- root

    /// The next root to try, `N+1.root.json`, or `None` once the timestamp is loaded or after 256 rotations. A "not found"
    /// (HTTP 404 or 403) for it ends the rotation.
    pub fn next_root(&self) -> Option<Request> {
        if self.timestamp.is_some() || self.rotations >= limits::ROOT_ROTATIONS {
            return None;
        }
        Some(Request { path: format!("{}.root.json", self.root.meta.common.version + 1), max_length: limits::ROOT })
    }

    /// Takes `N+1.root.json`: version N+1, signed by a threshold of the trusted root's root keys and of its own. Its expiry
    /// is checked once it is the last ([`update_timestamp`](Self::update_timestamp)).
    pub fn update_root(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.timestamp.is_some() {
            return Err(Error::State("a root after the timestamp".into()));
        }
        let env = envelope(bytes)?;
        let new = Root::parse(&env.signed)?;
        self.root.meta.verify("root", &env)?;
        let expected = self.root.meta.common.version + 1;
        if new.common.version != expected {
            return Err(Error::Version { role: "root".into(), expected, got: new.common.version });
        }
        new.verify("root", &env)?;
        // (a timestamp or snapshot kept from before is loaded only after this, and so checked with the new root's keys: one
        // whose key was rotated away does not verify and is dropped, which is the specification's recovery from a
        // fast-forward attack)
        self.root = Trusted { meta: new, bytes: bytes.to_vec() };
        self.rotations += 1;
        Ok(())
    }

    fn check_expiry(&self, role: &str, c: &Common) -> Result<(), Error> {
        if self.now >= c.expires {
            return Err(Error::Expired { role: role.into(), expires: c.expires });
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------------- timestamp

    /// What to fetch for the timestamp: `timestamp.json`.
    pub fn timestamp_request(&self) -> Request {
        Request { path: "timestamp.json".into(), max_length: limits::TIMESTAMP }
    }

    /// Takes a timestamp the caller kept from an earlier update, for rollback protection. It is checked against the
    /// current root's keys and ignored (an error is returned, nothing changes) if it does not verify; an expired one is
    /// kept for the comparison and an error says that it expired. Call it after the root is final and before
    /// [`update_timestamp`](Self::update_timestamp) ([`refresh`] does, given [`Local`] metadata).
    pub fn load_local_timestamp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.timestamp_step(bytes).map(|_| ())
    }

    /// Takes the repository's timestamp. The last root must not have expired. Signed by a threshold of the timestamp keys;
    /// not older than one trusted before, and naming no older snapshot; the same version as the one trusted leaves that one
    /// ([`TimestampUpdate::Unchanged`]); and not expired.
    pub fn update_timestamp(&mut self, bytes: &[u8]) -> Result<TimestampUpdate, Error> {
        self.timestamp_step(bytes)
    }

    fn timestamp_step(&mut self, bytes: &[u8]) -> Result<TimestampUpdate, Error> {
        if self.snapshot.is_some() {
            return Err(Error::State("a timestamp after the snapshot".into()));
        }
        self.check_expiry("root", &self.root.meta.common)?;
        let env = envelope(bytes)?;
        let new = Timestamp::parse(&env.signed)?;
        self.root.meta.verify("timestamp", &env)?;
        if let Some(old) = &self.timestamp {
            if new.common.version < old.meta.common.version {
                return Err(Error::Rollback(format!("timestamp version {} after {}", new.common.version, old.meta.common.version)));
            }
            if new.common.version == old.meta.common.version {
                return Ok(TimestampUpdate::Unchanged);
            }
            if new.snapshot.version < old.meta.snapshot.version {
                return Err(Error::Rollback(format!("the timestamp names snapshot version {} after {}", new.snapshot.version, old.meta.snapshot.version)));
            }
        }
        self.timestamp = Some(Trusted { meta: new, bytes: bytes.to_vec() });
        self.check_final_timestamp()?;
        Ok(TimestampUpdate::New)
    }

    fn check_final_timestamp(&self) -> Result<&Timestamp, Error> {
        let t = &self.timestamp.as_ref().ok_or_else(|| Error::State("no timestamp".into()))?.meta;
        self.check_expiry("timestamp", &t.common)?;
        Ok(t)
    }

    // ---------------------------------------------------------------------------------------- snapshot

    /// What to fetch for the snapshot: `V.snapshot.json` for the version the timestamp names (`snapshot.json` in a
    /// repository without consistent snapshots), as long as the timestamp says, or [`limits::SNAPSHOT`].
    pub fn snapshot_request(&self) -> Result<Request, Error> {
        let t = self.check_final_timestamp()?;
        let path = if self.root.meta.consistent_snapshot { format!("{}.snapshot.json", t.snapshot.version) } else { "snapshot.json".into() };
        Ok(Request { path, max_length: t.snapshot.length.unwrap_or(limits::SNAPSHOT) })
    }

    /// Takes a snapshot the caller kept from an earlier update. It need not have the hashes the current timestamp gives;
    /// it must verify with the snapshot keys. It is kept for rollback protection even when it is not the current one, and
    /// is used as the current one if it is (then there is nothing to fetch: [`snapshot_is_final`](Self::snapshot_is_final)).
    pub fn load_local_snapshot(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.snapshot_step(bytes, true)
    }

    /// Whether the trusted snapshot is the one the timestamp names and has not expired.
    pub fn snapshot_is_final(&self) -> bool {
        self.check_final_snapshot().is_ok()
    }

    /// Takes the repository's snapshot: the length and hashes the timestamp gives; signed by a threshold of the snapshot
    /// keys; every targets file of a snapshot trusted before still there and not older; the version the timestamp names;
    /// not expired.
    pub fn update_snapshot(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.snapshot_step(bytes, false)
    }

    fn snapshot_step(&mut self, bytes: &[u8], local: bool) -> Result<(), Error> {
        if !self.targets.is_empty() {
            return Err(Error::State("a snapshot after targets".into()));
        }
        let meta = self.check_final_timestamp()?.snapshot.clone();
        if !local {
            meta.check("snapshot", bytes)?;
        }
        let env = envelope(bytes)?;
        let new = Snapshot::parse(&env.signed)?;
        self.root.meta.verify("snapshot", &env)?;
        if let Some(old) = &self.snapshot {
            for (name, m) in &old.meta.meta {
                match new.meta.get(name) {
                    None => return Err(Error::Rollback(format!("the snapshot no longer lists {name}"))),
                    Some(n) if n.version < m.version => return Err(Error::Rollback(format!("{name} version {} after {}", n.version, m.version))),
                    _ => {}
                }
            }
        }
        self.snapshot = Some(Trusted { meta: new, bytes: bytes.to_vec() });
        self.check_final_snapshot().map(|_| ())
    }

    fn check_final_snapshot(&self) -> Result<&Snapshot, Error> {
        let t = self.check_final_timestamp()?;
        let s = &self.snapshot.as_ref().ok_or_else(|| Error::State("no snapshot".into()))?.meta;
        self.check_expiry("snapshot", &s.common)?;
        if s.common.version != t.snapshot.version {
            return Err(Error::Version { role: "snapshot".into(), expected: t.snapshot.version, got: s.common.version });
        }
        Ok(s)
    }

    // ---------------------------------------------------------------------------------------- targets

    /// What to fetch for a targets role: `V.ROLE.json` (`ROLE.json` without consistent snapshots, the name percent-encoded
    /// as python-tuf does), as long as the snapshot says, or [`limits::TARGETS`].
    pub fn targets_request(&self, role: &str) -> Result<Request, Error> {
        let s = self.check_final_snapshot()?;
        let Some(m) = s.meta.get(&format!("{role}.json")) else { return Err(Error::Malformed(format!("the snapshot does not list {role}.json"))) };
        let name = quote(role);
        let path = if self.root.meta.consistent_snapshot { format!("{}.{name}.json", m.version) } else { format!("{name}.json") };
        Ok(Request { path, max_length: m.length.unwrap_or(limits::TARGETS) })
    }

    /// Takes the top-level `targets` metadata.
    pub fn update_targets(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.update_delegated("targets", "root", bytes)
    }

    /// Takes the metadata of `role`, delegated by `delegator` (`root` for `targets`): the length, hashes and version the
    /// snapshot gives; signed by a threshold of the keys the delegator gives the role; not expired.
    pub fn update_delegated(&mut self, role: &str, delegator: &str, bytes: &[u8]) -> Result<(), Error> {
        let s = self.check_final_snapshot()?;
        let Some(meta) = s.meta.get(&format!("{role}.json")).cloned() else { return Err(Error::Malformed(format!("the snapshot does not list {role}.json"))) };
        meta.check(role, bytes)?;
        let env = envelope(bytes)?;
        let new = Targets::parse(&env.signed)?;
        if delegator == "root" {
            if role != "targets" {
                return Err(Error::State(format!("{role} is not delegated by the root")));
            }
            self.root.meta.verify("targets", &env)?;
        } else {
            let parent = self.targets.get(delegator).ok_or_else(|| Error::State(format!("{delegator} is not loaded")))?;
            let d = parent.delegations.as_ref().ok_or_else(|| Error::State(format!("{delegator} delegates nothing")))?;
            let r = d.roles.iter().find(|r| r.name == role).ok_or_else(|| Error::State(format!("{delegator} does not delegate {role}")))?;
            verify_role(role, &d.keys, &r.keys, &env)?;
        }
        if new.common.version != meta.version {
            return Err(Error::Version { role: role.into(), expected: meta.version, got: new.common.version });
        }
        self.check_expiry(role, &new.common)?;
        self.targets.insert(role.to_string(), new);
        Ok(())
    }

    /// Looks `path` up, as python-tuf's preorder depth-first walk does: the top-level targets first, then each delegated
    /// role that covers the path, in the order of the delegating role, children before the next sibling; a terminating role
    /// that covers the path ends the search outside it; at most [`limits::DELEGATIONS`] roles are visited. A role that is
    /// needed and not loaded yet is asked for ([`Lookup::Load`]).
    pub fn find_target(&self, path: &str) -> Result<Lookup, Error> {
        let mut stack: Vec<(String, String)> = vec![("targets".into(), "root".into())];
        let mut visited: Vec<String> = Vec::new();
        while visited.len() <= limits::DELEGATIONS && !stack.is_empty() {
            let (role, parent) = stack.pop().expect("not empty");
            if visited.contains(&role) {
                continue;
            }
            let Some(t) = self.targets.get(&role) else { return Ok(Lookup::Load { role, delegator: parent }) };
            if let Some(f) = t.targets.get(path) {
                return Ok(Lookup::Found(f.clone()));
            }
            visited.push(role.clone());
            if let Some(d) = &t.delegations {
                let mut children = Vec::new();
                for r in d.roles.iter().filter(|r| r.covers(path)) {
                    children.push((r.name.clone(), role.clone()));
                    if r.terminating {
                        stack.clear();
                        break;
                    }
                }
                children.reverse();
                stack.extend(children);
            }
        }
        Ok(Lookup::NotFound)
    }

    /// Where a target is fetched from, relative to the targets URL: with consistent snapshots, its directory, the first of
    /// its hashes, a dot and its file name (`registry.npmjs.org/<hex>.keys.json`); otherwise its path.
    pub fn target_request(&self, target: &TargetFile) -> Request {
        let path = if self.root.meta.consistent_snapshot {
            let first = &target.hashes[0].1;
            match target.path.rsplit_once('/') {
                Some((dir, name)) => format!("{dir}/{first}.{name}"),
                None => format!("{first}.{}", target.path),
            }
        } else {
            target.path.clone()
        };
        Request { path, max_length: target.length }
    }
}

/// Python's `urllib.parse.quote(name, "")`: every byte but ASCII letters, digits and `_.-~` percent-encoded.
fn quote(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ================================================================================================ driving it

/// What fetching one file gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// The bytes (no more than the request's `max_length`).
    Data(Vec<u8>),
    /// It is not there (HTTP 404 or 403).
    NotFound,
}

/// Metadata the caller kept from an earlier update (the bytes [`Updater::timestamp`] and [`Updater::snapshot`] gave), for
/// rollback protection: a repository cannot then go back to an older timestamp or snapshot without being noticed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Local<'a> {
    pub timestamp: Option<&'a [u8]>,
    pub snapshot: Option<&'a [u8]>,
}

/// Brings `u` up to date, in the order of the specification and python-tuf: rotates the root as far as the repository goes,
/// loads the local timestamp (if it does not verify with the root now trusted, or has expired, it is dropped or only
/// compared against), the repository's timestamp, the local snapshot (used as it is if it is the current one), the
/// repository's snapshot, and the top-level targets. Each file is fetched with `metadata` (a path relative to the metadata
/// URL, and the most bytes to take).
pub fn refresh(u: &mut Updater, local: Local, metadata: &mut dyn FnMut(&Request) -> Result<Fetched, String>) -> Result<(), Error> {
    while let Some(req) = u.next_root() {
        match fetch(metadata, &req)? {
            Fetched::Data(d) => u.update_root(&d)?,
            Fetched::NotFound => break,
        }
    }
    if let Some(t) = local.timestamp {
        // what was trusted before is only a floor for rollback checks: if it no longer verifies, it is not used
        let _ = u.load_local_timestamp(t);
    }
    let req = u.timestamp_request();
    let data = required(metadata, &req)?;
    u.update_timestamp(&data)?;
    if let Some(s) = local.snapshot {
        let _ = u.load_local_snapshot(s);
    }
    if !u.snapshot_is_final() {
        let req = u.snapshot_request()?;
        let data = required(metadata, &req)?;
        u.update_snapshot(&data)?;
    }
    let req = u.targets_request("targets")?;
    let data = required(metadata, &req)?;
    u.update_targets(&data)
}

/// Finds `path` (fetching delegated metadata with `metadata` as needed) and fetches it with `target` (a path relative to
/// the targets URL), checking its length and hashes. Call after [`refresh`].
pub fn fetch_target(
    u: &mut Updater,
    path: &str,
    metadata: &mut dyn FnMut(&Request) -> Result<Fetched, String>,
    target: &mut dyn FnMut(&Request) -> Result<Fetched, String>,
) -> Result<(TargetFile, Vec<u8>), Error> {
    let info = loop {
        match u.find_target(path)? {
            Lookup::Found(t) => break t,
            Lookup::NotFound => return Err(Error::NotFound(path.into())),
            Lookup::Load { role, delegator } => {
                let req = u.targets_request(&role)?;
                let data = required(metadata, &req)?;
                u.update_delegated(&role, &delegator, &data)?;
            }
        }
    };
    let data = required(target, &u.target_request(&info))?;
    info.verify(&data)?;
    Ok((info, data))
}

fn fetch(f: &mut dyn FnMut(&Request) -> Result<Fetched, String>, req: &Request) -> Result<Fetched, Error> {
    let got = f(req).map_err(|e| Error::Fetch(format!("{}: {e}", req.path)))?;
    if let Fetched::Data(d) = &got {
        if d.len() as u64 > req.max_length {
            return Err(Error::LengthOrHash(format!("{} is longer than {} bytes", req.path, req.max_length)));
        }
    }
    Ok(got)
}

fn required(f: &mut dyn FnMut(&Request) -> Result<Fetched, String>, req: &Request) -> Result<Vec<u8>, Error> {
    match fetch(f, req)? {
        Fetched::Data(d) => Ok(d),
        Fetched::NotFound => Err(Error::Fetch(format!("{} is not in the repository", req.path))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_is_securesystemslibs() {
        let v = json::parse(r#"{"b": [1, -0, true, null], "a": "q\"\\\n\u00e9", "\u00e9": {}, "B": 2}"#.as_bytes()).unwrap();
        assert_eq!(canonical_json(&v).unwrap(), "{\"B\":2,\"a\":\"q\\\"\\\\\n\u{e9}\",\"b\":[1,0,true,null],\"\u{e9}\":{}}".as_bytes());
        assert!(canonical_json(&json::parse(b"[1.5]").unwrap()).is_err());
        assert!(canonical_json(&json::parse(b"[1e3]").unwrap()).is_err());
        assert_eq!(canonical_json(&json::parse(b"[123456789012345678901234567890]").unwrap()).unwrap(), b"[123456789012345678901234567890]");
    }

    #[test]
    fn path_patterns_match_segment_by_segment() {
        for (t, p, want) in [
            ("registry.npmjs.org/keys.json", "registry.npmjs.org/*", true),
            ("registry.npmjs.org/a/keys.json", "registry.npmjs.org/*", false),
            ("registry.npmjs.org", "registry.npmjs.org/*", false),
            ("a/b.txt", "*/*.txt", true),
            ("a/b.txt", "*", false),
            ("abc", "a?c", true),
            ("ac", "a?c", false),
            ("a1", "a[0-9]", true),
            ("ax", "a[0-9]", false),
            ("ax", "a[!0-9]", true),
            ("a]", "a[]]", true),
            ("a-", "a[!]-]", false),
            ("a[", "a[", true),
            ("a[b", "a[b", true),
            ("ab", "a[z-a]", false),
            ("", "*", true),
            ("x", "", false),
            ("A", "a", false),
            ("aXbXc", "a*b*c", true),
            ("aXbX", "a*b*c", false),
            ("é", "?", true),
            ("a\\b", "a\\b", true),
        ] {
            assert_eq!(path_matches(t, p), want, "{t:?} against {p:?}");
        }
    }

    #[test]
    fn a_role_covers_paths_or_hash_prefixes() {
        let r = |paths: Option<Vec<&str>>, prefixes: Option<Vec<&str>>| DelegatedRole {
            name: "r".into(),
            keys: RoleKeys { keyids: vec![], threshold: 1 },
            terminating: false,
            paths: paths.map(|v| v.into_iter().map(str::to_string).collect()),
            path_hash_prefixes: prefixes.map(|v| v.into_iter().map(str::to_string).collect()),
        };
        let h = hex(&HashAlg::Sha256.digest(b"file.txt"));
        assert!(r(None, Some(vec![&h[..2]])).covers("file.txt"));
        assert!(r(None, Some(vec!["zz", &h[..5]])).covers("file.txt"));
        assert!(!r(None, Some(vec!["zz"])).covers("file.txt"));
        assert!(r(Some(vec!["*.txt"]), None).covers("file.txt"));
        assert!(!r(Some(vec![]), None).covers("file.txt"));
    }

    #[test]
    fn names_are_quoted_as_python_quotes_them() {
        assert_eq!(quote("registry.npmjs.org"), "registry.npmjs.org");
        assert_eq!(quote("a/b c%"), "a%2Fb%20c%25");
        assert_eq!(quote("é"), "%C3%A9");
    }

    #[test]
    fn expiry_must_be_whole_seconds_in_utc() {
        let v = |s: &str| json::parse(format!("{{\"expires\": \"{s}\"}}").as_bytes()).unwrap();
        assert_eq!(expires(&v("2030-01-01T00:00:00Z"), "s").unwrap(), 1_893_456_000);
        for bad in ["2030-01-01T00:00:00.5Z", "2030-01-01T00:00:00+00:00", "2030-01-01 00:00:00Z", "2030-02-30T00:00:00Z", "2030-01-01T00:00:60Z", "2030-1-01T00:00:00Z"] {
            assert!(expires(&v(bad), "s").is_err(), "{bad}");
        }
    }

    #[test]
    fn hashes_are_compared_as_lower_case_hex_and_unknown_algorithms_refused() {
        let d = b"data";
        let h = hex(&HashAlg::Sha256.digest(d));
        assert!(check_hashes("f", d, &[("sha256".into(), h.clone())]).is_ok());
        assert!(check_hashes("f", d, &[("sha256".into(), h.to_uppercase())]).is_err());
        assert!(check_hashes("f", d, &[("sha256".into(), h.clone()), ("md5".into(), "00".into())]).unwrap_err().to_string().contains("unsupported hash algorithm"));
        assert!(check_hashes("f", d, &[("sha512".into(), hex(&HashAlg::Sha512.digest(d))), ("sha384".into(), hex(&HashAlg::Sha384.digest(d)))]).is_ok());
        assert!(check_length("f", d, 4).is_ok() && check_length("f", d, 5).is_err());
    }

    #[test]
    fn the_embedded_sigstore_root_signs_itself() {
        let u = Updater::new(SIGSTORE_ROOT, 1_790_000_000).unwrap();
        let r = u.root();
        assert_eq!(r.common.version, 15);
        assert!(r.consistent_snapshot);
        assert_eq!((r.roles[0].threshold, r.roles[0].keyids.len()), (3, 5));
        assert!(r.keys.values().all(Key::usable));
        assert_eq!(u.next_root().unwrap(), Request { path: "16.root.json".into(), max_length: limits::ROOT });
        // the root's expiry is checked only once it is the last: then it is an error
        let mut later = Updater::new(SIGSTORE_ROOT, 1_900_000_000).unwrap();
        assert!(matches!(later.update_timestamp(b"{}"), Err(Error::Expired { ref role, .. }) if role == "root"));
    }

    #[test]
    fn errors_say_what_they_are() {
        let all = [
            Error::Malformed("x".into()),
            Error::Unsupported("x".into()),
            Error::Signature { role: "root".into(), verified: 1, threshold: 3 },
            Error::Version { role: "snapshot".into(), expected: 2, got: 1 },
            Error::Rollback("x".into()),
            Error::Expired { role: "timestamp".into(), expires: 5 },
            Error::LengthOrHash("x".into()),
            Error::NotFound("p".into()),
            Error::State("x".into()),
            Error::Fetch("x".into()),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(Error::Signature { role: "root".into(), verified: 1, threshold: 3 }.to_string(), "root metadata is signed by 1 of its keys and needs 3");
    }
}
