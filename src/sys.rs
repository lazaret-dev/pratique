//! What the library takes from the operating system: the clock and the CA bundle files. Behind the
//! `net` feature; the pure verification part of the crate is handed the time and the trust anchors.

use crate::error::{cert, Result};
use crate::x509::TrustStore;
use std::path::Path;

/// Loads the trust anchors from a PEM file (a CA bundle).
pub fn trust_store_from_pem_file(path: impl AsRef<Path>) -> Result<TrustStore> {
    let text = std::fs::read_to_string(path)?;
    let mut store = TrustStore::empty();
    store.add_pem(&text);
    if store.is_empty() {
        return cert("no usable certificates found in PEM file");
    }
    Ok(store)
}

/// Where the systems keep their CA bundle file, in the order they are looked for.
pub(crate) const BUNDLE_FILES: [&str; 8] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
];

/// Loads the operating system's CA bundle from its conventional file location.
///
/// Honors `SSL_CERT_FILE` first. Common Linux, macOS and BSD bundle paths follow. On Windows, which has no bundle file,
/// the certificate store is read when none of those exists ([`native_trust_store`]). On macOS the bundle file
/// (`/etc/ssl/cert.pem`) is used, which knows nothing of the Keychain's trust settings: [`native_trust_store`] reads those.
pub fn system_trust_store() -> Result<TrustStore> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        candidates.push(p);
    }
    for p in BUNDLE_FILES {
        candidates.push(p.to_string());
    }
    for c in &candidates {
        if let Ok(store) = trust_store_from_pem_file(c) {
            return Ok(store);
        }
    }
    if cfg!(windows) {
        return native_trust_store();
    }
    cert("could not find a system CA bundle; set SSL_CERT_FILE or load a PEM file explicitly")
}

/// The roots the operating system's own store trusts for TLS servers: the macOS Keychain's trust settings (the user's, the
/// administrator's and the system's), or the Windows certificate store less its `Disallowed` certificates; an error
/// elsewhere. See [`native_roots`](crate::native_roots) for what is taken and what is left out.
pub fn native_trust_store() -> Result<TrustStore> {
    let mut roots = crate::native_roots::native_roots().map_err(crate::error::Error::Tls)?;
    let store = roots.trust_store();
    if store.is_empty() {
        return cert("the operating system's store has no root trusted for TLS servers");
    }
    Ok(store)
}

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
