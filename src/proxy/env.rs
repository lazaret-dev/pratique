//! Pointing programs at the proxy: the files that make them trust its CA, and the environment variables that name the
//! proxy and those files, for the package managers of Python and JavaScript and the tools under them.
//!
//! | variable | read by |
//! |----------|---------|
//! | `HTTPS_PROXY`, `HTTP_PROXY` (and lower case) | pip, uv, Poetry, requests, urllib, npm, pnpm, Yarn 1, curl, Go, git |
//! | `PIP_PROXY` | pip (over a `proxy` in its configuration files, which would win over `HTTPS_PROXY`) |
//! | `npm_config_https_proxy`, `npm_config_proxy` | npm, pnpm, Yarn 1 (over a value in `.npmrc`) |
//! | `YARN_HTTPS_PROXY`, `YARN_HTTP_PROXY` | Yarn 2 and later |
//! | `NO_PROXY` (and lower case), `npm_config_noproxy` | the same: this machine itself, never through the proxy (and the registries not passed by, whatever a `.npmrc` says) |
//! | `NODE_EXTRA_CA_CERTS` | Node.js and what runs on it (npm, pnpm, Yarn): added to Node's own roots |
//! | `SSL_CERT_FILE` | OpenSSL (Python's `ssl`, curl built on it, Ruby), uv, Go on Linux |
//! | `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` | requests (and Poetry), pip, curl, git |
//!
//! Each names the bundle: the roots this machine trusts ([`local_roots`]) and the proxy's CA, so that the hosts the proxy
//! tunnels, whose certificates the program checks itself, still verify. Java keeps its roots in a KeyStore of its own,
//! which this does not write (`keytool -importcert` adds the CA's file, [`TrustFiles::ca`]).
//!
//! **Behind a gateway that inspects TLS** (Zscaler, Netskope, a corporate proxy): the gateway signs every site again
//! with the company's root, which the machine's administrator installed, often in the operating system's own store (the
//! macOS Keychain, the Windows certificate store) and in the variables above. [`local_roots`] takes all of those, so the
//! proxy trusts the gateway on its way to the registries, and the programs still trust it for the hosts the proxy
//! tunnels. A gateway reached as an explicit proxy (`HTTPS_PROXY` in the proxy's own environment) is gone through, as
//! [`ProxyBuilder::build`](super::ProxyBuilder::build) says.

use super::Proxy;
use crate::x509::TrustStore;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The files that make programs trust the proxy's CA.
#[derive(Clone, Debug)]
pub struct TrustFiles {
    /// The CA's certificate alone (PEM): for a program told to trust one more certificate (Java's `keytool`).
    pub ca: PathBuf,
    /// The roots this machine trusts and the CA (PEM): what the variables name.
    pub bundle: PathBuf,
}

/// The variables through which a machine's administrator, or a TLS-inspecting gateway's installer, often hands programs
/// the roots they need: files of PEM certificates.
pub const ROOT_FILE_VARIABLES: [&str; 7] = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PIP_CERT", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE"];

/// The roots this machine trusts, together: the system's CA bundle file (the first of the usual places that has one),
/// the operating system's own store where it has one (the macOS Keychain's trust settings, the Windows certificate
/// store: where a company's root is installed), and the certificates of the files that [`ROOT_FILE_VARIABLES`] name in
/// this process's environment; each certificate once. An error only if there is none at all.
pub fn local_roots() -> io::Result<TrustStore> {
    local_roots_from(&|name| std::env::var(name).ok(), true)
}

/// The same with another environment, and without the system's file and store when `system` is false (for tests).
pub(crate) fn local_roots_from(env: &dyn Fn(&str) -> Option<String>, system: bool) -> io::Result<TrustStore> {
    let mut roots = Roots { store: TrustStore::empty(), seen: HashSet::new() };
    if system {
        if let Some(text) = crate::sys::BUNDLE_FILES.iter().find_map(|f| std::fs::read_to_string(f).ok().filter(|t| t.contains("BEGIN CERTIFICATE"))) {
            roots.add_pem(&text);
        }
        if let Ok(native) = crate::sys::native_trust_store() {
            for der in native.certificates() {
                roots.add(der);
            }
        }
    }
    for name in ROOT_FILE_VARIABLES {
        if let Some(text) = env(name).filter(|p| !p.is_empty()).and_then(|p| std::fs::read_to_string(p).ok()) {
            roots.add_pem(&text);
        }
    }
    if roots.store.is_empty() {
        return Err(io::Error::other("no trusted root on this machine: no CA bundle file, no system store, and no file in SSL_CERT_FILE or the like"));
    }
    Ok(roots.store)
}

/// A store being gathered from several places, each certificate once.
struct Roots {
    store: TrustStore,
    seen: HashSet<Vec<u8>>,
}

impl Roots {
    fn add(&mut self, der: &[u8]) {
        if self.seen.insert(der.to_vec()) {
            let _ = self.store.add_der(der); // a certificate that does not parse is left out
        }
    }

    fn add_pem(&mut self, text: &str) {
        for block in crate::pem::parse(text).into_iter().filter(|b| b.label == "CERTIFICATE") {
            self.add(&block.data);
        }
    }
}

/// Percent-encodes what a URL's user information may not hold as it is.
fn userinfo_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Proxy {
    /// Writes `ca.pem` and `bundle.pem` into `dir` (made if missing, and then readable by its owner only), the bundle
    /// with the roots this machine trusts ([`local_roots`]).
    pub fn write_trust_files(&self, dir: &Path) -> io::Result<TrustFiles> {
        self.write_trust_files_with(dir, &local_roots()?)
    }

    /// The same, with the roots of `roots` in the bundle.
    pub fn write_trust_files_with(&self, dir: &Path, roots: &TrustStore) -> io::Result<TrustFiles> {
        super::relay::make_private_dir(dir)?;
        let ca_pem = self.ca().certificate_pem();
        let ca = dir.join("ca.pem");
        let bundle = dir.join("bundle.pem");
        std::fs::write(&ca, &ca_pem)?;
        let mut text = String::new();
        for der in roots.certificates() {
            text.push_str(&super::ca::pem("CERTIFICATE", der));
        }
        text.push_str(&ca_pem);
        std::fs::write(&bundle, text)?;
        Ok(TrustFiles { ca, bundle })
    }

    /// The environment that points programs at the proxy listening on `addr` (an unspecified address, `0.0.0.0` or
    /// `::`, is reached at the loopback address) and makes them trust its CA through `files`; with the proxy's
    /// credentials in its URL, if it has some.
    pub fn client_env(&self, addr: SocketAddr, files: &TrustFiles) -> Vec<(String, String)> {
        let ip = match addr.ip() {
            ip if ip.is_unspecified() && ip.is_ipv4() => "127.0.0.1".to_string(),
            ip if ip.is_unspecified() => "[::1]".to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            ip => ip.to_string(),
        };
        let auth = match &self.0.credentials {
            Some(c) => {
                let (user, pass) = c.split_once(':').unwrap_or((c, ""));
                format!("{}:{}@", userinfo_escape(user), userinfo_escape(pass))
            }
            None => String::new(),
        };
        let url = format!("http://{auth}{ip}:{}", addr.port());
        let bundle = files.bundle.display().to_string();
        let mut env = Vec::new();
        for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "PIP_PROXY", "npm_config_https_proxy", "npm_config_proxy", "YARN_HTTPS_PROXY", "YARN_HTTP_PROXY"] {
            env.push((name.to_string(), url.clone()));
        }
        for name in ["NO_PROXY", "no_proxy", "npm_config_noproxy"] {
            env.push((name.to_string(), "localhost,127.0.0.1,::1".to_string()));
        }
        for name in ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PIP_CERT", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"] {
            env.push((name.to_string(), bundle.clone()));
        }
        env
    }
}

/// `env` as lines for a POSIX shell (`export NAME='value'`), each value quoted.
pub fn shell_exports(env: &[(String, String)]) -> String {
    env.iter().map(|(n, v)| format!("export {n}='{}'\n", v.replace('\'', "'\\''"))).collect()
}
