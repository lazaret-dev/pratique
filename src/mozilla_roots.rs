//! Mozilla's root store, built into the crate (feature `mozilla-roots`, off by default; BACKLOG B-31).
//!
//! The certificates that NSS, and so Firefox, trusts as certificate authorities for TLS servers, taken from NSS's
//! `certdata.txt` by `tools/gen_mozilla_roots.py` into `roots/mozilla.pem` (which says which NSS version, and the hash
//! of the file it came from). Where Mozilla has set a date after which a CA's new certificates are no longer trusted,
//! the anchor carries it ([`TrustStore::add_der_distrusted_after`]): a leaf issued after it is refused under that root.
//!
//! What it is for: a machine whose own bundle is missing or old (macOS's `/etc/ssl/cert.pem` did not have ISRG Root X2
//! in October 2026; a container may have none at all), and a program that wants the same roots everywhere. What it
//! costs: the roots are as new as this crate's copy, so a root Mozilla adds or removes later reaches the program only
//! with an update of the crate (or of the file, with the tool). It does not read the operating system's store, and
//! the operating system's own changes (a root an administrator added or distrusted) do not apply to it.
//!
//! ```
//! let roots = pratique::mozilla_roots::trust_store();
//! assert!(roots.len() > 100);
//! ```

use crate::pem;
use crate::x509::{AnchorLimits, TrustStore};

const PEM: &str = include_str!("../roots/mozilla.pem");

/// One root of the store.
#[derive(Clone, Debug)]
pub struct MozillaRoot {
    /// NSS's label for it (`CKA_LABEL`), usually the common name.
    pub label: String,
    /// The certificate (DER).
    pub der: Vec<u8>,
    /// Leaves issued after this time (Unix seconds) are not trusted under it.
    pub distrust_tls_after: Option<i64>,
    /// The name constraints NSS imposes on it in code (a NameConstraints extension value, DER), applied as if the root
    /// carried them.
    pub name_constraints: Option<Vec<u8>>,
}

/// The NSS builtins version the roots come from (`2.90`, say).
pub fn version() -> &'static str {
    PEM.lines().find_map(|l| l.strip_prefix("# builtins-version: ")).unwrap_or("unknown")
}

/// Every root, in the order of the file.
pub fn roots() -> Vec<MozillaRoot> {
    let mut out = Vec::new();
    let (mut label, mut distrust, mut block): (String, Option<i64>, Option<String>) = (String::new(), None, None);
    let mut constraints: Option<Vec<u8>> = None;
    for line in PEM.lines() {
        if let Some(b) = block.as_mut() {
            b.push_str(line);
            b.push('\n');
            if line == "-----END CERTIFICATE-----" {
                if let Some(cert) = pem::parse(b).into_iter().next() {
                    out.push(MozillaRoot { label: std::mem::take(&mut label), der: cert.data, distrust_tls_after: distrust.take(), name_constraints: constraints.take() });
                }
                block = None;
            }
        } else if line == "-----BEGIN CERTIFICATE-----" {
            block = Some(format!("{line}\n"));
        } else if let Some(rest) = line.strip_prefix("# distrust-tls-after: ") {
            distrust = rest.split(' ').next().and_then(|t| t.parse().ok());
        } else if let Some(rest) = line.strip_prefix("# name-constraints: ") {
            constraints = hex(rest);
        } else if line.starts_with("# sha256: ") {
        } else if let Some(rest) = line.strip_prefix("# ") {
            label = rest.to_string();
        }
    }
    out
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// A trust store holding every root, each with its distrust date and imposed name constraints. A root this crate cannot
/// parse would be left out; none is (the tests check every one).
pub fn trust_store() -> TrustStore {
    let mut store = TrustStore::empty();
    for root in roots() {
        let limits = AnchorLimits { distrust_after: root.distrust_tls_after, name_constraints: root.name_constraints };
        let _ = store.add_der_with_limits(&root.der, &limits);
    }
    store
}
