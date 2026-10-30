//! What the library takes from the operating system: the clock, the CA bundle files, and a socket shutdown that wakes
//! whoever waits on the socket. Behind the `net` feature; the pure verification part of the crate is handed the time and
//! the trust anchors.

use crate::error::{cert, Result};
use crate::x509::TrustStore;
use std::io;
use std::net::{Shutdown, TcpStream};
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

/// Shuts `tcp` down as [`TcpStream::shutdown`] does, and wakes a thread that is blocked reading or writing it, through any
/// handle to it, so that the call ends at once. Linux and macOS end such a wait on the shutdown itself. Windows does not:
/// a blocking `recv` waits on after `shutdown`, and takes what arrives later (B-119). There the calls that wait on the
/// socket are cancelled as well (`CancelIoEx`), and fail; the next call finds the socket shut.
///
/// That cancels a send under way even when only the reading side is shut, which Linux and macOS let go on, and a send
/// cancelled part way does not say how much of it went. So a caller that shuts only the reading side must know that
/// nothing is being sent on the socket: the server stops an HTTP/1.1 connection that waits for a request, an HTTP/2
/// connection once its last bytes are sent and while it holds the right to send, and a tunnel that is over; and the
/// server's writes fail rather than try again a send that was cancelled. Shutting both sides is safe either way: what
/// is under way is meant to end, and the next send finds the socket shut.
pub(crate) fn shutdown(tcp: &TcpStream, how: Shutdown) -> io::Result<()> {
    let result = tcp.shutdown(how);
    #[cfg(windows)]
    windows::cancel_io(tcp);
    result
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    #[link(name = "kernel32")]
    extern "system" {
        fn CancelIoEx(file: *mut c_void, overlapped: *mut c_void) -> i32;
    }

    /// Cancels every call of this process that waits on the socket: a blocking `recv` or `send` on a socket made for
    /// overlapped I/O (the standard library makes its sockets so, and their duplicates) waits for a request that this
    /// cancels, and then fails.
    pub(super) fn cancel_io(tcp: &TcpStream) {
        // SAFETY: the handle is the socket's, open for as long as `tcp` is borrowed (a SOCKET of the system's provider is
        // a kernel handle, which is what CancelIoEx takes); a null OVERLAPPED asks for every request on it to be
        // cancelled, and the call writes nothing of ours. With nothing to cancel it fails, which changes nothing.
        unsafe {
            CancelIoEx(
                tcp.as_raw_socket() as usize as *mut c_void,
                std::ptr::null_mut(),
            );
        }
    }
}
