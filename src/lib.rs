//! `pratique`: an HTTPS client built from scratch with only the Rust standard library.
//!
//! * TLS 1.3 client (X25519, P-256 and P-384 key exchange with HelloRetryRequest, AES-128/256-GCM,
//!   ChaCha20-Poly1305; sessions resumed from the server's tickets with a fresh key exchange, see
//!   [`tls::Resumption`]), and TLS 1.2 for servers that speak nothing newer (ECDHE and AEAD suites only, the extended
//!   master secret required, the downgrade check of RFC 8446; see [`tls::tls12`]), with a minimum version per client
//!   and per request and the version spoken in every response
//! * X.509 chain validation (RSA and ECDSA P-256/P-384 signatures) and hostname checks
//! * revocation: OCSP stapling and CRLs, with soft-fail and hard-fail policies (see [`revocation`])
//! * HTTP/1.1 (content-length, chunked, redirects); opt-in: `gzip`/`deflate` bodies decoded with limits, a cookie jar,
//!   `Expect: 100-continue`
//! * async use: thread-backed futures, a sans-IO TLS core and an async client (see the `asyncio` module)
//! * Ed25519 verification (the rules of Go's `crypto/ed25519`), and transparency-log verification: signed
//!   notes ([`note`]), Merkle proofs and tiles ([`tlog`]) and the Go checksum database check ([`sumdb`]),
//!   all pure functions over bytes
//! * CMS / PKCS#7 signatures (Java `META-INF/*.RSA`, `.p7s`, S/MIME) and RFC 3161 time stamps, checked
//!   against roots the caller supplies at the time the signature was made ([`cms`], with the BER reader
//!   [`ber`]), also pure
//! * Sigstore attestations (npm provenance, PyPI's PEP 740, any bundle of version 0.1 to 0.3): the DSSE
//!   signature, the signer's Fulcio certificate (with its signed certificate timestamps, [`ct`]) or registry key, Rekor entries (signed entry timestamps and
//!   inclusion proofs to signed checkpoints) and RFC 3161 time stamps, all checked at times the logs and
//!   time-stamp authorities vouch for and never the clock, against a trusted root the caller supplies
//!   ([`sigstore`], [`trust_root`], and a strict I-JSON reader [`json`]), also pure; and a TUF client ([`tuf`], pure, with
//!   a fetcher behind `net`) that brings Sigstore's trusted root and npm's keys from Sigstore's TUF repository
//! * DEFLATE, zlib and gzip decompression with limits on the size and the ratio, as a streaming decoder over slices
//!   ([`inflate`]), also pure; the HTTP client uses it to decode `Content-Encoding` when asked to
//! * features: `net` (default) is everything above except the verification primitives. Without it
//!   (`default-features = false`) the crate is only the pure part (ASN.1 and BER, PEM, X.509 path validation,
//!   revocation checking, SHA-1/2, RSA, ECDSA and Ed25519 verification, CMS signatures, signed notes, Merkle
//!   proofs, the checksum database check, Sigstore bundles and decompression), with `#![forbid(unsafe_code)]`, no I/O and no threads, and it
//!   builds for `wasm32-unknown-unknown`.
//!
//! This crate has zero dependencies. It has not been audited; see README.

#![cfg_attr(not(feature = "net"), forbid(unsafe_code))]

// The pure part: always built. With `default-features = false` this is the whole crate, and it must
// stay free of `unsafe`, I/O, threads and anything that reads the clock or the environment. Every
// module below this line could move unchanged into a crate of its own; `tools/check_features.sh`
// enforces that. The only lines in these files that mention the `net` side carry the marker
// `net seam` and are listed by the script.
pub mod asn1;
pub mod ber;
pub mod cms;
pub mod crypto;
pub mod ct;
pub mod idna;
pub mod inflate;
pub mod json;
#[cfg(feature = "mozilla-roots")]
pub mod mozilla_roots;
#[cfg(test)]
mod fuzz;
pub mod note;
pub mod pem;
pub mod revocation;
pub mod sigstore;
pub mod sumdb;
pub mod tlog;
pub mod trust_root;
pub mod tuf;
pub mod util;
pub mod verify_error;
pub mod x509;

// The `net` part (default feature): TLS, HTTP, sockets, OS randomness, the SIMD kernels and
// zeroizing. It depends on the pure part, never the other way round.
#[cfg(feature = "net")]
pub mod asyncio;
#[cfg(feature = "net")]
pub mod error;
#[cfg(feature = "net")]
pub mod http;
#[cfg(feature = "net")]
pub mod native_roots;
#[cfg(feature = "net")]
pub mod quic;
#[cfg(feature = "net")]
pub mod sys;
#[cfg(feature = "net")]
pub mod tls;
#[cfg(feature = "net")]
pub mod zeroize;

#[cfg(feature = "net")]
pub use http::{Client, Response, ResponseFuture};

/// Fetches `url` with a default [`Client`] (system CA bundle, proxy from the environment).
#[cfg(feature = "net")]
pub fn get(url: &str) -> error::Result<Response> {
    Client::new()?.proxy_from_env().get(url)
}

#[cfg(all(test, feature = "net"))]
mod thread_safety {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}

    /// Compile-time proof that the public types can be shared or moved across threads.
    #[test]
    fn public_types_are_thread_safe() {
        assert_send_sync::<crate::Client>();
        assert_send_sync::<crate::Response>();
        assert_send_sync::<crate::tls::ClientConfig>();
        assert_send_sync::<crate::x509::TrustStore>();
        assert_send_sync::<crate::x509::Certificate>();
        assert_send::<crate::tls::TlsStream<std::net::TcpStream>>();
        assert_send_sync::<crate::asyncio::Pool>();
        assert_send_sync::<crate::ResponseFuture>();
        assert_send_sync::<crate::http::AsyncClient>();
        assert_send::<crate::asyncio::AsyncTlsStream<crate::asyncio::ThreadedStream>>();
        assert_send_sync::<crate::tls::ClientConnection>();
        // the futures of the async client can be moved to another thread (spawned on a runtime)
        fn is_send<F: std::future::Future + Send>(_: &F) {}
        let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty())).into_async();
        is_send(&client.get("https://example.com/"));
        is_send(&client.request("POST", "https://example.com/").body("x").send());
        assert_send_sync::<crate::asyncio::BlockingTask<crate::error::Result<crate::Response>>>();
    }
}
