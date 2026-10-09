//! A TLS 1.3 client (RFC 8446), which speaks TLS 1.2 (RFC 5246) to a server that cannot do 1.3, unless told not to.
//!
//! [`TlsStream`] runs it over any blocking `Read + Write` transport. [`ClientConnection`] is the
//! same protocol as a state machine that does no I/O, for callers that bring their own event
//! loop, and the async stream in [`crate::asyncio`] is built on it.
//!
//! Supported: key exchange with X25519, P-256 and P-384 (X25519 is offered first; a server that
//! wants another group answers with a HelloRetryRequest and the client retries once),
//! TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, certificate chain
//! + hostname validation, ALPN, KeyUpdate, and session resumption with the server's tickets and a fresh key exchange
//! (`psk_dhe_ke`; on by default, see [`Resumption`] for what is kept, for how long and for whom).
//! TLS 1.2, for servers that cannot do 1.3 (the npm registry was one, in 2026), with only what has no known weakness of its own:
//! ECDHE, AEAD suites, the extended master secret required, the downgrade protection of TLS 1.3, no renegotiation, no
//! resumption, and the same certificate checks (see [`tls12`]). [`ClientConfig::min_version`] turns it off.
//! A client certificate, in TLS 1.3, when the server asks for one ([`ClientConfig::with_client_certificate`]).
//! Not supported: TLS 1.1 and earlier, 0-RTT (early data, which can be replayed), resumption in TLS 1.2 and over QUIC,
//! client certificates in TLS 1.2 (an empty Certificate is sent if the server asks), post-quantum or finite-field key
//! exchange groups.
//! Revocation: a stapled OCSP response is requested and checked by default, CRLs can be supplied or
//! fetched, and the policy is in [`ClientConfig::revocation`] (see [`crate::revocation`]).

mod conn;
pub(crate) mod session;
mod split;
// The split tests drive the stream over `UnixStream::pair`, so they are built on Unix only.
#[cfg(all(test, unix))]
mod split_tests;
pub(crate) mod handshake;
pub(crate) mod messages;
mod signature;
pub(crate) mod suite;
pub mod tls12;
pub mod certs;
#[cfg(any(test, feature = "server"))]
pub mod pki;
#[cfg(any(test, feature = "server"))]
pub mod server;
#[cfg(any(test, feature = "server"))]
pub mod server_split;
#[cfg(any(test, feature = "server"))]
pub mod tickets;
#[cfg(test)]
mod server_tests;
#[cfg(any(test, pratique_fuzzing))]
mod scripted;
#[cfg(test)]
mod fake_server;
#[cfg(test)]
mod resumption_tests;
#[cfg(test)]
mod hello_retry;
#[cfg(pratique_fuzzing)]
#[doc(hidden)]
pub mod fuzz_hooks;
#[cfg(all(pratique_fuzzing, feature = "server"))]
#[doc(hidden)]
pub mod server_fuzz;
#[cfg(test)]
mod rfc8448;

pub use conn::ClientConnection;
pub use session::Resumption;
pub use split::{Duplex, TlsReadHalf, TlsWriteHalf};
pub(crate) use conn::RecvBuf;
pub use suite::Suite;

use crate::error::{Error, Result};
use crate::revocation::{Revocation, RevocationMode};
use crate::x509::TrustStore;
use std::io::{self, Read, Write};
use std::sync::Arc;

/// A version of TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
        })
    }
}

/// Client-side TLS settings.
#[derive(Clone)]
pub struct ClientConfig {
    pub trust_store: Arc<TrustStore>,
    /// ALPN protocol names to offer, in preference order.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// When false, the server certificate chain and host name are NOT validated. Testing only.
    pub verify_server_certificate: bool,
    /// Overrides the clock used for certificate validity checks (Unix seconds).
    pub time_override: Option<i64>,
    /// What to do about revoked certificates: OCSP stapling and CRLs. Soft-fail by default. See
    /// [`crate::revocation`].
    pub revocation: Revocation,
    /// Rotate our sending keys with a KeyUpdate once one key has protected this many records
    /// (counting the KeyUpdate itself; at least 2). `None` uses the cipher suite's own limit: 2^24
    /// records for AES-GCM (RFC 8446 section 5.5), far more for ChaCha20-Poly1305.
    pub rekey_after_records: Option<u64>,
    /// The oldest version spoken: TLS 1.2 by default, so that a server that cannot do 1.3 can still be reached (with what
    /// [`tls12`] allows of it); `TlsVersion::Tls13` offers TLS 1.3 alone, as this library did before. Either way a server that
    /// can do 1.3 does 1.3, and one that is made to look as if it cannot (by someone in the middle) is caught by the downgrade
    /// check of RFC 8446.
    pub min_version: TlsVersion,
    /// TLS 1.3 session resumption: on by default, sessions shared by the clones of this configuration and used for at most an
    /// hour after the certificate check they rest on; see [`Resumption`].
    pub resumption: Resumption,
    /// A certificate and key to present when a TLS 1.3 server asks for one (mutual TLS), if its key can make a signature
    /// the server takes; otherwise, and over TLS 1.2, the client answers with no certificate.
    pub client_certificate: Option<Arc<certs::CertifiedKey>>,
}

impl ClientConfig {
    pub fn new(trust_store: TrustStore) -> ClientConfig {
        ClientConfig {
            trust_store: Arc::new(trust_store),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            verify_server_certificate: true,
            time_override: None,
            revocation: Revocation::default(),
            rekey_after_records: None,
            min_version: TlsVersion::Tls12,
            resumption: Resumption::new(),
            client_certificate: None,
        }
    }

    /// Presents `cert` to a server that asks for a client certificate (TLS 1.3).
    pub fn with_client_certificate(mut self, cert: certs::CertifiedKey) -> ClientConfig {
        self.client_certificate = Some(Arc::new(cert));
        self
    }

    /// Sets how sessions are resumed (or [`Resumption::off`]); see [`resumption`](ClientConfig::resumption).
    pub fn with_resumption(mut self, resumption: Resumption) -> ClientConfig {
        self.resumption = resumption;
        self
    }

    /// Sets the oldest TLS version spoken; see [`min_version`](ClientConfig::min_version).
    pub fn with_min_version(mut self, version: TlsVersion) -> ClientConfig {
        self.min_version = version;
        self
    }

    /// Rotates the sending keys after `records` records instead of at the suite's own limit; see
    /// [`rekey_after_records`](ClientConfig::rekey_after_records). Values below 2 count as 2.
    pub fn with_rekey_after_records(mut self, records: u64) -> ClientConfig {
        self.rekey_after_records = Some(records.max(2));
        self
    }

    /// Sets the revocation policy; see [`Revocation`].
    pub fn with_revocation(mut self, revocation: Revocation) -> ClientConfig {
        self.revocation = revocation;
        self
    }

    /// Shorthand for [`with_revocation`](ClientConfig::with_revocation) with just a mode.
    pub fn revocation_mode(mut self, mode: RevocationMode) -> ClientConfig {
        self.revocation.mode = mode;
        self
    }

    /// Uses the operating system's CA bundle (see [`sys::system_trust_store`](crate::sys::system_trust_store)).
    pub fn with_system_roots() -> Result<ClientConfig> {
        Ok(ClientConfig::new(crate::sys::system_trust_store()?))
    }

    /// A configuration that trusts the roots of the operating system's own store (the macOS Keychain's trust settings, the
    /// Windows certificate store): see [`sys::native_trust_store`](crate::sys::native_trust_store).
    pub fn with_native_roots() -> Result<ClientConfig> {
        Ok(ClientConfig::new(crate::sys::native_trust_store()?))
    }

    /// Disables certificate validation. Anyone on the network path can then impersonate the server.
    pub fn danger_disable_verification(mut self) -> ClientConfig {
        self.verify_server_certificate = false;
        self
    }
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// Performs the TLS 1.3 handshake over `io`, blocking, and returns the established connection (the sans-IO
/// state, which has our Finished queued: it goes out with the first write). On failure the fatal alert the
/// protocol error called for, if any, is sent before the error is returned.
pub(crate) fn handshake<S: Read + Write>(io: &mut S, server_name: &str, config: &ClientConfig) -> Result<ClientConnection> {
    fn send<S: Write>(io: &mut S, conn: &mut ClientConnection) -> io::Result<()> {
        if !conn.wants_write() {
            return Ok(());
        }
        let res = io.write_all(conn.output());
        let n = conn.output().len();
        conn.consume_output(n);
        res
    }

    fn run<S: Read + Write>(io: &mut S, conn: &mut ClientConnection) -> Result<()> {
        send(io, conn)?; // ClientHello and the compatibility change_cipher_spec, in one write
        io.flush()?;
        while conn.is_handshaking() {
            // one read from the transport; an end of file is an error unless the peer said close_notify first
            loop {
                let space = conn.recv_buf();
                match io.read(space) {
                    Ok(0) => {
                        conn.recv_eof()?;
                        break;
                    }
                    Ok(n) => {
                        conn.recv_filled(n);
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            conn.process()?;
            if conn.is_handshaking() {
                // A HelloRetryRequest is answered with a second ClientHello, which has to be on
                // its way before the server can reply. (When the handshake has just finished, what
                // is queued is our Finished, which waits for the first request.)
                send(io, conn)?;
                io.flush()?;
            }
        }
        Ok(())
    }

    let mut conn = ClientConnection::new(server_name, config)?;
    match run(io, &mut conn) {
        Ok(()) => Ok(conn),
        Err(e) => {
            // a fatal alert, if the protocol error called for one; the connection is dead
            let _ = send(io, &mut conn);
            let _ = io.flush();
            Err(e)
        }
    }
}

/// An established TLS connection (1.3, or 1.2 with a server that cannot do 1.3). Implements [`Read`] and [`Write`].
///
/// A blocking driver around [`ClientConnection`].
pub struct TlsStream<S: Read + Write> {
    io: S,
    conn: ClientConnection,
}

impl<S: Read + Write> TlsStream<S> {
    /// Performs the TLS 1.3 handshake over `io`, verifying the server against `server_name`
    /// (a DNS name or IP literal).
    ///
    /// The client's final handshake message (Finished) is not sent until the connection is first
    /// used: it travels in the same write as the first request. Reading, writing, `flush` and
    /// `close`/drop all send it first, so this only matters to code that watches the raw transport.
    pub fn connect(mut io: S, server_name: &str, config: &ClientConfig) -> Result<TlsStream<S>> {
        let conn = handshake(&mut io, server_name, config)?;
        Ok(TlsStream { io, conn })
    }

    /// A stream over a transport and a connection whose handshake has been done by [`handshake`].
    pub(crate) fn from_parts(io: S, conn: ClientConnection) -> TlsStream<S> {
        TlsStream { io, conn }
    }

    /// Sends everything the connection has queued with one `write_all`. The queue is emptied even
    /// if the write fails, so stale bytes can never be sent later in the middle of a record.
    fn send_output(&mut self) -> io::Result<()> {
        if !self.conn.wants_write() {
            return Ok(());
        }
        let res = self.io.write_all(self.conn.output());
        let n = self.conn.output().len();
        self.conn.consume_output(n);
        res
    }

    /// Reads once from the transport into the connection. An end of file is an error unless the
    /// peer said close_notify first.
    fn receive(&mut self) -> Result<()> {
        loop {
            let space = self.conn.recv_buf();
            match self.io.read(space) {
                Ok(0) => return self.conn.recv_eof(),
                Ok(n) => {
                    self.conn.recv_filled(n);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends the fatal alert a failed `process` queued, then turns the error into an I/O error.
    fn failed(&mut self, e: Error) -> io::Error {
        let _ = self.send_output();
        let _ = self.io.flush();
        to_io(e)
    }

    /// The TLS 1.3 cipher suite negotiated with the server; `None` for a TLS 1.2 connection.
    pub fn cipher_suite(&self) -> Option<Suite> {
        self.conn.cipher_suite()
    }

    /// The TLS 1.2 cipher suite negotiated with the server, if it is a TLS 1.2 connection.
    pub fn cipher_suite12(&self) -> Option<tls12::Suite12> {
        self.conn.cipher_suite12()
    }

    /// The name of the negotiated cipher suite, in either version.
    pub fn cipher_suite_name(&self) -> Option<&'static str> {
        self.conn.cipher_suite_name()
    }

    /// The version of TLS spoken.
    pub fn protocol_version(&self) -> Option<TlsVersion> {
        self.conn.protocol_version()
    }

    /// Whether the handshake resumed a session (see [`Resumption`]).
    pub fn is_resumed(&self) -> bool {
        self.conn.is_resumed()
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// The server's end-entity certificate (DER).
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.conn.peer_certificate()
    }

    /// Every certificate the server sent, DER encoded, leaf first. Useful for diagnosing a chain
    /// that failed validation elsewhere or for pinning an intermediate.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.conn.peer_certificates()
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Digests what arrived along with the end of the last response (session tickets, a
    /// KeyUpdate), sends what that calls for, and says whether the connection is now quiet, that
    /// is, fit to wait for another request: no unread data, no partial record, nobody closing.
    pub fn settle(&mut self) -> bool {
        if self.conn.process().is_err() {
            return false;
        }
        if self.conn.wants_write() && (self.send_output().is_err() || self.io.flush().is_err()) {
            return false;
        }
        self.conn.is_quiet()
    }

    /// Sends a close_notify alert. The write side is closed afterwards.
    pub fn close(&mut self) -> Result<()> {
        if self.conn.write_closed() {
            return Ok(());
        }
        self.conn.send_close_notify();
        self.send_output()?;
        self.io.flush()?;
        Ok(())
    }
}

impl<S: Duplex> TlsStream<S> {
    /// Splits the stream into a reading half and a writing half, which two threads can use at once (one waits for what the
    /// server sends while the other sends). They share the TLS state; reading never waits for a write that is blocked, and
    /// records go out in the order they are made, with the answers to the server's KeyUpdates among them. Our Finished, if
    /// it has not gone yet, is sent first. Dropping the writing half (or [`TlsWriteHalf::close`]) sends close_notify.
    ///
    /// The transport is split with [`Duplex::duplicate`] (for a socket, a second handle to it), so its options, such as
    /// timeouts, are shared by both halves.
    pub fn split(mut self) -> io::Result<(TlsReadHalf<S>, TlsWriteHalf<S>)> {
        self.flush()?;
        let reader = self.io.duplicate()?;
        let writer = self.io.duplicate()?;
        // what is left is spent, so dropping it (and the original handle) sends nothing
        let conn = std::mem::replace(&mut self.conn, ClientConnection::spent());
        Ok(split::halves(conn, reader, writer))
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.conn.read_plaintext(buf);
            if n > 0 {
                return Ok(n);
            }
            if self.conn.peer_closed() {
                return Ok(0);
            }
            if let Err(e) = self.conn.process() {
                return Err(self.failed(e));
            }
            if self.conn.has_plaintext() || self.conn.peer_closed() {
                continue;
            }
            // About to block on the peer: make sure it has what we queued first (our Finished,
            // or the answer to a KeyUpdate).
            if self.conn.wants_write() {
                self.send_output()?;
                self.io.flush()?;
            }
            self.receive().map_err(to_io)?;
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Up to four records' worth per call; they are encrypted into the connection's output
        // buffer (behind the client Finished, for the first write) and sent with one `write_all`.
        let n = self.conn.write_plaintext(buf).map_err(to_io)?;
        self.send_output()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_output()?;
        self.io.flush()
    }
}

impl<S: Read + Write> Drop for TlsStream<S> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
