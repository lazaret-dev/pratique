//! The TLS 1.3 client as a state machine that does no I/O (sans-IO).
//!
//! [`ClientConnection`] only turns bytes into bytes: the caller moves ciphertext between it and
//! any transport (a blocking socket, a non-blocking one, an async stream, a test buffer) and
//! decides when to wait. [`TlsStream`](super::TlsStream) and
//! [`AsyncTlsStream`](crate::asyncio::AsyncTlsStream) are two such drivers.
//!
//! ```
//! # use pratique::tls::{ClientConfig, ClientConnection};
//! # use pratique::x509::TrustStore;
//! # let config = ClientConfig::new(TrustStore::empty());
//! let mut conn = ClientConnection::new("example.com", &config)?;
//! // the ClientHello is waiting to be sent
//! assert!(conn.is_handshaking() && !conn.output().is_empty());
//! let n = conn.output().len();
//! conn.consume_output(n); // ...after writing those bytes to the transport
//! // then: read from the transport into conn.recv_buf(), call conn.recv_filled(n) and
//! // conn.process(), and repeat until conn.is_handshaking() is false.
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! The driver loop, in outline:
//!
//! 1. Send everything in [`output`](ClientConnection::output), then call
//!    [`consume_output`](ClientConnection::consume_output) with the number of bytes accepted.
//! 2. To receive: read from the transport into [`recv_buf`](ClientConnection::recv_buf), call
//!    [`recv_filled`](ClientConnection::recv_filled) with the count, then
//!    [`process`](ClientConnection::process). A read of zero bytes is
//!    [`recv_eof`](ClientConnection::recv_eof).
//! 3. Decrypted data is taken with [`read_plaintext`](ClientConnection::read_plaintext); data to
//!    send is given to [`write_plaintext`](ClientConnection::write_plaintext), which queues the
//!    encrypted records in `output`.
//!
//! The client's final handshake message (Finished) is queued like any other output but nothing
//! forces the driver to send it at once: sending it together with the first request saves a packet.

use super::handshake::{alert_description, take_message, Epoch, Event, Handshake};
use super::messages::*;
use super::suite::*;
use super::tls12::{Handshake12, RecordCipher12, Step12, Suite12, HS_HELLO_REQUEST};
use super::{ClientConfig, TlsVersion};
use crate::crypto::dit::Dit;
use crate::crypto::rand;
use crate::error::{Error, Result};
use crate::zeroize::{Zeroize, Zeroizing};
use std::io;

const MAX_CIPHERTEXT_RECORD: usize = MAX_PLAINTEXT + 256;
/// Size of the receive buffer: room for several maximum-size records, so one read on the
/// transport can bring in more than one record and records are parsed out of memory.
pub(super) const READ_BUF_SIZE: usize = 64 * 1024;
/// How many middlebox-compatibility change_cipher_spec records we tolerate from the server.
const MAX_COMPAT_CCS: u8 = 2;
/// The most plaintext one call to `write_plaintext` accepts: four full records.
const MAX_WRITE: usize = 4 * MAX_PLAINTEXT;

pub(super) fn alert_error(content: &[u8]) -> Error {
    match content.len() {
        2 => Error::Alert(content[0], content[1]),
        // RFC 8446 section 5.4: an alert record with nothing in it is an unexpected_message
        0 => Error::Tls("unexpected_message: empty alert record".into()),
        _ => Error::Tls("decode_error: malformed alert".into()),
    }
}

/// The receive buffer of a [`ClientConnection`], out of it: see `ClientConnection::take_recv_buf`. What it holds is wiped
/// when it is dropped.
pub(crate) struct RecvBuf {
    buf: Vec<u8>,
    /// Where what is received goes: bytes before it are received and not yet parsed.
    end: usize,
}

impl RecvBuf {
    /// Where the next bytes from the transport go. It is not empty (the connection made room for at least the rest of
    /// the record it is waiting for).
    pub(crate) fn space(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..]
    }
}

impl Drop for RecvBuf {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// The record protection of one direction, in either version.
pub(crate) enum Cipher {
    V13(RecordCipher),
    V12(RecordCipher12),
}

impl Cipher {
    fn encrypt_into(&mut self, record_type: u8, content: &[u8], out: &mut Vec<u8>) {
        match self {
            Cipher::V13(c) => c.encrypt_into(record_type, content, out),
            Cipher::V12(c) => c.encrypt_into(record_type, content, out),
        }
    }

    /// Opens a record in place: (content type, where the content starts in `payload`, its length).
    fn decrypt_in_place(&mut self, header: &[u8; 5], payload: &mut [u8]) -> Result<(u8, usize, usize)> {
        match self {
            Cipher::V13(c) => c.decrypt_in_place(header, payload).map(|(t, n)| (t, 0, n)),
            Cipher::V12(c) => c.decrypt_in_place(header, payload),
        }
    }

    fn records(&self) -> u64 {
        match self {
            Cipher::V13(c) => c.records(),
            Cipher::V12(c) => c.records(),
        }
    }
}

/// The handshake in progress, in either version: it starts as TLS 1.3 and becomes TLS 1.2 if the server answers so.
enum Hs {
    V13(Box<Handshake>),
    V12(Box<Handshake12>),
}

/// A TLS client connection (TLS 1.3, or 1.2 with a server that cannot do 1.3) without any I/O. See the module documentation.
pub struct ClientConnection {
    read_cipher: Option<Cipher>,
    write_cipher: Option<Cipher>,
    hs_buf: Vec<u8>,
    /// Receive buffer. `rbuf[rpos..rend]` holds bytes received but not yet parsed.
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// How many bytes from `rpos` the record being waited for needs.
    need: usize,
    /// Decrypted application data not yet handed out: `rbuf[app_pos..app_end]`. It sits in the
    /// already-consumed part of `rbuf` (records are decrypted where they were received), so the
    /// buffer is not compacted or refilled until it has been drained.
    app_pos: usize,
    app_end: usize,
    /// Bytes for the peer: `out[out_pos..]` has not been taken yet.
    out: Vec<u8>,
    out_pos: usize,
    hs: Option<Hs>,
    handshake_done: bool,
    /// The version the server chose, once it has (at its ServerHello).
    version: Option<TlsVersion>,
    /// The TLS 1.2 cipher suite, if the connection is a TLS 1.2 one.
    suite12: Option<Suite12>,
    /// The middlebox-compatibility change_cipher_spec of TLS 1.3 has still to go out, before our next flight (RFC 8446 appendix D.4).
    /// A ClientHello that offers TLS 1.2 cannot be followed by it at once, as a TLS 1.3-only one is, because a TLS 1.2 server
    /// takes a change_cipher_spec before its ServerHello for the error it would be in TLS 1.2.
    compat_ccs_pending: bool,
    got_close_notify: bool,
    sent_close_notify: bool,
    failed: bool,
    suite: Option<Suite>,
    alpn: Option<Vec<u8>>,
    peer_chain: Vec<Vec<u8>>,
    /// A verified chain whose revocation sources are still to be asked (the configuration deferred them).
    unchecked: Option<Box<crate::revocation::Unchecked>>,
    /// Number of compatibility change_cipher_spec records skipped so far.
    ccs_skipped: u8,
    /// Records one sending key may protect before we send a KeyUpdate (including the KeyUpdate).
    rekey_after: u64,
    /// The server took the session the ClientHello offered.
    resumed: bool,
    /// Where the server's tickets go, as soon as the handshake gives the secret to make their PSKs with (TLS 1.3 with
    /// resumption on); `None` otherwise.
    tickets: Option<TicketSink>,
}

/// What turns a NewSessionTicket into a session kept for the next connection.
struct TicketSink {
    resumption: super::Resumption,
    server: String,
    scope: super::session::Scope,
    time_override: Option<i64>,
    /// Set at the end of the handshake: the suite, the resumption master secret and when the chain was checked.
    secret: Option<(Suite, Zeroizing<Vec<u8>>, i64)>,
}

impl ClientConnection {
    /// Starts a connection to `server_name` (a DNS name or IP literal): builds the ClientHello
    /// and leaves it in [`output`](ClientConnection::output).
    pub fn new(server_name: &str, config: &ClientConfig) -> Result<ClientConnection> {
        super::handshake::check_server_name(server_name)?;
        // the key share's private key, the random and the legacy session id, from one call to the system (B-104)
        let all: Zeroizing<[u8; 96]> = Zeroizing::new(rand::bytes()?);
        let mut private = Zeroizing::new([0u8; 32]);
        private.copy_from_slice(&all[..32]);
        let random: [u8; 32] = all[32..64].try_into().expect("32 bytes");
        let session_id: [u8; 32] = all[64..].try_into().expect("32 bytes");
        Ok(ClientConnection::start(server_name, config, private, &random, &session_id))
    }

    /// `new` with the randomness given, so that tests can fix it.
    pub(super) fn start(server_name: &str, config: &ClientConfig, private: Zeroizing<[u8; 32]>, random: &[u8; 32], session_id: &[u8; 32]) -> ClientConnection {
        let (hs, client_hello) = Handshake::start(server_name, config, None, private, random, session_id);
        let mut conn = ClientConnection::blank();
        if config.resumption.is_enabled() {
            conn.tickets = Some(TicketSink {
                resumption: config.resumption.clone(),
                server: super::handshake::session_key(server_name),
                scope: super::handshake::scope_of(config),
                time_override: config.time_override,
                secret: None,
            });
        }
        conn.queue_plain(RT_HANDSHAKE, &client_hello);
        if config.min_version >= TlsVersion::Tls13 {
            // ClientHello plus the middlebox-compatibility change_cipher_spec (RFC 8446 appendix D.4,
            // which the server ignores) go out together.
            conn.queue_plain(RT_CHANGE_CIPHER_SPEC, &[1]);
        } else {
            // (it goes before our second flight instead, if the server speaks TLS 1.3)
            conn.compat_ccs_pending = true;
        }
        conn.hs = Some(Hs::V13(Box::new(hs)));
        conn
    }

    /// A connection that treats `client_hello` (a ClientHello handshake message made elsewhere,
    /// such as a trace from an RFC) as the one it sent, with the matching X25519 private key and
    /// legacy session id. Extensions of the types in `ignored_ee_extensions` that the server
    /// answers in EncryptedExtensions are skipped instead of refused, because the recorded
    /// ClientHello offered extensions this client never does. For tests.
    #[cfg(test)]
    pub(super) fn with_recorded_hello(
        server_name: &str,
        config: &ClientConfig,
        private: [u8; 32],
        session_id: &[u8],
        client_hello: &[u8],
        ignored_ee_extensions: &[u16],
    ) -> ClientConnection {
        let mut conn = ClientConnection::blank();
        conn.queue_plain(RT_HANDSHAKE, client_hello);
        conn.hs = Some(Hs::V13(Box::new(Handshake::recorded(server_name, config, private, session_id, client_hello, ignored_ee_extensions))));
        conn
    }

    fn blank() -> ClientConnection {
        ClientConnection {
            read_cipher: None,
            write_cipher: None,
            hs_buf: Vec::new(),
            rbuf: vec![0u8; READ_BUF_SIZE],
            rpos: 0,
            rend: 0,
            need: 5,
            app_pos: 0,
            app_end: 0,
            out: Vec::new(),
            out_pos: 0,
            hs: None,
            handshake_done: false,
            version: None,
            suite12: None,
            compat_ccs_pending: false,
            got_close_notify: false,
            sent_close_notify: false,
            failed: false,
            suite: None,
            alpn: None,
            peer_chain: Vec::new(),
            unchecked: None,
            ccs_skipped: 0,
            rekey_after: u64::MAX,
            resumed: false,
            tickets: None,
        }
    }

    /// Whether this connection resumed a session (TLS 1.3 with a ticket from an earlier connection to the server): the
    /// server's chain was then checked by that connection, and [`peer_certificates`](Self::peer_certificates) is the chain
    /// it checked.
    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    /// The verified chain whose revocation sources the configuration left for later ([`Revocation::deferred`](
    /// crate::revocation::Revocation::deferred)), taken out (once): finish it with [`Unchecked::check`](
    /// crate::revocation::Unchecked::check) before trusting the connection.
    pub fn take_unchecked(&mut self) -> Option<Box<crate::revocation::Unchecked>> {
        self.unchecked.take()
    }

    /// What is left in a `TlsStream` whose connection has moved elsewhere (`TlsStream::split`): it has no keys and nothing to
    /// send, and counts as closed, so that dropping the stream sends nothing.
    pub(super) fn spent() -> ClientConnection {
        let mut c = ClientConnection::blank();
        c.rbuf = Vec::new();
        c.sent_close_notify = true;
        c.failed = true;
        c
    }

    /// A connection that is already established with fixed traffic keys (for tests and the fuzzer).
    #[cfg(any(test, pratique_fuzzing))]
    pub(super) fn established(suite: Suite, read_secret: &[u8], write_secret: &[u8]) -> ClientConnection {
        let mut c = ClientConnection::blank();
        c.read_cipher = Some(Cipher::V13(RecordCipher::new(suite, read_secret)));
        c.write_cipher = Some(Cipher::V13(RecordCipher::new(suite, write_secret)));
        c.handshake_done = true;
        c.version = Some(TlsVersion::Tls13);
        c.suite = Some(suite);
        c.rekey_after = suite.records_per_key();
        c
    }

    /// Lowers the number of records a sending key protects before a KeyUpdate (for tests and the fuzzer).
    #[cfg(any(test, pratique_fuzzing))]
    pub(super) fn set_rekey_after(&mut self, records: u64) {
        self.rekey_after = records;
    }

    // ------------------------------------------------------------------ state

    /// True until the server's Finished has been verified and ours queued.
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_done && !self.failed
    }

    /// True once the handshake has finished.
    pub fn is_established(&self) -> bool {
        self.handshake_done
    }

    /// True once the peer's close_notify has been received: no more data will arrive.
    pub fn peer_closed(&self) -> bool {
        self.got_close_notify
    }

    /// True after a fatal error: the connection cannot be used any more (a fatal alert may be
    /// waiting in [`output`](ClientConnection::output)).
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// A TLS 1.2 connection that is established with fixed keys (for tests and the fuzzer).
    #[cfg(any(test, pratique_fuzzing))]
    pub(super) fn established12(read: RecordCipher12, write: RecordCipher12) -> ClientConnection {
        let mut c = ClientConnection::blank();
        c.suite12 = Some(read.suite());
        c.rekey_after = read.suite().records_per_key();
        c.read_cipher = Some(Cipher::V12(read));
        c.write_cipher = Some(Cipher::V12(write));
        c.handshake_done = true;
        c.version = Some(TlsVersion::Tls12);
        c
    }

    /// The TLS 1.3 cipher suite negotiated with the server; `None` for a TLS 1.2 connection (see
    /// [`cipher_suite_name`](ClientConnection::cipher_suite_name)).
    pub fn cipher_suite(&self) -> Option<Suite> {
        self.suite
    }

    /// The TLS 1.2 cipher suite negotiated with the server, if the connection is a TLS 1.2 one.
    pub fn cipher_suite12(&self) -> Option<Suite12> {
        self.suite12
    }

    /// The name of the negotiated cipher suite, in either version (`TLS_AES_128_GCM_SHA256`,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, ...).
    pub fn cipher_suite_name(&self) -> Option<&'static str> {
        self.suite12.map(Suite12::name).or(self.suite.map(Suite::name))
    }

    /// The version of TLS the server chose; `None` before its ServerHello.
    pub fn protocol_version(&self) -> Option<TlsVersion> {
        self.version
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The server's end-entity certificate (DER).
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_chain.first().map(|c| c.as_slice())
    }

    /// Every certificate the server sent, DER encoded, leaf first (empty before the handshake
    /// reaches the Certificate message).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_chain
    }

    // ------------------------------------------------------------------ bytes out

    /// Bytes waiting to be sent to the peer.
    pub fn output(&self) -> &[u8] {
        &self.out[self.out_pos..]
    }

    /// True if [`output`](ClientConnection::output) is not empty.
    pub fn wants_write(&self) -> bool {
        self.out_pos < self.out.len()
    }

    /// Marks the first `n` bytes of [`output`](ClientConnection::output) as sent.
    pub fn consume_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out.len());
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
    }

    /// Moves everything waiting to be sent into `into` (cleared first), by swapping buffers when it can, so that it can be
    /// sent with the connection no longer borrowed or locked (`TlsStream::split`).
    pub(crate) fn take_output(&mut self, into: &mut Vec<u8>) {
        into.clear();
        if self.out_pos == 0 {
            std::mem::swap(&mut self.out, into);
        } else {
            into.extend_from_slice(&self.out[self.out_pos..]);
            self.out.clear();
        }
        self.out_pos = 0;
    }

    /// Appends an unprotected record to the output.
    fn queue_plain(&mut self, record_type: u8, content: &[u8]) {
        self.out.extend_from_slice(&[record_type, 0x03, 0x03]);
        self.out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.out.extend_from_slice(content);
    }

    /// Encrypts `content` into records appended to the output.
    fn queue_protected(&mut self, inner_type: u8, content: &[u8]) -> Result<()> {
        let cipher = self.write_cipher.as_mut().ok_or_else(|| Error::Tls("internal: no write keys".into()))?;
        for chunk in content.chunks(MAX_PLAINTEXT) {
            cipher.encrypt_into(inner_type, chunk, &mut self.out);
        }
        Ok(())
    }

    /// Queues application data, encrypted, and returns how many bytes of `data` were taken (at
    /// most four records' worth per call; call again with the rest). Fails before the handshake
    /// has finished, after `send_close_notify` and after a fatal error.
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<usize> {
        if self.failed {
            return Err(Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "the TLS connection failed")));
        }
        if self.sent_close_notify {
            return Err(Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "TLS connection already closed for writing")));
        }
        if !self.handshake_done {
            return Err(Error::Tls("internal: application data before the handshake finished".into()));
        }
        let n = data.len().min(MAX_WRITE);
        let _dit = Dit::on(); // one switch for the records of this call (B-104)
        for chunk in data[..n].chunks(MAX_PLAINTEXT) {
            self.rekey_if_due()?;
            self.queue_protected(RT_APPLICATION_DATA, chunk)?;
        }
        Ok(n)
    }

    /// Sends a KeyUpdate (update_not_requested) and switches our sending keys when the current
    /// ones are about to have protected as many records as they may (RFC 8446 section 5.5 and
    /// 4.6.3). The KeyUpdate is the last record under the old key; the peer is not asked to rotate
    /// its own sending keys, which it does on its own schedule.
    ///
    /// TLS 1.2 has no KeyUpdate: a connection whose key is used up cannot go on, and says so (the HTTP client then opens
    /// another; at 2^24 records of up to 16 KiB that is 256 GiB in one direction).
    fn rekey_if_due(&mut self) -> Result<()> {
        let due = self.write_cipher.as_ref().is_some_and(|c| c.records().saturating_add(1) >= self.rekey_after);
        if due {
            let next = match self.write_cipher.as_ref() {
                Some(Cipher::V13(c)) => c.next_generation(),
                _ => return Err(Error::Tls("internal: this TLS 1.2 connection has sent as much as one key may protect; open another".into())),
            };
            let update = handshake_message(HS_KEY_UPDATE, &[0]);
            self.queue_protected(RT_HANDSHAKE, &update)?;
            self.write_cipher = Some(Cipher::V13(next));
        }
        Ok(())
    }

    /// Queues a close_notify alert; the write side is closed afterwards. Does nothing before the
    /// handshake has finished or after a failure.
    pub fn send_close_notify(&mut self) {
        if !self.handshake_done || self.sent_close_notify || self.failed {
            return;
        }
        self.sent_close_notify = true;
        let _ = self.queue_protected(RT_ALERT, &[1, 0]);
    }

    /// True once `send_close_notify` has been called (or a fatal alert queued).
    pub fn write_closed(&self) -> bool {
        self.sent_close_notify
    }

    // ------------------------------------------------------------------ bytes in

    /// Space to read ciphertext into. Never call this while decrypted data is waiting
    /// ([`has_plaintext`](ClientConnection::has_plaintext)): the buffer cannot be rearranged until
    /// it has been taken, and the slice may then be empty.
    pub fn recv_buf(&mut self) -> &mut [u8] {
        if self.app_pos == self.app_end {
            if self.rpos == self.rend {
                self.rpos = 0;
                self.rend = 0;
            } else if self.rpos + self.need > self.rbuf.len() {
                self.rbuf.copy_within(self.rpos..self.rend, 0);
                self.rend -= self.rpos;
                self.rpos = 0;
            }
        }
        &mut self.rbuf[self.rend..]
    }

    /// Records that `n` bytes were read into [`recv_buf`](ClientConnection::recv_buf).
    pub fn recv_filled(&mut self, n: usize) {
        self.rend = (self.rend + n).min(self.rbuf.len());
    }

    /// Makes the receive buffer at least `size` bytes (it is [`READ_BUF_SIZE`] to begin with): a connection that is
    /// read from a good deal at once, such as one that carries many requests, takes more per read.
    pub(crate) fn grow_recv_buf(&mut self, size: usize) {
        if self.rbuf.len() < size {
            let mut bigger = vec![0u8; size];
            bigger[..self.rbuf.len()].copy_from_slice(&self.rbuf);
            self.rbuf.zeroize();
            self.rbuf = bigger;
        }
    }

    /// Takes the receive buffer out of the connection, arranged as [`recv_buf`](ClientConnection::recv_buf) does, so that the
    /// transport can be read into it without the connection being borrowed (or locked) for as long as that takes, and
    /// without the bytes being copied from a buffer of the reader's into this one. It is given back, with how many bytes
    /// were read into it, by [`restore_recv_buf`](ClientConnection::restore_recv_buf); the connection can do nothing
    /// with received bytes meanwhile. `None` if decrypted data is waiting (it lives in the buffer) or the buffer is out
    /// already.
    pub(crate) fn take_recv_buf(&mut self) -> Option<RecvBuf> {
        if self.app_pos != self.app_end || self.rbuf.is_empty() {
            return None;
        }
        self.recv_buf();
        Some(RecvBuf { buf: std::mem::take(&mut self.rbuf), end: self.rend })
    }

    /// Gives back what [`take_recv_buf`](ClientConnection::take_recv_buf) took; `filled` bytes were read into it.
    pub(crate) fn restore_recv_buf(&mut self, mut taken: RecvBuf, filled: usize) {
        debug_assert!(self.rbuf.is_empty(), "the receive buffer was not out");
        self.rbuf = std::mem::take(&mut taken.buf);
        self.rend = (taken.end + filled).min(self.rbuf.len());
    }

    /// Tells the connection that the transport reached end of file. Returns an error unless the
    /// peer's close_notify was received first: a stream that just stops may have been truncated.
    pub fn recv_eof(&mut self) -> Result<()> {
        if self.got_close_notify {
            return Ok(());
        }
        let msg = if self.rend == self.rpos {
            "connection closed without a TLS close_notify (possible truncation)"
        } else {
            "connection closed in the middle of a TLS record"
        };
        Err(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, msg)))
    }

    /// True if decrypted application data is waiting for [`read_plaintext`](ClientConnection::read_plaintext).
    pub fn has_plaintext(&self) -> bool {
        self.app_pos < self.app_end
    }

    /// True when the connection is established and has nothing going on: no decrypted data and no
    /// received bytes waiting (not even part of a record), nothing queued to send, and neither side
    /// has said close_notify or failed. A connection kept for another request has to be like this.
    /// Records that arrived with the end of the last response (a session ticket, a KeyUpdate) are
    /// only digested by [`process`](ClientConnection::process), so call that first.
    pub fn is_quiet(&self) -> bool {
        self.handshake_done
            && !self.failed
            && !self.got_close_notify
            && !self.sent_close_notify
            && self.app_pos == self.app_end
            && self.rpos == self.rend
            && !self.wants_write()
    }

    /// The decrypted application data waiting, where it is (no copy). Take what is used with
    /// [`consume_plaintext`](ClientConnection::consume_plaintext); nothing else about the connection changes
    /// until then.
    pub fn plaintext(&self) -> &[u8] {
        &self.rbuf[self.app_pos..self.app_end]
    }

    /// `n` bytes of [`plaintext`](ClientConnection::plaintext) have been used.
    pub fn consume_plaintext(&mut self, n: usize) {
        self.app_pos = (self.app_pos + n).min(self.app_end);
    }

    /// Copies decrypted application data into `buf`; returns 0 if there is none right now (call
    /// `process` after receiving more bytes; see also `peer_closed`).
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.app_end - self.app_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rbuf[self.app_pos..self.app_pos + n]);
        self.app_pos += n;
        n
    }

    // ------------------------------------------------------------------ processing

    /// Parses and handles the records received so far: drives the handshake, applies KeyUpdate,
    /// and decrypts application data (which then waits for `read_plaintext`; processing pauses
    /// until it has been drained). Needing more bytes is not an error: it returns `Ok` with
    /// nothing to show for it.
    ///
    /// On a protocol error the connection is dead: the matching fatal alert is queued in the
    /// output (send it if you can) and every later call fails.
    pub fn process(&mut self) -> Result<()> {
        if self.failed {
            return Err(Error::Tls("internal: the connection has already failed".into()));
        }
        // One switch to data-independent timing for all the records this call opens and the handshake work on them (B-104):
        // the AEAD, HMAC and X25519 calls inside then find it set and leave it (on ARM a switch on and off is about 30 ns).
        let _dit = Dit::on();
        match self.process_records() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.fail(&e);
                Err(e)
            }
        }
    }

    fn fail(&mut self, err: &Error) {
        self.failed = true;
        if !self.sent_close_notify {
            if let Some(description) = alert_description(err) {
                let alert = [2u8, description];
                if self.write_cipher.is_some() {
                    let _ = self.queue_protected(RT_ALERT, &alert);
                } else {
                    self.queue_plain(RT_ALERT, &alert);
                }
            }
            // no goodbye after a fatal alert (or after an error we do not answer)
            self.sent_close_notify = true;
        }
    }

    fn process_records(&mut self) -> Result<()> {
        loop {
            if self.app_pos < self.app_end || self.got_close_notify {
                return Ok(());
            }
            let Some((t, start, n)) = self.next_record()? else { return Ok(()) };
            if self.hs.is_some() {
                match t {
                    RT_HANDSHAKE if n == 0 => {
                        // RFC 8446 section 5.1: zero-length fragments of Handshake types are forbidden.
                        return Err(Error::Tls("unexpected_message: empty handshake record".into()));
                    }
                    RT_HANDSHAKE => {
                        self.hs_buf.extend_from_slice(&self.rbuf[start..start + n]);
                        while self.hs.is_some() {
                            let Some(msg) = self.take_buffered_handshake_message()? else { break };
                            self.handshake_step(&msg)?;
                        }
                    }
                    // (only TLS 1.2 passes a change_cipher_spec up: TLS 1.3's are skipped below)
                    RT_CHANGE_CIPHER_SPEC => {
                        if !self.hs_buf.is_empty() {
                            return Err(Error::Tls("unexpected_message: a handshake message is cut by change_cipher_spec".into()));
                        }
                        let Some(Hs::V12(hs)) = self.hs.as_mut() else {
                            return Err(Error::Tls("unexpected_message: change_cipher_spec".into()));
                        };
                        let cipher = hs.on_change_cipher_spec()?;
                        self.read_cipher = Some(Cipher::V12(cipher));
                    }
                    RT_ALERT => return Err(alert_error(&self.rbuf[start..start + n])),
                    _ => return Err(Error::Tls("unexpected_message: non-handshake record during handshake".into())),
                }
            } else {
                // RFC 8446 section 5.1: no record of another type inside a handshake message split over records
                if t != RT_HANDSHAKE && !self.hs_buf.is_empty() {
                    return Err(Error::Tls("unexpected_message: a record of another type inside a handshake message".into()));
                }
                match t {
                    RT_APPLICATION_DATA => {
                        self.app_pos = start;
                        self.app_end = start + n;
                    }
                    RT_ALERT => {
                        let content = &self.rbuf[start..start + n];
                        if content == [1, 0] {
                            self.got_close_notify = true;
                        } else {
                            return Err(alert_error(content));
                        }
                    }
                    RT_HANDSHAKE => {
                        if n == 0 {
                            return Err(Error::Tls("unexpected_message: empty handshake record".into()));
                        }
                        self.hs_buf.extend_from_slice(&self.rbuf[start..start + n]);
                        if self.version == Some(TlsVersion::Tls12) {
                            self.process_post_handshake12()?;
                        } else {
                            self.process_post_handshake()?;
                        }
                    }
                    _ => return Err(Error::Tls("unexpected_message: unexpected record type".into())),
                }
            }
        }
    }

    /// The next complete record in the receive buffer, decrypted in place if needed: (content
    /// type, start, length) with the content in `rbuf[start..start + length]`. `None` when more
    /// bytes are needed. Change-cipher-spec compatibility records are skipped.
    fn next_record(&mut self) -> Result<Option<(u8, usize, usize)>> {
        loop {
            if self.rend - self.rpos < 5 {
                self.need = 5;
                return Ok(None);
            }
            let h = &self.rbuf[self.rpos..self.rpos + 5];
            let header: [u8; 5] = [h[0], h[1], h[2], h[3], h[4]];
            let record_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[1] != 0x03 {
                return Err(Error::Tls("protocol_version: peer is not speaking TLS".into()));
            }
            let limit = if self.read_cipher.is_some() { MAX_CIPHERTEXT_RECORD } else { MAX_PLAINTEXT };
            if length > limit {
                return Err(Error::Tls("record_overflow: record too large".into()));
            }
            if self.rend - self.rpos < 5 + length {
                self.need = 5 + length;
                return Ok(None);
            }
            let start = self.rpos + 5;
            self.rpos = start + length;
            let payload = &mut self.rbuf[start..start + length];
            let tls12 = self.version == Some(TlsVersion::Tls12);
            match (self.read_cipher.as_mut(), record_type) {
                // TLS 1.2's is the real thing: the server's keys start after it (only during the handshake, and before any keys)
                (None, RT_CHANGE_CIPHER_SPEC) if tls12 => {
                    if payload != [1] || self.handshake_done {
                        return Err(Error::Tls("unexpected_message: bad change_cipher_spec".into()));
                    }
                    return Ok(Some((RT_CHANGE_CIPHER_SPEC, start, length)));
                }
                (Some(_), RT_CHANGE_CIPHER_SPEC) if tls12 => {
                    return Err(Error::Tls("unexpected_message: change_cipher_spec after the keys changed".into()));
                }
                (_, RT_CHANGE_CIPHER_SPEC) => {
                    // RFC 8446 appendix D.4: a single 0x01 byte, only during the handshake. A
                    // conforming server sends at most one; a flood is treated as an attack.
                    if self.handshake_done || payload != [1] || self.ccs_skipped >= MAX_COMPAT_CCS {
                        return Err(Error::Tls("unexpected_message: bad change_cipher_spec".into()));
                    }
                    self.ccs_skipped += 1;
                    continue;
                }
                (Some(c @ Cipher::V13(_)), RT_APPLICATION_DATA) => {
                    let (t, _, n) = c.decrypt_in_place(&header, payload)?;
                    if t == RT_CHANGE_CIPHER_SPEC {
                        return Err(Error::Tls("unexpected_message: protected change_cipher_spec".into()));
                    }
                    return Ok(Some((t, start, n)));
                }
                // TLS 1.2 protects records of every type and does not hide which
                (Some(c @ Cipher::V12(_)), RT_APPLICATION_DATA | RT_HANDSHAKE | RT_ALERT) => {
                    let (t, offset, n) = c.decrypt_in_place(&header, payload)?;
                    return Ok(Some((t, start + offset, n)));
                }
                (Some(_), _) => {
                    return Err(Error::Tls("unexpected_message: unprotected record after keys were established".into()));
                }
                (None, RT_ALERT) | (None, RT_HANDSHAKE) => return Ok(Some((record_type, start, length))),
                (None, _) => return Err(Error::Tls("unexpected_message: unexpected record type".into())),
            }
        }
    }

    fn take_buffered_handshake_message(&mut self) -> Result<Option<Vec<u8>>> {
        take_message(&mut self.hs_buf)
    }

    // ------------------------------------------------------------------ handshake

    fn handshake_step(&mut self, msg: &[u8]) -> Result<()> {
        let trailing = !self.hs_buf.is_empty();
        match self.hs.take().ok_or_else(|| Error::Tls("internal: no handshake in progress".into()))? {
            Hs::V13(mut hs) => {
                let events = hs.on_message(msg, trailing)?;
                let rekey_after = hs.config().rekey_after_records;
                // the server may turn out to speak TLS 1.2: the handshake goes on as one of those
                match self.apply(events, rekey_after)? {
                    Some(hs12) => self.hs = Some(Hs::V12(hs12)),
                    None if !self.handshake_done => self.hs = Some(Hs::V13(hs)),
                    None => {}
                }
            }
            Hs::V12(mut hs) => {
                let steps = hs.on_message(msg, trailing)?;
                self.apply12(steps)?;
                if !self.handshake_done {
                    self.hs = Some(Hs::V12(hs));
                }
            }
        }
        Ok(())
    }

    /// Does what a step of the TLS 1.2 handshake asks for, in the order it asks.
    fn apply12(&mut self, steps: Vec<Step12>) -> Result<()> {
        for step in steps {
            match step {
                Step12::SendPlain(m) => self.queue_plain(RT_HANDSHAKE, &m),
                Step12::ChangeCipherSpec(cipher) => {
                    self.queue_plain(RT_CHANGE_CIPHER_SPEC, &[1]);
                    self.rekey_after = cipher.suite().records_per_key();
                    self.write_cipher = Some(Cipher::V12(cipher));
                }
                Step12::SendProtected(m) => self.queue_protected(RT_HANDSHAKE, &m)?,
                Step12::Alpn(protocol) => self.alpn = protocol,
                Step12::PeerCertificates(chain) => self.peer_chain = chain,
                Step12::Unchecked(u) => self.unchecked = Some(u),
                Step12::Established => self.handshake_done = true,
            }
        }
        Ok(())
    }

    /// Queues the middlebox-compatibility change_cipher_spec, if it has not gone out yet.
    fn compat_ccs(&mut self) {
        if std::mem::take(&mut self.compat_ccs_pending) {
            self.queue_plain(RT_CHANGE_CIPHER_SPEC, &[1]);
        }
    }

    /// Does what a step of the handshake asks for, in the order it asks. Returns the TLS 1.2 handshake to go on with if the
    /// server turned out to speak TLS 1.2.
    fn apply(&mut self, events: Vec<Event>, rekey_after: Option<u64>) -> Result<Option<Box<Handshake12>>> {
        for event in events {
            match event {
                Event::Send(Epoch::Initial, message) => {
                    // (a second ClientHello, after a HelloRetryRequest: our second flight)
                    self.compat_ccs();
                    self.queue_plain(RT_HANDSHAKE, &message)
                }
                // protected with the client handshake keys, which are installed by now
                Event::Send(Epoch::Handshake, message) => {
                    self.compat_ccs();
                    self.queue_protected(RT_HANDSHAKE, &message)?
                }
                Event::HandshakeSecrets { suite, client, server } => {
                    self.suite = Some(suite);
                    self.version = Some(TlsVersion::Tls13);
                    self.read_cipher = Some(Cipher::V13(RecordCipher::new(suite, &server)));
                    // from here on anything we send, a fatal alert included, is under the handshake keys
                    self.write_cipher = Some(Cipher::V13(RecordCipher::new(suite, &client)));
                }
                Event::Alpn(protocol) => self.alpn = protocol,
                Event::PeerCertificates(chain) => self.peer_chain = chain,
                Event::Unchecked(u) => self.unchecked = Some(u),
                Event::PeerTransportParameters(_) => {} // only a QUIC handshake has them
                Event::ApplicationSecrets { suite, client, server } => {
                    // The Finished record stays in the output until the driver chooses to send it; see the
                    // module documentation.
                    self.write_cipher = Some(Cipher::V13(RecordCipher::new(suite, &client)));
                    self.read_cipher = Some(Cipher::V13(RecordCipher::new(suite, &server)));
                    self.rekey_after = rekey_after.unwrap_or(suite.records_per_key()).max(2);
                    self.handshake_done = true;
                }
                Event::Resumed => self.resumed = true,
                Event::ResumptionSecret { suite, secret, verified_at } => {
                    // a chain whose revocation is still to be checked (deferred) gives no sessions: a resumption would skip
                    // that check
                    if self.unchecked.is_some() {
                        self.tickets = None;
                    }
                    if let Some(sink) = self.tickets.as_mut() {
                        sink.secret = Some((suite, secret, verified_at));
                    }
                }
                Event::Tls12(hs12, steps) => {
                    // no compatibility change_cipher_spec in TLS 1.2: the real one comes with our flight
                    self.compat_ccs_pending = false;
                    // (and no sessions: resumption here is TLS 1.3's)
                    self.tickets = None;
                    self.version = Some(TlsVersion::Tls12);
                    self.suite12 = Some(hs12.suite());
                    self.apply12(steps)?;
                    return Ok(Some(hs12));
                }
            }
        }
        Ok(None)
    }

    fn process_post_handshake(&mut self) -> Result<()> {
        while let Some(msg) = self.take_buffered_handshake_message()? {
            match msg[0] {
                HS_NEW_SESSION_TICKET => {
                    let ticket = parse_new_session_ticket(&msg[4..])?;
                    self.keep_ticket(ticket);
                }
                HS_KEY_UPDATE => {
                    if msg.len() != 5 {
                        return Err(Error::Tls("decode_error: malformed KeyUpdate".into()));
                    }
                    if msg[4] > 1 {
                        // RFC 8446 section 4.6.3
                        return Err(Error::Tls("illegal_parameter: a KeyUpdate that neither asks nor does not ask".into()));
                    }
                    if !self.hs_buf.is_empty() {
                        // RFC 8446 section 5.1: messages must not span a key change
                        return Err(Error::Tls("unexpected_message: handshake data follows a KeyUpdate in the same record".into()));
                    }
                    let (Some(Cipher::V13(rc)), Some(Cipher::V13(wc))) = (self.read_cipher.as_ref(), self.write_cipher.as_ref()) else {
                        return Err(Error::Tls("internal: KeyUpdate without traffic keys".into()));
                    };
                    let next = rc.next_generation();
                    let next_write = wc.next_generation();
                    self.read_cipher = Some(Cipher::V13(next));
                    // peer asked us to update too: answer under the old keys, then rotate (unless we have sent close_notify:
                    // nothing is sent after that, and our keys are not used again)
                    if msg[4] == 1 && !self.sent_close_notify {
                        let reply = handshake_message(HS_KEY_UPDATE, &[0]);
                        self.queue_protected(RT_HANDSHAKE, &reply)?;
                        self.write_cipher = Some(Cipher::V13(next_write));
                    }
                }
                _ => return Err(Error::Tls("unexpected_message: unexpected post-handshake message".into())),
            }
        }
        Ok(())
    }

    /// Keeps a ticket for the next connection to this server (RFC 8446 section 4.6.1): its PSK is HKDF-Expand-Label of the
    /// resumption master secret with the ticket's nonce. A ticket of lifetime 0 is not kept.
    fn keep_ticket(&mut self, t: NewSessionTicket) {
        let Some(TicketSink { resumption, server, scope, time_override, secret: Some((suite, secret, verified_at)) }) = &self.tickets else { return };
        if t.lifetime == 0 {
            return;
        }
        let alg = suite.hash();
        let now = time_override.unwrap_or_else(crate::sys::now_unix);
        let expires = resumption.expiry(now, t.lifetime, *verified_at);
        if expires <= now {
            return;
        }
        let session = super::session::Session {
            ticket: t.ticket,
            psk: Zeroizing::new(expand_label(alg, secret, "resumption", &t.nonce, alg.output_len())),
            suite: *suite,
            age_add: t.age_add,
            received: std::time::Instant::now(),
            expires,
            verified_at: *verified_at,
            peer_chain: self.peer_chain.clone(),
            scope: scope.clone(),
        };
        resumption.insert(server, session);
    }

    /// What a TLS 1.2 server may send after the handshake: a HelloRequest, which asks for a renegotiation and is answered with a
    /// `no_renegotiation` warning (RFC 5246 section 7.4.1.1; this client never renegotiates). Nothing else.
    fn process_post_handshake12(&mut self) -> Result<()> {
        while let Some(msg) = self.take_buffered_handshake_message()? {
            match msg[0] {
                // (nothing is sent after our close_notify, an answer included)
                HS_HELLO_REQUEST if msg.len() == 4 && self.sent_close_notify => {}
                HS_HELLO_REQUEST if msg.len() == 4 => self.queue_protected(RT_ALERT, &[1, 100])?,
                _ => return Err(Error::Tls("unexpected_message: unexpected handshake message after a TLS 1.2 handshake".into())),
            }
        }
        Ok(())
    }

    /// Overwrites the buffers that hold decrypted application data and handshake bytes.
    fn wipe_buffers(&mut self) {
        self.rbuf.zeroize();
        self.out.zeroize();
        self.hs_buf.zeroize();
        self.rpos = 0;
        self.rend = 0;
        self.app_pos = 0;
        self.app_end = 0;
        self.out_pos = 0;
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        // The record ciphers wipe their keys in their own `Drop`; clear what was decrypted too.
        self.wipe_buffers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-34: what a server name may be, and the server_name extension without a trailing dot (RFC 6066 section 3).
    #[test]
    fn server_names_are_checked_and_sent_without_a_trailing_dot() {
        let config = ClientConfig::new(crate::x509::TrustStore::empty());
        for good in ["example.com", "example.com.", "EXAMPLE.com", "localhost", "_srv.example", "xn--bcher-kva.example", "127.0.0.1", "::1", "a-b.c-d"] {
            ClientConnection::new(good, &config).unwrap_or_else(|e| panic!("{good:?}: {e}"));
        }
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = vec!["abcdefghi"; 26].join(".");
        for bad in ["", ".", "a..b", "example.com..", "[::1]", "exa mple.com", "*.example.com", "a/b", "bücher.example", long_label.as_str(), long_name.as_str()] {
            let e = ClientConnection::new(bad, &config).err().unwrap_or_else(|| panic!("{bad:?} accepted")).to_string();
            assert!(e.contains("is not a host name or IP address"), "{bad:?}: {e}");
            assert_eq!(e.contains("idna::to_ascii"), !bad.is_ascii(), "{bad:?}: {e}");
        }
        // the extension carries the name without its trailing dot, and an IP literal is not sent at all
        let hello = |name: &str| ClientConnection::new(name, &config).unwrap().output().to_vec();
        let with_dot = hello("example.com.");
        assert!(with_dot.windows(11).any(|w| w == b"example.com") && !with_dot.windows(12).any(|w| w == b"example.com."));
        assert_eq!(with_dot.len(), hello("example.com").len());
        assert!(!hello("127.0.0.1").windows(9).any(|w| w == b"127.0.0.1"));
    }

    #[test]
    fn buffers_holding_plaintext_are_wiped() {
        let mut c = ClientConnection::blank();
        c.hs_buf = vec![1, 2, 3];
        c.rbuf = vec![0xaa; READ_BUF_SIZE];
        c.rpos = 5;
        c.rend = 100;
        c.app_pos = 10;
        c.app_end = 50;
        c.out = vec![0xbb; 64];
        let ptr = c.rbuf.as_ptr();
        c.wipe_buffers();
        assert!(c.rbuf.is_empty() && c.out.is_empty() && c.hs_buf.is_empty());
        assert_eq!((c.rpos, c.rend, c.app_pos, c.app_end), (0, 0, 0, 0));
        // SAFETY: `zeroize` keeps the allocation (it only clears the length) and `rbuf` still
        // owns READ_BUF_SIZE bytes at `ptr`, all of which were initialised.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, READ_BUF_SIZE) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn output_is_consumed_in_pieces() {
        let mut c = ClientConnection::blank();
        c.out = (0u8..10).collect();
        assert_eq!(c.output(), &(0u8..10).collect::<Vec<_>>()[..]);
        c.consume_output(4);
        assert_eq!(c.output(), &[4, 5, 6, 7, 8, 9]);
        c.consume_output(100); // more than is there: everything, not a panic
        assert!(!c.wants_write() && c.output().is_empty());
    }
    // ------------------------------------------------------------------ KeyUpdate

    /// The server's half of an established connection: `send` protects what the client reads,
    /// `recv` opens what the client writes.
    struct Peer {
        suite: Suite,
        send: RecordCipher,
        recv: RecordCipher,
    }

    impl Peer {
        fn connect(suite: Suite) -> (ClientConnection, Peer) {
            let n = suite.hash().output_len();
            let (read_secret, write_secret) = (vec![2u8; n], vec![1u8; n]);
            let client = ClientConnection::established(suite, &read_secret, &write_secret);
            (client, Peer { suite, send: RecordCipher::new(suite, &read_secret), recv: RecordCipher::new(suite, &write_secret) })
        }

        /// The peer's next record, protecting `content`.
        fn record(&mut self, inner_type: u8, content: &[u8]) -> Vec<u8> {
            self.send.encrypt(inner_type, content)
        }

        /// A KeyUpdate record under the current keys; the peer then switches its sending keys.
        fn key_update(&mut self, request: u8) -> Vec<u8> {
            let rec = self.record(RT_HANDSHAKE, &[HS_KEY_UPDATE, 0, 0, 1, request]);
            self.send = self.send.next_generation();
            rec
        }

        /// Opens every record in `bytes` with the peer's receiving keys, following any KeyUpdate
        /// the way a real peer must. Returns `(inner type, content)` of each record.
        fn open_all(&mut self, mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
            let mut out = Vec::new();
            while !bytes.is_empty() {
                let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
                let header: [u8; 5] = bytes[..5].try_into().unwrap();
                let opened = self.recv.decrypt(&header, &bytes[5..5 + len]).expect("the client's record opens under the peer's keys");
                if opened.0 == RT_HANDSHAKE && opened.1[0] == HS_KEY_UPDATE {
                    assert_eq!(opened.1[1..4], [0, 0, 1], "a KeyUpdate is one byte long");
                    self.recv = self.recv.next_generation();
                }
                out.push(opened);
                bytes = &bytes[5 + len..];
            }
            out
        }

        fn suite(&self) -> Suite {
            self.suite
        }
    }

    /// Hands `bytes` to the client in whatever pieces its buffer takes and returns the
    /// application data that came out.
    fn feed(c: &mut ClientConnection, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut got = Vec::new();
        let mut rest = bytes;
        let mut chunk = [0u8; 4096];
        loop {
            if c.has_plaintext() {
                let n = c.read_plaintext(&mut chunk);
                got.extend_from_slice(&chunk[..n]);
            } else if !rest.is_empty() {
                let space = c.recv_buf();
                let n = space.len().min(rest.len());
                space[..n].copy_from_slice(&rest[..n]);
                c.recv_filled(n);
                rest = &rest[n..];
            } else {
                return Ok(got);
            }
            c.process()?;
        }
    }

    /// Everything the client has queued to send.
    fn take_output(c: &mut ClientConnection) -> Vec<u8> {
        let out = c.output().to_vec();
        c.consume_output(out.len());
        out
    }

    fn write_all(c: &mut ClientConnection, mut data: &[u8]) {
        while !data.is_empty() {
            let n = c.write_plaintext(data).unwrap();
            data = &data[n..];
        }
    }

    #[test]
    fn a_peer_key_update_without_a_request_rotates_only_what_we_read() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            assert_eq!(feed(&mut c, &peer.record(RT_APPLICATION_DATA, b"before")).unwrap(), b"before");
            assert_eq!(feed(&mut c, &peer.key_update(0)).unwrap(), b"");
            assert_eq!(peer.send.records(), 0, "the new generation starts counting again");
            assert_eq!(feed(&mut c, &peer.record(RT_APPLICATION_DATA, b"after")).unwrap(), b"after");
            assert!(c.output().is_empty(), "update_not_requested needs no answer");
            // what we send is still under the old keys
            write_all(&mut c, b"reply");
            let sent = take_output(&mut c);
            assert_eq!(peer.open_all(&sent), vec![(RT_APPLICATION_DATA, b"reply".to_vec())], "{:?}", peer.suite());
        }
    }

    #[test]
    fn a_peer_key_update_with_a_request_is_answered_under_the_old_keys_and_we_rotate() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            write_all(&mut c, b"one");
            assert_eq!(feed(&mut c, &peer.key_update(1)).unwrap(), b"");
            write_all(&mut c, b"two");
            let sent = take_output(&mut c);
            // one, the KeyUpdate answer (update_not_requested), then two under the next keys
            let got = peer.open_all(&sent);
            assert_eq!(
                got,
                vec![
                    (RT_APPLICATION_DATA, b"one".to_vec()),
                    (RT_HANDSHAKE, vec![HS_KEY_UPDATE, 0, 0, 1, 0]),
                    (RT_APPLICATION_DATA, b"two".to_vec())
                ],
                "{:?}",
                suite
            );
            assert_eq!(peer.recv.records(), 1, "the record after the answer is the first under the new keys");
        }
    }

    #[test]
    fn after_our_close_notify_a_key_update_request_is_not_answered() {
        // (a split stream's reading half goes on after the writing half has closed; nothing may follow our close_notify)
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            c.send_close_notify();
            assert_eq!(peer.open_all(&take_output(&mut c)), vec![(RT_ALERT, vec![1, 0])]);
            assert_eq!(feed(&mut c, &peer.key_update(1)).unwrap(), b"");
            assert!(!c.wants_write(), "{suite:?}: an answer after close_notify");
            // and what the peer sends under its next keys is still read
            assert_eq!(feed(&mut c, &peer.record(RT_APPLICATION_DATA, b"still read")).unwrap(), b"still read");
        }
    }

    #[test]
    fn many_key_updates_in_a_row_keep_both_directions_in_step() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            for round in 0..9u8 {
                let request = round % 2; // alternate requested and not requested
                assert_eq!(feed(&mut c, &peer.key_update(request)).unwrap(), b"");
                let msg = vec![round; 50 + round as usize];
                assert_eq!(feed(&mut c, &peer.record(RT_APPLICATION_DATA, &msg)).unwrap(), msg, "round {round}");
                write_all(&mut c, &msg);
                let sent = take_output(&mut c);
                let got = peer.open_all(&sent);
                assert_eq!(got.last(), Some(&(RT_APPLICATION_DATA, msg)), "{:?} round {round}", suite);
                assert_eq!(got.len(), 1 + request as usize, "a KeyUpdate answer exactly when one was requested");
            }
        }
    }

    #[test]
    fn records_under_superseded_keys_are_refused() {
        for suite in Suite::ALL {
            let n = suite.hash().output_len();
            let (mut c, mut peer) = Peer::connect(suite);
            let mut stale = RecordCipher::new(suite, &vec![2u8; n]);
            assert_eq!(feed(&mut c, &peer.key_update(0)).unwrap(), b"");
            let err = feed(&mut c, &stale.encrypt(RT_APPLICATION_DATA, b"replayed under the old key")).unwrap_err();
            assert!(err.to_string().contains("bad_record_mac"), "{}", err);
            // and the alert it sends is protected with the (unchanged) write keys, which the peer can open
            let sent = take_output(&mut c);
            assert_eq!(peer.open_all(&sent), vec![(RT_ALERT, vec![2, 20])]);
        }
    }

    #[test]
    fn malformed_key_updates_end_the_connection() {
        let alert_for = |suite: Suite, records: &[Vec<u8>]| {
            let (mut c, mut peer) = Peer::connect(suite);
            let mut result = Ok(Vec::new());
            for r in records {
                let rec = peer.record(RT_HANDSHAKE, r);
                result = feed(&mut c, &rec);
                if result.is_err() {
                    break;
                }
            }
            let err = result.expect_err("a malformed KeyUpdate must fail");
            let sent = take_output(&mut c);
            let alerts = peer.open_all(&sent);
            assert_eq!(alerts.len(), 1, "{err}");
            (err.to_string(), alerts[0].1[1])
        };
        let s = Suite::Aes128GcmSha256;
        // an unknown request value (illegal_parameter, RFC 8446 section 4.6.3), a wrong length either way (decode_error)
        for (bad, wanted) in [(vec![HS_KEY_UPDATE, 0, 0, 1, 2], 47), (vec![HS_KEY_UPDATE, 0, 0, 2, 0, 0], 50), (vec![HS_KEY_UPDATE, 0, 0, 0], 50)] {
            let (text, alert) = alert_for(s, std::slice::from_ref(&bad));
            assert!(text.contains("KeyUpdate"), "{:?}: {}", bad, text);
            assert_eq!(alert, wanted, "{:?}", bad);
        }
        // another handshake message in the same record, after the KeyUpdate (section 5.1)
        let (text, alert) = alert_for(s, &[vec![HS_KEY_UPDATE, 0, 0, 1, 0, HS_KEY_UPDATE, 0, 0, 1, 0]]);
        assert!(text.contains("follows a KeyUpdate"), "{}", text);
        assert_eq!(alert, 10, "unexpected_message");
        // a handshake message that is not allowed after the handshake
        let (_, alert) = alert_for(s, &[vec![HS_FINISHED, 0, 0, 1, 0]]);
        assert_eq!(alert, 10);
    }

    #[test]
    fn a_handshake_message_split_across_records_may_not_have_other_records_between() {
        // RFC 8446 section 5.1
        let (mut c, mut peer) = Peer::connect(Suite::Aes128GcmSha256);
        let first = peer.record(RT_HANDSHAKE, &[HS_KEY_UPDATE, 0]);
        let between = peer.record(RT_APPLICATION_DATA, b"between");
        let second = peer.record(RT_HANDSHAKE, &[0, 1, 0]);
        let err = feed(&mut c, &[first, between, second].concat()).unwrap_err().to_string();
        assert!(err.contains("inside a handshake message"), "{err}");
    }

    #[test]
    fn a_key_update_split_across_records_is_accepted() {
        let (mut c, mut peer) = Peer::connect(Suite::Aes256GcmSha384);
        let first = peer.record(RT_HANDSHAKE, &[HS_KEY_UPDATE, 0]);
        let second = peer.record(RT_HANDSHAKE, &[0, 1, 1]);
        assert_eq!(feed(&mut c, &[first, second].concat()).unwrap(), b"");
        peer.send = peer.send.next_generation();
        assert_eq!(feed(&mut c, &peer.record(RT_APPLICATION_DATA, b"fine")).unwrap(), b"fine");
        let sent = take_output(&mut c);
        let mut peer_recv = Peer::connect(Suite::Aes256GcmSha384).1.recv;
        assert_eq!(sent.len(), 5 + 5 + 1 + 16, "the connection answered the request with one record");
        let header: [u8; 5] = sent[..5].try_into().unwrap();
        assert_eq!(peer_recv.decrypt(&header, &sent[5..]).unwrap(), (RT_HANDSHAKE, vec![HS_KEY_UPDATE, 0, 0, 1, 0]));
    }

    #[test]
    fn we_rotate_our_sending_keys_before_the_record_limit() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            c.set_rekey_after(4);
            let mut sent = Vec::new();
            for i in 0..10u8 {
                write_all(&mut c, &[i; 20]);
                sent.extend(take_output(&mut c));
            }
            // a key protects 4 records: three of data and the KeyUpdate that retires it
            let mut generation_sizes = Vec::new();
            let mut opened = Vec::new();
            let mut rest = &sent[..];
            while !rest.is_empty() {
                let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
                let header: [u8; 5] = rest[..5].try_into().unwrap();
                let rec = peer.recv.decrypt(&header, &rest[5..5 + len]).expect("every record opens under the peer's current keys");
                if rec.0 == RT_HANDSHAKE {
                    assert_eq!(rec.1, vec![HS_KEY_UPDATE, 0, 0, 1, 0], "update_not_requested");
                    generation_sizes.push(peer.recv.records());
                    peer.recv = peer.recv.next_generation();
                } else {
                    opened.push(rec.1);
                }
                rest = &rest[5 + len..];
            }
            // the KeyUpdate goes out before the 4th, 7th and 10th data record
            assert_eq!(generation_sizes, vec![4, 4, 4], "{:?}", suite);
            assert_eq!(opened, (0..10u8).map(|i| vec![i; 20]).collect::<Vec<_>>());
        }
    }

    #[test]
    fn no_key_update_is_sent_before_the_limit() {
        let (mut c, mut peer) = Peer::connect(Suite::Aes128GcmSha256);
        for i in 0..200u8 {
            write_all(&mut c, &[i; 10]);
        }
        let sent = take_output(&mut c);
        let records = peer.open_all(&sent);
        assert_eq!(records.len(), 200);
        assert!(records.iter().all(|(t, _)| *t == RT_APPLICATION_DATA));
        // the limit for AES-GCM is 2^24 records and for ChaCha20-Poly1305 far more (RFC 8446 section 5.5)
        assert_eq!(Suite::Aes128GcmSha256.records_per_key(), 1 << 24);
        assert_eq!(Suite::Aes256GcmSha384.records_per_key(), 1 << 24);
        assert!(Suite::Chacha20Poly1305Sha256.records_per_key() > 1 << 40);
    }

    #[test]
    fn a_write_that_spans_a_rotation_arrives_intact() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            c.set_rekey_after(3);
            // five full records in one call (four per call are taken, so two calls)
            let data: Vec<u8> = (0..5 * MAX_PLAINTEXT + 17).map(|i| (i * 7 % 251) as u8).collect();
            write_all(&mut c, &data);
            let sent = take_output(&mut c);
            let records = peer.open_all(&sent);
            let got: Vec<u8> = records.iter().filter(|(t, _)| *t == RT_APPLICATION_DATA).flat_map(|(_, d)| d.clone()).collect();
            assert!(got == data, "{:?}: the data came back different", suite);
            let updates = records.iter().filter(|(t, _)| *t == RT_HANDSHAKE).count();
            assert_eq!(updates, 2, "{:?}", suite);
        }
    }

    #[test]
    fn our_rotation_and_the_peers_request_can_cross() {
        for suite in Suite::ALL {
            let (mut c, mut peer) = Peer::connect(suite);
            c.set_rekey_after(3);
            write_all(&mut c, b"a");
            write_all(&mut c, b"b");
            // the peer asks for an update after our second record: the answer is the third (the last
            // record under this key), and the next data record starts the new generation
            assert_eq!(feed(&mut c, &peer.key_update(1)).unwrap(), b"");
            write_all(&mut c, b"c");
            write_all(&mut c, b"d");
            write_all(&mut c, b"e");
            write_all(&mut c, b"f");
            let sent = take_output(&mut c);
            let records: Vec<(u8, Vec<u8>)> = peer.open_all(&sent);
            let shapes: Vec<(u8, usize)> = records.iter().map(|(t, d)| (*t, d.len())).collect();
            // a, b, KeyUpdate (the answer), c, d, KeyUpdate (the proactive one), e, f
            let ku = (RT_HANDSHAKE, 5);
            let app = (RT_APPLICATION_DATA, 1);
            assert_eq!(shapes, vec![app, app, ku, app, app, ku, app, app], "{:?}", suite);
        }
    }

    #[test]
    fn the_rekey_interval_can_be_configured_and_is_never_below_two() {
        let cfg = ClientConfig::new(crate::x509::TrustStore::empty());
        assert_eq!(cfg.rekey_after_records, None);
        assert_eq!(cfg.clone().with_rekey_after_records(1000).rekey_after_records, Some(1000));
        assert_eq!(cfg.clone().with_rekey_after_records(0).rekey_after_records, Some(2));
        assert_eq!(cfg.with_rekey_after_records(1).rekey_after_records, Some(2));
    }

    // ------------------------------------------------------------------ TLS 1.2 after the handshake

    /// A TLS 1.2 connection and the server's two ciphers: (client, server's sealer, server's opener).
    fn tls12_pair(suite: Suite12) -> (ClientConnection, RecordCipher12, RecordCipher12) {
        let key = vec![3u8; suite.aead_suite().key_len()];
        let other = vec![4u8; suite.aead_suite().key_len()];
        let iv = [5u8; 12];
        let client = ClientConnection::established12(RecordCipher12::new(suite, &key, &iv[..4]), RecordCipher12::new(suite, &other, &iv[..4]));
        (client, RecordCipher12::new(suite, &key, &iv[..4]), RecordCipher12::new(suite, &other, &iv[..4]))
    }

    fn open12(opener: &mut RecordCipher12, mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            let header: [u8; 5] = bytes[..5].try_into().unwrap();
            let mut p = bytes[5..5 + len].to_vec();
            let (t, off, n) = opener.decrypt_in_place(&header, &mut p).unwrap();
            out.push((t, p[off..off + n].to_vec()));
            bytes = &bytes[5 + len..];
        }
        out
    }

    #[test]
    fn tls12_data_flows_both_ways_and_close_notify_ends_it() {
        for suite in Suite12::ALL {
            let (mut c, mut seal, mut open) = tls12_pair(suite);
            assert_eq!(c.protocol_version(), Some(TlsVersion::Tls12));
            let mut wire = Vec::new();
            seal.encrypt_into(RT_APPLICATION_DATA, b"from the server", &mut wire);
            seal.encrypt_into(RT_APPLICATION_DATA, &[7u8; MAX_PLAINTEXT], &mut wire);
            let got = feed(&mut c, &wire).unwrap();
            assert_eq!(got.len(), 15 + MAX_PLAINTEXT);
            assert_eq!(&got[..15], b"from the server");
            write_all(&mut c, b"from the client");
            c.send_close_notify();
            let sent = open12(&mut open, &take_output(&mut c));
            assert_eq!(sent, vec![(RT_APPLICATION_DATA, b"from the client".to_vec()), (RT_ALERT, vec![1, 0])], "{}", suite.name());
            let mut wire = Vec::new();
            seal.encrypt_into(RT_ALERT, &[1, 0], &mut wire);
            feed(&mut c, &wire).unwrap();
            assert!(c.peer_closed());
        }
    }

    #[test]
    fn tls12_a_hello_request_is_answered_with_no_renegotiation_and_nothing_else_is_taken() {
        let (mut c, mut seal, mut open) = tls12_pair(Suite12::EcdheRsaAes128Gcm);
        let mut wire = Vec::new();
        seal.encrypt_into(RT_HANDSHAKE, &[HS_HELLO_REQUEST, 0, 0, 0], &mut wire);
        seal.encrypt_into(RT_APPLICATION_DATA, b"still here", &mut wire);
        assert_eq!(feed(&mut c, &wire).unwrap(), b"still here");
        // a warning, not a handshake: the connection goes on as it was
        assert_eq!(open12(&mut open, &take_output(&mut c)), vec![(RT_ALERT, vec![1, 100])]);
        assert!(c.is_quiet());
        // after our close_notify, a HelloRequest gets no answer (nothing follows close_notify) and is otherwise ignored
        c.send_close_notify();
        assert_eq!(open12(&mut open, &take_output(&mut c)), vec![(RT_ALERT, vec![1, 0])]);
        let mut wire = Vec::new();
        seal.encrypt_into(RT_HANDSHAKE, &[HS_HELLO_REQUEST, 0, 0, 0], &mut wire);
        seal.encrypt_into(RT_APPLICATION_DATA, b"read on", &mut wire);
        assert_eq!(feed(&mut c, &wire).unwrap(), b"read on");
        assert!(!c.wants_write());
        // a KeyUpdate, a session ticket, a ClientHello-shaped thing or a HelloRequest with a body: not in TLS 1.2 after the handshake
        for msg in [vec![HS_KEY_UPDATE, 0, 0, 1, 0], vec![HS_NEW_SESSION_TICKET, 0, 0, 0], vec![HS_HELLO_REQUEST, 0, 0, 1, 0], vec![1, 0, 0, 0]] {
            let (mut c, mut seal, _) = tls12_pair(Suite12::EcdheRsaAes128Gcm);
            let mut wire = Vec::new();
            seal.encrypt_into(RT_HANDSHAKE, &msg, &mut wire);
            assert!(feed(&mut c, &wire).is_err(), "{msg:02x?}");
        }
        // nor a change_cipher_spec, protected or not, nor a record in the clear
        let (mut c, mut seal, _) = tls12_pair(Suite12::EcdheRsaAes128Gcm);
        let mut wire = Vec::new();
        seal.encrypt_into(RT_CHANGE_CIPHER_SPEC, &[1], &mut wire);
        assert!(feed(&mut c, &wire).is_err());
        let (mut c, _, _) = tls12_pair(Suite12::EcdheRsaAes128Gcm);
        assert!(feed(&mut c, &[RT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]).is_err());
        let (mut c, _, _) = tls12_pair(Suite12::EcdheRsaAes128Gcm);
        assert!(feed(&mut c, &[RT_APPLICATION_DATA, 3, 3, 0, 2, 0, 0]).is_err());
    }

    #[test]
    fn tls12_a_used_up_key_stops_the_connection_rather_than_wrap() {
        let (mut c, _, _) = tls12_pair(Suite12::EcdheEcdsaAes128Gcm);
        c.set_rekey_after(3);
        assert!(c.write_plaintext(b"one").is_ok());
        assert!(c.write_plaintext(b"two").is_ok());
        let e = c.write_plaintext(b"three").unwrap_err();
        assert!(e.to_string().contains("open another"), "{e}");
    }

    #[test]
    fn the_compatibility_change_cipher_spec_waits_when_tls12_is_offered() {
        let tls13 = ClientConfig::new(crate::x509::TrustStore::empty()).with_min_version(TlsVersion::Tls13);
        let c = ClientConnection::start("example.com", &tls13, Zeroizing::new([7; 32]), &[1; 32], &[2; 32]);
        assert!(c.output().ends_with(&[RT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]), "after a TLS 1.3-only ClientHello at once");
        let both = ClientConfig::new(crate::x509::TrustStore::empty());
        let c = ClientConnection::start("example.com", &both, Zeroizing::new([7; 32]), &[1; 32], &[2; 32]);
        assert_eq!(c.output()[0], RT_HANDSHAKE);
        let len = u16::from_be_bytes([c.output()[3], c.output()[4]]) as usize;
        assert_eq!(c.output().len(), 5 + len, "nothing after a ClientHello that offers TLS 1.2 too");
        assert!(c.compat_ccs_pending);
    }
}
