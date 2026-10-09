//! A TLS 1.3 server (RFC 8446), so that tests and tools have a real peer for the client: keep-alive,
//! streaming and HTTP/2 over TLS, interop checks against OpenSSL, curl and Go, and the handshakes the
//! scripted servers of the unit tests cannot reach.
//!
//! **Experimental, and not for production.** Behind the `server` feature (always built for this crate's own
//! tests). The signing is Ed25519 and is not constant-time (see [`crate::crypto::ed25519_sign`]), the code
//! has had no review, and it takes whatever shortcut keeps a test simple: no client certificates, no early data, one
//! certificate, and sessions resumed from tickets that are kept in memory per configuration (used once, never expiring),
//! so that the client's resumption (B-35) has a peer in the tests; OpenSSL's server checks that too. The independent
//! review of BACKLOG B-23 does not cover it.
//!
//! It is the same shape as the client: [`ServerConnection`] is the protocol as a state machine that does no
//! I/O (bytes in with [`receive`](ServerConnection::receive), bytes out of [`output`](ServerConnection::output)),
//! and [`ServerStream`] drives it over a blocking `Read + Write`.
//!
//! What it does: ClientHello parsing with the checks that matter to a server (versions, duplicate
//! extensions, the legacy fields), X25519, P-256 and P-384 key exchange with a HelloRetryRequest when the
//! client's share is not for a group it takes, the three TLS 1.3 cipher suites, ALPN, an optional stapled
//! OCSP response, NewSessionTicket messages (resumable with PSK and a fresh key exchange, `psk_dhe_ke`),
//! KeyUpdate in both directions, and close_notify. What it shares with the client: the key schedule and the
//! record cipher (`suite.rs`), the message constants and the CertificateVerify content (`messages.rs`); the
//! record layer around them (framing, fragmentation, buffering) is its own, so that a mistake there is not
//! made the same way on both ends of a test.

use super::messages::*;
use super::pki::{CertSpec, KeyPair, TestPki};
use super::suite::*;
use crate::crypto::ecdsa::Curve;
use crate::crypto::sha2::HashAlg;
use crate::crypto::{ecdh, rand, x25519};
use crate::error::{Error, Result};
use crate::util::{ct_eq, Reader};
use crate::zeroize::{Zeroize, Zeroizing};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// Ed25519 (the only key this server has), as a SignatureScheme.
const ED25519: u16 = 0x0807;
const MAX_HANDSHAKE_MESSAGE: usize = 1 << 18;
const MAX_CIPHERTEXT_RECORD: usize = MAX_PLAINTEXT + 256;
/// What one call to `write_plaintext` takes: four full records.
const MAX_WRITE: usize = 4 * MAX_PLAINTEXT;
const MAX_COMPAT_CCS: u8 = 2;

/// What a server does.
#[derive(Clone)]
pub struct ServerConfig {
    /// The certificate chain, DER, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The key of the first certificate.
    pub key: KeyPair,
    /// ALPN protocols, in the server's order of preference. Empty: no ALPN.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// A client that offers ALPN protocols the server has none of is refused with `no_application_protocol`
    /// (RFC 7301 section 3.2) rather than served without one.
    pub alpn_required: bool,
    /// Cipher suites, in the server's order of preference.
    pub suites: Vec<Suite>,
    /// Key exchange groups the server takes, in order of preference. A client share for one of them is
    /// used (the first of these that the client sent a share for); otherwise a HelloRetryRequest asks for
    /// the first of these that the client lists.
    pub groups: Vec<u16>,
    /// NewSessionTicket messages sent once the handshake is done.
    pub tickets: usize,
    /// Send those tickets after the first data the server writes instead of before it (some servers do:
    /// the client then meets them in the middle of the first response).
    pub tickets_after_first_write: bool,
    /// The most plaintext in one record (at most 16384). Small values make a client reassemble messages
    /// and data from many records.
    pub max_fragment: usize,
    /// Rotate our sending keys with a KeyUpdate after this many records under one key (at least 2).
    pub rekey_after_records: Option<u64>,
    /// An OCSP response to staple to the leaf certificate for a client that asks for one.
    pub ocsp_staple: Option<Vec<u8>>,
    /// The tickets issued and not used yet (shared by clones of this configuration), or `None` to resume nothing (the
    /// tickets sent are then random bytes).
    pub sessions: Option<Arc<Mutex<ServerSessions>>>,
}

/// A server's resumable sessions: ticket, the PSK it stands for, and the suite it came from.
#[derive(Default)]
pub struct ServerSessions {
    tickets: HashMap<Vec<u8>, (Zeroizing<Vec<u8>>, Suite)>,
    /// How many handshakes resumed a session.
    pub resumed: usize,
}

impl ServerConfig {
    pub fn new(chain: Vec<Vec<u8>>, key: KeyPair) -> ServerConfig {
        ServerConfig {
            chain,
            key,
            alpn_protocols: Vec::new(),
            alpn_required: true,
            suites: Suite::preference_order().to_vec(),
            groups: SUPPORTED_GROUPS.to_vec(),
            tickets: 1,
            tickets_after_first_write: false,
            max_fragment: MAX_PLAINTEXT,
            rekey_after_records: None,
            ocsp_staple: None,
            sessions: Some(Arc::new(Mutex::new(ServerSessions::default()))),
        }
    }

    /// Resumes nothing: every handshake is a full one.
    pub fn without_resumption(mut self) -> ServerConfig {
        self.sessions = None;
        self
    }

    /// How many handshakes resumed a session so far.
    pub fn resumed_count(&self) -> usize {
        self.sessions.as_ref().map_or(0, |s| s.lock().unwrap().resumed)
    }

    /// The server certificate of `pki`.
    pub fn from_pki(pki: &TestPki) -> ServerConfig {
        ServerConfig::new(pki.chain.clone(), pki.server_key.clone())
    }

    /// A throwaway PKI for `names` (DNS names or IP literals) and a config that serves it. The root is what
    /// a client must trust (`TestPki::trust_store`).
    pub fn for_names(names: &[&str]) -> io::Result<(ServerConfig, TestPki)> {
        let pki = TestPki::with_spec(CertSpec::server(names))?;
        Ok((ServerConfig::from_pki(&pki), pki))
    }

    pub fn with_alpn(mut self, protocols: &[&str]) -> ServerConfig {
        self.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    pub fn with_suites(mut self, suites: &[Suite]) -> ServerConfig {
        self.suites = suites.to_vec();
        self
    }

    pub fn with_groups(mut self, groups: &[u16]) -> ServerConfig {
        self.groups = groups.to_vec();
        self
    }

    pub fn with_tickets(mut self, count: usize) -> ServerConfig {
        self.tickets = count;
        self
    }

    pub fn with_max_fragment(mut self, bytes: usize) -> ServerConfig {
        self.max_fragment = bytes.clamp(1, MAX_PLAINTEXT);
        self
    }

    pub fn with_rekey_after_records(mut self, records: u64) -> ServerConfig {
        self.rekey_after_records = Some(records.max(2));
        self
    }

    pub fn with_ocsp_staple(mut self, response: &[u8]) -> ServerConfig {
        self.ocsp_staple = Some(response.to_vec());
        self
    }
}

// ------------------------------------------------------------------------------------------------ errors

fn bad(msg: &str) -> Error {
    Error::Tls(format!("decode_error: {msg}"))
}

fn alert_error(content: &[u8]) -> Error {
    if content.len() == 2 {
        Error::Alert(content[0], content[1])
    } else {
        bad("malformed alert")
    }
}

/// The alert a protocol error is answered with; `None` for errors that are not the peer's fault on the wire.
fn alert_description(err: &Error) -> Option<u8> {
    const TABLE: [(&str, u8); 11] = [
        ("unexpected_message", 10),
        ("bad_record_mac", 20),
        ("record_overflow", 22),
        ("handshake_failure", 40),
        ("illegal_parameter", 47),
        ("decode_error", 50),
        ("decrypt_error", 51),
        ("protocol_version", 70),
        ("missing_extension", 109),
        ("unsupported_extension", 110),
        ("no_application_protocol", 120),
    ];
    match err {
        Error::Io(_) | Error::Alert(_, _) => None,
        Error::Tls(m) => Some(TABLE.iter().find(|(prefix, _)| m.starts_with(prefix)).map(|(_, d)| *d).unwrap_or(80)), // internal_error
        _ => Some(80),
    }
}

// ------------------------------------------------------------------------------------------------ ClientHello

/// What the server needs from a ClientHello.
struct Hello {
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    server_name: Option<String>,
    versions: Vec<u16>,
    groups: Vec<u16>,
    shares: Vec<(u16, Vec<u8>)>,
    signature_algorithms: Option<Vec<u16>>,
    alpn: Option<Vec<Vec<u8>>>,
    status_request: bool,
    psk_dhe_ke: bool,
    /// `pre_shared_key`: the first identity and its binder, and the length of the binders list (with its own length),
    /// which the end of the ClientHello is.
    psk: Option<(Vec<u8>, Vec<u8>, usize)>,
}

fn u16_list(data: &[u8], what: &str) -> Result<Vec<u16>> {
    let mut r = Reader::new(data);
    let list = r.vec16().ok_or_else(|| bad(what))?;
    if !r.is_empty() || list.len() % 2 != 0 {
        return Err(bad(what));
    }
    Ok(list.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
}

/// Parses the body of a ClientHello (RFC 8446 section 4.1.2).
fn parse_hello(body: &[u8]) -> Result<Hello> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16().ok_or_else(|| bad("ClientHello version"))?;
    let random: [u8; 32] = r.take(32).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| bad("ClientHello random"))?;
    let session_id = r.vec8().ok_or_else(|| bad("ClientHello session id"))?.to_vec();
    if session_id.len() > 32 {
        return Err(Error::Tls("illegal_parameter: session id longer than 32 bytes".into()));
    }
    let suites = r.vec16().ok_or_else(|| bad("ClientHello cipher suites"))?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(bad("ClientHello cipher suites"));
    }
    let cipher_suites = suites.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    let compression = r.vec8().ok_or_else(|| bad("ClientHello compression methods"))?;
    if compression != [0] {
        return Err(Error::Tls("illegal_parameter: legacy_compression_methods is not exactly null".into()));
    }
    let extensions = r.vec16().ok_or_else(|| Error::Tls("protocol_version: a ClientHello without extensions cannot offer TLS 1.3".into()))?;
    if !r.is_empty() {
        return Err(bad("trailing data in ClientHello"));
    }
    let mut hello = Hello {
        random,
        session_id,
        cipher_suites,
        server_name: None,
        versions: Vec::new(),
        groups: Vec::new(),
        shares: Vec::new(),
        signature_algorithms: None,
        alpn: None,
        status_request: false,
        psk_dhe_ke: false,
        psk: None,
    };
    let mut seen: Vec<u16> = Vec::new();
    let mut er = Reader::new(extensions);
    while !er.is_empty() {
        let t = er.u16().ok_or_else(|| bad("truncated extension type"))?;
        let d = er.vec16().ok_or_else(|| bad("truncated extension"))?;
        if seen.contains(&t) {
            return Err(Error::Tls("illegal_parameter: duplicate extension".into()));
        }
        seen.push(t);
        match t {
            EXT_SUPPORTED_VERSIONS => {
                let mut vr = Reader::new(d);
                let list = vr.vec8().ok_or_else(|| bad("supported_versions"))?;
                if !vr.is_empty() || list.is_empty() || list.len() % 2 != 0 {
                    return Err(bad("supported_versions"));
                }
                hello.versions = list.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            EXT_SUPPORTED_GROUPS => hello.groups = u16_list(d, "supported_groups")?,
            EXT_SIGNATURE_ALGORITHMS => hello.signature_algorithms = Some(u16_list(d, "signature_algorithms")?),
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(d);
                let list = kr.vec16().ok_or_else(|| bad("key_share"))?;
                if !kr.is_empty() {
                    return Err(bad("key_share"));
                }
                let mut lr = Reader::new(list);
                while !lr.is_empty() {
                    let group = lr.u16().ok_or_else(|| bad("key_share group"))?;
                    let key = lr.vec16().ok_or_else(|| bad("key_share key"))?;
                    if hello.shares.iter().any(|(g, _)| *g == group) {
                        return Err(Error::Tls("illegal_parameter: two key shares for one group".into()));
                    }
                    hello.shares.push((group, key.to_vec()));
                }
            }
            EXT_SERVER_NAME => {
                let mut nr = Reader::new(d);
                let list = nr.vec16().ok_or_else(|| bad("server_name"))?;
                if !nr.is_empty() {
                    return Err(bad("server_name"));
                }
                let mut lr = Reader::new(list);
                while !lr.is_empty() {
                    let name_type = lr.u8().ok_or_else(|| bad("server_name type"))?;
                    let name = lr.vec16().ok_or_else(|| bad("server_name"))?;
                    if name_type == 0 && hello.server_name.is_none() {
                        hello.server_name = Some(String::from_utf8(name.to_vec()).map_err(|_| Error::Tls("illegal_parameter: server_name is not text".into()))?);
                    }
                }
            }
            EXT_ALPN => {
                let mut ar = Reader::new(d);
                let list = ar.vec16().ok_or_else(|| bad("ALPN"))?;
                if !ar.is_empty() {
                    return Err(bad("ALPN"));
                }
                let mut lr = Reader::new(list);
                let mut names = Vec::new();
                while !lr.is_empty() {
                    let name = lr.vec8().ok_or_else(|| bad("ALPN protocol"))?;
                    if name.is_empty() {
                        return Err(bad("empty ALPN protocol name"));
                    }
                    names.push(name.to_vec());
                }
                if names.is_empty() {
                    return Err(bad("empty ALPN list"));
                }
                hello.alpn = Some(names);
            }
            EXT_STATUS_REQUEST => hello.status_request = true,
            EXT_PSK_KEY_EXCHANGE_MODES => {
                let mut mr = Reader::new(d);
                let modes = mr.vec8().ok_or_else(|| bad("psk_key_exchange_modes"))?;
                hello.psk_dhe_ke = modes.contains(&PSK_DHE_KE);
            }
            EXT_PRE_SHARED_KEY => {
                // RFC 8446 section 4.2.11: the last extension, identities and then binders, as many of one as of the other
                if !er.is_empty() {
                    return Err(Error::Tls("illegal_parameter: pre_shared_key is not the last extension".into()));
                }
                let mut pr = Reader::new(d);
                let ids = pr.vec16().ok_or_else(|| bad("pre_shared_key identities"))?;
                let binders_at = d.len() - pr.remaining();
                let binders = pr.vec16().ok_or_else(|| bad("pre_shared_key binders"))?;
                if !pr.is_empty() {
                    return Err(bad("pre_shared_key"));
                }
                let (mut ir, mut br) = (Reader::new(ids), Reader::new(binders));
                let mut first = None;
                while !ir.is_empty() {
                    let id = ir.vec16().ok_or_else(|| bad("PSK identity"))?;
                    ir.u32().ok_or_else(|| bad("PSK age"))?;
                    let binder = br.vec8().ok_or_else(|| Error::Tls("illegal_parameter: fewer binders than identities".into()))?;
                    first.get_or_insert((id.to_vec(), binder.to_vec()));
                }
                if !br.is_empty() {
                    return Err(Error::Tls("illegal_parameter: more binders than identities".into()));
                }
                let (id, binder) = first.ok_or_else(|| bad("pre_shared_key without identities"))?;
                hello.psk = Some((id, binder, d.len() - binders_at));
            }
            _ => {} // a server ignores extensions it does not know
        }
    }
    Ok(hello)
}

// ------------------------------------------------------------------------------------------------ the connection

enum Stage {
    /// Waiting for the first ClientHello.
    Hello,
    /// A HelloRetryRequest has been sent; waiting for the second ClientHello.
    RetriedHello,
    /// Our flight is out; waiting for the client's Finished.
    ClientFinished,
}

/// The values of the first ClientHello that the second must repeat, and what the HelloRetryRequest chose.
struct Retried {
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    suite: Suite,
    group: u16,
}

struct Handshake {
    stage: Stage,
    transcript: Vec<u8>,
    retried: Option<Retried>,
    /// A compatibility change_cipher_spec went out already.
    ccs_sent: bool,
    /// The client's Finished, as it must be, and the keys that follow it.
    expected_finished: Vec<u8>,
    client_application_secret: Zeroizing<Vec<u8>>,
    suite: Suite,
    /// The master secret, for the resumption master secret once the client's Finished is in.
    master_secret: Zeroizing<Vec<u8>>,
}

/// The private half of our key share.
enum Secret {
    X25519(Zeroizing<[u8; 32]>),
    Ec(Curve, Zeroizing<Vec<u8>>),
}

fn curve_of(group: u16) -> Option<Curve> {
    match group {
        GROUP_SECP256R1 => Some(Curve::P256),
        GROUP_SECP384R1 => Some(Curve::P384),
        _ => None,
    }
}

/// Our key share for `group` and the shared secret with the client's.
fn key_exchange(group: u16, client_share: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let (secret, public) = if group == GROUP_X25519 {
        let private: Zeroizing<[u8; 32]> = Zeroizing::new(rand::bytes()?);
        let public = x25519::public_key(&private).to_vec();
        (Secret::X25519(private), public)
    } else {
        let curve = curve_of(group).ok_or_else(|| Error::Tls("internal: key exchange for an unsupported group".into()))?;
        let (scalar, public) = ecdh::generate(curve)?;
        (Secret::Ec(curve, scalar), public)
    };
    let shared = match secret {
        Secret::X25519(private) => {
            let peer: [u8; 32] = <[u8; 32]>::try_from(client_share).map_err(|_| Error::Tls("illegal_parameter: X25519 key share is not 32 bytes".into()))?;
            let shared = Zeroizing::new(x25519::x25519(&private, &peer));
            if shared.iter().fold(0u8, |acc, &b| acc | b) == 0 {
                return Err(Error::Tls("illegal_parameter: X25519 produced an all-zero shared secret".into()));
            }
            Zeroizing::new(shared.to_vec())
        }
        Secret::Ec(curve, scalar) => ecdh::shared_secret(curve, &scalar, client_share)
            .ok_or_else(|| Error::Tls("illegal_parameter: the client's key share is not a valid point on the curve".into()))?,
    };
    Ok((public, shared))
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put_vec8(v: &mut Vec<u8>, data: &[u8]) {
    v.push(data.len() as u8);
    v.extend_from_slice(data);
}

fn put_vec16(v: &mut Vec<u8>, data: &[u8]) {
    put_u16(v, data.len() as u16);
    v.extend_from_slice(data);
}

fn put_vec24(v: &mut Vec<u8>, data: &[u8]) {
    v.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
    v.extend_from_slice(data);
}

fn put_extension(v: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    put_u16(v, ext_type);
    put_vec16(v, data);
}

/// A TLS 1.3 server connection without any I/O. See the module documentation.
pub struct ServerConnection {
    config: Arc<ServerConfig>,
    read_cipher: Option<RecordCipher>,
    write_cipher: Option<RecordCipher>,
    /// Bytes received and not parsed yet.
    inbuf: Vec<u8>,
    hs_buf: Vec<u8>,
    /// Decrypted application data not yet handed out: `plain[plain_pos..]`.
    plain: Vec<u8>,
    plain_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
    hs: Option<Box<Handshake>>,
    established: bool,
    got_close_notify: bool,
    sent_close_notify: bool,
    failed: bool,
    ccs_skipped: u8,
    suite: Option<Suite>,
    alpn: Option<Vec<u8>>,
    server_name: Option<String>,
    group: Option<u16>,
    rekey_after: u64,
    /// Tickets still to be sent (when they wait for the first write).
    late_tickets: usize,
    /// The handshake resumed a session.
    resumed: bool,
    /// The suite and resumption master secret, which the PSKs of our tickets are made from.
    resumption_secret: Option<(Suite, Zeroizing<Vec<u8>>)>,
}

impl ServerConnection {
    /// A connection that waits for a ClientHello.
    pub fn new(config: Arc<ServerConfig>) -> ServerConnection {
        ServerConnection {
            config,
            read_cipher: None,
            write_cipher: None,
            inbuf: Vec::new(),
            hs_buf: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            hs: Some(Box::new(Handshake {
                stage: Stage::Hello,
                transcript: Vec::new(),
                retried: None,
                ccs_sent: false,
                expected_finished: Vec::new(),
                client_application_secret: Zeroizing::new(Vec::new()),
                suite: Suite::Aes128GcmSha256,
                master_secret: Zeroizing::new(Vec::new()),
            })),
            established: false,
            got_close_notify: false,
            sent_close_notify: false,
            failed: false,
            ccs_skipped: 0,
            suite: None,
            alpn: None,
            server_name: None,
            group: None,
            rekey_after: u64::MAX,
            late_tickets: 0,
            resumed: false,
            resumption_secret: None,
        }
    }

    /// Whether the handshake resumed a session.
    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    // ------------------------------------------------------------------ state

    /// True until the client's Finished has been checked.
    pub fn is_handshaking(&self) -> bool {
        !self.established && !self.failed
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// True once the peer's close_notify has arrived.
    pub fn peer_closed(&self) -> bool {
        self.got_close_notify
    }

    /// True after a fatal error (a fatal alert may be waiting in the output).
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn cipher_suite(&self) -> Option<Suite> {
        self.suite
    }

    /// The ALPN protocol selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The host name the client asked for (its server_name extension), if it sent one.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The key exchange group that was used.
    pub fn group(&self) -> Option<u16> {
        self.group
    }

    // ------------------------------------------------------------------ bytes out

    pub fn output(&self) -> &[u8] {
        &self.out[self.out_pos..]
    }

    pub fn wants_write(&self) -> bool {
        self.out_pos < self.out.len()
    }

    pub fn consume_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out.len());
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
    }

    fn queue_plain(&mut self, record_type: u8, content: &[u8]) {
        self.out.extend_from_slice(&[record_type, 0x03, 0x03]);
        put_vec16(&mut self.out, content);
    }

    /// Encrypts `content` into records of at most `max_fragment` bytes. An alert is never split (RFC 8446
    /// section 5.1): it is one record whatever the limit.
    fn queue_protected(&mut self, inner_type: u8, content: &[u8]) -> Result<()> {
        let fragment = if inner_type == RT_ALERT { MAX_PLAINTEXT } else { self.config.max_fragment.clamp(1, MAX_PLAINTEXT) };
        let cipher = self.write_cipher.as_mut().ok_or_else(|| Error::Tls("internal: no write keys".into()))?;
        for chunk in content.chunks(fragment) {
            cipher.encrypt_into(inner_type, chunk, &mut self.out);
        }
        Ok(())
    }

    /// Queues application data and returns how many bytes of `data` were taken (at most four full records
    /// per call; call again with the rest).
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<usize> {
        if self.failed || self.sent_close_notify {
            return Err(Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "the TLS connection is closed for writing")));
        }
        if !self.established {
            return Err(Error::Tls("internal: application data before the handshake finished".into()));
        }
        let n = data.len().min(MAX_WRITE);
        for chunk in data[..n].chunks(MAX_PLAINTEXT) {
            self.rekey_if_due()?;
            self.queue_protected(RT_APPLICATION_DATA, chunk)?;
        }
        if self.late_tickets > 0 && n > 0 {
            let count = std::mem::take(&mut self.late_tickets);
            self.send_session_tickets(count)?;
        }
        Ok(n)
    }

    fn rekey_if_due(&mut self) -> Result<()> {
        let due = self.write_cipher.as_ref().is_some_and(|c| c.records().saturating_add(1) >= self.rekey_after);
        if due {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    /// Sends a KeyUpdate and switches our sending keys. With `request_peer` the client is asked to
    /// switch its own too.
    pub fn send_key_update(&mut self, request_peer: bool) -> Result<()> {
        if !self.established {
            return Err(Error::Tls("internal: KeyUpdate before the handshake finished".into()));
        }
        self.queue_protected(RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[request_peer as u8]))?;
        let next = self.write_cipher.as_ref().map(|c| c.next_generation());
        self.write_cipher = next;
        Ok(())
    }

    /// Queues `count` NewSessionTicket messages: resumable ones if the configuration keeps sessions, else random bytes for a
    /// client to read past.
    pub fn send_session_tickets(&mut self, count: usize) -> Result<()> {
        for i in 0..count {
            let ticket = rand::bytes::<32>()?.to_vec();
            let nonce = [i as u8];
            if let (Some(sessions), Some((suite, secret))) = (&self.config.sessions, &self.resumption_secret) {
                let alg = suite.hash();
                let psk = Zeroizing::new(expand_label(alg, secret, "resumption", &nonce, alg.output_len()));
                sessions.lock().unwrap().tickets.insert(ticket.clone(), (psk, *suite));
            }
            let mut body = Vec::new();
            body.extend_from_slice(&7200u32.to_be_bytes()); // ticket_lifetime
            body.extend_from_slice(&rand::bytes::<4>()?); // ticket_age_add
            put_vec8(&mut body, &nonce); // ticket_nonce
            put_vec16(&mut body, &ticket); // ticket
            put_vec16(&mut body, &[]); // extensions
            self.queue_protected(RT_HANDSHAKE, &handshake_message(HS_NEW_SESSION_TICKET, &body))?;
        }
        Ok(())
    }

    /// Queues a close_notify alert; the write side is closed afterwards.
    pub fn send_close_notify(&mut self) {
        if !self.established || self.sent_close_notify || self.failed {
            return;
        }
        self.sent_close_notify = true;
        let _ = self.queue_protected(RT_ALERT, &[1, 0]);
    }

    pub fn write_closed(&self) -> bool {
        self.sent_close_notify
    }

    // ------------------------------------------------------------------ bytes in

    /// Gives the connection bytes received from the peer. They are parsed by [`process`](ServerConnection::process).
    pub fn receive(&mut self, data: &[u8]) {
        self.inbuf.extend_from_slice(data);
    }

    /// Tells the connection the transport reached end of file: an error unless the peer said close_notify.
    pub fn recv_eof(&mut self) -> Result<()> {
        if self.got_close_notify {
            return Ok(());
        }
        let msg = if self.inbuf.is_empty() {
            "connection closed without a TLS close_notify (possible truncation)"
        } else {
            "connection closed in the middle of a TLS record"
        };
        Err(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, msg)))
    }

    pub fn has_plaintext(&self) -> bool {
        self.plain_pos < self.plain.len()
    }

    /// Copies decrypted application data into `buf`; 0 if there is none right now.
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.plain.len() - self.plain_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        if self.plain_pos == self.plain.len() {
            self.plain.zeroize();
            self.plain_pos = 0;
        }
        n
    }

    /// Parses and handles the bytes received so far. Needing more is not an error. On a protocol error the
    /// connection is dead: the matching fatal alert is queued in the output and every later call fails.
    pub fn process(&mut self) -> Result<()> {
        if self.failed {
            return Err(Error::Tls("internal: the connection has already failed".into()));
        }
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
            self.sent_close_notify = true;
        }
    }

    fn process_records(&mut self) -> Result<()> {
        loop {
            if self.has_plaintext() || self.got_close_notify {
                return Ok(());
            }
            let Some((record_type, content)) = self.next_record()? else { return Ok(()) };
            if self.established {
                match record_type {
                    RT_APPLICATION_DATA => {
                        self.plain = content;
                        self.plain_pos = 0;
                    }
                    RT_ALERT => {
                        if content == [1, 0] {
                            self.got_close_notify = true;
                        } else {
                            return Err(alert_error(&content));
                        }
                    }
                    RT_HANDSHAKE => {
                        if content.is_empty() {
                            return Err(Error::Tls("unexpected_message: empty handshake record".into()));
                        }
                        self.hs_buf.extend_from_slice(&content);
                        self.process_post_handshake()?;
                    }
                    _ => return Err(Error::Tls("unexpected_message: unexpected record type".into())),
                }
            } else {
                match record_type {
                    RT_HANDSHAKE if content.is_empty() => return Err(Error::Tls("unexpected_message: empty handshake record".into())),
                    RT_HANDSHAKE => {
                        self.hs_buf.extend_from_slice(&content);
                        while self.hs.is_some() {
                            let Some(msg) = self.take_handshake_message()? else { break };
                            self.handshake_step(&msg)?;
                            if self.established {
                                break;
                            }
                        }
                    }
                    RT_ALERT => return Err(alert_error(&content)),
                    _ => return Err(Error::Tls("unexpected_message: non-handshake record during the handshake".into())),
                }
            }
        }
    }

    /// The next complete record: (content type, content), decrypted if the keys are in place. `None` when more
    /// bytes are needed. Compatibility change_cipher_spec records are skipped.
    fn next_record(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        loop {
            if self.inbuf.len() < 5 {
                return Ok(None);
            }
            let header: [u8; 5] = [self.inbuf[0], self.inbuf[1], self.inbuf[2], self.inbuf[3], self.inbuf[4]];
            let record_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[1] != 0x03 {
                return Err(Error::Tls("protocol_version: peer is not speaking TLS".into()));
            }
            let limit = if self.read_cipher.is_some() { MAX_CIPHERTEXT_RECORD } else { MAX_PLAINTEXT };
            if length > limit {
                return Err(Error::Tls("record_overflow: record too large".into()));
            }
            if self.inbuf.len() < 5 + length {
                return Ok(None);
            }
            let record: Vec<u8> = self.inbuf.drain(..5 + length).collect();
            let payload = &record[5..];
            match (self.read_cipher.as_mut(), record_type) {
                (_, RT_CHANGE_CIPHER_SPEC) => {
                    // RFC 8446 appendix D.4: a client may send one after its ClientHello (or its second), not before
                    let before_hello = matches!(self.hs.as_ref().map(|h| &h.stage), Some(Stage::Hello));
                    if self.established || before_hello || payload != [1] || self.ccs_skipped >= MAX_COMPAT_CCS {
                        return Err(Error::Tls("unexpected_message: bad change_cipher_spec".into()));
                    }
                    self.ccs_skipped += 1;
                }
                (Some(cipher), RT_APPLICATION_DATA) => {
                    let mut content = payload.to_vec();
                    let (t, n) = cipher.decrypt_in_place(&header, &mut content)?;
                    content.truncate(n);
                    if t == RT_CHANGE_CIPHER_SPEC {
                        return Err(Error::Tls("unexpected_message: protected change_cipher_spec".into()));
                    }
                    return Ok(Some((t, content)));
                }
                (Some(_), _) => return Err(Error::Tls("unexpected_message: unprotected record after keys were established".into())),
                (None, RT_HANDSHAKE) | (None, RT_ALERT) => return Ok(Some((record_type, payload.to_vec()))),
                (None, _) => return Err(Error::Tls("unexpected_message: unexpected record type".into())),
            }
        }
    }

    fn take_handshake_message(&mut self) -> Result<Option<Vec<u8>>> {
        if self.hs_buf.len() < 4 {
            return Ok(None);
        }
        let len = ((self.hs_buf[1] as usize) << 16) | ((self.hs_buf[2] as usize) << 8) | self.hs_buf[3] as usize;
        if len > MAX_HANDSHAKE_MESSAGE {
            return Err(Error::Tls("illegal_parameter: handshake message too large".into()));
        }
        if self.hs_buf.len() < 4 + len {
            return Ok(None);
        }
        Ok(Some(self.hs_buf.drain(..4 + len).collect()))
    }

    // ------------------------------------------------------------------ handshake

    fn handshake_step(&mut self, msg: &[u8]) -> Result<()> {
        let mut hs = self.hs.take().ok_or_else(|| Error::Tls("internal: no handshake in progress".into()))?;
        let result = self.on_message(&mut hs, msg);
        if !self.established {
            self.hs = Some(hs);
        }
        result
    }

    fn on_message(&mut self, hs: &mut Handshake, msg: &[u8]) -> Result<()> {
        match (&hs.stage, msg[0]) {
            (Stage::Hello, HS_CLIENT_HELLO) | (Stage::RetriedHello, HS_CLIENT_HELLO) => self.on_client_hello(hs, msg),
            (Stage::ClientFinished, HS_FINISHED) => self.on_client_finished(hs, msg),
            _ => Err(Error::Tls("unexpected_message: handshake message out of order".into())),
        }
    }

    fn on_client_hello(&mut self, hs: &mut Handshake, msg: &[u8]) -> Result<()> {
        let hello = parse_hello(&msg[4..])?;
        if !self.hs_buf.is_empty() {
            return Err(Error::Tls("unexpected_message: data after the ClientHello that the client cannot have sent yet".into()));
        }
        if !hello.versions.contains(&VERSION_TLS13) {
            return Err(Error::Tls("protocol_version: the client does not offer TLS 1.3 (this server speaks TLS 1.3 only)".into()));
        }
        let config = self.config.clone();
        let suite = config
            .suites
            .iter()
            .copied()
            .find(|s| hello.cipher_suites.contains(&s.id()))
            .ok_or_else(|| Error::Tls("handshake_failure: no cipher suite in common".into()))?;
        let Some(sig_algs) = &hello.signature_algorithms else {
            return Err(Error::Tls("missing_extension: no signature_algorithms".into()));
        };
        if !sig_algs.contains(&ED25519) {
            return Err(Error::Tls("handshake_failure: the client does not take Ed25519 signatures, the only kind this server makes".into()));
        }

        // the second ClientHello must be the first with a new key share
        let second = matches!(hs.stage, Stage::RetriedHello);
        if let Some(r) = &hs.retried {
            if hello.random != r.random || hello.session_id != r.session_id || hello.cipher_suites != r.cipher_suites || suite != r.suite {
                return Err(Error::Tls("illegal_parameter: the second ClientHello changed what the first said".into()));
            }
            if hello.shares.len() != 1 || hello.shares[0].0 != r.group {
                return Err(Error::Tls("illegal_parameter: the second ClientHello does not carry exactly the key share that was asked for".into()));
            }
        }

        // the key share: the first group of ours that the client sent a share for
        let share = config.groups.iter().find_map(|g| hello.shares.iter().find(|(sg, _)| sg == g));
        let Some((group, client_public)) = share else {
            if second {
                return Err(Error::Tls("illegal_parameter: no usable key share after a HelloRetryRequest".into()));
            }
            let Some(&wanted) = config.groups.iter().find(|g| hello.groups.contains(g)) else {
                return Err(Error::Tls("handshake_failure: no key exchange group in common".into()));
            };
            return self.send_retry(hs, msg, &hello, suite, wanted);
        };

        // ALPN
        let alpn = match &hello.alpn {
            Some(offered) if !config.alpn_protocols.is_empty() => {
                match config.alpn_protocols.iter().find(|p| offered.contains(p)) {
                    Some(p) => Some(p.clone()),
                    None if config.alpn_required => {
                        return Err(Error::Tls("no_application_protocol: the client offers none of the protocols this server has".into()))
                    }
                    None => None,
                }
            }
            _ => None,
        };

        // a session to resume: the first identity, if it is a ticket of ours (used once) of a suite with this one's hash, with
        // a fresh key exchange; its binder must be right (RFC 8446 section 4.2.11.2: a wrong one ends the handshake)
        let mut psk = None;
        if let (Some((id, binder, binders_len)), true, Some(sessions)) = (&hello.psk, hello.psk_dhe_ke, &config.sessions) {
            let found = sessions.lock().unwrap().tickets.remove(id);
            if let Some((key, _)) = found.filter(|(_, s)| s.hash() == suite.hash()) {
                let alg = suite.hash();
                let early = Zeroizing::new(hkdf_extract(alg, &[], &key));
                let binder_key = Zeroizing::new(derive_secret(alg, &early, "res binder", &alg.digest(&[])));
                let finished_key = Zeroizing::new(expand_label(alg, &binder_key, "finished", &[], alg.output_len()));
                let mut t = hs.transcript.clone();
                t.extend_from_slice(&msg[..msg.len() - binders_len]);
                if !ct_eq(&hmac(alg, &finished_key, &alg.digest(&t)), binder) {
                    return Err(Error::Tls("decrypt_error: the PSK binder is wrong".into()));
                }
                sessions.lock().unwrap().resumed += 1;
                psk = Some(key);
            }
        }

        hs.transcript.extend_from_slice(msg);
        self.send_flight(hs, &hello, suite, *group, client_public, alpn, psk)
    }

    /// Asks for a key share for `group` (RFC 8446 section 4.1.4).
    fn send_retry(&mut self, hs: &mut Handshake, ch: &[u8], hello: &Hello, suite: Suite, group: u16) -> Result<()> {
        let mut body = Vec::new();
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        put_vec8(&mut body, &hello.session_id);
        put_u16(&mut body, suite.id());
        body.push(0);
        let mut exts = Vec::new();
        put_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &VERSION_TLS13.to_be_bytes());
        put_extension(&mut exts, EXT_KEY_SHARE, &group.to_be_bytes());
        put_vec16(&mut body, &exts);
        let hrr = handshake_message(HS_SERVER_HELLO, &body);

        // the transcript restarts: ClientHello1 becomes a message_hash message
        hs.transcript = handshake_message(HS_MESSAGE_HASH, &suite.hash().digest(ch));
        hs.transcript.extend_from_slice(&hrr);
        self.queue_plain(RT_HANDSHAKE, &hrr);
        if !hello.session_id.is_empty() {
            self.queue_plain(RT_CHANGE_CIPHER_SPEC, &[1]);
            hs.ccs_sent = true;
        }
        hs.retried = Some(Retried {
            random: hello.random,
            session_id: hello.session_id.clone(),
            cipher_suites: hello.cipher_suites.clone(),
            suite,
            group,
        });
        hs.stage = Stage::RetriedHello;
        Ok(())
    }

    /// ServerHello and everything up to our Finished; the keys for the rest.
    #[allow(clippy::too_many_arguments)]
    fn send_flight(
        &mut self,
        hs: &mut Handshake,
        hello: &Hello,
        suite: Suite,
        group: u16,
        client_public: &[u8],
        alpn: Option<Vec<u8>>,
        psk: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<()> {
        let (server_public, shared) = key_exchange(group, client_public)?;

        // ServerHello
        let mut body = Vec::new();
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&rand::bytes::<32>()?);
        put_vec8(&mut body, &hello.session_id);
        put_u16(&mut body, suite.id());
        body.push(0);
        let mut exts = Vec::new();
        put_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &VERSION_TLS13.to_be_bytes());
        let mut share = group.to_be_bytes().to_vec();
        put_vec16(&mut share, &server_public);
        put_extension(&mut exts, EXT_KEY_SHARE, &share);
        if psk.is_some() {
            put_extension(&mut exts, EXT_PRE_SHARED_KEY, &0u16.to_be_bytes());
        }
        put_vec16(&mut body, &exts);
        let server_hello = handshake_message(HS_SERVER_HELLO, &body);
        hs.transcript.extend_from_slice(&server_hello);
        self.queue_plain(RT_HANDSHAKE, &server_hello);
        if !hello.session_id.is_empty() && !hs.ccs_sent {
            self.queue_plain(RT_CHANGE_CIPHER_SPEC, &[1]);
            hs.ccs_sent = true;
        }

        // the key schedule, as RFC 8446 section 7.1
        let alg: HashAlg = suite.hash();
        let hash_len = alg.output_len();
        let zeros = vec![0u8; hash_len];
        let empty_hash = alg.digest(&[]);
        let early_secret = Zeroizing::new(hkdf_extract(alg, &[], psk.as_deref().map_or(&zeros[..], |p| &p[..])));
        let derived = Zeroizing::new(derive_secret(alg, &early_secret, "derived", &empty_hash));
        let handshake_secret = Zeroizing::new(hkdf_extract(alg, &derived, &shared));
        let hello_hash = alg.digest(&hs.transcript);
        self.resumed = psk.is_some();
        let c_hs = Zeroizing::new(derive_secret(alg, &handshake_secret, "c hs traffic", &hello_hash));
        let s_hs = Zeroizing::new(derive_secret(alg, &handshake_secret, "s hs traffic", &hello_hash));
        self.write_cipher = Some(RecordCipher::new(suite, &s_hs));
        self.read_cipher = Some(RecordCipher::new(suite, &c_hs));
        self.suite = Some(suite);
        self.group = Some(group);
        self.alpn = alpn.clone();
        self.server_name = hello.server_name.clone();

        // EncryptedExtensions
        let mut exts = Vec::new();
        if hello.server_name.is_some() {
            put_extension(&mut exts, EXT_SERVER_NAME, &[]);
        }
        if let Some(p) = &alpn {
            let mut list = Vec::new();
            put_vec8(&mut list, p);
            let mut data = Vec::new();
            put_vec16(&mut data, &list);
            put_extension(&mut exts, EXT_ALPN, &data);
        }
        let mut ee = Vec::new();
        put_vec16(&mut ee, &exts);
        self.queue_handshake(hs, &handshake_message(HS_ENCRYPTED_EXTENSIONS, &ee))?;

        if psk.is_none() {
            self.queue_certificate(hs, hello, alg)?;
        }

        // Finished
        let finished_key = Zeroizing::new(expand_label(alg, &s_hs, "finished", &[], hash_len));
        let verify_data = hmac(alg, &finished_key, &alg.digest(&hs.transcript));
        self.queue_handshake(hs, &handshake_message(HS_FINISHED, &verify_data))?;

        // application keys (transcript through our Finished) and what the client's Finished must be
        let app_hash = alg.digest(&hs.transcript);
        let derived2 = Zeroizing::new(derive_secret(alg, &handshake_secret, "derived", &empty_hash));
        let master_secret = Zeroizing::new(hkdf_extract(alg, &derived2, &zeros));
        let c_ap = Zeroizing::new(derive_secret(alg, &master_secret, "c ap traffic", &app_hash));
        let s_ap = Zeroizing::new(derive_secret(alg, &master_secret, "s ap traffic", &app_hash));
        let client_finished_key = Zeroizing::new(expand_label(alg, &c_hs, "finished", &[], hash_len));
        hs.expected_finished = hmac(alg, &client_finished_key, &app_hash);
        hs.client_application_secret = c_ap;
        hs.suite = suite;
        hs.master_secret = master_secret;
        // we may send application data as soon as our Finished is out; we read the client's Finished first
        self.write_cipher = Some(RecordCipher::new(suite, &s_ap));
        hs.stage = Stage::ClientFinished;
        Ok(())
    }

    /// Certificate and CertificateVerify (a full handshake's).
    fn queue_certificate(&mut self, hs: &mut Handshake, hello: &Hello, alg: HashAlg) -> Result<()> {
        let config = self.config.clone();
        // Certificate
        let mut list = Vec::new();
        for (i, der) in config.chain.iter().enumerate() {
            put_vec24(&mut list, der);
            let mut entry_exts = Vec::new();
            if i == 0 && hello.status_request {
                if let Some(staple) = &config.ocsp_staple {
                    let mut status = vec![1u8]; // status_type: ocsp
                    put_vec24(&mut status, staple);
                    put_extension(&mut entry_exts, EXT_STATUS_REQUEST, &status);
                }
            }
            put_vec16(&mut list, &entry_exts);
        }
        let mut cert = vec![0u8]; // certificate_request_context: empty
        put_vec24(&mut cert, &list);
        self.queue_handshake(hs, &handshake_message(HS_CERTIFICATE, &cert))?;

        // CertificateVerify
        let content = server_certificate_verify_content(&alg.digest(&hs.transcript));
        let signature = config.key.sign(&content);
        let mut verify = Vec::new();
        put_u16(&mut verify, ED25519);
        put_vec16(&mut verify, &signature);
        self.queue_handshake(hs, &handshake_message(HS_CERTIFICATE_VERIFY, &verify))
    }

    /// Queues a handshake message under the handshake keys and adds it to the transcript.
    fn queue_handshake(&mut self, hs: &mut Handshake, msg: &[u8]) -> Result<()> {
        hs.transcript.extend_from_slice(msg);
        self.queue_protected(RT_HANDSHAKE, msg)
    }

    fn on_client_finished(&mut self, hs: &mut Handshake, msg: &[u8]) -> Result<()> {
        if !ct_eq(&hs.expected_finished, &msg[4..]) {
            return Err(Error::Tls("decrypt_error: client Finished MAC is invalid".into()));
        }
        if !self.hs_buf.is_empty() {
            return Err(Error::Tls("unexpected_message: handshake data after the client Finished".into()));
        }
        self.read_cipher = Some(RecordCipher::new(hs.suite, &hs.client_application_secret));
        self.rekey_after = self.config.rekey_after_records.unwrap_or(hs.suite.records_per_key()).max(2);
        self.established = true;
        // the resumption master secret: the transcript through the client's Finished
        let alg = hs.suite.hash();
        hs.transcript.extend_from_slice(msg);
        let res_master = Zeroizing::new(derive_secret(alg, &hs.master_secret, "res master", &alg.digest(&hs.transcript)));
        self.resumption_secret = Some((hs.suite, res_master));
        if self.config.tickets_after_first_write {
            self.late_tickets = self.config.tickets;
        } else {
            self.send_session_tickets(self.config.tickets)?;
        }
        Ok(())
    }

    fn process_post_handshake(&mut self) -> Result<()> {
        while let Some(msg) = self.take_handshake_message()? {
            match msg[0] {
                HS_KEY_UPDATE => {
                    if msg.len() != 5 || msg[4] > 1 {
                        return Err(bad("malformed KeyUpdate"));
                    }
                    if !self.hs_buf.is_empty() {
                        return Err(Error::Tls("unexpected_message: handshake data follows a KeyUpdate in the same record".into()));
                    }
                    let next = self.read_cipher.as_ref().map(|c| c.next_generation());
                    self.read_cipher = next;
                    if msg[4] == 1 {
                        // asked to update too: answer under the old keys, then rotate
                        self.send_key_update(false)?;
                    }
                }
                // a client may send nothing else after its Finished (no certificates were asked for)
                _ => return Err(Error::Tls("unexpected_message: unexpected post-handshake message".into())),
            }
        }
        Ok(())
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        self.inbuf.zeroize();
        self.plain.zeroize();
        self.out.zeroize();
        self.hs_buf.zeroize();
    }
}

// ------------------------------------------------------------------------------------------------ blocking driver

/// An accepted TLS 1.3 connection over a blocking transport. Implements [`Read`] and [`Write`]; a
/// close_notify is sent when it is dropped.
pub struct ServerStream<S: Read + Write> {
    io: S,
    conn: ServerConnection,
    staging: Vec<u8>,
}

impl<S: Read + Write> ServerStream<S> {
    /// Performs the server side of the handshake over `io`.
    pub fn accept(io: S, config: &Arc<ServerConfig>) -> Result<ServerStream<S>> {
        let mut s = ServerStream { io, conn: ServerConnection::new(config.clone()), staging: vec![0u8; 32 * 1024] };
        while s.conn.is_handshaking() {
            if let Err(e) = s.pump() {
                let _ = s.send_output();
                let _ = s.io.flush();
                return Err(e);
            }
        }
        // the tickets and anything else our side has queued go out with the first write, or now
        s.send_output()?;
        s.io.flush()?;
        Ok(s)
    }

    /// Reads once from the transport into the connection and processes it; sends what that queued.
    fn pump(&mut self) -> Result<()> {
        self.send_output()?;
        self.io.flush()?;
        loop {
            match self.io.read(&mut self.staging) {
                Ok(0) => return self.conn.recv_eof().and_then(|_| Err(Error::Tls("the client closed the connection during the handshake".into()))),
                Ok(n) => {
                    self.conn.receive(&self.staging[..n]);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.conn.process()
    }

    fn send_output(&mut self) -> io::Result<()> {
        if !self.conn.wants_write() {
            return Ok(());
        }
        let res = self.io.write_all(self.conn.output());
        let n = self.conn.output().len();
        self.conn.consume_output(n);
        res
    }

    pub fn cipher_suite(&self) -> Option<Suite> {
        self.conn.cipher_suite()
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    pub fn server_name(&self) -> Option<&str> {
        self.conn.server_name()
    }

    pub fn group(&self) -> Option<u16> {
        self.conn.group()
    }

    /// Whether the handshake resumed a session.
    pub fn is_resumed(&self) -> bool {
        self.conn.is_resumed()
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// The connection state machine, for tests that steer it (KeyUpdate, tickets).
    pub fn connection_mut(&mut self) -> &mut ServerConnection {
        &mut self.conn
    }

    /// Sends what the connection has queued (after a call that queued something directly).
    pub fn flush_queued(&mut self) -> io::Result<()> {
        self.send_output()?;
        self.io.flush()
    }

    /// Sends a close_notify; the write side is closed afterwards.
    pub fn close(&mut self) -> io::Result<()> {
        if self.conn.write_closed() {
            return Ok(());
        }
        self.conn.send_close_notify();
        self.send_output()?;
        self.io.flush()
    }
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

impl<S: Read + Write> Read for ServerStream<S> {
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
                let _ = self.send_output();
                let _ = self.io.flush();
                return Err(to_io(e));
            }
            if self.conn.has_plaintext() || self.conn.peer_closed() {
                continue;
            }
            self.send_output()?; // what the processing queued (the answer to a KeyUpdate)
            self.io.flush()?;
            match self.io.read(&mut self.staging) {
                Ok(0) => return self.conn.recv_eof().map(|_| 0).map_err(to_io),
                Ok(n) => self.conn.receive(&self.staging[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Read + Write> Write for ServerStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.conn.write_plaintext(buf).map_err(to_io)?;
        self.send_output()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_output()?;
        self.io.flush()
    }
}

impl<S: Read + Write> Drop for ServerStream<S> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
