//! The message-level half of the TLS 1.3 client handshake.
//!
//! [`Handshake`] takes whole handshake messages and says what to do about them: which messages to send under which keys, which
//! secrets to install, and what the server turned out to be (its ALPN choice, its certificate chain, its QUIC transport
//! parameters). It knows nothing of how messages travel. [`ClientConnection`](super::ClientConnection) carries them in TLS records
//! over a byte stream; `crate::quic` carries them in CRYPTO frames (RFC 9001), which differ in four ways that live here: no
//! middlebox-compatibility mode (the legacy session id is empty), the `quic_transport_parameters` extension in both directions,
//! an ALPN protocol that the server has to select, and no change_cipher_spec.
//!
//! The order of what a step returns matters (a Finished that is sent under the handshake keys comes before the application
//! secrets that replace them), so a step returns a list of [`Event`]s to be applied in order.

use super::messages::*;
use super::session::{Scope, Session};
use super::suite::*;
use super::tls12::{Handshake12, Start12, Step12, VERSION_TLS12};
use super::{ClientConfig, TlsVersion};
use crate::crypto::ecdsa::Curve;
use crate::crypto::sha2::{HashAlg, Running};
use crate::crypto::{ecdh, rand, x25519};
use crate::error::{Error, Result};
use crate::revocation::{self, RevocationMode};
use crate::sys;
use crate::util::ct_eq;
use crate::verify_error::Error as VerifyError;
use crate::x509::Certificate;
use crate::zeroize::Zeroizing;
use std::net::IpAddr;

/// The largest handshake message accepted (a certificate chain with room to spare).
pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 1 << 18;

/// The alert a protocol error is answered with; `None` for errors that are not the peer's fault
/// on the wire (I/O failures, alerts the peer sent).
pub(crate) fn alert_description(err: &Error) -> Option<u8> {
    Some(match err {
        Error::Io(_) | Error::Alert(_, _) => return None,
        Error::Verify(VerifyError::Certificate(m)) if m.starts_with("certificate_revoked") => 44,
        Error::Verify(VerifyError::Certificate(m)) if m.starts_with("bad_certificate_status_response") => 113,
        Error::Verify(_) => 42, // bad_certificate
        Error::Tls(m) if m.starts_with("unexpected_message") => 10,
        Error::Tls(m) if m.starts_with("bad_record_mac") => 20,
        Error::Tls(m) if m.starts_with("record_overflow") => 22,
        Error::Tls(m) if m.starts_with("illegal_parameter") => 47,
        Error::Tls(m) if m.starts_with("decode_error") => 50,
        Error::Tls(m) if m.starts_with("decrypt_error") => 51,
        Error::Tls(m) if m.starts_with("protocol_version") => 70,
        Error::Tls(m) if m.starts_with("unsupported_extension") => 110,
        Error::Tls(m) if m.starts_with("missing_extension") => 109,
        Error::Tls(m) if m.starts_with("no_application_protocol") => 120,
        _ => 40, // handshake_failure
    })
}

/// The complete handshake message at the front of `buf`, taken out of it; `None` if `buf` holds only part of one.
pub(crate) fn take_message(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if len > MAX_HANDSHAKE_MESSAGE {
        return Err(Error::Tls("illegal_parameter: handshake message too large".into()));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some(buf.drain(..4 + len).collect()))
}

/// The keys a message of ours goes out under: the Initial keys of QUIC (or no keys, over TCP) for the ClientHello, the handshake keys
/// for the rest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Epoch {
    Initial,
    Handshake,
}

/// What a step of the handshake asks for.
pub(crate) enum Event {
    /// Send a handshake message under the keys of this epoch.
    Send(Epoch, Vec<u8>),
    /// The ServerHello is in: the cipher suite, and the traffic secrets of the handshake epoch, ours (the client's) and the
    /// server's. What we send from now on, and what we are sent, is under these.
    HandshakeSecrets { suite: Suite, client: Zeroizing<Vec<u8>>, server: Zeroizing<Vec<u8>> },
    /// The ALPN protocol the server selected (None: it selected none).
    Alpn(Option<Vec<u8>>),
    /// The certificate chain the server sent and that was accepted (the leaf first).
    PeerCertificates(Vec<Vec<u8>>),
    /// The chain is verified but the sources of revocation evidence are still to be asked (the configuration deferred them).
    Unchecked(Box<revocation::Unchecked>),
    /// The server's `quic_transport_parameters`, as sent (QUIC only).
    PeerTransportParameters(Vec<u8>),
    /// The server's Finished is verified and ours is in the events before this: the handshake is over, and these are the traffic
    /// secrets of the application epoch.
    ApplicationSecrets { suite: Suite, client: Zeroizing<Vec<u8>>, server: Zeroizing<Vec<u8>> },
    /// The server speaks TLS 1.2: the handshake goes on in this one (see [`super::tls12`]), which asks for these steps first.
    /// Never over QUIC, which offers TLS 1.3 only.
    Tls12(Box<Handshake12>, Vec<Step12>),
    /// The server took the session the ClientHello offered: no certificate comes, and these are the ones of the full handshake
    /// the session descends from (before [`Event::PeerCertificates`] with them).
    Resumed,
    /// The handshake is over (after [`Event::ApplicationSecrets`]): the resumption master secret, from which the PSKs of the
    /// server's tickets are made, and when the chain these tickets rest on was checked (Unix seconds).
    ResumptionSecret { suite: Suite, secret: Zeroizing<Vec<u8>>, verified_at: i64 },
}

/// Where the server's flight stands.
#[derive(PartialEq, Clone, Copy)]
enum Stage {
    ServerHello,
    EncryptedExtensions,
    CertificateOrRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

/// Secrets and values the handshake needs after ServerHello.
struct HandshakeKeys {
    suite: Suite,
    alg: crate::crypto::sha2::HashAlg,
    /// The server took the offered session.
    resumed: bool,
    handshake_secret: Zeroizing<Vec<u8>>,
    c_hs: Zeroizing<Vec<u8>>,
    s_hs: Zeroizing<Vec<u8>>,
}

/// The private half of the key share the ClientHello carries.
enum KeyShareSecret {
    X25519(Zeroizing<[u8; 32]>),
    /// A NIST curve: the private scalar, big-endian.
    Ec(Curve, Zeroizing<Vec<u8>>),
}

fn curve_of_group(group: u16) -> Option<Curve> {
    match group {
        GROUP_SECP256R1 => Some(Curve::P256),
        GROUP_SECP384R1 => Some(Curve::P384),
        _ => None,
    }
}

/// A fresh key share for `group`: the secret and the public value that goes in the ClientHello.
fn new_key_share(group: u16) -> Result<(KeyShareSecret, Vec<u8>)> {
    if group == GROUP_X25519 {
        let private: Zeroizing<[u8; 32]> = Zeroizing::new(rand::bytes()?);
        let public = x25519::public_key(&private).to_vec();
        return Ok((KeyShareSecret::X25519(private), public));
    }
    let curve = curve_of_group(group).ok_or_else(|| Error::Tls("internal: key share for an unsupported group".into()))?;
    let (secret, public) = ecdh::generate(curve)?;
    Ok((KeyShareSecret::Ec(curve, secret), public))
}

/// The handshake messages so far, for the Transcript-Hash (RFC 8446 section 4.4.1): as bytes until the ServerHello names the
/// hash (a HelloRetryRequest restarts them, and TLS 1.2 takes them over), then as a running hash, from which each
/// Transcript-Hash is a copy finished (B-104: hashing all the bytes again at each of the six points where one is needed was a
/// seventh of a full handshake's client CPU on an x86-64 server).
struct Transcript {
    bytes: Vec<u8>,
    running: Option<Running>,
}

impl Transcript {
    fn new(first: Vec<u8>) -> Transcript {
        Transcript { bytes: first, running: None }
    }

    fn add(&mut self, msg: &[u8]) {
        match &mut self.running {
            Some(h) => h.update(msg),
            None => self.bytes.extend_from_slice(msg),
        }
    }

    /// From here on the messages are kept as their running hash with `alg`.
    fn hash_with(&mut self, alg: HashAlg) {
        let mut h = alg.start();
        h.update(&self.bytes);
        self.running = Some(h);
        self.bytes = Vec::new();
    }

    /// Transcript-Hash of the messages so far.
    fn hash(&self, alg: HashAlg) -> Vec<u8> {
        match &self.running {
            Some(h) => h.digest(),
            None => alg.digest(&self.bytes),
        }
    }
}

pub(crate) struct Handshake {
    stage: Stage,
    secret: KeyShareSecret,
    /// The group of the key share in the ClientHello sent last.
    sent_group: u16,
    /// The random of the ClientHello (the same in a second one).
    client_random: [u8; 32],
    /// The ClientHello offers TLS 1.2 too (see [`ClientConfig::min_version`]): never over QUIC.
    offers_tls12: bool,
    /// The ClientHello's random and legacy session id, kept to build the second ClientHello after a
    /// HelloRetryRequest (it must repeat them). `None` for a recorded hello (tests), which cannot retry.
    hello_inputs: Option<([u8; 32], Vec<u8>)>,
    /// A HelloRetryRequest has been answered (a second one is a protocol violation) and the cipher
    /// suite it named, which the ServerHello must repeat.
    retry_suite: Option<Suite>,
    session_id: Vec<u8>,
    server_name: String,
    sent_sni: bool,
    /// The ClientHello asked for a stapled OCSP response, so Certificate entries may carry one.
    status_requested: bool,
    /// Our QUIC transport parameters, which both ClientHellos carry: `Some` makes this a QUIC handshake.
    quic: Option<Vec<u8>>,
    config: ClientConfig,
    transcript: Transcript,
    keys: Option<HandshakeKeys>,
    /// the server's CertificateRequest, answered after its Finished
    request: Option<CertificateRequest>,
    leaf: Option<Certificate>,
    /// The session the ClientHello offers, if it offers one (TLS 1.3 over TCP, with resumption on and a session kept).
    psk: Option<Session>,
    /// When the server's chain was checked (Unix seconds): now, in a full handshake; the session's, in a resumed one.
    verified_at: i64,
    /// Extension types removed from EncryptedExtensions before they are checked (tests only).
    #[cfg(test)]
    ignored_ee_extensions: Vec<u16>,
}

impl Handshake {
    /// Starts a handshake: the state, and the ClientHello that is to be sent first (in the Initial epoch).
    ///
    /// `quic` is the encoded transport parameters of a QUIC client (RFC 9000 section 18); `Some` also means that `session_id`
    /// is empty (RFC 9001 section 8.4: no compatibility mode) and that the server has to name an ALPN protocol. Over TCP,
    /// `session_id` is 32 random bytes for the compatibility mode.
    pub(crate) fn start(
        server_name: &str,
        config: &ClientConfig,
        quic: Option<&[u8]>,
        private: Zeroizing<[u8; 32]>,
        random: &[u8; 32],
        session_id: &[u8],
    ) -> (Handshake, Vec<u8>) {
        let public = x25519::public_key(&private);
        // RFC 6066 section 3: no IP literal, and no trailing dot ("example.com." is sent as "example.com")
        let sni = if server_name.parse::<IpAddr>().is_ok() { None } else { Some(server_name.strip_suffix('.').unwrap_or(server_name)) };
        let status_requested = config.verify_server_certificate && config.revocation.mode != RevocationMode::Off;
        let offers_tls12 = quic.is_none() && config.min_version <= TlsVersion::Tls12;
        // a session to resume: over TCP only (a QUIC client neither keeps nor offers any)
        let now = config.time_override.unwrap_or_else(sys::now_unix);
        let psk = if quic.is_none() { config.resumption.take(&session_key(server_name), &scope_of(config), now) } else { None };
        let offer = psk.as_ref().map(|s| PskOffer { identity: &s.ticket, obfuscated_age: s.obfuscated_age(), binder_len: s.suite.hash().output_len() });
        let mut client_hello = build_client_hello(&ClientHello {
            random,
            session_id,
            server_name: sni,
            key_share_group: GROUP_X25519,
            key_share_public: &public,
            alpn: &config.alpn_protocols,
            status_request: status_requested,
            cookie: None,
            quic_transport_parameters: quic,
            tls12: offers_tls12,
            psk: offer,
        });
        if let Some(session) = &psk {
            let binder = psk_binder(session, &[], &client_hello);
            set_psk_binder(&mut client_hello, &binder);
        }
        let hs = Handshake {
            stage: Stage::ServerHello,
            secret: KeyShareSecret::X25519(private),
            sent_group: GROUP_X25519,
            client_random: *random,
            offers_tls12,
            hello_inputs: Some((*random, session_id.to_vec())),
            retry_suite: None,
            session_id: session_id.to_vec(),
            server_name: server_name.to_string(),
            sent_sni: sni.is_some(),
            status_requested,
            quic: quic.map(<[u8]>::to_vec),
            config: config.clone(),
            transcript: Transcript::new(client_hello.clone()),
            keys: None,
            request: None,
            leaf: None,
            psk,
            verified_at: now,
            #[cfg(test)]
            ignored_ee_extensions: Vec::new(),
        };
        (hs, client_hello)
    }

    /// A handshake that treats `client_hello` (a ClientHello handshake message made elsewhere, such as a trace from an RFC) as the
    /// one it sent, with the matching X25519 private key and legacy session id. Extensions of the types in `ignored_ee_extensions`
    /// that the server answers in EncryptedExtensions are skipped instead of refused, because the recorded ClientHello offered
    /// extensions this client never does. For tests.
    #[cfg(test)]
    pub(crate) fn recorded(
        server_name: &str,
        config: &ClientConfig,
        private: [u8; 32],
        session_id: &[u8],
        client_hello: &[u8],
        ignored_ee_extensions: &[u16],
    ) -> Handshake {
        let mut client_random = [0u8; 32];
        if client_hello.len() >= 38 {
            client_random.copy_from_slice(&client_hello[6..38]);
        }
        Handshake {
            stage: Stage::ServerHello,
            secret: KeyShareSecret::X25519(Zeroizing::new(private)),
            sent_group: GROUP_X25519,
            client_random,
            offers_tls12: false,
            hello_inputs: None,
            retry_suite: None,
            session_id: session_id.to_vec(),
            server_name: server_name.to_string(),
            sent_sni: server_name.parse::<IpAddr>().is_err(),
            status_requested: false,
            quic: None,
            config: config.clone(),
            transcript: Transcript::new(client_hello.to_vec()),
            keys: None,
            request: None,
            leaf: None,
            psk: None,
            verified_at: 0,
            ignored_ee_extensions: ignored_ee_extensions.to_vec(),
        }
    }

    /// The configuration the handshake runs under.
    pub(crate) fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Processes one complete handshake message (with its four-byte header) from the server. `trailing` says that more handshake
    /// bytes follow it in what was received at the same time: at the messages that change keys (ServerHello, HelloRetryRequest,
    /// Finished) that is an error, because what follows would have to be read under keys it was not sent under.
    pub(crate) fn on_message(&mut self, msg: &[u8], trailing: bool) -> Result<Vec<Event>> {
        if msg.len() < 4 {
            return Err(Error::Tls("decode_error: handshake message without a header".into()));
        }
        let body = &msg[4..];
        let mut events = Vec::new();
        match (self.stage, msg[0]) {
            (Stage::ServerHello, HS_SERVER_HELLO) => {
                let sh = parse_server_hello(body)?;
                if sh.random == HELLO_RETRY_REQUEST_RANDOM {
                    self.on_hello_retry_request(msg, sh, trailing, &mut events)?;
                    return Ok(events);
                }
                // RFC 8446 section 4.1.3: a server that can do TLS 1.3 and speaks an older version marks its random so; a client
                // that offered 1.3 and sees the mark knows that 1.3 was taken out of its ClientHello on the way
                if has_downgrade_sentinel(&sh.random) {
                    return Err(Error::Tls(
                        "illegal_parameter: ServerHello.random carries the TLS downgrade sentinel (possible downgrade attack)".into(),
                    ));
                }
                match sh.selected_version {
                    Some(VERSION_TLS13) => {}
                    // a version in supported_versions that is not 1.3 is one we did not offer there (section 4.2.1)
                    Some(_) => return Err(Error::Tls("illegal_parameter: the server selected a version in supported_versions that was not offered".into())),
                    None if sh.legacy_version == VERSION_TLS12 && self.offers_tls12 && self.retry_suite.is_none() => {
                        // (in TLS 1.2 the messages after ServerHello are in the clear too, so they may come with it)
                        return self.switch_to_tls12(msg, &sh);
                    }
                    None if sh.legacy_version == VERSION_TLS12 && !self.offers_tls12 => {
                        return Err(Error::Tls("protocol_version: the server speaks TLS 1.2, and this connection requires TLS 1.3".into()));
                    }
                    None => return Err(Error::Tls("protocol_version: server did not negotiate TLS 1.3 or 1.2".into())),
                }
                if let Some((t, _)) = sh.other_extensions.first() {
                    return Err(Error::Tls(format!("unsupported_extension: unexpected extension {} in ServerHello", t)));
                }
                if sh.legacy_version != 0x0303 || sh.compression != 0 {
                    return Err(Error::Tls("illegal_parameter: bad legacy fields in ServerHello".into()));
                }
                if sh.session_id != self.session_id {
                    return Err(Error::Tls("illegal_parameter: ServerHello did not echo the legacy session id".into()));
                }
                let suite = Suite::from_id(sh.cipher_suite)
                    .ok_or_else(|| Error::Tls("illegal_parameter: server chose a cipher suite we did not offer".into()))?;
                if self.retry_suite.is_some_and(|retry| retry != suite) {
                    return Err(Error::Tls("illegal_parameter: ServerHello changed the cipher suite chosen in the HelloRetryRequest".into()));
                }
                // RFC 8446 section 4.2.11: the identity must be one that was offered (there is one), and the suite's hash the
                // PSK's
                let resumed = match (sh.selected_identity, &self.psk) {
                    (None, _) => false,
                    (Some(_), None) => return Err(Error::Tls("illegal_parameter: the server took a PSK that was not offered".into())),
                    (Some(0), Some(session)) if session.suite.hash() == suite.hash() => true,
                    (Some(0), Some(_)) => return Err(Error::Tls("illegal_parameter: the server resumed with a cipher suite of another hash than the session's".into())),
                    (Some(i), Some(_)) => return Err(Error::Tls(format!("illegal_parameter: the server took PSK identity {i}, and one was offered"))),
                };
                // (only psk_dhe_ke was offered, so the server must send a key share whether it resumes or not)
                let (group, server_share) = sh.key_share.ok_or_else(|| Error::Tls("missing_extension: no key_share in ServerHello".into()))?;
                if group != self.sent_group {
                    return Err(Error::Tls("illegal_parameter: ServerHello selected a key share group we did not send".into()));
                }
                let shared: Zeroizing<Vec<u8>> = match &self.secret {
                    KeyShareSecret::X25519(private) => {
                        let server_public: [u8; 32] = <[u8; 32]>::try_from(server_share.as_slice())
                            .map_err(|_| Error::Tls("illegal_parameter: unexpected key share length".into()))?;
                        let shared = Zeroizing::new(x25519::x25519(private, &server_public));
                        // OR-fold rather than `all()`: it must not stop at the first non-zero byte of a secret.
                        if shared.iter().fold(0u8, |acc, &b| acc | b) == 0 {
                            return Err(Error::Tls("illegal_parameter: X25519 produced an all-zero shared secret".into()));
                        }
                        Zeroizing::new(shared.to_vec())
                    }
                    KeyShareSecret::Ec(curve, private) => ecdh::shared_secret(*curve, private, &server_share)
                        .ok_or_else(|| Error::Tls("illegal_parameter: the server's key share is not a valid point on the curve".into()))?,
                };
                self.transcript.add(msg);
                if trailing {
                    return Err(Error::Tls("unexpected_message: data after ServerHello in the same record".into()));
                }

                // key schedule up to the handshake traffic secrets
                let alg = suite.hash();
                self.transcript.hash_with(alg);
                let hash_len = alg.output_len();
                let zeros = vec![0u8; hash_len];
                let empty_hash = alg.digest(&[]);
                let psk: &[u8] = match (&self.psk, resumed) {
                    (Some(session), true) => &session.psk,
                    _ => &zeros,
                };
                let early_secret = Zeroizing::new(hkdf_extract(alg, &[], psk));
                let derived = Zeroizing::new(derive_secret(alg, &early_secret, "derived", &empty_hash));
                let handshake_secret = Zeroizing::new(hkdf_extract(alg, &derived, &shared));
                let hello_hash = self.transcript.hash(alg);
                let prk = Prk::new(alg, &handshake_secret);
                let c_hs = Zeroizing::new(prk.derive_secret("c hs traffic", &hello_hash));
                let s_hs = Zeroizing::new(prk.derive_secret("s hs traffic", &hello_hash));
                events.push(Event::HandshakeSecrets { suite, client: c_hs.clone(), server: s_hs.clone() });
                self.keys = Some(HandshakeKeys { suite, alg, resumed, handshake_secret, c_hs, s_hs });
                self.stage = Stage::EncryptedExtensions;
            }
            (Stage::EncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                let offered = &self.config.alpn_protocols;
                #[cfg(test)]
                let stripped = without_extensions(body, &self.ignored_ee_extensions);
                #[cfg(test)]
                let body = &stripped[..];
                let ee = parse_encrypted_extensions_for(body, self.sent_sni, !offered.is_empty(), self.quic.is_some())?;
                if let Some(p) = &ee.alpn {
                    if !offered.contains(p) {
                        return Err(Error::Tls("illegal_parameter: server selected an ALPN protocol we did not offer".into()));
                    }
                }
                if self.quic.is_some() {
                    // RFC 9001 section 8.1 and 8.2: both are required of a server
                    if ee.alpn.is_none() {
                        return Err(Error::Tls("no_application_protocol: the server selected no ALPN protocol".into()));
                    }
                    match ee.quic_transport_parameters {
                        Some(params) => events.push(Event::PeerTransportParameters(params)),
                        None => return Err(Error::Tls("missing_extension: no quic_transport_parameters in EncryptedExtensions".into())),
                    }
                }
                events.push(Event::Alpn(ee.alpn));
                self.transcript.add(msg);
                let resumed = self.keys.as_ref().is_some_and(|k| k.resumed);
                if let (true, Some(session)) = (resumed, &self.psk) {
                    // a resumed handshake has no Certificate, CertificateVerify or CertificateRequest (RFC 8446 section 2.2,
                    // 4.3.2): the server's Finished is next, and the chain is the one the session was made on
                    self.verified_at = session.verified_at;
                    events.push(Event::Resumed);
                    events.push(Event::PeerCertificates(session.peer_chain.clone()));
                    self.stage = Stage::Finished;
                } else {
                    self.stage = Stage::CertificateOrRequest;
                }
            }
            (Stage::CertificateOrRequest, HS_CERTIFICATE_REQUEST) => {
                self.request = Some(parse_certificate_request(body)?);
                self.transcript.add(msg);
                self.stage = Stage::Certificate;
            }
            (Stage::CertificateOrRequest, HS_CERTIFICATE) | (Stage::Certificate, HS_CERTIFICATE) => {
                let ServerCertificates { chain, staples } = parse_certificate(body, self.status_requested)?;
                self.leaf = Some(if self.config.verify_server_certificate {
                    let now = self.config.time_override.unwrap_or_else(sys::now_unix);
                    self.verified_at = now;
                    let (leaf, path) = self.config.trust_store.verify_server_path(&chain, &self.server_name, now)?;
                    let evidence = revocation::ChainEvidence { sent: &chain, staples: &staples };
                    revocation::check_path(&self.config.revocation, &path, &evidence, now)?;
                    if self.config.revocation.is_deferred() {
                        events.push(Event::Unchecked(Box::new(revocation::Unchecked { path, sent: chain.clone(), staples })));
                    }
                    leaf
                } else {
                    // nothing is verified, so nothing is refused for an extension it does not know either (an ACME
                    // validator reads a TLS-ALPN-01 challenge certificate, whose acmeIdentifier extension is critical)
                    Certificate::parse(&chain[0])?
                });
                events.push(Event::PeerCertificates(chain));
                self.transcript.add(msg);
                self.stage = Stage::CertificateVerify;
            }
            (Stage::CertificateVerify, HS_CERTIFICATE_VERIFY) => {
                let keys = self.keys.as_ref().ok_or_else(|| Error::Tls("internal: no handshake keys".into()))?;
                let (scheme, signature) = parse_certificate_verify(body)?;
                let content = server_certificate_verify_content(&self.transcript.hash(keys.alg));
                let Some(leaf) = self.leaf.as_ref() else {
                    return Err(Error::Tls("unexpected_message: CertificateVerify without a Certificate".into()));
                };
                super::signature::verify_tls13_signature(leaf, scheme, &content, &signature)?;
                self.transcript.add(msg);
                self.stage = Stage::Finished;
            }
            (Stage::Finished, HS_FINISHED) => self.finish(msg, trailing, &mut events)?,
            _ => return Err(Error::Tls("unexpected_message: handshake message out of order".into())),
        }
        Ok(events)
    }

    /// The server chose TLS 1.2: the handshake goes on as one of those, with what it needs from this one.
    fn switch_to_tls12(&mut self, msg: &[u8], sh: &ServerHello) -> Result<Vec<Event>> {
        let x25519_private = match &self.secret {
            KeyShareSecret::X25519(p) => Some(p.clone()),
            KeyShareSecret::Ec(..) => None,
        };
        let start = Start12 {
            client_random: self.client_random,
            session_id: self.session_id.clone(),
            server_name: self.server_name.clone(),
            sent_sni: self.sent_sni,
            status_requested: self.status_requested,
            config: self.config.clone(),
            transcript: std::mem::take(&mut self.transcript.bytes),
            x25519_private,
        };
        let (hs12, steps) = Handshake12::start(start, msg, sh)?;
        Ok(vec![Event::Tls12(Box::new(hs12), steps)])
    }

    /// A HelloRetryRequest (RFC 8446 section 4.1.4): the server wants a key share for another
    /// group and/or a cookie echoed. Answers with a second ClientHello; anything else about the
    /// request that is not allowed ends the handshake.
    fn on_hello_retry_request(&mut self, msg: &[u8], hrr: ServerHello, trailing: bool, events: &mut Vec<Event>) -> Result<()> {
        if self.retry_suite.is_some() {
            return Err(Error::Tls("unexpected_message: second HelloRetryRequest".into()));
        }
        let Some((random, session_id)) = self.hello_inputs.clone() else {
            return Err(Error::Tls("internal: this connection cannot answer a HelloRetryRequest".into()));
        };
        if hrr.selected_version != Some(VERSION_TLS13) {
            return Err(Error::Tls("protocol_version: HelloRetryRequest did not select TLS 1.3".into()));
        }
        if hrr.legacy_version != 0x0303 || hrr.compression != 0 {
            return Err(Error::Tls("illegal_parameter: bad legacy fields in HelloRetryRequest".into()));
        }
        if hrr.session_id != self.session_id {
            return Err(Error::Tls("illegal_parameter: HelloRetryRequest did not echo the legacy session id".into()));
        }
        let suite = Suite::from_id(hrr.cipher_suite)
            .ok_or_else(|| Error::Tls("illegal_parameter: HelloRetryRequest chose a cipher suite we did not offer".into()))?;
        if trailing {
            return Err(Error::Tls("unexpected_message: data after HelloRetryRequest in the same record".into()));
        }
        // The retry must change something: a different key share group, or a cookie to return.
        if hrr.key_share.is_none() && hrr.cookie.is_none() {
            return Err(Error::Tls("illegal_parameter: HelloRetryRequest would not change the ClientHello".into()));
        }
        let mut new_share = None;
        if let Some((group, _)) = &hrr.key_share {
            // section 4.2.8: the group must be one we listed and must not be the one we already sent
            if !SUPPORTED_GROUPS.contains(group) || *group == self.sent_group {
                return Err(Error::Tls("illegal_parameter: HelloRetryRequest selected a group we cannot use or already sent".into()));
            }
            new_share = Some((*group, new_key_share(*group)?));
        }

        // The transcript restarts: ClientHello1 is replaced by a synthetic message_hash message
        // holding its hash (computed with the hash of the cipher suite the server chose), then the
        // HelloRetryRequest, then the second ClientHello.
        let digest = self.transcript.hash(suite.hash());
        self.transcript = Transcript::new(handshake_message(HS_MESSAGE_HASH, &digest));
        self.transcript.add(msg);

        let (group, public) = match &new_share {
            Some((group, (_, public))) => (*group, public.clone()),
            None => {
                // cookie only: the same key share again
                let public = match &self.secret {
                    KeyShareSecret::X25519(private) => x25519::public_key(private).to_vec(),
                    KeyShareSecret::Ec(curve, private) => ecdh::public_key(*curve, private)
                        .ok_or_else(|| Error::Tls("internal: stored key share is invalid".into()))?,
                };
                (self.sent_group, public)
            }
        };
        // the session goes into the second ClientHello too, with its binder over the new transcript, unless the suite the
        // server chose has another hash than the session's (RFC 8446 section 4.1.4): then it is not offered again
        if self.psk.as_ref().is_some_and(|s| s.suite.hash() != suite.hash()) {
            self.psk = None;
        }
        let offer = self.psk.as_ref().map(|s| PskOffer { identity: &s.ticket, obfuscated_age: s.obfuscated_age(), binder_len: s.suite.hash().output_len() });
        let mut client_hello = build_client_hello(&ClientHello {
            random: &random,
            session_id: &session_id,
            server_name: if self.sent_sni { Some(self.server_name.as_str()) } else { None },
            key_share_group: group,
            key_share_public: &public,
            alpn: &self.config.alpn_protocols,
            status_request: self.status_requested,
            cookie: hrr.cookie.as_deref(),
            quic_transport_parameters: self.quic.as_deref(),
            tls12: self.offers_tls12,
            psk: offer,
        });
        if let Some(session) = &self.psk {
            let binder = psk_binder(session, &self.transcript.bytes, &client_hello);
            set_psk_binder(&mut client_hello, &binder);
        }
        self.transcript.add(&client_hello);
        // The compatibility change_cipher_spec went out after the first ClientHello; one is enough.
        events.push(Event::Send(Epoch::Initial, client_hello));
        if let Some((group, (secret, _))) = new_share {
            self.secret = secret;
            self.sent_group = group;
        }
        self.retry_suite = Some(suite);
        Ok(())
    }

    /// The server's Finished: verify it, derive the application keys and make our flight.
    fn finish(&mut self, msg: &[u8], trailing: bool, events: &mut Vec<Event>) -> Result<()> {
        let body = &msg[4..];
        let keys = self.keys.as_ref().ok_or_else(|| Error::Tls("internal: no handshake keys".into()))?;
        let (alg, suite) = (keys.alg, keys.suite);
        let hash_len = alg.output_len();
        if body.len() != hash_len {
            return Err(Error::Tls("decode_error: the server Finished is not the length of the hash".into()));
        }
        let finished_key = Zeroizing::new(expand_label(alg, &keys.s_hs, "finished", &[], hash_len));
        let expected = hmac(alg, &finished_key, &self.transcript.hash(alg));
        if !ct_eq(&expected, body) {
            return Err(Error::Tls("decrypt_error: server Finished MAC is invalid".into()));
        }
        self.transcript.add(msg);
        if trailing {
            return Err(Error::Tls("unexpected_message: handshake data after server Finished".into()));
        }

        // application traffic secrets (transcript through the server Finished)
        let zeros = vec![0u8; hash_len];
        let empty_hash = alg.digest(&[]);
        let app_hash = self.transcript.hash(alg);
        let derived2 = Zeroizing::new(derive_secret(alg, &keys.handshake_secret, "derived", &empty_hash));
        let master_secret = Zeroizing::new(hkdf_extract(alg, &derived2, &zeros));
        let master = Prk::new(alg, &master_secret);
        let c_ap = Zeroizing::new(master.derive_secret("c ap traffic", &app_hash));
        let s_ap = Zeroizing::new(master.derive_secret("s ap traffic", &app_hash));

        // client flight, protected with the client handshake keys
        if let Some(request) = self.request.take() {
            // our certificate, if we have one whose key makes a signature the server takes; else an empty Certificate
            let ours = self.config.client_certificate.as_ref().and_then(|c| {
                let scheme = c.key().tls_schemes().into_iter().find(|s| request.signature_algorithms.contains(s))?;
                Some((c.clone(), scheme))
            });
            let mut b = vec![request.context.len() as u8];
            b.extend_from_slice(&request.context);
            let mut list = Vec::new();
            if let Some((c, _)) = &ours {
                for der in c.chain() {
                    list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
                    list.extend_from_slice(der);
                    list.extend_from_slice(&[0, 0]); // no extensions
                }
            }
            b.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
            b.extend_from_slice(&list);
            let m = handshake_message(HS_CERTIFICATE, &b);
            self.transcript.add(&m);
            events.push(Event::Send(Epoch::Handshake, m));
            if let Some((c, scheme)) = ours {
                let content = client_certificate_verify_content(&self.transcript.hash(alg));
                let signature = c.key().sign_tls(scheme, &content)?;
                let mut v = scheme.to_be_bytes().to_vec();
                v.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                v.extend_from_slice(&signature);
                let m = handshake_message(HS_CERTIFICATE_VERIFY, &v);
                self.transcript.add(&m);
                events.push(Event::Send(Epoch::Handshake, m));
            }
        }
        let client_finished_key = Zeroizing::new(expand_label(alg, &keys.c_hs, "finished", &[], hash_len));
        let verify_data = hmac(alg, &client_finished_key, &self.transcript.hash(alg));
        let client_finished = handshake_message(HS_FINISHED, &verify_data);
        // the resumption master secret covers the transcript through our Finished (RFC 8446 section 7.1)
        self.transcript.add(&client_finished);
        let res_master = Zeroizing::new(master.derive_secret("res master", &self.transcript.hash(alg)));
        events.push(Event::Send(Epoch::Handshake, client_finished));
        events.push(Event::ApplicationSecrets { suite, client: c_ap, server: s_ap });
        events.push(Event::ResumptionSecret { suite, secret: res_master, verified_at: self.verified_at });
        Ok(())
    }
}

/// `body` (an EncryptedExtensions body) without the extensions whose type is in `types`. Anything
/// that does not parse is returned as it is, for the real parser to refuse.
#[cfg(test)]
fn without_extensions(body: &[u8], types: &[u16]) -> Vec<u8> {
    let mut r = crate::util::Reader::new(body);
    let Some(list) = r.vec16() else { return body.to_vec() };
    let mut kept = Vec::new();
    let mut lr = crate::util::Reader::new(list);
    while !lr.is_empty() {
        let (Some(t), Some(d)) = (lr.u16(), lr.vec16()) else { return body.to_vec() };
        if !types.contains(&t) {
            kept.extend_from_slice(&t.to_be_bytes());
            kept.extend_from_slice(&(d.len() as u16).to_be_bytes());
            kept.extend_from_slice(d);
        }
    }
    let mut out = (kept.len() as u16).to_be_bytes().to_vec();
    out.extend(kept);
    out
}

/// The name sessions are kept under: the server name in lower case, without a trailing dot.
pub(crate) fn session_key(server_name: &str) -> String {
    server_name.strip_suffix('.').unwrap_or(server_name).to_ascii_lowercase()
}

/// The trust a session made under `config` rests on.
pub(crate) fn scope_of(config: &ClientConfig) -> Scope {
    Scope { trust: config.trust_store.clone(), verify: config.verify_server_certificate, revocation: config.revocation.mode }
}

/// The binder of `session` in `client_hello` (built with a binder of zeros), after the messages of `transcript` (empty for
/// a first ClientHello; the message_hash and HelloRetryRequest for a second): the HMAC, under the binder key's finished key,
/// of the transcript hash through the ClientHello without its binders (RFC 8446 section 4.2.11.2).
fn psk_binder(session: &Session, transcript: &[u8], client_hello: &[u8]) -> Vec<u8> {
    let alg = session.suite.hash();
    let hash_len = alg.output_len();
    let early_secret = Zeroizing::new(hkdf_extract(alg, &[], &session.psk));
    let binder_key = Zeroizing::new(derive_secret(alg, &early_secret, "res binder", &alg.digest(&[])));
    let finished_key = Zeroizing::new(expand_label(alg, &binder_key, "finished", &[], hash_len));
    let mut t = transcript.to_vec();
    t.extend_from_slice(truncated_client_hello(client_hello, hash_len));
    hmac(alg, &finished_key, &alg.digest(&t))
}

/// Refuses a server name that a TLS connection cannot be made to as it is: one that is neither an IP address literal (without
/// brackets) nor an ASCII host name of labels of letters, digits, hyphens and underscores, at most 63 bytes each and 253 in
/// all, with one trailing dot allowed. A name in Unicode is the common case of a name refused here: certificates and the
/// server name extension hold A-labels, which [`crate::idna::to_ascii`] makes.
pub(crate) fn check_server_name(name: &str) -> Result<()> {
    if name.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let body = name.strip_suffix('.').unwrap_or(name);
    let fits = !body.is_empty()
        && body.len() <= 253
        && body.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    if fits {
        return Ok(());
    }
    let hint = if name.is_ascii() { "" } else { "; an internationalized name must be given as A-labels, which pratique::idna::to_ascii makes" };
    Err(Error::Tls(format!("{name:?} is not a host name or IP address a TLS connection can be made to{hint}")))
}

