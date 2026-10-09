//! TLS 1.2 (RFC 5246), the client side, for the servers that cannot speak TLS 1.3, and no further than that takes.
//!
//! The ClientHello offers TLS 1.3 first and TLS 1.2 after it (when the configuration allows 1.2, which it does by default; see
//! [`ClientConfig::min_version`](super::ClientConfig::min_version)), so a server that can do 1.3 does 1.3, and only one that cannot
//! gets here. What is offered and accepted here is the part of TLS 1.2 that has no known weakness of its own:
//!
//! * key exchange by ephemeral elliptic-curve Diffie-Hellman only (X25519, P-256, P-384), signed with the server's certificate key
//!   (ECDSA, Ed25519 or RSA, PKCS#1 v1.5 or PSS, with SHA-256 or more; SHA-1 is never offered and is refused if a server uses it);
//! * AEAD record protection only: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 (RFC 5288, RFC 7905); no CBC, no RC4, no
//!   static RSA key exchange, no compression;
//! * the extended master secret (RFC 7627) is **required**: a server that does not do it is refused, because without it a
//!   man in the middle can make two connections share a master secret (the triple handshake attack);
//! * the downgrade protection of RFC 8446 section 4.1.3: a server that could have spoken TLS 1.3 says so in the last eight bytes of
//!   its random when it speaks 1.2, and such a ServerHello is refused (someone took 1.3 out of the ClientHello on the way);
//! * no renegotiation (the `renegotiation_info` extension says so, RFC 5746, and a HelloRequest is answered with a
//!   `no_renegotiation` warning), no session resumption, no session tickets;
//! * the certificate chain, the host name and revocation are checked exactly as for TLS 1.3 (an OCSP staple comes in the
//!   CertificateStatus message here).
//!
//! It is a state machine over whole handshake messages like the TLS 1.3 one, and the connection
//! ([`ClientConnection`](super::ClientConnection)) carries its records. The record protection is [`RecordCipher12`].

use super::handshake::MAX_HANDSHAKE_MESSAGE;
use super::messages::*;
use super::suite::{hmac, Aead, Suite, AEAD_TAG_LEN, MAX_PLAINTEXT};
use super::ClientConfig;
use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::sha2::HashAlg;
use crate::crypto::{ecdh, ed25519, x25519};
use crate::error::{Error, Result};
use crate::revocation;
use crate::sys;
use crate::util::{ct_eq, Reader};
use crate::x509::{Certificate, PublicKey};
use crate::zeroize::{Zeroize, Zeroizing};

pub const VERSION_TLS12: u16 = 0x0303;

pub const HS_HELLO_REQUEST: u8 = 0;
pub const HS_SERVER_KEY_EXCHANGE: u8 = 12;
pub const HS_SERVER_HELLO_DONE: u8 = 14;
pub const HS_CLIENT_KEY_EXCHANGE: u8 = 16;
pub const HS_CERTIFICATE_STATUS: u8 = 22;

pub const EXT_EC_POINT_FORMATS: u16 = 11;
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub const EXT_SESSION_TICKET: u16 = 35;
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The TLS 1.2 cipher suites offered: ECDHE and an AEAD, nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite12 {
    EcdheEcdsaAes128Gcm,
    EcdheRsaAes128Gcm,
    EcdheEcdsaAes256Gcm,
    EcdheRsaAes256Gcm,
    EcdheEcdsaChacha20Poly1305,
    EcdheRsaChacha20Poly1305,
}

impl Suite12 {
    pub const ALL: [Suite12; 6] = [
        Suite12::EcdheEcdsaAes128Gcm,
        Suite12::EcdheRsaAes128Gcm,
        Suite12::EcdheEcdsaAes256Gcm,
        Suite12::EcdheRsaAes256Gcm,
        Suite12::EcdheEcdsaChacha20Poly1305,
        Suite12::EcdheRsaChacha20Poly1305,
    ];

    /// The order of the ClientHello, after the TLS 1.3 suites: the same rule as for 1.3 (AES-GCM first where the CPU has AES
    /// instructions in use, ChaCha20-Poly1305 first where it has not), and ECDSA before RSA for each.
    pub fn preference_order() -> [Suite12; 6] {
        use Suite12::*;
        if crate::crypto::aes::hardware_accelerated() {
            [EcdheEcdsaAes128Gcm, EcdheRsaAes128Gcm, EcdheEcdsaAes256Gcm, EcdheRsaAes256Gcm, EcdheEcdsaChacha20Poly1305, EcdheRsaChacha20Poly1305]
        } else {
            [EcdheEcdsaChacha20Poly1305, EcdheRsaChacha20Poly1305, EcdheEcdsaAes128Gcm, EcdheRsaAes128Gcm, EcdheEcdsaAes256Gcm, EcdheRsaAes256Gcm]
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Suite12::EcdheEcdsaAes128Gcm => 0xc02b,
            Suite12::EcdheRsaAes128Gcm => 0xc02f,
            Suite12::EcdheEcdsaAes256Gcm => 0xc02c,
            Suite12::EcdheRsaAes256Gcm => 0xc030,
            Suite12::EcdheEcdsaChacha20Poly1305 => 0xcca9,
            Suite12::EcdheRsaChacha20Poly1305 => 0xcca8,
        }
    }

    pub fn from_id(id: u16) -> Option<Suite12> {
        Suite12::ALL.into_iter().find(|s| s.id() == id)
    }

    /// The TLS 1.3 suite with the same AEAD and hash (the record protection and the PRF's hash are the same functions).
    pub fn aead_suite(self) -> Suite {
        match self {
            Suite12::EcdheEcdsaAes128Gcm | Suite12::EcdheRsaAes128Gcm => Suite::Aes128GcmSha256,
            Suite12::EcdheEcdsaAes256Gcm | Suite12::EcdheRsaAes256Gcm => Suite::Aes256GcmSha384,
            Suite12::EcdheEcdsaChacha20Poly1305 | Suite12::EcdheRsaChacha20Poly1305 => Suite::Chacha20Poly1305Sha256,
        }
    }

    /// The hash of the PRF and of the handshake transcript.
    pub fn hash(self) -> HashAlg {
        self.aead_suite().hash()
    }

    fn is_chacha(self) -> bool {
        matches!(self, Suite12::EcdheEcdsaChacha20Poly1305 | Suite12::EcdheRsaChacha20Poly1305)
    }

    /// Whether the server's key is to be an RSA key (the `ECDHE_RSA` suites) rather than an ECDSA or EdDSA one.
    pub fn signs_with_rsa(self) -> bool {
        matches!(self, Suite12::EcdheRsaAes128Gcm | Suite12::EcdheRsaAes256Gcm | Suite12::EcdheRsaChacha20Poly1305)
    }

    /// The implicit part of the nonce from the key block: 4 bytes for AES-GCM (the salt), 12 for ChaCha20-Poly1305.
    fn fixed_iv_len(self) -> usize {
        if self.is_chacha() {
            12
        } else {
            4
        }
    }

    /// The bytes of nonce sent in each record: 8 for AES-GCM, none for ChaCha20-Poly1305.
    fn explicit_nonce_len(self) -> usize {
        if self.is_chacha() {
            0
        } else {
            8
        }
    }

    /// How many records one key may protect: TLS 1.2 has no KeyUpdate, so a connection that reaches this stops (see
    /// [`Suite::records_per_key`]).
    pub fn records_per_key(self) -> u64 {
        self.aead_suite().records_per_key()
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite12::EcdheEcdsaAes128Gcm => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            Suite12::EcdheRsaAes128Gcm => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Suite12::EcdheEcdsaAes256Gcm => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            Suite12::EcdheRsaAes256Gcm => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            Suite12::EcdheEcdsaChacha20Poly1305 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            Suite12::EcdheRsaChacha20Poly1305 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        }
    }
}

/// The PRF of TLS 1.2 (RFC 5246 section 5): `P_hash(secret, label || seed)`, `len` bytes.
pub fn prf(alg: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    let mut out = Zeroizing::new(Vec::with_capacity(len + alg.output_len()));
    // A(1) = HMAC(secret, label_seed); A(i) = HMAC(secret, A(i-1))
    let mut a = Zeroizing::new(hmac(alg, secret, &label_seed));
    while out.len() < len {
        let mut input = Zeroizing::new(Vec::with_capacity(a.len() + label_seed.len()));
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&Zeroizing::new(hmac(alg, secret, &input)));
        a = Zeroizing::new(hmac(alg, secret, &a));
    }
    out.truncate(len);
    out
}

// ------------------------------------------------------------------------------------------------ the records

/// The protection of one direction of a TLS 1.2 connection: an AEAD with the nonce and additional data of RFC 5288 (AES-GCM: a
/// 4-byte salt and 8 bytes sent in each record, here the sequence number) and RFC 7905 (ChaCha20-Poly1305: a 12-byte IV and the
/// sequence number, nothing sent). Unlike TLS 1.3 the record type is not hidden and there is no padding.
pub struct RecordCipher12 {
    suite: Suite12,
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl Drop for RecordCipher12 {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl RecordCipher12 {
    pub fn new(suite: Suite12, key: &[u8], fixed_iv: &[u8]) -> RecordCipher12 {
        let mut iv = [0u8; 12];
        iv[..fixed_iv.len()].copy_from_slice(fixed_iv);
        RecordCipher12 { suite, aead: Aead::new(suite.aead_suite(), key), iv, seq: 0 }
    }

    pub fn suite(&self) -> Suite12 {
        self.suite
    }

    /// How many records this key has protected or opened so far (the sequence number).
    pub fn records(&self) -> u64 {
        self.seq
    }

    fn nonce(&self, explicit: &[u8; 8]) -> [u8; 12] {
        let mut n = self.iv;
        if self.suite.is_chacha() {
            for i in 0..8 {
                n[4 + i] ^= explicit[i];
            }
        } else {
            n[4..].copy_from_slice(explicit);
        }
        n
    }

    fn aad(&self, record_type: u8, len: usize) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[..8].copy_from_slice(&self.seq.to_be_bytes());
        a[8] = record_type;
        a[9] = 0x03;
        a[10] = 0x03;
        a[11..].copy_from_slice(&(len as u16).to_be_bytes());
        a
    }

    /// Protects `content` as a record of `record_type` and appends the whole wire record to `out`.
    pub fn encrypt_into(&mut self, record_type: u8, content: &[u8], out: &mut Vec<u8>) {
        debug_assert!(content.len() <= MAX_PLAINTEXT);
        let explicit_len = self.suite.explicit_nonce_len();
        let body_len = explicit_len + content.len() + AEAD_TAG_LEN;
        let start = out.len();
        out.reserve(5 + body_len);
        out.extend_from_slice(&[record_type, 0x03, 0x03, (body_len >> 8) as u8, body_len as u8]);
        // the sequence number is the explicit nonce: unique for as long as the key lives
        let explicit = self.seq.to_be_bytes();
        out.extend_from_slice(&explicit[..explicit_len]);
        out.extend_from_slice(content);
        out.resize(start + 5 + body_len, 0);
        let nonce = self.nonce(&explicit);
        let aad = self.aad(record_type, content.len());
        self.aead.seal_in_place(&nonce, &aad, &mut out[start + 5 + explicit_len..]);
        self.seq += 1;
    }

    /// Opens a record in place: `payload` is its body as received. Returns (record type, where the content starts in `payload`,
    /// its length). On failure nothing is changed and the sequence number does not advance.
    pub fn decrypt_in_place(&mut self, header: &[u8; 5], payload: &mut [u8]) -> Result<(u8, usize, usize)> {
        let explicit_len = self.suite.explicit_nonce_len();
        if payload.len() < explicit_len + AEAD_TAG_LEN {
            return Err(Error::Tls("bad_record_mac: record too short to be protected".into()));
        }
        let mut explicit = [0u8; 8];
        if explicit_len == 8 {
            explicit.copy_from_slice(&payload[..8]);
        } else {
            explicit = self.seq.to_be_bytes();
        }
        let len = payload.len() - explicit_len - AEAD_TAG_LEN;
        if len > MAX_PLAINTEXT {
            return Err(Error::Tls("record_overflow: record too long".into()));
        }
        let nonce = self.nonce(&explicit);
        let aad = self.aad(header[0], len);
        let n = self
            .aead
            .open_in_place(&nonce, &aad, &mut payload[explicit_len..])
            .ok_or_else(|| Error::Tls("bad_record_mac: record failed authentication".into()))?;
        self.seq += 1;
        Ok((header[0], explicit_len, n))
    }
}

// ------------------------------------------------------------------------------------------------ the handshake

/// What the connection is to do about a step of the TLS 1.2 handshake, in order.
pub(crate) enum Step12 {
    /// Send this handshake message in the clear (before our change_cipher_spec).
    SendPlain(Vec<u8>),
    /// Send change_cipher_spec; everything we send after it is under this cipher.
    ChangeCipherSpec(RecordCipher12),
    /// Send this handshake message under our new keys (our Finished).
    SendProtected(Vec<u8>),
    Alpn(Option<Vec<u8>>),
    PeerCertificates(Vec<Vec<u8>>),
    /// The chain is verified, and the sources of revocation evidence are left for later (see the TLS 1.3 `Event`).
    Unchecked(Box<revocation::Unchecked>),
    /// The server's Finished is verified: the handshake is over.
    Established,
}

/// What the TLS 1.3 handshake hands over when the server turns out to speak 1.2.
pub(crate) struct Start12 {
    pub(crate) client_random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) server_name: String,
    pub(crate) sent_sni: bool,
    pub(crate) status_requested: bool,
    pub(crate) config: ClientConfig,
    /// The ClientHello as sent.
    pub(crate) transcript: Vec<u8>,
    /// The private key of the X25519 key share in the ClientHello, used again if the server picks X25519.
    pub(crate) x25519_private: Option<Zeroizing<[u8; 32]>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Certificate,
    StatusOrKeyExchange,
    KeyExchange,
    RequestOrDone,
    Done,
    ChangeCipherSpec,
    Finished,
    Over,
}

pub(crate) struct Handshake12 {
    stage: Stage,
    suite: Suite12,
    start: Start12,
    server_random: [u8; 32],
    status_acked: bool,
    chain: Vec<Vec<u8>>,
    staple: Option<Vec<u8>>,
    leaf: Option<Certificate>,
    /// The server's ephemeral key: (group, public value), from ServerKeyExchange.
    server_share: Option<(u16, Vec<u8>)>,
    certificate_requested: bool,
    master_secret: Option<Zeroizing<Vec<u8>>>,
    /// The server's read cipher, installed when its change_cipher_spec arrives.
    pending_read: Option<RecordCipher12>,
}

fn bad(msg: &str) -> Error {
    Error::Tls(format!("decode_error: {msg}"))
}

impl Handshake12 {
    /// Takes over after a ServerHello that chose TLS 1.2 (`msg` is the whole message, `sh` what it says). Checks what it says that
    /// only matters for TLS 1.2, and returns the handshake that goes on.
    pub(crate) fn start(start: Start12, msg: &[u8], sh: &ServerHello) -> Result<(Handshake12, Vec<Step12>)> {
        // (the caller checked the version, the downgrade sentinel and that a TLS 1.2 ServerHello was allowed)
        if sh.compression != 0 {
            return Err(Error::Tls("illegal_parameter: the server chose compression".into()));
        }
        if sh.key_share.is_some() || sh.cookie.is_some() {
            return Err(Error::Tls("illegal_parameter: TLS 1.3 extensions in a TLS 1.2 ServerHello".into()));
        }
        // there is no session to resume: a server that claims to resume one (by echoing our random session id) is lying
        if !sh.session_id.is_empty() && sh.session_id == start.session_id {
            return Err(Error::Tls("illegal_parameter: the server resumed a session that was never offered".into()));
        }
        let suite = Suite12::from_id(sh.cipher_suite).ok_or_else(|| Error::Tls("illegal_parameter: server chose a cipher suite we did not offer".into()))?;
        let mut ems = false;
        let mut status_acked = false;
        let mut alpn: Option<Vec<u8>> = None;
        for (t, d) in &sh.other_extensions {
            match *t {
                EXT_EXTENDED_MASTER_SECRET if d.is_empty() => ems = true,
                EXT_RENEGOTIATION_INFO => {
                    // an empty renegotiated_connection: this is the first handshake, and the server knows about RFC 5746
                    if d.as_slice() != [0] {
                        return Err(Error::Tls("handshake_failure: renegotiation_info is not empty".into()));
                    }
                }
                EXT_EC_POINT_FORMATS => {
                    let mut r = Reader::new(d);
                    let formats = r.vec8().ok_or_else(|| bad("ec_point_formats"))?;
                    if !r.is_empty() || !formats.contains(&0) {
                        return Err(Error::Tls("illegal_parameter: the server cannot take uncompressed points".into()));
                    }
                }
                EXT_SERVER_NAME if d.is_empty() && start.sent_sni => {}
                EXT_STATUS_REQUEST if d.is_empty() && start.status_requested => status_acked = true,
                EXT_ALPN if !start.config.alpn_protocols.is_empty() => {
                    let mut r = Reader::new(d);
                    let list = r.vec16().ok_or_else(|| bad("ALPN"))?;
                    let mut lr = Reader::new(list);
                    let p = lr.vec8().ok_or_else(|| bad("ALPN protocol"))?;
                    if !r.is_empty() || !lr.is_empty() || p.is_empty() {
                        return Err(bad("ALPN must name exactly one protocol"));
                    }
                    if !start.config.alpn_protocols.iter().any(|o| o.as_slice() == p) {
                        return Err(Error::Tls("illegal_parameter: server selected an ALPN protocol we did not offer".into()));
                    }
                    alpn = Some(p.to_vec());
                }
                t => return Err(Error::Tls(format!("unsupported_extension: unexpected extension {t} in a TLS 1.2 ServerHello"))),
            }
        }
        if !ems {
            return Err(Error::Tls(
                "handshake_failure: the server does not do the extended master secret (RFC 7627), which TLS 1.2 here requires".into(),
            ));
        }
        let mut hs = Handshake12 {
            stage: Stage::Certificate,
            suite,
            start,
            server_random: sh.random,
            status_acked,
            chain: Vec::new(),
            staple: None,
            leaf: None,
            server_share: None,
            certificate_requested: false,
            master_secret: None,
            pending_read: None,
        };
        hs.start.transcript.extend_from_slice(msg);
        Ok((hs, vec![Step12::Alpn(alpn)]))
    }

    pub(crate) fn suite(&self) -> Suite12 {
        self.suite
    }

    /// Processes one whole handshake message from the server (with its header). `trailing`: more handshake bytes came with it.
    pub(crate) fn on_message(&mut self, msg: &[u8], trailing: bool) -> Result<Vec<Step12>> {
        if msg.len() < 4 || msg.len() > MAX_HANDSHAKE_MESSAGE + 4 {
            return Err(bad("handshake message"));
        }
        let body = &msg[4..];
        let mut steps = Vec::new();
        match (self.stage, msg[0]) {
            (Stage::Certificate, HS_CERTIFICATE) => {
                self.chain = parse_certificate12(body)?;
                self.start.transcript.extend_from_slice(msg);
                self.stage = Stage::StatusOrKeyExchange;
            }
            (Stage::StatusOrKeyExchange, HS_CERTIFICATE_STATUS) if self.status_acked => {
                let mut r = Reader::new(body);
                let (Some(1), Some(response), true) = (r.u8(), r.vec24(), r.is_empty()) else {
                    return Err(bad("CertificateStatus"));
                };
                if response.is_empty() {
                    return Err(bad("empty OCSP response in CertificateStatus"));
                }
                self.staple = Some(response.to_vec());
                self.start.transcript.extend_from_slice(msg);
                self.stage = Stage::KeyExchange;
            }
            (Stage::StatusOrKeyExchange | Stage::KeyExchange, HS_SERVER_KEY_EXCHANGE) => {
                self.check_chain(&mut steps)?;
                self.server_key_exchange(body)?;
                self.start.transcript.extend_from_slice(msg);
                self.stage = Stage::RequestOrDone;
            }
            (Stage::RequestOrDone, HS_CERTIFICATE_REQUEST) => {
                parse_certificate_request12(body)?;
                self.certificate_requested = true;
                self.start.transcript.extend_from_slice(msg);
                self.stage = Stage::Done;
            }
            (Stage::RequestOrDone | Stage::Done, HS_SERVER_HELLO_DONE) => {
                if !body.is_empty() {
                    return Err(bad("ServerHelloDone with a body"));
                }
                if trailing {
                    return Err(Error::Tls("unexpected_message: handshake data after ServerHelloDone".into()));
                }
                self.start.transcript.extend_from_slice(msg);
                self.client_flight(&mut steps)?;
                self.stage = Stage::ChangeCipherSpec;
            }
            (Stage::Finished, HS_FINISHED) => {
                let master = self.master_secret.as_ref().ok_or_else(|| Error::Tls("internal: no master secret".into()))?;
                let alg = self.suite.hash();
                let expected = prf(alg, master, b"server finished", &alg.digest(&self.start.transcript), 12);
                if !ct_eq(&expected, body) {
                    return Err(Error::Tls("decrypt_error: server Finished is wrong".into()));
                }
                if trailing {
                    return Err(Error::Tls("unexpected_message: handshake data after the server's Finished".into()));
                }
                self.start.transcript.extend_from_slice(msg);
                self.stage = Stage::Over;
                steps.push(Step12::Established);
            }
            _ => return Err(Error::Tls("unexpected_message: handshake message out of order".into())),
        }
        Ok(steps)
    }

    /// The server's change_cipher_spec: the cipher to read the rest with. Only after our own flight, and never twice.
    pub(crate) fn on_change_cipher_spec(&mut self) -> Result<RecordCipher12> {
        if self.stage != Stage::ChangeCipherSpec {
            return Err(Error::Tls("unexpected_message: change_cipher_spec out of order".into()));
        }
        self.stage = Stage::Finished;
        self.pending_read.take().ok_or_else(|| Error::Tls("internal: no read keys".into()))
    }

    /// The chain the server sent, verified for the host and checked for revocation, as for TLS 1.3.
    fn check_chain(&mut self, steps: &mut Vec<Step12>) -> Result<()> {
        let config = &self.start.config;
        let leaf = if config.verify_server_certificate {
            let now = config.time_override.unwrap_or_else(sys::now_unix);
            let (leaf, path) = config.trust_store.verify_server_path(&self.chain, &self.start.server_name, now)?;
            let mut staples: Vec<Option<Vec<u8>>> = vec![None; self.chain.len()];
            staples[0] = self.staple.clone();
            let evidence = revocation::ChainEvidence { sent: &self.chain, staples: &staples };
            revocation::check_path(&config.revocation, &path, &evidence, now)?;
            if config.revocation.is_deferred() {
                steps.push(Step12::Unchecked(Box::new(revocation::Unchecked { path, sent: self.chain.clone(), staples })));
            }
            leaf
        } else {
            Certificate::from_der(&self.chain[0])?
        };
        // the suite says what kind of key signs the key exchange
        let fits = match &leaf.public_key {
            PublicKey::Rsa(_) => self.suite.signs_with_rsa(),
            PublicKey::Ec { .. } | PublicKey::Ed25519(_) => !self.suite.signs_with_rsa(),
            PublicKey::Unsupported => false,
        };
        if !fits {
            return Err(Error::Tls("illegal_parameter: the server's certificate key does not fit the cipher suite it chose".into()));
        }
        self.leaf = Some(leaf);
        steps.push(Step12::PeerCertificates(std::mem::take(&mut self.chain)));
        Ok(())
    }

    /// ServerKeyExchange for ECDHE (RFC 8422 section 5.4): the curve, the server's ephemeral key, and its signature over both
    /// randoms and these, made with the certificate's key.
    fn server_key_exchange(&mut self, body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        let curve_type = r.u8().ok_or_else(|| bad("ServerKeyExchange"))?;
        if curve_type != 3 {
            return Err(Error::Tls("illegal_parameter: ServerKeyExchange is not for a named curve".into()));
        }
        let group = r.u16().ok_or_else(|| bad("ServerKeyExchange curve"))?;
        let public = r.vec8().ok_or_else(|| bad("ServerKeyExchange key"))?;
        let params_len = 1 + 2 + 1 + public.len();
        let scheme = r.u16().ok_or_else(|| bad("ServerKeyExchange signature algorithm"))?;
        let signature = r.vec16().ok_or_else(|| bad("ServerKeyExchange signature"))?;
        if !r.is_empty() {
            return Err(bad("trailing data in ServerKeyExchange"));
        }
        if !SUPPORTED_GROUPS.contains(&group) {
            return Err(Error::Tls("illegal_parameter: the server chose a curve we did not offer".into()));
        }
        let mut signed = Vec::with_capacity(64 + params_len);
        signed.extend_from_slice(&self.start.client_random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&body[..params_len]);
        let leaf = self.leaf.as_ref().ok_or_else(|| Error::Tls("internal: no certificate".into()))?;
        verify_tls12_signature(leaf, self.suite, scheme, &signed, signature)?;
        self.server_share = Some((group, public.to_vec()));
        Ok(())
    }

    /// Our flight after ServerHelloDone: an empty Certificate if one was asked for, ClientKeyExchange, change_cipher_spec and
    /// Finished; and the keys.
    fn client_flight(&mut self, steps: &mut Vec<Step12>) -> Result<()> {
        let (group, server_public) = self.server_share.take().ok_or_else(|| Error::Tls("unexpected_message: no ServerKeyExchange".into()))?;
        if self.certificate_requested {
            // no client certificate: an empty list
            let m = handshake_message(HS_CERTIFICATE, &[0, 0, 0]);
            self.start.transcript.extend_from_slice(&m);
            steps.push(Step12::SendPlain(m));
        }
        let (premaster, our_public): (Zeroizing<Vec<u8>>, Vec<u8>) = if group == GROUP_X25519 {
            let private = match self.start.x25519_private.take() {
                Some(p) => p,
                None => Zeroizing::new(crate::crypto::rand::bytes()?),
            };
            let peer: [u8; 32] = <[u8; 32]>::try_from(server_public.as_slice()).map_err(|_| Error::Tls("illegal_parameter: bad X25519 key".into()))?;
            let shared = Zeroizing::new(x25519::x25519(&private, &peer));
            if shared.iter().fold(0u8, |acc, &b| acc | b) == 0 {
                return Err(Error::Tls("illegal_parameter: X25519 produced an all-zero shared secret".into()));
            }
            (Zeroizing::new(shared.to_vec()), x25519::public_key(&private).to_vec())
        } else {
            let curve = if group == GROUP_SECP256R1 { Curve::P256 } else { Curve::P384 };
            let (secret, public) = ecdh::generate(curve)?;
            let shared = ecdh::shared_secret(curve, &secret, &server_public)
                .ok_or_else(|| Error::Tls("illegal_parameter: the server's key is not a valid point on the curve".into()))?;
            (shared, public)
        };
        let mut cke = vec![our_public.len() as u8];
        cke.extend_from_slice(&our_public);
        let m = handshake_message(HS_CLIENT_KEY_EXCHANGE, &cke);
        self.start.transcript.extend_from_slice(&m);
        steps.push(Step12::SendPlain(m));

        // the extended master secret (RFC 7627 section 4): over the hash of the handshake so far, ClientKeyExchange included
        let alg = self.suite.hash();
        let session_hash = alg.digest(&self.start.transcript);
        let master = prf(alg, &premaster, b"extended master secret", &session_hash, 48);
        // the key block (RFC 5246 section 6.3): no MAC keys for an AEAD
        let (key_len, iv_len) = (self.suite.aead_suite().key_len(), self.suite.fixed_iv_len());
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.start.client_random);
        let block = prf(alg, &master, b"key expansion", &seed, 2 * key_len + 2 * iv_len);
        let (client_key, rest) = block.split_at(key_len);
        let (server_key, rest) = rest.split_at(key_len);
        let (client_iv, server_iv) = rest.split_at(iv_len);
        let write = RecordCipher12::new(self.suite, client_key, client_iv);
        self.pending_read = Some(RecordCipher12::new(self.suite, server_key, server_iv));
        steps.push(Step12::ChangeCipherSpec(write));
        let verify_data = prf(alg, &master, b"client finished", &alg.digest(&self.start.transcript), 12);
        let finished = handshake_message(HS_FINISHED, &verify_data);
        self.start.transcript.extend_from_slice(&finished);
        steps.push(Step12::SendProtected(finished));
        self.master_secret = Some(master);
        Ok(())
    }
}

/// A TLS 1.2 Certificate message: the chain, leaf first, with no context and no extensions per entry.
fn parse_certificate12(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let list = r.vec24().ok_or_else(|| bad("Certificate list"))?;
    if !r.is_empty() {
        return Err(bad("trailing data in Certificate"));
    }
    let mut lr = Reader::new(list);
    let mut certs = Vec::new();
    while !lr.is_empty() {
        let der = lr.vec24().ok_or_else(|| bad("certificate entry"))?;
        if der.is_empty() {
            return Err(bad("empty certificate entry"));
        }
        certs.push(der.to_vec());
        if certs.len() > 16 {
            return Err(Error::Tls("illegal_parameter: certificate chain too long".into()));
        }
    }
    if certs.is_empty() {
        return Err(Error::Tls("decode_error: server sent an empty certificate list".into()));
    }
    Ok(certs)
}

/// A TLS 1.2 CertificateRequest, read only to see that it is well formed (we have no certificate to send).
fn parse_certificate_request12(body: &[u8]) -> Result<()> {
    let mut r = Reader::new(body);
    let types = r.vec8().ok_or_else(|| bad("CertificateRequest types"))?;
    let algs = r.vec16().ok_or_else(|| bad("CertificateRequest algorithms"))?;
    let _authorities = r.vec16().ok_or_else(|| bad("CertificateRequest authorities"))?;
    if types.is_empty() || algs.is_empty() || algs.len() % 2 != 0 || !r.is_empty() {
        return Err(bad("CertificateRequest"));
    }
    Ok(())
}

/// Verifies the signature of a TLS 1.2 ServerKeyExchange: only the schemes we offered (none with SHA-1), and only ones that go with
/// the key and with the suite (an `ECDHE_RSA` suite is signed with RSA, an `ECDHE_ECDSA` one with ECDSA or EdDSA). Unlike TLS 1.3,
/// RSA may sign with PKCS#1 v1.5 here, and an ECDSA key of either curve may use either hash.
pub fn verify_tls12_signature(cert: &Certificate, suite: Suite12, scheme: u16, signed: &[u8], signature: &[u8]) -> Result<()> {
    if !SIGNATURE_SCHEMES.contains(&scheme) {
        return Err(Error::Tls(format!("illegal_parameter: the server signed with a scheme we did not offer ({scheme:#06x})")));
    }
    let ok = match (scheme, &cert.public_key, suite.signs_with_rsa()) {
        (0x0403, PublicKey::Ec { curve, point }, false) => ecdsa::verify(*curve, point, HashAlg::Sha256, signed, signature),
        (0x0503, PublicKey::Ec { curve, point }, false) => ecdsa::verify(*curve, point, HashAlg::Sha384, signed, signature),
        (0x0603, PublicKey::Ec { curve, point }, false) => ecdsa::verify(*curve, point, HashAlg::Sha512, signed, signature),
        (0x0807, PublicKey::Ed25519(k), false) => ed25519::verify(k, signed, signature),
        (0x0401, PublicKey::Rsa(k), true) => k.verify_pkcs1(HashAlg::Sha256, signed, signature),
        (0x0501, PublicKey::Rsa(k), true) => k.verify_pkcs1(HashAlg::Sha384, signed, signature),
        (0x0601, PublicKey::Rsa(k), true) => k.verify_pkcs1(HashAlg::Sha512, signed, signature),
        (0x0804, PublicKey::Rsa(k), true) => k.verify_pss(HashAlg::Sha256, signed, signature),
        (0x0805, PublicKey::Rsa(k), true) => k.verify_pss(HashAlg::Sha384, signed, signature),
        (0x0806, PublicKey::Rsa(k), true) => k.verify_pss(HashAlg::Sha512, signed, signature),
        _ => return Err(Error::Tls(format!("illegal_parameter: signature scheme {scheme:#06x} does not fit the key or the cipher suite"))),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Tls("decrypt_error: the ServerKeyExchange signature is invalid".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::{Event, Handshake};
    use crate::tls::TlsVersion;
    use crate::util::{hex, unhex};
    use crate::x509::TrustStore;

    #[test]
    fn the_prf_gives_the_published_vector_and_a_second_implementations_output() {
        // SHA-256: the vector that was circulated on the TLS working group's list (and Python's hmac agrees); SHA-384 from Python
        let (secret, seed) = (unhex("9bbe436ba940f017b17652849a71db35"), unhex("a0ba9f936cda311827a6f796ffd5198c"));
        assert_eq!(
            hex(&prf(HashAlg::Sha256, &secret, b"test label", &seed, 100)),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        );
        assert_eq!(
            hex(&prf(HashAlg::Sha384, &secret, b"test label", &seed, 148)),
            "dd88775cd827187b67a3f7652b5c13f715791cc46e0274a6d3fb16651103defc544cd8afb68369a219bb918b8b21ddb1764af0a70339e6dec085e574f655851ba692513203536bdfc3675e53768210f0a2389dd324311a440c7c30ef44b391d914c3b0c7c80f1cb5e134cf4253d859fa8a46e978360d095dd2fba0c18a1f4d7b4cf9f24667b5cb0adc5ab65df3a0dc627c9b73cc"
        );
        // a shorter output is a prefix of a longer one
        assert_eq!(&prf(HashAlg::Sha256, &secret, b"test label", &seed, 13)[..], &prf(HashAlg::Sha256, &secret, b"test label", &seed, 100)[..13]);
    }

    /// Records sealed by Python's `cryptography` with the nonces and additional data of RFC 5288 and RFC 7905 (sequence number 5,
    /// application data, "hello tls 1.2 record").
    #[test]
    fn records_are_what_another_implementation_makes_and_opens() {
        let content = b"hello tls 1.2 record";
        let (key16, key32): (Vec<u8>, Vec<u8>) = ((0..16).collect(), (0..32).collect());
        for (suite, key, iv, wire) in [
            (Suite12::EcdheRsaAes128Gcm, &key16, unhex("a1a2a3a4"), "00000000000000052772af0a26c20746e46996702aa80a35b7a87548e5c2a6841b0dc4b82fe8e0e7319c7371"),
            (Suite12::EcdheEcdsaAes256Gcm, &key32, unhex("a1a2a3a4"), "00000000000000059de00b0bc342afaefad31786b13f98f32721427991e8a14722b4e73ea1b080e3526af851"),
            (Suite12::EcdheRsaChacha20Poly1305, &key32, unhex("c0c1c2c3c4c5c6c7c8c9cacb"), "92838e6c72c43959148e75dbf83bb8edf69411725bb39ad7670170f41600e52f506bba4b"),
        ] {
            let mut sealer = RecordCipher12::new(suite, key, &iv);
            sealer.seq = 5;
            let mut out = Vec::new();
            sealer.encrypt_into(23, content, &mut out);
            assert_eq!(hex(&out[5..]), wire, "{}", suite.name());
            assert_eq!(out[..3], [23, 3, 3]);
            assert_eq!(u16::from_be_bytes([out[3], out[4]]) as usize, out.len() - 5);
            // and opened, by a fresh cipher at the same sequence number
            let mut opener = RecordCipher12::new(suite, key, &iv);
            opener.seq = 5;
            let header: [u8; 5] = out[..5].try_into().unwrap();
            let mut payload = out[5..].to_vec();
            let (t, offset, n) = opener.decrypt_in_place(&header, &mut payload).unwrap();
            assert_eq!((t, &payload[offset..offset + n]), (23, &content[..]));
            // not at another sequence number, not as another type, not with a bit changed
            for (seq, rtype, flip) in [(6u64, 23u8, None), (5, 21, None), (5, 23, Some(payload.len() - 1))] {
                let mut opener = RecordCipher12::new(suite, key, &iv);
                opener.seq = seq;
                let mut header = header;
                header[0] = rtype;
                let mut p = out[5..].to_vec();
                if let Some(i) = flip {
                    p[i] ^= 1;
                }
                assert!(opener.decrypt_in_place(&header, &mut p).is_err(), "{} {seq} {rtype} {flip:?}", suite.name());
                assert_eq!(opener.seq, seq, "a failure moves the sequence number on");
            }
        }
    }

    fn server_hello(random: [u8; 32], session_id: &[u8], suite: u16, exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&random);
        b.push(session_id.len() as u8);
        b.extend_from_slice(session_id);
        b.extend_from_slice(&suite.to_be_bytes());
        b.push(0);
        let mut e = Vec::new();
        for (t, d) in exts {
            e.extend_from_slice(&t.to_be_bytes());
            e.extend_from_slice(&(d.len() as u16).to_be_bytes());
            e.extend_from_slice(d);
        }
        b.extend_from_slice(&(e.len() as u16).to_be_bytes());
        b.extend_from_slice(&e);
        handshake_message(HS_SERVER_HELLO, &b)
    }

    fn good_extensions() -> Vec<(u16, Vec<u8>)> {
        vec![(EXT_EXTENDED_MASTER_SECRET, vec![]), (EXT_RENEGOTIATION_INFO, vec![0]), (EXT_EC_POINT_FORMATS, vec![1, 0])]
    }

    /// What the TLS 1.3 handshake makes of a TLS 1.2 ServerHello: `Ok(true)` if it goes on as TLS 1.2, or the error.
    fn answer(min: TlsVersion, hello: &[u8]) -> std::result::Result<bool, String> {
        let config = ClientConfig::new(TrustStore::empty()).with_min_version(min);
        let (mut hs, _) = Handshake::start("example.com", &config, None, Zeroizing::new([7; 32]), &[1; 32], &[2; 32]);
        match hs.on_message(hello, false) {
            Ok(events) => Ok(events.iter().any(|e| matches!(e, Event::Tls12(..)))),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn a_tls12_server_hello_is_taken_only_as_the_rules_say() {
        let suite = Suite12::EcdheRsaAes128Gcm.id();
        let random = [9u8; 32];
        assert_eq!(answer(TlsVersion::Tls12, &server_hello(random, &[5; 32], suite, &good_extensions())), Ok(true));
        assert_eq!(answer(TlsVersion::Tls12, &server_hello(random, &[], suite, &good_extensions())), Ok(true));
        // the extensions a server may answer with, when they were asked for
        let mut more = good_extensions();
        more.push((EXT_SERVER_NAME, vec![]));
        more.push((EXT_STATUS_REQUEST, vec![]));
        more.push((EXT_ALPN, vec![0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']));
        assert_eq!(answer(TlsVersion::Tls12, &server_hello(random, &[], suite, &more)), Ok(true));
        let refused = |min, hello: Vec<u8>, why: &str| {
            let r = answer(min, &hello);
            assert!(matches!(&r, Err(e) if e.contains(why)), "wanted {why:?}, got {r:?}");
        };
        // a client that requires TLS 1.3
        refused(TlsVersion::Tls13, server_hello(random, &[], suite, &good_extensions()), "requires TLS 1.3");
        // the downgrade sentinel, for 1.2 and for 1.1 and below
        for last in [1u8, 0] {
            let mut r = random;
            r[24..31].copy_from_slice(b"DOWNGRD");
            r[31] = last;
            refused(TlsVersion::Tls12, server_hello(r, &[], suite, &good_extensions()), "downgrade");
        }
        // no extended master secret, or one with a body
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &good_extensions()[1..]), "extended master secret");
        let mut ems_body = good_extensions();
        ems_body[0].1 = vec![0];
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &ems_body), "unsupported_extension");
        // renegotiation_info that is not the empty one of a first handshake
        let mut reneg = good_extensions();
        reneg[1].1 = vec![1, 0];
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &reneg), "renegotiation_info");
        // no uncompressed points
        let mut points = good_extensions();
        points[2].1 = vec![1, 1];
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &points), "uncompressed");
        // a session we never had, a suite we never offered (CBC, RSA key exchange, a TLS 1.3 suite), compression
        refused(TlsVersion::Tls12, server_hello(random, &[2; 32], suite, &good_extensions()), "resumed");
        for bad in [0xc013u16, 0x009c, 0x1301, 0x002f] {
            refused(TlsVersion::Tls12, server_hello(random, &[], bad, &good_extensions()), "did not offer");
        }
        let mut compressed = server_hello(random, &[], suite, &good_extensions());
        compressed[4 + 2 + 32 + 1 + 2] = 1;
        refused(TlsVersion::Tls12, compressed, "compression");
        // TLS 1.3's extensions, a session ticket we never asked for, and anything unknown
        for (t, d) in [(EXT_KEY_SHARE, vec![0, 0x1d, 0, 1, 9]), (EXT_SESSION_TICKET, vec![]), (0x1234, vec![])] {
            let mut e = good_extensions();
            e.push((t, d));
            assert!(answer(TlsVersion::Tls12, &server_hello(random, &[], suite, &e)).is_err(), "{t:#x}");
        }
        // an ALPN protocol that was not offered
        let mut alpn = good_extensions();
        alpn.push((EXT_ALPN, vec![0, 3, 2, b'h', b'2']));
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &alpn), "did not offer");
        // supported_versions that names 1.2 is not how a server chooses 1.2
        let mut sv = good_extensions();
        sv.push((EXT_SUPPORTED_VERSIONS, vec![3, 3]));
        refused(TlsVersion::Tls12, server_hello(random, &[], suite, &sv), "not offered");
    }

    #[test]
    fn the_server_key_exchange_signature_must_be_one_we_offered_and_fit_the_key_and_suite() {
        let rsa = Certificate::from_der(&crate::pem::parse(include_str!("../../tests/data/leaf_rsa.pem")).remove(0).data).unwrap();
        let ed = Certificate::from_der(&crate::pem::parse(include_str!("../../tests/data/ed_leaf.pem")).remove(0).data).unwrap();
        let sig = [0u8; 256];
        // SHA-1 (RSA and ECDSA), DSA, unknown: never offered
        for scheme in [0x0201u16, 0x0203, 0x0202, 0x0101, 0x0700] {
            let e = verify_tls12_signature(&rsa, Suite12::EcdheRsaAes128Gcm, scheme, b"x", &sig).unwrap_err();
            assert!(e.to_string().contains("did not offer"), "{scheme:#x}: {e}");
        }
        // an RSA key under an ECDSA suite, an ECDSA scheme for an RSA key, an Ed25519 key under an RSA suite
        assert!(verify_tls12_signature(&rsa, Suite12::EcdheEcdsaAes128Gcm, 0x0401, b"x", &sig).unwrap_err().to_string().contains("does not fit"));
        assert!(verify_tls12_signature(&rsa, Suite12::EcdheRsaAes128Gcm, 0x0403, b"x", &sig).unwrap_err().to_string().contains("does not fit"));
        assert!(verify_tls12_signature(&ed, Suite12::EcdheRsaAes128Gcm, 0x0807, b"x", &sig[..64]).unwrap_err().to_string().contains("does not fit"));
        // a scheme that fits but a signature that does not verify
        assert!(verify_tls12_signature(&rsa, Suite12::EcdheRsaAes128Gcm, 0x0401, b"x", &sig).unwrap_err().to_string().contains("invalid"));
    }

    #[test]
    fn the_client_hello_offers_tls12_only_when_it_may() {
        for (min, offered) in [(TlsVersion::Tls12, true), (TlsVersion::Tls13, false)] {
            let config = ClientConfig::new(TrustStore::empty()).with_min_version(min);
            let (_, hello) = Handshake::start("example.com", &config, None, Zeroizing::new([7; 32]), &[1; 32], &[2; 32]);
            let has = |needle: &[u8]| hello.windows(needle.len()).any(|w| w == needle);
            assert_eq!(has(&[0x00, 0x17, 0x00, 0x00]), offered, "extended_master_secret, {min:?}");
            assert_eq!(has(&[0xff, 0x01, 0x00, 0x01, 0x00]), offered, "renegotiation_info, {min:?}");
            assert_eq!(has(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]), offered, "supported_versions with 1.2, {min:?}");
            assert_eq!(has(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]), !offered, "supported_versions with 1.3 alone, {min:?}");
            // the cipher suites: TLS 1.3's, then (if 1.2 is offered) the six ECDHE AEAD ones, and nothing else
            let mut r = Reader::new(&hello[4..]);
            let (_, _, _, suites) = (r.u16(), r.take(32), r.vec8(), r.vec16().unwrap());
            let suites: Vec<u16> = suites.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            let mut want: Vec<u16> = Suite::ALL.iter().map(|s| s.id()).collect();
            if offered {
                want.extend(Suite12::ALL.iter().map(|s| s.id()));
            }
            let (mut got_sorted, mut want_sorted) = (suites.clone(), want);
            got_sorted.sort();
            want_sorted.sort();
            assert_eq!(got_sorted, want_sorted, "{min:?}");
        }
        // and no signature scheme with SHA-1, whatever is offered
        assert!(!SIGNATURE_SCHEMES.iter().any(|s| s >> 8 == 2), "{SIGNATURE_SCHEMES:04x?}");
        // and QUIC offers 1.3 alone, whatever the configuration says
        let config = ClientConfig::new(TrustStore::empty());
        let (_, hello) = Handshake::start("example.com", &config, Some(&[1, 2, 3]), Zeroizing::new([7; 32]), &[1; 32], &[]);
        assert!(!hello.windows(2).any(|w| w == Suite12::EcdheRsaAes128Gcm.id().to_be_bytes()));
    }
}
