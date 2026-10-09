//! A scripted TLS 1.3 server, for the unit tests and the coverage-guided fuzzer.
//!
//! It is not a real server: it answers the client's ClientHello with whatever byte stream the test
//! builds, using the client's own key-schedule code to encrypt the handshake flight. That makes it
//! possible to send deliberately wrong ServerHello fields, unsolicited extensions, empty records,
//! flooded change_cipher_spec records or fuzzed handshake messages, none of which `openssl
//! s_server` will produce. It cannot complete a handshake (it has no signing key), so successful
//! connections are covered by the OpenSSL interop tests instead.
//!
//! Built for tests and, with `--cfg pratique_fuzzing`, for the fuzzing hooks in `fuzz_hooks`.
#![allow(dead_code)]

use super::messages::*;
use super::suite::*;
use super::*;
use crate::crypto::x25519;
use crate::util::Reader;
use std::cell::RefCell;
use std::rc::Rc;

pub(super) struct Hello {
    pub msg: Vec<u8>,
    pub session_id: Vec<u8>,
    pub x25519: [u8; 32],
}

/// Extracts what the fake needs from the first record of the client's output, once it is complete.
pub(super) fn parse_client_hello(inbound: &[u8]) -> Option<Hello> {
    if inbound.len() < 5 {
        return None;
    }
    let len = u16::from_be_bytes([inbound[3], inbound[4]]) as usize;
    if inbound.len() < 5 + len || len < 4 {
        return None;
    }
    let msg = inbound[5..5 + len].to_vec();
    let mut r = Reader::new(&msg[4..]);
    r.u16()?;
    r.take(32)?; // random
    let session_id = r.vec8()?.to_vec();
    r.vec16()?;
    r.vec8()?;
    let exts = r.vec16()?;
    let mut er = Reader::new(exts);
    while !er.is_empty() {
        let t = er.u16()?;
        let d = er.vec16()?;
        if t == EXT_KEY_SHARE {
            let mut lr = Reader::new(Reader::new(d).vec16()?);
            while !lr.is_empty() {
                let group = lr.u16()?;
                let key = lr.vec16()?;
                if group == GROUP_X25519 {
                    return Some(Hello { msg: msg.clone(), session_id, x25519: key.try_into().ok()? });
                }
            }
        }
    }
    None
}

pub(super) fn plain_record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![record_type, 3, 3];
    v.extend_from_slice(&(content.len() as u16).to_be_bytes());
    v.extend_from_slice(content);
    v
}

pub(super) fn ext(t: u16, data: &[u8]) -> Vec<u8> {
    let mut v = t.to_be_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

pub(super) fn block16(inner: &[u8]) -> Vec<u8> {
    let mut v = (inner.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(inner);
    v
}

/// How the fake builds its ServerHello; the default is a correct one.
#[derive(Clone)]
pub(super) struct ShOpts {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub cipher_suite: Option<u16>,
    pub compression: u8,
    pub supported_version: Option<u16>,
    pub echo_session_id: bool,
    /// Extensions added at the end of the ServerHello's.
    pub extra_extensions: Vec<(u16, Vec<u8>)>,
}

impl Default for ShOpts {
    fn default() -> Self {
        ShOpts {
            legacy_version: 0x0303,
            random: [0x42; 32],
            cipher_suite: None,
            compression: 0,
            supported_version: Some(0x0304),
            echo_session_id: true,
            extra_extensions: Vec::new(),
        }
    }
}

const SERVER_PRIVATE: [u8; 32] = [0x55; 32];

pub(super) struct Session {
    pub hello: Hello,
    pub suite: Suite,
    server_public: [u8; 32],
    shared: [u8; 32],
    /// The PSK the handshake's key schedule starts from (a resumption), instead of zeros.
    pub psk: Option<Vec<u8>>,
}

impl Session {
    pub fn new(hello: Hello, suite: Suite) -> Session {
        let shared = x25519::x25519(&SERVER_PRIVATE, &hello.x25519);
        Session { server_public: x25519::public_key(&SERVER_PRIVATE), shared, hello, suite, psk: None }
    }

    /// The ServerHello handshake message (header included).
    pub fn server_hello(&self, o: &ShOpts) -> Vec<u8> {
        let mut body = o.legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&o.random);
        if o.echo_session_id {
            body.push(self.hello.session_id.len() as u8);
            body.extend_from_slice(&self.hello.session_id);
        } else {
            body.extend_from_slice(&[4, 1, 2, 3, 4]);
        }
        body.extend_from_slice(&o.cipher_suite.unwrap_or(self.suite.id()).to_be_bytes());
        body.push(o.compression);
        let mut exts = Vec::new();
        if let Some(v) = o.supported_version {
            exts.extend(ext(EXT_SUPPORTED_VERSIONS, &v.to_be_bytes()));
        }
        let mut share = GROUP_X25519.to_be_bytes().to_vec();
        share.extend(block16(&self.server_public));
        exts.extend(ext(EXT_KEY_SHARE, &share));
        for (t, d) in &o.extra_extensions {
            exts.extend(ext(*t, d));
        }
        body.extend(block16(&exts));
        handshake_message(HS_SERVER_HELLO, &body)
    }

    /// The cipher the server encrypts its handshake flight with, given the ServerHello it sent.
    pub fn flight_cipher(&self, server_hello: &[u8]) -> RecordCipher {
        let alg = self.suite.hash();
        let zeros = vec![0u8; alg.output_len()];
        let empty = alg.digest(&[]);
        let early = hkdf_extract(alg, &[], self.psk.as_deref().unwrap_or(&zeros));
        let derived = derive_secret(alg, &early, "derived", &empty);
        let hs = hkdf_extract(alg, &derived, &self.shared);
        let mut transcript = self.hello.msg.clone();
        transcript.extend_from_slice(server_hello);
        let s_hs = derive_secret(alg, &hs, "s hs traffic", &alg.digest(&transcript));
        RecordCipher::new(self.suite, &s_hs)
    }

    /// The cipher the client encrypts with after the ServerHello (its handshake traffic keys).
    pub fn client_flight_cipher(&self, server_hello: &[u8]) -> RecordCipher {
        let alg = self.suite.hash();
        let zeros = vec![0u8; alg.output_len()];
        let empty = alg.digest(&[]);
        let early = hkdf_extract(alg, &[], self.psk.as_deref().unwrap_or(&zeros));
        let derived = derive_secret(alg, &early, "derived", &empty);
        let hs = hkdf_extract(alg, &derived, &self.shared);
        let mut transcript = self.hello.msg.clone();
        transcript.extend_from_slice(server_hello);
        let c_hs = derive_secret(alg, &hs, "c hs traffic", &alg.digest(&transcript));
        RecordCipher::new(self.suite, &c_hs)
    }

    /// ServerHello plus compatibility CCS, as a server would send them.
    pub fn hello_records(&self, o: &ShOpts) -> (Vec<u8>, Vec<u8>) {
        let sh = self.server_hello(o);
        let mut out = plain_record(RT_HANDSHAKE, &sh);
        out.extend(plain_record(RT_CHANGE_CIPHER_SPEC, &[1]));
        (out, sh)
    }
}

/// Seals each message as its own handshake record.
pub(super) fn sealed_flight(cipher: &mut RecordCipher, msgs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in msgs {
        cipher.encrypt_into(RT_HANDSHAKE, m, &mut out);
    }
    out
}

/// The transport the client talks to.
pub(super) struct FakeServer {
    inbound: Rc<RefCell<Vec<u8>>>,
    outbound: Vec<u8>,
    pos: usize,
    respond: Option<Box<dyn FnOnce(Hello) -> Vec<u8>>>,
}

impl FakeServer {
    /// Answers the ClientHello with the bytes `respond` builds. The second value shows everything
    /// the client has written.
    pub fn new(respond: impl FnOnce(Hello) -> Vec<u8> + 'static) -> (FakeServer, Rc<RefCell<Vec<u8>>>) {
        let inbound = Rc::new(RefCell::new(Vec::new()));
        (FakeServer { inbound: inbound.clone(), outbound: Vec::new(), pos: 0, respond: Some(Box::new(respond)) }, inbound)
    }

    /// A transport that just plays back `stream` (for connections that skip the handshake).
    pub fn playing(stream: Vec<u8>) -> FakeServer {
        FakeServer { inbound: Rc::new(RefCell::new(Vec::new())), outbound: stream, pos: 0, respond: None }
    }
}

impl Read for FakeServer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.outbound.len() {
            if let Some(f) = self.respond.take() {
                let hello = parse_client_hello(&self.inbound.borrow());
                match hello {
                    Some(h) => self.outbound = f(h),
                    None => self.respond = Some(f), // ClientHello not complete yet
                }
            }
        }
        let n = buf.len().min(self.outbound.len() - self.pos);
        buf[..n].copy_from_slice(&self.outbound[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for FakeServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inbound.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------- HelloRetryRequest

/// The server's handshake write cipher for a key exchange that gave `shared`, over `transcript`.
pub(super) fn handshake_write_cipher(suite: Suite, shared: &[u8], transcript: &[u8]) -> RecordCipher {
    let alg = suite.hash();
    let zeros = vec![0u8; alg.output_len()];
    let early = hkdf_extract(alg, &[], &zeros);
    let derived = derive_secret(alg, &early, "derived", &alg.digest(&[]));
    let hs = hkdf_extract(alg, &derived, shared);
    RecordCipher::new(suite, &derive_secret(alg, &hs, "s hs traffic", &alg.digest(transcript)))
}

/// A HelloRetryRequest handshake message. `group` is the group it asks for (none: a cookie only).
pub(super) fn retry_message(session_id: &[u8], suite: Suite, group: Option<u16>, cookie: Option<&[u8]>) -> Vec<u8> {
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut exts = ext(EXT_SUPPORTED_VERSIONS, &[3, 4]);
    if let Some(g) = group {
        exts.extend(ext(EXT_KEY_SHARE, &g.to_be_bytes()));
    }
    if let Some(c) = cookie {
        exts.extend(ext(EXT_COOKIE, &block16(c)));
    }
    body.extend(block16(&exts));
    handshake_message(HS_SERVER_HELLO, &body)
}

/// The legacy session id and the first key share (group, public value) of a ClientHello message.
pub(super) fn client_hello_session_and_share(msg: &[u8]) -> Option<(Vec<u8>, Option<(u16, Vec<u8>)>)> {
    let mut r = Reader::new(msg.get(4..)?);
    r.u16()?;
    r.take(32)?;
    let session_id = r.vec8()?.to_vec();
    r.vec16()?;
    r.vec8()?;
    let mut er = Reader::new(r.vec16()?);
    let mut share = None;
    while !er.is_empty() {
        let t = er.u16()?;
        let d = er.vec16()?;
        if t == EXT_KEY_SHARE {
            let mut lr = Reader::new(Reader::new(d).vec16()?);
            let group = lr.u16()?;
            share = Some((group, lr.vec16()?.to_vec()));
        }
    }
    Some((session_id, share))
}

/// A scripted server that answers the first ClientHello with a HelloRetryRequest and the second
/// with a ServerHello and `flight`, sealed under the keys the client must have derived. It is
/// the retry counterpart of `FakeServer` and, like it, cannot finish a handshake.
///
/// `kind`: 1 asks for P-256, 2 for P-384 and sends a cookie too, 3 sends a cookie only (the
/// x25519 share stays).
pub(super) struct RetryServer {
    suite: Suite,
    kind: u8,
    flight: Vec<u8>,
    piece: usize,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    pos: usize,
    stage: u8,
    ch1: Vec<u8>,
    hrr: Vec<u8>,
    session_id: Vec<u8>,
}

impl RetryServer {
    pub fn new(suite: Suite, kind: u8, flight: Vec<u8>, piece: usize) -> RetryServer {
        RetryServer { suite, kind, flight, piece: piece.max(1), inbound: Vec::new(), outbound: Vec::new(), pos: 0, stage: 0, ch1: Vec::new(), hrr: Vec::new(), session_id: Vec::new() }
    }

    fn on_client_hello(&mut self, msg: &[u8]) {
        use crate::crypto::ecdh;
        use crate::crypto::ecdsa::Curve;
        let Some((session_id, share)) = client_hello_session_and_share(msg) else { return };
        if self.stage == 0 {
            let (group, cookie): (Option<u16>, Option<&[u8]>) = match self.kind {
                1 => (Some(GROUP_SECP256R1), None),
                2 => (Some(GROUP_SECP384R1), Some(&[0xc0, 0x0c, 0x1e, 7, 7][..])),
                _ => (None, Some(&[0xc0, 0x0c, 0x1e][..])),
            };
            self.ch1 = msg.to_vec();
            self.session_id = session_id.clone();
            self.hrr = retry_message(&session_id, self.suite, group, cookie);
            self.outbound.extend(plain_record(RT_HANDSHAKE, &self.hrr));
            self.outbound.extend(plain_record(RT_CHANGE_CIPHER_SPEC, &[1]));
            self.stage = 1;
            return;
        }
        let Some((group, public)) = share else { return };
        let (server_public, shared): (Vec<u8>, Vec<u8>) = match group {
            GROUP_X25519 => {
                let Ok(client) = <[u8; 32]>::try_from(public.as_slice()) else { return };
                (x25519::public_key(&SERVER_PRIVATE).to_vec(), x25519::x25519(&SERVER_PRIVATE, &client).to_vec())
            }
            GROUP_SECP256R1 | GROUP_SECP384R1 => {
                let (curve, len) = if group == GROUP_SECP256R1 { (Curve::P256, 32) } else { (Curve::P384, 48) };
                let scalar = vec![0x2b; len];
                let Some(server_public) = ecdh::public_key(curve, &scalar) else { return };
                let Some(shared) = ecdh::shared_secret(curve, &scalar, &public) else { return };
                (server_public, shared.to_vec())
            }
            _ => return,
        };
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x42; 32]);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&self.suite.id().to_be_bytes());
        body.push(0);
        let mut exts = ext(EXT_SUPPORTED_VERSIONS, &[3, 4]);
        let mut share = group.to_be_bytes().to_vec();
        share.extend(block16(&server_public));
        exts.extend(ext(EXT_KEY_SHARE, &share));
        body.extend(block16(&exts));
        let sh = handshake_message(HS_SERVER_HELLO, &body);

        let mut transcript = handshake_message(HS_MESSAGE_HASH, &self.suite.hash().digest(&self.ch1));
        transcript.extend_from_slice(&self.hrr);
        transcript.extend_from_slice(msg);
        transcript.extend_from_slice(&sh);
        let mut cipher = handshake_write_cipher(self.suite, &shared, &transcript);
        self.outbound.extend(plain_record(RT_HANDSHAKE, &sh));
        let flight = std::mem::take(&mut self.flight);
        for chunk in flight.chunks(self.piece) {
            cipher.encrypt_into(RT_HANDSHAKE, chunk, &mut self.outbound);
        }
        self.stage = 2;
    }
}

impl Read for RetryServer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.outbound.len() - self.pos);
        buf[..n].copy_from_slice(&self.outbound[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for RetryServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inbound.extend_from_slice(buf);
        while self.inbound.len() >= 5 && self.stage < 2 {
            let len = u16::from_be_bytes([self.inbound[3], self.inbound[4]]) as usize;
            if self.inbound.len() < 5 + len {
                break;
            }
            let record: Vec<u8> = self.inbound.drain(..5 + len).collect();
            if record[0] == RT_HANDSHAKE {
                self.on_client_hello(&record[5..]);
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
