//! A TLS 1.3 server for the tests of the QUIC client, working on handshake messages (no records, no packets).
//!
//! It answers a ClientHello with the server's whole flight: the ServerHello, then EncryptedExtensions, Certificate,
//! CertificateVerify and Finished, with the secrets that go with them, so that a test can cut the flight into CRYPTO frames
//! as it likes, change it to be wrong in one way, and check what the client does. The certificate comes from `tls::pki`; the key
//! exchange is X25519. It does the key schedule with the same functions as the client does (so it is no check of those: aioquic
//! and quic-go are), and what it checks is the client's messages and the driver's handling of them.
#![allow(dead_code)]

use crate::crypto::x25519;
use crate::tls::messages::*;
use crate::tls::pki::TestPki;
use crate::tls::suite::*;
use crate::util::Reader;

const SERVER_PRIVATE: [u8; 32] = [0x55; 32];

/// A ClientHello as the server reads it.
pub struct Hello {
    pub message: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub suites: Vec<u16>,
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    pub fn parse(message: &[u8]) -> Hello {
        assert_eq!(message[0], HS_CLIENT_HELLO);
        let len = ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
        assert_eq!(len, message.len() - 4, "the ClientHello is one whole message");
        let mut r = Reader::new(&message[4..]);
        assert_eq!(r.u16(), Some(0x0303));
        let random: [u8; 32] = r.take(32).unwrap().try_into().unwrap();
        let session_id = r.vec8().unwrap().to_vec();
        let suites: Vec<u16> = r.vec16().unwrap().chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        assert_eq!(r.vec8().unwrap(), &[0], "only the null compression");
        let mut er = Reader::new(r.vec16().unwrap());
        assert!(r.is_empty());
        let mut extensions = Vec::new();
        while !er.is_empty() {
            let t = er.u16().unwrap();
            extensions.push((t, er.vec16().unwrap().to_vec()));
        }
        Hello { message: message.to_vec(), random, session_id, suites, extensions }
    }

    pub fn extension(&self, t: u16) -> Option<&[u8]> {
        self.extensions.iter().find(|(e, _)| *e == t).map(|(_, d)| d.as_slice())
    }

    /// The ALPN protocols offered.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        let Some(d) = self.extension(EXT_ALPN) else { return Vec::new() };
        let mut r = Reader::new(Reader::new(d).vec16().unwrap());
        let mut out = Vec::new();
        while !r.is_empty() {
            out.push(r.vec8().unwrap().to_vec());
        }
        out
    }

    /// The key shares offered: (group, public value).
    pub fn key_shares(&self) -> Vec<(u16, Vec<u8>)> {
        let mut r = Reader::new(Reader::new(self.extension(EXT_KEY_SHARE).unwrap()).vec16().unwrap());
        let mut out = Vec::new();
        while !r.is_empty() {
            let group = r.u16().unwrap();
            out.push((group, r.vec16().unwrap().to_vec()));
        }
        out
    }
}

/// What the server does that is not what it should (each a field a test can set).
#[derive(Clone)]
pub struct Options {
    pub suite: Suite,
    /// The ALPN protocol in EncryptedExtensions (None: none).
    pub alpn: Option<Vec<u8>>,
    /// The transport parameters in EncryptedExtensions (None: none).
    pub params: Option<Vec<u8>>,
    /// Extensions to add to EncryptedExtensions.
    pub extra_extensions: Vec<(u16, Vec<u8>)>,
    /// What the ServerHello says for the legacy session id (None: what the ClientHello had).
    pub session_id: Option<Vec<u8>>,
    /// A CertificateRequest after EncryptedExtensions.
    pub request_certificate: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            suite: Suite::Aes128GcmSha256,
            alpn: Some(b"h3".to_vec()),
            params: Some(vec![0x0f, 0x00]),
            extra_extensions: Vec::new(),
            session_id: None,
            request_certificate: false,
        }
    }
}

/// The server's flight and what goes with it.
pub struct Flight {
    pub server_hello: Vec<u8>,
    /// EncryptedExtensions, (CertificateRequest,) Certificate, CertificateVerify, Finished: whole messages.
    pub handshake: Vec<Vec<u8>>,
    pub suite: Suite,
    pub client_handshake_secret: Vec<u8>,
    pub server_handshake_secret: Vec<u8>,
    pub client_application_secret: Vec<u8>,
    pub server_application_secret: Vec<u8>,
    /// The client's Finished, the message that it has to send.
    pub client_finished: Vec<u8>,
}

fn ext(out: &mut Vec<u8>, t: u16, data: &[u8]) {
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn block16(inner: &[u8]) -> Vec<u8> {
    let mut v = (inner.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(inner);
    v
}

pub struct TestServer {
    pub pki: TestPki,
}

impl TestServer {
    pub fn new(name: &str) -> TestServer {
        TestServer { pki: TestPki::new(&[name]).expect("a test PKI") }
    }

    /// A ServerHello-less HelloRetryRequest that asks for a key share for `group`.
    pub fn hello_retry_request(&self, hello: &Hello, suite: Suite, group: u16) -> Vec<u8> {
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        body.push(hello.session_id.len() as u8);
        body.extend_from_slice(&hello.session_id);
        body.extend_from_slice(&suite.id().to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        ext(&mut exts, EXT_SUPPORTED_VERSIONS, &[3, 4]);
        ext(&mut exts, EXT_KEY_SHARE, &group.to_be_bytes());
        body.extend(block16(&exts));
        handshake_message(HS_SERVER_HELLO, &body)
    }

    /// The flight for `hello` (the client's first and only ClientHello, which has an X25519 share).
    pub fn flight(&self, hello: &Hello, o: &Options) -> Flight {
        let suite = o.suite;
        let alg = suite.hash();
        let hash_len = alg.output_len();
        let (_, client_public) = hello.key_shares().into_iter().find(|(g, _)| *g == GROUP_X25519).expect("an X25519 share");
        let shared = x25519::x25519(&SERVER_PRIVATE, &client_public.as_slice().try_into().unwrap());

        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x42; 32]);
        let session_id = o.session_id.clone().unwrap_or_else(|| hello.session_id.clone());
        body.push(session_id.len() as u8);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&suite.id().to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        ext(&mut exts, EXT_SUPPORTED_VERSIONS, &[3, 4]);
        let mut share = GROUP_X25519.to_be_bytes().to_vec();
        share.extend(block16(&x25519::public_key(&SERVER_PRIVATE)));
        ext(&mut exts, EXT_KEY_SHARE, &share);
        body.extend(block16(&exts));
        let server_hello = handshake_message(HS_SERVER_HELLO, &body);

        let mut transcript = hello.message.clone();
        transcript.extend_from_slice(&server_hello);
        let zeros = vec![0u8; hash_len];
        let empty_hash = alg.digest(&[]);
        let early = hkdf_extract(alg, &[], &zeros);
        let derived = derive_secret(alg, &early, "derived", &empty_hash);
        let handshake_secret = hkdf_extract(alg, &derived, &shared);
        let hello_hash = alg.digest(&transcript);
        let c_hs = derive_secret(alg, &handshake_secret, "c hs traffic", &hello_hash);
        let s_hs = derive_secret(alg, &handshake_secret, "s hs traffic", &hello_hash);

        let mut handshake = Vec::new();
        let add = |message: Vec<u8>, transcript: &mut Vec<u8>, handshake: &mut Vec<Vec<u8>>| {
            transcript.extend_from_slice(&message);
            handshake.push(message);
        };
        // EncryptedExtensions
        let mut exts = Vec::new();
        if let Some(alpn) = &o.alpn {
            let mut list = vec![alpn.len() as u8];
            list.extend_from_slice(alpn);
            ext(&mut exts, EXT_ALPN, &block16(&list));
        }
        if let Some(params) = &o.params {
            ext(&mut exts, EXT_QUIC_TRANSPORT_PARAMETERS, params);
        }
        for (t, d) in &o.extra_extensions {
            ext(&mut exts, *t, d);
        }
        add(handshake_message(HS_ENCRYPTED_EXTENSIONS, &block16(&exts)), &mut transcript, &mut handshake);
        if o.request_certificate {
            let mut sigs = Vec::new();
            ext(&mut sigs, EXT_SIGNATURE_ALGORITHMS, &block16(&0x0807u16.to_be_bytes()));
            let mut body = vec![0u8]; // certificate_request_context
            body.extend(block16(&sigs));
            add(handshake_message(HS_CERTIFICATE_REQUEST, &body), &mut transcript, &mut handshake);
        }
        // Certificate
        let mut list = Vec::new();
        for der in &self.pki.chain {
            list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
            list.extend_from_slice(der);
            list.extend_from_slice(&[0, 0]); // no extensions
        }
        let mut cert = vec![0u8];
        cert.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        cert.extend(list);
        add(handshake_message(HS_CERTIFICATE, &cert), &mut transcript, &mut handshake);
        // CertificateVerify
        let content = server_certificate_verify_content(&alg.digest(&transcript));
        let signature = self.pki.server_key.sign(&content);
        let mut verify = 0x0807u16.to_be_bytes().to_vec();
        verify.extend(block16(&signature));
        add(handshake_message(HS_CERTIFICATE_VERIFY, &verify), &mut transcript, &mut handshake);
        // Finished
        let finished_key = expand_label(alg, &s_hs, "finished", &[], hash_len);
        let verify_data = hmac(alg, &finished_key, &alg.digest(&transcript));
        add(handshake_message(HS_FINISHED, &verify_data), &mut transcript, &mut handshake);

        let app_hash = alg.digest(&transcript);
        let derived2 = derive_secret(alg, &handshake_secret, "derived", &empty_hash);
        let master = hkdf_extract(alg, &derived2, &zeros);
        let c_ap = derive_secret(alg, &master, "c ap traffic", &app_hash);
        let s_ap = derive_secret(alg, &master, "s ap traffic", &app_hash);
        let client_finished_key = expand_label(alg, &c_hs, "finished", &[], hash_len);
        // the client's Finished covers a certificate it sent, if one was asked for: an empty one
        let mut client_transcript = transcript.clone();
        if o.request_certificate {
            let empty_certificate = handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0]);
            client_transcript.extend_from_slice(&empty_certificate);
        }
        let client_finished = handshake_message(HS_FINISHED, &hmac(alg, &client_finished_key, &alg.digest(&client_transcript)));
        Flight {
            server_hello,
            handshake,
            suite,
            client_handshake_secret: c_hs,
            server_handshake_secret: s_hs,
            client_application_secret: c_ap,
            server_application_secret: s_ap,
            client_finished,
        }
    }
}
