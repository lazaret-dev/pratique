//! The fuzzer's entry point for the TLS server (B-110): a client whose every message comes from the input, with a
//! small client inside that does the cryptography, so that the input reaches past the ClientHello. Compiled only with
//! `--cfg pratique_fuzzing` and the `server` feature; not part of the API.
//!
//! The input:
//!
//! ```text
//! flags (1) | len (2) | ClientHello body | len (2) | client handshake messages | records: (type (1), len (2), data)*
//! ```
//!
//! `flags`: bit 0 requires client certificates (else they are optional); bit 1 makes the server's store strict about
//! names; bit 2 has the harness send its own client Certificate and a correct CertificateVerify after the messages of
//! the input; bit 3 has it send a correct client Finished after them; bits 4 and 5 cut what is sent into pieces of 1, 7
//! or 300 bytes (or none). The ClientHello is the input's; when its X25519 key share is the harness's own (the public
//! key of `CLIENT_PRIVATE`), the harness can read the server's flight and protect what follows with the right keys:
//! the input's handshake messages under the client handshake keys, then the records under the client application keys
//! once the handshake is done.
//!
//! The server's own randomness (its random, its key share, ticket nonces) is not fixed, so an input repeats the same
//! path but not the same bytes. What must hold: nothing panics, and a connection that says it is established has a suite
//! and, when certificates were required, a client chain.

use super::certs::{CertStore, CertifiedKey};
use super::messages::*;
use super::pki::{issue, CertSpec, KeyPair};
use super::server::{ClientAuth, ServerConfig, ServerConnection};
use super::suite::*;
use crate::crypto::sha2::HashAlg;
use crate::crypto::x25519;
use crate::x509::TrustStore;
use std::sync::{Arc, OnceLock};

/// The harness client's X25519 key.
pub const CLIENT_PRIVATE: [u8; 32] = [0x41; 32];

struct Fixture {
    configs: [Arc<ServerConfig>; 4],
    client_cert: CertifiedKey,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let root_key = KeyPair::from_seed([0x51; 32]);
        let root = issue(&CertSpec::ca("fuzz root"), &root_key, None);
        let leaf_key = KeyPair::from_seed([0x52; 32]);
        let leaf = issue(&CertSpec::server(&["server.test", "*.wild.test"]), &leaf_key, Some(("fuzz root", &root_key)));
        let ca_key = KeyPair::from_seed([0x53; 32]);
        let ca = issue(&CertSpec::ca("fuzz client CA"), &ca_key, None);
        let client_key = KeyPair::from_seed([0x54; 32]);
        let spec = CertSpec { common_name: "fuzz client".into(), server_auth: false, client_auth: true, ..CertSpec::default() };
        let client = issue(&spec, &client_key, Some(("fuzz client CA", &ca_key)));
        let mut roots = TrustStore::empty();
        roots.add_der(&ca).expect("the client CA parses");
        let roots = Arc::new(roots);
        let _ = root;
        let make = |required: bool, strict: bool| {
            let store = CertStore::single(CertifiedKey::new(vec![leaf.clone()], leaf_key.signing_key().clone()).expect("the leaf is its key's"));
            let store = if strict { store.strict() } else { store };
            let auth = if required { ClientAuth::Required(roots.clone()) } else { ClientAuth::Optional(roots.clone()) };
            Arc::new(ServerConfig::with_certificates(store).with_client_auth(auth).with_alpn(&["h2", "http/1.1"]))
        };
        Fixture {
            configs: [make(false, false), make(true, false), make(false, true), make(true, true)],
            client_cert: CertifiedKey::new(vec![client], client_key.signing_key().clone()).expect("the client certificate is its key's"),
        }
    })
}

fn record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut r = vec![record_type, 3, 3];
    r.extend_from_slice(&(content.len() as u16).to_be_bytes());
    r.extend_from_slice(content);
    r
}

/// Gives the server `bytes` in pieces and processes; false once it has failed.
fn feed(conn: &mut ServerConnection, bytes: &[u8], piece: usize) -> bool {
    for part in bytes.chunks(piece.max(1)) {
        conn.receive(part);
        if conn.process().is_err() {
            return false;
        }
        let mut sink = [0u8; 512];
        while conn.read_plaintext(&mut sink) > 0 {}
    }
    true
}

fn take_output(conn: &mut ServerConnection) -> Vec<u8> {
    let out = conn.output().to_vec();
    conn.consume_output(out.len());
    out
}

/// The server's flight read as the harness client: (suite, client handshake secret, transcript through the server's
/// Finished, handshake secret), if the server answered the hello with a ServerHello for our key share.
fn read_flight(hello_msg: &[u8], out: &[u8]) -> Option<(Suite, Vec<u8>, Vec<u8>, Vec<u8>)> {
    if out.len() < 5 || out[0] != RT_HANDSHAKE {
        return None;
    }
    let sh_len = u16::from_be_bytes([out[3], out[4]]) as usize;
    let server_hello = out.get(5..5 + sh_len)?.to_vec();
    let sh = parse_server_hello(server_hello.get(4..)?).ok()?;
    let suite = Suite::from_id(sh.cipher_suite)?;
    let (group, server_public) = sh.key_share?;
    if group != GROUP_X25519 || sh.random == HELLO_RETRY_REQUEST_RANDOM {
        return None;
    }
    let alg = suite.hash();
    let shared = x25519::x25519(&CLIENT_PRIVATE, server_public.as_slice().try_into().ok()?);
    let early = hkdf_extract(alg, &[], &vec![0u8; alg.output_len()]);
    let derived = derive_secret(alg, &early, "derived", &alg.digest(&[]));
    let handshake_secret = hkdf_extract(alg, &derived, &shared);
    let mut transcript = hello_msg.to_vec();
    transcript.extend_from_slice(&server_hello);
    let s_hs = derive_secret(alg, &handshake_secret, "s hs traffic", &alg.digest(&transcript));
    let c_hs = derive_secret(alg, &handshake_secret, "c hs traffic", &alg.digest(&transcript));
    let mut cipher = RecordCipher::new(suite, &s_hs);
    let mut rest = &out[5 + sh_len..];
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let header: [u8; 5] = rest[..5].try_into().ok()?;
        let body = rest.get(5..5 + len)?;
        if header[0] == RT_APPLICATION_DATA {
            let mut buf = body.to_vec();
            let (t, n) = cipher.decrypt_in_place(&header, &mut buf).ok()?;
            if t == RT_HANDSHAKE {
                transcript.extend_from_slice(&buf[..n]);
            }
        }
        rest = &rest[5 + len..];
    }
    Some((suite, c_hs, transcript, handshake_secret))
}

pub fn server_exchange(data: &[u8]) {
    let Some((&flags, rest)) = data.split_first() else { return };
    let piece = [usize::MAX, 1, 7, 300][((flags >> 4) & 3) as usize];
    let take = |r: &mut &[u8]| -> Option<Vec<u8>> {
        if r.len() < 2 {
            return None;
        }
        let len = (u16::from_be_bytes([r[0], r[1]]) as usize).min(r.len() - 2);
        let v = r[2..2 + len].to_vec();
        *r = &r[2 + len..];
        Some(v)
    };
    let mut rest = rest;
    let Some(hello_body) = take(&mut rest) else { return };
    let messages = take(&mut rest).unwrap_or_default();
    let f = fixture();
    let config = f.configs[(flags & 3) as usize].clone();
    let required = flags & 1 == 1;
    let mut conn = ServerConnection::new(config);

    let hello = handshake_message(HS_CLIENT_HELLO, &hello_body);
    if !feed(&mut conn, &record(RT_HANDSHAKE, &hello), piece) {
        return;
    }
    let out = take_output(&mut conn);
    let Some((suite, c_hs, mut transcript, handshake_secret)) = read_flight(&hello, &out) else { return };
    let server_transcript = transcript.clone();
    let alg: HashAlg = suite.hash();
    let mut hs_cipher = RecordCipher::new(suite, &c_hs);
    let mut client_flight = Vec::new();
    if !messages.is_empty() {
        transcript.extend_from_slice(&messages);
        hs_cipher.encrypt_into(RT_HANDSHAKE, &messages, &mut client_flight);
    }
    if flags & 4 != 0 {
        let mut list = Vec::new();
        for der in f.client_cert.chain() {
            list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
            list.extend_from_slice(der);
            list.extend_from_slice(&[0, 0]);
        }
        let mut body = vec![0u8];
        body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&list);
        let cert_msg = handshake_message(HS_CERTIFICATE, &body);
        transcript.extend_from_slice(&cert_msg);
        let content = client_certificate_verify_content(&alg.digest(&transcript));
        let scheme = f.client_cert.key().tls_schemes()[0];
        let Ok(signature) = f.client_cert.key().sign_tls(scheme, &content) else { return };
        let mut v = scheme.to_be_bytes().to_vec();
        v.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        v.extend_from_slice(&signature);
        let verify_msg = handshake_message(HS_CERTIFICATE_VERIFY, &v);
        transcript.extend_from_slice(&verify_msg);
        hs_cipher.encrypt_into(RT_HANDSHAKE, &cert_msg, &mut client_flight);
        hs_cipher.encrypt_into(RT_HANDSHAKE, &verify_msg, &mut client_flight);
    }
    if flags & 8 != 0 {
        let key = expand_label(alg, &c_hs, "finished", &[], alg.output_len());
        let finished = handshake_message(HS_FINISHED, &hmac(alg, &key, &alg.digest(&transcript)));
        hs_cipher.encrypt_into(RT_HANDSHAKE, &finished, &mut client_flight);
    }
    if !feed(&mut conn, &client_flight, piece) {
        return;
    }
    if !conn.is_established() {
        return;
    }
    assert!(conn.cipher_suite().is_some(), "established without a suite");
    assert!(!required || !conn.peer_certificates().is_empty() || conn.is_resumed(), "established without the required client certificate");
    // application records under the client application keys (from the transcript through the server's Finished)
    let zeros = vec![0u8; alg.output_len()];
    let derived = derive_secret(alg, &handshake_secret, "derived", &alg.digest(&[]));
    let master = hkdf_extract(alg, &derived, &zeros);
    let app_hash = alg.digest(&server_transcript);
    let mut app = RecordCipher::new(suite, &derive_secret(alg, &master, "c ap traffic", &app_hash));
    let mut records = Vec::new();
    let mut r = rest;
    while r.len() >= 3 {
        let t = r[0];
        let len = (u16::from_be_bytes([r[1], r[2]]) as usize).min(r.len() - 3).min(MAX_PLAINTEXT);
        app.encrypt_into(t, &r[3..3 + len], &mut records);
        if t == RT_HANDSHAKE && r[3..3 + len].first() == Some(&HS_KEY_UPDATE) {
            app = app.next_generation();
        }
        r = &r[3 + len..];
    }
    let _ = feed(&mut conn, &records, piece);
    let _ = conn.write_plaintext(b"pratique fuzz: the server writes");
}

/// Seeds: a ClientHello with the harness's key share, then the paths the flags open (no certificate, the harness's
/// certificate, a Finished, application data and a KeyUpdate after it).
pub fn server_exchange_seeds() -> Vec<Vec<u8>> {
    let public = x25519::public_key(&CLIENT_PRIVATE);
    let hello = build_client_hello(&ClientHello {
        random: &[0x61; 32],
        session_id: &[0x62; 32],
        server_name: Some("server.test"),
        key_share_group: GROUP_X25519,
        key_share_public: &public,
        alpn: &[b"h2".to_vec(), b"http/1.1".to_vec()],
        status_request: true,
        cookie: None,
        quic_transport_parameters: None,
        tls12: false,
        psk: None,
    });
    let body = hello[4..].to_vec();
    let empty_certificate = handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0]);
    let mut app = Vec::new();
    for (t, d) in [(RT_APPLICATION_DATA, &b"GET / HTTP/1.1\r\nHost: server.test\r\n\r\n"[..]), (RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[1])[..]), (RT_APPLICATION_DATA, b"more"), (RT_ALERT, &[1, 0])] {
        app.push(t);
        app.extend_from_slice(&(d.len() as u16).to_be_bytes());
        app.extend_from_slice(d);
    }
    let seed = |flags: u8, messages: &[u8], app: &[u8]| {
        let mut v = vec![flags];
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(&body);
        v.extend_from_slice(&(messages.len() as u16).to_be_bytes());
        v.extend_from_slice(messages);
        v.extend_from_slice(app);
        v
    };
    vec![
        seed(0x08, &empty_certificate, &app), // optional, no certificate, Finished, data
        seed(0x0c, &[], &app),                // the harness's certificate and Finished
        seed(0x0d, &[], &app),                // required, with the certificate
        seed(0x09, &empty_certificate, &app), // required, none: refused
        seed(0x00, &[], &[]),                 // the ClientHello alone
        seed(0x1e, &[], &app),                // strict store, certificate, pieces of one byte
    ]
}
