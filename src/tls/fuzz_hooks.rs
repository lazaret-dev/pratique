//! Entry points for the coverage-guided fuzzer in `fuzz/`. Compiled only with
//! `--cfg pratique_fuzzing`; not part of the API.
//!
//! Each function takes the raw bytes the fuzzer produced, reads its own settings from the first
//! bytes, and drives the client with the rest. A panic is a finding. Everything is deterministic:
//! the ClientHello's randomness is fixed, so an input reproduces.

use super::conn::ClientConnection;
use super::messages::*;
use super::scripted::*;
use super::suite::*;
use super::*;
use crate::zeroize::Zeroizing;
use crate::x509::TrustStore;

// the fixed ClientHello secrets
const PRIVATE: [u8; 32] = [0x17; 32];
const RANDOM: [u8; 32] = [0x29; 32];
const SESSION_ID: [u8; 32] = [0x3b; 32];

/// 2026-09-15, inside the validity of the fixture certificates.
const NOW: i64 = 1_789_430_400;

fn pick_piece(selector: u8) -> usize {
    [usize::MAX, 1, 2, 5, 17, 64, 300, 1400][(selector % 8) as usize]
}

/// The certificate chain (leaf first) the fuzz seeds use, valid for "example.test" under the trust
/// store in `server_flight`.
pub fn example_chain() -> Vec<Vec<u8>> {
    let der = |p: &str| crate::pem::parse(p).remove(0).data;
    vec![der(include_str!("../../tests/data/leaf_p384.pem")), der(include_str!("../../tests/data/inter_p256.pem"))]
}

fn example_trust() -> TrustStore {
    let mut ts = TrustStore::empty();
    ts.add_der(&crate::pem::parse(include_str!("../../tests/data/root_rsa.pem")).remove(0).data).unwrap();
    ts
}

/// Moves `bytes` into the connection in pieces of `piece` bytes, processing after each, and
/// discards what it produces. Returns false once the connection has failed or is closed.
fn drive(c: &mut ClientConnection, bytes: &[u8], piece: usize) -> bool {
    let mut sink = [0u8; 512];
    for part in bytes.chunks(piece.max(1)) {
        let mut rest = part;
        while !rest.is_empty() {
            while c.has_plaintext() {
                if c.read_plaintext(&mut sink) == 0 {
                    break;
                }
            }
            let space = c.recv_buf();
            let n = space.len().min(rest.len());
            if n == 0 {
                break;
            }
            space[..n].copy_from_slice(&rest[..n]);
            c.recv_filled(n);
            rest = &rest[n..];
            if c.process().is_err() {
                return false;
            }
        }
        let out = c.output().len();
        c.consume_output(out);
        if c.peer_closed() {
            return true;
        }
    }
    while c.has_plaintext() {
        if c.read_plaintext(&mut sink) == 0 {
            break;
        }
    }
    true
}

/// The wire bytes of a correct ServerHello (and compatibility change_cipher_spec) for exactly the
/// client `server_bytes` starts, for the suite `sel % 3`: a seed that gets past the plaintext
/// handshake into the key schedule.
pub fn example_server_hello(sel: u8) -> Vec<u8> {
    let cfg = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
    let c = ClientConnection::start("example.test", &cfg, Zeroizing::new(PRIVATE), &RANDOM, &SESSION_ID);
    let hello = parse_client_hello(c.output()).expect("our own ClientHello parses");
    Session::new(hello, Suite::ALL[(sel % 3) as usize]).hello_records(&ShOpts::default()).0
}

/// The wire bytes of a HelloRetryRequest, the server's compatibility change_cipher_spec and a
/// ServerHello that answers the retried ClientHello with a valid key share (the group's generator
/// point, so it passes validation and reaches the key schedule), for the client `server_bytes`
/// starts. `sel % 3` picks the suite, `sel / 3 % 3` the retry: P-256, P-384 or a cookie only.
pub fn example_hello_retry(sel: u8) -> Vec<u8> {
    use crate::crypto::ecdh;
    use crate::crypto::ecdsa::Curve;
    let suite = Suite::ALL[(sel % 3) as usize];
    let kind = (sel / 3) % 3;
    let (group, cookie): (Option<u16>, Option<&[u8]>) = match kind {
        0 => (Some(GROUP_SECP256R1), None),
        1 => (Some(GROUP_SECP384R1), Some(&[0xc0, 0x0c, 0x1e][..])),
        _ => (None, Some(&[0xc0, 0x0c, 0x1e][..])),
    };
    let hrr = retry_message(&SESSION_ID, suite, group, cookie);
    let (g, public) = match kind {
        0 => (GROUP_SECP256R1, ecdh::public_key(Curve::P256, &[&[0u8; 31][..], &[1]].concat()).unwrap()),
        1 => (GROUP_SECP384R1, ecdh::public_key(Curve::P384, &[&[0u8; 47][..], &[1]].concat()).unwrap()),
        _ => (GROUP_X25519, crate::crypto::x25519::public_key(&[9; 32]).to_vec()),
    };
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x42; 32]);
    body.push(32);
    body.extend_from_slice(&SESSION_ID);
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut exts = ext(EXT_SUPPORTED_VERSIONS, &[3, 4]);
    let mut share = g.to_be_bytes().to_vec();
    share.extend(block16(&public));
    exts.extend(ext(EXT_KEY_SHARE, &share));
    body.extend(block16(&exts));
    let sh = handshake_message(HS_SERVER_HELLO, &body);
    let mut out = plain_record(RT_HANDSHAKE, &hrr);
    out.extend(plain_record(RT_CHANGE_CIPHER_SPEC, &[1]));
    out.extend(plain_record(RT_HANDSHAKE, &sh));
    out
}

/// Raw bytes from the wire into a fresh client: the record layer and the plaintext ServerHello.
/// `data[0]` chooses the piece size.
pub fn server_bytes(data: &[u8]) {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let cfg = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
    let mut c = ClientConnection::start("example.test", &cfg, Zeroizing::new(PRIVATE), &RANDOM, &SESSION_ID);
    let out = c.output().len();
    c.consume_output(out);
    drive(&mut c, bytes, pick_piece(sel));
}

/// A server flight: `data[2..]` is the plaintext of the handshake records the server sends after
/// a correct ServerHello (it is sealed with the keys the client derived, so it passes the record
/// MAC and reaches the message parsers). `data[0]` chooses the cipher suite and whether the
/// certificate chain is verified (against a trust store that fits `example_chain`), `data[1]` how
/// the flight is cut into records (low bits) and whether the server first sends a
/// HelloRetryRequest (bits 4 and 5). The handshake must never complete.
pub fn server_flight(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let suite = Suite::ALL[(data[0] % 3) as usize];
    let verify = data[0] & 0x08 != 0;
    let piece = pick_piece(data[1]).min(MAX_PLAINTEXT);
    let flight = data[2..].to_vec();
    let cfg = if verify {
        let mut cfg = ClientConfig::new(example_trust());
        cfg.time_override = Some(NOW);
        cfg
    } else {
        ClientConfig::new(TrustStore::empty()).danger_disable_verification()
    };
    // data[1] >> 4: 0 a plain handshake, 1 to 3 a HelloRetryRequest first (see `RetryServer`)
    let retry = (data[1] >> 4) & 3;
    if retry != 0 {
        let io = RetryServer::new(suite, retry, flight, piece);
        if TlsStream::connect(io, "example.test", &cfg).is_ok() {
            panic!("a fuzzed server flight completed a handshake after a HelloRetryRequest");
        }
        return;
    }
    let respond = move |h: Hello| {
        let s = Session::new(h, suite);
        let (mut out, sh) = s.hello_records(&ShOpts::default());
        let mut cipher = s.flight_cipher(&sh);
        for chunk in flight.chunks(piece) {
            cipher.encrypt_into(RT_HANDSHAKE, chunk, &mut out);
        }
        out
    };
    let (io, _) = FakeServer::new(respond);
    if TlsStream::connect(io, "example.test", &cfg).is_ok() {
        panic!("a fuzzed server flight completed a handshake");
    }
}

/// Records sent to an established connection: `data[0]` chooses the suite (and, with bit 3 set, a
/// tiny rekey interval, so our own KeyUpdates and writes are exercised), then each record is
/// `[inner type][length][content]`. The records are sealed with the peer's keys, which follow
/// every KeyUpdate the way a real peer's would. Inner type 0xff makes the client write the content
/// as application data instead.
///
/// With bit 2 of `data[0]` set the connection is a TLS 1.2 one instead (the suite from the top bits): its records carry their
/// real type, and what the server may send after the handshake is different (a HelloRequest, answered with a warning).
pub fn peer_records(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else { return };
    if sel & 0x04 != 0 {
        return peer_records12(sel, rest);
    }
    let suite = Suite::ALL[(sel % 3) as usize];
    let n = suite.hash().output_len();
    let (read_secret, write_secret) = (vec![2u8; n], vec![1u8; n]);
    let mut c = ClientConnection::established(suite, &read_secret, &write_secret);
    if sel & 0x08 != 0 {
        c.set_rekey_after(2 + (sel >> 4) as u64);
    }
    let mut peer = RecordCipher::new(suite, &read_secret);
    while rest.len() >= 2 {
        let (ty, len) = (rest[0], rest[1] as usize);
        rest = &rest[2..];
        let take = len.min(rest.len());
        let content = &rest[..take];
        rest = &rest[take..];
        if ty == 0xff {
            let _ = c.write_plaintext(content);
            let out = c.output().len();
            c.consume_output(out);
            continue;
        }
        let mut record = Vec::new();
        peer.encrypt_into(ty, content, &mut record);
        if ty == RT_HANDSHAKE && content.len() == 5 && content[0] == HS_KEY_UPDATE && content[1..4] == [0, 0, 1] && content[4] <= 1 {
            peer = peer.next_generation();
        }
        if !drive(&mut c, &record, usize::MAX) {
            return;
        }
    }
}

fn peer_records12(sel: u8, mut rest: &[u8]) {
    use super::tls12::{RecordCipher12, Suite12};
    let suite = Suite12::ALL[(sel >> 4) as usize % 6];
    let n = suite.aead_suite().key_len();
    let (key, other, iv) = (vec![3u8; n], vec![4u8; n], [5u8; 12]);
    let mut c = ClientConnection::established12(RecordCipher12::new(suite, &key, &iv), RecordCipher12::new(suite, &other, &iv));
    if sel & 0x08 != 0 {
        c.set_rekey_after(2 + (sel & 3) as u64);
    }
    let mut peer = RecordCipher12::new(suite, &key, &iv);
    while rest.len() >= 2 {
        let (ty, len) = (rest[0], rest[1] as usize);
        rest = &rest[2..];
        let take = len.min(rest.len());
        let content = &rest[..take];
        rest = &rest[take..];
        if ty == 0xff {
            let _ = c.write_plaintext(content);
            let out = c.output().len();
            c.consume_output(out);
            continue;
        }
        let mut record = Vec::new();
        peer.encrypt_into(ty, content, &mut record);
        if !drive(&mut c, &record, usize::MAX) {
            return;
        }
    }
}


// ------------------------------------------------------------------------------------------------ TLS 1.2 handshake

/// The certificates and keys of the TLS 1.2 flight target: a root and a leaf for "example.test" (Ed25519, valid around `NOW`, made
/// once and the same every run), the leaf's key, which signs the ServerKeyExchange of the seeds, and the server's X25519 key.
#[cfg(feature = "server")]
struct Pki12 {
    root: Vec<u8>,
    leaf: Vec<u8>,
    leaf_key: super::pki::KeyPair,
}

#[cfg(feature = "server")]
fn pki12() -> &'static Pki12 {
    static PKI: std::sync::OnceLock<Pki12> = std::sync::OnceLock::new();
    PKI.get_or_init(|| {
        use super::pki::{issue, CertSpec, KeyPair};
        let root_key = KeyPair::from_seed([0x61; 32]);
        let leaf_key = KeyPair::from_seed([0x62; 32]);
        let mut root_spec = CertSpec::ca("pratique fuzz root");
        root_spec.not_before = NOW - 400 * 86_400;
        root_spec.not_after = NOW + 365 * 86_400;
        let mut leaf_spec = CertSpec::server(&["example.test"]);
        leaf_spec.not_before = NOW - 86_400;
        leaf_spec.not_after = NOW + 30 * 86_400;
        let root = issue(&root_spec, &root_key, None);
        let leaf = issue(&leaf_spec, &leaf_key, Some((&root_spec.common_name, &root_key)));
        Pki12 { root, leaf, leaf_key }
    })
}

/// The server random of the TLS 1.2 target (no downgrade sentinel in it).
#[cfg(feature = "server")]
const SERVER_RANDOM12: [u8; 32] = [0x42; 32];
/// The server's X25519 secret in the seeds.
#[cfg(feature = "server")]
const SERVER_X25519: [u8; 32] = [0x63; 32];

#[cfg(feature = "server")]
fn vec24(inner: &[u8]) -> Vec<u8> {
    let mut v = (inner.len() as u32).to_be_bytes()[1..].to_vec();
    v.extend_from_slice(inner);
    v
}

/// A TLS 1.2 ServerHello for the suite `sel & 7` (mod 6) with what the client requires (the extended master secret, an empty
/// renegotiation_info, uncompressed points), acknowledging status_request when `staple`.
#[cfg(feature = "server")]
fn server_hello12(sel: u8, staple: bool) -> Vec<u8> {
    use super::tls12::{Suite12, EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO};
    let suite = Suite12::ALL[(sel & 7) as usize % 6];
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&SERVER_RANDOM12);
    body.push(32);
    body.extend_from_slice(&[0x5e; 32]); // a session id of its own, not ours echoed (that would claim a resumption)
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut exts = ext(EXT_EXTENDED_MASTER_SECRET, &[]);
    exts.extend(ext(EXT_RENEGOTIATION_INFO, &[0]));
    exts.extend(ext(EXT_EC_POINT_FORMATS, &[1, 0]));
    if staple {
        exts.extend(ext(EXT_STATUS_REQUEST, &[]));
    }
    body.extend(block16(&exts));
    handshake_message(HS_SERVER_HELLO, &body)
}

/// The wire bytes a TLS 1.2 server sends after its ServerHello in the target `server_flight12`, for the selector `sel` (see
/// there): Certificate, (CertificateStatus,) a ServerKeyExchange signed by the certificate's key, (CertificateRequest,)
/// ServerHelloDone, then change_cipher_spec and a record that stands for an encrypted Finished (which no fuzzer can make: it
/// is sealed under keys from the key exchange). `variant` bit 0 adds a CertificateRequest, bit 1 uses P-256 instead of X25519,
/// bit 2 puts each message in a record of its own.
#[cfg(feature = "server")]
pub fn example_tls12_flight(sel: u8, variant: u8) -> Vec<u8> {
    use super::tls12::{HS_CERTIFICATE_STATUS, HS_SERVER_HELLO_DONE, HS_SERVER_KEY_EXCHANGE};
    use crate::crypto::ecdh;
    use crate::crypto::ecdsa::Curve;
    let pki = pki12();
    let mut messages = vec![handshake_message(HS_CERTIFICATE, &vec24(&vec24(&pki.leaf)))];
    if sel & 0x10 != 0 {
        // an OCSP response with an error status (malformedRequest) and nothing to verify: with soft-fail, the default, the chain
        // check writes it down and goes on, as it does in TLS 1.3; the fuzzer makes the rest of what a staple can be
        messages.push(handshake_message(HS_CERTIFICATE_STATUS, &[&[1u8][..], &vec24(&[0x30, 0x03, 0x0a, 0x01, 0x01])].concat()));
    }
    let (group, public) = if variant & 2 != 0 {
        (GROUP_SECP256R1, ecdh::public_key(Curve::P256, &[&[0u8; 31][..], &[1]].concat()).unwrap())
    } else {
        (GROUP_X25519, crate::crypto::x25519::public_key(&SERVER_X25519).to_vec())
    };
    let mut params = vec![3];
    params.extend_from_slice(&group.to_be_bytes());
    params.push(public.len() as u8);
    params.extend_from_slice(&public);
    let signed = [&RANDOM[..], &SERVER_RANDOM12, &params].concat();
    let mut ske = params.clone();
    ske.extend_from_slice(&0x0807u16.to_be_bytes());
    ske.extend(block16(&pki.leaf_key.sign(&signed)));
    messages.push(handshake_message(HS_SERVER_KEY_EXCHANGE, &ske));
    if variant & 1 != 0 {
        let mut request = vec![1, 64]; // ecdsa_sign
        request.extend(block16(&[0x04, 0x03, 0x08, 0x07]));
        request.extend(block16(&[]));
        messages.push(handshake_message(HS_CERTIFICATE_REQUEST, &request));
    }
    messages.push(handshake_message(HS_SERVER_HELLO_DONE, &[]));
    let mut out = Vec::new();
    if variant & 4 != 0 {
        for m in &messages {
            out.extend(plain_record(RT_HANDSHAKE, m));
        }
    } else {
        out.extend(plain_record(RT_HANDSHAKE, &messages.concat()));
    }
    out.extend(plain_record(RT_CHANGE_CIPHER_SPEC, &[1]));
    // explicit nonce (AES-GCM only), a Finished of 16 bytes, the tag
    let sealed_len = if super::tls12::Suite12::ALL[(sel & 7) as usize % 6].name().contains("CHACHA") { 32 } else { 40 };
    out.extend(plain_record(RT_HANDSHAKE, &vec![0xa5; sealed_len]));
    out
}

/// A TLS 1.2 handshake after a correct TLS 1.2 ServerHello: `data[0]` chooses the suite (low three bits, mod 6: the ECDSA suites
/// fit the certificate's Ed25519 key, the RSA ones must be refused), whether the chain is verified against the target's root
/// (bit 3; otherwise verification is off, which leaves the ServerKeyExchange signature checked all the same), and whether the
/// ServerHello acknowledges status_request (bit 4, with bit 3 only); `data[1]` how the rest is cut; `data[2..]` is whatever the
/// server sends next, raw (records in the clear, then what should be encrypted). Never completes: the Finished it would need is
/// sealed under keys that come from the key exchange. Returns whether the client sent its own flight (ClientKeyExchange,
/// change_cipher_spec and Finished), so that the seeds can be checked to get that far.
#[cfg(feature = "server")]
pub fn server_flight12(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let (sel, piece) = (data[0], pick_piece(data[1]));
    let verify = sel & 0x08 != 0;
    let staple = verify && sel & 0x10 != 0;
    let cfg = if verify {
        let mut trust = TrustStore::empty();
        trust.add_der(&pki12().root).expect("the fuzz root parses");
        let mut cfg = ClientConfig::new(trust);
        cfg.time_override = Some(NOW);
        cfg
    } else {
        ClientConfig::new(TrustStore::empty()).danger_disable_verification()
    };
    let mut c = ClientConnection::start("example.test", &cfg, Zeroizing::new(PRIVATE), &RANDOM, &SESSION_ID);
    let out = c.output().len();
    c.consume_output(out);
    let hello = plain_record(RT_HANDSHAKE, &server_hello12(sel, staple));
    assert!(drive(&mut c, &hello, usize::MAX) && !c.is_failed(), "the TLS 1.2 ServerHello of the target is refused");
    let mut sent = Vec::new();
    let mut sink = [0u8; 512];
    'feed: for part in data[2..].chunks(piece.max(1)) {
        let mut rest = part;
        while !rest.is_empty() {
            let space = c.recv_buf();
            let n = space.len().min(rest.len());
            if n == 0 {
                break 'feed;
            }
            space[..n].copy_from_slice(&rest[..n]);
            c.recv_filled(n);
            rest = &rest[n..];
            let failed = c.process().is_err();
            sent.extend_from_slice(c.output());
            let out = c.output().len();
            c.consume_output(out);
            while c.has_plaintext() && c.read_plaintext(&mut sink) > 0 {}
            if failed || c.peer_closed() {
                break 'feed;
            }
        }
    }
    assert!(!c.is_established(), "a fuzzed TLS 1.2 server flight completed a handshake");
    // the client's change_cipher_spec record
    sent.windows(6).any(|w| w == [RT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1])
}
