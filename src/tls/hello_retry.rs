//! HelloRetryRequest (RFC 8446 section 4.1.4) and the secp256r1 / secp384r1 key shares, against a
//! scripted server.
//!
//! The server side here is a few functions that build the messages by hand and derive the
//! handshake keys with the client's own key-schedule helpers, the way `scripted.rs` does for a
//! plain ServerHello. What these tests establish: the second ClientHello changes only what the RFC
//! allows, the transcript restarts with the `message_hash` message (a wrong transcript makes the
//! server's encrypted flight unreadable, which a negative control shows), and every way a server
//! can misuse the mechanism ends the handshake with the right alert. That the transcript rule is
//! what real servers use is checked against `openssl s_server` in `tests/interop_openssl.rs`.

use super::conn::ClientConnection;
use super::messages::*;
use super::scripted::{block16, ext, plain_record};
use super::suite::*;
use super::*;
use crate::crypto::ecdh;
use crate::crypto::ecdsa::Curve;
use crate::crypto::x25519;
use crate::util::Reader;
use crate::zeroize::Zeroizing;

const RANDOM: [u8; 32] = [1; 32];
const SESSION: [u8; 32] = [2; 32];
const X25519_SERVER_PRIVATE: [u8; 32] = [0x55; 32];

/// TLS 1.3 only: these tests look at the flights byte by byte, and a ClientHello that offers TLS 1.2 too sends its
/// compatibility change_cipher_spec later (see `the_compatibility_change_cipher_spec_goes_before_the_second_hello`).
fn config() -> ClientConfig {
    ClientConfig::new(crate::x509::TrustStore::empty()).danger_disable_verification().with_min_version(crate::tls::TlsVersion::Tls13)
}

/// A client that has sent its ClientHello (taken from its output, which is returned).
fn start() -> (ClientConnection, Vec<u8>) {
    let mut c = ClientConnection::start("example.com", &config(), Zeroizing::new([7u8; 32]), &RANDOM, &SESSION);
    let out = take_output(&mut c);
    (c, out)
}

fn take_output(c: &mut ClientConnection) -> Vec<u8> {
    let out = c.output().to_vec();
    c.consume_output(out.len());
    out
}

fn feed(c: &mut ClientConnection, bytes: &[u8]) -> crate::error::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let space = c.recv_buf();
        let n = space.len().min(rest.len());
        space[..n].copy_from_slice(&rest[..n]);
        c.recv_filled(n);
        rest = &rest[n..];
        c.process()?;
    }
    Ok(())
}

/// The records in `bytes` as (type, content).
fn records(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        out.push((rest[0], rest[5..5 + len].to_vec()));
        rest = &rest[5 + len..];
    }
    out
}

/// A ClientHello taken apart.
struct Hello {
    msg: Vec<u8>,
    random: Vec<u8>,
    session_id: Vec<u8>,
    suites: Vec<u8>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn parse(msg: &[u8]) -> Hello {
        assert_eq!(msg[0], HS_CLIENT_HELLO);
        let mut r = Reader::new(&msg[4..]);
        r.u16().unwrap();
        let random = r.take(32).unwrap().to_vec();
        let session_id = r.vec8().unwrap().to_vec();
        let suites = r.vec16().unwrap().to_vec();
        r.vec8().unwrap();
        let mut er = Reader::new(r.vec16().unwrap());
        assert!(r.is_empty());
        let mut exts = Vec::new();
        while !er.is_empty() {
            let t = er.u16().unwrap();
            exts.push((t, er.vec16().unwrap().to_vec()));
        }
        Hello { msg: msg.to_vec(), random, session_id, suites, exts }
    }

    fn ext(&self, t: u16) -> Option<&[u8]> {
        self.exts.iter().find(|(x, _)| *x == t).map(|(_, d)| d.as_slice())
    }

    fn types(&self) -> Vec<u16> {
        self.exts.iter().map(|(t, _)| *t).collect()
    }

    /// The one key share: (group, public value).
    fn key_share(&self) -> (u16, Vec<u8>) {
        let mut list = Reader::new(Reader::new(self.ext(EXT_KEY_SHARE).unwrap()).vec16().unwrap());
        let group = list.u16().unwrap();
        let key = list.vec16().unwrap().to_vec();
        assert!(list.is_empty(), "exactly one key share");
        (group, key)
    }
}

/// A HelloRetryRequest; the default is a correct one asking for P-256.
#[derive(Clone)]
struct Retry {
    random: [u8; 32],
    legacy_version: u16,
    session_id: Vec<u8>,
    suite: u16,
    compression: u8,
    version: Option<u16>,
    group: Option<u16>,
    /// Bytes after the group in the key_share extension (a violation if not empty).
    key_after_group: Vec<u8>,
    cookie: Option<Vec<u8>>,
    extra: Vec<(u16, Vec<u8>)>,
}

impl Retry {
    fn to(group: u16) -> Retry {
        Retry {
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_version: 0x0303,
            session_id: SESSION.to_vec(),
            suite: Suite::Aes128GcmSha256.id(),
            compression: 0,
            version: Some(0x0304),
            group: Some(group),
            key_after_group: Vec::new(),
            cookie: None,
            extra: Vec::new(),
        }
    }

    fn message(&self) -> Vec<u8> {
        let mut body = self.legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&self.suite.to_be_bytes());
        body.push(self.compression);
        let mut exts = Vec::new();
        if let Some(v) = self.version {
            exts.extend(ext(EXT_SUPPORTED_VERSIONS, &v.to_be_bytes()));
        }
        if let Some(g) = self.group {
            let mut d = g.to_be_bytes().to_vec();
            d.extend_from_slice(&self.key_after_group);
            exts.extend(ext(EXT_KEY_SHARE, &d));
        }
        if let Some(c) = &self.cookie {
            exts.extend(ext(EXT_COOKIE, &block16(c)));
        }
        for (t, d) in &self.extra {
            exts.extend(ext(*t, d));
        }
        body.extend(block16(&exts));
        handshake_message(HS_SERVER_HELLO, &body)
    }

    fn record(&self) -> Vec<u8> {
        plain_record(RT_HANDSHAKE, &self.message())
    }
}

fn server_hello(suite: u16, group: u16, public: &[u8]) -> Vec<u8> {
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x42; 32]);
    body.push(32);
    body.extend_from_slice(&SESSION);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    let mut exts = ext(EXT_SUPPORTED_VERSIONS, &[3, 4]);
    let mut share = group.to_be_bytes().to_vec();
    share.extend(block16(public));
    exts.extend(ext(EXT_KEY_SHARE, &share));
    body.extend(block16(&exts));
    handshake_message(HS_SERVER_HELLO, &body)
}

fn curve(group: u16) -> Curve {
    if group == GROUP_SECP256R1 {
        Curve::P256
    } else {
        Curve::P384
    }
}

/// What the server derives from the key exchange: its handshake write cipher, given the transcript.
fn server_cipher(suite: Suite, shared: &[u8], transcript: &[u8]) -> RecordCipher {
    let alg = suite.hash();
    let zeros = vec![0u8; alg.output_len()];
    let early = hkdf_extract(alg, &[], &zeros);
    let derived = derive_secret(alg, &early, "derived", &alg.digest(&[]));
    let hs = hkdf_extract(alg, &derived, shared);
    RecordCipher::new(suite, &derive_secret(alg, &hs, "s hs traffic", &alg.digest(transcript)))
}

/// An empty EncryptedExtensions message sealed as the server's first protected record.
fn sealed_encrypted_extensions(cipher: &mut RecordCipher) -> Vec<u8> {
    let mut out = Vec::new();
    cipher.encrypt_into(RT_HANDSHAKE, &handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]), &mut out);
    out
}

/// The server's key exchange against the client's key share: (its public value, the shared secret).
fn server_exchange(group: u16, client_public: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if group == GROUP_X25519 {
        let client: [u8; 32] = client_public.try_into().unwrap();
        (x25519::public_key(&X25519_SERVER_PRIVATE).to_vec(), x25519::x25519(&X25519_SERVER_PRIVATE, &client).to_vec())
    } else {
        let (secret, public) = ecdh::generate(curve(group)).unwrap();
        let shared = ecdh::shared_secret(curve(group), &secret, client_public).expect("the client's share is a valid point");
        (public, shared.to_vec())
    }
}

/// Runs the ClientHello, the HelloRetryRequest and the second ClientHello; returns the client, the
/// two hellos and the HelloRetryRequest message.
fn retried(retry: &Retry) -> (ClientConnection, Hello, Hello, Vec<u8>) {
    let (mut c, out1) = start();
    let r1 = records(&out1);
    assert_eq!(r1.len(), 2, "ClientHello and the compatibility change_cipher_spec");
    assert_eq!((r1[0].0, r1[1].0), (RT_HANDSHAKE, RT_CHANGE_CIPHER_SPEC));
    let ch1 = Hello::parse(&r1[0].1);
    feed(&mut c, &retry.record()).expect("the retry is accepted");
    let r2 = records(&take_output(&mut c));
    assert_eq!(r2.len(), 1, "only the second ClientHello: the change_cipher_spec went out once already");
    assert_eq!(r2[0].0, RT_HANDSHAKE);
    let ch2 = Hello::parse(&r2[0].1);
    (c, ch1, ch2, retry.message())
}

/// Finishes the exchange the way a server would and returns whether the client could read the
/// server's first protected record. `message_hash` false builds the transcript the wrong way.
fn finish_exchange(c: &mut ClientConnection, suite: Suite, ch1: &Hello, hrr: &[u8], ch2: &Hello, message_hash: bool) -> crate::error::Result<()> {
    let (group, client_public) = ch2.key_share();
    let (server_public, shared) = server_exchange(group, &client_public);
    let sh = server_hello(suite.id(), group, &server_public);
    let mut transcript = if message_hash { handshake_message(HS_MESSAGE_HASH, &suite.hash().digest(&ch1.msg)) } else { ch1.msg.clone() };
    transcript.extend_from_slice(hrr);
    transcript.extend_from_slice(&ch2.msg);
    transcript.extend_from_slice(&sh);
    let mut cipher = server_cipher(suite, &shared, &transcript);
    let mut bytes = plain_record(RT_HANDSHAKE, &sh);
    bytes.extend(sealed_encrypted_extensions(&mut cipher));
    feed(c, &bytes)
}

fn message(err: crate::error::Error) -> String {
    err.to_string()
}

#[test]
fn a_retry_to_a_nist_group_completes_the_key_exchange_for_every_suite() {
    for suite in Suite::preference_order() {
        for group in [GROUP_SECP256R1, GROUP_SECP384R1] {
            let mut retry = Retry::to(group);
            retry.suite = suite.id();
            let (mut c, ch1, ch2, hrr) = retried(&retry);
            let (g, public) = ch2.key_share();
            assert_eq!(g, group);
            assert_eq!(public.len(), if group == GROUP_SECP256R1 { 65 } else { 97 });
            assert_eq!(public[0], 4, "uncompressed point");
            finish_exchange(&mut c, suite, &ch1, &hrr, &ch2, true).unwrap_or_else(|e| panic!("{suite:?} group {group:#x}: {e}"));
            assert!(c.is_handshaking() && !c.is_failed());
        }
    }
}

#[test]
fn the_transcript_must_restart_with_message_hash() {
    // Negative control: a server that hashes ClientHello1 into the transcript as it is (no
    // message_hash) derives different keys, and the client cannot read its record.
    let retry = Retry::to(GROUP_SECP256R1);
    let (mut c, ch1, ch2, hrr) = retried(&retry);
    let err = finish_exchange(&mut c, Suite::Aes128GcmSha256, &ch1, &hrr, &ch2, false).expect_err("wrong transcript");
    assert!(message(err).contains("bad_record_mac"));
}

#[test]
fn the_second_client_hello_changes_only_the_key_share() {
    let (_, out1) = start();
    let ch1 = Hello::parse(&records(&out1)[0].1);
    assert_eq!(ch1.key_share().0, GROUP_X25519);
    let groups = Reader::new(ch1.ext(EXT_SUPPORTED_GROUPS).unwrap()).vec16().unwrap().to_vec();
    assert_eq!(groups, [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18], "x25519, secp256r1, secp384r1 in that order");

    let (_, ch1, ch2, _) = retried(&Retry::to(GROUP_SECP384R1));
    assert_eq!(ch2.random, RANDOM);
    assert_eq!(ch2.session_id, SESSION);
    assert_eq!(ch2.random, ch1.random);
    assert_eq!(ch2.session_id, ch1.session_id);
    assert_eq!(ch2.suites, ch1.suites);
    assert_eq!(ch2.types(), ch1.types(), "same extensions in the same order");
    for ((t, d1), (_, d2)) in ch1.exts.iter().zip(&ch2.exts) {
        if *t != EXT_KEY_SHARE {
            assert_eq!(d1, d2, "extension {t} must not change");
        }
    }
    assert_eq!(ch2.key_share().0, GROUP_SECP384R1);
    assert!(ch2.ext(EXT_COOKIE).is_none());
    assert_ne!(ch2.key_share().1, ch1.key_share().1);
}

#[test]
fn a_cookie_is_echoed_and_a_cookie_alone_keeps_the_key_share() {
    let cookie = vec![0xc0, 0x0c, 0x1e, 1, 2, 3];
    // cookie only: same group, same public value, and the handshake completes with x25519
    let mut retry = Retry::to(GROUP_X25519);
    retry.group = None;
    retry.cookie = Some(cookie.clone());
    let (mut c, ch1, ch2, hrr) = retried(&retry);
    assert_eq!(ch2.key_share(), ch1.key_share());
    assert_eq!(ch2.ext(EXT_COOKIE).unwrap(), block16(&cookie).as_slice());
    finish_exchange(&mut c, Suite::Aes128GcmSha256, &ch1, &hrr, &ch2, true).unwrap();

    // a new group and a cookie together
    let mut retry = Retry::to(GROUP_SECP256R1);
    retry.cookie = Some(cookie.clone());
    let (mut c, ch1, ch2, hrr) = retried(&retry);
    assert_eq!(ch2.key_share().0, GROUP_SECP256R1);
    assert_eq!(ch2.ext(EXT_COOKIE).unwrap(), block16(&cookie).as_slice());
    finish_exchange(&mut c, Suite::Aes128GcmSha256, &ch1, &hrr, &ch2, true).unwrap();
}

#[test]
fn a_retry_that_breaks_the_rules_ends_the_handshake() {
    let mut cases: Vec<(&str, Retry, &str)> = Vec::new();
    let mut add = |name, f: &dyn Fn(&mut Retry), expect| {
        let mut r = Retry::to(GROUP_SECP256R1);
        f(&mut r);
        cases.push((name, r, expect));
    };
    add("the group already sent", &|r| r.group = Some(GROUP_X25519), "illegal_parameter");
    add("a group we never offered (secp521r1)", &|r| r.group = Some(0x0019), "illegal_parameter");
    add("a group we never offered (ffdhe2048)", &|r| r.group = Some(0x0100), "illegal_parameter");
    add("nothing changes", &|r| r.group = None, "illegal_parameter");
    add("wrong session id", &|r| r.session_id = vec![9; 32], "illegal_parameter");
    add("empty session id", &|r| r.session_id = Vec::new(), "illegal_parameter");
    add("unknown cipher suite", &|r| r.suite = 0x1304, "illegal_parameter");
    add("legacy version 1.2 changed", &|r| r.legacy_version = 0x0302, "illegal_parameter");
    add("compression", &|r| r.compression = 1, "illegal_parameter");
    add("no supported_versions", &|r| r.version = None, "protocol_version");
    add("TLS 1.2 selected", &|r| r.version = Some(0x0303), "protocol_version");
    add("a key in the key_share", &|r| r.key_after_group = vec![0, 1, 7], "decode_error");
    add("an empty cookie", &|r| r.cookie = Some(Vec::new()), "decode_error");
    add("an unsolicited extension", &|r| r.extra = vec![(EXT_SERVER_NAME, vec![])], "unsupported_extension");
    add("a second cookie", &|r| {
        r.cookie = Some(vec![1]);
        r.extra = vec![(EXT_COOKIE, block16(&[2]))];
    }, "illegal_parameter");
    for (name, retry, expect) in cases {
        let (mut c, _) = start();
        let err = feed(&mut c, &retry.record()).expect_err(name);
        assert!(message(err).contains(expect), "{name}: expected {expect}");
        assert!(c.is_failed(), "{name}");
    }
}

#[test]
fn a_second_retry_is_refused() {
    let (mut c, _, _, _) = retried(&Retry::to(GROUP_SECP256R1));
    let err = feed(&mut c, &Retry::to(GROUP_SECP384R1).record()).expect_err("second HelloRetryRequest");
    assert!(message(err).contains("unexpected_message"));
    // also when it only carries a cookie
    let (mut c, _, _, _) = retried(&Retry::to(GROUP_SECP256R1));
    let mut again = Retry::to(GROUP_SECP256R1);
    again.group = None;
    again.cookie = Some(vec![1]);
    assert!(message(feed(&mut c, &again.record()).unwrap_err()).contains("unexpected_message"));
}

#[test]
fn more_handshake_data_after_the_retry_in_the_same_record_is_refused() {
    let (mut c, _) = start();
    let mut content = Retry::to(GROUP_SECP256R1).message();
    content.push(HS_ENCRYPTED_EXTENSIONS); // the start of another message
    let err = feed(&mut c, &plain_record(RT_HANDSHAKE, &content)).expect_err("data after the retry");
    assert!(message(err).contains("unexpected_message"));
}

#[test]
fn a_server_hello_after_a_retry_must_match_the_retry() {
    let valid_share = |client_public: &[u8]| server_exchange(GROUP_SECP256R1, client_public).0;
    type Case = (&'static str, Box<dyn Fn(&[u8]) -> Vec<u8>>);
    let cases: Vec<Case> = vec![
        ("a different cipher suite", Box::new(move |p| server_hello(Suite::Aes256GcmSha384.id(), GROUP_SECP256R1, &valid_share(p)))),
        ("another group", Box::new(|_| server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP384R1, &[4; 97]))),
        ("the group that was first sent", Box::new(|_| server_hello(Suite::Aes128GcmSha256.id(), GROUP_X25519, &[9; 32]))),
        ("a point off the curve", Box::new(move |p| {
            let mut s = valid_share(p);
            *s.last_mut().unwrap() ^= 1;
            server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &s)
        })),
        ("a compressed point", Box::new(move |p| {
            let s = valid_share(p);
            let mut compressed = vec![2 + (s[64] & 1)];
            compressed.extend_from_slice(&s[1..33]);
            server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &compressed)
        })),
        ("a short key", Box::new(|_| server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &[4; 64]))),
        ("an empty key", Box::new(|_| server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &[]))),
        ("the point (0, 0)", Box::new(|_| {
            let mut z = vec![0u8; 65];
            z[0] = 4;
            server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &z)
        })),
    ];
    for (name, build) in cases {
        let (mut c, _, ch2, _) = retried(&Retry::to(GROUP_SECP256R1));
        let sh = build(&ch2.key_share().1);
        let err = feed(&mut c, &plain_record(RT_HANDSHAKE, &sh)).expect_err(name);
        assert!(message(err).contains("illegal_parameter"), "{name}");
        assert!(c.is_failed(), "{name}");
    }
}

#[test]
fn a_nist_key_share_without_a_retry_is_refused() {
    // we sent an x25519 share only; a ServerHello may not pick a group we did not send a share for
    let (mut c, _) = start();
    let sh = server_hello(Suite::Aes128GcmSha256.id(), GROUP_SECP256R1, &[4; 65]);
    let err = feed(&mut c, &plain_record(RT_HANDSHAKE, &sh)).expect_err("group not sent");
    assert!(message(err).contains("illegal_parameter"));
}

#[test]
fn a_connection_started_from_a_recorded_hello_cannot_retry() {
    let mut c = ClientConnection::with_recorded_hello("example.com", &config(), [7; 32], &[], &[1, 0, 0, 0], &[]);
    take_output(&mut c);
    let err = feed(&mut c, &Retry::to(GROUP_SECP256R1).record()).expect_err("no inputs to rebuild the hello");
    assert!(message(err).contains("internal"));
}

/// A transport that answers the ClientHello with a HelloRetryRequest and then insists that the
/// second ClientHello has been written before it is asked for anything more.
struct RetryingServer {
    writes: usize,
    reads: usize,
    pending: Vec<u8>,
    first_write: Vec<u8>,
}

impl std::io::Read for RetryingServer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads == 1 {
            assert!(self.writes >= 1, "the first ClientHello goes out before the first read");
            // the client picked its own session id: echo it
            let hello = Hello::parse(&records(&self.first_write)[0].1);
            let mut retry = Retry::to(GROUP_SECP256R1);
            retry.session_id = hello.session_id;
            self.pending = retry.record();
        } else {
            assert!(self.writes >= 2, "the second ClientHello must be written before waiting for the server again (it would never arrive)");
            return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "the test ends here"));
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl std::io::Write for RetryingServer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.writes == 0 {
            self.first_write = buf.to_vec();
        }
        self.writes += 1;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_blocking_driver_sends_the_second_client_hello_before_it_reads_again() {
    // Regression test: the blocking driver once sent only the first flight, so a server that
    // answered with a HelloRetryRequest waited for a second ClientHello that never came.
    let io = RetryingServer { writes: 0, reads: 0, pending: Vec::new(), first_write: Vec::new() };
    let err = TlsStream::connect(io, "example.com", &config()).err().expect("the transport fails afterwards");
    let text = message(err);
    assert!(text.contains("the test ends here"), "{text}");
}

#[test]
fn the_scripted_retry_server_gets_the_client_to_read_its_flight() {
    // `RetryServer` (also used by the fuzzer) seals an EncryptedExtensions message under the keys
    // the client must derive after the retry. The client reads it, so the handshake then ends
    // only because the server has nothing more to say, never because of a MAC or key error.
    use super::scripted::RetryServer;
    for kind in 1..=3u8 {
        for suite in Suite::preference_order() {
            let flight = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
            let io = RetryServer::new(suite, kind, flight, usize::MAX);
            let err = TlsStream::connect(io, "example.test", &config()).err().expect("no certificate follows");
            let text = message(err);
            assert!(!text.contains("bad_record_mac") && !text.contains("illegal_parameter"), "kind {kind} {suite:?}: {text}");
            assert!(text.to_lowercase().contains("eof") || text.contains("closed") || text.contains("end"), "kind {kind} {suite:?}: {text}");
        }
    }
}

#[test]
fn the_compatibility_change_cipher_spec_goes_before_the_second_hello() {
    // a ClientHello that offers TLS 1.2 as well is sent alone (a TLS 1.2 server would take a change_cipher_spec before its
    // ServerHello for an error); after a HelloRetryRequest, which only a TLS 1.3 server sends, it goes before the second hello
    let config = ClientConfig::new(crate::x509::TrustStore::empty()).danger_disable_verification();
    let mut c = ClientConnection::start("example.com", &config, Zeroizing::new([7u8; 32]), &RANDOM, &SESSION);
    let r1 = records(&take_output(&mut c));
    assert_eq!(r1.iter().map(|r| r.0).collect::<Vec<_>>(), vec![RT_HANDSHAKE]);
    let retry = Retry::to(GROUP_SECP256R1);
    feed(&mut c, &retry.record()).expect("the retry is accepted");
    let r2 = records(&take_output(&mut c));
    assert_eq!(r2.iter().map(|r| r.0).collect::<Vec<_>>(), vec![RT_CHANGE_CIPHER_SPEC, RT_HANDSHAKE]);
}

