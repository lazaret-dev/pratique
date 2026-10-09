//! Tests of the TLS server: against this crate's client over real sockets, then the server's own handling of
//! hellos and records that are wrong. (Against programs that are not ours, see `interop`.)

use super::messages::*;
use super::pki::{CertSpec, TestPki};
use super::server::*;
use super::suite::*;
use crate::crypto::sha2::HashAlg;
use super::*;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Serves one connection on a loopback port: accepts, completes the handshake and hands the stream to `handler`.
fn serve_one<T: Send + 'static>(
    config: ServerConfig,
    handler: impl FnOnce(ServerStream<TcpStream>) -> T + Send + 'static,
) -> (u16, JoinHandle<Result<T>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        let stream = ServerStream::accept(socket, &config)?;
        Ok(handler(stream))
    });
    (port, handle)
}

fn dial(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.set_write_timeout(Some(TIMEOUT)).unwrap();
    s
}

/// Connects and sends the client's Finished, which `TlsStream::connect` holds back until the first request (a
/// server cannot finish its side of the handshake without it).
fn connect(port: u16, host: &str, config: &ClientConfig) -> Result<TlsStream<TcpStream>> {
    let mut stream = TlsStream::connect(dial(port), host, config)?;
    stream.flush()?;
    Ok(stream)
}

fn setup(names: &[&str]) -> (ServerConfig, ClientConfig) {
    let (server, pki) = ServerConfig::for_names(names).unwrap();
    let client = ClientConfig::new(pki.trust_store());
    (server, client)
}

/// Reads until end of file (the peer's close_notify).
fn read_to_end(s: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    s.read_to_end(&mut out)?;
    Ok(out)
}

/// A recognisable byte for position `i`.
fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31).wrapping_add(seed) ^ (i >> 8)) as u8).collect()
}

// ------------------------------------------------------------------------------------------------ the happy path

#[test]
fn a_client_connects_to_the_server_with_every_suite_and_group() {
    for suite in Suite::ALL {
        for group in [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1] {
            let (server, client) = setup(&["server.test"]);
            let server = server.with_suites(&[suite]).with_groups(&[group]);
            let (port, handle) = serve_one(server, move |mut s| {
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).unwrap();
                s.write_all(&buf.to_ascii_uppercase()).unwrap();
                s.flush().unwrap();
                (s.cipher_suite(), s.group(), s.server_name().map(str::to_string))
            });
            let mut c = connect(port, "server.test", &client).unwrap_or_else(|e| panic!("{suite:?} {group:#x}: {e}"));
            assert_eq!(c.cipher_suite(), Some(suite));
            c.write_all(b"hello").unwrap();
            let mut reply = [0u8; 5];
            c.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"HELLO");
            let (got_suite, got_group, name) = handle.join().unwrap().unwrap();
            assert_eq!(got_suite, Some(suite));
            // a group the client did not send a share for costs a HelloRetryRequest, and works
            assert_eq!(got_group, Some(group));
            assert_eq!(name.as_deref(), Some("server.test"));
        }
    }
}

/// The RSA test keys of `crypto::rsa_sign` (PKCS#1 DER), by size.
fn rsa_test_key(bits: usize) -> crate::sign::SigningKey {
    let line = include_str!("../../tests/data/rsa_signing_keys.txt")
        .lines()
        .find(|l| l.starts_with(&format!("{bits} ")))
        .expect("a key of that size");
    let der = crate::util::unhex(line.split(' ').nth(1).unwrap());
    crate::sign::RsaSigningKey::from_pkcs1_der(&der).unwrap().into()
}

#[test]
fn a_client_connects_whatever_kind_of_key_the_server_and_its_root_have() {
    use super::pki::KeyPair;
    use crate::crypto::ecdsa::Curve;
    let kinds = || -> Vec<(&'static str, KeyPair)> {
        vec![
            ("Ed25519", KeyPair::generate().unwrap()),
            ("ECDSA P-256", KeyPair::generate_ecdsa(Curve::P256).unwrap()),
            ("ECDSA P-384", KeyPair::generate_ecdsa(Curve::P384).unwrap()),
            ("RSA-2048", KeyPair::from_key(rsa_test_key(2048))),
            ("RSA-3072", KeyPair::from_key(rsa_test_key(3072))),
        ]
    };
    for (root_name, root_key) in kinds() {
        for (leaf_name, leaf_key) in kinds() {
            let pki = TestPki::with_keys(CertSpec::server(&["server.test"]), &root_key, leaf_key);
            let client = ClientConfig::new(pki.trust_store());
            let (port, handle) = serve_one(ServerConfig::from_pki(&pki), |mut s| {
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).unwrap();
                s.write_all(&buf).unwrap();
                s.flush().unwrap();
            });
            let mut c = connect(port, "server.test", &client).unwrap_or_else(|e| panic!("root {root_name}, leaf {leaf_name}: {e}"));
            c.write_all(b"ping").unwrap();
            c.flush().unwrap();
            let mut back = [0u8; 4];
            c.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"ping", "root {root_name}, leaf {leaf_name}");
            handle.join().unwrap().unwrap();
        }
    }
}

#[test]
fn the_server_picks_the_alpn_protocol_by_its_own_preference() {
    let cases: [(&[&str], &[&str], Option<&str>); 5] = [
        (&["h2", "http/1.1"], &["http/1.1", "h2"], Some("h2")),
        (&["http/1.1", "h2"], &["h2", "http/1.1"], Some("http/1.1")),
        (&["h2"], &["http/1.1", "h2"], Some("h2")),
        (&["http/1.1"], &["http/1.1"], Some("http/1.1")),
        (&[], &["http/1.1"], None),
    ];
    for (server_list, client_list, expect) in cases {
        let (server, mut client) = setup(&["server.test"]);
        client.alpn_protocols = client_list.iter().map(|p| p.as_bytes().to_vec()).collect();
        let (port, handle) = serve_one(server.with_alpn(server_list), |s| s.alpn_protocol().map(|p| p.to_vec()));
        let c = connect(port, "server.test", &client).unwrap();
        assert_eq!(c.alpn_protocol(), expect.map(|p| p.as_bytes()), "{server_list:?} {client_list:?}");
        assert_eq!(handle.join().unwrap().unwrap().as_deref(), expect.map(|p| p.as_bytes()));
    }
}

#[test]
fn no_alpn_protocol_in_common_is_refused_unless_the_server_is_lenient() {
    let (server, mut client) = setup(&["server.test"]);
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (port, handle) = serve_one(server.clone().with_alpn(&["h2"]), |_| ());
    let err = connect(port, "server.test", &client).err().expect("refused").to_string();
    assert!(err.contains("alert") && err.contains("120"), "{err}");
    assert!(handle.join().unwrap().err().unwrap().to_string().contains("no_application_protocol"));

    let mut lenient = server.with_alpn(&["h2"]);
    lenient.alpn_required = false;
    let (port, handle) = serve_one(lenient, |s| s.alpn_protocol().map(|p| p.to_vec()));
    let c = connect(port, "server.test", &client).unwrap();
    assert_eq!(c.alpn_protocol(), None);
    assert_eq!(handle.join().unwrap().unwrap(), None);
}

/// Sends `up` bytes to the server, which sends back `down` bytes, in both directions at once.
fn exchange(server: ServerConfig, client: ClientConfig, up: usize, down: usize) {
    let (port, handle) = serve_one(server, move |s| {
        // read and write at the same time: with big sizes neither side may wait for the other
        let mut writer = s;
        let data = pattern(down, 7);
        let mut got = Vec::new();
        let mut buf = vec![0u8; 8192];
        while got.len() < up {
            let n = writer.read(&mut buf).unwrap();
            assert!(n > 0, "the client closed early");
            got.extend_from_slice(&buf[..n]);
        }
        writer.write_all(&data).unwrap();
        writer.flush().unwrap();
        got
    });
    let mut c = connect(port, "server.test", &client).unwrap();
    c.write_all(&pattern(up, 3)).unwrap();
    c.flush().unwrap();
    let mut back = vec![0u8; down];
    c.read_exact(&mut back).unwrap();
    assert_eq!(back, pattern(down, 7));
    assert_eq!(handle.join().unwrap().unwrap(), pattern(up, 3));
}

#[test]
fn data_goes_both_ways_in_records_of_every_size() {
    for fragment in [16384, 4000, 100, 1] {
        let (server, client) = setup(&["server.test"]);
        let size = if fragment == 1 { 3000 } else { 300_000 };
        exchange(server.with_max_fragment(fragment), client, size, size);
    }
}

#[test]
fn a_megabyte_each_way() {
    for suite in Suite::ALL {
        let (server, client) = setup(&["server.test"]);
        exchange(server.with_suites(&[suite]), client, 1 << 20, 1 << 20);
    }
}

#[test]
fn empty_and_tiny_messages_are_not_lost() {
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server, |mut s| {
        let got = read_to_end(&mut s).unwrap();
        s.write_all(&got).unwrap();
        got.len()
    });
    let mut c = connect(port, "server.test", &client).unwrap();
    c.write_all(b"").unwrap();
    c.write_all(b"a").unwrap();
    c.write_all(b"").unwrap();
    c.write_all(b"bc").unwrap();
    c.close().unwrap();
    assert_eq!(read_to_end(&mut c).unwrap(), b"abc");
    assert_eq!(handle.join().unwrap().unwrap(), 3);
}

// ------------------------------------------------------------------------------------------------ after the handshake

#[test]
fn key_updates_in_both_directions_lose_nothing() {
    for suite in Suite::ALL {
        let (server, client) = setup(&["server.test"]);
        // both sides rotate their sending keys every few records, and the server also asks the client to
        let server = server.with_suites(&[suite]).with_rekey_after_records(4);
        let client = client.with_rekey_after_records(5);
        let (port, handle) = serve_one(server, |mut s| {
            let mut buf = [0u8; 64];
            for round in 0..60u8 {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0);
                s.write_all(&buf[..n]).unwrap();
                if round % 7 == 3 {
                    s.connection_mut().send_key_update(true).unwrap();
                }
                s.flush_queued().unwrap();
            }
            read_to_end(&mut s).unwrap().len()
        });
        let mut c = connect(port, "server.test", &client).unwrap();
        for round in 0..60u8 {
            let msg = pattern(1 + round as usize, round as usize);
            c.write_all(&msg).unwrap();
            let mut back = vec![0u8; msg.len()];
            c.read_exact(&mut back).unwrap();
            assert_eq!(back, msg, "{suite:?} round {round}");
        }
        c.close().unwrap();
        assert_eq!(handle.join().unwrap().unwrap(), 0);
    }
}

#[test]
fn session_tickets_are_read_past_whenever_they_arrive() {
    for (tickets, late) in [(0, false), (1, false), (3, false), (1, true), (4, true)] {
        let (mut server, client) = setup(&["server.test"]);
        server.tickets = tickets;
        server.tickets_after_first_write = late;
        // the response is long enough to be several records, so a late ticket lands inside it
        let (port, handle) = serve_one(server.with_max_fragment(1000), |mut s| {
            let mut req = [0u8; 4];
            s.read_exact(&mut req).unwrap();
            s.write_all(&pattern(5000, 1)).unwrap();
            s.flush().unwrap();
            let mut more = [0u8; 4];
            s.read_exact(&mut more).unwrap();
            s.write_all(&pattern(10, 2)).unwrap();
        });
        let mut c = connect(port, "server.test", &client).unwrap();
        c.write_all(b"one!").unwrap();
        let mut body = vec![0u8; 5000];
        c.read_exact(&mut body).unwrap();
        assert_eq!(body, pattern(5000, 1));
        // the connection is quiet again, and usable
        assert!(c.settle(), "tickets {tickets} late {late}");
        c.write_all(b"two!").unwrap();
        let mut tail = vec![0u8; 10];
        c.read_exact(&mut tail).unwrap();
        assert_eq!(tail, pattern(10, 2));
        handle.join().unwrap().unwrap();
    }
}

#[test]
fn close_notify_ends_a_stream_in_either_direction() {
    // the server closes first
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server, |mut s| {
        s.write_all(b"bye").unwrap();
        s.close().unwrap();
        // reading after our own close_notify still works until the client's arrives
        read_to_end(&mut s).unwrap()
    });
    let mut c = connect(port, "server.test", &client).unwrap();
    assert_eq!(read_to_end(&mut c).unwrap(), b"bye");
    c.write_all(b"late").unwrap_or_default();
    c.close().unwrap();
    assert_eq!(handle.join().unwrap().unwrap(), b"late");

    // the client closes first
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server, |mut s| read_to_end(&mut s).unwrap());
    let mut c = connect(port, "server.test", &client).unwrap();
    c.write_all(b"x").unwrap();
    c.close().unwrap();
    assert_eq!(handle.join().unwrap().unwrap(), b"x");
}

#[test]
fn a_connection_cut_without_close_notify_is_an_error_for_the_server() {
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server, |mut s| {
        let mut buf = [0u8; 16];
        let first = s.read(&mut buf).unwrap();
        let second = s.read(&mut buf);
        (first, second.map_err(|e| e.kind()))
    });
    let mut c = connect(port, "server.test", &client).unwrap();
    c.write_all(b"data").unwrap();
    c.flush().unwrap();
    // drop the socket under the TLS layer: no close_notify
    let tcp = c.get_ref().try_clone().unwrap();
    std::mem::forget(c);
    tcp.shutdown(std::net::Shutdown::Both).unwrap();
    let (first, second) = handle.join().unwrap().unwrap();
    assert_eq!(first, 4);
    assert_eq!(second, Err(io::ErrorKind::UnexpectedEof));
}

// ------------------------------------------------------------------------------------------------ what the client must refuse

#[test]
fn the_client_refuses_the_wrong_name_and_the_wrong_root_and_the_server_sees_the_alert() {
    // a certificate for another name
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server, |_| ());
    let err = connect(port, "other.test", &client).err().expect("refused");
    assert!(matches!(err, Error::Verify(_)), "{err}");
    let seen = handle.join().unwrap().err().expect("the server saw a failure").to_string();
    assert!(seen.contains("alert") && seen.contains("42"), "bad_certificate expected: {seen}");

    // a root that did not sign it
    let (server, _) = setup(&["server.test"]);
    let other = TestPki::new(&["server.test"]).unwrap();
    let (port, handle) = serve_one(server, |_| ());
    assert!(connect(port, "server.test", &ClientConfig::new(other.trust_store())).is_err());
    assert!(handle.join().unwrap().is_err());

    // an expired certificate
    let now = crate::sys::now_unix();
    let expired = CertSpec { not_before: now - 20 * 86_400, not_after: now - 10 * 86_400, ..CertSpec::server(&["server.test"]) };
    let pki = TestPki::with_spec(expired).unwrap();
    let (port, handle) = serve_one(ServerConfig::from_pki(&pki), |_| ());
    assert!(connect(port, "server.test", &ClientConfig::new(pki.trust_store())).is_err());
    assert!(handle.join().unwrap().is_err());
    // and the same certificate when the client's clock is back then
    let mut earlier = ClientConfig::new(pki.trust_store());
    earlier.time_override = Some(now - 15 * 86_400);
    let (port, handle) = serve_one(ServerConfig::from_pki(&pki), |_| ());
    connect(port, "server.test", &earlier).unwrap();
    handle.join().unwrap().unwrap();
}

#[test]
fn a_certificate_for_an_ip_address_is_checked_as_one() {
    let (server, client) = setup(&["127.0.0.1"]);
    let (port, handle) = serve_one(server, |s| s.server_name().map(str::to_string));
    connect(port, "127.0.0.1", &client).unwrap();
    // an address is not sent as a server name
    assert_eq!(handle.join().unwrap().unwrap(), None);
}

#[test]
fn a_stapled_response_the_client_cannot_use_does_not_stop_a_soft_fail_handshake() {
    // the client asks for a staple by default; a response that is not an OCSP response at all
    let (server, client) = setup(&["server.test"]);
    let (port, handle) = serve_one(server.with_ocsp_staple(b"not an OCSP response"), |_| ());
    let c = connect(port, "server.test", &client);
    // soft-fail, the default: a staple that does not parse is no staple
    assert!(c.is_ok(), "{:?}", c.err());
    handle.join().unwrap().unwrap();
}

// ------------------------------------------------------------------------------------------------ the server's own checks

/// A ClientHello (the handshake message), built field by field so that a test can get any one of them wrong.
struct HelloBuilder {
    versions: Option<Vec<u16>>,
    suites: Vec<u16>,
    groups: Option<Vec<u16>>,
    shares: Vec<(u16, Vec<u8>)>,
    sig_algs: Option<Vec<u16>>,
    compression: Vec<u8>,
    session_id: Vec<u8>,
    sni: Option<&'static str>,
    alpn: Option<Vec<&'static str>>,
    extensions: bool,
    duplicate: Option<u16>,
    trailing: Vec<u8>,
    extra: Vec<(u16, Vec<u8>)>,
    legacy_version: u16,
    no_key_share: bool,
}

impl HelloBuilder {
    fn new() -> HelloBuilder {
        HelloBuilder {
            versions: Some(vec![VERSION_TLS13]),
            suites: vec![0x1303, 0x1301, 0x1302],
            groups: Some(vec![GROUP_X25519]),
            shares: vec![(GROUP_X25519, crate::crypto::x25519::public_key(&[9u8; 32]).to_vec())],
            sig_algs: Some(vec![0x0807]),
            compression: vec![0],
            session_id: vec![5; 32],
            sni: Some("server.test"),
            alpn: None,
            extensions: true,
            duplicate: None,
            trailing: Vec::new(),
            extra: Vec::new(),
            legacy_version: 0x0303,
            no_key_share: false,
        }
    }

    fn build(&self) -> Vec<u8> {
        let ext = |out: &mut Vec<u8>, t: u16, d: &[u8]| {
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(d);
        };
        let list16 = |items: &[u16]| {
            let mut v = ((items.len() * 2) as u16).to_be_bytes().to_vec();
            for i in items {
                v.extend_from_slice(&i.to_be_bytes());
            }
            v
        };
        let mut exts = Vec::new();
        if let Some(v) = &self.versions {
            let mut d = vec![(v.len() * 2) as u8];
            for x in v {
                d.extend_from_slice(&x.to_be_bytes());
            }
            ext(&mut exts, EXT_SUPPORTED_VERSIONS, &d);
        }
        if let Some(g) = &self.groups {
            ext(&mut exts, EXT_SUPPORTED_GROUPS, &list16(g));
        }
        if (!self.shares.is_empty() || self.groups.is_some()) && !self.no_key_share {
            let mut shares = Vec::new();
            for (g, k) in &self.shares {
                shares.extend_from_slice(&g.to_be_bytes());
                shares.extend_from_slice(&(k.len() as u16).to_be_bytes());
                shares.extend_from_slice(k);
            }
            let mut d = (shares.len() as u16).to_be_bytes().to_vec();
            d.extend(shares);
            ext(&mut exts, EXT_KEY_SHARE, &d);
        }
        if let Some(s) = &self.sig_algs {
            ext(&mut exts, EXT_SIGNATURE_ALGORITHMS, &list16(s));
        }
        if let Some(name) = self.sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut d = (entry.len() as u16).to_be_bytes().to_vec();
            d.extend(entry);
            ext(&mut exts, EXT_SERVER_NAME, &d);
        }
        if let Some(protocols) = &self.alpn {
            let mut list = Vec::new();
            for p in protocols {
                list.push(p.len() as u8);
                list.extend_from_slice(p.as_bytes());
            }
            let mut d = (list.len() as u16).to_be_bytes().to_vec();
            d.extend(list);
            ext(&mut exts, EXT_ALPN, &d);
        }
        for (t, d) in &self.extra {
            ext(&mut exts, *t, d);
        }
        if let Some(t) = self.duplicate {
            ext(&mut exts, t, &[0, 0]);
            ext(&mut exts, t, &[0, 0]);
        }
        let mut body = self.legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x42; 32]);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&((self.suites.len() * 2) as u16).to_be_bytes());
        for s in &self.suites {
            body.extend_from_slice(&s.to_be_bytes());
        }
        body.push(self.compression.len() as u8);
        body.extend_from_slice(&self.compression);
        if self.extensions {
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend(exts);
        }
        body.extend_from_slice(&self.trailing);
        handshake_message(HS_CLIENT_HELLO, &body)
    }
}

fn record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut r = vec![record_type, 3, 3];
    r.extend_from_slice(&(content.len() as u16).to_be_bytes());
    r.extend_from_slice(content);
    r
}

fn fresh_server() -> ServerConnection {
    ServerConnection::new(Arc::new(ServerConfig::for_names(&["server.test"]).unwrap().0))
}

/// Feeds `bytes` to a new server and returns the result of `process` and the plaintext alert it queued, if any.
fn run_hello(config: ServerConfig, bytes: &[u8]) -> (Result<()>, Option<u8>, ServerConnection) {
    let mut conn = ServerConnection::new(Arc::new(config));
    conn.receive(bytes);
    let result = conn.process();
    let out = conn.output();
    let alert = (out.len() >= 7 && out[0] == RT_ALERT).then(|| out[6]);
    (result, alert, conn)
}

fn default_config() -> ServerConfig {
    ServerConfig::for_names(&["server.test"]).unwrap().0
}

#[test]
fn a_well_formed_hello_is_answered_with_a_flight() {
    let hello = HelloBuilder::new().build();
    let (result, alert, conn) = run_hello(default_config(), &record(RT_HANDSHAKE, &hello));
    result.unwrap();
    assert_eq!(alert, None);
    assert!(conn.is_handshaking() && conn.wants_write());
    // a ServerHello record, a compatibility change_cipher_spec (the hello had a session id), then protected records
    let out = conn.output();
    assert_eq!(out[0], RT_HANDSHAKE);
    let sh_len = u16::from_be_bytes([out[3], out[4]]) as usize;
    assert_eq!(out[5], HS_SERVER_HELLO);
    assert_eq!(&out[5 + sh_len..5 + sh_len + 6], &[RT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
    assert_eq!(out[5 + sh_len + 6], RT_APPLICATION_DATA);
    // no session id, no change_cipher_spec
    let mut b = HelloBuilder::new();
    b.session_id.clear();
    let (result, _, conn) = run_hello(default_config(), &record(RT_HANDSHAKE, &b.build()));
    result.unwrap();
    let sh_len = u16::from_be_bytes([conn.output()[3], conn.output()[4]]) as usize;
    assert_eq!(conn.output()[5 + sh_len], RT_APPLICATION_DATA);
}

#[test]
fn a_hello_that_is_wrong_is_refused_with_the_alert_that_says_why() {
    type Edit = fn(&mut HelloBuilder);
    let cases: [(&str, Edit, u8, &str); 23] = [
        ("no supported_versions", |b| b.versions = None, 70, "protocol_version"),
        ("only TLS 1.2", |b| b.versions = Some(vec![0x0303]), 70, "protocol_version"),
        ("no extensions at all", |b| b.extensions = false, 70, "protocol_version"),
        ("no cipher suite in common", |b| b.suites = vec![0x1304, 0xc02f], 40, "no cipher suite"),
        ("no signature_algorithms", |b| b.sig_algs = None, 109, "missing_extension"),
        ("no Ed25519", |b| b.sig_algs = Some(vec![0x0403, 0x0804]), 40, "no certificate whose signatures"),
        ("no group in common", |b| { b.groups = Some(vec![0x001e]); b.shares = vec![(0x001e, vec![1; 56])]; }, 40, "no key exchange group"),
        ("compression", |b| b.compression = vec![0, 1], 47, "compression"),
        ("no null compression", |b| b.compression = vec![1], 47, "compression"),
        ("a session id of 33 bytes", |b| b.session_id = vec![1; 33], 47, "session id"),
        ("two key shares for one group", |b| b.shares.push((GROUP_X25519, vec![1; 32])), 47, "two key shares"),
        ("a duplicate extension", |b| b.duplicate = Some(0x4141), 47, "duplicate"),
        ("data after the extensions", |b| b.trailing = vec![0], 50, "trailing"),
        ("a short X25519 share", |b| b.shares = vec![(GROUP_X25519, vec![1; 31])], 47, "not 32 bytes"),
        ("an all-zero X25519 share", |b| b.shares = vec![(GROUP_X25519, vec![0; 32])], 47, "all-zero"),
        ("a P-256 share that is not on the curve", |b| { b.groups = Some(vec![GROUP_SECP256R1]); b.shares = vec![(GROUP_SECP256R1, vec![4; 65])]; }, 47, "not a valid point"),
        ("an empty ALPN name", |b| b.alpn = Some(vec![""]), 50, "empty ALPN"),
        // what tlsfuzzer found (BACKLOG B-114)
        ("SSL 3.0 in legacy_version", |b| b.legacy_version = 0x0300, 70, "legacy_version"),
        ("an SSL 2 legacy_version", |b| b.legacy_version = 0x0002, 70, "legacy_version"),
        ("supported_groups without key_share", |b| b.no_key_share = true, 109, "not both there"),
        ("key_share without supported_groups", |b| b.groups = None, 109, "not both there"),
        ("neither, and no PSK", |b| { b.groups = None; b.shares.clear(); }, 109, "not both there"),
        ("a share for a group of ours that supported_groups does not list", |b| b.groups = Some(vec![GROUP_SECP256R1]), 47, "does not list"),
    ];
    for (name, edit, alert_wanted, text) in cases {
        let mut b = HelloBuilder::new();
        edit(&mut b);
        let (result, alert, conn) = run_hello(default_config(), &record(RT_HANDSHAKE, &b.build()));
        let err = result.err().unwrap_or_else(|| panic!("{name}: accepted")).to_string();
        assert!(err.contains(text), "{name}: {err}");
        assert_eq!(alert, Some(alert_wanted), "{name}: {err}");
        assert!(conn.is_failed(), "{name}");
        // and a dead connection stays dead
        let mut conn = conn;
        assert!(conn.process().is_err());
    }
}

#[test]
fn things_that_are_not_a_hello_are_refused() {
    let hello = HelloBuilder::new().build();
    let cases: Vec<(&str, Vec<u8>, u8)> = vec![
        ("an HTTP request", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), 70),
        ("application data first", record(RT_APPLICATION_DATA, &[1, 2, 3]), 10),
        ("a Finished first", record(RT_HANDSHAKE, &handshake_message(HS_FINISHED, &[0; 32])), 10),
        ("an empty handshake record", record(RT_HANDSHAKE, &[]), 10),
        ("a change_cipher_spec first", record(RT_CHANGE_CIPHER_SPEC, &[1]), 10),
        ("a record that is too long", [&[RT_HANDSHAKE, 3, 3][..], &(MAX_PLAINTEXT as u16 + 1).to_be_bytes()[..]].concat(), 22),
        ("a ServerHello", record(RT_HANDSHAKE, &handshake_message(HS_SERVER_HELLO, &[0; 40])), 10),
        ("a hello and then more in the same record", record(RT_HANDSHAKE, &[hello.clone(), handshake_message(HS_FINISHED, &[0; 32])].concat()), 10),
    ];
    for (name, bytes, alert_wanted) in cases {
        let (result, alert, _) = run_hello(default_config(), &bytes);
        assert!(result.is_err(), "{name}");
        assert_eq!(alert, Some(alert_wanted), "{name}: {:?}", result.err());
    }
    // a fatal alert from the client is an error that is not answered
    let (result, alert, conn) = run_hello(default_config(), &record(RT_ALERT, &[2, 40]));
    assert!(matches!(result, Err(Error::Alert(2, 40))));
    assert_eq!(alert, None);
    assert!(conn.is_failed() && !conn.wants_write());
}

#[test]
fn a_hello_split_across_records_and_reads_is_put_together() {
    let hello = HelloBuilder::new().build();
    // two records, then one byte at a time
    let (a, b) = hello.split_at(37);
    let wire = [record(RT_HANDSHAKE, a), record(RT_HANDSHAKE, b)].concat();
    let mut conn = fresh_server();
    for byte in &wire {
        conn.receive(std::slice::from_ref(byte));
        conn.process().unwrap();
    }
    assert!(conn.wants_write() && conn.is_handshaking());
}

#[test]
fn a_hello_retry_request_asks_for_a_group_and_the_second_hello_is_checked() {
    let config = default_config().with_groups(&[GROUP_SECP256R1]);
    // the client lists P-256 but sent a share for X25519 only
    let mut first = HelloBuilder::new();
    first.groups = Some(vec![GROUP_X25519, GROUP_SECP256R1]);
    let mut conn = ServerConnection::new(Arc::new(config.clone()));
    conn.receive(&record(RT_HANDSHAKE, &first.build()));
    conn.process().unwrap();
    // a HelloRetryRequest and a change_cipher_spec, nothing protected
    let out = conn.output().to_vec();
    assert_eq!(out[5], HS_SERVER_HELLO);
    assert_eq!(&out[11..43], &HELLO_RETRY_REQUEST_RANDOM);
    let n = out.len();
    conn.consume_output(n);
    assert!(conn.is_handshaking() && conn.group().is_none());

    // a second hello that changes the session id is refused
    let (_, p256_public) = crate::crypto::ecdh::generate(crate::crypto::ecdsa::Curve::P256).unwrap();
    let mut second = HelloBuilder::new();
    second.groups = Some(vec![GROUP_X25519, GROUP_SECP256R1]);
    second.shares = vec![(GROUP_SECP256R1, p256_public.clone())];
    let mut changed = HelloBuilder::new();
    changed.groups = second.groups.clone();
    changed.shares = second.shares.clone();
    changed.session_id = vec![6; 32];
    let mut conn2 = ServerConnection::new(Arc::new(config.clone()));
    conn2.receive(&record(RT_HANDSHAKE, &first.build()));
    conn2.process().unwrap();
    conn2.receive(&record(RT_HANDSHAKE, &changed.build()));
    assert!(conn2.process().err().unwrap().to_string().contains("changed what the first said"));

    // a second hello with the share for the wrong group is refused too
    let mut wrong = HelloBuilder::new();
    wrong.groups = second.groups.clone();
    let mut conn3 = ServerConnection::new(Arc::new(config.clone()));
    conn3.receive(&record(RT_HANDSHAKE, &first.build()));
    conn3.process().unwrap();
    conn3.receive(&record(RT_HANDSHAKE, &wrong.build()));
    assert!(conn3.process().err().unwrap().to_string().contains("exactly the key share"));

    // the right second hello gets a flight
    let mut conn4 = ServerConnection::new(Arc::new(config.clone()));
    conn4.receive(&record(RT_HANDSHAKE, &first.build()));
    conn4.process().unwrap();
    let n = conn4.output().len();
    conn4.consume_output(n);
    conn4.receive(&record(RT_HANDSHAKE, &second.build()));
    conn4.process().unwrap();
    assert_eq!(conn4.group(), Some(GROUP_SECP256R1));
    assert!(conn4.wants_write());

    // a hello that still has no usable share after a retry is refused, not retried again
    let mut conn5 = ServerConnection::new(Arc::new(config));
    conn5.receive(&record(RT_HANDSHAKE, &first.build()));
    conn5.process().unwrap();
    conn5.receive(&record(RT_HANDSHAKE, &first.build()));
    assert!(conn5.process().is_err());
}

/// What a client derives from the server's first flight, and the messages in it.
struct Flight {
    suite: Suite,
    /// the client's handshake write key
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
    handshake_secret: Vec<u8>,
    /// the transcript through the server's Finished
    transcript: Vec<u8>,
    messages: Vec<Vec<u8>>,
    server_hello: Vec<u8>,
}

/// Reads the server's flight (`out`, the answer to `hello_msg`) as a client holding `client_private` would.
fn read_flight(suite: Suite, client_private: &[u8; 32], hello_msg: &[u8], out: &[u8]) -> Flight {
    let sh_len = u16::from_be_bytes([out[3], out[4]]) as usize;
    let server_hello = out[5..5 + sh_len].to_vec();
    let sh = parse_server_hello(&server_hello[4..]).unwrap();
    assert_eq!(sh.cipher_suite, suite.id());
    let (group, server_public) = sh.key_share.unwrap();
    assert_eq!(group, GROUP_X25519);
    let alg = suite.hash();
    let shared = crate::crypto::x25519::x25519(client_private, server_public.as_slice().try_into().unwrap());
    let early = hkdf_extract(alg, &[], &vec![0u8; alg.output_len()]);
    let derived = derive_secret(alg, &early, "derived", &alg.digest(&[]));
    let handshake_secret = hkdf_extract(alg, &derived, &shared);
    let mut transcript = hello_msg.to_vec();
    transcript.extend_from_slice(&server_hello);
    let s_hs = derive_secret(alg, &handshake_secret, "s hs traffic", &alg.digest(&transcript));
    let c_hs = derive_secret(alg, &handshake_secret, "c hs traffic", &alg.digest(&transcript));
    let mut cipher = RecordCipher::new(suite, &s_hs);
    // the protected records: one handshake message each (after the compatibility change_cipher_spec)
    let mut rest = &out[5 + sh_len + 6..];
    let mut messages = Vec::new();
    while !rest.is_empty() {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let header: [u8; 5] = rest[..5].try_into().unwrap();
        let (t, plain) = cipher.decrypt(&header, &rest[5..5 + len]).unwrap();
        assert_eq!(t, RT_HANDSHAKE);
        messages.push(plain);
        rest = &rest[5 + len..];
    }
    for m in &messages {
        transcript.extend_from_slice(m);
    }
    Flight { suite, c_hs, s_hs, handshake_secret, transcript, messages, server_hello }
}

impl Flight {
    /// A Finished message from the client, with `verify_data` as given or the correct one.
    fn client_finished_record(&self, verify_data: Option<Vec<u8>>) -> Vec<u8> {
        let alg = self.suite.hash();
        let key = expand_label(alg, &self.c_hs, "finished", &[], alg.output_len());
        let data = verify_data.unwrap_or_else(|| hmac(alg, &key, &alg.digest(&self.transcript)));
        RecordCipher::new(self.suite, &self.c_hs).encrypt(RT_HANDSHAKE, &handshake_message(HS_FINISHED, &data))
    }

    fn application_secrets(&self) -> (Vec<u8>, Vec<u8>) {
        let alg = self.suite.hash();
        let zeros = vec![0u8; alg.output_len()];
        let derived = derive_secret(alg, &self.handshake_secret, "derived", &alg.digest(&[]));
        let master = hkdf_extract(alg, &derived, &zeros);
        let hash = alg.digest(&self.transcript);
        (derive_secret(alg, &master, "c ap traffic", &hash), derive_secret(alg, &master, "s ap traffic", &hash))
    }
}

const CLIENT_PRIVATE: [u8; 32] = [9u8; 32];

/// A server that has answered a hello with `HelloBuilder`'s default key share (the public key of `CLIENT_PRIVATE`).
fn first_flight(config: ServerConfig, builder: &HelloBuilder) -> (ServerConnection, Flight) {
    let hello = builder.build();
    let suite = *config.suites.first().unwrap();
    let mut conn = ServerConnection::new(Arc::new(config));
    conn.receive(&record(RT_HANDSHAKE, &hello));
    conn.process().unwrap();
    let out = conn.output().to_vec();
    conn.consume_output(out.len());
    let flight = read_flight(suite, &CLIENT_PRIVATE, &hello, &out);
    (conn, flight)
}

#[test]
fn the_server_flight_has_the_shape_the_rfc_gives_it() {
    let mut b = HelloBuilder::new();
    b.alpn = Some(vec!["http/1.1", "h2"]);
    let config = default_config().with_suites(&[Suite::Aes128GcmSha256]).with_alpn(&["h2"]);
    let (_, flight) = first_flight(config, &b);
    let sh = parse_server_hello(&flight.server_hello[4..]).unwrap();
    assert_eq!(sh.session_id, vec![5; 32]);
    assert_eq!(sh.selected_version, Some(VERSION_TLS13));
    assert_eq!(sh.compression, 0);
    let kinds: Vec<u8> = flight.messages.iter().map(|m| m[0]).collect();
    assert_eq!(kinds, [HS_ENCRYPTED_EXTENSIONS, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_FINISHED]);
    assert_eq!(parse_encrypted_extensions(&flight.messages[0][4..], true, true).unwrap(), Some(b"h2".to_vec()));
    let certs = parse_certificate(&flight.messages[1][4..], false).unwrap();
    assert_eq!(certs.chain.len(), 1);

    // CertificateVerify: a signature by the certificate's key over the transcript through the Certificate
    let alg = flight.suite.hash();
    let mut through_certificate = flight.transcript[..flight.transcript.len() - flight.messages[2].len() - flight.messages[3].len()].to_vec();
    let (scheme, signature) = parse_certificate_verify(&flight.messages[2][4..]).unwrap();
    assert_eq!(scheme, 0x0807);
    let leaf = crate::x509::Certificate::from_der(&certs.chain[0]).unwrap();
    super::signature::verify_tls13_signature(&leaf, scheme, &server_certificate_verify_content(&alg.digest(&through_certificate)), &signature).unwrap();
    // Finished: the HMAC of the transcript through CertificateVerify
    through_certificate.extend_from_slice(&flight.messages[2]);
    let key = expand_label(alg, &flight.s_hs, "finished", &[], alg.output_len());
    assert_eq!(&flight.messages[3][4..], &hmac(alg, &key, &alg.digest(&through_certificate))[..]);
}

#[test]
fn a_correct_client_finished_completes_the_handshake_and_data_flows_under_the_application_keys() {
    for suite in Suite::ALL {
        let config = default_config().with_suites(&[suite]).with_tickets(2);
        let (mut conn, flight) = first_flight(config, &HelloBuilder::new());
        conn.receive(&flight.client_finished_record(None));
        conn.process().unwrap();
        assert!(conn.is_established() && !conn.is_handshaking());
        assert_eq!(conn.cipher_suite(), Some(suite));
        let (c_ap, s_ap) = flight.application_secrets();

        // two tickets, under the server application keys
        let out = conn.output().to_vec();
        conn.consume_output(out.len());
        let mut reader = RecordCipher::new(suite, &s_ap);
        let mut rest = &out[..];
        let mut kinds = Vec::new();
        while !rest.is_empty() {
            let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            let (t, plain) = reader.decrypt(&rest[..5].try_into().unwrap(), &rest[5..5 + len]).unwrap();
            assert_eq!(t, RT_HANDSHAKE);
            kinds.push(plain[0]);
            rest = &rest[5 + len..];
        }
        assert_eq!(kinds, [HS_NEW_SESSION_TICKET, HS_NEW_SESSION_TICKET]);

        // data from the client arrives, data from the server leaves, both under the application keys
        let mut writer = RecordCipher::new(suite, &c_ap);
        conn.receive(&writer.encrypt(RT_APPLICATION_DATA, b"request"));
        conn.process().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read_plaintext(&mut buf);
        assert_eq!(&buf[..n], b"request");
        assert_eq!(conn.write_plaintext(b"response").unwrap(), 8);
        let out = conn.output().to_vec();
        let (t, plain) = reader.decrypt(&out[..5].try_into().unwrap(), &out[5..]).unwrap();
        assert_eq!((t, plain.as_slice()), (RT_APPLICATION_DATA, &b"response"[..]));

        // and the client's keys are not the handshake keys any more
        let mut late = RecordCipher::new(suite, &flight.c_hs);
        let mut conn2 = conn;
        conn2.receive(&late.encrypt(RT_APPLICATION_DATA, b"x"));
        assert!(conn2.process().err().unwrap().to_string().contains("bad_record_mac"));
    }
}

#[test]
fn an_alert_is_one_record_even_when_records_are_one_byte() {
    // OpenSSL found this: close_notify split in two ("invalid alert"); RFC 8446 section 5.1 forbids it
    let suite = Suite::Aes128GcmSha256;
    let (mut conn, flight) = first_flight(default_config().with_suites(&[suite]).with_tickets(0).with_max_fragment(1), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    conn.write_plaintext(b"ab").unwrap();
    conn.send_close_notify();
    let out = conn.output().to_vec();
    let (_, s_ap) = flight.application_secrets();
    let mut reader = RecordCipher::new(suite, &s_ap);
    let mut rest = &out[..];
    let mut records = Vec::new();
    while !rest.is_empty() {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        records.push(reader.decrypt(&rest[..5].try_into().unwrap(), &rest[5..5 + len]).unwrap());
        rest = &rest[5 + len..];
    }
    // the data in two records of one byte, then the whole alert in one
    assert_eq!(records, [(RT_APPLICATION_DATA, vec![b'a']), (RT_APPLICATION_DATA, vec![b'b']), (RT_ALERT, vec![1, 0])]);
}

#[test]
fn a_wrong_client_finished_is_refused_with_decrypt_error_and_a_damaged_one_with_bad_record_mac() {
    // the right record, but a MAC over something else
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let mut wrong = hmac(HashAlg::Sha256, &[1; 32], b"not the transcript");
    wrong.truncate(32);
    conn.receive(&flight.client_finished_record(Some(wrong)));
    let err = conn.process().err().expect("refused").to_string();
    assert!(err.contains("decrypt_error"), "{err}");
    assert!(conn.is_failed() && !conn.is_established());
    // the fatal alert is queued under the keys the server writes with, and says decrypt_error (51)
    let (_, s_ap) = flight.application_secrets();
    let out = conn.output().to_vec();
    let (t, alert) = RecordCipher::new(Suite::Aes128GcmSha256, &s_ap).decrypt(&out[..5].try_into().unwrap(), &out[5..]).unwrap();
    assert_eq!((t, alert.as_slice()), (RT_ALERT, &[2u8, 51][..]));

    // a correct Finished with one bit of the record changed, wherever
    let (_, flight2) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let good = flight2.client_finished_record(None);
    for i in 0..good.len() {
        let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
        let mut damaged = flight.client_finished_record(None);
        damaged[i] ^= 0x10;
        conn.receive(&damaged);
        // a damaged header may leave the record incomplete or oversized instead of failing at once
        let result = conn.process();
        assert!(result.is_err() || (!conn.is_established() && conn.is_handshaking()), "byte {i} changed and the handshake finished");
    }
}

#[test]
fn a_finished_in_the_wrong_place_and_other_wrong_messages_are_refused() {
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    // a second ClientHello where the Finished belongs
    let mut cipher = RecordCipher::new(Suite::Aes128GcmSha256, &flight.c_hs);
    conn.receive(&cipher.encrypt(RT_HANDSHAKE, &HelloBuilder::new().build()));
    assert!(conn.process().err().unwrap().to_string().contains("out of order"));

    // a client Certificate we did not ask for
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let mut cipher = RecordCipher::new(Suite::Aes128GcmSha256, &flight.c_hs);
    conn.receive(&cipher.encrypt(RT_HANDSHAKE, &handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0])));
    assert!(conn.process().err().unwrap().to_string().contains("out of order"));

    // application data before the Finished
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let mut cipher = RecordCipher::new(Suite::Aes128GcmSha256, &flight.c_hs);
    conn.receive(&cipher.encrypt(RT_APPLICATION_DATA, b"early"));
    assert!(conn.process().err().unwrap().to_string().contains("non-handshake record"));
    assert!(conn.write_plaintext(b"x").is_err());

    // data after the Finished in the same record, and a Finished that is split in two records (which is allowed)
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let alg = HashAlg::Sha256;
    let key = expand_label(alg, &flight.c_hs, "finished", &[], 32);
    let finished = handshake_message(HS_FINISHED, &hmac(alg, &key, &alg.digest(&flight.transcript)));
    let mut cipher = RecordCipher::new(Suite::Aes128GcmSha256, &flight.c_hs);
    let (a, b) = finished.split_at(10);
    conn.receive(&cipher.encrypt(RT_HANDSHAKE, a));
    conn.receive(&cipher.encrypt(RT_HANDSHAKE, b));
    conn.process().unwrap();
    assert!(conn.is_established());
    let (mut conn, flight) = first_flight(default_config().with_suites(&[Suite::Aes128GcmSha256]), &HelloBuilder::new());
    let mut cipher = RecordCipher::new(Suite::Aes128GcmSha256, &flight.c_hs);
    let key = expand_label(alg, &flight.c_hs, "finished", &[], 32);
    let finished = handshake_message(HS_FINISHED, &hmac(alg, &key, &alg.digest(&flight.transcript)));
    conn.receive(&cipher.encrypt(RT_HANDSHAKE, &[finished, vec![HS_KEY_UPDATE, 0, 0, 1, 0]].concat()));
    assert!(conn.process().err().unwrap().to_string().contains("after the client Finished"));
}

/// The alert the server queued, opened with the keys it writes with at that point (after its Finished, the
/// application keys).
fn alert_sent(conn: &ServerConnection, suite: Suite, secret: &[u8]) -> Vec<u8> {
    let out = conn.output().to_vec();
    let (t, alert) = RecordCipher::new(suite, secret).decrypt(&out[..5].try_into().unwrap(), &out[5..]).unwrap();
    assert_eq!(t, RT_ALERT);
    alert
}

#[test]
fn what_tlsfuzzer_found_in_the_records_and_the_finished_is_refused_as_the_rfc_says() {
    let suite = Suite::Aes128GcmSha256;
    let config = || default_config().with_suites(&[suite]);
    let alg = suite.hash();
    let finished = |flight: &Flight| {
        let key = expand_label(alg, &flight.c_hs, "finished", &[], alg.output_len());
        handshake_message(HS_FINISHED, &hmac(alg, &key, &alg.digest(&flight.transcript)))
    };

    // a Finished padded to the largest record: the inner plaintext is over 2^14 + 1 (record_overflow, RFC 8446 5.4) ...
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    let fin = finished(&flight);
    let padding = MAX_PLAINTEXT + 256 - fin.len() - 1 - 16;
    conn.receive(&RecordCipher::new(suite, &flight.c_hs).encrypt_padded(RT_HANDSHAKE, &fin, padding));
    assert!(conn.process().err().unwrap().to_string().contains("record_overflow"));
    assert_eq!(alert_sent(&conn, suite, &flight.application_secrets().1), [2, 22]);
    // ... and one padded to exactly 2^14 + 1 is taken
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    let fin = finished(&flight);
    conn.receive(&RecordCipher::new(suite, &flight.c_hs).encrypt_padded(RT_HANDSHAKE, &fin, MAX_PLAINTEXT - fin.len()));
    conn.process().unwrap();
    assert!(conn.is_established());

    // a Finished that is not the length of the hash is a decode_error, not a decrypt_error
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    let mut long = finished(&flight)[4..].to_vec();
    long.splice(0..0, [0u8; 16]);
    conn.receive(&RecordCipher::new(suite, &flight.c_hs).encrypt(RT_HANDSHAKE, &handshake_message(HS_FINISHED, &long)));
    assert!(conn.process().err().unwrap().to_string().contains("decode_error"));
    assert_eq!(alert_sent(&conn, suite, &flight.application_secrets().1), [2, 50]);
    // and one that says it is far longer is refused at once, before its bytes come
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    conn.receive(&RecordCipher::new(suite, &flight.c_hs).encrypt(RT_HANDSHAKE, &[HS_FINISHED, 0xff, 0xff, 0xff, 0, 0]));
    assert!(conn.process().err().unwrap().to_string().contains("decode_error"));

    // an alert record with nothing in it, under the handshake keys or the application keys, is an unexpected_message
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    conn.receive(&RecordCipher::new(suite, &flight.c_hs).encrypt_padded(RT_ALERT, &[], 5));
    assert!(conn.process().err().unwrap().to_string().contains("empty alert"));
    assert_eq!(alert_sent(&conn, suite, &flight.application_secrets().1), [2, 10]);
    let (mut conn, flight) = first_flight(config().with_tickets(0), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    let (c_ap, s_ap) = flight.application_secrets();
    conn.receive(&RecordCipher::new(suite, &c_ap).encrypt(RT_ALERT, &[]));
    assert!(conn.process().err().unwrap().to_string().contains("empty alert"));
    assert_eq!(alert_sent(&conn, suite, &s_ap), [2, 10]);

    // one compatibility change_cipher_spec is skipped; a second is an unexpected_message
    let (mut conn, flight) = first_flight(config(), &HelloBuilder::new());
    conn.receive(&record(RT_CHANGE_CIPHER_SPEC, &[1]));
    conn.process().unwrap();
    conn.receive(&record(RT_CHANGE_CIPHER_SPEC, &[1]));
    assert!(conn.process().err().unwrap().to_string().contains("change_cipher_spec"));
    assert_eq!(alert_sent(&conn, suite, &flight.application_secrets().1), [2, 10]);

    // a client that cannot read our flight may say so in the clear: its alert ends the handshake, unanswered
    let (mut conn, _) = first_flight(config(), &HelloBuilder::new());
    conn.receive(&record(RT_ALERT, &[2, 48]));
    assert!(matches!(conn.process(), Err(Error::Alert(2, 48))));
    assert!(conn.is_failed() && !conn.wants_write());
    // (once the handshake is over, only protected alerts count)
    let (mut conn, flight) = first_flight(config().with_tickets(0), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    conn.receive(&record(RT_ALERT, &[2, 48]));
    assert!(conn.process().err().unwrap().to_string().contains("unprotected record"));

    // TLS 1.0 in legacy_version is taken (only SSL 3.0 and older are refused)
    let mut b = HelloBuilder::new();
    b.legacy_version = 0x0301;
    let (result, _, _) = run_hello(config(), &record(RT_HANDSHAKE, &b.build()));
    result.unwrap();
}

#[test]
fn a_second_client_hello_may_not_offer_early_data_again() {
    // tlsfuzzer's test-tls13-0rtt-garbage found early data skipped after a retry (RFC 8446 section 4.2.10)
    let config = default_config().with_groups(&[GROUP_SECP256R1]);
    let mut first = HelloBuilder::new();
    first.groups = Some(vec![GROUP_X25519, GROUP_SECP256R1]);
    first.extra = vec![(EXT_EARLY_DATA, Vec::new())];
    let (_, p256_public) = crate::crypto::ecdh::generate(crate::crypto::ecdsa::Curve::P256).unwrap();
    let mut second = HelloBuilder::new();
    second.groups = first.groups.clone();
    second.shares = vec![(GROUP_SECP256R1, p256_public)];
    for (again, wanted) in [(true, Some("early_data in the second ClientHello")), (false, None)] {
        let mut conn = ServerConnection::new(Arc::new(config.clone()));
        conn.receive(&record(RT_HANDSHAKE, &first.build()));
        conn.process().unwrap();
        let n = conn.output().len();
        conn.consume_output(n);
        // early data sent with the first hello, before the second, is skipped
        conn.receive(&record(RT_APPLICATION_DATA, &[0x55; 100]));
        conn.process().unwrap();
        let mut hello = HelloBuilder::new();
        hello.groups = second.groups.clone();
        hello.shares = second.shares.clone();
        if again {
            hello.extra = first.extra.clone();
        }
        conn.receive(&record(RT_HANDSHAKE, &hello.build()));
        match (conn.process(), wanted) {
            (Err(e), Some(text)) => assert!(e.to_string().contains(text), "{e}"),
            (Ok(()), None) => assert_eq!(conn.group(), Some(GROUP_SECP256R1)),
            (r, w) => panic!("{r:?} where {w:?} was wanted"),
        }
        if !again {
            // and after it, a record that does not open is an error, not more early data
            conn.receive(&record(RT_APPLICATION_DATA, &[0x55; 100]));
            assert!(conn.process().is_err());
        }
    }
}

#[test]
fn a_key_update_from_the_client_is_followed_and_answered_when_asked_for() {
    let suite = Suite::Aes256GcmSha384;
    let (mut conn, flight) = first_flight(default_config().with_suites(&[suite]).with_tickets(0), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    let (c_ap, s_ap) = flight.application_secrets();
    let mut client_write = RecordCipher::new(suite, &c_ap);
    let mut server_read = RecordCipher::new(suite, &s_ap);

    // update_requested: the server answers with its own KeyUpdate under its old key, then uses new keys
    conn.receive(&client_write.encrypt(RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[1])));
    client_write = client_write.next_generation();
    conn.receive(&client_write.encrypt(RT_APPLICATION_DATA, b"after the update"));
    conn.process().unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read_plaintext(&mut buf);
    assert_eq!(&buf[..n], b"after the update");
    conn.write_plaintext(b"reply").unwrap();
    let out = conn.output().to_vec();
    let len1 = u16::from_be_bytes([out[3], out[4]]) as usize;
    let (t, plain) = server_read.decrypt(&out[..5].try_into().unwrap(), &out[5..5 + len1]).unwrap();
    assert_eq!((t, plain.as_slice()), (RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[0])[..]));
    server_read = server_read.next_generation();
    let rest = &out[5 + len1..];
    let (t, plain) = server_read.decrypt(&rest[..5].try_into().unwrap(), &rest[5..]).unwrap();
    assert_eq!((t, plain.as_slice()), (RT_APPLICATION_DATA, &b"reply"[..]));

    // malformed KeyUpdates (a request_update other than 0 or 1 is an illegal_parameter, RFC 8446 section 4.6.3)
    for (bad, wanted) in [(vec![HS_KEY_UPDATE, 0, 0, 2, 1, 0], "decode_error"), (vec![HS_KEY_UPDATE, 0, 0, 1, 2], "illegal_parameter"), (vec![HS_KEY_UPDATE, 0, 0, 0], "decode_error")] {
        let (mut conn, flight) = first_flight(default_config().with_suites(&[suite]).with_tickets(0), &HelloBuilder::new());
        conn.receive(&flight.client_finished_record(None));
        conn.process().unwrap();
        let (c_ap, _) = flight.application_secrets();
        conn.receive(&RecordCipher::new(suite, &c_ap).encrypt(RT_HANDSHAKE, &bad));
        let err = conn.process().err().unwrap_or_else(|| panic!("{bad:?} taken")).to_string();
        assert!(err.contains(wanted), "{bad:?}: {err}");
    }
    // a KeyUpdate split over two records with application data between them (RFC 8446 section 5.1, tlsfuzzer's
    // test-tls13-keyupdate)
    let (mut conn, flight) = first_flight(default_config().with_suites(&[suite]).with_tickets(0), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    let mut w = RecordCipher::new(suite, &flight.application_secrets().0);
    conn.receive(&w.encrypt(RT_HANDSHAKE, &[HS_KEY_UPDATE, 0, 0, 1]));
    conn.receive(&w.encrypt(RT_APPLICATION_DATA, b"between"));
    conn.receive(&w.encrypt(RT_HANDSHAKE, &[0]));
    assert!(conn.process().err().unwrap().to_string().contains("inside a handshake message"));
    // and anything else after the handshake
    let (mut conn, flight) = first_flight(default_config().with_suites(&[suite]).with_tickets(0), &HelloBuilder::new());
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    let (c_ap, _) = flight.application_secrets();
    conn.receive(&RecordCipher::new(suite, &c_ap).encrypt(RT_HANDSHAKE, &handshake_message(HS_NEW_SESSION_TICKET, &[0; 12])));
    assert!(conn.process().err().unwrap().to_string().contains("unexpected post-handshake"));
}

#[test]
fn random_and_damaged_input_never_panics_the_server() {
    use crate::fuzz::{mutate, random_up_to, run, Rng};
    let valid = record(RT_HANDSHAKE, &HelloBuilder::new().build());
    let mut b = HelloBuilder::new();
    b.groups = Some(vec![GROUP_SECP256R1, GROUP_X25519]);
    b.alpn = Some(vec!["h2", "http/1.1"]);
    let valid2 = record(RT_HANDSHAKE, &b.build());
    let config = Arc::new(default_config());
    run("tls server input", 3000, |rng: &mut Rng| {
        let bytes = match rng.below(3) {
            0 => random_up_to(rng, 300),
            1 => mutate(rng, &valid),
            _ => mutate(rng, &valid2),
        };
        let mut conn = ServerConnection::new(config.clone());
        // in pieces of random size, as a socket delivers them
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len().min(80));
            conn.receive(&rest[..n]);
            rest = &rest[n..];
            if conn.process().is_err() {
                break;
            }
        }
        let _ = conn.recv_eof();
        let mut buf = [0u8; 16];
        let _ = conn.read_plaintext(&mut buf);
    });
}

// ------------------------------------------------------------------------------------------------ B-110: certificates, client
// certificates, early data, floods

use super::certs::{CertStore, CertifiedKey};
use super::pki::{issue, KeyPair};
use crate::x509::TrustStore;

/// A root and a store of certificates under it, one per name list, the first the default.
fn store_under_one_root(name_lists: &[&[&str]]) -> (CertStore, ClientConfig) {
    let root_key = KeyPair::generate().unwrap();
    let root_spec = CertSpec::ca("pratique test root");
    let root = issue(&root_spec, &root_key, None);
    let store = CertStore::new();
    for names in name_lists {
        let k = KeyPair::generate_ecdsa(crate::crypto::ecdsa::Curve::P256).unwrap();
        let der = issue(&CertSpec::server(names), &k, Some((&root_spec.common_name, &root_key)));
        store.add(CertifiedKey::new(vec![der], k.signing_key().clone()).unwrap());
    }
    let mut trust = TrustStore::empty();
    trust.add_der(&root).unwrap();
    (store, ClientConfig::new(trust))
}

#[test]
fn the_certificate_is_the_one_for_the_name_the_client_asks_for() {
    let (store, client) = store_under_one_root(&[&["default.test"], &["a.test"], &["*.b.test"]]);
    let config = ServerConfig::with_certificates(store);
    for (sni, want) in [("a.test", "a.test"), ("x.b.test", "*.b.test"), ("default.test", "default.test")] {
        let (port, handle) = serve_one(config.clone(), |mut s| s.connection_mut().certificate().unwrap().dns_names()[0].clone());
        let mut c = connect(port, sni, &client).unwrap_or_else(|e| panic!("{sni}: {e}"));
        let _ = c.write_all(b"x");
        assert_eq!(handle.join().unwrap().unwrap(), want, "for {sni}");
    }
    // a name none is for: the default certificate, which the client refuses (it is not for that name)
    let (port, handle) = serve_one(config.clone(), |_| ());
    let err = connect(port, "unknown.test", &client).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("unknown.test") || err.to_lowercase().contains("name"), "{err}");
    let _ = handle.join();
    // a strict store refuses the name with unrecognized_name
    let (store, client) = store_under_one_root(&[&["only.test"]]);
    let (port, handle) = serve_one(ServerConfig::with_certificates(store.strict()), |_| ());
    let err = connect(port, "unknown.test", &client).err().map(|e| e.to_string()).unwrap_or_default();
    let server_err = handle.join().unwrap().err().map(|e| e.to_string()).unwrap_or_default();
    assert!(server_err.contains("unrecognized_name"), "{server_err}");
    assert!(err.contains("112") || err.contains("unrecognized_name"), "{err}");
}

#[test]
fn the_certificate_is_one_whose_signature_the_client_takes() {
    let root_key = KeyPair::generate().unwrap();
    let store = CertStore::new();
    for key in [KeyPair::generate_ecdsa(crate::crypto::ecdsa::Curve::P256).unwrap(), KeyPair::from_key(rsa_test_key(2048))] {
        let der = issue(&CertSpec::server(&["server.test"]), &key, Some(("root", &root_key)));
        store.add(CertifiedKey::new(vec![der], key.signing_key().clone()).unwrap());
    }
    let config = ServerConfig::with_certificates(store);
    for (offered, want) in [(vec![0x0804], 0x0804), (vec![0x0403, 0x0804], 0x0403), (vec![0x0805, 0x0806], 0x0805)] {
        let mut b = HelloBuilder::new();
        b.sig_algs = Some(offered.clone());
        let (_, flight) = first_flight(config.clone(), &b);
        let (scheme, _) = parse_certificate_verify(&flight.messages[2][4..]).unwrap();
        assert_eq!(scheme, want, "offered {offered:04x?}");
    }
    // nothing the keys can make: handshake_failure (the name is fine)
    let mut b = HelloBuilder::new();
    b.sig_algs = Some(vec![0x0503]);
    let (result, alert, _) = run_hello(config, &record(RT_HANDSHAKE, &b.build()));
    assert!(result.unwrap_err().to_string().contains("handshake_failure"));
    assert_eq!(alert, Some(40));
}

/// A client CA, its certificate (DER), a client certificate under it, and a TrustStore holding the CA.
fn client_ca() -> (CertifiedKey, Arc<TrustStore>) {
    let ca_key = KeyPair::generate_ecdsa(crate::crypto::ecdsa::Curve::P256).unwrap();
    let ca_spec = CertSpec::ca("pratique client CA");
    let ca = issue(&ca_spec, &ca_key, None);
    let key = KeyPair::generate_ecdsa(crate::crypto::ecdsa::Curve::P384).unwrap();
    let spec = CertSpec { common_name: "a client".into(), server_auth: false, client_auth: true, ..CertSpec::default() };
    let cert = issue(&spec, &key, Some((&ca_spec.common_name, &ca_key)));
    let mut roots = TrustStore::empty();
    roots.add_der(&ca).unwrap();
    (CertifiedKey::new(vec![cert], key.signing_key().clone()).unwrap(), Arc::new(roots))
}

/// Connects, sends four bytes and reads four back: what the client saw and what the server saw (its peer's chain).
fn client_auth_exchange(config: ServerConfig, client: &ClientConfig) -> (std::result::Result<(), String>, std::result::Result<Vec<Vec<u8>>, String>) {
    let (port, handle) = serve_one(config, |mut s| {
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).map_err(|e| e.to_string())?;
        s.write_all(&buf).map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())?;
        Ok::<_, String>(s.peer_certificates().to_vec())
    });
    let client_side = (|| -> Result<()> {
        let mut c = connect(port, "server.test", client)?;
        c.write_all(b"ping")?;
        c.flush()?;
        let mut back = [0u8; 4];
        c.read_exact(&mut back)?;
        Ok(())
    })()
    .map_err(|e| e.to_string());
    let server_side = match handle.join().unwrap() {
        Ok(inner) => inner,
        Err(e) => Err(e.to_string()),
    };
    (client_side, server_side)
}

#[test]
fn client_certificates_are_required_optional_or_refused() {
    let (server, pki) = ServerConfig::for_names(&["server.test"]).unwrap();
    let (client_cert, roots) = client_ca();
    let plain = ClientConfig::new(pki.trust_store()).with_resumption(Resumption::off());
    let with_cert = plain.clone().with_client_certificate(client_cert.clone());
    let required = server.clone().with_client_auth(ClientAuth::Required(roots.clone())).without_resumption();
    let optional = server.clone().with_client_auth(ClientAuth::Optional(roots.clone())).without_resumption();

    // a certificate under the roots: in, and the server sees the chain
    let (c, s) = client_auth_exchange(required.clone(), &with_cert);
    c.unwrap();
    assert_eq!(s.unwrap(), client_cert.chain().to_vec());
    // none, when one is required: certificate_required
    let (c, s) = client_auth_exchange(required.clone(), &plain);
    assert!(s.unwrap_err().contains("certificate_required"));
    assert!(c.unwrap_err().contains("116"), "the client hears certificate_required");
    // one under other roots: bad_certificate
    let (other, _) = client_ca();
    let (c, s) = client_auth_exchange(required.clone(), &plain.clone().with_client_certificate(other));
    assert!(s.unwrap_err().contains("bad_certificate"));
    assert!(c.unwrap_err().contains("42"));
    // optional: in without one (nothing seen), and with one (seen)
    let (c, s) = client_auth_exchange(optional.clone(), &plain);
    c.unwrap();
    assert!(s.unwrap().is_empty());
    let (c, s) = client_auth_exchange(optional, &with_cert);
    c.unwrap();
    assert_eq!(s.unwrap().len(), 1);
    // a server that does not ask: the client's certificate is never sent
    let (c, s) = client_auth_exchange(server.clone().without_resumption(), &with_cert);
    c.unwrap();
    assert!(s.unwrap().is_empty());
}

#[test]
fn a_resumed_session_keeps_the_client_certificate_it_was_made_with() {
    let (server, pki) = ServerConfig::for_names(&["server.test"]).unwrap();
    let (client_cert, roots) = client_ca();
    let config = server.with_client_auth(ClientAuth::Required(roots));
    let client = ClientConfig::new(pki.trust_store()).with_client_certificate(client_cert.clone());
    let (c, s) = client_auth_exchange(config.clone(), &client);
    c.unwrap();
    assert_eq!(s.unwrap(), client_cert.chain().to_vec());
    let (c, s) = client_auth_exchange(config.clone(), &client);
    c.unwrap();
    assert_eq!(s.unwrap(), client_cert.chain().to_vec(), "the resumed connection knows the client too");
    assert_eq!(config.resumed_count(), 1);
}

#[test]
fn a_client_certificate_verify_that_is_wrong_is_refused() {
    let (server, _) = ServerConfig::for_names(&["server.test"]).unwrap();
    let (client_cert, roots) = client_ca();
    let config = server.with_client_auth(ClientAuth::Required(roots));
    let (_, flight) = first_flight(config.clone(), &HelloBuilder::new());
    let kinds: Vec<u8> = flight.messages.iter().map(|m| m[0]).collect();
    assert_eq!(kinds, [HS_ENCRYPTED_EXTENSIONS, HS_CERTIFICATE_REQUEST, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_FINISHED]);
    let request = parse_certificate_request(&flight.messages[1][4..]).unwrap();
    assert!(request.context.is_empty() && request.signature_algorithms.contains(&0x0503));
    // the client's Certificate, then a CertificateVerify signed over the wrong transcript
    let mut list = Vec::new();
    for der in client_cert.chain() {
        list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(der);
        list.extend_from_slice(&[0, 0]);
    }
    let mut body = vec![0u8];
    body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&list);
    let certificate = handshake_message(HS_CERTIFICATE, &body);
    let signature = client_cert.key().sign_tls(0x0503, &client_certificate_verify_content(&[0u8; 32])).unwrap();
    // signed over the wrong transcript: decrypt_error; a scheme our request offers that does not go with the key (P-256
    // for a P-384 key, tlsfuzzer's test-tls13-ecdsa-in-certificate-verify): illegal_parameter
    for (scheme, wanted) in [(0x0503u16, "decrypt_error"), (0x0403, "illegal_parameter"), (0x0807, "illegal_parameter")] {
        let mut v = scheme.to_be_bytes().to_vec();
        v.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        v.extend_from_slice(&signature);
        let verify = handshake_message(HS_CERTIFICATE_VERIFY, &v);
        let (mut conn, flight) = first_flight(config.clone(), &HelloBuilder::new());
        let mut cipher = RecordCipher::new(flight.suite, &flight.c_hs);
        conn.receive(&cipher.encrypt(RT_HANDSHAKE, &certificate));
        conn.receive(&cipher.encrypt(RT_HANDSHAKE, &verify));
        let err = conn.process().unwrap_err().to_string();
        assert!(err.contains(wanted), "{scheme:#06x}: {err}");
    }
}

#[test]
fn early_data_the_server_never_accepts_is_skipped_up_to_a_limit() {
    let mut b = HelloBuilder::new();
    b.extra.push((EXT_EARLY_DATA, vec![]));
    // records under keys the server does not have, before the client's Finished: skipped
    let (mut conn, flight) = first_flight(default_config(), &b);
    let junk = record(RT_APPLICATION_DATA, &[0x55; 300]);
    conn.receive(&junk);
    conn.receive(&junk);
    conn.receive(&flight.client_finished_record(None));
    conn.process().unwrap();
    assert!(conn.is_established());
    // more than the limit: an error
    let (mut conn, _) = first_flight(default_config(), &b);
    for _ in 0..super::server::MAX_EARLY_DATA_SKIP / 16_000 + 2 {
        conn.receive(&record(RT_APPLICATION_DATA, &vec![0x55; 16_000]));
    }
    assert!(conn.process().is_err());
    // without early_data in the hello, a record that does not open is fatal at once
    let (mut conn, _) = first_flight(default_config(), &HelloBuilder::new());
    conn.receive(&junk);
    assert!(conn.process().unwrap_err().to_string().contains("bad_record_mac"));
}

#[test]
fn floods_of_key_updates_and_empty_records_are_refused() {
    let established = || {
        let (mut conn, flight) = first_flight(default_config(), &HelloBuilder::new());
        conn.receive(&flight.client_finished_record(None));
        conn.process().unwrap();
        let (c_ap, _) = flight.application_secrets();
        (conn, RecordCipher::new(flight.suite, &c_ap))
    };
    let (mut conn, mut cipher) = established();
    for i in 0..=super::server::MAX_KEY_UPDATES_IN_A_ROW {
        conn.receive(&cipher.encrypt(RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[0])));
        cipher = cipher.next_generation();
        let r = conn.process();
        if i < super::server::MAX_KEY_UPDATES_IN_A_ROW {
            r.unwrap();
        } else {
            assert!(r.unwrap_err().to_string().contains("KeyUpdates"));
        }
    }
    // data between them resets the count
    let (mut conn, mut cipher) = established();
    for _ in 0..3 * super::server::MAX_KEY_UPDATES_IN_A_ROW {
        conn.receive(&cipher.encrypt(RT_HANDSHAKE, &handshake_message(HS_KEY_UPDATE, &[0])));
        cipher = cipher.next_generation();
        conn.receive(&cipher.encrypt(RT_APPLICATION_DATA, b"x"));
        conn.process().unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(conn.read_plaintext(&mut buf), 1);
    }
    let (mut conn, mut cipher) = established();
    for _ in 0..=super::server::MAX_EMPTY_RECORDS_IN_A_ROW {
        conn.receive(&cipher.encrypt(RT_APPLICATION_DATA, &[]));
    }
    assert!(conn.process().unwrap_err().to_string().contains("empty records"));
}
