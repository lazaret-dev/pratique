//! Session resumption (B-35, B-47): the client against this crate's server over loopback sockets, and against the scripted
//! server for what a correct server never does. (Against OpenSSL: `tests/interop_openssl.rs`.)

use super::messages::*;
use super::scripted::*;
use super::server::*;
use super::session::{Scope, Session as Kept};
use crate::zeroize::Zeroizing;
use std::sync::Mutex;
use super::suite::*;
use super::*;
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(20);

/// Serves `n` connections, one after the other, with one configuration (one store of sessions): each echoes five bytes in
/// upper case and says whether it resumed.
fn serve(config: Arc<ServerConfig>, n: usize) -> (u16, JoinHandle<Vec<bool>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut resumed = Vec::new();
        for _ in 0..n {
            let (socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(TIMEOUT)).unwrap();
            let Ok(mut s) = ServerStream::accept(socket, &config) else {
                resumed.push(false);
                continue;
            };
            let mut buf = [0u8; 5];
            if s.read_exact(&mut buf).is_ok() {
                s.write_all(&buf.to_ascii_uppercase()).unwrap();
                s.flush().unwrap();
            }
            resumed.push(s.is_resumed());
            let _ = s.close();
        }
        resumed
    });
    (port, handle)
}

/// One exchange: connects, writes, reads the answer (which brings the server's tickets in), and says whether it resumed
/// and what chain it reports.
fn exchange(port: u16, host: &str, config: &ClientConfig) -> Result<(bool, Vec<Vec<u8>>)> {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut s = TlsStream::connect(socket, host, config)?;
    s.write_all(b"hello")?;
    s.flush()?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf)?;
    assert_eq!(&buf, b"HELLO");
    Ok((s.is_resumed(), s.peer_certificates().to_vec()))
}

fn setup() -> (ServerConfig, ClientConfig) {
    let (server, pki) = ServerConfig::for_names(&["server.test", "other.test"]).unwrap();
    (server, ClientConfig::new(pki.trust_store()))
}

#[test]
fn the_second_connection_resumes_with_every_suite() {
    for suite in Suite::ALL {
        let (server, client) = setup();
        let server = Arc::new(server.with_suites(&[suite]));
        let (port, handle) = serve(server.clone(), 3);
        let (resumed, chain1) = exchange(port, "server.test", &client).unwrap();
        assert!(!resumed);
        assert_eq!(client.resumption.sessions(), 1, "the server's ticket is kept");
        let (resumed, chain2) = exchange(port, "server.test", &client).unwrap();
        assert!(resumed, "{suite:?}");
        // the chain of the full handshake is reported again
        assert_eq!(chain1, chain2);
        // the resumed connection's own ticket is kept, and resumes the third
        assert_eq!(client.resumption.sessions(), 1);
        assert!(exchange(port, "server.test", &client).unwrap().0);
        assert_eq!(handle.join().unwrap(), [false, true, true]);
        assert_eq!(server.resumed_count(), 2);
    }
}

#[test]
fn a_ticket_is_offered_once_and_only_to_its_server_name() {
    let (server, client) = setup();
    let server = Arc::new(server.with_tickets(1));
    let (port, handle) = serve(server, 4);
    exchange(port, "server.test", &client).unwrap();
    // another name of the same server: no ticket for it, a full handshake (whose ticket is kept under that name)
    assert!(!exchange(port, "other.test", &client).unwrap().0);
    assert_eq!(client.resumption.sessions(), 2);
    assert!(exchange(port, "SERVER.test.", &client).unwrap().0, "the same name in another spelling");
    assert!(exchange(port, "other.test", &client).unwrap().0);
    handle.join().unwrap();
}

#[test]
fn a_server_that_does_not_know_the_ticket_makes_a_full_handshake() {
    let (server, client) = setup();
    // two servers with the same certificate and different stores: the second has never seen the first's ticket
    let first = Arc::new(server.clone().without_resumption().with_tickets(0));
    let (port, handle) = serve(Arc::new(server.clone()), 1);
    exchange(port, "server.test", &client).unwrap();
    handle.join().unwrap();
    assert_eq!(client.resumption.sessions(), 1);
    let fresh = Arc::new(ServerConfig { sessions: Some(Arc::new(Mutex::new(ServerSessions::default()))), ..server });
    let (port, handle) = serve(fresh.clone(), 1);
    assert!(!exchange(port, "server.test", &client).unwrap().0, "offered, not taken: a full handshake, checked in full");
    assert_eq!(handle.join().unwrap(), [false]);
    // and a server that resumes nothing sends tickets that lead nowhere: the client tries one and does a full handshake
    let (port, handle) = serve(first, 1);
    assert!(!exchange(port, "server.test", &client).unwrap().0);
    handle.join().unwrap();
}

#[test]
fn after_a_hello_retry_request_the_session_is_offered_again_with_a_new_binder() {
    let (server, client) = setup();
    // the client's first key share is X25519; this server takes P-256 only, so it asks again
    let server = Arc::new(server.with_groups(&[GROUP_SECP256R1]));
    let (port, handle) = serve(server, 2);
    exchange(port, "server.test", &client).unwrap();
    assert!(exchange(port, "server.test", &client).unwrap().0);
    assert_eq!(handle.join().unwrap(), [false, true]);
}

#[test]
fn a_session_of_another_hash_is_not_resumed_by_a_suite_of_this_one() {
    let (server, client) = setup();
    let (port, handle) = serve(Arc::new(server.clone().with_suites(&[Suite::Aes256GcmSha384])), 1);
    exchange(port, "server.test", &client).unwrap();
    handle.join().unwrap();
    // the same store, but only SHA-256 suites now: the ticket (of a SHA-384 suite) cannot be used
    let (port, handle) = serve(Arc::new(server.with_suites(&[Suite::Aes128GcmSha256])), 1);
    assert!(!exchange(port, "server.test", &client).unwrap().0);
    handle.join().unwrap();
}

#[test]
fn a_session_is_used_only_under_the_trust_it_was_checked_with() {
    let (server, pki) = ServerConfig::for_names(&["server.test"]).unwrap();
    let client = ClientConfig::new(pki.trust_store());
    let (port, handle) = serve(Arc::new(server), 3);
    exchange(port, "server.test", &client).unwrap();
    // the same store of sessions with another trust store (equal to the first), or verification off: not offered
    let other = ClientConfig::new(pki.trust_store()).with_resumption(client.resumption.clone());
    assert!(!exchange(port, "server.test", &other).unwrap().0);
    let unchecked = client.clone().danger_disable_verification();
    assert!(!exchange(port, "server.test", &unchecked).unwrap().0);
    handle.join().unwrap();
}

#[test]
fn a_session_is_not_used_past_its_max_age_after_the_full_handshake() {
    let (server, client) = setup();
    let now = crate::sys::now_unix();
    let at = |t: i64| ClientConfig { time_override: Some(t), ..client.clone() };
    let (port, handle) = serve(Arc::new(server), 4);
    exchange(port, "server.test", &at(now)).unwrap();
    // half an hour later: resumed, and the new ticket still rests on the check of the first connection
    assert!(exchange(port, "server.test", &at(now + 1800)).unwrap().0);
    // an hour and a second after that check: a full handshake, though the ticket (two hours) has not run out
    assert!(!exchange(port, "server.test", &at(now + 3601)).unwrap().0);
    // whose session counts from then
    assert!(exchange(port, "server.test", &at(now + 3700)).unwrap().0);
    handle.join().unwrap();
    // a max age of 0 keeps nothing
    let (server, client) = setup();
    let client = client.with_resumption(Resumption::new().max_age(0));
    let (port, handle) = serve(Arc::new(server), 2);
    exchange(port, "server.test", &client).unwrap();
    assert_eq!(client.resumption.sessions(), 0);
    assert!(!exchange(port, "server.test", &client).unwrap().0);
    handle.join().unwrap();
}

#[test]
fn resumption_off_offers_and_keeps_nothing() {
    let (server, client) = setup();
    let client = client.with_resumption(Resumption::off());
    let (port, handle) = serve(Arc::new(server), 2);
    exchange(port, "server.test", &client).unwrap();
    assert!(!exchange(port, "server.test", &client).unwrap().0);
    assert_eq!(handle.join().unwrap(), [false, false]);
}

#[test]
fn the_client_hello_offers_the_ticket_last_with_a_fresh_key_exchange() {
    let (server, client) = setup();
    let (port, handle) = serve(Arc::new(server), 1);
    exchange(port, "server.test", &client).unwrap();
    handle.join().unwrap();
    let mut c = ClientConnection::new("server.test", &client).unwrap();
    let out = c.output().to_vec();
    c.consume_output(out.len());
    // the ClientHello record: its extensions, the last of which is pre_shared_key, after psk_key_exchange_modes (psk_dhe_ke)
    let ch = &out[5..];
    let hello = parse_client_hello_for_tests(ch);
    let types: Vec<u16> = hello.iter().map(|(t, _)| *t).collect();
    assert_eq!(types.last(), Some(&EXT_PRE_SHARED_KEY));
    assert_eq!(types[types.len() - 2], EXT_PSK_KEY_EXCHANGE_MODES);
    assert_eq!(hello[types.len() - 2].1, [1, PSK_DHE_KE]);
    assert!(types.contains(&EXT_KEY_SHARE));
    // one identity and one binder of the suite's hash length
    let psk = &hello.last().unwrap().1;
    let ids_len = u16::from_be_bytes([psk[0], psk[1]]) as usize;
    let binders = &psk[2 + ids_len..];
    assert!(binders.len() == 2 + 1 + 32 || binders.len() == 2 + 1 + 48);
    assert_eq!(client.resumption.sessions(), 0, "the ticket is taken when it is offered");
}

/// The extensions of a ClientHello handshake message, in order.
fn parse_client_hello_for_tests(msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut r = crate::util::Reader::new(&msg[4..]);
    r.take(2 + 32).unwrap();
    r.vec8().unwrap();
    r.vec16().unwrap();
    r.vec8().unwrap();
    let mut er = crate::util::Reader::new(r.vec16().unwrap());
    let mut out = Vec::new();
    while !er.is_empty() {
        out.push((er.u16().unwrap(), er.vec16().unwrap().to_vec()));
    }
    out
}

// ------------------------------------------------------------------------------------------------ servers that misbehave

/// A client configuration with one session for `host` of `suite`, its PSK all 0x11.
fn with_session(host: &str, suite: Suite) -> ClientConfig {
    let cfg = ClientConfig::new(TrustStore::empty());
    let scope = Scope { trust: cfg.trust_store.clone(), verify: true, revocation: cfg.revocation.mode };
    let session = Kept {
        ticket: vec![9; 16],
        psk: Zeroizing::new(vec![0x11; suite.hash().output_len()]),
        suite,
        age_add: 0,
        received: Instant::now(),
        expires: i64::MAX,
        verified_at: crate::sys::now_unix(),
        peer_chain: vec![vec![1, 2, 3]],
        scope,
    };
    cfg.resumption.insert(host, session);
    cfg
}

fn refused(cfg: &ClientConfig, respond: impl FnOnce(Hello) -> Vec<u8> + 'static) -> String {
    let (io, _) = FakeServer::new(respond);
    match TlsStream::connect(io, "server.test", cfg) {
        Ok(_) => panic!("the handshake succeeded"),
        Err(e) => e.to_string(),
    }
}

fn server_hello_with(suite: Suite, extra: Vec<(u16, Vec<u8>)>, psk: Option<Vec<u8>>, flight: Vec<Vec<u8>>) -> impl FnOnce(Hello) -> Vec<u8> {
    move |h| {
        let mut s = super::scripted::Session::new(h, suite);
        s.psk = psk;
        let o = ShOpts { extra_extensions: extra, ..ShOpts::default() };
        let (mut out, sh) = s.hello_records(&o);
        let mut c = s.flight_cipher(&sh);
        out.extend(sealed_flight(&mut c, &flight));
        out
    }
}

#[test]
fn a_server_may_take_only_the_identity_that_was_offered_with_a_suite_of_its_hash() {
    let suite = Suite::Chacha20Poly1305Sha256;
    // no PSK offered (no session), and the server says it took one
    let e = refused(&ClientConfig::new(TrustStore::empty()), server_hello_with(suite, vec![(EXT_PRE_SHARED_KEY, vec![0, 0])], None, vec![]));
    assert!(e.contains("took a PSK that was not offered"), "{e}");
    // identity 1, when one was offered
    let e = refused(&with_session("server.test", suite), server_hello_with(suite, vec![(EXT_PRE_SHARED_KEY, vec![0, 1])], None, vec![]));
    assert!(e.contains("took PSK identity 1"), "{e}");
    // a session of SHA-384 resumed with a SHA-256 suite
    let e = refused(&with_session("server.test", Suite::Aes256GcmSha384), server_hello_with(suite, vec![(EXT_PRE_SHARED_KEY, vec![0, 0])], None, vec![]));
    assert!(e.contains("cipher suite of another hash"), "{e}");
    // a malformed pre_shared_key
    let e = refused(&with_session("server.test", suite), server_hello_with(suite, vec![(EXT_PRE_SHARED_KEY, vec![0])], None, vec![]));
    assert!(e.contains("pre_shared_key"), "{e}");
}

#[test]
fn a_resumed_handshake_with_a_certificate_is_refused() {
    let suite = Suite::Chacha20Poly1305Sha256;
    let cfg = with_session("server.test", suite);
    let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
    let cert = handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0]);
    let e = refused(&cfg, server_hello_with(suite, vec![(EXT_PRE_SHARED_KEY, vec![0, 0])], Some(vec![0x11; 32]), vec![ee, cert]));
    assert!(e.contains("unexpected_message"), "{e}");
}

#[test]
fn malformed_tickets_end_the_connection() {
    let ok = |lifetime: u32, ticket: &[u8]| {
        let mut b = lifetime.to_be_bytes().to_vec();
        b.extend_from_slice(&[0, 0, 0, 7, 1, 0]);
        b.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        b.extend_from_slice(ticket);
        b.extend_from_slice(&[0, 0]);
        b
    };
    let t = parse_new_session_ticket(&ok(7200, b"abc")).unwrap();
    assert_eq!((t.lifetime, t.age_add, t.nonce.as_slice(), t.ticket.as_slice()), (7200, 7, &[0u8][..], &b"abc"[..]));
    assert!(parse_new_session_ticket(&ok(7200, b"")).is_err(), "an empty ticket");
    assert!(parse_new_session_ticket(&ok(604_801, b"abc")).is_err(), "more than seven days");
    assert!(parse_new_session_ticket(&ok(7200, b"abc")[..12]).is_err(), "cut short");
    assert!(parse_new_session_ticket(&[ok(7200, b"abc"), vec![0]].concat()).is_err(), "trailing bytes");
    // an extension (early_data) is skipped; the same one twice is an error
    let mut with_ext = ok(7200, b"abc");
    with_ext.truncate(with_ext.len() - 2);
    with_ext.extend_from_slice(&[0, 8, 0, 42, 0, 4, 0, 0, 0x40, 0]);
    assert!(parse_new_session_ticket(&with_ext).is_ok());
    let mut twice = ok(7200, b"abc");
    twice.truncate(twice.len() - 2);
    twice.extend_from_slice(&[0, 16, 0, 42, 0, 4, 0, 0, 0x40, 0, 0, 42, 0, 4, 0, 0, 0x40, 0]);
    assert!(parse_new_session_ticket(&twice).is_err());
}
