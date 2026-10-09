//! TLS 1.3 as QUIC uses it (RFC 9001 section 4 to 8): the client's handshake carried in CRYPTO frames instead of TLS records.
//!
//! [`TlsClient`] sits between the connection and `Handshake` (`tls::handshake`), the message-level handshake that the TLS
//! client over TCP is also built on. The connection gives it the handshake bytes that CRYPTO frames brought, in order, at the
//! encryption level of the packets they came in ([`TlsClient::read_crypto`]); it says what the connection is to do about them:
//! send handshake bytes at a level, install the keys of a level, learn the server's transport parameters
//! ([`Event`]). The records, the change_cipher_spec compatibility mode and the alerts of TLS are not here: QUIC has packets for
//! framing, no compatibility mode (RFC 9001 section 8.4), and CONNECTION_CLOSE for an alert, with the error code 0x100 plus the
//! alert's description ([`close_code`], section 4.8).
//!
//! What QUIC adds to the handshake that is checked here (RFC 9001 section 8): the client offers ALPN and the server has to select a
//! protocol (no_application_protocol, alert 120, if it does not), both sides send their transport parameters in an extension (the
//! server's is required: missing_extension, alert 109), a message belongs at one level (a ServerHello in Initial packets, the
//! rest of the server's flight in Handshake packets) and no message may be left over when the keys change, and the TLS
//! KeyUpdate is not used (section 6): receiving one is an error. Session tickets are ignored, as over TCP.

use crate::error::{Error, Result};
use crate::tls::handshake::{alert_description, take_message, Epoch, Event as CoreEvent, Handshake};
use crate::tls::messages::{HS_KEY_UPDATE, HS_NEW_SESSION_TICKET, HS_SERVER_HELLO};
use crate::tls::{ClientConfig, Suite};
use crate::zeroize::Zeroizing;

/// The encryption levels that carry handshake data. (0-RTT carries none, and is not used.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Initial,
    Handshake,
    /// 1-RTT packets.
    Application,
}

impl Level {
    /// 0, 1 and 2: the index of the packet number space and of the crypto stream of the level.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// What the connection is asked to do.
pub enum Event {
    /// Send these handshake bytes in CRYPTO frames in packets of this level (they continue what was sent there).
    Crypto(Level, Vec<u8>),
    /// Install keys for packets of this level: `write` protects what we send, `read` opens what we receive. They are traffic
    /// secrets; the connection derives packet keys from them (RFC 9001 section 5.1) with the TLS cipher suite's hash and AEAD.
    Keys { level: Level, suite: Suite, write: Zeroizing<Vec<u8>>, read: Zeroizing<Vec<u8>> },
    /// The server's `quic_transport_parameters`, as sent: for [`TransportParameters::decode`](super::transport_params).
    PeerTransportParameters(Vec<u8>),
    /// The server's certificate chain was accepted (the leaf first), and the ALPN protocol it selected is known:
    /// [`TlsClient::peer_certificates`] and [`TlsClient::alpn`] have them.
    ServerAuthenticated,
    /// The server's Finished is verified and ours is in the `Crypto` events that came before: TLS is done. The 1-RTT keys come with
    /// it. (The connection is not confirmed until the server says so with HANDSHAKE_DONE, RFC 9001 section 4.1.2.)
    Complete,
}

/// The TLS 1.3 client of a QUIC connection.
pub struct TlsClient {
    hs: Option<Box<Handshake>>,
    /// Bytes received at each level that are not a whole message yet.
    pending: [Vec<u8>; 3],
    /// The Handshake keys are installed (the ServerHello is in).
    have_handshake_keys: bool,
    complete: bool,
    suite: Option<Suite>,
    alpn: Option<Vec<u8>>,
    peer_chain: Vec<Vec<u8>>,
    peer_params: Option<Vec<u8>>,
}

/// The CONNECTION_CLOSE error code for a handshake failure: CRYPTO_ERROR (0x0100) plus the TLS alert (RFC 9001 section 4.8).
pub fn close_code(err: &Error) -> u64 {
    0x100 + alert_description(err).unwrap_or(40) as u64
}

impl TlsClient {
    /// Starts the handshake with `server_name` (a DNS name or IP address) and the client's `transport_params`, encoded. The
    /// events hold the ClientHello, to be sent in CRYPTO frames in Initial packets. The configuration has to offer ALPN
    /// protocols (RFC 9001 section 8.1).
    pub fn new(server_name: &str, config: &ClientConfig, transport_params: &[u8]) -> Result<(TlsClient, Vec<Event>)> {
        let private = Zeroizing::new(crate::crypto::rand::bytes()?);
        let random: [u8; 32] = crate::crypto::rand::bytes()?;
        TlsClient::with_randomness(server_name, config, transport_params, private, &random)
    }

    /// `new` with the randomness given, so that tests can fix it.
    pub(crate) fn with_randomness(
        server_name: &str,
        config: &ClientConfig,
        transport_params: &[u8],
        private: Zeroizing<[u8; 32]>,
        random: &[u8; 32],
    ) -> Result<(TlsClient, Vec<Event>)> {
        if config.alpn_protocols.is_empty() {
            return Err(Error::Tls("QUIC needs an ALPN protocol: the configuration has none".into()));
        }
        crate::tls::handshake::check_server_name(server_name)?;
        // no compatibility mode: an empty legacy session id (RFC 9001 section 8.4)
        let (hs, client_hello) = Handshake::start(server_name, config, Some(transport_params), private, random, &[]);
        let client = TlsClient {
            hs: Some(Box::new(hs)),
            pending: [Vec::new(), Vec::new(), Vec::new()],
            have_handshake_keys: false,
            complete: false,
            suite: None,
            alpn: None,
            peer_chain: Vec::new(),
            peer_params: None,
        };
        Ok((client, vec![Event::Crypto(Level::Initial, client_hello)]))
    }

    /// Handshake bytes that came in order in CRYPTO frames in packets of `level`. On an error the handshake is over: close the
    /// connection with [`close_code`].
    pub fn read_crypto(&mut self, level: Level, data: &[u8]) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        self.pending[level.index()].extend_from_slice(data);
        loop {
            let Some(message) = take_message(&mut self.pending[level.index()])? else { return Ok(events) };
            // more bytes after this message at the same level
            let trailing = !self.pending[level.index()].is_empty();
            match level {
                Level::Initial if message[0] != HS_SERVER_HELLO => {
                    return Err(Error::Tls("unexpected_message: only the ServerHello comes in Initial packets".into()));
                }
                Level::Handshake if message[0] == HS_SERVER_HELLO => {
                    return Err(Error::Tls("unexpected_message: a ServerHello in a Handshake packet".into()));
                }
                Level::Handshake if !self.have_handshake_keys => {
                    return Err(Error::Tls("unexpected_message: handshake data before the ServerHello".into()));
                }
                Level::Application => {
                    self.post_handshake(&message)?;
                    continue;
                }
                _ => {}
            }
            let Some(hs) = self.hs.as_mut() else {
                return Err(Error::Tls("unexpected_message: handshake data after the handshake".into()));
            };
            let core = hs.on_message(&message, trailing)?;
            self.apply(core, &mut events);
        }
    }

    /// A message after the handshake, in 1-RTT packets: session tickets are ignored (nothing is resumed), the TLS KeyUpdate is not
    /// allowed in QUIC (RFC 9001 section 6), and nothing else is expected from a server.
    fn post_handshake(&mut self, message: &[u8]) -> Result<()> {
        if !self.complete {
            return Err(Error::Tls("unexpected_message: handshake data at the 1-RTT level before the handshake is complete".into()));
        }
        match message[0] {
            HS_NEW_SESSION_TICKET => Ok(()),
            HS_KEY_UPDATE => Err(Error::Tls("unexpected_message: KeyUpdate in QUIC (the keys are updated with the key phase bit)".into())),
            _ => Err(Error::Tls("unexpected_message: unexpected post-handshake message".into())),
        }
    }

    fn apply(&mut self, core: Vec<CoreEvent>, events: &mut Vec<Event>) {
        for event in core {
            match event {
                CoreEvent::Send(Epoch::Initial, message) => events.push(Event::Crypto(Level::Initial, message)),
                CoreEvent::Send(Epoch::Handshake, message) => events.push(Event::Crypto(Level::Handshake, message)),
                CoreEvent::HandshakeSecrets { suite, client, server } => {
                    self.suite = Some(suite);
                    self.have_handshake_keys = true;
                    events.push(Event::Keys { level: Level::Handshake, suite, write: client, read: server });
                }
                CoreEvent::Alpn(protocol) => self.alpn = protocol,
                CoreEvent::PeerCertificates(chain) => {
                    self.peer_chain = chain;
                    events.push(Event::ServerAuthenticated);
                }
                CoreEvent::PeerTransportParameters(params) => {
                    self.peer_params = Some(params.clone());
                    events.push(Event::PeerTransportParameters(params));
                }
                CoreEvent::ApplicationSecrets { suite, client, server } => {
                    self.complete = true;
                    self.hs = None;
                    events.push(Event::Keys { level: Level::Application, suite, write: client, read: server });
                    events.push(Event::Complete);
                }
                // (never: over QUIC the ClientHello offers TLS 1.3 alone, and a TLS 1.2 ServerHello is refused before this)
                CoreEvent::Tls12(..) => debug_assert!(false, "TLS 1.2 over QUIC"),
                // (the QUIC client's configuration never defers the revocation sources)
                CoreEvent::Unchecked(_) => {}
                // a QUIC handshake offers no session, and keeps none (see `tls::session`)
                CoreEvent::Resumed | CoreEvent::ResumptionSecret { .. } => {}
            }
        }
    }

    /// True once the server's Finished is verified and ours has been produced.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The TLS cipher suite, once the ServerHello is in.
    pub fn cipher_suite(&self) -> Option<Suite> {
        self.suite
    }

    /// The ALPN protocol the server selected, once its EncryptedExtensions are in.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The server's certificate chain (leaf first), once it is in and was accepted.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_chain
    }

    /// The server's transport parameters, as sent, once its EncryptedExtensions are in.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.peer_params.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_peer::{Flight, Hello, Options, TestServer};
    use super::*;
    use crate::tls::messages::*;

    const PARAMS: &[u8] = &[0x0f, 0x04, 1, 2, 3, 4];
    const SERVER_PARAMS: &[u8] = &[0x00, 0x00, 0x0f, 0x00];

    fn config(server: &TestServer) -> ClientConfig {
        let mut config = ClientConfig::new(server.pki.trust_store());
        config.alpn_protocols = vec![b"h3".to_vec()];
        config
    }

    /// A client, the ClientHello it made and the flight a server answers with.
    fn start(o: &Options) -> (TlsClient, Hello, Flight, TestServer) {
        let server = TestServer::new("example.test");
        let (client, events) = TlsClient::new("example.test", &config(&server), PARAMS).unwrap();
        let [Event::Crypto(Level::Initial, hello)] = &events[..] else { panic!("the first event is the ClientHello") };
        let hello = Hello::parse(hello);
        let flight = server.flight(&hello, o);
        (client, hello, flight, server)
    }

    fn options() -> Options {
        Options { params: Some(SERVER_PARAMS.to_vec()), ..Options::default() }
    }

    fn handshake_bytes(f: &Flight) -> Vec<u8> {
        f.handshake.concat()
    }

    fn describe(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                Event::Crypto(level, data) => format!("crypto {level:?} {}", data.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                Event::Keys { level, suite, write, read } => format!("keys {level:?} {suite:?} {:02x?} {:02x?}", &**write, &**read),
                Event::PeerTransportParameters(p) => format!("params {p:02x?}"),
                Event::ServerAuthenticated => "authenticated".to_string(),
                Event::Complete => "complete".to_string(),
            })
            .collect()
    }

    fn code(r: Result<Vec<Event>>) -> u64 {
        match r {
            Ok(_) => panic!("it was accepted"),
            Err(e) => close_code(&e),
        }
    }

    #[test]
    fn the_client_hello_is_what_quic_wants() {
        let (_, hello, _, _) = start(&options());
        assert!(hello.session_id.is_empty(), "no compatibility mode (RFC 9001 section 8.4)");
        assert_eq!(hello.extension(EXT_QUIC_TRANSPORT_PARAMETERS), Some(PARAMS));
        assert_eq!(hello.alpn(), vec![b"h3".to_vec()]);
        assert!(hello.suites.contains(&0x1301) && hello.suites.contains(&0x1302) && hello.suites.contains(&0x1303));
        assert_eq!(hello.key_shares().len(), 1);
        assert_eq!(hello.extension(EXT_SUPPORTED_VERSIONS), Some(&[2, 3, 4][..]));
        // the extension is there once
        assert_eq!(hello.extensions.iter().filter(|(t, _)| *t == EXT_QUIC_TRANSPORT_PARAMETERS).count(), 1);
    }

    #[test]
    fn a_whole_handshake() {
        let (mut c, _, f, server) = start(&options());
        assert!(!c.is_complete());
        let events = c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        let [Event::Keys { level: Level::Handshake, suite, write, read }] = &events[..] else { panic!("{:?}", describe(&events)) };
        assert_eq!(*suite, Suite::Aes128GcmSha256);
        assert_eq!((&**write, &**read), (&f.client_handshake_secret, &f.server_handshake_secret));
        assert_eq!(c.cipher_suite(), Some(Suite::Aes128GcmSha256));
        assert!(!c.is_complete());

        let events = c.read_crypto(Level::Handshake, &handshake_bytes(&f)).unwrap();
        let [Event::PeerTransportParameters(p), Event::ServerAuthenticated, Event::Crypto(Level::Handshake, finished), Event::Keys { level: Level::Application, write, read, .. }, Event::Complete] =
            &events[..]
        else {
            panic!("{:?}", describe(&events))
        };
        assert_eq!(p, SERVER_PARAMS);
        assert_eq!(finished, &f.client_finished, "the client's Finished is the one the server expects");
        assert_eq!((&**write, &**read), (&f.client_application_secret, &f.server_application_secret));
        assert!(c.is_complete());
        assert_eq!(c.alpn(), Some(&b"h3"[..]));
        assert_eq!(c.peer_transport_parameters(), Some(SERVER_PARAMS));
        assert_eq!(c.peer_certificates(), &server.pki.chain[..]);
    }

    #[test]
    fn the_same_handshake_in_pieces_of_any_size() {
        let (mut whole, _, f, _) = start(&options());
        let mut want = describe(&whole.read_crypto(Level::Initial, &f.server_hello).unwrap());
        want.extend(describe(&whole.read_crypto(Level::Handshake, &handshake_bytes(&f)).unwrap()));
        // the client's randomness is its own, so each client needs its own flight: build them the same way
        for piece in [1usize, 2, 3, 7, 100, 1000] {
            // a fresh client with the same randomness
            let server = TestServer::new("example.test");
            let (mut c, events) =
                TlsClient::with_randomness("example.test", &config(&server), PARAMS, crate::zeroize::Zeroizing::new([9u8; 32]), &[8u8; 32]).unwrap();
            let [Event::Crypto(Level::Initial, hello)] = &events[..] else { panic!() };
            let f = server.flight(&Hello::parse(hello), &options());
            let mut got = Vec::new();
            for chunk in f.server_hello.chunks(piece) {
                got.extend(describe(&c.read_crypto(Level::Initial, chunk).unwrap()));
            }
            for chunk in handshake_bytes(&f).chunks(piece) {
                got.extend(describe(&c.read_crypto(Level::Handshake, chunk).unwrap()));
            }
            assert!(c.is_complete(), "pieces of {piece}");
            // the same events, apart from what depends on the keys and certificate, which differ between the two servers
            let kinds = |v: &[String]| v.iter().map(|s| s.split(' ').next().unwrap().to_string()).collect::<Vec<_>>();
            assert_eq!(kinds(&got), kinds(&want), "pieces of {piece}");
        }
    }

    #[test]
    fn what_the_server_gets_wrong_is_a_crypto_error_with_the_alert_that_tls_has_for_it() {
        let cases: Vec<(&str, Options, u64)> = vec![
            ("no transport parameters", Options { params: None, ..options() }, 0x100 + 109),
            ("no ALPN protocol selected", Options { alpn: None, ..options() }, 0x100 + 120),
            ("an ALPN protocol that was not offered", Options { alpn: Some(b"h2".to_vec()), ..options() }, 0x100 + 47),
            ("an extension that was not asked for", Options { extra_extensions: vec![(0x1234, vec![])], ..options() }, 0x100 + 110),
            ("the transport parameters twice", Options { extra_extensions: vec![(EXT_QUIC_TRANSPORT_PARAMETERS, vec![])], ..options() }, 0x100 + 47),
        ];
        for (name, o, want) in cases {
            let (mut c, _, f, _) = start(&o);
            c.read_crypto(Level::Initial, &f.server_hello).unwrap();
            assert_eq!(code(c.read_crypto(Level::Handshake, &handshake_bytes(&f))), want, "{name}");
        }
        // a ServerHello that says another legacy session id than the empty one that was sent
        let (mut c, _, f, _) = start(&Options { session_id: Some(vec![1, 2, 3]), ..options() });
        assert_eq!(code(c.read_crypto(Level::Initial, &f.server_hello)), 0x100 + 47);
        // a Finished that is not the server's
        let (mut c, _, mut f, _) = start(&options());
        let last = f.handshake.last_mut().unwrap();
        *last.last_mut().unwrap() ^= 1;
        c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        assert_eq!(code(c.read_crypto(Level::Handshake, &handshake_bytes(&f))), 0x100 + 51);
        // a certificate the client does not trust: it trusts the root of another PKI than the server's
        let other = TestServer::new("example.test");
        let server = TestServer::new("example.test");
        let (mut distrusting, events) =
            TlsClient::with_randomness("example.test", &config(&other), PARAMS, crate::zeroize::Zeroizing::new([9u8; 32]), &[8u8; 32]).unwrap();
        let [Event::Crypto(Level::Initial, hello)] = &events[..] else { panic!() };
        let f = server.flight(&Hello::parse(hello), &options());
        distrusting.read_crypto(Level::Initial, &f.server_hello).unwrap();
        assert_eq!(code(distrusting.read_crypto(Level::Handshake, &handshake_bytes(&f))), 0x100 + 42);
    }

    #[test]
    fn a_message_belongs_to_one_level() {
        // the rest of the flight in an Initial packet
        let (mut c, _, f, _) = start(&options());
        assert_eq!(code(c.read_crypto(Level::Initial, &f.handshake[0])), 0x10a);
        // a ServerHello in a Handshake packet, or Handshake data before the ServerHello
        let (mut c, _, f, _) = start(&options());
        assert_eq!(code(c.read_crypto(Level::Handshake, &f.server_hello)), 0x10a);
        let (mut c, _, f, _) = start(&options());
        assert_eq!(code(c.read_crypto(Level::Handshake, &f.handshake[0])), 0x10a);
        // 1-RTT data before the handshake is complete
        let (mut c, _, f, _) = start(&options());
        c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        assert_eq!(code(c.read_crypto(Level::Application, &[HS_NEW_SESSION_TICKET, 0, 0, 0])), 0x10a);
    }

    #[test]
    fn nothing_may_follow_a_message_that_changes_the_keys() {
        // the ServerHello and then a part of another message, in the same Initial data
        let (mut c, _, f, _) = start(&options());
        let mut data = f.server_hello.clone();
        data.extend_from_slice(&f.handshake[0][..3]);
        assert_eq!(code(c.read_crypto(Level::Initial, &data)), 0x10a);
        // the server's Finished and more after it
        let (mut c, _, f, _) = start(&options());
        c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        let mut data = handshake_bytes(&f);
        data.extend_from_slice(&[HS_NEW_SESSION_TICKET, 0, 0, 0]);
        assert_eq!(code(c.read_crypto(Level::Handshake, &data)), 0x10a);
    }

    #[test]
    fn after_the_handshake_tickets_are_ignored_and_a_key_update_is_an_error() {
        let finish = || {
            let (mut c, _, f, _) = start(&options());
            c.read_crypto(Level::Initial, &f.server_hello).unwrap();
            c.read_crypto(Level::Handshake, &handshake_bytes(&f)).unwrap();
            assert!(c.is_complete());
            c
        };
        let ticket = [&[HS_NEW_SESSION_TICKET, 0, 0, 12][..], &[0u8; 12]].concat();
        let mut c = finish();
        assert!(c.read_crypto(Level::Application, &ticket).unwrap().is_empty());
        // in pieces, and two at once
        for chunk in [&ticket[..1], &ticket[1..9], &ticket[9..]] {
            assert!(c.read_crypto(Level::Application, chunk).unwrap().is_empty());
        }
        assert!(c.read_crypto(Level::Application, &[ticket.clone(), ticket.clone()].concat()).unwrap().is_empty());
        // RFC 9001 section 6: a TLS KeyUpdate is a connection error of type 0x010a
        assert_eq!(code(finish().read_crypto(Level::Application, &[HS_KEY_UPDATE, 0, 0, 1, 0])), 0x10a);
        // nothing else is expected, either
        assert_eq!(code(finish().read_crypto(Level::Application, &[HS_CERTIFICATE_REQUEST, 0, 0, 0])), 0x10a);
        // and no more handshake data at the other levels once TLS is done
        assert_eq!(code(finish().read_crypto(Level::Handshake, &handshake_message(HS_FINISHED, &[0; 32]))), 0x10a);
    }

    #[test]
    fn a_message_that_is_too_long_is_refused_before_it_is_read() {
        let (mut c, _, f, _) = start(&options());
        c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        // the header of a message of 2^24 - 1 bytes
        assert_eq!(code(c.read_crypto(Level::Handshake, &[HS_ENCRYPTED_EXTENSIONS, 0xff, 0xff, 0xff])), 0x100 + 47);
    }

    #[test]
    fn a_certificate_request_is_answered_with_an_empty_certificate() {
        let (mut c, _, f, _) = start(&Options { request_certificate: true, ..options() });
        c.read_crypto(Level::Initial, &f.server_hello).unwrap();
        let events = c.read_crypto(Level::Handshake, &handshake_bytes(&f)).unwrap();
        let crypto: Vec<&Vec<u8>> = events.iter().filter_map(|e| if let Event::Crypto(Level::Handshake, d) = e { Some(d) } else { None }).collect();
        assert_eq!(crypto.len(), 2);
        assert_eq!(crypto[0], &handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0]));
        assert_eq!(crypto[1], &f.client_finished);
    }

    #[test]
    fn a_hello_retry_request_is_answered_in_the_initial_level_with_the_same_parameters() {
        let (mut c, hello, _, server) = start(&options());
        let hrr = server.hello_retry_request(&hello, Suite::Aes128GcmSha256, GROUP_SECP256R1);
        let events = c.read_crypto(Level::Initial, &hrr).unwrap();
        let [Event::Crypto(Level::Initial, second)] = &events[..] else { panic!("{:?}", describe(&events)) };
        let second = Hello::parse(second);
        assert!(second.session_id.is_empty());
        assert_eq!(second.extension(EXT_QUIC_TRANSPORT_PARAMETERS), Some(PARAMS));
        assert_eq!(second.alpn(), vec![b"h3".to_vec()]);
        assert_eq!(second.random, hello.random);
        let shares = second.key_shares();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].0, GROUP_SECP256R1);
        // a second retry is not allowed
        let again = server.hello_retry_request(&hello, Suite::Aes128GcmSha256, GROUP_SECP384R1);
        assert_eq!(code(c.read_crypto(Level::Initial, &again)), 0x10a);
    }

    #[test]
    fn quic_needs_an_alpn_protocol_to_offer() {
        let server = TestServer::new("example.test");
        let mut config = config(&server);
        config.alpn_protocols.clear();
        assert!(TlsClient::new("example.test", &config, PARAMS).is_err());
    }
}
