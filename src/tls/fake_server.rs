//! Tests of the client against the scripted server (see `scripted`).

use super::messages::*;
use super::scripted::*;
use super::suite::*;
use super::*;
use crate::fuzz::{mutate, random_up_to, run, Rng};
use crate::revocation::{Crl, Revocation, RevocationMode};
use crate::util::Reader;

fn config_for_tests() -> ClientConfig {
    ClientConfig::new(TrustStore::empty()).danger_disable_verification()
}

/// Connects to the fake and returns the error text (the handshake must fail) and what the client sent.
fn handshake_error(host: &str, cfg: &ClientConfig, respond: impl FnOnce(Hello) -> Vec<u8> + 'static) -> (String, Vec<u8>) {
    let (io, seen) = FakeServer::new(respond);
    match TlsStream::connect(io, host, cfg) {
        Ok(_) => panic!("the handshake unexpectedly succeeded"),
        Err(e) => (e.to_string(), seen.borrow().clone()),
    }
}

const SUITE: Suite = Suite::Chacha20Poly1305Sha256;

/// ServerHello (correct unless `o` says otherwise) followed by `flight`, encrypted.
fn respond_with_flight(o: ShOpts, flight: Vec<Vec<u8>>) -> impl FnOnce(Hello) -> Vec<u8> {
    move |h| {
        let s = Session::new(h, SUITE);
        let (mut out, sh) = s.hello_records(&o);
        let mut c = s.flight_cipher(&sh);
        out.extend(sealed_flight(&mut c, &flight));
        out
    }
}

fn ee(exts: &[u8]) -> Vec<u8> {
    handshake_message(HS_ENCRYPTED_EXTENSIONS, &block16(exts))
}

/// The alert description the client sent in plaintext, if it sent one.
fn plaintext_alert(client_bytes: &[u8]) -> Option<u8> {
    // skip the ClientHello record and the compatibility CCS record
    let mut rest = client_bytes;
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if rest.len() < 5 + len {
            return None;
        }
        if rest[0] == RT_ALERT && len == 2 {
            return Some(rest[6]);
        }
        rest = &rest[5 + len..];
    }
    None
}

/// The first encrypted record the client sent after its ClientHello, opened with its handshake
/// traffic keys: `(inner content type, plaintext)`. For a failed handshake that is the alert.
fn encrypted_alert(client_bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
    let session = Session::new(parse_client_hello(client_bytes)?, SUITE);
    let mut cipher = session.client_flight_cipher(&session.server_hello(&ShOpts::default()));
    let mut rest = client_bytes;
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if rest.len() < 5 + len {
            return None;
        }
        if rest[0] == RT_APPLICATION_DATA {
            let header = [rest[0], rest[1], rest[2], rest[3], rest[4]];
            return Some(cipher.decrypt(&header, &rest[5..5 + len]).expect("decrypts under the client handshake keys"));
        }
        rest = &rest[5 + len..];
    }
    None
}

/// The description of the fatal alert the client sent under its handshake keys.
fn encrypted_alert_description(client_bytes: &[u8]) -> Option<u8> {
    match encrypted_alert(client_bytes) {
        Some((RT_ALERT, body)) if body.len() == 2 && body[0] == 2 => Some(body[1]),
        _ => None,
    }
}

#[test]
fn downgrade_sentinel_aborts_with_illegal_parameter() {
    for version in [0x0303u16, 0x0304] {
        let mut random = [9u8; 32];
        random[24..32].copy_from_slice(b"DOWNGRD\x01");
        let o = ShOpts { random, supported_version: Some(version), ..ShOpts::default() };
        let (err, sent) = handshake_error("example.test", &config_for_tests(), move |h| Session::new(h, SUITE).hello_records(&o).0);
        assert!(err.contains("downgrade sentinel"), "{}", err);
        assert_eq!(plaintext_alert(&sent), Some(47), "client must send illegal_parameter");
    }
    // supported_versions naming TLS 1.2 is no way to choose it (RFC 8446 section 4.2.1): illegal_parameter, not a downgrade
    let o = ShOpts { supported_version: Some(0x0303), ..ShOpts::default() };
    let (err, sent) = handshake_error("example.test", &config_for_tests(), move |h| Session::new(h, SUITE).hello_records(&o).0);
    assert!(err.contains("not offered"), "{}", err);
    assert_eq!(plaintext_alert(&sent), Some(47));
}

#[test]
fn server_hello_legacy_fields_are_validated() {
    let cases: [(ShOpts, &str); 5] = [
        (ShOpts { legacy_version: 0x0302, ..ShOpts::default() }, "bad legacy fields"),
        (ShOpts { legacy_version: 0x0304, ..ShOpts::default() }, "bad legacy fields"),
        (ShOpts { compression: 1, ..ShOpts::default() }, "bad legacy fields"),
        (ShOpts { echo_session_id: false, ..ShOpts::default() }, "did not echo the legacy session id"),
        (ShOpts { cipher_suite: Some(0x1304), ..ShOpts::default() }, "cipher suite we did not offer"),
    ];
    for (o, expect) in cases {
        let (err, _) = handshake_error("example.test", &config_for_tests(), move |h| Session::new(h, SUITE).hello_records(&o).0);
        assert!(err.contains(expect), "wanted {:?}, got {}", expect, err);
    }
    // no supported_versions extension at all: TLS 1.2, which a TLS 1.3-only client refuses, and which this ServerHello (with its
    // TLS 1.3 key share) is not a well-made one of
    let o = ShOpts { supported_version: None, ..ShOpts::default() };
    let tls13 = config_for_tests().with_min_version(crate::tls::TlsVersion::Tls13);
    let (err, sent) = handshake_error("example.test", &tls13, move |h| Session::new(h, SUITE).hello_records(&o).0);
    assert!(err.contains("requires TLS 1.3"), "{}", err);
    assert_eq!(plaintext_alert(&sent), Some(70));
    let o = ShOpts { supported_version: None, ..ShOpts::default() };
    let (err, _) = handshake_error("example.test", &config_for_tests(), move |h| Session::new(h, SUITE).hello_records(&o).0);
    assert!(err.contains("TLS 1.3 extensions in a TLS 1.2 ServerHello"), "{}", err);
}

#[test]
fn compat_change_cipher_spec_is_tolerated_once_or_twice_but_not_flooded() {
    let ccs = plain_record(RT_CHANGE_CIPHER_SPEC, &[1]);
    // one CCS before the ServerHello is skipped: the ServerHello that follows is then parsed
    // (and rejected here for its suite, which proves it was reached)
    let (err, _) = handshake_error("example.test", &config_for_tests(), {
        let ccs = ccs.clone();
        move |h| {
            let o = ShOpts { cipher_suite: Some(0x1304), ..ShOpts::default() };
            let mut out = ccs;
            out.extend(Session::new(h, SUITE).hello_records(&o).0);
            out
        }
    });
    assert!(err.contains("cipher suite we did not offer"), "{}", err);
    // a flood is an error
    let (err, _) = handshake_error("example.test", &config_for_tests(), move |_| ccs.repeat(50));
    assert!(err.contains("change_cipher_spec"), "{}", err);
    // a CCS with the wrong content
    let (err, _) = handshake_error("example.test", &config_for_tests(), |_| plain_record(RT_CHANGE_CIPHER_SPEC, &[2]));
    assert!(err.contains("change_cipher_spec"), "{}", err);
}

#[test]
fn a_failure_after_the_server_hello_sends_its_alert_under_the_handshake_keys() {
    // EncryptedExtensions, then a Finished where a Certificate belongs
    let flight = vec![ee(&[]), handshake_message(HS_FINISHED, &[0u8; 32])];
    let (err, sent) = handshake_error("example.test", &config_for_tests(), respond_with_flight(ShOpts::default(), flight));
    assert!(err.contains("out of order"), "{}", err);
    assert_eq!(plaintext_alert(&sent), None, "the alert must not travel in the clear after the ServerHello");

    let alert = encrypted_alert(&sent);
    // alert level 2 (fatal), description 10 (unexpected_message)
    assert_eq!(alert, Some((RT_ALERT, vec![2, 10])));
}

#[test]
fn encrypted_extensions_strictness_through_the_handshake() {
    let cfg = config_for_tests();
    let finished = handshake_message(HS_FINISHED, &[0u8; 32]);

    // Accepted: empty server_name (we sent SNI) and supported_groups. The next message, a Finished
    // out of order, is what stops the handshake, which proves EncryptedExtensions was accepted.
    let mut good = ext(EXT_SERVER_NAME, &[]);
    good.extend(ext(EXT_SUPPORTED_GROUPS, &block16(&[0, 0x1d])));
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![ee(&good), finished.clone()]));
    assert!(err.contains("out of order"), "{}", err);

    // key_share belongs in the ServerHello
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![ee(&ext(EXT_KEY_SHARE, &[0, 0]))]));
    assert!(err.contains("unsupported_extension"), "{}", err);

    // server_name is unsolicited when we connect to an IP address (no SNI is sent)
    let (err, _) = handshake_error("127.0.0.1", &cfg, respond_with_flight(ShOpts::default(), vec![ee(&ext(EXT_SERVER_NAME, &[]))]));
    assert!(err.contains("unsupported_extension"), "{}", err);

    // ALPN is unsolicited when we offered none
    let mut no_alpn = config_for_tests();
    no_alpn.alpn_protocols.clear();
    let mut alpn = vec![8u8];
    alpn.extend_from_slice(b"http/1.1");
    let alpn_ext = ext(EXT_ALPN, &block16(&alpn));
    let (err, _) = handshake_error("example.test", &no_alpn, respond_with_flight(ShOpts::default(), vec![ee(&alpn_ext)]));
    assert!(err.contains("unsupported_extension"), "{}", err);
    // ...but fine when offered
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![ee(&alpn_ext), finished.clone()]));
    assert!(err.contains("out of order"), "{}", err);
    // and a protocol we did not offer is still refused
    let mut other = vec![2u8];
    other.extend_from_slice(b"h2");
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![ee(&ext(EXT_ALPN, &block16(&other)))]));
    assert!(err.contains("did not offer"), "{}", err);
}

#[test]
fn handshake_ordering_and_framing_strictness() {
    let cfg = config_for_tests();
    let finished = handshake_message(HS_FINISHED, &[0u8; 32]);
    let empty_ee = ee(&[]);
    // Certificate before EncryptedExtensions
    let cert = handshake_message(HS_CERTIFICATE, &[0, 0, 0, 0]);
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![cert]));
    assert!(err.contains("out of order"), "{}", err);
    // EncryptedExtensions twice
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![empty_ee.clone(), empty_ee.clone()]));
    assert!(err.contains("out of order"), "{}", err);
    // a Finished with no certificate flight
    let (err, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), vec![empty_ee.clone(), finished]));
    assert!(err.contains("out of order"), "{}", err);
    // an empty handshake record is forbidden (RFC 8446 section 5.1)
    let (err, _) = handshake_error("example.test", &cfg, move |h| {
        let s = Session::new(h, SUITE);
        let (mut out, sh) = s.hello_records(&ShOpts::default());
        let mut c = s.flight_cipher(&sh);
        c.encrypt_into(RT_HANDSHAKE, &[], &mut out);
        out
    });
    assert!(err.contains("empty handshake record"), "{}", err);
    // a handshake message that claims to be megabytes long
    let (err, _) = handshake_error("example.test", &cfg, move |h| {
        let s = Session::new(h, SUITE);
        let (mut out, sh) = s.hello_records(&ShOpts::default());
        let mut c = s.flight_cipher(&sh);
        c.encrypt_into(RT_HANDSHAKE, &[HS_ENCRYPTED_EXTENSIONS, 0x0f, 0xff, 0xff], &mut out);
        out
    });
    assert!(err.contains("too large"), "{}", err);
}

// ------------------------------------------------------------------------------ revocation

/// Fixtures made by tools/gen_revocation_fixtures.py. Valid on NOW (2026-09-15).
mod rev {
    pub const ROOT: &str = include_str!("../../tests/data/rev_root.pem");
    pub const INTER: &str = include_str!("../../tests/data/rev_inter.pem");
    pub const LEAF: &str = include_str!("../../tests/data/rev_leaf.pem");
    pub const LEAF_MS: &str = include_str!("../../tests/data/rev_leaf_ms.pem");
    pub const OCSP_GOOD: &[u8] = include_bytes!("../../tests/data/rev_ocsp_good.der");
    pub const OCSP_REVOKED: &[u8] = include_bytes!("../../tests/data/rev_ocsp_revoked.der");
    pub const OCSP_FORGED: &[u8] = include_bytes!("../../tests/data/rev_ocsp_forged.der");
    pub const OCSP_EXPIRED: &[u8] = include_bytes!("../../tests/data/rev_ocsp_expired.der");
    pub const OCSP_UNKNOWN: &[u8] = include_bytes!("../../tests/data/rev_ocsp_unknown.der");
    pub const OCSP_MS_GOOD: &[u8] = include_bytes!("../../tests/data/rev_ocsp_ms_good.der");
    pub const OCSP_INTER_REVOKED: &[u8] = include_bytes!("../../tests/data/rev_ocsp_inter_revoked.der");
    pub const OCSP_INTER_GOOD: &[u8] = include_bytes!("../../tests/data/rev_ocsp_inter_good.der");
    pub const CRL_EMPTY: &[u8] = include_bytes!("../../tests/data/rev_crl_empty.der");
    pub const CRL_REVOKED: &[u8] = include_bytes!("../../tests/data/rev_crl_revoked.der");
}

fn rev_trust() -> TrustStore {
    let mut ts = TrustStore::empty();
    ts.add_der(&crate::pem::parse(rev::ROOT).remove(0).data).unwrap();
    ts
}

fn rev_cfg(mode: RevocationMode) -> ClientConfig {
    let mut cfg = ClientConfig::new(rev_trust()).revocation_mode(mode);
    cfg.time_override = Some(NOW);
    cfg
}

/// A Certificate message whose entries carry the given stapled OCSP responses (`None`: no extension).
fn certificate_with_staples(chain: &[Vec<u8>], staples: &[Option<&[u8]>]) -> Vec<u8> {
    let mut list = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
        let exts = match staples.get(i).copied().flatten() {
            Some(response) => {
                let mut status = vec![1u8]; // CertificateStatusType ocsp
                status.extend_from_slice(&(response.len() as u32).to_be_bytes()[1..]);
                status.extend_from_slice(response);
                ext(EXT_STATUS_REQUEST, &status)
            }
            None => Vec::new(),
        };
        list.extend(block16(&exts));
    }
    let mut body = vec![0];
    body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    body.extend(list);
    handshake_message(HS_CERTIFICATE, &body)
}

/// How a handshake against the scripted server (which sends `certificate`, then a Finished it
/// cannot make valid) ended. A certificate the client accepts leads to the next message and the
/// "out of order" complaint; a rejected one stops at the Certificate itself.
enum Outcome {
    Accepted,
    Rejected { error: String, alert: Option<u8> },
}

fn run_certificate(cfg: &ClientConfig, leaf: &str, staples: &[Option<&[u8]>]) -> Outcome {
    let chain = vec![crate::pem::parse(leaf).remove(0).data, crate::pem::parse(rev::INTER).remove(0).data];
    let flight = vec![ee(&[]), certificate_with_staples(&chain, staples), handshake_message(HS_FINISHED, &[0u8; 32])];
    let (error, sent) = handshake_error("example.test", cfg, respond_with_flight(ShOpts::default(), flight));
    if error.contains("out of order") {
        return Outcome::Accepted;
    }
    Outcome::Rejected { alert: encrypted_alert_description(&sent), error }
}

fn crl(der: &[u8]) -> Crl {
    Crl::from_der(der).unwrap()
}

#[test]
fn the_client_hello_asks_for_a_staple_unless_revocation_is_off() {
    // the status_request extension of the ClientHello the client sent, if any
    fn requested(cfg: &ClientConfig) -> Option<Vec<u8>> {
        let (_, sent) = handshake_error("example.test", cfg, |_| plain_record(RT_CHANGE_CIPHER_SPEC, &[2]));
        let hello = parse_client_hello(&sent).expect("a client hello").msg;
        let mut r = Reader::new(&hello[4..]);
        r.u16().unwrap();
        r.take(32).unwrap();
        r.vec8().unwrap();
        r.vec16().unwrap();
        r.vec8().unwrap();
        let mut er = Reader::new(r.vec16().unwrap());
        while !er.is_empty() {
            let (t, d) = (er.u16().unwrap(), er.vec16().unwrap());
            if t == EXT_STATUS_REQUEST {
                return Some(d.to_vec());
            }
        }
        None
    }
    // status_type ocsp, empty responder_id_list, empty request_extensions (RFC 6066 section 8)
    let want = Some(vec![1, 0, 0, 0, 0]);
    assert_eq!(requested(&rev_cfg(RevocationMode::SoftFail)), want);
    assert_eq!(requested(&rev_cfg(RevocationMode::HardFail)), want);
    assert_eq!(requested(&rev_cfg(RevocationMode::Off)), None);
    // nothing is checked, so nothing is asked for, when verification is off altogether
    assert_eq!(requested(&config_for_tests()), None);
}

#[test]
fn stapled_responses_decide_the_handshake_by_policy() {
    use RevocationMode::*;
    let soft = rev_cfg(SoftFail);
    let hard = rev_cfg(HardFail);
    let accepted = |o: &Outcome| matches!(o, Outcome::Accepted);
    let rejected = |o: Outcome, text: &str, alert: u8| match o {
        Outcome::Rejected { error, alert: got } => {
            assert!(error.contains(text), "wanted \"{}\" in: {}", text, error);
            assert_eq!(got, Some(alert), "alert for: {}", error);
        }
        Outcome::Accepted => panic!("wanted \"{}\" but the handshake got past the certificate", text),
    };

    // a good staple: accepted in every mode
    for cfg in [&soft, &hard] {
        assert!(accepted(&run_certificate(cfg, rev::LEAF, &[Some(rev::OCSP_GOOD)])));
    }
    // a revoked staple: refused with certificate_revoked (44), in both modes
    for cfg in [&soft, &hard] {
        rejected(run_certificate(cfg, rev::LEAF, &[Some(rev::OCSP_REVOKED)]), "certificate_revoked", 44);
    }
    // the intermediate's own staple counts too (entry 1, signed by the root)
    rejected(run_certificate(&soft, rev::LEAF, &[Some(rev::OCSP_GOOD), Some(rev::OCSP_INTER_REVOKED)]), "certificate_revoked", 44);
    assert!(accepted(&run_certificate(&soft, rev::LEAF, &[Some(rev::OCSP_GOOD), Some(rev::OCSP_INTER_GOOD)])));
    // a staple that is attached to the wrong entry says nothing about that entry
    assert!(accepted(&run_certificate(&soft, rev::LEAF, &[None, Some(rev::OCSP_GOOD)])));

    // no staple, or one that cannot be used: soft-fail carries on, hard-fail refuses (113)
    let unusable: [(&str, Option<&[u8]>); 5] = [
        ("no staple", None),
        ("a forged staple", Some(rev::OCSP_FORGED)),
        ("an expired staple", Some(rev::OCSP_EXPIRED)),
        ("an 'unknown' staple", Some(rev::OCSP_UNKNOWN)),
        ("garbage", Some(b"\x30\x03\x0a\x01\x00")),
    ];
    for (what, staple) in unusable {
        assert!(accepted(&run_certificate(&soft, rev::LEAF, &[staple])), "soft-fail with {}", what);
        rejected(run_certificate(&hard, rev::LEAF, &[staple]), "bad_certificate_status_response", 113);
    }

    // must-staple: the leaf demands a staple, so soft-fail refuses a missing or unusable one too
    for staple in [None, Some(rev::OCSP_FORGED), Some(rev::OCSP_GOOD)] {
        // OCSP_GOOD is about the other leaf (same issuer, different serial), so it does not count
        rejected(run_certificate(&soft, rev::LEAF_MS, &[staple]), "requires a stapled OCSP response", 113);
    }
    assert!(accepted(&run_certificate(&soft, rev::LEAF_MS, &[Some(rev::OCSP_MS_GOOD)])));
    assert!(accepted(&run_certificate(&hard, rev::LEAF_MS, &[Some(rev::OCSP_MS_GOOD)])));
    // ...and a CRL cannot stand in for a staple that must-staple requires
    let crl_cfg = rev_cfg(SoftFail).with_revocation(Revocation::soft_fail().with_crl(crl(rev::CRL_EMPTY)));
    rejected(run_certificate(&crl_cfg, rev::LEAF_MS, &[None]), "requires a stapled OCSP response", 113);
}

#[test]
fn supplied_crls_apply_during_the_handshake() {
    let with = |mode: Revocation, der: &[u8]| rev_cfg(RevocationMode::Off).with_revocation(mode.with_crl(crl(der)));
    // a CRL listing the leaf: refused even in soft-fail
    let revoked = with(Revocation::soft_fail(), rev::CRL_REVOKED);
    match run_certificate(&revoked, rev::LEAF, &[None]) {
        Outcome::Rejected { error, alert } => {
            assert!(error.contains("certificate_revoked") && error.contains("a CRL"), "{}", error);
            assert_eq!(alert, Some(44));
        }
        Outcome::Accepted => panic!("a revoked certificate was accepted"),
    }
    // the same list does not touch a certificate it does not name
    assert!(matches!(run_certificate(&with(Revocation::soft_fail(), rev::CRL_EMPTY), rev::LEAF, &[None]), Outcome::Accepted));
    // hard-fail is satisfied by a current CRL that covers the leaf, without any staple
    assert!(matches!(run_certificate(&with(Revocation::hard_fail(), rev::CRL_EMPTY), rev::LEAF, &[None]), Outcome::Accepted));
    // a staple that says "good" does not override a CRL that says "revoked"
    match run_certificate(&revoked, rev::LEAF, &[Some(rev::OCSP_GOOD)]) {
        Outcome::Rejected { error, .. } => assert!(error.contains("certificate_revoked"), "{}", error),
        Outcome::Accepted => panic!("a CRL entry was overridden by a good staple"),
    }
    // revocation checking switched off: nothing is consulted
    let off = with(Revocation::off(), rev::CRL_REVOKED);
    assert!(matches!(run_certificate(&off, rev::LEAF, &[None]), Outcome::Accepted));
}

#[test]
fn a_staple_nobody_asked_for_is_a_protocol_error() {
    // revocation off: no status_request was sent, so a server may not send a CertificateStatus
    match run_certificate(&rev_cfg(RevocationMode::Off), rev::LEAF, &[Some(rev::OCSP_GOOD)]) {
        Outcome::Rejected { error, alert } => {
            assert!(error.contains("unsupported_extension"), "{}", error);
            assert_eq!(alert, Some(110));
        }
        Outcome::Accepted => panic!("an unsolicited staple was accepted"),
    }
}

#[test]
fn a_staple_cannot_replace_the_certificate_checks() {
    // a good staple does not make an untrusted chain acceptable
    let chain = vec![crate::pem::parse(rev::LEAF).remove(0).data, crate::pem::parse(rev::INTER).remove(0).data];
    let flight = vec![ee(&[]), certificate_with_staples(&chain, &[Some(rev::OCSP_GOOD)]), handshake_message(HS_FINISHED, &[0u8; 32])];
    let mut cfg = ClientConfig::new(TrustStore::empty());
    cfg.time_override = Some(NOW);
    let (error, _) = handshake_error("example.test", &cfg, respond_with_flight(ShOpts::default(), flight.clone()));
    assert!(!error.contains("out of order"), "an untrusted chain got through: {}", error);
    // nor a name mismatch
    let (error, _) = handshake_error("other.test", &rev_cfg(RevocationMode::SoftFail), respond_with_flight(ShOpts::default(), flight));
    assert!(!error.contains("out of order"), "a wrong host name got through: {}", error);
}

// ------------------------------------------------------------------------------------ fuzzing

const NOW: i64 = 1_789_430_400;

/// A trust store and chain that validate for "example.test", so fuzzed flights get past the
/// Certificate message and into signature checking.
fn valid_chain() -> (TrustStore, Vec<Vec<u8>>) {
    let der = |p: &str| crate::pem::parse(p).remove(0).data;
    let mut ts = TrustStore::empty();
    ts.add_der(&der(include_str!("../../tests/data/root_rsa.pem"))).unwrap();
    let chain = vec![
        der(include_str!("../../tests/data/leaf_p384.pem")),
        der(include_str!("../../tests/data/inter_p256.pem")),
    ];
    (ts, chain)
}

fn certificate_body(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in chain {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
        list.extend_from_slice(&[0, 0]);
    }
    let mut body = vec![0];
    body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    body.extend(list);
    body
}

fn fuzz_message(rng: &mut Rng, msg_type: u8, body: &[u8]) -> Vec<u8> {
    let body = mutate(rng, body);
    let mut m = vec![msg_type];
    let len = if rng.chance(85) { body.len() } else { rng.below(1 << 20) };
    m.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    m.extend(body);
    m
}

#[test]
fn fuzzed_server_flights_never_panic_and_never_succeed() {
    let (ts, chain) = valid_chain();
    let cert_body = certificate_body(&chain);
    let mut cfg = ClientConfig::new(ts);
    cfg.time_override = Some(NOW);
    let cr_body = {
        let mut b = vec![0];
        b.extend(block16(&ext(EXT_SIGNATURE_ALGORITHMS, &block16(&[0x04, 0x03]))));
        b
    };
    let cv_body = {
        let mut b = vec![0x05, 0x03];
        b.extend(block16(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
        b
    };
    let kinds = std::cell::RefCell::new(std::collections::BTreeSet::new());
    run("tls_server_flights", 1500, |rng| {
        let suite = *rng.pick(&Suite::ALL);
        let with_request = rng.chance(40);
        // which message gets damaged (or none: the valid flight must still fail at the signature)
        let victim = rng.below(5);
        let mut msgs: Vec<(u8, Vec<u8>)> = vec![(HS_ENCRYPTED_EXTENSIONS, block16(&[]))];
        if with_request {
            msgs.push((HS_CERTIFICATE_REQUEST, cr_body.clone()));
        }
        msgs.push((HS_CERTIFICATE, cert_body.clone()));
        msgs.push((HS_CERTIFICATE_VERIFY, cv_body.clone()));
        msgs.push((HS_FINISHED, vec![0xab; suite.hash().output_len()]));
        let flight: Vec<u8> = msgs
            .iter()
            .enumerate()
            .flat_map(|(i, (t, b))| {
                if i % 5 == victim % msgs.len() && rng.chance(80) {
                    fuzz_message(rng, *t, b)
                } else {
                    handshake_message(*t, b)
                }
            })
            .collect();
        // cut the flight into records at random places (messages then span records)
        let mut cuts = vec![0usize];
        for _ in 0..rng.below(4) {
            cuts.push(rng.below(flight.len() + 1));
        }
        cuts.push(flight.len());
        cuts.sort();
        let extra_record = rng.below(12);
        let mut r2 = Rng::new(rng.next_u64());
        let respond = move |h: Hello| {
            let s = Session::new(h, suite);
            let (mut out, sh) = s.hello_records(&ShOpts::default());
            let mut c = s.flight_cipher(&sh);
            for (n, w) in cuts.windows(2).enumerate() {
                if n == extra_record {
                    // an unexpected record type in the middle of the flight
                    let t = *r2.pick(&[RT_APPLICATION_DATA, RT_ALERT, 0, 25, 255]);
                    let body = random_up_to(&mut r2, 20);
                    c.encrypt_into(t, &body, &mut out);
                }
                c.encrypt_into(RT_HANDSHAKE, &flight[w[0]..w[1]], &mut out);
            }
            out
        };
        let (io, _) = FakeServer::new(respond);
        match TlsStream::connect(io, "example.test", &cfg) {
            Ok(_) => panic!("a fuzzed flight completed a handshake"),
            Err(e) => {
                let text = e.to_string();
                kinds.borrow_mut().insert(text.chars().take(45).collect::<String>());
            }
        }
    });
    let kinds = kinds.into_inner();
    // the harness must be reaching many different parts of the handshake, not failing at once
    assert!(kinds.len() >= 8, "only {} distinct failures reached: {:?}", kinds.len(), kinds);
}

fn established(suite: Suite, stream: Vec<u8>) -> TlsStream<FakeServer> {
    let n = suite.hash().output_len();
    TlsStream { io: FakeServer::playing(stream), conn: ClientConnection::established(suite, &vec![2u8; n], &vec![1u8; n]) }
}

#[test]
fn fuzzed_post_handshake_records_never_panic() {
    let delivered = std::cell::Cell::new(0usize);
    let key_updates = std::cell::Cell::new(0usize);
    run("tls_post_handshake", 3000, |rng| {
        let suite = *rng.pick(&Suite::ALL);
        let n = suite.hash().output_len();
        let mut sealer = RecordCipher::new(suite, &vec![2u8; n]);
        let mut stream = Vec::new();
        for _ in 0..1 + rng.below(8) {
            match rng.below(8) {
                0 | 1 => {
                    let body = random_up_to(rng, 300);
                    sealer.encrypt_into(RT_APPLICATION_DATA, &body, &mut stream);
                }
                2 => {
                    let alert = *rng.pick(&[&[1u8, 0][..], &[2, 40], &[1], &[], &[1, 0, 0], &[1, 90]]);
                    sealer.encrypt_into(RT_ALERT, alert, &mut stream);
                }
                3 => {
                    // KeyUpdate, well formed or not; after a good one the server's keys move on
                    let req = rng.below(3) as u8;
                    let msg = handshake_message(HS_KEY_UPDATE, &[req]);
                    let msg = if rng.chance(30) { mutate(rng, &msg) } else { msg };
                    sealer.encrypt_into(RT_HANDSHAKE, &msg, &mut stream);
                    if msg == handshake_message(HS_KEY_UPDATE, &[req]) && req <= 1 {
                        sealer = sealer.next_generation();
                        key_updates.set(key_updates.get() + 1);
                    }
                }
                4 => {
                    let body = random_up_to(rng, 100);
                    let msg = handshake_message(HS_NEW_SESSION_TICKET, &body);
                    sealer.encrypt_into(RT_HANDSHAKE, &msg, &mut stream);
                }
                5 => {
                    let t = *rng.pick(&[0u8, 20, 24, 25, 100, 255]);
                    let body = random_up_to(rng, 50);
                    sealer.encrypt_into(t, &body, &mut stream);
                }
                6 => {
                    // a handshake message split over two records
                    let msg = handshake_message(HS_NEW_SESSION_TICKET, &[0; 40]);
                    let cut = rng.below(msg.len() + 1);
                    sealer.encrypt_into(RT_HANDSHAKE, &msg[..cut], &mut stream);
                    sealer.encrypt_into(RT_HANDSHAKE, &msg[cut..], &mut stream);
                }
                _ => {
                    // damage the wire bytes themselves
                    let before = stream.len();
                    sealer.encrypt_into(RT_APPLICATION_DATA, b"damaged", &mut stream);
                    let damaged = mutate(rng, &stream[before..].to_vec());
                    stream.truncate(before);
                    stream.extend(damaged);
                }
            }
        }
        if rng.chance(15) {
            stream = mutate(rng, &stream);
        }
        let mut tls = established(suite, stream);
        let mut buf = vec![0u8; 1 + rng.below(400)];
        for _ in 0..40 {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => delivered.set(delivered.get() + n),
            }
            if rng.chance(20) {
                let _ = tls.write(b"hello");
            }
        }
    });
    assert!(delivered.get() > 1000, "the fuzz run delivered almost no application data ({})", delivered.get());
    assert!(key_updates.get() > 50, "too few valid KeyUpdates were exercised ({})", key_updates.get());
}

#[test]
fn random_bytes_from_the_server_never_panic() {
    run("tls_random_streams", 2000, |rng| {
        let stream = if rng.chance(50) {
            random_up_to(rng, 2000)
        } else {
            // plausible record headers followed by junk
            let mut s = Vec::new();
            for _ in 0..1 + rng.below(6) {
                let rt = *rng.pick(&[20u8, 21, 22, 23, 24, 0]);
                let body = random_up_to(rng, 80);
                s.extend(plain_record(rt, &body));
            }
            mutate(rng, &s)
        };
        let (io, _) = FakeServer::new(move |_| stream);
        assert!(TlsStream::connect(io, "example.test", &config_for_tests()).is_err());
    });
}
