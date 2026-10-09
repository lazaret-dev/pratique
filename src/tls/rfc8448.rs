//! The "Simple 1-RTT Handshake" of RFC 8448 section 3, replayed through the client.
//!
//! RFC 8448 is the IETF's trace of a complete TLS 1.3 handshake with every secret, key and record
//! printed, produced by independent implementations. The client here is given the trace's
//! ClientHello and X25519 private key (see `ClientConnection::with_recorded_hello`), then fed the
//! trace's ServerHello and encrypted server flight. If its key schedule, transcript hashing,
//! record protection, CertificateVerify and Finished handling are right, it ends up with the very
//! bytes the RFC prints for the client's Finished record and for application data in both
//! directions. That checks the glue between the primitives, which the OpenSSL tests only check
//! against one other implementation, and without a network.
//!
//! The trace is TLS_AES_128_GCM_SHA256 with an RSA-1024 self-signed certificate (so certificate
//! validation is off; its CertificateVerify, RSASSA-PSS, is still checked) and a ClientHello that
//! differs from ours (no session id, `record_size_limit`), which is why the connection is built
//! from the recorded hello.
//!
//! About the data: the trace was copied from the RFC text by a tool that misread one byte of the
//! 679-byte server flight record (offset 218). That byte was recomputed from the RFC's own
//! plaintext messages, server handshake key and IV with an independent AES-GCM (Python
//! `cryptography`), which reproduces the other 678 bytes exactly; every secret and key below is
//! copied from the RFC and checked against the library (`key_schedule_matches_the_rfc_trace`), and
//! the client's records are compared with the RFC's bytes. The server's application-data record
//! is number 1 in its direction (the RFC's NewSessionTicket is number 0).

use super::conn::ClientConnection;
use super::suite::*;
use super::*;
use crate::crypto::sha2::HashAlg;
use crate::crypto::x25519;
use crate::util::hex;

/// Hex with any whitespace, as the RFC prints it.
fn h(text: &str) -> Vec<u8> {
    let digits: String = text.split_whitespace().collect();
    crate::util::unhex(&digits)
}

fn client_hello() -> Vec<u8> {
    h("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38
       c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef
       62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01
       00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76
       65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
       17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
       23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
       e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e
       51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00
       03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
       02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
       04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
       00 02 40 01")
}

/// The client's ephemeral X25519 private key (RFC 8448 section 3).
fn client_private() -> [u8; 32] {
    h("49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05").try_into().unwrap()
}

/// The ServerHello as a TLS record.
fn server_hello_record() -> Vec<u8> {
    h("16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12
       18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb
       14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00
       2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95
       fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d
       f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04")
}

/// EncryptedExtensions, Certificate, CertificateVerify and Finished, in one protected record.
fn server_flight_record() -> Vec<u8> {
    h("17 03 03 02 a2 d1 ff 33 4a 56 f5 bf f6 59 4a 07
       cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e
       df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca
       07 61 2e f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78
       b1 11 b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61
       34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
       d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79
       02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d 57 a6 b9
       d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25 0c
       7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e
       d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3
       60 98 72 55 cc 74 41 10 c4 53 ba a4 fc d6 10 92
       8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82
       04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 86 94
       5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8
       94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68
       45 96 c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63
       aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f
       44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26
       4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26
       f5 9e ca ba 9a cb bb 31 7b 66 d9 02 f4 f2 92 a3
       6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22 45 31
       7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64
       7e 92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e
       1b 7a 6c 71 78 af 36 87 90 18 e3 f2 52 10 7f 24
       3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da
       8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c
       f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4
       61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c
       74 11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be
       5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18
       a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb
       99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88 cb
       56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59
       77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51 56 14
       63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38
       eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97
       8c 31 7f c9 fa 66 a7 3f 60 f0 50 4d e9 3b 5b 84
       5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78
       40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5
       d2 af 93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31
       ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e
       75 0e dc 53 37 0d 2b")
}

/// The client's Finished, protected with its handshake traffic keys.
fn client_finished_record() -> Vec<u8> {
    h("17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44
       a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc
       44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c
       ae ac ab 68 67 d7 26 c4 05 46")
}

/// 50 bytes of application data, 00 01 02 ... 31, sent by the client under its application keys.
fn client_app_record() -> Vec<u8> {
    h("17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe
       82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f
       2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b
       62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6
       3a ee bb 21 69 49 15 e4")
}

/// The same 50 bytes sent by the server.
fn server_app_record() -> Vec<u8> {
    h("17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad
       36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36
       e3 0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8
       fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3 32 54
       0d d0 32 e1 67 c2 95 5d")
}

fn app_data() -> Vec<u8> {
    (0u8..50).collect()
}

/// The handshake messages inside the server's flight, as printed in the RFC, for the transcript.
fn server_flight_messages() -> [Vec<u8>; 4] {
    let encrypted_extensions = h("08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17
       00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
       00 02 40 01 00 00 00 00");
    let certificate = h("0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
       82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a
       86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a
       06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36
       30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30
       37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
       06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06
       09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00
       30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98
       08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
       d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a
       95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12
       09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
       63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80
       30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
       3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a
       8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18
       30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55
       1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86
       f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5
       b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f
       8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
       8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a
       03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02
       70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e
       b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0
       a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8
       f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00");
    let certificate_verify = h("0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2
       e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
       b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3
       3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee
       aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51
       1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
       9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09
       d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2
       0d 53 df ac d4 2f 74 f3");
    let finished = h("14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7
       1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54
       b7 8f 07 18");
    [encrypted_extensions, certificate, certificate_verify, finished]
}

/// The ServerHello handshake message (the record without its 5-byte header).
fn server_hello_message() -> Vec<u8> {
    server_hello_record()[5..].to_vec()
}

fn trace_config() -> ClientConfig {
    ClientConfig::new(crate::x509::TrustStore::empty()).danger_disable_verification()
}

fn start() -> ClientConnection {
    let mut c = ClientConnection::with_recorded_hello("server", &trace_config(), client_private(), &[], &client_hello(), &[0x001c]);
    let hello_out = c.output().len();
    c.consume_output(hello_out);
    c
}

/// Feeds `bytes` in pieces of `piece` bytes, processing after each, and returns the first error.
fn feed(c: &mut ClientConnection, bytes: &[u8], piece: usize) -> crate::error::Result<Vec<u8>> {
    let mut app = Vec::new();
    for part in bytes.chunks(piece.max(1)) {
        let mut rest = part;
        while !rest.is_empty() || c.has_plaintext() {
            let mut buf = [0u8; 256];
            let n = c.read_plaintext(&mut buf);
            app.extend_from_slice(&buf[..n]);
            if rest.is_empty() {
                continue;
            }
            let space = c.recv_buf();
            let n = space.len().min(rest.len());
            space[..n].copy_from_slice(&rest[..n]);
            c.recv_filled(n);
            rest = &rest[n..];
            c.process()?;
        }
    }
    let mut buf = [0u8; 256];
    loop {
        let n = c.read_plaintext(&mut buf);
        if n == 0 {
            break;
        }
        app.extend_from_slice(&buf[..n]);
    }
    Ok(app)
}

fn take_output(c: &mut ClientConnection) -> Vec<u8> {
    let out = c.output().to_vec();
    c.consume_output(out.len());
    out
}

#[test]
fn the_recorded_values_are_what_the_rfc_prints() {
    // sizes the RFC states, so that a mistake in copying the trace shows up here and not as a
    // mysterious failure further down
    assert_eq!(client_hello().len(), 196);
    assert_eq!(server_hello_record().len(), 95);
    assert_eq!(server_flight_record().len(), 679);
    assert_eq!(client_finished_record().len(), 58);
    assert_eq!(client_app_record().len(), 72);
    assert_eq!(server_app_record().len(), 72);
    let flight = server_flight_messages();
    assert_eq!(flight.iter().map(|m| m.len()).collect::<Vec<_>>(), vec![40, 445, 136, 36]);
    // the key share in the ClientHello is the public key of the private key
    let public = x25519::public_key(&client_private());
    assert_eq!(hex(&public), "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    assert!(client_hello().windows(32).any(|w| w == public));
}

/// The secrets and keys of RFC 8448 section 3, from the library's own primitives, in the order
/// RFC 8446 section 7.1 derives them.
#[test]
fn key_schedule_matches_the_rfc_trace() {
    let alg = HashAlg::Sha256;
    let zeros = [0u8; 32];
    let early = hkdf_extract(alg, &[], &zeros);
    assert_eq!(hex(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");

    // the server's key share: the 32 bytes after key_share(0x33), length 0x24, group x25519, length 0x20
    let sh = server_hello_message();
    let at = sh.windows(8).position(|w| w == [0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]).expect("a key_share extension") + 8;
    let server_share: [u8; 32] = sh[at..at + 32].try_into().unwrap();
    assert_eq!(hex(&server_share), "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
    let shared = x25519::x25519(&client_private(), &server_share);
    let derived = derive_secret(alg, &early, "derived", &alg.digest(&[]));
    let handshake = hkdf_extract(alg, &derived, &shared);
    assert_eq!(hex(&handshake), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");

    let mut transcript = client_hello();
    transcript.extend(server_hello_message());
    let hello_hash = alg.digest(&transcript);
    let c_hs = derive_secret(alg, &handshake, "c hs traffic", &hello_hash);
    let s_hs = derive_secret(alg, &handshake, "s hs traffic", &hello_hash);
    assert_eq!(hex(&c_hs), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    assert_eq!(hex(&s_hs), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    // the client's handshake write key and iv, and the server Finished key
    assert_eq!(hex(&expand_label(alg, &c_hs, "key", &[], 16)), "dbfaa693d1762c5b666af5d950258d01");
    assert_eq!(hex(&expand_label(alg, &c_hs, "iv", &[], 12)), "5bd3c71b836e0b76bb73265f");
    assert_eq!(hex(&expand_label(alg, &s_hs, "finished", &[], 32)), "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");

    // application secrets: the transcript through the server's Finished
    for m in server_flight_messages() {
        transcript.extend(m);
    }
    let app_hash = alg.digest(&transcript);
    let derived2 = derive_secret(alg, &handshake, "derived", &alg.digest(&[]));
    let master = hkdf_extract(alg, &derived2, &zeros);
    assert_eq!(hex(&master), "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    let c_ap = derive_secret(alg, &master, "c ap traffic", &app_hash);
    let s_ap = derive_secret(alg, &master, "s ap traffic", &app_hash);
    assert_eq!(hex(&c_ap), "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    assert_eq!(hex(&s_ap), "a11af9f05531f856ad47116b45a95032 8204b4f44bfb6b3a4b4f1f3fcb631643".replace(' ', ""));
    assert_eq!(hex(&expand_label(alg, &c_ap, "key", &[], 16)), "17422dda596ed5d9acd890e3c63f5051");
    assert_eq!(hex(&expand_label(alg, &c_ap, "iv", &[], 12)), "5b78923dee08579033e523d9");
    assert_eq!(hex(&expand_label(alg, &s_ap, "key", &[], 16)), "9f02283b6c9c07efc26bb9f2ac92e356");
    assert_eq!(hex(&expand_label(alg, &s_ap, "iv", &[], 12)), "cf782b88dd83549aadf1e984");
}

#[test]
fn the_client_completes_the_rfc_trace_and_produces_its_bytes() {
    // whole, and in pieces of every awkward size: the flight is one 679-byte record
    for piece in [usize::MAX, 1, 2, 5, 7, 64, 100, 679] {
        let mut c = start();
        let mut flight = server_hello_record();
        flight.extend(server_flight_record());
        feed(&mut c, &flight, piece).unwrap_or_else(|e| panic!("piece {piece}: {e}"));

        assert!(c.is_established(), "piece {piece}");
        assert_eq!(c.cipher_suite(), Some(Suite::Aes128GcmSha256));
        assert_eq!(c.alpn_protocol(), None);
        let cert = crate::x509::Certificate::from_der(c.peer_certificate().expect("the server's certificate")).unwrap();
        assert!(cert.subject_summary().contains("rsa"), "{}", cert.subject_summary());

        // the client's Finished is exactly the RFC's, byte for byte (no change_cipher_spec: the
        // trace's ClientHello had an empty session id)
        assert_eq!(hex(&take_output(&mut c)), hex(&client_finished_record()), "piece {piece}");

        // application data both ways under the application keys
        assert_eq!(c.write_plaintext(&app_data()).unwrap(), 50);
        assert_eq!(hex(&take_output(&mut c)), hex(&client_app_record()), "piece {piece}");
        // The trace's server sends a NewSessionTicket under its application keys before the data, so
        // the data record is number 1 in that direction. The RFC's ticket is not copied here: any
        // ticket (which this client ignores) under the RFC's server application secret does.
        let mut server_keys = RecordCipher::new(Suite::Aes128GcmSha256, &h("a11af9f05531f856ad47116b45a95032 8204b4f44bfb6b3a4b4f1f3fcb631643"));
        let ticket = [&[0x04u8, 0, 0, 17][..], &[0, 0, 0x1e, 0, 1, 2, 3, 4, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef, 0, 0]].concat();
        assert_eq!(feed(&mut c, &server_keys.encrypt(RT_HANDSHAKE, &ticket), piece).unwrap(), b"", "piece {piece}");
        assert_eq!(feed(&mut c, &server_app_record(), piece).unwrap(), app_data(), "piece {piece}");
    }
}

#[test]
fn any_change_to_the_recorded_server_flight_breaks_the_handshake() {
    // every byte of the ServerHello record and the flight, flipped one at a time: the handshake
    // must fail (key share, transcript, record MAC, certificate, signature or Finished) and must
    // never end with an established connection
    let mut stream = server_hello_record();
    stream.extend(server_flight_record());
    for i in 0..stream.len() {
        if i == 2 {
            // the minor version of a record header is not checked (RFC 8446 section 5.1: it is
            // frozen at 0x0303 only for compatibility, and a ServerHello record may carry 0x0301)
            continue;
        }
        let mut damaged = stream.clone();
        damaged[i] ^= 0x01;
        let mut c = start();
        let result = feed(&mut c, &damaged, usize::MAX);
        assert!(result.is_err() || !c.is_established(), "flipping byte {i} still completed the handshake");
    }
    // and a flight that stops early never completes
    for len in 0..stream.len() {
        let mut c = start();
        let result = feed(&mut c, &stream[..len], usize::MAX);
        assert!(result.is_ok() && !c.is_established(), "{len} bytes completed the handshake or failed oddly");
    }
}
