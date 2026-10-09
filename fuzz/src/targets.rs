//! What gets fuzzed, and what must hold.
//!
//! Every target takes the raw bytes the engine made up. Besides "does not panic, hang or balloon",
//! each asserts something about the answer, because a parser that quietly accepts the wrong thing
//! is the dangerous kind of bug:
//!
//! | target            | invariant beyond "no panic"                                                     |
//! |-------------------|----------------------------------------------------------------------------------|
//! | `der`             | elements lie inside their input and use the shortest length form; INTEGERs are minimal; a time that parses is a real calendar date |
//! | `certificate`     | the certificate keeps exactly the bytes it was given; only a known certificate verifies its own signature |
//! | `hostname`        | a wildcard pattern matches exactly one label and nothing else                    |
//! | `chain`           | a chain that is not made of known certificates, or a host or time the leaf is not valid for, is never accepted |
//! | `pem`             | Base64 and PEM armor round-trip                                                  |
//! | `note`            | a signed note opens only with signatures that are known good ones (see `log_targets.rs`) |
//! | `tlog`            | Merkle proof checks agree with a second implementation; any changed or missing tile is refused |
//! | `sumdb`           | what parses prints back; a made-up log in two histories never has both accepted |
//! | `ber`             | whatever parses can be walked (constructed elements have children and no content, primitive ones the reverse); what `der()` writes is strict DER, parses again and writes itself unchanged |
//! | `cms`             | a CMS message or RFC 3161 token made from the OpenSSL and JDK fixtures and changed by the input verifies only with a signature value, content and certificate that a fixture message verified with, at the caller's time or a fixture time stamp's (see `cms_targets.rs`) |
//! | `json`            | what parses has unique object names and RFC 8259 numbers; the canonical form parses again, is its own canonical form and ignores member order; padding with white space changes nothing, any other trailing byte is refused; a smaller depth limit only takes values away (see `sigstore_targets.rs`) |
//! | `sigstore`        | a Sigstore bundle (our own synthetic Sigstore, npm's attestations, PyPI's provenance) changed by the input verifies only to the facts of a seed that verified: signer, statement, subject, times and log entries (see `sigstore_targets.rs`) |
//! | `tuf`             | a file of a good synthetic TUF repository replaced by the input: the client gives the case's own target or refuses, never other bytes; TUF's canonical JSON is its own canonical form (see `sigstore_targets.rs`) |
//! | `sct`             | a real Fulcio certificate with its SCT list replaced by the input still parses and has the same precertificate; a list that parses is its own bytes; an SCT verifies only as the log signed it, and only with the certificate's issuer (see `sigstore_targets.rs`) |
//! | `trust_root`      | a trusted root or npm key list that parses parses again, equal, from its canonical JSON, with consistent keys, logs and authorities; an RFC 3339 time that parses is the calendar time its digits say |
//! | `ed25519`         | a signature verifies only if it is a known good one or its key has small order; adding L to S always breaks it |
//! | `crl`             | a list that is not byte-for-byte a known good one never gives "good" or "revoked" |
//! | `ocsp`            | the same for OCSP responses                                                       |
//! | `revocation_path` | `Off` always accepts, `HardFail` implies `SoftFail`, evidence marked revoked is never accepted, `HardFail` needs known-good evidence |
//! | `http_response`   | the result does not depend on how the bytes are cut into reads                   |
//! | `inflate`         | DEFLATE, zlib and gzip: the result (bytes or error) does not depend on how the input and the output are cut; nothing past the limit; a stream fits at exactly its size and not one byte under; within the ratio; zlib implies "zlib or DEFLATE" and one gzip member implies gzip (see `inflate_targets.rs`) |
//! | `url`             | print and parse again gives the same URL; a relative redirect keeps the origin   |
//! | `egress`          | a client with a rule about hosts (entries, one-label wildcards, the default port only), limits on a URL and a hook that gives each hop its headers decides about a request and every redirect as a second, simple account of the rules does, a refused hop leaves the request as it was, the hook's headers are this hop's and no other's, and what is sent is well made |
//! | `aead`            | AES-GCM and ChaCha20-Poly1305 made by the code this CPU gets (vector kernels where there are some: the aarch64 ones on an ARM machine) are the same bytes as the portable code makes, are read by both, and are not read when anything of them is changed |
//! | `h3_qpack`, `h3_qpack_exchange`, `h3_qpack_encoder` | the QPACK decoder fed anything, our encoder and decoder over links that delay and cut, the encoder fed a hostile decoder stream: bookkeeping adds up, limits hold, what is encoded decodes to what was given (see `h3_targets.rs`) |
//! | `h3_connection` | a whole HTTP/3 client connection against a server made up from the bytes, with a QPACK table, delays, resets, GOAWAY and garbage: books balance, errors have the RFCs' codes, what a well-made server sent is what is read, what the client wrote decodes |
//! | `alt_svc` | an `Alt-Svc` field value: skipped or read as one alternative within bounds, which written out again reads back the same, whatever of another protocol is in front of it |
//! | `h3_frames` | the HTTP/3 frame reader against a model that has the whole stream before it, however the stream is cut; what it read is written again and read back |
//! | `quic_packet`     | a packet made from the fields in the input is sealed, read back and opened as what went in, and not opened with one bit changed; a datagram is read as coalesced packets within its bytes (see `quic_targets.rs`) |
//! | `quic_frame`      | a packet payload is read as frames or refused; every frame lies inside the payload, writes and reads again as itself, and is allowed in its packet type |
//! | `quic_params`     | transport parameters are within RFC 9000 section 18.2's limits, have no id twice, round-trip and write canonically (see `quic_state_targets.rs`) |
//! | `quic_buffers`    | `RangeSet` equals a set of numbers; `SendBuf` into `Reassembler` over a lossy path delivers exactly the bytes written; `Reassembler` equals a map of bytes, and a refusal changes nothing |
//! | `quic_streams`    | two stream endpoints over a lossy path lose and change no byte and keep their books; one endpoint fed any frames never panics and writes frames that fit |
//! | `quic_recovery`   | loss recovery agrees with a model of the outstanding packets: bytes in flight, what an ack acknowledges, what the thresholds declare lost, the timer, the congestion window floor |
//! | `quic_connection` | a whole connection against the test server over a lossy, duplicating, corrupting network: honest, every byte arrives and the connection ends by the idle timeout; hostile, no panic, no growth, no oversize datagram (see `src/quic/fuzz_hooks.rs`) |
//! | `tls_records`     | (no panic) raw bytes at a fresh client: record layer, ServerHello, retry         |
//! | `tls_flight`      | a server flight sealed under the right keys (after a retry too) never completes  |
//! | `tls_post`        | (no panic) records at an established connection, including KeyUpdates and our own writes; TLS 1.2 ones too (HelloRequest) |
//! | `tls12_flight`    | a TLS 1.2 server's flight in the clear after its ServerHello (a correctly signed ServerKeyExchange in the seeds) never completes |

use crate::seed_data;
use std::sync::OnceLock;
use pratique::asn1::{self, Der};
use pratique::pem;
use pratique::x509::{dns_pattern_matches, Certificate, GeneralName, Purpose, TrustStore, VerifyOptions};

/// The CMS messages of the fixtures, as they are, for the BER reader.
fn seeds_cms_blobs() -> Vec<Vec<u8>> {
    crate::cms_targets::seeds_cms().into_iter().map(|s| s[1..].to_vec()).collect()
}

pub struct Target {
    pub name: &'static str,
    pub run: fn(&[u8]),
    pub seeds: fn() -> Vec<Vec<u8>>,
    pub dict: &'static [&'static [u8]],
    /// Longest input the engine will make.
    pub max_len: usize,
    /// Memory a run may allocate beyond this plus `alloc_per_byte` times the input length before it
    /// is reported as bloat.
    pub alloc_base: usize,
    pub alloc_per_byte: usize,
}

pub fn all() -> Vec<Target> {
    vec![
        Target { name: "der", run: der, seeds: seeds_certificates, dict: DER_DICT, max_len: 2048, alloc_base: 1 << 16, alloc_per_byte: 64 },
        Target { name: "certificate", run: certificate, seeds: seeds_certificates, dict: DER_DICT, max_len: 2048, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "hostname", run: hostname, seeds: seeds_hostnames, dict: HOST_DICT, max_len: 128, alloc_base: 1 << 16, alloc_per_byte: 64 },
        Target { name: "idna", run: idna, seeds: seeds_idna, dict: HOST_DICT, max_len: 256, alloc_base: 1 << 16, alloc_per_byte: 64 },
        Target { name: "chain", run: chain, seeds: seeds_chains, dict: DER_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "chain_algs", run: chain_algs, seeds: seeds_chain_algs, dict: DER_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "purpose_chain", run: purpose_chain, seeds: seeds_purpose_chains, dict: DER_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "ed25519", run: ed25519, seeds: seeds_ed25519, dict: ED25519_DICT, max_len: 384, alloc_base: 1 << 16, alloc_per_byte: 64 },
        Target { name: "note", run: crate::log_targets::note, seeds: crate::log_targets::seeds_note, dict: crate::log_targets::NOTE_DICT, max_len: 2049, alloc_base: 1 << 18, alloc_per_byte: 64 },
        Target { name: "tlog", run: crate::log_targets::tlog, seeds: crate::log_targets::seeds_tlog, dict: crate::log_targets::TLOG_DICT, max_len: 2200, alloc_base: 1 << 22, alloc_per_byte: 256 },
        Target { name: "sumdb", run: crate::log_targets::sumdb, seeds: crate::log_targets::seeds_sumdb, dict: crate::log_targets::SUMDB_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "ber", run: crate::cms_targets::ber, seeds: seeds_cms_blobs, dict: crate::cms_targets::CMS_DICT, max_len: 4096, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "cms", run: crate::cms_targets::cms, seeds: crate::cms_targets::seeds_cms, dict: crate::cms_targets::CMS_DICT, max_len: 4096, alloc_base: 1 << 22, alloc_per_byte: 512 },
        Target { name: "json", run: crate::sigstore_targets::json, seeds: crate::sigstore_targets::seeds_json, dict: crate::sigstore_targets::JSON_DICT, max_len: 1024, alloc_base: 1 << 18, alloc_per_byte: 256 },
        Target { name: "sigstore", run: crate::sigstore_targets::sigstore, seeds: crate::sigstore_targets::seeds_sigstore, dict: crate::sigstore_targets::SIGSTORE_DICT, max_len: 16384, alloc_base: 1 << 23, alloc_per_byte: 512 },
        Target { name: "tuf", run: crate::sigstore_targets::tuf, seeds: crate::sigstore_targets::seeds_tuf, dict: crate::sigstore_targets::TUF_DICT, max_len: 8192, alloc_base: 1 << 22, alloc_per_byte: 512 },
        Target { name: "sct", run: crate::sigstore_targets::sct, seeds: crate::sigstore_targets::seeds_sct, dict: crate::sigstore_targets::SCT_DICT, max_len: 1024, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "trust_root", run: crate::sigstore_targets::trust_root, seeds: crate::sigstore_targets::seeds_trust_root, dict: crate::sigstore_targets::TRUST_ROOT_DICT, max_len: 8192, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "h2_hpack", run: crate::h2_targets::hpack, seeds: crate::h2_targets::seeds_hpack, dict: crate::h2_targets::H2_DICT, max_len: 2048, alloc_base: 1 << 21, alloc_per_byte: 512 },
        Target { name: "h2_frames", run: crate::h2_targets::frames, seeds: crate::h2_targets::seeds_frames, dict: crate::h2_targets::H2_DICT, max_len: 2048, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "h2_client", run: crate::h2_targets::client, seeds: crate::h2_targets::seeds_client, dict: crate::h2_targets::H2_DICT, max_len: 4096, alloc_base: 1 << 23, alloc_per_byte: 1024 },
        Target { name: "h2_server", run: crate::h2_targets::server, seeds: crate::h2_targets::seeds_server, dict: crate::h2_targets::H2_DICT, max_len: 4096, alloc_base: 1 << 23, alloc_per_byte: 1024 },
        Target { name: "h3_qpack", run: crate::h3_targets::qpack, seeds: crate::h3_targets::seeds_qpack, dict: crate::h3_targets::QPACK_DICT, max_len: 2048, alloc_base: 1 << 23, alloc_per_byte: 4096 },
        Target { name: "h3_qpack_exchange", run: crate::h3_targets::exchange, seeds: crate::h3_targets::seeds_exchange, dict: &[], max_len: 2048, alloc_base: 1 << 23, alloc_per_byte: 4096 },
        Target { name: "h3_qpack_encoder", run: crate::h3_targets::encoder, seeds: crate::h3_targets::seeds_encoder, dict: crate::h3_targets::QPACK_DICT, max_len: 2048, alloc_base: 1 << 23, alloc_per_byte: 4096 },
        Target { name: "alt_svc", run: crate::h3_targets::alt_svc, seeds: crate::h3_targets::seeds_alt_svc, dict: crate::h3_targets::ALT_SVC_DICT, max_len: 600, alloc_base: 1 << 20, alloc_per_byte: 1024 },
        Target { name: "h3_frames", run: crate::h3_targets::frames, seeds: crate::h3_targets::seeds_frames, dict: crate::h3_targets::FRAME_DICT, max_len: 4096, alloc_base: 1 << 23, alloc_per_byte: 4096 },
        Target { name: "h3_connection", run: crate::h3_targets::connection, seeds: crate::h3_targets::seeds_connection, dict: &[], max_len: 6000, alloc_base: 1 << 24, alloc_per_byte: 8192 },
        Target { name: "quic_packet", run: crate::quic_targets::packet, seeds: crate::quic_targets::seeds_packet, dict: crate::quic_targets::QUIC_DICT, max_len: 1500, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "quic_frame", run: crate::quic_targets::frame, seeds: crate::quic_targets::seeds_frame, dict: crate::quic_targets::QUIC_DICT, max_len: 1500, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "quic_params", run: crate::quic_state_targets::params, seeds: crate::quic_state_targets::seeds_params, dict: crate::quic_state_targets::PARAMS_DICT, max_len: 600, alloc_base: 1 << 18, alloc_per_byte: 256 },
        Target { name: "quic_buffers", run: crate::quic_state_targets::buffers, seeds: crate::quic_state_targets::seeds_buffers, dict: &[], max_len: 1500, alloc_base: 1 << 22, alloc_per_byte: 4096 },
        Target { name: "quic_streams", run: crate::quic_state_targets::streams, seeds: crate::quic_state_targets::seeds_streams, dict: crate::quic_targets::QUIC_DICT, max_len: 1500, alloc_base: 1 << 24, alloc_per_byte: 8192 },
        Target { name: "quic_recovery", run: crate::quic_state_targets::recovery, seeds: crate::quic_state_targets::seeds_recovery, dict: &[], max_len: 1500, alloc_base: 1 << 22, alloc_per_byte: 4096 },
        Target { name: "quic_connection", run: crate::quic_state_targets::connection, seeds: crate::quic_state_targets::seeds_connection, dict: crate::quic_state_targets::CONNECTION_DICT, max_len: 800, alloc_base: 1 << 26, alloc_per_byte: 65536 },
        Target { name: "pem", run: pem_text, seeds: seeds_pem, dict: PEM_DICT, max_len: 3072, alloc_base: 1 << 20, alloc_per_byte: 64 },
        Target { name: "signing_key", run: crate::key_targets::signing_key, seeds: crate::key_targets::seeds_signing_key, dict: crate::key_targets::KEY_DICT, max_len: 3072, alloc_base: 1 << 20, alloc_per_byte: 256 },
        Target { name: "crl", run: crl, seeds: seeds_crl, dict: DER_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "ocsp", run: ocsp, seeds: seeds_ocsp, dict: DER_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "revocation_path", run: revocation_path, seeds: seeds_revocation_path, dict: DER_DICT, max_len: 6144, alloc_base: 1 << 22, alloc_per_byte: 256 },
        Target { name: "http_response", run: http_response, seeds: seeds_http, dict: HTTP_DICT, max_len: 2048, alloc_base: 1 << 18, alloc_per_byte: 64 },
        Target { name: "inflate", run: crate::inflate_targets::inflate, seeds: crate::inflate_targets::seeds_inflate, dict: crate::inflate_targets::INFLATE_DICT, max_len: 4096, alloc_base: 1 << 23, alloc_per_byte: 2048 },
        Target { name: "url", run: url, seeds: seeds_url, dict: URL_DICT, max_len: 512, alloc_base: 1 << 16, alloc_per_byte: 64 },
        Target { name: "egress", run: egress, seeds: seeds_egress, dict: EGRESS_DICT, max_len: 700, alloc_base: 1 << 20, alloc_per_byte: 2048 },
        Target { name: "aead", run: aead, seeds: seeds_aead, dict: &[], max_len: 1200, alloc_base: 1 << 20, alloc_per_byte: 64 },
        Target { name: "tls_records", run: tls_records, seeds: seeds_tls_records, dict: TLS_DICT, max_len: 4096, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "tls_flight", run: tls_flight, seeds: seeds_tls_flight, dict: TLS_DICT, max_len: 8192, alloc_base: 1 << 22, alloc_per_byte: 256 },
        Target { name: "tls_post", run: tls_post, seeds: seeds_tls_post, dict: TLS_DICT, max_len: 2048, alloc_base: 1 << 21, alloc_per_byte: 256 },
        Target { name: "tls12_flight", run: tls12_flight, seeds: seeds_tls12_flight, dict: TLS_DICT, max_len: 4096, alloc_base: 1 << 22, alloc_per_byte: 256 },
        Target { name: "tls_server", run: tls_server, seeds: pratique::tls::server_fuzz::server_exchange_seeds, dict: TLS_DICT, max_len: 4096, alloc_base: 1 << 23, alloc_per_byte: 512 },
    ]
}

/// Targets that misbehave on purpose, to check that the engine notices and saves the input (run
/// them with `run selftest_hang` and so on; they are not part of a campaign).
pub fn selftests() -> Vec<Target> {
    fn seeds() -> Vec<Vec<u8>> {
        vec![b"go".to_vec()]
    }
    fn panics(d: &[u8]) {
        if d.len() >= 2 {
            panic!("selftest: a panic");
        }
    }
    fn overflows(d: &[u8]) {
        let x = std::hint::black_box(d.len() as u8);
        if d.len() >= 2 {
            let _ = x + 255; // an arithmetic overflow, found because the fuzz build has overflow-checks on
        }
    }
    fn hangs(d: &[u8]) {
        if d.len() >= 2 {
            loop {
                std::hint::black_box(());
            }
        }
    }
    #[allow(unconditional_recursion)]
    fn recurse(n: usize) -> usize {
        let pad = [n as u8; 256];
        std::hint::black_box(&pad);
        recurse(n + 1) + pad[0] as usize
    }
    fn overflows_the_stack(d: &[u8]) {
        if d.len() >= 2 {
            std::hint::black_box(recurse(0));
        }
    }
    fn aborts(d: &[u8]) {
        if d.len() >= 2 {
            std::process::abort();
        }
    }
    fn bloats(d: &[u8]) {
        if d.len() >= 2 {
            let v = vec![1u8; 300 << 20];
            std::hint::black_box(&v);
        }
    }
    fn creeps(d: &[u8]) {
        // many moderate allocations: over the per-input budget, under the single-allocation cap
        if d.len() >= 2 {
            let v: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 1 << 20]).collect();
            std::hint::black_box(&v);
        }
    }
    let t = |name, run: fn(&[u8])| Target { name, run, seeds, dict: &[], max_len: 16, alloc_base: 1 << 16, alloc_per_byte: 64 };
    vec![
        t("selftest_panic", panics),
        t("selftest_overflow", overflows),
        t("selftest_hang", hangs),
        t("selftest_stack", overflows_the_stack),
        t("selftest_abort", aborts),
        t("selftest_bloat", bloats),
        t("selftest_creep", creeps),
    ]
}

// ------------------------------------------------------------------------------------- fixtures

/// Mid-September 2026, inside the validity of the fixtures (see tests/data/rev_* and the others).
const NOW: i64 = 1_789_430_400;

fn der_of(pem_text: &str) -> Vec<u8> {
    pem::parse(pem_text).remove(0).data
}

fn fixture(name: &str) -> &'static [u8] {
    seed_data::PEM.iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("no fixture {name}")).1
}

fn fixture_der(name: &str) -> Vec<u8> {
    der_of(std::str::from_utf8(fixture(&format!("{name}.pem"))).unwrap())
}

/// The DER of every certificate fixture.
fn certificates() -> &'static Vec<Vec<u8>> {
    static C: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    C.get_or_init(|| {
        seed_data::PEM
            .iter()
            .flat_map(|(_, text)| pem::parse(std::str::from_utf8(text).unwrap()))
            .filter(|b| b.label == "CERTIFICATE")
            .map(|b| b.data)
            .collect()
    })
}

fn is_fixture_certificate(der: &[u8]) -> bool {
    certificates().iter().any(|c| c == der)
}

fn file(set: &'static [(&'static str, &'static [u8])], name: &str) -> Vec<u8> {
    set.iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("no fixture {name}")).1.to_vec()
}

/// Is `data` exactly one of the fixtures in `set`, other than the deliberately forged ones? Whether
/// a fixture is good depends on the certificate and the clock it is checked against (a "stale" list
/// is current ten days earlier, an answer about "another certificate" is about the one it names), so
/// the invariant is only that nothing but a real, signed fixture ever decides a certificate. That a
/// given fixture gives the right answer is the job of the unit tests.
///
/// One more input is genuine: `rev_ocsp_forged.der` is a signed response with the last bit of its
/// signature flipped (tools/gen_revocation_fixtures.py), and the fuzzer does find the byte that puts
/// the bit back (a false alarm in the first 3600 s campaign, about 5 million inputs in). That
/// repaired response is a real signed one, so it is allowed to decide a certificate.
fn is_known_good(set: &'static [(&'static str, &'static [u8])], data: &[u8]) -> bool {
    set.iter().any(|(name, bytes)| {
        if *name == "rev_ocsp_forged.der" {
            return bytes.split_last().is_some_and(|(last, head)| data.len() == bytes.len() && data[..head.len()] == *head && data[head.len()] == last ^ 0x01);
        }
        *bytes == data && !name.contains("forged")
    })
}

// ------------------------------------------------------------------------------------ dictionaries

const DER_DICT: &[&[u8]] = &[
    b"\x30\x82",
    b"\x30\x81",
    b"\x30\x00",
    b"\x31\x00",
    b"\x02\x01\x00",
    b"\x02\x01\x02",
    b"\x02\x02\x00\xff",
    b"\x05\x00",
    b"\x06\x03\x55\x04\x03",
    b"\x06\x03\x55\x1d\x13",
    b"\x06\x03\x55\x1d\x25",
    b"\x06\x03\x55\x1d\x11",
    b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b",
    b"\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x01",
    b"\x17\x0d",
    b"\x18\x0f",
    b"\x17\x0d260231000000Z",
    b"\x17\x0d260230120000Z",
    b"\x17\x0d250229000000Z",
    b"\x17\x0d261331000000Z",
    b"\x18\x0f20260431000000Z",
    b"\x18\x0f21000229000000Z",
    b"\x17\x0d991231235960Z",
    b"\x03\x02\x00",
    b"\x03\x02\x01",
    b"\xa0\x03\x02\x01\x02",
    b"\xa3\x82",
    b"\x01\x01\xff",
    b"\x0a\x01\x00",
    b"\x80\x00",
    b"\x82\x0b",
    b"\xff\xff\xff\xff",
];

const ED25519_DICT: &[&[u8]] = &[
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\xec\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
    b"\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
    b"\xed\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14",
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10",
    b"\x80",
    b"\xff\xff\xff\xff\xff\xff\xff\xff",
];

const HOST_DICT: &[&[u8]] = &[b"*.", b".", b"\0", b"example.test", b"*.example.test", b"EXAMPLE", b"..", b"*"];

const PEM_DICT: &[&[u8]] = &[b"-----BEGIN CERTIFICATE-----\n", b"-----END CERTIFICATE-----\n", b"-----BEGIN X-----", b"-----END X-----", b"\r\n", b"====", b"=", b"\n\n", b" \t", b"+/", b"-_"];

const HTTP_DICT: &[&[u8]] = &[
    b"HTTP/1.1 ",
    b"HTTP/1.0 ",
    b"\r\n",
    b"\r\n\r\n",
    b"\n",
    b"Content-Length: ",
    b"Transfer-Encoding: chunked",
    b"Transfer-Encoding: identity",
    b"Connection: close",
    b"Content-Type: ",
    b"Location: ",
    b"0\r\n\r\n",
    b";ext=1",
    b"Set-Cookie: ",
    b" 200 OK",
    b" 304 ",
    b" 100 Continue",
    b"ffffffffffffffff",
    b"18446744073709551616",
    b": ",
];

const URL_DICT: &[&[u8]] = &[b"://", b"https://", b"http://", b"@", b"[::1]", b"[", b"]", b":443", b":0", b":65536", b"/../", b"/./", b"..", b"?", b"#", b"\n", b"//", b"%2f", b"\\", b".", b"user:pw@"];

const TLS_DICT: &[&[u8]] = &[
    // HelloRetryRequest: the fixed random, the cookie extension, the NIST group ids
    b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c",
    b"\x00\x2c",
    b"\x00\x17",
    b"\x00\x18",
    b"\x08\x00\x00\x02\x00\x00",
    b"\x0b\x00\x00",
    b"\x0f\x00\x00",
    b"\x14\x00\x00",
    b"\x18\x00\x00\x01\x00",
    b"\x18\x00\x00\x01\x01",
    b"\x04\x00\x00",
    b"\x00\x05",
    b"\x00\x00\x00\x00",
    b"\x00\x0a",
    b"\x00\x2b",
    b"\x00\x33",
    b"\x00\x1c",
    b"\x01\x00\x00\x00\x00",
    b"\x03\x03",
    b"\x03\x04",
    b"\x16\x03\x03",
    b"\x17\x03\x03",
    b"\x15\x03\x03",
    b"\x08\x04",
    b"\x05\x03",
    b"\xff\xff",
];

// ------------------------------------------------------------------------------------------- seeds

fn seeds_certificates() -> Vec<Vec<u8>> {
    certificates().clone()
}

fn seeds_hostnames() -> Vec<Vec<u8>> {
    ["*.example.test\0www.example.test", "example.test\0EXAMPLE.TEST", "*.example.test\0example.test", "*.example.test\0a.b.example.test", "*.*.test\0a.b.test", "example.test.\0example.test"].iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn seeds_chains() -> Vec<Vec<u8>> {
    let leaf = fixture_der("leaf_p384");
    let inter = fixture_der("inter_p256");
    let root = fixture_der("root_rsa");
    let mut v = Vec::new();
    for sel in [0u8, 1, 8, 16, 24, 2] {
        v.push([&[sel][..], &leaf, &inter].concat());
    }
    v.push([&[0u8][..], &leaf, &inter, &root].concat());
    v.push([&[0u8][..], &inter, &leaf].concat());
    v.push([&[0u8][..], &leaf].concat());
    v.push([&[0u8][..], &fixture_der("leaf_rsa"), &fixture_der("inter2_p256")].concat());
    v.push([&[0u8][..], &fixture_der("leaf_nc_ok"), &fixture_der("inter_nc")].concat());
    v.push([&[0u8][..], &fixture_der("leaf_deep"), &fixture_der("inter2_p256"), &inter].concat());
    v
}

fn seeds_purpose_chains() -> Vec<Vec<u8>> {
    // (purpose, time, flags, certificates)
    let cases: &[(u8, u8, u8, &[&str])] = &[
        (2, 0, 0, &["cs_leaf_workflow", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_email", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_other", "cs_inter"]),
        (2, 0, 2, &["cs_leaf_critical", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_critical", "cs_inter"]),
        (2, 0, 1, &["cs_leaf_noeku", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_noeku", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_noku", "cs_inter"]),
        (7, 0, 0, &["cs_leaf_tls", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_tls", "cs_inter"]),
        (0, 0, 4, &["cs_leaf_tls", "cs_inter"]),
        (2, 0, 0, &["cs_leaf_anyeku", "cs_inter"]),
        (2, 2, 0, &["cs_leaf_workflow", "cs_inter"]),
        (2, 1, 0, &["as_leaf", "as_inter"]),
        (6, 1, 0, &["as_leaf", "as_inter"]),
        (2, 2, 0, &["as_leaf", "as_inter"]),
        (2, 1, 0, &["as_leaf", "as_inter", "as_root"]),
        (4, 3, 0, &["ts_leaf"]),
        (4, 5, 0, &["ts_leaf"]),
        (3, 2, 0, &["em_leaf"]),
        (1, 2, 0, &["em_leaf"]),
        (3, 2, 0, &["em_leaf_nr"]),
        (1, 2, 0, &["em_leaf_nr"]),
        (7, 2, 0, &["em_leaf_nr"]),
        (2, 2, 0, &["cs_nc_ok", "cs_inter_nc"]),
        (2, 2, 0, &["cs_nc_bad_email", "cs_inter_nc"]),
        (2, 2, 0, &["cs_nc_bad_uri", "cs_inter_nc"]),
        (2, 2, 0, &["cs_nc_bad_ip", "cs_inter_nc"]),
        (2, 2, 0, &["cs_nco_other", "cs_inter_nc_other"]),
        (2, 2, 0, &["cs_nco_email", "cs_inter_nc_other"]),
        (7, 3, 0, &["fulcio_real_inter"]),
        (7, 4, 0, &["fulcio_real_inter"]),
        (7, 0, 0, &["fulcio_real_inter", "fulcio_real_root"]),
        (2, 6, 0, &["fulcio_real_leaf", "fulcio_real_inter"]),
        (2, 6, 0, &["fulcio_real_leaf"]),
        (2, 2, 0, &["fulcio_real_leaf", "fulcio_real_inter"]),
        (4, 6, 0, &["fulcio_real_leaf", "fulcio_real_inter"]),
        (2, 3, 0, &["apple_mas_leaf", "apple_wwdr_g5"]),
        (7, 3, 0, &["apple_mas_leaf", "apple_wwdr_g5", "apple_root_ca"]),
        (2, 2, 0, &["apple_mas_leaf", "apple_wwdr_g5"]),
        (4, 3, 0, &["apple_mas_leaf", "apple_wwdr_g5"]),
    ];
    cases
        .iter()
        .map(|(purpose, time, flags, certs)| {
            let mut v = vec![purpose | (time << 3), *flags];
            for c in *certs {
                v.extend(fixture_der(c));
            }
            v
        })
        .collect()
}

fn seeds_pem() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = seed_data::PEM.iter().map(|(_, t)| t.to_vec()).collect();
    v.push(b"-----BEGIN X-----\nAAAA\n-----END X-----\n".to_vec());
    v.push(b"junk\n-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\r\nMAAA\r\n-----END CERTIFICATE-----".to_vec());
    v
}

/// Selector byte, then the object: bits 0-1 choose the (certificate, issuer) pair, bits 2-3 the clock.
fn seeds_ocsp() -> Vec<Vec<u8>> {
    seed_data::OCSP.iter().flat_map(|(_, b)| [[&[0u8][..], b].concat(), [&[1u8][..], b].concat(), [&[2u8][..], b].concat()]).collect()
}

fn seeds_crl() -> Vec<Vec<u8>> {
    seed_data::CRL.iter().flat_map(|(_, b)| [[&[0u8][..], b].concat(), [&[1u8][..], b].concat()]).collect()
}

fn path_input(staple: &[u8], crl: &[u8]) -> Vec<u8> {
    let mut v = (staple.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(staple);
    v.extend_from_slice(crl);
    v
}

fn seeds_revocation_path() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for (_, s) in seed_data::OCSP {
        v.push(path_input(s, &[]));
    }
    for (_, c) in seed_data::CRL {
        v.push(path_input(&[], c));
    }
    v.push(path_input(&file(seed_data::OCSP, "rev_ocsp_good.der"), &file(seed_data::CRL, "rev_crl_empty.der")));
    v.push(path_input(&file(seed_data::OCSP, "rev_ocsp_good.der"), &file(seed_data::CRL, "rev_crl_revoked.der")));
    v.push(path_input(&file(seed_data::OCSP, "rev_ocsp_revoked.der"), &file(seed_data::CRL, "rev_crl_empty.der")));
    v
}

fn seeds_http() -> Vec<Vec<u8>> {
    const RESPONSES: [&[u8]; 9] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nSet-Cookie: a=b\r\n\r\n",
        b"HTTP/1.0 301 Moved\r\nLocation: https://example.com/a/../b?c=d#e\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody until close",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n",
        b"HTTP/1.1 200 Connection established\r\n\r\n",
    ];
    let mut v = Vec::new();
    for r in RESPONSES {
        for (method, piece) in [(0u8, 20u8), (1, 0), (3, 96)] {
            v.push([&[method, 128, 255, piece][..], r].concat());
        }
    }
    v
}

fn seeds_url() -> Vec<Vec<u8>> {
    [
        "https://user:pw@example.com:8443/a/b/../c?x=1#frag\n../x?y",
        "https://[::1]:443/\n/abs",
        "https://example.com\n?q",
        "http://example.com/dir/page\n//other.example/x",
        "https://example.com/a\nhttps://other.example/",
        "https://example.com:8080/a/b/c\n./d/./e/../f",
        "http://h:80\n#frag",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

fn seeds_tls_records() -> Vec<Vec<u8>> {
    use pratique::tls::fuzz_hooks::{example_hello_retry, example_server_hello};
    let mut v = Vec::new();
    for sel in 0..3u8 {
        let hello = example_server_hello(sel);
        v.push([&[0u8][..], &hello].concat()); // one read
        v.push([&[1u8][..], &hello].concat()); // byte by byte
        // plus an encrypted-looking record and an alert, to get the framing code going
        let mut tail = hello.clone();
        tail.extend_from_slice(&[0x17, 3, 3, 0, 20]);
        tail.extend_from_slice(&[0xa5; 20]);
        v.push([&[3u8][..], &tail].concat());
    }
    // a HelloRetryRequest, then the ServerHello that answers the retried ClientHello
    for sel in 0..9u8 {
        let retry = example_hello_retry(sel);
        v.push([&[0u8][..], &retry].concat());
        v.push([&[1u8][..], &retry].concat());
    }
    v.push(vec![0, 0x15, 3, 3, 0, 2, 2, 40]);
    v.push(vec![0, 0x16, 3, 3, 0, 4, 0x02, 0, 0, 0]);
    v
}

// handshake messages, built by hand so the seeds do not depend on the crate's own encoders

fn u24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![kind];
    v.extend_from_slice(&u24(body.len()));
    v.extend_from_slice(body);
    v
}

fn len16(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

fn encrypted_extensions(exts: &[u8]) -> Vec<u8> {
    handshake(8, &len16(exts))
}

fn certificate_message(chain: &[Vec<u8>], staple_for_leaf: Option<&[u8]>) -> Vec<u8> {
    let mut list = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        list.extend_from_slice(&u24(c.len()));
        list.extend_from_slice(c);
        let mut exts = Vec::new();
        if let (0, Some(s)) = (i, staple_for_leaf) {
            let mut body = vec![1];
            body.extend_from_slice(&u24(s.len()));
            body.extend_from_slice(s);
            exts.extend_from_slice(&[0, 5]);
            exts.extend_from_slice(&len16(&body));
        }
        list.extend_from_slice(&len16(&exts));
    }
    let mut body = vec![0];
    body.extend_from_slice(&u24(list.len()));
    body.extend_from_slice(&list);
    handshake(11, &body)
}

fn certificate_verify(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = scheme.to_be_bytes().to_vec();
    body.extend_from_slice(&len16(signature));
    handshake(15, &body)
}

fn flight(sel0: u8, sel1: u8, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![sel0, sel1];
    for m in messages {
        v.extend_from_slice(m);
    }
    v
}

fn seeds_tls_flight() -> Vec<Vec<u8>> {
    use pratique::tls::fuzz_hooks::example_chain;
    let chain = example_chain();
    let staple = file(seed_data::OCSP, "rev_ocsp_good.der");
    let mut v = Vec::new();
    for suite in 0..3u8 {
        let hash_len = if suite == 1 { 48 } else { 32 };
        let finished = handshake(20, &vec![0x5a; hash_len]);
        let verify = certificate_verify(0x0503, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        for (sel0, piece) in [(suite, 0u8), (suite | 8, 0), (suite | 8, 3), (suite, 1)] {
            v.push(flight(sel0, piece, &[encrypted_extensions(&[]), certificate_message(&chain, None), verify.clone(), finished.clone()]));
        }
        v.push(flight(suite | 8, 0, &[encrypted_extensions(&[0, 0, 0, 0]), certificate_message(&chain, Some(&staple)), verify.clone(), finished.clone()]));
        v.push(flight(suite, 0, &[encrypted_extensions(&[]), certificate_message(&chain[..1], None), certificate_verify(0x0804, &[7; 256]), finished.clone()]));
    }
    // the same flight after a HelloRetryRequest (selector bits 4-5 of the second byte: 1 asks for
    // P-256, 2 for P-384 with a cookie, 3 for a cookie only)
    for suite in 0..3u8 {
        let hash_len = if suite == 1 { 48 } else { 32 };
        let finished = handshake(20, &vec![0x5a; hash_len]);
        let verify = certificate_verify(0x0503, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        for kind in 1..=3u8 {
            for (sel0, piece) in [(suite, 0u8), (suite | 8, 0), (suite, 1)] {
                v.push(flight(sel0, kind << 4 | piece, &[encrypted_extensions(&[]), certificate_message(&chain, None), verify.clone(), finished.clone()]));
            }
        }
    }
    // a lone Finished, and an empty certificate list
    v.push(flight(0, 0, &[encrypted_extensions(&[]), handshake(20, &[0; 32])]));
    v.push(flight(0, 0, &[encrypted_extensions(&[]), handshake(11, &[0, 0, 0, 0])]));
    v
}

fn seeds_tls_post() -> Vec<Vec<u8>> {
    // [selector] then records [type][length][content]
    let key_update = |requested: u8| vec![0x16, 5, 0x18, 0, 0, 1, requested];
    let app = |text: &[u8]| [&[0x17, text.len() as u8][..], text].concat();
    let write = |text: &[u8]| [&[0xff, text.len() as u8][..], text].concat();
    let ticket = {
        let mut body = 3600u32.to_be_bytes().to_vec();
        body.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        body.extend_from_slice(&[4, 1, 2, 3, 4]);
        body.extend_from_slice(&len16(&[9; 24]));
        body.extend_from_slice(&len16(&[]));
        let msg = handshake(4, &body);
        [&[0x16, msg.len() as u8][..], &msg].concat()
    };
    let mut v = Vec::new();
    for sel in [0u8, 1, 2, 0x08, 0x38, 0x19] {
        v.push([&[sel][..], &key_update(0), &app(b"after"), &key_update(1), &app(b"again")].concat());
        v.push([&[sel][..], &app(b"hello"), &write(b"GET / HTTP/1.1\r\n\r\n"), &ticket, &app(b"world")].concat());
        v.push([&[sel][..], &write(b"one"), &write(b"two"), &write(b"three"), &write(b"four"), &write(b"five"), &key_update(1), &write(b"six")].concat());
        v.push([&[sel][..], &app(b"bye"), &[0x15, 2, 1, 0][..]].concat());
    }
    v.push(vec![0, 0x15, 2, 2, 40]);
    v.push([&[0u8][..], &[0x16, 4, 0x18, 0, 0, 0][..]].concat());
    // TLS 1.2 (bit 2; the suite in the top bits, bit 3 a tiny limit on records): a HelloRequest, which is answered with a warning,
    // a change_cipher_spec, which may not come now, and the rest as above
    let hello_request = vec![0x16, 4, 0, 0, 0, 0];
    for sel in [0x04u8, 0x14, 0x24, 0x34, 0x44, 0x54, 0x0c, 0x5d] {
        v.push([&[sel][..], &app(b"hello"), &hello_request, &write(b"GET / HTTP/1.1\r\n\r\n"), &app(b"world")].concat());
        v.push([&[sel][..], &write(b"one"), &write(b"two"), &write(b"three"), &write(b"four"), &app(b"five")].concat());
        v.push([&[sel][..], &app(b"bye"), &[0x15, 2, 1, 0][..]].concat());
        v.push([&[sel][..], &[0x14, 1, 1][..]].concat());
    }
    v
}

fn seeds_tls12_flight() -> Vec<Vec<u8>> {
    use pratique::tls::fuzz_hooks::{example_tls12_flight, server_flight12};
    let mut v = Vec::new();
    // [suite + checks][cut] then the server's bytes: every suite, verified or not, each variant, cut whole or into small pieces
    for suite in 0..6u8 {
        for checks in [0u8, 0x08, 0x18] {
            for variant in 0..8u8 {
                let sel = suite | checks;
                for cut in [0u8, 3] {
                    let seed = [&[sel, cut][..], &example_tls12_flight(sel, variant)].concat();
                    // the ECDSA suites (0 = ECDHE_ECDSA with AES-128-GCM, 2 with AES-256-GCM, 4 with ChaCha20) fit the key, and those
                    // seeds get as far as the client's own flight, which is what makes them seeds (the staple of 0x18 is an OCSP error
                    // response, which soft-fail, the default, writes down and goes on from, as in TLS 1.3)
                    let should_reach = suite % 2 == 0;
                    assert_eq!(server_flight12(&seed), should_reach, "TLS 1.2 seed for suite {suite}, checks {checks:#x}, variant {variant}");
                    if cut == 0 || variant == 0 {
                        v.push(seed);
                    }
                }
            }
        }
    }
    // a Certificate alone, a ServerKeyExchange first, and nothing
    v.push(vec![0, 0, 0x16, 3, 3, 0, 7, 11, 0, 0, 3, 0, 0, 0]);
    v.push(vec![8, 0, 0x16, 3, 3, 0, 8, 12, 0, 0, 4, 3, 0, 0x1d, 0]);
    v.push(vec![0, 0]);
    v
}

// ------------------------------------------------------------------------------------------ targets

// ---- der

fn minimal_header(content_len: usize) -> usize {
    if content_len < 0x80 {
        2
    } else {
        let mut n = 0;
        let mut c = content_len;
        while c > 0 {
            n += 1;
            c >>= 8;
        }
        2 + n
    }
}

/// Days since 1970-01-01 to (year, month, day), the inverse of the parser's own conversion.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn check_time(t: &asn1::Tlv, seconds: i64) {
    let c = t.content;
    let num = |a: usize, n: usize| std::str::from_utf8(&c[a..a + n]).unwrap().parse::<i64>().unwrap();
    let (year, rest) = if t.tag == asn1::TAG_UTC_TIME {
        let yy = num(0, 2);
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
    } else {
        (num(0, 4), 4)
    };
    let (mo, d, h, mi, s) = (num(rest, 2), num(rest + 2, 2), num(rest + 4, 2), num(rest + 6, 2), num(rest + 8, 2));
    if s == 60 {
        return; // a leap second is the first second of the next minute
    }
    let days = seconds.div_euclid(86400);
    let secs = seconds.rem_euclid(86400);
    let back = civil_from_days(days);
    assert_eq!((back, secs), ((year, mo, d), h * 3600 + mi * 60 + s), "the time {:?} parsed, but is not a real date (it came out as {:?})", String::from_utf8_lossy(c), back);
}

fn walk(d: &[u8], depth: usize) {
    let mut r = Der::new(d);
    while !r.is_empty() {
        let Ok(t) = r.next() else { return };
        let (start, end) = (d.as_ptr() as usize, d.as_ptr() as usize + d.len());
        let (rs, re) = (t.raw.as_ptr() as usize, t.raw.as_ptr() as usize + t.raw.len());
        assert!(rs >= start && re <= end, "an element reaches outside its input");
        assert_eq!(t.raw[0], t.tag);
        assert!(t.raw.ends_with(t.content), "content is not the tail of the encoding");
        assert_eq!(t.raw.len() - t.content.len(), minimal_header(t.content.len()), "a length was accepted in a longer form than DER allows");
        if let Ok(v) = asn1::unsigned_integer(&t) {
            assert!(!v.is_empty() && (v.len() == 1 || v[0] != 0), "unsigned_integer returned a padded magnitude");
            assert!(t.content == &v[..] || t.content == &[&[0u8][..], &v[..]].concat()[..]);
        }
        if let Ok(b) = asn1::bit_string_bytes(&t) {
            assert_eq!(b, &t.content[1..]);
        }
        if let Ok(seconds) = asn1::parse_time(&t) {
            check_time(&t, seconds);
        }
        if t.tag == asn1::TAG_OID {
            check_oid(t.content);
        }
        if depth < 8 {
            if t.tag & 0x20 != 0 || t.tag == asn1::TAG_OCTET_STRING {
                walk(t.content, depth + 1);
            } else if t.tag == asn1::TAG_BIT_STRING && !t.content.is_empty() {
                walk(&t.content[1..], depth + 1);
            }
        }
    }
}

/// An OID's dotted form reads back as an OID with the same dotted form (the bytes may differ: an
/// arc written with leading 0x80 octets is not minimal, and comes back minimal).
fn check_oid(content: &[u8]) {
    let text = asn1::oid_to_string(content);
    if text == "<invalid OID>" {
        return;
    }
    // (an arc wider than 64 bits has no encoder here; every other OID must round-trip)
    if let Some(again) = asn1::oid_from_string(&text) {
        assert_eq!(asn1::oid_to_string(&again), text, "an OID changed in a round trip through its dotted form");
        if !content.iter().enumerate().any(|(i, &b)| b == 0x80 && (i == 0 || content[i - 1] & 0x80 == 0)) {
            assert_eq!(again, content, "a minimally encoded OID did not round-trip to the same bytes");
        }
    }
}

fn der(data: &[u8]) {
    walk(data, 0);
}

// ---- certificate

fn certificate(data: &[u8]) {
    let Ok(c) = Certificate::from_der(data) else { return };
    assert_eq!(c.der, data, "a certificate does not keep exactly the bytes it was parsed from");
    let _ = c.subject_summary();
    let _ = c.issuer_summary();
    let _ = c.is_self_issued();
    for name in ["example.test", "127.0.0.1", "::1", "", "*.test", "EXAMPLE.TEST."] {
        let _ = c.matches_hostname(name);
    }
    for name in c.dns_names.iter().take(4) {
        // what a certificate names must not make the matcher misbehave
        let _ = dns_pattern_matches(name, "example.test");
    }
    if c.verify_signed_by(&c).is_ok() {
        assert!(is_fixture_certificate(data), "a certificate that is not a known one has a valid self-signature");
    }
    // the names and extensions it reports agree with each other and with the fields TLS uses
    let san = c.subject_alt_names();
    let dns: Vec<&String> = san.iter().filter_map(|n| if let GeneralName::Dns(s) = n { Some(s) } else { None }).collect();
    assert_eq!(dns, c.dns_names.iter().collect::<Vec<_>>(), "the DNS names of the subjectAltName differ between the two accessors");
    let ips: Vec<&Vec<u8>> = san.iter().filter_map(|n| if let GeneralName::Ip(a) = n { Some(a) } else { None }).collect();
    assert_eq!(ips, c.ip_addrs.iter().collect::<Vec<_>>());
    for n in san {
        match n {
            GeneralName::Email(s) | GeneralName::Uri(s) => assert!(s.is_ascii()),
            GeneralName::Other { type_id: o, .. } | GeneralName::RegisteredId(o) => check_oid(o),
            _ => {}
        }
    }
    assert_eq!(c.email_addresses().count(), san.iter().filter(|n| matches!(n, GeneralName::Email(_))).count());
    assert_eq!(c.uris().count(), san.iter().filter(|n| matches!(n, GeneralName::Uri(_))).count());
    for e in c.extensions() {
        assert_eq!(c.extension(&e.oid), Some(e), "an extension of the certificate cannot be found by its OID");
        check_oid(&e.oid);
        let _ = e.oid_string();
        let _ = e.der_string();
    }
}

// ---- ed25519

/// Known signatures (tests/data/ed25519_sign_input.txt, whose lines are `key:message:signature`) and the
/// vectors from tools/ed25519_vectors.py (`family:key:signature:message:go:openssl`), as
/// (key, signature, message) with Go's verdict.
fn ed25519_known() -> &'static Vec<(Vec<u8>, Vec<u8>, Vec<u8>, bool)> {
    static K: OnceLock<Vec<(Vec<u8>, Vec<u8>, Vec<u8>, bool)>> = OnceLock::new();
    K.get_or_init(|| {
        let unhex = pratique::util::unhex;
        let mut out = Vec::new();
        for line in include_str!("../../tests/data/ed25519_sign_input.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(':').collect();
            out.push((unhex(f[0]), unhex(f[2]), unhex(f[1]), true));
        }
        for line in include_str!("../../tests/data/ed25519_vectors.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(':').collect();
            out.push((unhex(f[1]), unhex(f[2]), unhex(f[3]), f[4] == "1"));
            // the "malleable" rows are an honest signature with S + L, S + 2L, S + 8L or a high bit set: the honest one
            // (S reduced modulo L) is good too, and a fuzzer that clears the high bit finds it (the field run's did)
            if f[0] == "malleable" {
                let sig = unhex(f[2]);
                let mut s: [u8; 32] = sig[32..].try_into().expect("64-byte signature");
                reduce_mod_l(&mut s);
                out.push((unhex(f[1]), [&sig[..32], &s[..]].concat(), unhex(f[3]), true));
            }
        }
        out
    })
}

/// The group order L of Ed25519, little-endian.
const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `s` (little-endian, below 2^256) reduced modulo L by subtraction (at most 16 times).
fn reduce_mod_l(s: &mut [u8; 32]) {
    let at_least_l = |s: &[u8; 32]| {
        for i in (0..32).rev() {
            if s[i] != ED25519_L[i] {
                return s[i] > ED25519_L[i];
            }
        }
        true
    };
    while at_least_l(s) {
        let mut borrow = 0i16;
        for i in 0..32 {
            let t = s[i] as i16 - ED25519_L[i] as i16 - borrow;
            s[i] = t.rem_euclid(256) as u8;
            borrow = i16::from(t < 0);
        }
    }
}

/// The 14 encodings of the points of small order that Go's decoder accepts as a key: with one of them as
/// the key and R and S chosen to fit, a signature verifies for any message, and the fuzzer may find such
/// a combination.
const SMALL_ORDER_KEYS: [&str; 14] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

fn seeds_ed25519() -> Vec<Vec<u8>> {
    ed25519_known()
        .iter()
        .enumerate()
        .filter(|(i, (_, _, _, good))| *good || i % 4 == 0)
        .map(|(_, (k, s, m, _))| [k.as_slice(), s.as_slice(), m.as_slice()].concat())
        .collect()
}

/// The input is a key (32 bytes), a signature (64 bytes) and the message (the rest); a short input
/// gives a key or signature that is too short.
fn ed25519(data: &[u8]) {
    let (key, rest) = data.split_at(data.len().min(32));
    let (sig, msg) = rest.split_at(rest.len().min(64));
    if !pratique::crypto::ed25519::verify(key, msg, sig) {
        return;
    }
    let small_order = SMALL_ORDER_KEYS.iter().any(|k| pratique::util::unhex(k) == key);
    let known = ed25519_known().iter().any(|(k, s, m, good)| *good && k == key && s == sig && m == msg);
    assert!(small_order || known, "a signature that is neither a known good one nor under a key of small order verified: key {:x?} signature {:x?} message {:x?}", key, sig, msg);
    // S + L is the same signature in the eyes of the equation and must still be refused
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut longer = sig.to_vec();
    let mut carry = 0u16;
    for i in 0..32 {
        let t = longer[32 + i] as u16 + L[i] as u16 + carry;
        longer[32 + i] = t as u8;
        carry = t >> 8;
    }
    assert!(!pratique::crypto::ed25519::verify(key, msg, &longer), "S + L verified");
}

// ---- hostname

fn hostname(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let (pattern, host) = text.split_once('\0').unwrap_or((&text, "example.test"));
    if !dns_pattern_matches(pattern, host) {
        return;
    }
    let p = pattern.strip_suffix('.').unwrap_or(pattern);
    assert!(!host.is_empty() && !p.is_empty());
    if let Some(base) = p.strip_prefix("*.") {
        // one label, not empty, not itself a wildcard, under a name with at least two labels
        let (first, rest) = host.split_once('.').expect("a wildcard matched a name with no dot");
        assert!(!first.is_empty() && rest.eq_ignore_ascii_case(base) && base.contains('.') && !base.contains('*'), "wildcard {pattern:?} matched {host:?}");
    } else {
        assert!(!p.contains('*'), "{pattern:?} matched {host:?} with a * in a position the matcher should refuse");
        assert!(p.eq_ignore_ascii_case(host), "{pattern:?} matched {host:?}");
    }
}

// ---- idna

fn seeds_idna() -> Vec<Vec<u8>> {
    ["bücher.example", "xn--bcher-kva.example", "пример.испытание", "例え。テスト", "faß.de.", "a..b", "İstanbul", "xn--ls8h", "egbpdaj6bu4bxfgehfvwxn", "-> $1.00 <--"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

/// `to_ascii` gives ASCII that is its own conversion and that `to_unicode` turns into a name converting back to it, or
/// an error; Punycode decodes what it encodes, and what decodes encodes back to the same thing in lower case.
fn idna(data: &[u8]) {
    use pratique::idna::{punycode_decode, punycode_encode, to_ascii, to_unicode};
    let text = String::from_utf8_lossy(data);
    if let Ok(ascii) = to_ascii(&text) {
        assert!(ascii.is_ascii() && ascii.len() <= 254, "{text:?} gave {ascii:?}");
        assert_eq!(to_ascii(&ascii).as_deref(), Ok(ascii.as_str()), "not its own conversion: {text:?}");
        assert_eq!(to_ascii(&to_unicode(&ascii)).as_deref(), Ok(ascii.as_str()), "to_unicode does not come back: {text:?}");
    }
    let chars: Vec<char> = text.chars().collect();
    let encoded = punycode_encode(&chars).expect("a short input encodes");
    assert_eq!(punycode_decode(&encoded), Some(chars), "{text:?} encoded to {encoded:?}");
    if let Some(decoded) = punycode_decode(&text) {
        let back = punycode_encode(&decoded).expect("encodes");
        assert_eq!(back.to_ascii_lowercase(), text.to_ascii_lowercase(), "{text:?} decoded to {decoded:?}");
    }
}

// ---- chain

struct ChainFixture {
    trust: TrustStore,
    hosts: [&'static str; 8],
    times: [i64; 4],
}

fn chain_fixture() -> &'static ChainFixture {
    static F: OnceLock<ChainFixture> = OnceLock::new();
    F.get_or_init(|| {
        let mut trust = TrustStore::empty();
        trust.add_der(&fixture_der("root_rsa")).unwrap();
        ChainFixture {
            trust,
            hosts: ["example.test", "other.test", "EXAMPLE.test", "*.test", "example.test.", "", "127.0.0.1", "sub.example.test"],
            times: [NOW, 1_000_000_000, 4_000_000_000, i64::MAX],
        }
    })
}

/// Cuts `data` into DER elements by their own lengths (the rest, if it does not parse, is the last).
fn split_ders(mut rest: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !rest.is_empty() && out.len() < 8 {
        let n = Der::new(rest).next().map(|t| t.raw.len()).unwrap_or(rest.len());
        out.push(rest[..n].to_vec());
        rest = &rest[n..];
    }
    out
}

fn chain(data: &[u8]) {
    check_chain(chain_fixture(), data)
}

/// The chains of BACKLOG B-33 (tools/gen_algorithm_fixtures.py): a P-521 root, an RSA root whose intermediate signs with
/// RSASSA-PSS (and leaves signed with PSS parameters the library does not read).
fn alg_chain_fixture() -> &'static ChainFixture {
    static F: OnceLock<ChainFixture> = OnceLock::new();
    F.get_or_init(|| {
        let mut trust = TrustStore::empty();
        trust.add_der(&fixture_der("alg_p521_root")).unwrap();
        trust.add_der(&fixture_der("alg_pss_root")).unwrap();
        ChainFixture {
            trust,
            hosts: ["p521.example.test", "pss.example.test", "P521.Example.Test", "*.example.test", "example.test", "", "pss.example.test.", "x.pss.example.test"],
            times: [NOW, 1_000_000_000, 4_000_000_000, i64::MAX],
        }
    })
}

/// The same invariant as `chain`, over P-521 and RSA-PSS chains: the PSS parameters and the P-521 arithmetic are what
/// a mutation meets here.
fn chain_algs(data: &[u8]) {
    check_chain(alg_chain_fixture(), data)
}

fn seeds_chain_algs() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for (sel, leaf, inter) in [
        (0u8, "alg_p521_leaf", "alg_p521_inter"),
        (1, "alg_pss_leaf", "alg_pss_inter"),
        (1, "alg_pss_leaf_sha384", "alg_pss_inter"),
        (1, "alg_pss_leaf_salt20", "alg_pss_inter"),
        (1, "alg_pss_leaf_mgf_sha512", "alg_pss_inter"),
        (2, "alg_p521_leaf", "alg_p521_inter"),
        (8, "alg_pss_leaf", "alg_pss_inter"),
    ] {
        v.push([&[sel][..], &fixture_der(leaf), &fixture_der(inter)].concat());
    }
    v.push([&[0u8][..], &fixture_der("alg_p521_leaf"), &fixture_der("alg_p521_inter"), &fixture_der("alg_p521_root")].concat());
    v
}

fn check_chain(f: &ChainFixture, data: &[u8]) {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let host = f.hosts[(sel & 7) as usize];
    let now = f.times[((sel >> 3) & 3) as usize];
    let chain = split_ders(bytes);
    let Ok(leaf) = f.trust.verify_server_chain(&chain, host, now) else { return };
    // accepted: now check that it deserved to be
    assert!(is_fixture_certificate(&chain[0]), "a leaf that is not a known certificate was accepted");
    if chain.len() == 2 {
        assert!(is_fixture_certificate(&chain[1]), "a two-certificate chain with an unknown issuer was accepted");
    }
    assert!(chain.iter().skip(1).any(|c| is_fixture_certificate(c)), "a chain with no known intermediate was accepted");
    assert!(leaf.matches_hostname(host), "accepted for {host:?}, a name the leaf does not carry");
    assert!(leaf.not_before <= now && now <= leaf.not_after, "accepted at {now}, outside the leaf's validity");
}

// ---- chain for other purposes

const PURPOSE_TIMES: [i64; 8] = [1_740_830_700, 1_685_577_600, NOW, 1_748_736_000, 1_640_995_200, 2_050_000_000, 1_791_055_827, i64::MAX];
const PURPOSE_HOSTS: [&str; 2] = ["example.test", "tls-only.example.test"];
const LIFETIME_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x0d];
const PRIVATE_CRITICAL: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01];

fn purpose_of(sel: u8) -> Purpose {
    match sel & 7 {
        0 => Purpose::ServerAuth,
        1 => Purpose::ClientAuth,
        2 => Purpose::CodeSigning,
        3 => Purpose::EmailProtection,
        4 => Purpose::TimeStamping,
        5 => Purpose::OcspSigning,
        6 => Purpose::Oid(LIFETIME_SIGNING.to_vec()),
        _ => Purpose::Any,
    }
}

fn purpose_store() -> &'static TrustStore {
    static T: OnceLock<TrustStore> = OnceLock::new();
    T.get_or_init(|| {
        let mut trust = TrustStore::empty();
        for name in ["cs_root", "as_root", "ts_root", "em_root", "fulcio_real_root", "apple_root_ca", "root_rsa"] {
            trust.add_der(&fixture_der(name)).unwrap();
        }
        trust
    })
}

/// The purpose, time, host name and flags come from the first two bytes; the chain from the rest.
/// A chain that is accepted must be made of known certificates, valid at that time and allowing
/// that purpose, for that host name if one was asked for.
fn purpose_chain(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let Some((&flags, bytes)) = rest.split_first() else { return };
    let purpose = purpose_of(sel);
    let time = PURPOSE_TIMES[((sel >> 3) & 7) as usize];
    let mut opts = VerifyOptions::new(purpose.clone(), time);
    if sel & 0x40 != 0 || purpose == Purpose::ServerAuth {
        opts = opts.with_hostname(PURPOSE_HOSTS[((flags >> 2) & 1) as usize]);
    }
    opts.allow_missing_leaf_eku = flags & 1 != 0;
    if flags & 2 != 0 {
        opts = opts.with_critical_extension(PRIVATE_CRITICAL);
    }
    let chain = split_ders(bytes);
    let Ok(ok) = purpose_store().verify_chain(&chain, &opts) else { return };
    assert!(is_fixture_certificate(&chain[0]), "a leaf that is not a known certificate was accepted");
    assert_eq!(ok.path[0], chain[0]);
    assert!(ok.path.len() >= 2, "a path with no anchor above the leaf");
    assert!(is_fixture_certificate(ok.anchor()), "the path ends in something that is not a known certificate");
    assert!(ok.path[1..].iter().all(|c| is_fixture_certificate(c)), "a certificate that is not a known one is in an accepted path");
    assert!(ok.leaf.not_before <= time && time <= ok.leaf.not_after, "accepted at {time}, outside the leaf's validity");
    if let Some(h) = &opts.hostname {
        assert!(ok.leaf.matches_hostname(h), "accepted for {h:?}, a name the leaf does not carry");
    }
    let oid: Option<Vec<u8>> = match &purpose {
        Purpose::ServerAuth => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
        Purpose::ClientAuth => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]),
        Purpose::CodeSigning => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03]),
        Purpose::EmailProtection => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]),
        Purpose::TimeStamping => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]),
        Purpose::OcspSigning => Some(vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]),
        Purpose::Oid(o) => Some(o.clone()),
        Purpose::Any => None,
    };
    let any_eku = [0x55u8, 0x1d, 0x25, 0x00];
    for (i, der) in ok.path.iter().enumerate() {
        // (a certificate with a critical extension of the caller's is not parseable on its own)
        let Ok(c) = Certificate::from_der(der) else { continue };
        assert!(c.not_before <= time && time <= c.not_after, "a certificate of the path is outside its validity at {time}");
        let Some(oid) = &oid else { continue };
        match c.extended_key_usage() {
            Some(list) => assert!(list.iter().any(|o| o == oid || *o == any_eku), "certificate {i} of the path does not allow the purpose"),
            None => assert!(i > 0 || opts.allow_missing_leaf_eku, "a leaf with no extendedKeyUsage was accepted for a purpose it did not name"),
        }
    }
}

// ---- pem

fn pem_text(data: &[u8]) {
    let encoded = pem::base64_encode(data);
    assert_eq!(pem::base64_decode(&encoded).expect("our own Base64 does not decode"), data);
    let text = String::from_utf8_lossy(data);
    let blocks = pem::parse(&text);
    for b in &blocks {
        let body: Vec<String> = pem::base64_encode(&b.data).as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        let armored = format!("-----BEGIN {}-----\n{}\n-----END {}-----\n", b.label, body.join("\n"), b.label);
        let again = pem::parse(&armored);
        assert_eq!(again.len(), 1, "re-armoring a block gave {} blocks", again.len());
        assert_eq!((&again[0].label, &again[0].data), (&b.label, &b.data));
    }
    let _ = pem::base64_decode(&text);
    let mut ts = TrustStore::empty();
    let n = ts.add_pem(&text);
    assert!(n <= blocks.len(), "{n} certificates loaded from {} PEM blocks", blocks.len());
}

// ---- revocation

fn pair(sel: u8) -> (Vec<u8>, Vec<u8>) {
    match sel & 3 {
        0 => (fixture_der("rev_leaf"), fixture_der("rev_inter")),
        1 => (fixture_der("rev_inter"), fixture_der("rev_root")),
        2 => (fixture_der("rev_leaf_ms"), fixture_der("rev_inter")),
        _ => (fixture_der("rev_other"), fixture_der("rev_inter")),
    }
}

fn clock(sel: u8) -> i64 {
    [NOW, NOW + 10 * 86_400, NOW - 10 * 86_400][((sel >> 2) & 3) as usize % 3]
}

fn crl(data: &[u8]) {
    let Some((&sel, der)) = data.split_first() else { return };
    let (leaf, issuer) = pair(sel);
    let verdict = pratique::revocation::fuzz_hooks::crl(der, &leaf, &issuer, clock(sel));
    if verdict == 0 || verdict == 1 {
        assert!(is_known_good(seed_data::CRL, der), "a CRL that is not one of the known good ones decided a certificate (verdict {verdict})");
    }
}

fn ocsp(data: &[u8]) {
    let Some((&sel, der)) = data.split_first() else { return };
    let (leaf, issuer) = pair(sel);
    let verdict = pratique::revocation::fuzz_hooks::ocsp(der, &leaf, &issuer, clock(sel));
    if verdict == 0 || verdict == 1 {
        assert!(is_known_good(seed_data::OCSP, der), "an OCSP response that is not one of the known good ones decided a certificate (verdict {verdict})");
    }
    // the unverified look at a response's window that a cache takes: never a panic, and a window for any response that decided
    let until = pratique::revocation::ocsp_response_valid_until(der);
    if verdict == 0 || verdict == 1 {
        assert!(until.is_some(), "a response that decided a certificate has no window for a cache");
    }
}

fn revocation_path(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let n = (u16::from_be_bytes([data[0], data[1]]) as usize).min(data.len() - 2);
    let (staple, crl) = (&data[2..2 + n], &data[2 + n..]);
    let path = [fixture_der("rev_leaf"), fixture_der("rev_inter"), fixture_der("rev_root")];
    let accepted = pratique::revocation::fuzz_hooks::path(&path, staple, crl, NOW);
    let (off, soft, hard) = (accepted & 1 != 0, accepted & 2 != 0, accepted & 4 != 0);
    assert!(off, "a policy that is switched off refused a chain");
    assert!(!hard || soft, "HardFail accepted what SoftFail refused");
    if staple == file(seed_data::OCSP, "rev_ocsp_revoked.der") || crl == file(seed_data::CRL, "rev_crl_revoked.der") {
        assert!(!soft && !hard, "a certificate the evidence says is revoked was accepted");
    }
    if hard {
        assert!(is_known_good(seed_data::OCSP, staple) || is_known_good(seed_data::CRL, crl), "HardFail accepted a chain on evidence that is not known to be good");
    }
}

// ---- http, url

fn http_response(data: &[u8]) {
    use pratique::http::fuzz_hooks::response;
    if data.len() < 5 {
        return;
    }
    let as_given = response(data);
    let mut v = data.to_vec();
    v[3] = 0; // one byte per read
    let byte_wise = response(&v);
    v[3] = 96; // 97 bytes per read
    let chunked = response(&v);
    assert_eq!(byte_wise, chunked, "the same response parsed differently when read in 1 and in 97 byte pieces");
    assert_eq!(as_given, byte_wise, "the same response parsed differently when read in {}-byte pieces and byte by byte", 1 + data[3] as usize % 97);
}

fn url(data: &[u8]) {
    use pratique::http::Url;
    let text = String::from_utf8_lossy(data);
    let (base, location) = text.split_once('\n').unwrap_or((&text, ""));
    let check = |u: &Url| {
        assert!(u.scheme == "http" || u.scheme == "https");
        assert!(!u.host.is_empty() && u.port != 0 && u.path_and_query.starts_with('/'));
        assert_eq!(u.host, u.host.to_ascii_lowercase());
        if u.host.contains(':') {
            assert!(u.host.parse::<std::net::Ipv6Addr>().is_ok(), "host {:?} has a colon but is not an IPv6 address", u.host);
        }
        // printing and parsing again is stable (the credentials are not printed)
        let printed = u.to_string();
        let again = Url::parse(&printed).unwrap_or_else(|e| panic!("{u:?} prints as {printed:?}, which does not parse: {e}"));
        let mut bare = u.clone();
        bare.userinfo = None;
        assert_eq!(again, bare, "{printed:?} parsed differently the second time");
    };
    let Ok(u) = Url::parse(base) else { return };
    check(&u);
    let _ = (u.host_header(), u.origin(), u.is_https());
    if let Ok(j) = u.join(location) {
        check(&j);
        let l = location.trim();
        if !l.contains("://") && !l.starts_with("//") {
            assert_eq!(j.origin(), u.origin(), "the relative redirect {l:?} moved {u} to {j}");
        }
    }
}

fn egress(data: &[u8]) {
    pratique::http::fuzz_hooks::egress(data);
}

fn seeds_egress() -> Vec<Vec<u8>> {
    pratique::http::fuzz_hooks::egress_example_inputs()
}

const EGRESS_DICT: &[&[u8]] = &[
    b"*.", b".example.com", b"*.0.0.1", b"*.gallerycdn.vsassets.io", b"https://", b"http://", b"@", b"user:pw@", b"[::1]", b"[::1]:8443", b":443", b":8443", b":0", b"\n", b" ", b"//", b"/../", b"..",
    b"Authorization: Bearer ", b"Private-Token: ", b"Host: ", b"Content-Length: ", b"X-A: b\r\nX-B: c", b";", b"-", b"_", b"%", b"\xc3\xa9", b"\x7f", b"0x7f", b"127.0.0.1", b"10.1.1", b"localhost",
];

fn aead(data: &[u8]) {
    pratique::crypto::fuzz_hooks::aead(data);
}

fn seeds_aead() -> Vec<Vec<u8>> {
    pratique::crypto::fuzz_hooks::aead_example_inputs()
}

// ---- tls

fn tls_records(data: &[u8]) {
    pratique::tls::fuzz_hooks::server_bytes(data);
}

fn tls_flight(data: &[u8]) {
    pratique::tls::fuzz_hooks::server_flight(data);
}

fn tls_server(data: &[u8]) {
    pratique::tls::server_fuzz::server_exchange(data);
}

fn tls_post(data: &[u8]) {
    pratique::tls::fuzz_hooks::peer_records(data);
}

fn tls12_flight(data: &[u8]) {
    pratique::tls::fuzz_hooks::server_flight12(data);
}
