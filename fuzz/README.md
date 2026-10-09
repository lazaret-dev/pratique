# Coverage-guided fuzzing

`pratique` parses bytes that strangers control: certificates, OCSP responses, CRLs, TLS records,
HTTP responses, HTTP/2 frames, header blocks and connections, QUIC packets and frames, transparency-log data (signed notes, Merkle proofs and tiles), CMS / PKCS#7 signatures and Sigstore bundles. This directory holds a fuzzer for all of it. It has **no dependencies**, like
the library, and it needs **no nightly compiler, `cargo-fuzz` or libFuzzer**.

```sh
sh run_all.sh 3600        # one hour, one process per core, every target
sh run_all.sh check       # is the coverage feedback working? (build + 2 s)
```

While it runs it prints a table of every target once a minute (executions, edges reached, corpus size,
speed, findings). Ctrl-C stops the workers, merges what they found and prints the summary, so an early stop
loses nothing.

When it finishes it prints a summary, and writes `fuzz-results.tgz` (summary, findings, corpus).
Findings are inputs that crashed, hung or ballooned memory; there should be none. If there are,
send `fuzz-results.tgz` back, or reproduce one with `sh run_all.sh replay TARGET FILE`.

## How it works

LLVM can instrument a program with edge counters (SanitizerCoverage). Stable `rustc` can emit
them: `-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3
-C llvm-args=-sanitizer-coverage-inline-8bit-counters` (see `run_all.sh`). Every instrumented
module registers its counter array through `__sanitizer_cov_8bit_counters_init`, which `src/main.rs`
defines. After each input the engine looks at which edges ran, and how often (in AFL's hit-count
buckets). An input that reaches a new edge, or a new bucket of an old one, is kept and mutated
further. That is the whole idea; it is what lets the fuzzer get through a length field, a magic
number or a signature-shaped blob that random bytes would never pass.

The engine (`src/main.rs`, about 900 lines) adds what a fuzzer needs around that loop:

* **Mutations**: bit and byte flips, interesting values (0, 1, 0x7fff.., 0xffff..), arithmetic,
  insert, delete, duplicate, copy a block, splice with another corpus entry, dictionary tokens
  (`targets.rs` has one per target: DER tags and OIDs, HTTP header names, TLS handshake types...).
* **Panics** are caught per input and de-duplicated by location. The fuzz binary is built with
  `debug-assertions` and `overflow-checks` on, so an arithmetic overflow or a failed
  `debug_assert!` in the library is a finding.
* **Crashes no panic handler sees** (stack overflow, abort) are found by a supervisor process: the
  child writes the current input to a file before running it, and the supervisor reads it back.
* **Hangs**: a watchdog thread stops any input that runs longer than `--timeout` seconds (default 5).
* **Memory bloat**: a counting global allocator reports an input that makes the target allocate
  far more than a parser should for its size (budget per target in `targets.rs`), a single
  allocation over 256 MiB, or more than 1 GiB live at once. "Trusts a length field before the
  bytes are there" is the classic parser bug.
* `merge` keeps the smallest set of inputs that reaches everything the corpus reaches.

## What each target checks

Every target asserts something about the answer, because a parser that quietly accepts the wrong
thing is the dangerous kind of bug. The table is in `src/targets.rs`; in short:

| target | beyond "does not panic, hang or balloon" |
|---|---|
| `der` | every element lies inside its input and uses the shortest length form; INTEGERs are minimal; a time that parses is a real calendar date; an OID's dotted form reads back as the same OID |
| `certificate` | the parsed certificate keeps exactly the bytes it was given; only a known certificate has a valid self-signature; its subjectAltName and extension accessors agree with each other and with the fields TLS uses |
| `hostname` | a wildcard pattern matches exactly one label and nothing else |
| `chain` | a chain that is not made of known certificates, or a host or time the leaf is not valid for, is never accepted |
| `idna` | `idna::to_ascii` gives ASCII (or an error) that is its own conversion and that `to_unicode` turns back into the same; Punycode decodes what it encodes, and what decodes encodes back to the same text (in lower case) |
| `chain_algs` | the same over the chains of B-33: a P-521 root and intermediate (ECDSA with SHA-512 and SHA-384), an RSA intermediate that signs with RSASSA-PSS, and leaves signed with PSS parameters the library does not read (`tools/gen_algorithm_fixtures.py`) |
| `purpose_chain` | the same for chains verified for a purpose other than TLS (server or client authentication, code signing, e-mail, time stamping, an OID, any), at a chosen time, with or without a host name: an accepted path is made of known certificates, every one valid at that time, every one that parses allows the purpose, and the leaf names the purpose unless told it need not |
| `ber` | whatever parses can be walked (a constructed element has children and no content, a primitive one the reverse); what `der()` writes is strict DER (the `asn1` reader takes it as one element with the same bytes), parses again, and writes itself again unchanged; `der_content()` is the content of `der()` |
| `cms` | a SignedData or an RFC 3161 time-stamp token made from the fixtures (`tests/data/cms_fixtures.txt`, signed by OpenSSL and the JDK's `jarsigner`) and changed by the input verifies only if its signature value, its content and its signer's certificate are ones a fixture message verified with, and the chain time is the caller's or a fixture time stamp's; the signature check alone never refuses what the full check accepts. At start-up the target also checks that the fixtures that must never verify (a wrong digest, a swapped algorithm, a time-stamp authority without the right key usage) do not, so a check removed from the library kills the process at once |
| `json` | what parses has no object with a name twice, only numbers of the RFC 8259 grammar and nesting within the limit; a string that reads as a 64-bit integer is its canonical decimal spelling; the canonical form of a value parses again, is its own canonical form and does not depend on the order of the members; a canonical form is refused only for a number that is not an integer within 2^53 - 1; white space around a value changes nothing and any other trailing byte is refused; a smaller depth limit only takes values away. Seeds: the 1,000 or so differential cases of `tests/data/json_vectors.txt`, whose verdicts were agreed with Python and Go |
| `sigstore` | the first byte of the input chooses what the rest is: one Sigstore bundle checked against a made-up Sigstore (`tests/data/sigstore/synthetic.json`: 108 bundles from `tools/gen_sigstore_fixtures.py`), npm's attestations of one of three `sigstore` releases, or PyPI's PEP 740 provenance, the last two against Sigstore's real trusted root and npm's keys. A bundle changed by the input that verifies must say what a seed that verified says: the same format, signer (certificate or key), statement and matched subject, and only times, log entries (with their signed entry timestamps and inclusion proofs) and signed certificate timestamps that a good bundle with that signer and statement has. Losing evidence (a time stamp, an entry) is not an error, since what remains is still true; saying something new is. The first 80 seconds found exactly that: renaming `rfc3161Timestamps` made the verifier ignore the time stamp, so the bundle verified with less evidence. At start-up the target checks that the seeds that are meant to be refused are |
| `sct` | the SCT list of one of the four real Fulcio certificates replaced by the input (the first byte chooses the certificate, and whether the SCTs are checked with its issuer or with the root of its chain): the certificate still parses and its precertificate (`ct::precertificate_tbs`) is the one the log signed; a list that parses has at most 32 SCTs and, when all are version 1, is written back as the same bytes; every SCT that verifies against Sigstore's CT logs has the log, time and extensions of the SCT the log signed, none verifies with the wrong issuer, and every SCT is either verified, from a log not listed, or of another version |
| `tuf` | one file of a TUF repository made with python-tuf (`tests/data/tuf/synthetic.json`, the cases that give their target) replaced by the input: the client of `pratique::tuf` gives that case's own target or refuses, never other bytes; and JSON that parses has an OLPC canonical form that is its own canonical form (or holds a raw control character, which that form writes as it is) |
| `trust_root` | a trusted root or npm key list that parses parses again, equal, from its canonical JSON (so spelling and order do not matter); the logs, keys and authorities in it are consistent (a key reads again as itself, a log is found by its id, a validity contains its own ends and not the seconds beside them); an npm key's id is the OpenSSH fingerprint of its key; an RFC 3339 time that parses is the calendar time its digits say, offset and fraction included (checked with a second implementation of the calendar) |
| `inflate` | DEFLATE, zlib and gzip (`pratique::inflate`): the bytes, or the error, do not depend on how the input and the output are cut; nothing is written past the limit; a stream that fits fits at exactly its size and is refused with `OutputLimit` one byte under it; what passes a ratio limit is within it; zlib implies "zlib or bare DEFLATE" and one gzip member implies gzip. Seeds: the streams of `tests/data/inflate_vectors.txt`. 482,000 executions on x86-64 (2026-10-07), nothing found |
| `h2_hpack` | a header block (HPACK, with its Huffman strings) decodes or is refused, whatever table size and list limit the decoder was given; a list that decoded within the limit is written by our encoder (sensitive or not, two blocks on one table) and read back by a fresh decoder as the same list |
| `h2_frames` | frames cut from the bytes parse or are refused; the pieces of one that parsed lie within its payload |
| `h2_client` | the client's HTTP/2 connection fed what a server might send, in pieces of 1 to 200 bytes, with windows from 1000 bytes to 32 MiB and the server's SETTINGS first or not: the flow-control books balance after every step; what the client writes is the preface and whole frames that parse, and its header blocks decode; when the transport is lost every stream ends or fails, and nothing is left once they are released |
| `h2_server` | the in-crate HTTP/2 server connection (the `server` feature) fed what a client might send: no panic, and what it writes is whole frames that parse |
| `quic_packet` | `data[0]` odd: a QUIC packet is made from the fields in the input, sealed, read back, opened (its packet number and payload are what went in) and not opened with one bit changed anywhere. `data[0]` even: a datagram is read as coalesced packets, every field inside its packet and each packet inside the datagram; a packet that opens with the Initial keys that anyone can make is sealed again to the same bytes |
| `quic_frame` | a QUIC packet payload is read as frames or refused with a transport error; every frame that is read lies inside the payload, is written and read again as itself, and is allowed in the packet it was in |
| `quic_params` | QUIC transport parameters (RFC 9000 section 18) are read or refused with a transport parameter error, never a panic; what is read is within the limits of section 18.2 (no `max_udp_payload_size` under 1200, no `ack_delay_exponent` over 20, no `max_ack_delay` of 2^14 or more, no stream limit over 2^60), has no parameter id twice (checked by a second, independent walk over the bytes), is written and read again as itself, and the writing is the same bytes again; a cut anywhere in the input is an error and not a panic |
| `quic_buffers` | the first byte chooses: a `RangeSet` is the same set of numbers as a `BTreeSet` after every insert, remove, pop and split, and holds the fewest ranges (none touching); a `SendBuf` with a `Reassembler` as the receiver, over chunks that are lost, delivered twice and acknowledged late, sends exactly the bytes written, its books balance after every step, and when everything is acknowledged the receiver has it all and the buffer is empty; a `Reassembler` holds what a map of the bytes says, refuses (final size, window) what the map says, and a refusal changes nothing |
| `quic_streams` | the first byte chooses: two `Streams` endpoints joined by a simulated network that loses, delays and duplicates, with an application that opens, writes, reads, stops and resets as the input says, lose and change no byte, keep their books (`Streams::check`: flow-control credit, send and receive buffers, pending frames) after every step and end with nothing owed; or one endpoint given the frames the input makes (any, as from a hostile peer) between calls of the application: no panic, the books hold, and what it writes is frames that read and fit in the packet |
| `quic_recovery` | loss recovery (RFC 9002) against a model of the packets that were sent: bytes in flight and the count of ack-eliciting packets in flight are the model's after every step, an acknowledgment acknowledges exactly the packets sent in its ranges, no packet that the packet threshold or the time threshold says is lost is left outstanding, a timer is set whenever something is outstanding, the latest RTT sample is never more than the time that has passed, and the congestion window never falls under its minimum |
| `quic_connection` | a whole client connection against the test server (`src/quic/test_server.rs`, a small QUIC server made from the same packet, frame and TLS layers, compiled only for tests and fuzzing), over a simulated network that loses, duplicates, reorders, delays and corrupts datagrams, with the settings (windows, limits, datagram size, connection id length, Retry or not) and the steps (advance the clock, open, write, read, stop, reset, ping, key update, close, frames injected by the server) all from the input. Honest (the server follows the rules): every byte of every stream that was not reset comes out as it went in, no side closes with an error, and when the script is done the connection ends by its idle timeout and then sends nothing. Hostile (the server also sends the frames the input makes, and may corrupt datagrams before the handshake is over): no panic, nothing grows without end, no datagram is larger than the peer allows (1200 bytes at least for a client's first), the congestion books agree with recovery's, the window never falls under its minimum. The entry point is `pratique::quic::fuzz_hooks::connection`, which exists only in a build with `--cfg pratique_fuzzing` |
| `h3_qpack` | the decoder fed an encoder stream, field sections and cancellations made up from the bytes: no panic, and after each step its table adds up and is within what it announced, what it holds of a cut instruction is bounded, a list it gives is within the limit, a section it holds back is one that waits for entries it has not got, and what it writes on the decoder stream is whole instructions; every list that decoded is written by our encoder (several settings, sensitive or not, three sections on one pair) and read back by a fresh decoder as the same list |
| `h3_qpack_exchange` | our encoder and our decoder over links that delay, cut and drop (settings, requests, deliveries and abandoned streams all chosen by the bytes): nothing they say is an error, the decoder reads the fields the encoder was given, no stream waits on more than was allowed, no entry is evicted while a section not acknowledged refers to it, and when everything has arrived the tables agree and nothing is counted as referred to |
| `h3_frames` | the frame reader on a request stream or the control stream, from bytes made up as they come, cut in pieces the bytes choose: it says what a model that has the whole stream before it says (the frames, the code of the error, whether the stream is between frames), a data range is inside the piece it came from, a HEADERS frame over the limit is not kept, and what was read from a request stream is written again and read back the same |
| `h3_connection` | a whole HTTP/3 client connection against a server made up from the bytes (requests, well-made responses with a QPACK table that is filled, delayed and acknowledged, slow writes, resets, GOAWAY, streams of unknown types, and with the low bit of the first byte set, bytes that mean nothing): the books add up, a lost connection was closed with a code of the RFCs, the application sees each stream's events in order, a server that is well made does not lose the connection and what it sent is what is read, and what the client wrote decodes to the requests |
| `h3_qpack_encoder` | the encoder fed a decoder stream made up from the bytes, between requests: an instruction that makes no sense is an error, anything else leaves its books balanced (what is counted as referred to is what the sections not acknowledged refer to, the table is within its limits, no more streams may be blocked than allowed) |
| `egress` | a client with a rule about hosts (entries, one-label wildcards, the default port only), limits on a URL and a hook that gives each hop its headers decides about a request and every redirect as a second, simple account of the rules does (that account is written apart from the code, from the README's words); a refused hop is an `Error::Refused` for the right hop and rule and leaves the request as it was, a host whose last label is a number is never under a wildcard, the hook's headers are this hop's and no other's (never carried, never on a connection for another origin), and what is sent is well made |
| `aead` | AES-GCM and ChaCha20-Poly1305 made by the code this CPU gets (the vector kernels where there are some, so the aarch64 NEON, PMULL and AES paths on an ARM machine) are the same bytes as the portable code makes, are read by both, and are not read when anything of them (nonce, associated data, ciphertext, tag) is changed |
| `alt_svc` | an `Alt-Svc` field from bytes made up as it would come from a server (with a dictionary of `h3`, `clear`, `ma=`, quoted authorities, percent-escapes and IPv6 literals): nothing panics, a `clear` is the whole field or nothing, an alternative is an `h3` one with a port and a lifetime that is within 30 days (24 hours if it gave none), a host is a name or an address in its canonical form, and a field that is written again from what was read (alternatives re-quoted) is read as the same |
| `ed25519` | a signature verifies only if it is one of the known ones (`tests/data/ed25519_*`) or its key is one of the 14 encodings of a point of small order; adding L to S always breaks a signature that verified. The input is a key (32 bytes), a signature (64 bytes) and the message. The build has overflow checks on, which is what would catch a limb bound broken in the field arithmetic |
| `pem` | Base64 and PEM armor round-trip |
| `signing_key` | private keys in PEM and DER (PKCS#8, SEC 1, PKCS#1; `src/sign.rs`, B-109): nothing panics; a key that is read signs, and every signature it makes for each TLS scheme it offers verifies under its own public key; an ECDSA or Ed25519 key written out as PKCS#8 reads back as the same key |
| `note` | a signed note opens only with signatures that are, byte for byte, known good ones (`tests/data/note_fixtures.txt`, the real `sum.golang.org` notes), made by a key that was given; a verifier key that parses prints back as itself |
| `tlog` | the Merkle inclusion and consistency checks (RFC 9162, iterative) give the same verdict as a second implementation written after RFC 6962's recursive definitions, on every input, with the right roots also supplied so that the accepting side is exercised; a tile path that parses prints back as the same text; and for a tree built inside the target, genuine tiles authenticate while **any one byte changed in a needed tile, or a needed tile missing, is refused** (CVE-2026-56865 was a tile Go did not check) |
| `sumdb` | tree heads and lookup responses that parse print back as the bytes they came from; a lookup path that is made unescapes to what it came from; with a made-up log in two histories under a test key (`tests/data/sumdb_synthetic.txt`), heads, lookups and tiles damaged by the input, nothing is accepted that was not signed and no two histories are ever accepted together |
| `crl`, `ocsp` | nothing but a byte-for-byte known, signed fixture ever decides a certificate: no modified copy gives "good" or "revoked", and a forged one never does. (One exception, found by the first long campaign: `rev_ocsp_forged.der` is a genuine response with the last bit of its signature flipped, so flipping it back is a genuine response, and the check allows exactly that one input.) |
| `revocation_path` | `Off` always accepts, `HardFail` implies `SoftFail`, evidence that says "revoked" is never accepted, `HardFail` needs known-good evidence |
| `http_response` | the result is the same however the bytes are cut into reads (1 byte, 97 bytes, as given) |
| `url` | print then parse gives the same URL; a relative redirect never changes the origin; a host with a colon is an IPv6 address |
| `tls_records` | raw bytes at a fresh client (record layer, ServerHello, HelloRetryRequest and the ServerHello that follows it) |
| `tls_flight` | a server flight sealed under the correct handshake keys (so it passes the record MAC and reaches the message parsers), optionally after a HelloRetryRequest for P-256, P-384 or a cookie, never completes a handshake |
| `tls_post` | records at an established connection: KeyUpdates, tickets, alerts, application data, and our own writes with a tiny rekey interval; and the same at a TLS 1.2 connection (selector bit 2), where a HelloRequest is answered with a warning and a change_cipher_spec may not come |
| `tls12_flight` | what a TLS 1.2 server sends after a correct TLS 1.2 ServerHello, raw: Certificate, CertificateStatus, ServerKeyExchange, CertificateRequest, ServerHelloDone, change_cipher_spec and the encrypted Finished, on every suite, with the chain verified or not. The seeds carry a correctly signed ServerKeyExchange (the client random is fixed, so the signature can be made in advance), so they reach the client's own flight (the seed list checks that); the handshake never completes (the Finished it would need is sealed under keys from the key exchange) |

The TLS targets call hooks in the library (`tls::fuzz_hooks`, `revocation::fuzz_hooks`,
`http::fuzz_hooks`; the HTTP/3 ones are in `http::fuzz_hooks` too, from `src/http/h3/fuzz_hooks.rs`). They exist only under `--cfg pratique_fuzzing`, are `#[doc(hidden)]`, and
are not part of the API; a normal build does not contain them.

## What it has found

* The HTTP parser's check of a chunked body against `max_body_bytes` was `body.len() + size`.
  A chunk size near 2^64 overflowed it: a panic in a debug build, and in a release build a wrap to a
  small number, so the limit was skipped and a hostile server could stream an unlimited body.
* `http://a:b:80/` parsed with the host `a:b` (a colon outside a bracketed IPv6 literal).
* A header line of exactly the size limit was refused when read byte by byte (its CR counted
  against it before the LF arrived) and accepted when read at once.
* The OCSP response parser read only the OID of the unsigned `signatureAlgorithm` and ignored
  whatever followed, so a response was still accepted with garbage there. Parameters are now
  required to be absent or NULL (certificates and CRLs share the same code).
* DER times such as 30 February parsed (as 2 March).

Each has a regression test in the unit tests.

The seven QUIC targets have found no bug in the client's QUIC code so far (about 25 minutes on the whole-connection target alone,
200,000 connections, and minutes on each of the others). What they found were mistakes in the things around it: the test server
kept sending Handshake data for ever after the client had dropped those keys (so an honest run could idle out), and the harness
had to learn what a bad network may and may not do (three lost datagrams in a row at most in an honest run, a Retry that cannot be
sent again). Whether such a target can find anything is what the next section answers.

The five HTTP/3 targets (QPACK, the frame reader, the client connection) have found no bug in the code either, in minutes of
fuzzing each (about 400,000 runs of the connection target, 2.4 million of the frame target); what they and the tests found was in
what they were checked against. `ls-qpack`, the library under aioquic, reads a Required Insert Count from the capacity it was
last given and not from the maximum, and refuses a base that is not 0 in a section that needs nothing, so the encoder announces
the peer's maximum and writes a section with no references with base 0 (RFC 9204 allows the other ways too, and the first draft
of the encoder did one of them; ls-qpack could not read it). The first runs of the connection target "crashed" eight times, each time a mistake of the harness (it
judged a stream before the last delivery of the server's instructions, which a connection that failed in that delivery had not
yet given the stream). Each of these has a regression test.

## Are the targets any good?

A target that never fails proves nothing unless it would fail if the code were wrong. `mutate.py` (with the list in `mutants.py`)
breaks the code on purpose, one change at a time (an off-by-one in a threshold, a check removed, an acknowledgment that is never
applied), builds the fuzzer on the broken copy and runs the target that is meant to notice, for 25 to 60 seconds. For the QUIC state
code there are 23 changes: 21 are noticed and 2 change nothing anybody can see (acknowledging a stream chunk twice; forgetting the
handshake's crypto data on acknowledgment rather than with the keys of its space).

It was not that way at first. The first run noticed 17 of the 20 then in the list; one of the other three changed nothing visible,
and two were holes in the targets: transport parameter limits (random input does not land on exactly 2^14, so the target now has a
seed on each side of every limit) and the send buffer's model, which never reported a loss for data that was never sent. Three
changes to the connection were then added, and two of them got through as well: acknowledgments of stream data that are never applied
(so no stream is ever forgotten) and packets that arrive without counting as activity (so a connection that only listens idles
out). The whole-connection target now checks that a stream both sides have finished with is forgotten once everything is
acknowledged, and that a server that keeps pinging keeps the client from idling out however long the client says nothing.

For HTTP/3 there are 58 changes, plus 9 of the connection's again for its fuzz target to find (the others are caught by unit
tests, which is what a connection that has so many small rules wants). The first run noticed 21 of QPACK's 24 and the unit tests
had to be given three cases: the required insert count that wraps (the entry counts either side of the wrap), a reference to the
entry the section's own required insert count names (an off-by-one that no random list lands on), and an instruction whose 5-bit
prefix is exactly full; random input does not find the edge of a limit, so each is now a unit test. The frame reader's 13 and the
connection's 21 were all noticed, except one: a stream whose last byte arrives together with a field section that has to wait for
the table, whose end was then lost. The test transport let the connection read the end of a stream twice, so the end came back
on the next read; the real transport does not promise that, so the test transport now says a stream whose end was read is gone.

Asked of the fuzz target alone, the first run of those 9 noticed 4, and the five that got through were holes in what the model
server did and checked, each now closed: no check that a complete, well-made response is read to its end (so a lost end of a
stream went unseen); no stream of a type nobody knows that is given more bytes later and ended (a connection that remembered
such streams for ever was never caught); and no response bigger than what the connection reads ahead of an application that is
not reading (so a connection that never stopped reading, or never started again, was never caught). The second run noticed all 9.

```sh
python3 fuzz/mutate.py --list
python3 fuzz/mutate.py params streams     # only the mutants whose names start so
```

## Files

| path | what |
|---|---|
| `run_all.sh` | build, campaign, `replay`, `regen` |
| `src/main.rs` | the engine |
| `src/targets.rs` | the targets, their invariants, seeds and dictionaries (the `ber` and `cms` ones are in `src/cms_targets.rs`, the note, tlog and sumdb ones in `src/log_targets.rs`, `json`, `sigstore` and `trust_root` in `src/sigstore_targets.rs`, `inflate` in `src/inflate_targets.rs`, the four `h2_` ones in `src/h2_targets.rs`, which call `pratique::http::fuzz_hooks`, the two packet-level `quic_` ones in `src/quic_targets.rs`, which call the public `pratique::quic` layers; the five that keep state, `quic_params`, `quic_buffers`, `quic_streams`, `quic_recovery` and `quic_connection`, in `src/quic_state_targets.rs`, the last of which calls `pratique::quic::fuzz_hooks`) |
| `mutate.py`, `mutants.py` | breaks the code on purpose and checks that a target notices (see "Are the targets any good?") |
| `src/seed_data.rs` | the fixtures from `../tests/data` embedded as bytes (`sh run_all.sh regen` after adding one) |
| `corpus/TARGET/` | the minimal corpus found so far; each run starts from it |
| `artifacts/`, `work/`, `logs/` | created by a campaign (findings, per-process corpora, output); a new campaign moves the previous one's findings to `artifacts.prev/` so the summary lists only its own |

## Using the engine directly

```sh
RUSTFLAGS="--cfg pratique_fuzzing -C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-inline-8bit-counters" cargo build --release
target/release/pratique_fuzz list
target/release/pratique_fuzz run chain --seconds 300 --corpus corpus/chain --artifacts artifacts/chain
target/release/pratique_fuzz replay chain artifacts/chain/crash-*
target/release/pratique_fuzz merge chain --into corpus/chain some/other/dir
```

## Adding a target

Write a `fn(&[u8])` in `src/targets.rs` that feeds the bytes to the code and `assert!`s what must
hold, give it seeds (real inputs: they matter more than anything else) and a dictionary, and
list it in `all()`. Check the invariant against the seeds first: a target whose invariant fails
on its own seeds fails at once.

An invariant that holds only for some inputs makes noise. Two early reports here were the harness
being wrong: it treated a fixture as "bad" although a different clock or certificate made it
good. Prefer "only these known bytes are ever accepted" to "this input must be rejected".

## Limits

* Unix only (it writes the current input with `pwrite`); one thread per process; no sanitizers
  (no AddressSanitizer or MemorySanitizer: those need nightly), so a memory error would have to
  show up as a crash or a wrong answer. The library's `unsafe` is confined to the SIMD cipher
  kernels (AES, GHASH, ChaCha20), zeroization and OS random calls; the TLS targets drive the
  kernels with attacker-chosen record lengths.
* The edge counters cover the library and the fuzzer's own code; there is no value profile
  (comparison feedback), so a 4-byte magic number that is not in a seed or a dictionary is found only
  by luck. Add it to the dictionary.
* The aarch64 AES, carry-less multiply and ChaCha20 (NEON) paths run in `tls_post`, `tls_flight` and
  `aead` only on an ARM machine, which is one reason to run a campaign there; `aead` is the one that
  compares them with the portable code byte for byte, so an Apple-silicon run of it is the check that
  the vector code and the portable code agree.
