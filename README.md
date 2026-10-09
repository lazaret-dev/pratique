# pratique

An HTTPS client for Rust built from scratch with **zero dependencies** (only `std`).

The name goes with Lazaret, the package-security scanner it was written for: a
lazaret is a quarantine station, and pratique is the clearance a ship gets to leave quarantine and enter port.

## Status

A working HTTPS client: you can `get`/`post` over TLS 1.3 (or TLS 1.2, with a server that speaks nothing newer) with full certificate validation, over HTTP/1.1 (with a keep-alive pool and streaming bodies) or, when you ask for it, HTTP/2 or HTTP/3.

| Layer | State |
|-------|-------|
| Crypto: SHA-256/384/512, HMAC, HKDF, AES-128/256-GCM, ChaCha20-Poly1305, X25519, ECDH on P-256/P-384 (constant time), RSA (PKCS#1 v1.5 and PSS verify), ECDSA P-256/P-384/P-521 verify, Ed25519 verify (rules of Go's `crypto/ed25519`), bignum | Tested against RFC/NIST vectors, OpenSSL-generated signatures and Project Wycheproof (P-521, RSA-PSS: 894 vectors, B-33); all 123 supported self-signatures among the 128 real roots in a system CA bundle verify (the 5 others use SHA-1) |
| ASN.1/DER, PEM, X.509 chain validation for TLS servers and for other purposes (code signing, time stamping, e-mail, any), hostname matching, issuer names compared as RFC 5280 section 7.1 and OpenSSL compare them, internationalized host names to A-labels (`idna`, B-34) | Fixture tests (expiry, wrong host, non-CA issuer, pathLen, name constraints on DNS, e-mail, URI and IP names, wrong purpose, validation at a past time, tampering, names written in other string types, case and spacing, with OpenSSL's verdicts); Punycode against RFC 3492's samples and 200 strings from Python; a real Sigstore Fulcio chain (root, intermediate and a leaf from a real npm provenance attestation, validated at its logged time) and a real Apple Mac App Store code-signing chain; 127 of 128 real roots parse |
| TLS 1.3 client (handshake, HelloRetryRequest, record layer, KeyUpdate in both directions, ALPN, session resumption with a fresh key exchange: B-35) | Interoperates with `openssl s_server` (RSA/P-256/P-384 keys x 3 cipher suites, sessions resumed on every suite and after a HelloRetryRequest, P-521 keys and CAs, RSA-PSS-signed certificates, and servers that accept only P-256 or P-384 key exchange, which force a HelloRetryRequest) and with a third-party TLS gateway; reproduces the RFC 8448 handshake trace byte for byte |
| TLS 1.2 client for servers that speak nothing newer (B-36): ECDHE (X25519, P-256, P-384) with AES-GCM or ChaCha20-Poly1305 only, the extended master secret required, the downgrade check of RFC 8446, no renegotiation, no resumption; a minimum version per client and per request; the version in every response | `openssl s_server -tls1_2`: every suite with RSA, P-256 and P-384 keys, every group, 3 MiB down and up on every suite, ALPN, revocation by staple; a man in the middle that takes TLS 1.3 out of the ClientHello is caught by the downgrade check, and one that takes the extended master secret out of the ServerHello is refused; what is not offered (CBC, static RSA, no EMS) is refused; HTTP/1.1 and HTTP/2 over TLS 1.2 against Go's server, with the pool keeping TLS 1.2 connections from requests that require 1.3; the PRF and the records against published vectors and Python's `cryptography`; fuzz targets `tls12_flight` and `tls_post` |
| HTTP/1.1 client, keep-alive pool, streaming bodies, redirects, CONNECT proxy | Unit tests, HTTPS tests against OpenSSL, and tests against the in-crate TLS server (tickets, rekeys, stale connections) |
| DEFLATE, zlib and gzip decompression (`inflate`, pure, written from scratch, with limits on the size and the ratio) and, opt-in, `Content-Encoding` in the clients; `Expect: 100-continue`; an opt-in cookie jar | 256 streams made by zlib, gzip(1), zlib-flate, Go's `compress/*` and by hand decode at every cutting of input and output, and 1,039 damaged copies get exactly zlib's verdict (Go agrees on all but the gzip headers with a reserved flag bit, which it ignores and zlib and RFC 1952 refuse: `tests/inflate_vectors.rs`, `tools/gen_inflate_vectors.py`); a fuzz target (`inflate`: the answer does not depend on how the stream is cut, nothing past the limit); bombs of 1,032 to 1 stopped at the limit over HTTP/1.1, HTTP/2 and the async client; the 100-continue wait over TCP and TLS against scripted servers; the cookie rules of RFC 6265 and 6265bis, host-only |
| HTTP/2 client (opt-in, blocking `Client`): HPACK, framing, flow control, one shared connection per origin | HPACK checked against Go's and Python's implementations in both directions; 15 tests against Go's own HTTP/2 server; the in-crate server (below) against curl, Go and python-h2; 4 fuzz targets; real servers (pypi.org, npm) answer it over h2 |
| TLS 1.3 server and HTTP/1.1 and HTTP/2 server (`server` feature; being made ready for production, B-109 to B-114: **not reviewed yet**), with constant-time signing by ECDSA P-256/P-384, Ed25519 and RSA keys read from PEM (B-109), certificates chosen by name and by what the client can verify, stateless tickets under rotating keys, and client certificates (B-110), one handler API for both versions of HTTP, strict about request smuggling and the HTTP/2 floods (B-111), and a runtime with limits, timeouts a slow client cannot stretch, graceful shutdown and certificates kept fresh (B-112), and ACME: certificates got and renewed from Let's Encrypt or any ACME CA, by TLS-ALPN-01, HTTP-01 or DNS-01, renewal by ARI (B-113); and the scanning proxy for package registries: a CA in memory limited by a name constraint, requests scanned and made again, files read whole and refused before the client has them (B-78) | Against `openssl s_client`, curl, headless Chromium and Go's `crypto/tls` and `net/http`: 67 checks, with certificates and keys of every kind OpenSSL writes; HTTP/2 against curl, Go and python-h2: 41 checks; h2spec: 146 of 146 (147 of 147 strict); slowloris in each phase, shutdown and the limits in unit tests; a load test against Go's `net/http`; ACME against Pebble, Let's Encrypt's test CA, which validates each challenge: 24 checks, and against a CA of its own in unit tests; the proxy with pip, uv, npm, Yarn, pnpm, curl, Python and Go against the real PyPI and npm, and behind a re-signing gateway: 21 checks, and the name constraint as OpenSSL reads it; tlsfuzzer's TLS 1.3 scripts: 1,582 tests passed in 40 scripts, the rest for what the server does not do (B-114); testssl.sh: no finding |
| QUIC client transport for HTTP/3 (`net` feature, work in progress: B-91): packet and header protection (all three TLS 1.3 suites, key updates followed and, before the AEAD's limit, started: B-91, AEAD limits), the frame codec, transport parameters, the TLS 1.3 handshake in CRYPTO frames, Retry and Version Negotiation, loss recovery (RFC 9002) with NewReno and pacing, streams with flow control, closing and draining, the idle timeout, and keep-alive PINGs while a request waits; sans-IO, one `Connection` per path | The RFC 9001 appendix vectors; 72 packets made by aioquic 1.3.0 (each also under the next key generation) open, and what is sealed here is read by it; 1,745 frame payloads read by quic-go's own parser and by this one with the same result; a live handshake, requests (`GET`, bulk, `POST` echo) and the close against an aioquic server, with Retry, and through a relay that drops and delays datagrams, a 2 MB echo with the client's keys updated every 200 packets, and a connection kept alive past its idle timeout (`examples/quic_probe.rs`, `tools/quic_interop_server.py`); 7 fuzz targets, three of which run models (a set of numbers, a map of bytes, a list of outstanding packets) beside the code, and one a whole connection against the test server over a network that loses, duplicates, corrupts and reorders; 32 deliberate bugs in the packet protection, each caught by a test, and 21 in the buffers, flow control, transport parameters, loss recovery and connection, each caught by a fuzz target, and 5 in the key updates and keep-alive, each caught by a unit test (`fuzz/mutate.py`; two more change nothing that anyone could see) |
| HTTP/3 (`net` feature, opt-in on the blocking `Client` with `http3`: B-91): the client side described in the next section, over QPACK (RFC 9204: static and dynamic tables, the encoder and decoder streams, blocked streams, the required insert count), the frame reader of RFC 9114 (request and control streams, the rules for frames that may not be there, field-section limits) and the client connection on `quic::Connection` (control stream and SETTINGS both ways, the QPACK streams, request streams with trailers and `content-length` checked, interim responses, GOAWAY, streams of unknown types, push refused, flow-controlled reads, a bounded write buffer, a response that waits for the table) | QPACK: the static table checked against ls-qpack's (the library under aioquic), the examples of RFC 9204 appendix B, ls-qpack's output as a fixture and live in both directions with sections and instructions late, out of order and cut (`tools/qpack_interop.py`; it found that ls-qpack misreads the required insert count when the announced capacity is less than the maximum, so the encoder announces the maximum); the frame reader against a second parser that has the whole stream before it, under every cutting of the bytes; the connection against a model server (well-made responses, a table filled, delayed and acknowledged, resets, GOAWAY, bytes that mean nothing) with every request the client wrote decoded by a reference decoder: 148,000 responses read back byte for byte; 5 fuzz targets (`h3_qpack`, `h3_qpack_exchange`, `h3_qpack_encoder`, `h3_frames`, `h3_connection`); 58 deliberate bugs, each caught by a fuzz target or a unit test (`fuzz/mutate.py`); and over a UDP socket with a reader and a timer thread per connection, the Alt-Svc cache (RFC 7838) and the fallback to TCP | QPACK: the static table checked against ls-qpack's (the library under aioquic), the examples of RFC 9204 appendix B, ls-qpack's output as a fixture and live in both directions with sections and instructions late, out of order and cut (`tools/qpack_interop.py`; it found that ls-qpack misreads the required insert count when the announced capacity is less than the maximum, so the encoder announces the maximum); the frame reader against a second parser that has the whole stream before it, under every cutting of the bytes; the connection against a model server (well-made responses, a table filled, delayed and acknowledged, resets, GOAWAY, bytes that mean nothing) with every request the client wrote decoded by a reference decoder: 148,000 responses read back byte for byte; 5 fuzz targets (`h3_qpack`, `h3_qpack_exchange`, `h3_qpack_encoder`, `h3_frames`, `h3_connection`); 58 deliberate bugs, each caught by a fuzz target or a unit test (`fuzz/mutate.py`); the client against aioquic (`tests/h3_client_interop.rs`, 21 tests: bodies of every size, parallel streams on one connection, redirects, resets, size limits, Alt-Svc heeded and taken back, a network that refuses or silently drops UDP costing one try, a connection that dies under a request) and 11 unit tests of the registry's rules; the Alt-Svc parser by a sixth fuzz target (`alt_svc`) and 12 more deliberate bugs in the client's use of HTTP/3, each caught by a test |
| Revocation: OCSP stapling, OCSP responders asked (B-63), CRLs (supplied or fetched, with a bounded cache refreshed ahead of time), the leaf or the whole chain (B-64), must-staple, soft-fail / hard-fail; the async client asks its sources on its worker pool | Fixture tests (45 files from an independent implementation), a scripted TLS server, and `openssl s_server` / `ocsp` / `ca`: our OCSP request is byte for byte `openssl ocsp`'s, and a live `openssl ocsp` responder settles hard-fail for the TLS stream and both clients and refuses a revoked certificate; chains, responses and CRLs from the test PKI for the intermediates, the deferred check and the caches; 20 real OCSP responses and 13 real CRLs from eight public CAs (GlobalSign, Sectigo, Amazon, DigiCert, Apple, Microsoft, Google, Let's Encrypt), five of them saying revoked (the CAs' revoked test sites), replayed at the time they were fetched, altered byte by byte, and tried on other certificates and shards (B-65, B-102); live, the revoked test sites of DigiCert and Let's Encrypt are refused as revoked under hard-fail |
| Transparency logs: signed notes, Merkle inclusion and consistency proofs, tiles, the Go checksum database check (pure, no I/O) | Real `sum.golang.org` data (signed tree heads, a lookup, the seven tiles, real 26- and 17-hash proofs) verifies; 2,070 damaged and valid cases judged by Go's own `sumdb` packages and replayed; a made-up two-history log for forks; every tile authenticated (Go before x/mod 0.40 did not: CVE-2026-56865); 3 fuzz targets |
| Sigstore attestations: npm provenance and publish attestations, PyPI PEP 740 provenance, bundles v0.1 to v0.3 (strict JSON, DSSE, Fulcio identity and its signed certificate timestamps, Rekor signed entry timestamps and inclusion proofs, RFC 3161 time stamps; pure, no I/O, no clock) | The six real npm attestations of three `sigstore` releases (one per bundle format, two with a Rekor shard that has since closed) and PyPI's real provenance verify against Sigstore's production trusted root and npm's keys, and every member and string of every one, removed or changed in turn (about 1,700 changes), makes it fail unless nothing authenticates it, and their certificates' SCTs verify against the root's CT logs; 108 bundles from a Sigstore of our own cover time stamps, an Ed25519 log, every key type, CT logs and 78 refusals, each for the reason it was made for (and 600 more changes on four of them); 4 fuzz targets (`json`, `sigstore`, `trust_root`, `sct`) |
| CMS / PKCS#7 signatures (Java `META-INF/*.RSA`, `.p7s`, S/MIME) and RFC 3161 time stamps: BER reader, signer verification (RSA PKCS#1 and PSS, ECDSA P-256/P-384, Ed25519), chain to the caller's roots at the signature's time (pure, no I/O) | 45 messages made by OpenSSL and the JDK's `jarsigner` verify; 1,886 damaged messages judged by `openssl cms -verify` and replayed, each region of a message pinned as exactly OpenSSL's verdict, stricter, or deliberately more lenient; 2 fuzz targets; not Authenticode yet (B-70 phase 2, B-80) |

Checked against real public servers from a normal network (B-97 in `BACKLOG.md`): 43 of 49 live hosts, and 52 real certificate chains replayed offline. The six that failed were servers that spoke only TLS 1.2 to the client of then, `registry.npmjs.org` among them. With TLS 1.2 (B-36, see "TLS versions" below) the same network gave 42 of 42 hosts that must connect, npm and `www.globalsign.com` over TLS 1.2; the badssl.com test servers are refused, by design, because they do not do the extended master secret. A second run on 2026-10-08 (B-102), with the test sites of B-100: 48 of 48 hosts that must connect, every refusal for the right reason (15 certificates, 6 servers offering only TLS 1.0, 1.1, CBC, RSA key exchange, finite-field DH or no encryption, 21 without the extended master secret), the revoked test sites refused as revoked (4 of 4 with the built-in Mozilla roots; 2 of 4 with macOS's bundle, which lacks the roots of the other two), and 74 real chains replayed offline.
Test run at last check: 1,564 unit (including the mutation fuzzers; 24 more are ignored by default: 20 timing tests, two long random runs, a live QPACK peer and a replay of fuzz inputs; 336 of them also run without the `net` feature), 2 Go-vector, 1 CMS-vector, 2 inflate-vector (1,295 cases), 6 real-chain, 6 real-revocation, 2 Wycheproof (894 vectors), 4 built-in-roots (`mozilla-roots`), 15 real Sigstore, 5 synthetic Sigstore, 3 real Rekor, 3 synthetic TUF (58 repositories judged by python-tuf), 52 OpenSSL interop (12 of them TLS 1.2, 2 with a live OCSP responder, 1 of session resumption), 17 HTTP/2 client against Go's server, 22 HTTP/3 client against aioquic (they skip without `python3` and aioquic), 1 real-root, 1 native-store (B-101), 16 doc tests (17 with `mozilla-roots`, 21 with `server` as well), no warnings; `tools/server_interop.sh` (67 checks), `tools/h2_interop.sh` (41, and 43 with h2spec: 146 of 146, and 147 of 147 strict), `tools/acme_interop.sh` (24, against Pebble), `tools/proxy_interop.sh` (21, with real package managers and registries) and `tools/tlsfuzzer.sh` (41 runs of 40 scripts) pass.

## Security warning

This is hand-written, unaudited cryptography. Nothing has had an independent side-channel or code review. Do not use
it to protect sensitive data until the hardening items in the backlog are done. Revocation is checked only with the
evidence the server staples and the CRLs you supply or let the library fetch, and by default a missing answer is
ignored (soft-fail); see Revocation below. To report a vulnerability, see `SECURITY.md`.

`SECURITY_REVIEW.md` is the brief for an independent reviewer: what the verification code claims, the threat model, the evidence so far, what has not been done, and where to attack first.

## Async

The standard library has no asynchronous sockets, DNS or timers, so there is no event loop in this crate. Two layers
give async code what it needs without one, and both work with any executor (they use only `std::task::Waker`):

* **Thread-backed, no setup.** `Client::get_async`, `head_async`, `post_async` and `RequestBuilder::send_async` run the
  ordinary blocking request (redirects, proxy tunnelling, every timeout) on a small worker pool (`asyncio::Pool`,
  16 threads by default, `Client::pool` to choose another) and return a future. Dropping the future abandons the
  request, and one that has not started is never sent.
* **True async over your own transport.** The TLS client is a sans-IO state machine, `tls::ClientConnection` (bytes in,
  bytes out, no I/O inside), which the blocking `TlsStream` and the async `asyncio::AsyncTlsStream` both drive; the
  HTTP response parser is sans-IO too. `asyncio::AsyncRead` and `AsyncWrite` have the shape of the `futures-io`
  traits. `Client::into_async()` gives an `AsyncClient` with the same requests, redirects, proxy CONNECT, limits and
  TLS settings; it opens connections through the `Connect` trait. The default, `ThreadConnector`, needs nothing (it
  runs resolution, connecting and each socket read and write on the pool, one thread hand-off per operation); to use a
  runtime's own sockets, implement `Connect` for a small adapter. For tokio, forward each `poll_*` to the stream's
  own method (`tokio::io::ReadBuf` wraps the `&mut [u8]`).

`AsyncClient` speaks HTTP/1.1 only; HTTP/2 (below) is for the blocking `Client`, and for the `*_async` methods that run it on the pool (B-72 part 2 in `BACKLOG.md`).

`asyncio::block_on` is a minimal executor for tests, examples and small programs (`examples/async_get.rs`).
`Client::total_timeout` limits a whole request, redirects included. There is no timer in the standard library, so the crate
has its own: `asyncio::sleep`, `asyncio::timeout` and `asyncio::Timed` (read and write timeouts and a deadline on any
`AsyncRead` + `AsyncWrite` stream) run on one thread that keeps a heap of deadlines and wakes each timer's task, for any
executor (B-61). `AsyncClient` uses them to keep `connect_timeout`, `timeout` and `total_timeout` whatever its connector:
it times the connector's `connect` and puts a `Timed` over the stream it gets (`ThreadConnector` keeps them on its sockets
itself, and says so with `Connect::enforces_timeouts`, so its streams are not timed twice).
`AsyncTlsStream` cannot send close_notify when dropped (sending needs the executor): call `close()`.

## Connections, streaming and HTTP/2

Connections are kept alive and reused: the clones of a `Client` share a pool keyed by scheme, host, port and proxy, a connection goes
back to it when its response was read to the end, and a request that fails on a connection that had gone stale is sent again once if
its method may be repeated (`keep_alive`, `pool_idle_timeout` and `pool_max_idle_per_host` tune it; `keep_alive(false)` turns it off).
`send_stream` and `get_stream` return a `ResponseStream` as soon as the headers are in, a `Read` over the body, so a download can be
hashed and unpacked on the way without holding it in memory (`max_body_bytes` and the timeouts still apply).

A new connection (B-48, `http::connect`) looks the host name up on a thread of its own, so `connect_timeout` and `total_timeout`
bound a slow resolver too, and keeps the answer for 30 seconds (`dns_cache`; callers asking for one name at once share one
lookup). Its addresses are raced as RFC 8305 ("Happy Eyeballs") says: families interleaved, the address that last connected
first, the next address tried as well after 250 ms (`connection_attempt_delay`) or as soon as one fails, and the first connection
made wins. An address family that is routed nowhere costs a quarter of a second rather than the whole connect timeout per address.
`max_connections_per_host(n)` (off by default) keeps at most `n` connections open to a host: a request that needs another closes an
idle one it cannot use, or waits for one to close or come back to the pool and uses it, up to its deadline or the client's timeout.
An HTTP/2 connection takes one slot for all its requests.

**Scheduling requests** (B-74, `http::schedule`). A `Scheduler` (`max_in_flight`, `max_in_flight_per_host`, `byte_budget`) given to
clients with `Client::scheduler`, blocking or async, lets their requests go in turn: host by host (a long queue for one registry
does not hold up another), in order within a host. A request is in flight until its response has been read to its end or dropped;
it reserves the bytes it says it expects (`expected_bytes`), then the length its response gives. A `Batch` (`with_deadline`,
`with_timeout`) groups requests (`RequestBuilder::batch`, or `Client::in_batch` for all of a client's) under one deadline, and
`Batch::cancel` stops them all, waiting or under way, with `Error::Cancelled`.

```rust
use std::time::Duration;
use pratique::http::{Batch, Scheduler};
let sched = Scheduler::new().max_in_flight(16).max_in_flight_per_host(4).byte_budget(512 << 20);
let client = pratique::Client::new()?.scheduler(&sched);         // clones, and other clients given it, share it
let batch = Batch::with_timeout(Duration::from_secs(120));        // one scan: two minutes at most
let scan = client.in_batch(&batch);
let zip = scan.request("GET", "https://proxy.golang.org/golang.org/x/mod/@v/v0.20.0.zip").expected_bytes(4 << 20).send()?;
batch.cancel();                                                   // from any thread: what is left fails with Error::Cancelled
```

HTTP/2 is off by default. `Client::http2(true)` offers `h2` and `http/1.1` in the TLS handshake; a server that picks `h2` gets **one
connection per origin that all requests share** (up to the number of concurrent streams it allows, then another), and anything else
is spoken to in HTTP/1.1 as before:

```rust
let client = pratique::Client::new()?.http2(true);
let resp = client.get("https://example.com/")?;
println!("{} {}", resp.version, resp.status);        // "HTTP/2 200"
```

Requests and responses look the same as over HTTP/1.1, except that the reason phrase is empty, header names are lower case and
trailers are dropped. The windows are 8 MiB per stream and 32 MiB per connection: a body read in pieces (`send_stream`) holds no more than
that unread, and a body read whole (`send`) is kept as it arrives, up to `max_body_bytes`, and handed over without another copy. Server
push is refused and priorities are ignored. A connection has two threads (a reader and a writer) for as long as it is open (a request is read by its own caller when nobody else is reading, whether it is answered whole or read in pieces, as an HTTP/1.1 request is, and the reader thread steps aside for it: B-86), and it is
decrypted on one thread, about 0.9 GB/s here, so one HTTP/2 connection costs about what one HTTP/1.1 connection costs for a big download, and
eight big downloads at once take one core's time over HTTP/2 where eight HTTP/1.1 connections spread over several. The layers
are sans-IO (`src/http/h2/`: HPACK, frames, the connection state machine), so an async driver can be built on them (B-72 part 2).

Speed, against Go's `net/http` client on the same server and the same two cores (`bash tools/bench_h2.sh`; medians; the server is Go's, pinned to
one core, and its HTTP/2 costs it more CPU than its HTTP/1.1 does, which is most of why the HTTP/2 wall times below are above the HTTP/1.1 ones):

| CPU time in ms (wall time in ms) | ours HTTP/1.1 | Go HTTP/1.1 | ours HTTP/2 | Go HTTP/2 |
|---|---|---|---|---|
| one 100 MB download, read whole | 150 (176) | 165 (176) | 160 (185) | 253 (272) |
| one 100 MB download, read in pieces of 64 KiB | 90 (159) | 127 (157) | 120 (232) | 298 (346) |
| 8 x 47 MB at once | 680 (622) | 782 (668) | 660 (794) | 1058 (1175) |
| 2000 small requests, one thread | 110 (270) | 361 (445) | 130 (402) | 401 (538) |
| 4000 small requests, 8 threads | 150 (210) | 260 (275) | 210 (368) | 410 (473) |
| 128 requests at once, 20 ms round trip, nothing connected yet | 180 (247) | 197 (263) | 40 (69) | 195 (269) |
| one 47 MB download, 20 ms round trip | 80 (184) | 102 (187) | 80 (234) | 151 (355) |

(The numbers are from one run on one machine, 2026-10-08, 7 rounds; rows compare with each other, not with the numbers of other machines or earlier runs: this VM was slower that day than in the runs that the BACKLOG quotes.)

Where HTTP/2 helps most is many requests to an origin that has no connection yet: one handshake and one connection instead of one each.
For one big stream or a run of small requests on a fast local path HTTP/1.1 is as fast or faster, on this server. A run of small requests costs HTTP/2 about a sixth more CPU than HTTP/1.1 here (the two HTTP/2 servers tried, Go's and Node's, send the head and the body of a response in two TCP segments, so whoever reads has one wake-up more per response: B-86), a download read in pieces about a third more (it is copied once on its way to the caller, as over HTTP/1.1: B-87), and eight threads on one connection about two fifths more than eight connections (the callers read for each other and the reader and writer threads are seldom woken, B-89, but a caller whose response another read still sleeps once for it, where an HTTP/1.1 caller waits only on its own socket).
`cargo run --release --example fetch -- --http2 --parallel 8 URL` shows the sharing and the time.

Against other Rust libraries (`bench/compare`, BENCHMARKS.md, after B-104; the M5 figures from the Linux VM on it): on Apple
silicon its AES-GCM is the fastest of pratique, ring, aws-lc-rs and RustCrypto from 16 KiB records (11.7 GB/s against 9.7
to 9.9) and level at 1 KiB, and so is its ChaCha20-Poly1305 at 16 KiB (2.69 against 2.38 GB/s); its TLS client downloads on
about a fifth less CPU per byte than rustls's. On x86-64 ring and aws-lc-rs are 1.1 times faster at AES-GCM on 16 KiB records
(their kernels are assembly), and 1.1 and 1.2 times slower at 1 KiB and 1.6 and 1.8 times at 100 B; ChaCha20-Poly1305 there is 1.3
times slower than theirs. A full handshake costs 1.3 to 1.4 times rustls's client CPU (0.14 against 0.10 to 0.11 ms on the
M5, 0.46 to 0.48 against 0.33 to 0.37 on x86-64); X25519 is 1.2 times ring on the M5 and now quicker than ring on x86-64 (62
against 73 to 74 us); Ed25519 and RSA verification are level with aws-lc-rs on the M5 and 1.2 to 1.4 times ring; ECDSA P-256
is 1.2 to 1.3 times both. What is left to close, in order: B-106.

**Two threads on one TLS connection.** `TlsStream::split()` gives a `TlsReadHalf` and a `TlsWriteHalf` that two threads can use at
once (B-39), for protocols where both sides send at the same time (an echo larger than the socket buffers stops a single
blocking stream with both sides waiting to write). The halves share the TLS state under a lock that is never held across
I/O; reading never waits for a write that is blocked, records go out in the order they were made, and the answers the
reading half owes the server (the client's Finished, a KeyUpdate, TLS 1.2's no_renegotiation warning) go out with the
writing half's records or by themselves when nobody is writing. Closing (or dropping) the writing half sends close_notify,
and the reading half reads on. The transport is split with the `Duplex` trait (`TcpStream`, `UnixStream`; a second
handle to the same socket).

**Session resumption** (TLS 1.3, B-35). The tickets a server sends are kept per server name in `ClientConfig::resumption`
(on by default; the clones of a configuration, and so the connections of one client, share them), and the next connection
to that server offers one, which spares the certificate chain, its check and the server's signature: on loopback against
OpenSSL a handshake took 0.55 ms resumed against 1.0 ms (P-256 server key) or 1.6 ms (RSA-2048) in full. The key exchange
is fresh every time (`psk_dhe_ke` only), a ticket is used once, and a session is used for at most an hour after the
certificate check it rests on (`Resumption::max_age`; resuming from a resumed connection does not extend it), and only by
a connection with the same trust store, verification switch and revocation mode. A connection whose revocation check was
deferred keeps no tickets. There is no 0-RTT, and no resumption in TLS 1.2 or over QUIC. `TlsStream::is_resumed` says
whether a handshake resumed; `peer_certificates` gives the chain of the full handshake it descends from.
`ClientConfig::with_resumption(Resumption::off())` turns it off.


## TLS versions

TLS 1.3 is spoken whenever the server can. The ClientHello offers TLS 1.2 too, and a server that speaks nothing newer gets
TLS 1.2, under rules that leave nothing to that version's known weaknesses (`registry.npmjs.org` answered only TLS 1.2 from a home network
on 2026-10-07; it is what B-36 was for):

* **Downgrade check** (RFC 8446 section 4.1.3). A TLS 1.3 server that answers with 1.2 ends its random with `DOWNGRD` and 1 or 0,
  which it does only when something on the way took 1.3 out of the ClientHello: the handshake ends with `illegal_parameter`.
* **ECDHE with AEAD suites only**: `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256`, `..._AES_256_GCM_SHA384` and
  `..._CHACHA20_POLY1305_SHA256`, over X25519, P-256 or P-384. No RSA key exchange, no CBC, no static DH, no RC4, 3DES, NULL or export suite.
* **The extended master secret is required** (RFC 7627): a server that does not agree to it is refused.
* **Off**: renegotiation (`renegotiation_info` is sent empty and must come back empty; a HelloRequest is answered with a
  `no_renegotiation` warning and nothing more), compression, session resumption and tickets, and SHA-1 or MD5 in the
  ServerKeyExchange signature (the schemes offered are the TLS 1.3 ones and RSA PKCS#1 v1.5 with SHA-256, -384 or -512) and in
  certificates.
* **The same certificate checks as TLS 1.3**: chain, host name, purpose, validity and revocation through the same code (the OCSP
  staple comes in 1.2's CertificateStatus message), and the certificate's key must be the kind the suite says signs.
* A TLS 1.2 connection cannot change its keys: one that has sent as many records as a key may protect (2^24 with AES-GCM, about
  270 GB) fails rather than going on, and the next request opens another. HTTP/3 and QUIC are TLS 1.3 by definition.

The oldest version is set per client and per request, and every response says which one it came over:

```rust
use pratique::tls::TlsVersion;
let client = pratique::Client::new()?;                         // TLS 1.3, or 1.2 with a server that speaks nothing newer
let r = client.get("https://registry.npmjs.org/left-pad")?;
println!("{:?}", r.tls_version);                               // Some(Tls12) or Some(Tls13); None over plain http
let r = client.request("GET", "https://sum.golang.org/latest").min_tls_version(TlsVersion::Tls13).send()?;  // 1.3 or nothing
let strict = pratique::Client::new()?.min_tls_version(TlsVersion::Tls13);   // every request 1.3 or nothing
```

A request can only make the client's minimum stricter, never looser: `min_tls_version(TlsVersion::Tls12)` on a request of a
client that requires 1.3 changes nothing. The minimum holds for every redirect a request follows, and the pools (HTTP/1.1
and HTTP/2) are keyed by it, so a request that requires 1.3 never gets a connection that was opened for one that allows 1.2,
even one that turned out to be 1.3. `ResponseStream` and the async client's responses carry `tls_version` too, and a
`TlsStream` says `protocol_version()` and `cipher_suite_name()` (`cipher_suite()` is the TLS 1.3 suite, `cipher_suite12()` the
TLS 1.2 one). `ClientConfig::with_min_version` sets the same thing for a bare `TlsStream`. The default is TLS 1.2, so that a
supply-chain tool reaches every registry; a caller that would rather fail than speak 1.2 sets `TlsVersion::Tls13` once.

## Compressed bodies, cookies and `Expect: 100-continue`

All three are opt-in, so a client that asks for none of them sends and receives exactly what it did before.

**Decompression.** `Client::decompress(true)` (or `RequestBuilder::decompress`) makes requests ask for `gzip, deflate` and decodes a body
that comes as a single `gzip`, `x-gzip` or `deflate`, whether it is read whole, streamed (`send_stream`) or read by the async client.
The decoded response has no `Content-Encoding` and no `Content-Length` (they described the wire) and `uncompressed` is true. Compressed
data from a stranger can be a bomb (DEFLATE reaches 1,032 to 1), so the decoder, the crate's own `inflate`, is held to
`max_decoded_bytes` (by default the same number as `max_body_bytes`, which limits the compressed bytes) and, if you set one,
`max_decode_ratio`; a body that would pass a limit is an error, `Error::Decode`, never a body cut short. What is not decoded comes
as it came: another coding (`br`, `zstd`), a list of codings (each layer would be a bomb of its own), a response to `HEAD`, a 206 (a
range of the *encoded* body). The compressed stream must end where the body does, and an empty body is an empty body.

```rust
let client = pratique::Client::new()?.decompress(true).max_decoded_bytes(256 << 20);
let resp = client.get("https://registry.example/index.json")?;   // decoded, if it came compressed
```

`pratique::inflate` is usable on its own, with no HTTP, for a `.tgz` or anything else: a push-style streaming decoder over slices
(`Inflater::inflate(input, output)`) or `decode_all` for a buffer, with `Limits` on the output and the ratio. It is in the pure part.

**Cookies.** `Client::cookie_jar(CookieJar::new())` keeps the cookies that responses set (redirects included) and sends them back.
Every cookie goes back to the host that set it and to no other: a `Domain` attribute is honoured only as far as it names that host
or a domain the host is in, and the cookie stays the host's. There is no public-suffix list in this crate to tell `example.com` from
`co.uk`, and a cookie set for a whole domain is how one host plants a session on another. `Secure`, `Path`, `Expires`, `Max-Age` and the
`__Secure-` and `__Host-` prefixes work as RFC 6265bis says; a request with its own `Cookie` header sends that and nothing from the jar.

**`Expect: 100-continue`.** `RequestBuilder::expect_continue()` sends the head first and the body only when the server says to go on
(or after `expect_continue_timeout`, one second by default, if it says nothing). A server that answers at once (a 401, a redirect, a 413)
never gets the body, which is the point for a large upload; after a 417 the request goes again without the expectation. HTTP/1.1 only,
in the blocking and the async client alike: HTTP/2 and HTTP/3 send the body with the head.

## HTTP/3 (opt-in)

HTTP/3 is the caller's option and is off by default. Without it the order is what it was: HTTP/2 for a server that picks `h2` (if
`http2(true)` is on), else HTTP/1.1. `Client::http3(true)` makes the client use QUIC (over UDP) for an origin that has said it offers it, in
an `Alt-Svc` field of an ordinary response (`alt-svc: h3=":443"; ma=86400`: RFC 7838; the first alternative for `h3` counts, `clear` and `ma=0`
take it back, the lifetime is at most 30 days and 24 hours when there is none). The first request to an origin goes over TCP, as it would without
the option, and learns that; the ones after it go over QUIC, on **one connection per origin that all requests share** (another when the server's limit
on concurrent streams is reached):

```rust
let client = pratique::Client::new()?.http2(true).http3(true);
let first = client.get("https://example.com/")?;     // TCP: HTTP/2 or HTTP/1.1
let next = client.get("https://example.com/")?;      // QUIC, if the origin offered it
println!("{} then {}", first.version, next.version); // "HTTP/2 then HTTP/3"
```

`http3_eager(true)` (which turns the option on) tries QUIC for an origin nobody has spoken of, at the host and port of the request: for a client
that talks to servers it knows speak HTTP/3. The server is authenticated as the origin's name, as for TLS over TCP, even when the alternative is
at another host. A request through a proxy is never sent over QUIC (the proxies tunnel TCP), and neither is one while `keep_alive` is off.

QUIC is not always possible (a network that drops UDP; a firewall that lets TCP through only), and the fallback is built so that it costs little:
the handshake of an alternative that was only advertised is given 3 seconds at most (or `connect_timeout`, if that is shorter), an origin that
could not be reached is left to TCP for five minutes and twice as long after each failure that follows (to a day), the requests that come while
the first one dials go over TCP at once, a request that is refused or that a lost connection cut off in a way that allows another try is sent again
(a request that may be repeated that was lost on a connection that had just been made goes over TCP, and the origin is left to TCP), and a
`clear` from the origin closes the connection once its requests are done. The response is as over HTTP/2: no reason phrase, lower-case header names,
trailers dropped; `Response::version` is `HttpVersion::Http3`. A connection has two threads (a reader and a timer) while it is open and is closed
when it has been idle for `pool_idle_timeout`, when the server says to go away, when the network ends it and when the last clone of the client is dropped.

Not done: the async client (`AsyncClient`) does not speak HTTP/3 (the `*_async` methods of `Client` do), and there is no 0-RTT, no connection migration,
no stream priorities, no path-MTU discovery (the datagrams it sends are 1200 bytes, the least a QUIC path has to carry), and no UDP batching: a download over a clean fast
link is slower over this than over HTTP/2 until those and CUBIC are in (B-91). `examples/fetch.rs --http3` (or `--alt-svc`) asks for it from the command line.


## Host rules

A client can be limited to the hosts a caller (a module, a plug-in) is allowed to talk to. `Client::allowed_hosts(HostRules::new(["api.example.com", "*.cdn.example.net"])?)`
is applied to the URL of the request and to **every redirect that is followed**, before anything is sent to that host: a request or a redirect to
a host the rule does not name is an `Error::Refused` (see below) whose reason begins `host not allowed`, and nothing connects. An entry is a host, a host with a
port (`api.example.com:8443`, `[::1]:8443`), an IPv4 or IPv6 address, or a wildcard `*.example.com`, which allows what is under the domain and **not the
domain itself** (it needs an entry of its own); a wildcard needs a domain of two labels at least (`*.com` is refused), and an entry that is not
one of these is an error when the rule is made, not a rule that quietly does something else. The host compared is the one the client will
connect to, as the URL gives it (the part after the last `@`, lower case, ASCII: an internationalized name is matched in its `xn--` form, and
an address written as `2130706433` does not match the entry for the address it means).

The rule is loose unless it is told otherwise, and a caller that wants it tight says so with two switches and a set of limits on the URL:

| | default | switch |
|---|---|---|
| `*.example.com` matches | one label or more (`a.example.com`, `a.b.example.com`) | `one_label_wildcards(true)`: exactly one valid label (`[a-z0-9]`, inner `-`, at most 63 bytes), so `a.example.com` and not `a.b.example.com`, `evilexample.com` or an `_` name |
| a host with no port in its entry matches | any port | `default_port_only(true)`: the scheme's default port only (`:443` counts as the default); a wildcard never matches an explicit port, and a host on another port needs an entry of its own, `host:port` |
| the URL | anything the parser takes | `Client::url_limits(UrlLimits::strict())`: https only, no `user:password@`, printable ASCII only (no space or control character, nothing over `~`), at most 2,048 bytes; each can be asked for alone (`https_only`, `refuse_credentials`, `printable_ascii_only`, `max_length`) and the reason of a refusal begins `URL not allowed` |

The rule of a module that reaches the Marketplace's hosts (`<publisher>.gallerycdn.vsassets.io`, `<publisher>.gallery.vsassets.io`, and no other
host) is therefore
`client.clone().allowed_hosts(HostRules::new(["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io", "*.gallery.vsassets.io"])?.one_label_wildcards(true).default_port_only(true)).url_limits(UrlLimits::strict())`,
and it holds on the first URL and on every hop. The text of a URL is judged as it came: the caller's string, and for a redirect the `Location` value as
well as the URL it resolves to.

**A refusal is an error of its own.** A request or a redirect that the client's rules do not allow is `Error::Refused(Refused { hop, by, reason })`, not an
`Error::Io`, `Tls` or `Http`, so a caller can tell "the module was not allowed to go there" from "the network failed" or "the server was bad": `hop` is 0 for
the request itself and 1, 2, ... for the redirect it was following (`is_redirect()` says which, so a report can say "redirect blocked"), and `by` is
`RefusedBy::HostRule`, `UrlLimit`, `Scheme` (plain http without `allow_insecure_http`, or a redirect from https to http) or `Hook` (the enum is `#[non_exhaustive]`).
Nothing was sent to the host it names. Its `Display` begins `request refused:` or `redirect N refused:`, and the reason names the host and never the path, the
query, a credential or a header value.

**Credentials for each hop.** A header set on a request travels with its redirects (only `Authorization`, `Cookie` and `Proxy-Authorization` are dropped
at another origin), so a token should not be set that way. `Client::hop_headers(|hop| ...)` is called for the request itself and for **every redirect that is
followed**, after the host rule and the limits on a URL have allowed that URL and before anything is sent there, with the URL, the method the hop will have
(a 303 makes a GET), the hop's number, the URL that redirected to it and whether that crossed an origin; the headers it returns go with that hop and with no
other, so each host gets its own credentials (`GITHUB_TOKEN` to `api.github.com`, a private registry's token to the registry, nothing to a CDN that a redirect
names) and a token never follows a redirect to another host. An `Err` from the hook refuses the hop: nothing is sent there, and the request fails with `Error::Refused` (`by: Hook`, with the hop's number and the hook's message as the reason). A header it gives replaces the caller's of the same name, a bad name or value (or `Host`, `Connection`, `Content-Length`) is an error that never says the
value, and it is called once for a hop though the request is sent again on another connection. The async client and the clones apply their own hook. Its headers are never kept: there is no cache of
responses, a connection is for one origin only (the pools of HTTP/1.1, HTTP/2 and HTTP/3 are keyed by scheme, host, port and proxy, so HTTP/2 connections are never
coalesced across hosts), and the names it gives are marked never-indexed in HPACK and QPACK, as `Authorization` and `Cookie` are. A header that the *caller* sets other
than `Authorization`, `Cookie` and `Proxy-Authorization` (a `PRIVATE-TOKEN`, say) still follows a redirect to another host, so a credential goes through the hook.
A host whose last label is a number (`1`, `0x7f`) is an address to a resolver, not a name, so a wildcard never matches it.

Clones of a client share their connections, so `client.clone().allowed_hosts(rules)` is a client for one caller, and the limits of `timeout`,
`total_timeout`, `max_redirects`, `max_body_bytes` and `url_limits` are set on the clone the same way; the async client and the `*_async` methods apply the
rule too, and with HTTP/3 on, an `Alt-Svc` alternative is used only if the rule allows its host and port (the origin's own host when it names none). A POST
with a JSON body is `request("POST", url).header("Accept", "application/json").header("Content-Type", "application/json").body(json)`:
the caller's `Accept` replaces the default `*/*`, a 307 or 308 repeats the method and the body, a 303 (or a 302 of a POST) makes a GET with no body, and
credentials are dropped when a redirect changes the origin.

## Revocation

`ClientConfig` carries a revocation policy (`pratique::revocation`). The default, **soft-fail**, asks the server for
a stapled OCSP response (RFC 6066 `status_request`, carried in the Certificate message in TLS 1.3), checks the staple
and any CRLs you give it, and fails the handshake (alert `certificate_revoked`) if any of them shows a certificate on
the path to be revoked. Evidence that is missing, damaged, out of date or signed by the wrong key is ignored, except
for a leaf marked *must-staple* (RFC 7633), whose staple must be valid. **Hard-fail** also requires positive proof for
the leaf (a "good" staple or a covering CRL that does not list it) and refuses the connection (alert
`bad_certificate_status_response`) without it. **Off** does not check and does not ask for a staple.

When the staple and the CRLs you supply do not settle a certificate, two kinds of **source** can be asked (B-63): an
`OcspSource` asks the OCSP responder that the certificate's Authority Information Access names (`http::HttpOcspSource`
POSTs a request, the same bytes as `openssl ocsp -no_nonce`, and keeps the answer until its `nextUpdate`, for up to 1024
certificates), and then a `CrlSource` fetches the list at its CRL distribution point (`http::HttpCrlSource`, which keeps up
to 64 lists and 64 MiB, and fetches the next list in the background when a tenth of a list's window, or an hour, is left).
They are asked about the leaf; `Revocation::whole_chain()` asks them about every certificate below the anchor too, and then
hard-fail wants evidence for each (B-64).

```rust
use pratique::http::{HttpCrlSource, HttpOcspSource};
use pratique::revocation::{Crl, Revocation, RevocationMode};
use std::sync::Arc;

// strict: need proof, from the staple, the certificate's OCSP responder or its CRL (plain http, cached), for the whole chain
let strict = Revocation::hard_fail()
    .with_ocsp_source(Arc::new(HttpOcspSource::new()))
    .with_crl_source(Arc::new(HttpCrlSource::new()))
    .whole_chain();
// or supply a list you already hold
let mine = Revocation::soft_fail().with_crl(Crl::from_pem(&std::fs::read_to_string("issuer.crl.pem")?)?);
let cfg = ClientConfig::new(store).with_revocation(strict);   // or .revocation_mode(RevocationMode::Off)
```

Every response and list is verified (signature by the certificate's issuer or a delegated OCSP signer, validity
window, name and serial, and for CRLs the issuing-distribution-point scope) before it counts, so it does not matter how
it arrived. CRLs the library cannot interpret completely (delta, indirect, per-reason partitions; public CAs do not issue
them) are refused rather than misread, and count as no evidence. The blocking client asks the sources during the
handshake. The async client never lets its executor wait for them: its handshake leaves them for later
(`Revocation::deferred`), and they are asked on its worker pool before the connection is used; a custom driver of
`ClientConnection` can do the same with `take_unchecked()` and `Unchecked::check`. Requests carry no nonce: the public CAs'
responders answer from responses signed in advance (RFC 5019), and what stops an old response is its window.

## Constant-time status

X25519, the P-256/P-384 key exchange (`src/crypto/ecdh.rs`), GHASH, Poly1305, ChaCha20 and AES contain no
secret-dependent branches or table lookups (X25519 key generation looks up a table of multiples of the base point, but reads
every entry of a row at each lookup and keeps the one it needs with masks: `crypto/x25519_base.rs`), and a statistical timing harness (`src/crypto/timing.rs`, dudect style,
with deliberately leaky positive controls) found no timing dependence on keys or data on x86-64 or on an Apple M5 Max
(backlog B-24, B-58), with one exception that is not explained: on an Intel Xeon cloud VM the 32-bit-limb Poly1305 (which
64-bit builds do not use) reads |t| 4 to 12 for an all-zero key against random keys (B-95). Known on the M5 under macOS: the one-pass AES-GCM seal (B-85) takes about 0.1 ns longer per KiB for random plaintext than for all-zero plaintext (under 0.1 percent, measured to +/- 0.01 ns; it was twice that before the kernel stopped reading its ciphertext back, and the 3.5 times slower two-pass seal shows none). The likely cause is the CPU predicting the values loads return, which DIT does not turn off; what it could reveal is whether the plaintext holds long runs of one value, to someone timing many seals on the same machine (B-24). The Linux VM on the same CPU shows none of it. Copying memory shows the same kind of difference there, much larger. The harness earned its keep on the P-256/P-384 code: the first version showed |t| above 100
because LLVM had turned a mask-based conditional subtraction back into a branch on the data; the masks now go
through `black_box` and all eight comparisons read below 3. Verification-only ECDSA (`ecdsa.rs`) handles public
values only and is variable time by design.

AES used to be a byte-indexed S-box table, which is exposed to cache-timing attacks, and the harness saw it on one
x86-64 host (a zero or all-ones key against random keys, |t| 17 to 69). It is now either the CPU's own AES
instructions (AES-NI, or the ARMv8 AES instructions; found at run time and self-tested) or, where there are none, a
bitsliced circuit with no tables (B-20, B-41). Both pass the same harness: |t| stays under 3.5 on the key and data
rows for AES-128 and AES-256 on x86-64. GHASH uses PCLMULQDQ / PMULL, or integer multiplications on spaced-out
operands (`bmul64`) on other CPUs; that fallback assumes the CPU's integer multiplier takes the same time for any
operands, which holds on mainstream desktop, server and phone cores but not on some small embedded ones.
RSA, ECDSA and Ed25519 are verification only and handle public data (the Ed25519 code is variable time by design; the field arithmetic it shares with X25519 is the constant-time code, in `crypto/fe25519.rs`).

## Features

`net` (on by default) is TLS, the HTTP client, sockets, OS randomness, the SIMD kernels and the wiping of secrets: everything
that does I/O or needs `unsafe`. With `default-features = false` you get only the pure part: ASN.1, PEM, X.509 path
validation (the caller passes the trust anchors and the time), OCSP and CRL checking, SHA-1/SHA-2, big numbers, RSA,
ECDSA and Ed25519 verification, signed notes, Merkle proofs, the Go checksum database check, CMS / PKCS#7 signatures with RFC 3161 time stamps, and DEFLATE, zlib and gzip decompression. That build has `#![forbid(unsafe_code)]`, does no I/O, starts no threads, reads no clock or
environment variable, has no dependencies, and compiles for `wasm32-unknown-unknown`.

```toml
pratique = { version = "0.1", default-features = false }   # verification only
```

`server` (off by default, and always built for this crate's own tests) adds a TLS 1.3 server with an HTTP/1.1 and HTTP/2 server on top of it
(`tls::server`, `http::server`, and `cargo run --features server --example serve`; `tls::pki` writes test certificates, and
`http::h2_server` is the scripted HTTP/2 peer the client's tests use). It began so that tests and tools have a real peer to talk to, and
is being made into a server for real services (BACKLOG B-109 to B-114: real certificates, the HTTP server, limits and timeouts, ACME,
then the scanning proxy of B-78); `tools/server_interop.sh` and `tools/h2_interop.sh` check it against OpenSSL, curl, headless Chromium,
Go, python-h2 and h2spec, `tools/tlsfuzzer.sh` runs tlsfuzzer's TLS 1.3 conformance scripts against it, and
`tools/acme_interop.sh` checks it against Pebble. Done so far: signing in constant time with ECDSA P-256 and P-384,
Ed25519 and RSA keys of 2048 to 8192 bits, read from the PEM files CAs and tools write (`pratique::sign::SigningKey`;
`ServerConfig::from_pem(chain, key)`, B-109); any number of certificates, chosen by the name the client asks for and by the signatures
it can verify, replaceable while the server runs (`tls::certs::CertStore`, or a resolver of your own); stateless session tickets
under rotating keys that several servers can share (`tls::tickets::TicketKeys`); client certificates, optional or required, checked
against a trust store (`ClientAuth`); early data skipped up to a limit, and KeyUpdate and empty-record floods refused (B-110); and
the HTTP server (B-111): a `Handler` gets a `Request` whose body is a stream and returns a `Response` whose body is bytes, a reader or
a function that writes it, with trailers, interim responses and upgrades (CONNECT, 101), the same for HTTP/1.1 and HTTP/2; HTTP/1.1
refuses every ambiguous framing that request smuggling depends on, and HTTP/2 holds a client to its windows and to budgets for the
known floods (rapid reset, CONTINUATION, the 2019 advisories, HPACK bombs). `http::server::redirect_to_https` and
`AcmeHttp01` are for a plain listener. And the runtime (B-112): `ServerBuilder` starts a `Server` with listeners, limits on
connections in all and from one address, timeouts that a slow client cannot stretch (the handshake, an idle connection, a request
head from its first byte, a body as a minimum rate, each write), graceful shutdown, an access log, and certificates and OCSP staples
kept fresh while it runs (`reload_certificates`, `refresh_ocsp_staples`). Under load it keeps up with Go's `net/http` on the same
machine (`tools/bench_server.sh`; BENCHMARKS.md). And ACME (B-113, `http::server::acme`): the server gets its certificates
from Let's Encrypt or any other ACME CA and renews them while it runs, when the CA's renewal information (ARI) says to;
challenges TLS-ALPN-01 (on the TLS listener itself, so port 443 is all it needs), HTTP-01 (on the plain listener) and DNS-01
(through your DNS provider, for wildcards); IP addresses, external account binding, certificate profiles; the account and the
certificates kept in a state directory. `tools/acme_interop.sh` has Pebble, Let's Encrypt's test CA, validate each of them.

```rust
use pratique::http::server::acme::{self, Acme, AcmeConfig, AcmeTlsAlpn01};
use pratique::http::server::{redirect_to_https, AcmeHttp01, Request, Response, ServerBuilder};
use pratique::tls::certs::CertStore;
use pratique::tls::server::ServerConfig;
use std::sync::Arc;

let (http01, tls_alpn01) = (AcmeHttp01::new(), AcmeTlsAlpn01::new());
let mut tls = ServerConfig::with_certificates(CertStore::new()).with_alpn(&["h2", "http/1.1"]);
let store = tls.store.clone().expect("a store");
tls.certs = tls_alpn01.wrap(tls.certs.clone());
let acme = Acme::new(AcmeConfig::new(acme::LETS_ENCRYPT, "/var/lib/example/acme")
    .contact("mailto:admin@example.com").agree_to_terms().tls_alpn01(&tls_alpn01).http01(&http01))?;
let server = ServerBuilder::new(|req: Request| Response::text(200, format!("you asked for {}\n", req.path())))
    .tls("[::]:443", Arc::new(tls))
    .plain_with("[::]:80", http01.wrap(redirect_to_https(None)))
    .start()?;
let _renewals = acme::manage(acme, vec![vec!["example.com".into(), "www.example.com".into()]], store, |m| eprintln!("acme: {m}"));
server.wait();
```

(`cargo run --features server --example acme_serve -- names=example.com` is that server, asking Let's Encrypt's staging service
until it is told `directory=production`.) With certificates from files instead, `ServerConfig::from_pem(chain, key)` and
`reload_certificates`.

**It is not for production yet**: it has had no independent review (B-23). tlsfuzzer and testssl.sh have been run against it (B-114).

The same feature carries **the scanning proxy** (B-78, `pratique::proxy`): an HTTP proxy that opens the TLS of the package
registries (PyPI's and npm's hosts by default) so that a scanner sees every request for a package and every file the
registry sends, and can refuse a package, or read a file whole and refuse it, before the package manager has a byte of it;
every other host is tunnelled untouched, or refused. Its certificate authority is made in memory for one run, valid for a
day, and limited by a critical name constraint to the hosts it opens (with every IP address excluded); the leaves are for
the host of the CONNECT alone. Requests inside a tunnel are parsed by the strict HTTP server and made again by the client,
which verifies the real registry as any client would; a host that does not verify, or a body too large to inspect, is a
502, never passed on unread. `Proxy::client_env` gives the variables that point pip, uv, Poetry, npm, Yarn, pnpm, curl,
Python and Go at it and make them trust its CA (`write_trust_files` writes the CA, and a bundle of the machine's roots and
the CA). Behind a gateway that inspects TLS (Zscaler, Netskope), the proxy trusts the company's root wherever the machine
has it (the CA bundle file, the macOS Keychain or the Windows store, the files `SSL_CERT_FILE` and the like name), puts it
in the programs' bundle too, and goes through the proxy its own `HTTPS_PROXY` names.

```rust
use pratique::proxy::{Decision, Exchange, Proxy, Scanner};

struct Policy;
impl Scanner for Policy {
    fn request(&self, ex: &Exchange) -> Decision {
        match ex.package() {
            Some(p) if p.name == "left-pad" => Decision::Block("not here".into()),
            _ => Decision::Allow,
        }
    }
}

let proxy = Proxy::builder(Policy).build()?;
let server = proxy.start("127.0.0.1:0")?;
let files = proxy.write_trust_files(std::path::Path::new("/tmp/scan-proxy"))?;
let env = proxy.client_env(server.local_addrs()[0], &files); // HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, ...
std::process::Command::new("npm").args(["install"]).envs(env).status()?;
```

`cargo run --features server --example scan_proxy -- block=left-pad inspect=1 -- npm install` does that from the command
line. `tools/proxy_interop.sh` runs pip, uv, npm, Yarn, pnpm, curl, Python's urllib and Go through it against the real
registries, and behind a gateway that re-signs TLS (played by a second proxy). It is not to be relied on until the review of B-23 covers it; `PROXY_THREAT_MODEL.md` is its threat model, and
`PROXY_CONFIGURATION.md` says how to run it on each kind of network (an explicit corporate proxy, Zscaler or Netskope, a
system proxy or a PAC file, CI runners, containers) and how to scan a private registry or mirror.

`mozilla-roots` (off by default, pure, works with or without `net`) builds Mozilla's root store for TLS servers into the
crate: `pratique::mozilla_roots::trust_store()`, the certificates NSS (and so Firefox) trusts as CAs for TLS servers, with
the dates after which Mozilla no longer trusts a CA's new certificates (`roots/mozilla.pem`, about 190 KB, made from NSS's
`certdata.txt` by `tools/gen_mozilla_roots.py`, which names the NSS version; like NSS, it is under the Mozilla Public
License 2.0: see `NOTICE`). It is for machines whose own bundle is missing or old (macOS's `/etc/ssl/cert.pem` lacked ISRG
Root X2 in the first field run) and for programs that want the same roots everywhere; the price is that the roots are as
new as the crate's copy (B-31).

```toml
pratique = { version = "0.1", features = ["mozilla-roots"] }
```

The line is drawn so that the pure part could move unchanged into a crate of its own, with the `net` part in a second crate that
depends on it: the pure part never mentions the `net` part, and the `net` part adds nothing to the pure part's types (its error type
wraps the pure one, and the things that touch the operating system are free functions in `sys`, not methods on pure types).
`sh tools/check_features.sh` checks this (no `unsafe`, no I/O, no feature or target `cfg` in the pure files, no mention of
`net` modules; then builds and tests the pure part, natively and for wasm32). Without the feature the library has no
`Client`, `tls`, `http`, `asyncio`, `sys`, `error` or `zeroize` module, and `crypto` has only `sha1`/`sha2`, `bignum`, `rsa`, `ecdsa`, `ed25519` and the field arithmetic `fe25519`.

## Layout

```
Pure part (always built; the whole crate with `default-features = false`):
src/asn1.rs        strict DER reader
src/pem.rs         PEM and Base64
src/ber.rs         BER reader (indefinite lengths, constructed strings) that can rewrite what it read as strict DER
src/x509.rs        certificates, trust store, chain validation for any purpose, hostname checks
src/cms.rs         CMS / PKCS#7 SignedData and RFC 3161 time-stamp token verification
src/revocation.rs  OCSP staple and CRL verification, revocation policy (CrlSource trait)
src/note.rs        signed notes (c2sp.org/signed-note, Go's `note.Open`): the envelope of tree heads
src/tlog.rs        Merkle inclusion and consistency proofs (RFC 9162), tiles, authenticated tile reading
src/sumdb.rs       the Go checksum database check (`Check`, sans-IO), lookup paths, tree head and record parsing
src/json.rs        strict I-JSON reader (duplicate names, bad UTF-8, lone surrogates and non-RFC 8259 numbers are errors; 64-bit integers from decimal strings) and canonical writer
src/trust_root.rs  Sigstore's `trusted_root.json` and npm's key list: logs, Fulcio and time-stamp authorities, keys, validity periods
src/tuf.rs         The Update Framework's client as a pure state machine (root rotation, timestamp, snapshot, targets, delegations), and Sigstore's TUF root
src/ct.rs          Certificate Transparency: embedded SCTs (RFC 6962), the precertificate, verification against a list of logs
src/sigstore.rs    Sigstore bundle verification (v0.1 to v0.3, npm attestations, PyPI's PEP 740): DSSE, Fulcio identity, Rekor entries, time stamps, in-toto subject
src/mozilla_roots.rs  the `mozilla-roots` feature: Mozilla's roots for TLS servers, built in (roots/mozilla.pem)
src/idna.rs        Punycode (RFC 3492), and host names to A-labels and back, without Unicode tables (what needs them is refused)
src/inflate.rs     DEFLATE, zlib and gzip decompression: a streaming decoder over slices with limits on the size and the ratio
src/verify_error.rs  the error type of the pure part
src/util.rs        hex, constant-time compare, byte reader
src/crypto/        SHA-1 (OCSP certificate IDs, and reporting weak CMS signatures), SHA-2, big numbers, RSA, ECDSA and Ed25519 verification, the 2^255-19 field (also used by X25519)

Behind the `net` feature (default):
src/tls/           TLS 1.3 client: messages, cipher suites and record cipher, `ClientConnection` (sans-IO state machine), `TlsStream` (blocking driver); TLS 1.2 (`tls12.rs`: suites, PRF, records, handshake); `split.rs` (a stream's reading and writing halves)
src/http/          URL parsing, sans-IO response parser, HTTP/1.1 framing, Client and AsyncClient (redirects, CONNECT proxy, keep-alive pool, streaming bodies), HttpCrlSource
src/http/h2/       HTTP/2 client layers that do no I/O: Huffman, HPACK, frames, the connection state machine (flow control, streams, GOAWAY)
src/http/h2_transport.rs  the blocking client's HTTP/2 transport: one shared connection per origin, a reader and a writer thread
src/asyncio/       worker pool and futures, AsyncRead/AsyncWrite, AsyncTlsStream, ThreadedStream, timers (sleep, timeout, Timed), block_on
src/quic/         QUIC (RFC 9000, 9001, 9002) client transport for HTTP/3, sans-IO: wire primitives, packet headers, packet and header protection, frames, transport parameters, the TLS handshake in CRYPTO frames, range sets, send and receive buffers, loss recovery, NewReno and pacing, streams and flow control, `Connection`
src/http/h3/       HTTP/3 pieces that do no I/O (B-91): QPACK (static table, encoder and decoder with the dynamic table and blocked streams), the frame reader, the client connection over a `Transport` (`quic::Connection` is one)
src/http/h3_transport.rs  the blocking client's HTTP/3 transport: a UDP socket, a reader and a timer thread per connection, the registry of connections and Alt-Svc alternatives with its backoff
src/http/altsvc.rs  the `Alt-Svc` field (RFC 7838)
src/http/hostrules.rs  `HostRules`: the hosts a client may reach (one-label wildcards, default port only), applied to the request and every redirect
src/http/decode.rs  `Content-Encoding`: what to ask for and decode, and the sans-IO body decoder both clients drive
src/http/cookie.rs  `CookieJar` (RFC 6265 and 6265bis, host-only)
src/tls/server.rs, server_split.rs, pki.rs   the `server` feature: the TLS 1.3 server, its stream split for two threads, test certificates (not for production yet: B-109 to B-114)
src/http/server/   the HTTP server (B-111): the handler API (mod.rs), HTTP/1.1 (h1.rs), HTTP/2 (h2.rs), redirect and ACME HTTP-01 (helpers.rs), the runtime (runtime.rs, B-112), and ACME (acme.rs, B-113)
src/proxy/         the scanning proxy (B-78): the CONNECT and the tunnels (mod.rs), its CA (ca.rs), the relay and the scanner (relay.rs), the variables and trust files (env.rs), package URLs (registry.rs)
src/http/h2_server.rs   the scripted HTTP/2 server the client's tests talk to
src/tls/certs.rs, tickets.rs   a server's certificates and the resolver that picks one (also the client's certificate); stateless session tickets (B-110)
src/sign.rs        private keys (`SigningKey`): PEM and DER in PKCS#8, SEC 1 and PKCS#1, TLS 1.3 and X.509 signatures (B-109)
src/crypto/ecdsa_sign.rs, ed25519_sign.rs, rsa_sign.rs, ct_mod.rs   constant-time signing: ECDSA (RFC 6979, hedged), Ed25519, RSA (CRT, blinded, checked), and the arithmetic modulo group orders and secret primes
src/crypto/        HMAC/HKDF, AEAD ciphers (ChaCha20-Poly1305, AES-GCM, with the SIMD kernels), X25519, ECDH on P-256/P-384, OS randomness (the files `crypto/mod.rs` lists under "behind net")
src/error.rs       the error type of the net side (wraps the pure one)
src/sys.rs         the clock, the CA bundle files and the native store
src/native_roots.rs  the operating system's own store of roots: the macOS Keychain's trust settings, the Windows ROOT and Disallowed stores (FFI)
src/zeroize.rs     wiping secrets (with the SIMD kernels, OS randomness and the few calls into the OS, the only `unsafe`)

examples/       fetch (curl-like; `--http2`, `--http3` (QUIC first, TCP if that fails), `--alt-svc` (QUIC where the origin said it offers it), `--parallel N`, `--max-bytes N`), serve (the HTTP server over TLS 1.3 or plain TCP with pages for tests and tools, needs `--features server`), async_get, probe (negotiation report), sumdb (look a module up in the Go checksum database), cms_verify (check a CMS / PKCS#7 signature file), sigstore_verify (check Sigstore attestations of a file), native_roots (what the OS's own store trusts and leaves out), bench (the primitives) and bench_net (handshakes, requests and transfers on loopback, `--features server`; see BENCHMARKS.md)
tests/          OpenSSL interop tests, the HTTP/2 client against Go's server (h2_client_interop.rs), the HTTP/3 client against aioquic (h3_client_interop.rs), replays of vectors judged by Go (go_vectors.rs) and by OpenSSL (cms_vectors.rs) and fixtures (tests/data)
tools/          bench.sh (runs the benchmarks, compares with and records into bench/results.tsv; see BENCHMARKS.md), generators for test vectors and fixtures (Python, uses the `cryptography` package; the CMS ones also run the `openssl` command line tool and the JDK's `jarsigner`), check_features.sh, go_oracle.sh (runs Go's sumdb packages as an independent judge), server_interop.sh and h2_interop.sh (the server against OpenSSL, curl, headless Chromium, Go, python-h2 and h2spec), bench_server.sh with bench_server.go (the server's load test against Go's `net/http`), h2_oracle_server.go (Go's HTTP/2 server for `tests/h2_client_interop.rs`), bench_h2.sh with bench_client.go and bench_delay_proxy.go (the benchmark against Go's client above), hpack_oracle.* and h2_frame_oracle.py (HPACK and frames against Go, Python and hyperframe), gen_quic_vectors.py (packets made by aioquic), quicgo_oracle/ (frame payloads read by quic-go's parser), quic_interop_server.py (an aioquic HTTP/3 server, with an HTTPS side on TCP that advertises it, for `examples/quic_probe.rs` and `tests/h3_client_interop.rs`) and qpack_interop.py (QPACK against ls-qpack)
fuzz/           coverage-guided fuzzer (std-only, stable Rust) and its 52 targets: `sh fuzz/run_all.sh 3600`
```

## Usage

```rust
let client = pratique::Client::new()?            // trusts the OS CA bundle (or SSL_CERT_FILE)
    .proxy_from_env();                           // optional: HTTPS_PROXY / NO_PROXY
let resp = client.get("https://example.com/")?;
println!("{} {}", resp.status, resp.text());

let resp = client.request("POST", "https://example.com/api")
    .header("Content-Type", "application/json")
    .body(br#"{"hello":"world"}"#.to_vec())
    .send()?;
```

Where the roots come from:

* `Client::new()` reads `SSL_CERT_FILE`, else the system's bundle file (`/etc/ssl/cert.pem` on macOS, the distribution's on
  Linux and the BSDs). On Windows, which has no bundle file, it reads the certificate store instead (see the next point).
* `ClientConfig::with_native_roots()` (or `sys::native_trust_store()`) reads the operating system's own store: on macOS the
  Keychain's trust settings, in the user's, the administrator's and the system's domains, so a root the user or an
  administrator distrusts is left out and one they added for TLS is in; on Windows the current user's `ROOT` store less the
  `Disallowed` store and less the roots whose usage property leaves out TLS servers. Anything the system can say that a trust
  store cannot hold (a root for one host only, a distrust date) leaves the root out rather than in. `cargo run --example
  native_roots -- --compare /etc/ssl/cert.pem` shows what it takes, what it leaves out and why (`pratique::native_roots`).
  Elsewhere there is no such store and it is an error. The macOS code has been compiled for macOS but has not yet run there
  (the next field run on the Mac is its test); the Windows code has run under Wine.
* `sys::trust_store_from_pem_file("cacert.pem")` with `Client::with_tls_config(ClientConfig::new(store))` takes a bundle
  of your choice, and the `mozilla-roots` feature builds Mozilla's roots in: `ClientConfig::new(pratique::mozilla_roots::trust_store())`
  gives the same roots on any system.

Try it: `cargo run --release --example fetch -- -i https://example.com/`

### Verifying a chain for something other than TLS

`TrustStore::verify_chain` is the chain checker without the TLS in it, and it is in the pure part (no clock, no I/O):
the caller picks the purpose, the time to validate at and the anchors, and reads what the certificate says about its holder.
A Sigstore (Fulcio) signing certificate lives for ten minutes, so it is checked at the time of the signature:

```rust
use pratique::asn1::oid_from_string;
use pratique::x509::{Purpose, TrustStore, VerifyOptions};

let mut anchors = TrustStore::empty();                       // the caller's anchors: Fulcio roots, a code-signing root...
anchors.add_pem(&fulcio_root_pem);
let chain = [leaf_der, intermediate_der];                    // leaf first; the rest in any order
let options = VerifyOptions::new(Purpose::CodeSigning, signed_at_unix_seconds);   // not "now"; no host name
let ok = anchors.verify_chain(&chain, &options)?;            // ok.leaf, and ok.path from the leaf to the anchor

let workflow: Vec<&str> = ok.leaf.uris().collect();          // SAN URIs; e-mail names: email_addresses()
let issuer = ok.leaf.extension(&oid_from_string("1.3.6.1.4.1.57264.1.8").unwrap()).and_then(|e| e.der_string());
```

`Purpose` is `ServerAuth`, `ClientAuth`, `CodeSigning`, `EmailProtection`, `TimeStamping`, `OcspSigning`, `Oid(..)` or `Any`.
The leaf and every CA above it must allow the purpose (or have no extendedKeyUsage extension, except that the leaf must name it
unless `allow_missing_leaf_eku` is set); every certificate must be valid at the time; CAs need keyCertSign, pathLen and name
constraints (DNS, e-mail, URI and IP names) are enforced; RSA keys below the store's minimum are refused. A critical extension
this code does not know refuses the chain unless the caller lists it with `with_critical_extension` (for those it interprets
itself). What the certificate says (every SAN entry, every extension with its critical flag) is for the caller to compare;
nothing is matched but the host name, if one is given. Revocation is separate (`revocation`). `verify_server_chain` is the
`VerifyOptions::tls_server` case of the same code.

### Ed25519

`pratique::crypto::ed25519::verify(public_key, message, signature) -> bool` is in the pure part, and Ed25519 keys and
signatures work in certificates, CRLs, OCSP responses and TLS 1.3 (`PublicKey::Ed25519`, `SigAlg::Ed25519`, signature scheme
0x0807; RFC 8410 requires the algorithm parameters to be absent, so a NULL there is refused). Signing is behind `net`: `pratique::sign` (B-109).

Implementations disagree about some Ed25519 signatures, so this one follows a single reference exactly: Go's
`crypto/ed25519`, the one the Go checksum database and `go` itself use. A signature verifies if and only if it is 64
bytes with the top three bits of S clear, S is below the group order L (so `S + L` is refused), the key decodes (a
non-canonical `y` of `p` or more and a zero `x` with the sign bit set are accepted, as Go and `ref10` do), and
`[S]B - [k]A` encodes to exactly the bytes of R, where `k` is the hash reduced modulo L. That is the cofactorless
equation, so a torsion component in R or in the key is rejected unless it cancels, and R is never decoded, so a
non-canonical R never verifies. A key of small order is accepted as a key (with the identity as key and R and S = 0,
every message verifies), exactly as in Go.

The rules are pinned by 1,048 generated vectors, each with Go's verdict (go1.24; `tools/ed25519_vectors.py` regenerates
them; the 14 x 14 combinations of small-order keys and R values, mixed-order keys whose acceptance depends on reducing
`k`, torsion in R, malleable S, bit flips, keys off the curve), 128 known-answer signatures from the original Ed25519
test set (RFC 8032 TEST 1 and TEST 2 among them), and the group arithmetic against an independent Python implementation.
OpenSSL gives the same verdict on every vector. Five deliberate deviations (strict decoding of `y`, rejecting
`x = 0` with the sign bit, a cofactored equation, no canonical-S check, an unreduced `k`) each make the tests fail.

### Transparency logs and the Go checksum database

Three pure modules (they build without `net`, for wasm32 too). `note` reads signed notes (the format of c2sp.org/signed-note, as
Go's `note.Open` does: a text, a blank line, signature lines; a bad signature by a key you gave fails the whole note; signatures by
keys you did not give are kept aside as unverified; Ed25519 keys). `tlog` holds Merkle trees: `verify_inclusion` and
`verify_consistency` (RFC 9162), tiles with the path syntax of Go's checksum database, and tile reading in which **every tile is
authenticated**, the right edge against the signed root and each other tile against its entry in its parent. `sumdb` puts them
together as Go's client does, without any I/O:

```rust
use pratique::sumdb::{self, Check};
use pratique::tlog::TileSet;

let mut check = Check::new(sumdb::verifier());                  // the pinned key of sum.golang.org
// check.add_head(&saved_note)?;                                // the head kept from the last run, if any
check.add_lookup("golang.org/x/mod", "v0.17.0", &lookup_response)?;   // GET /lookup/golang.org/x/mod@v0.17.0
let mut tiles = TileSet::new();
for tile in check.tiles_needed()? {
    // fetch GET /<tile.path()> (a partial tile that is gone is served as the full one: tile.full()), then
    // tiles.insert(tile, data)?;
}
let outcome = check.finish(&tiles)?;                            // nothing is vouched for before this succeeds
// outcome.records[0].lines are the go.sum lines (never empty: a record with no line for the module and
// version is an error); keep outcome.latest_note for next time
```

`cargo run --release --example sumdb -- golang.org/x/mod v0.17.0` does all of it through `Client` (`--state FILE` keeps the
tree head between runs, so a log that later rewrites history is caught as a fork). A log that has shown two histories is
`tlog::Error::Fork`; a tile that does not hash to its parent's entry is `TileDoesNotMatchParent`. Go's own client before x/mod
0.40.0 (Go before 1.25.13, and 1.26 before 1.26.6) did not check some tiles against their parents (CVE-2026-56865), which let a
server swap a leaf tile; this code replays that attack against real tiles and refuses it.

Where Go is lenient this is not (documented in `sumdb`): Base64 must be canonical, record numbers and tree sizes are plain
decimals, lookup paths use only the characters real module paths use, and two signed heads of one size with different roots are a
fork without reading any tile. What the tests rest on: real `sum.golang.org` data captured on 2026-10-05 (`tests/data/sumdb`,
see its README), real 26- and 17-hash proofs made by Go from the real tiles, 1,641 note, tree head and record cases and 430 proof
cases each judged by Go's `sumdb/note` and `sumdb/tlog` (`tools/go_oracle.sh` runs them from the local Go toolchain; nothing of
Go's is in this repository; `sh tools/gen_sumdb_vectors.sh` and `sh tools/gen_tlog_vectors.sh` regenerate them, and
`tests/go_vectors.rs` replays them), a made-up log in two histories for fork tests, and three fuzz targets. Not here: signature
the `h1:` hash of a module's files. (Notes are verified with Ed25519 and, for Rekor's checkpoints, ECDSA P-256.)

### CMS / PKCS#7 signatures and time stamps

`ber` and `cms` are pure too. `ber` reads BER: indefinite lengths, constructed strings and non-minimal lengths, which is what Java
and `openssl smime` write, and re-encodes what it read as strict DER, which is what a signature over signed attributes covers.
`cms` reads SignedData (RFC 5652; the PKCS#7 of RFC 2315 that JAR files and Authenticode still use is the same bytes) and checks
every signer: the certificate is found by issuer and serial number or key identifier, the signed attributes carry the digest of
the content and its type, the signature over them (or over the content, when there are none) verifies with the certificate's key
(RSA PKCS#1 v1.5 and PSS, ECDSA P-256 and P-384, Ed25519), and the certificate chains to *your* roots for the purpose you name
(certificates may be signed with RSA PKCS#1 v1.5, RSA-PSS with the Web PKI's parameters, ECDSA P-256, P-384 or P-521, or Ed25519):

```rust
use pratique::cms::{Options, SignedData};
use pratique::x509::{Purpose, TrustStore};

let sd = SignedData::parse(&bytes)?;                          // BER or DER (strip PEM armor first: `pem::parse`)
let mut roots = TrustStore::empty();
roots.add_pem(&root_pem);
let options = Options::new(&roots, Purpose::CodeSigning, now_unix_seconds);   // the caller's clock: the pure part has none
for signer in sd.verify(Some(&manifest), &options)? {          // `None` when the message carries its own content
    // signer.chain (leaf and path), signer.chain_time, signer.timestamp, signer.weaknesses
}
```

`SignedData::verify_signature` is the arithmetic alone (digest and signature, no trust), for a scanner that wants to report "signed
with this key" before it knows whether anyone trusts it. An RFC 3161 time stamp on a signature (`timeStampToken`, or Microsoft's
attribute for the same thing) is verified against the time-stamp authority's chain, and then *its* time is the time the signer's chain
is validated at, so a code-signing certificate that expired after the signature was made still counts (`Options::timestamps`: ignore,
verify (default), require). The `signingTime` the signer wrote is reported and never believed. SHA-1 is checked like any other
digest and reported as a `Weakness`, but refused unless `Options::allow_sha1` is set, so a SHA-1 signature is never accepted by
accident; MD5, DSA and SHA-3 are refused by name. `cargo run --release --example cms_verify -- --detached META-INF/MANIFEST.SF
--cacert root.pem META-INF/CERT.RSA` prints the signers, chains, time stamps and weaknesses of a file.

Where this is stricter than OpenSSL it says so (`tests/cms_vectors.rs` lists every region of a message and how the two may differ):
version numbers and the signer identifier's issuer must be byte-exact, the content type attribute must be present once and equal
the content's type, `CMSAlgorithmProtection` (if present) must match the algorithms actually used, and anything after the message
but zero padding is refused. Where it is more lenient: the message's list of digest algorithms is ignored (it is only a hint for
one-pass readers, and OpenSSL refuses a message whose list lacks the signer's digest). What the tests rest on: 45 messages made by
OpenSSL (`openssl cms`, `smime`, streamed BER, time-stamp tokens from `openssl ts`) and the JDK's `jarsigner` (the only source of an
Ed25519 CMS signature that OpenSSL 3.0 could not make), 1,886 damaged variants of 18 of them each with OpenSSL's own verdict,
negative tests (wrong purpose, wrong time, rogue time-stamp authority, a time-stamp authority without the time-stamping key usage,
a swapped algorithm, a content type that disagrees), and two fuzz targets (`ber`, `cms`). Not here yet: Authenticode
(`SpcIndirectDataContent`, nested and counter signatures, the PE image digest; B-70 phase 2, which waits for real signed binaries,
B-80), the ESS signing-certificate attribute of a time-stamp token, the rule that a time-stamp authority's only key usage is
time stamping, revocation of the signer, and Apple's code-signature blobs.

### Sigstore attestations

`sigstore` (with `trust_root` for Sigstore's `trusted_root.json` and npm's key list, and `json`, a strict I-JSON reader and
canonical writer) is pure too: you bring bytes, the trust to check them against and the digest of the artifact; nothing reads a
clock, opens a file or fetches anything. What comes back is facts, and whether they are the ones you wanted is your policy.

```rust
use pratique::sigstore::{ArtifactDigest, Bundle, DigestAlgorithm, Signer, Trust};
use pratique::trust_root::{KeyRing, TrustedRoot};

let root = TrustedRoot::parse(&trusted_root_json)?;            // from Sigstore's TUF repository (see below)
let npm_keys = KeyRing::from_tuf_npm_keys(&npm_keys_json, "npm:attestations")?;   // the same, for npm's publish attestations
let trust = Trust::new(&root).with_keys(&npm_keys);
let digest = ArtifactDigest::of(DigestAlgorithm::Sha512, &tarball);   // npm's subject digest; PyPI's is SHA-256
for a in Bundle::parse_npm_attestations(&registry_response)? {        // or Bundle::parse (one bundle), Bundle::parse_pep740
    let v = a.verify(&trust, &digest)?;
    // v.signer: Signer::Certificate(identity) with identity.issuer, .uris, .repository(), .git_ref(),
    //           .source_repository_digest, .build_config_uri, ... (every Fulcio extension), or Signer::Key { id, .. }
    // v.statement: the in-toto statement (predicate_type, subjects, predicate); v.matched_subject
    // v.verified_time, v.times: Unix seconds the logs and time-stamp authorities vouch for, and which did
    // v.entries: every log entry that was authenticated (log index, log, kind, signed entry timestamp, inclusion proof)
}
```

The bundle formats are v0.1, v0.2 and v0.3 (a certificate chain, a single certificate or a key hint; signed entry timestamps,
inclusion proofs or both) and PyPI's PEP 740 provenance, all through one verifier. It checks that the DSSE envelope is an in-toto
statement signed by the key of the certificate (RSA, ECDSA P-256/P-384 or Ed25519) or of the ring; that every Rekor entry is
about *this* envelope (the body holds the same signature, certificate or key and payload hash), is authenticated by the log's
signed entry timestamp or by an inclusion proof to a checkpoint the log signed (ECDSA P-256 as Rekor v1 signs, or Ed25519 as
Rekor v2 does), or both, and that a promise or proof which is present is right even if the other is; that every RFC 3161 time
stamp is over the signature and by a time-stamp authority the root lists; and that the signer's certificate chain verifies to a
Fulcio authority for code signing (or the key's validity holds) **at a time those logs and authorities vouch for**, never now:
an entry's `integratedTime` is believed only when a signed entry timestamp covers it. That is how npm's first registry key,
which expired in January 2025, still verifies the publish attestations it signed in 2022 and 2024. With no such time the answer
is `NoVerifiedTime`, which is what a bundle with a proof and no time stamp gets.

The strictness is on purpose: JSON is read as I-JSON (duplicate names, bad UTF-8 and lone surrogates are errors, numbers follow
RFC 8259, 64-bit integers are decimal strings or exact integers), Base64 must be the canonical padded form, a bundle of a format
that needs a proof or promise and has none is malformed, not weaker, and the label the npm registry puts on an attestation must
be the predicate type of the statement that was signed. A Fulcio certificate must carry a signed certificate timestamp from
one of the trusted root's CT logs (RFC 6962, module `ct`; `Trust::with_sct_threshold` asks for more logs, or none). Not
verified: `messageSignature` bundles (a signature over an artifact's digest, with no statement), Rekor v2 entry types, the envelope hash
Rekor records, consistency between checkpoints, and the identity the caller wants (that is policy). `cargo run --release
--example sigstore_verify -- --root tests/data/sigstore/trusted_root.json --npm-keys tests/data/sigstore/npm-registry-keys.json
--npm tests/data/sigstore/sigstore-4.0.0.attestations.json tests/data/sigstore/sigstore-4.0.0.tgz` prints what the two real
attestations of that release prove. What the tests rest on is in `tests/data/sigstore/README.txt`: six real npm attestations
(three bundle formats, a closed Rekor shard, a key that had expired) and PyPI's real PEP 740 provenance verify; each of their
members and strings, removed or changed in turn, breaks them unless nothing authenticates it; 108 bundles made by
`tools/gen_sigstore_fixtures.py` from a Sigstore of our own reach what real data does not.


### Sigstore's trust through TUF

Sigstore publishes its trusted root and npm's registry keys through a TUF repository (`https://tuf-repo-cdn.sigstore.dev`).
`tuf` is a client for it, written as a pure state machine that follows the specification's client workflow and python-tuf's
`ngclient` step for step (root rotation signed by the old keys and the new, rollback and freeze protection, consistent
snapshots, delegations with path patterns and terminating roles); it never reads the clock and never does I/O itself. With
the `net` feature, `http::tuf_source` fetches for it:

```rust
use pratique::http::tuf_source::sigstore_trust;
use pratique::tuf::{Local, SIGSTORE_ROOT};

// the first time: the TUF root built into the crate; afterwards, the `tuf_root`, `timestamp` and `snapshot` kept from the last run
let t = sigstore_trust(&client, SIGSTORE_ROOT, Local::default(), now_unix_seconds)?;
let root = TrustedRoot::parse(&t.trusted_root)?;
let npm_keys = KeyRing::from_tuf_npm_keys(&t.npm_keys, "npm:attestations")?;
```

`cargo run --release --example tuf_refresh -- --state DIR` does that and prints what it verified. The client is checked against
58 repositories made with python-tuf, each judged as python-tuf's own client judged it (one difference on purpose: a threshold
counts distinct keys, not key ids), against every bit of the files of good ones changed in turn, and by a fuzz target. Sigstore's
real repository could not be reached from where this was written; `tools/mac_field_check.sh tuf` captures it for replay
(`tests/tuf_sigstore.rs`, ignored until there is a capture).

## Portability

Pure `std`, no build script, no external crates. All integer conversions are explicit
little/big-endian, so the code does not depend on the host byte order.

Speed-critical code has per-architecture backends with a portable fallback. What every CPU of a target has (SSE2, NEON)
and Poly1305 are chosen at compile time; what is an optional extension of the CPU (AVX2, AVX-512, the AES instructions)
is chosen at run time:

| Target | ChaCha20 keystream | Poly1305 | AES-GCM |
|--------|--------------------|----------|---------|
| x86-64 (Intel Macs, Windows, Linux) | SSE2, four blocks per step; AVX2, eight, if the CPU has it; AVX-512, sixteen, on Intel since Ice Lake and AMD since Zen 4 | radix 2^64 (two 64-bit limbs); four blocks at a time in AVX2's lanes for 2 KiB and more, if the CPU has it (B-104) | AES-NI + PCLMULQDQ if the CPU has them |
| aarch64 (Apple Silicon, ARM servers, Windows on ARM) | NEON, eight blocks per step (four for the end of a message), with Poly1305 run between its rounds | radix 2^64 | ARMv8 AES + PMULL if the CPU has them |
| anything else, including 32-bit targets | portable one-block loop | radix 2^64 on 64-bit pointers, 5 x 26-bit limbs on 32-bit | bitsliced AES + `bmul64` GHASH |

On an x86-64 VM (Cascade Lake) B-57 took ChaCha20-Poly1305 from about 0.62 to 1.1 GB/s (`examples/bench.rs`, 1 MiB
messages; 0.64 to 1.2 GB/s on 16 KiB records): the keystream from 1.1 to 2.3 GB/s with AVX2 (4.6 with AVX-512, which
that CPU has but is not given, for the clock it costs there) and Poly1305 from 1.55 to 2.6 GB/s. SHA-256 and SHA-512 use
the CPU's instructions where it has them (ARMv8's SHA-2 and SHA-512 extensions, and SHA-NI for SHA-256 on x86-64), found at
run time and checked against the portable code first, as the AES instructions are (B-103). Today's figures for
every primitive and for handshakes, requests and transfers, how to measure them and how to build an application for
speed (it needs no special settings) are in BENCHMARKS.md.

The AES instructions are detected with `is_x86_feature_detected!` / `is_aarch64_feature_detected!` the first time a
key is made, and checked with a self-test (FIPS 197 answers, and the CTR and GHASH code against the portable code);
if anything disagrees the process uses the portable path. `pratique::crypto::aes::hardware_accelerated()` says which
one is in use, and `examples/bench.rs` prints it. The ClientHello offers AES-GCM first when it is hardware
accelerated and ChaCha20-Poly1305 first when it is not (the bitsliced AES, with the 113-gate S-box of Boyar and Peralta
since B-62, does AES-128-GCM at about 96 MB/s on an x86-64 VM where the AES instructions do over 3 GB/s and ChaCha20-Poly1305
about 350 MB/s).
`RUSTFLAGS="--cfg pratique_portable"` forces the portable path on every target. On x86-64 CPUs with BMI2, the X25519
ladder and ECDSA P-256's point operations also run from copies compiled for it (`mulx`), chosen at run time (B-104). The SIMD
kernels (AES, GHASH, ChaCha20, Poly1305, SHA-2; in x86-64's AES-GCM kernel also an empty `asm!` that keeps the hash's products
between the AES rounds, B-103, and in the AVX2 ChaCha20 and Poly1305 empty ones that keep the compiler from rewriting their
shuffles and products, B-104), those BMI2 copies and their run-time checks, the volatile writes that wipe secrets, the OS random-number calls, the calls into the operating
systems' certificate-store libraries (`native_roots`), the one `recv` that looks at an idle socket without waiting (`asyncio::net`, B-90)
and the two instructions that set and read ARM's data-independent timing bit around secret work (`crypto::dit`) are the only places
that use `unsafe`.

The unit tests have been run natively on x86-64 and on an Apple M5 Max (aarch64 macOS; 1,426 of them on 2026-10-08, those
for x86-64 kernels not built there), and under qemu-user for aarch64 and 32-bit ARM at an earlier revision. The aarch64 AES /
PMULL code runs on the M5: since B-85 it seals AES-128-GCM at about 13 GB/s there (1 MiB messages; BENCHMARKS.md, backlog
B-85), against 0.24 GB/s for the portable code. One unit test fails if a CPU that has the instructions ends up on the
portable path, which is what a broken hardware path looks like from outside, because the self-test then switches it off.
The test suite has not run natively on Windows yet (the Windows store code has run under Wine; backlog B-58).

## Running the tests

`sh tools/native_check.sh` runs everything below plus the benchmark and the timing tests on the current machine and writes
a short `native_report.txt` (`--quick` skips the benchmark and timing runs).

`sh tools/mac_field_check.sh` is for a machine on a normal network (not one that re-signs TLS; it stops if it finds that).
It smoke-tests the library against about a hundred real public servers: fifty-odd that must connect, and test sites that
must be refused for their certificate (expired, wrong host, self-signed, unknown root), at the handshake (TLS 1.0 and 1.1,
CBC, RSA key exchange) or as revoked, with hard-fail revocation (backlog B-06, B-100); it captures
their certificate chains with OpenSSL and verifies each with the library at the moment it was captured (B-08: the result,
`field_results/real_chains/`, is what `cargo test --test real_chains` replays once it is copied to `tests/data/real_chains/`),
asks their OCSP responders and downloads their CRLs and checks each with the library at the time it was fetched (B-65: the
candidates are written to `field_results/real_revocation/`, of which `tests/data/real_revocation/` keeps a selection),
checks that four public HTTP/3 servers follow the QUIC client's key updates and that keep-alive holds a quiet connection open
(B-91; it needs UDP to port 443), and
with `fuzz HOURS` runs a long fuzz campaign under
`caffeinate` (B-66). Everything it produces is under `field_results/` and in `field_results.tgz`; it reads no secrets and
records only the names of proxy variables, never their values. First run on a real network on 2026-10-07 (an Apple M5 Max,
B-97 in `BACKLOG.md`): its chains are in `tests/data/real_chains/` and its OCSP responses and CRLs in
`tests/data/real_revocation/`.

Run suites one at a time and keep each under 45 seconds:

```
cargo test --lib
cargo test --lib --no-default-features   # the pure part alone (336 tests)
cargo test --test go_vectors             # notes, tree heads, records and Merkle proofs against Go's verdicts (pure)
cargo test --test cms_vectors            # damaged CMS messages against OpenSSL's verdicts (pure)
sh tools/check_features.sh               # the line between the pure part and `net`; builds for wasm32 if the target is installed
cargo test --test interop_openssl     # needs the `openssl` command line tool; skipped otherwise (TLS 1.3 and 1.2)
cargo test --test h2_client_interop   # the HTTP/2 client against Go's server; builds it with `go`, skipped if there is none
AIOQUIC_PATH=/dir cargo test --test h3_client_interop   # the HTTP/3 client against aioquic (pip install --target /dir aioquic==1.3.0); skipped if python3 or openssl is missing
sh tools/server_interop.sh            # the TLS server against OpenSSL, curl, headless Chromium (Python Playwright and certutil) and Go (67 checks)
sh tools/h2_interop.sh                # its HTTP/2 against curl, Go, python-h2 and h2spec, the production server and the test one (41 checks; PYTHONPATH may point at h2 and hyperframe, H2SPEC at h2spec)
cargo test --test system_roots        # checks the system CA bundle, if present
cargo test --test real_chains         # replays the 74 real certificate chains captured by tools/mac_field_check.sh
cargo test --test real_revocation     # replays 20 real OCSP responses and 13 real CRLs at the time they were fetched
cargo test --test wycheproof          # Project Wycheproof vectors for ECDSA P-521 and RSA-PSS (pure)
cargo test --features mozilla-roots --test mozilla_roots   # the built-in Mozilla roots, and the real chains against them
cargo test --test native_roots        # the OS's own store: on a Mac compared with the system roots keychain; elsewhere, that there is none
cargo test --test inflate_vectors     # streams from zlib, gzip(1), zlib-flate and Go, and damaged ones with zlib's verdicts (pure)
cargo test --doc
```

The test vectors in `src/crypto/test_vectors.rs` and `src/crypto/aead_vectors.rs` and the certificates in
`tests/data/` were generated with Python's `cryptography` package (OpenSSL underneath) by the scripts in
`tools/`. They contain public data only.

`fuzz/` is a coverage-guided fuzzer with no dependencies and no nightly compiler (LLVM's edge counters, which stable
`rustc` can emit, drive the mutation); `sh fuzz/run_all.sh 3600` fuzzes every parser for an hour on all cores. See
`fuzz/README.md` for what each target asserts and what it has found so far. It is kept out of the package
(`exclude` in `Cargo.toml`) and out of the normal build.

`cargo test --lib` includes deterministic mutation fuzzers (damaged certificates, chains, PEM, DER, signatures,
signed notes, checksum database data, Merkle proofs, BER and CMS messages, HTTP responses, URLs, and fuzzed handshake flights and records sent through a scripted TLS server). Tampered
chains must be rejected and nothing may panic. `PRATIQUE_FUZZ_SCALE=10 cargo test --lib`
runs ten times as many iterations.

The timing tests are `#[ignore]`d because they depend on the machine. Run them one at a time on a quiet machine:
`cargo test --release --lib crypto::timing::x25519 -- --ignored --nocapture` (also `ecdh`, `ghash`, `poly1305`,
`aead_and_mac`, `aes`, `harness`). A comparison that reads |t| above 4.5 is measured again with fresh inputs, and
fails if the repeat is above 10 or is above 4.5 again at the same statistic with the same sign (the same class slower
again; B-95); `harness_does_not_fail_comparisons_of_identical_classes` measures how often that happens with nothing to find.
A clock that ticks coarsely (Apple Silicon's, 41.67 ns) is found and handled by timing several calls together (B-98);
`operand_probe` asks whether the CPU itself takes longer for some operand values than for others (B-99), and
`dit_on_and_off` measures the comparisons an Apple M5 flagged with ARM's data-independent timing mode off and then on;
both report and do not fail, and `tools/native_check.sh` runs them. On the M5, ECDH, SHA-256 and AES key setup ran faster
on zero-heavy inputs with the mode off and showed nothing with it on, so the library sets it (on aarch64 CPUs that have it)
while its secret arithmetic runs: key exchange, the AEADs, AES and HMAC (`crypto::dit`).

## Licence

Apache License, Version 2.0; see `LICENSE`. `NOTICE` names what comes from elsewhere: the one file under another licence
is `roots/mozilla.pem` (Mozilla Public License 2.0, from NSS), which is built in only with the `mozilla-roots` feature.
