# Security review brief: the verification path of pratique

For: a security-review agent (or a human reviewer) asked to find out whether this code can be trusted to say "yes, this is authentic" and to say "no" when it is not.
Written: 2026-10-06, against the drop that contains this file. Counts below were measured on that drop; re-measure before you quote them.

## 1. The story

`pratique` is an HTTPS client written from scratch in Rust with no dependencies (only `std`). It has its own TLS 1.3 (and TLS 1.2 for servers that speak nothing newer), X.509 validation, signature verification and HTTP stack. Its main consumer is **Lazaret**, a supply-chain security tool that checks Python and JavaScript packages before they are used. Lazaret asks this library to do three kinds of thing that matter:

1. **Say whether a signature, a certificate chain or an attestation is real.** An npm or PyPI package arrives with a Sigstore attestation; a Go module has a line in the Go checksum database; a Java archive has a CMS signature. The library checks the cryptography and the chain of trust, and returns facts (who signed, what, when) for Lazaret's policy to judge.
2. **Fetch things over TLS** from package registries, with an egress policy that limits which hosts a module may reach and which credentials go to which host (`Client::allowed_hosts`, tight by default since B-75: a wildcard is one label and an entry without a port the default port; `url_limits`; `hop_headers`; a request's own rule, `RequestBuilder::allowed_hosts`; `allowed_proxies` for the proxy), through the proxy the environment or the operating system's settings name (`proxy_from_system`, B-117). A server's chain is held to RFC 5280 and, since 2026-10-10, to the CA/Browser Forum's rules where they bind a client (`VerifyOptions::web_pki`: serverAuth named in the leaf and anyExtendedKeyUsage not, RSA and ECDSA keys and signatures only, an issuer name byte for byte its issuer's subject name, and an authorityKeyIdentifier that is its issuer's subjectKeyIdentifier); a store of private anchors turns them off (`TrustStore::with_web_pki_rules(false)`).
3. **Stay quiet and bounded** when the bytes it is given are hostile: no panic, no unbounded memory, no unbounded time.

The worst thing this code can do is **accept something it should refuse**: a forged signature, a certificate that does not chain to a trusted root, a transparency-log proof for a record that is not in the log, an attestation whose signer was not who it says. Everything else (a wrong refusal, a slow request) is a smaller failure. A wrongly accepted artifact is the kind of failure Lazaret exists to prevent, so this library must not be the weak link.

The project's honest position, which is also what the README says: **this is unaudited, hand-written cryptography and parsing, and nobody outside the project has reviewed it** (backlog item B-23). Lazaret's rule is that it will not rely on the hand-written TLS until it has been independently reviewed. This document is the first step of that: it tells you what the code claims, what has been done to check it, what has not, and where we would attack it first.

One thing about how the evidence was produced, so you can weigh it: the code, its unit tests and the generators of its fixtures come from one development process. A test that passes shows the code agrees with the author's reading of a specification, which is weak evidence of correctness. Agreement with an implementation the project did not write (OpenSSL, Go, the JDK's `jarsigner`, Python `cryptography`, aioquic, real data from real services) is strong evidence, and most of what follows is sorted that way. Please treat the author's tests as hints about where to look, not as proof.

### What this review is, and is not

This brief asks for **Phase 1**: the *pure verification path*, 27 source files, about 14,500 lines of code and doc comments plus about 9,400 lines of in-file tests. It is the right place to start for three reasons. Its failures are the consequential kind (wrong acceptance). It is the smallest piece. And it is built with `#![forbid(unsafe_code)]`, no I/O, no threads, no clock and no dependencies, so you can read it as plain functions from bytes to verdicts, and it compiles to `wasm32-unknown-unknown`.

Phase 2 (the TLS client, the record layer, the constant-time code, the HTTP stack, the egress policy, QUIC and HTTP/3) and Phase 3 (the server and anything that signs) are **not** in scope here; section 9 says what is in them so you can see the boundary.

## 2. What we ask of you

Deliver, in this order of importance:

1. **A list of findings.** For each: an id, a severity, `file:line`, which claim in section 5 it breaks (or "none: a new one"), a **reproducer** (a failing test, a fuzz input, or a byte string and the call that mishandles it), what the correct behaviour is, and a suggested fix. A finding without a reproducer is a hypothesis; label it so.
2. **A scorecard of the claims in section 5**: for each, *holds*, *broken (see finding N)* or *could not determine*, and in one or two sentences what you did to decide. "Could not determine" is a useful answer; please do not round it up to "holds".
3. **Answers to the questions in section 8**, even if you find nothing wrong.
4. **What you would do next**: where the evidence is thinnest, and what independent check would be cheapest to add.

Severity: **Critical** = a wrongly accepted signature, chain, proof or attestation, reachable from attacker-controlled bytes. **High** = a panic, abort, unbounded loop or unbounded allocation reachable from attacker bytes in the pure path; or a verdict that differs from the reference implementation in a way an attacker can steer (a parser differential). **Medium** = a policy gap or a check that is documented and missing. **Low** = wrong documentation, misleading error text, hardening.

Rules of engagement. Work offline: every fixture is in the repository and none of the tests below needs the network. Do not edit files under `src/`; write reproducers as new files (a new `tests/review_*.rs` can use the public API) or as patches. All fixture keys and certificates are public test data. Run test suites one at a time; the pure suite takes about 10 seconds and the whole library suite about 30 seconds on a laptop-class machine.

## 3. How the pieces fit: a map of the verification path

Each entry point below is where a caller hands the library bytes it did not make, followed by what that entry point calls, in
the order the code calls it. `[net]` marks code of the `net` build (Phase 2) that hands the bytes in; everything else is
the pure build, which is Phase 1. `→ m` means the step calls into module `m`. The function names are the code's own, so
each line can be found with a search.

```
UNTRUSTED: every byte may be the attacker's                 TRUSTED: what the caller passes in
a server's certificates and staples, an OCSP response, a    a TrustStore (sys::trust_store_*, mozilla_roots, add_der),
CRL, a registry's bundle, tiles, a file's signature, a      pinned keys (the sumdb key, trusted_root.json, npm's keys)
TUF repository's metadata, a compressed body                and "now" (the pure code reads no clock)

1. A TLS server's certificate     [net] tls/handshake.rs (Certificate, CertificateVerify); tls12.rs (the same in TLS 1.2)
   ├─ x509::TrustStore::verify_server_path(chain, host, now)
   │    ├─ Certificate::parse ................................................ → asn1
   │    ├─ build_path → search: at most 256 signature checks, then a refusal
   │    │    └─ Certificate::verify_signed_by → x509::verify_signature ....... → rsa, ecdsa, ed25519
   │    └─ check_path: validity, critical extensions, CA and key usage, extended key usage, path length, name
   │       constraints, RSA minimum, host name; check_web_pki (the CA/B Forum's rules) unless the anchors are private
   ├─ revocation::check_path: staples, and what an OcspSource or CrlSource returns ([net] http/ocsp_source.rs,
   │  crl_source.rs)
   │    └─ Crl::check, check_ocsp: signed by the issuer or a responder it delegated, about this certificate, in
   │       its window ................................. → asn1, sha1 (the OCSP certificate ID), sha2, x509
   └─ tls/signature.rs verify_tls13_signature, tls12::verify_tls12_signature: the leaf's key over the transcript or
      the ServerKeyExchange ............................................... → rsa, ecdsa, ed25519
   (ClientConfig::verify_server_certificate = false skips the first two, for an ACME validator; a deferred revocation
   check, Revocation::deferred, is finished on a worker before the connection is used)

2. A Sigstore attestation         sigstore::{NpmAttestation, Pep740Attestation, Bundle}::verify(trust, artifact)
   ├─ Bundle::parse, parse_npm_attestations, parse_pep740 .................... → json, pem
   ├─ 1  the DSSE signature, by the certificate's key or a ring key by id .... → trust_root → ecdsa, ed25519
   ├─ 2  the in-toto statement ................................................ → json
   ├─ 3  each log entry: check_body binds it to this envelope; a signed entry timestamp by a log the root lists
   ├─ 4  verify_timestamps: RFC 3161 tokens over the signature ................ → cms::verify_timestamp_with → x509
   ├─ 5a check_inclusion: a signed checkpoint and an inclusion proof .......... → note::open, tlog::verify_inclusion
   ├─ 5b verify_certificate: the Fulcio chain at a verified time .............. → x509::TrustStore::verify_chain
   ├─ 5c check_scts: embedded SCTs from enough of the root's CT logs ... → ct::verify_embedded → asn1, trust_root
   └─ 6  a subject of the statement has the artifact's digest
   trust material: trust_root::TrustedRoot::parse (from entry point 5), KeyRing::from_npm_keys
                                                                              → json, x509::parse_spki

3. A Java archive (any CMS)       cms::SignedData::parse, then verify → verify_signer for each signer
   ├─ SignedData::parse ............................... → ber (BER in; what is signed re-encoded as DER)
   ├─ verify_signature: check_attributes (contentType, messageDigest, CMSAlgorithmProtection), then the signer's key
   │  over the signed attributes ....................... → rsa, ecdsa, ed25519, sha2, and sha1 if the caller allows it
   ├─ verify_timestamp: an RFC 3161 token among the unsigned attributes ... → this module again, x509 (time stamping)
   └─ the signer's chain, at the time stamp's time, else at the caller's .. → x509::TrustStore::verify_chain

4. A Go module's checksum         sumdb::Check::new(verifier) → add_head → add_lookup → tiles_needed → finish(tiles)
   ├─ add_head, and the head inside each lookup: a signed tree head; an older head must be a prefix of a newer one
   │                                                                          → note::open → ed25519, ecdsa
   ├─ add_lookup: the record and the tree it is in ............................ → parse_record, tlog::record_hash
   └─ finish: every tile authenticated against a signed root, then each record and each prefix
                                                                              → tlog::check_record, check_prefix

5. Sigstore's trusted root (TUF)  [net] http/tuf_source.rs → tuf::refresh, fetch_target over a tuf::Updater
   ├─ update_root: each new root signed by a threshold of the old root's keys and of its own → ecdsa, ed25519, rsa
   ├─ update_timestamp, update_snapshot, update_targets, update_delegated: thresholds, versions, lengths, hashes, expiry
   └─ find_target, TargetFile::verify; the caller hands the target to trust_root::TrustedRoot::parse or
      KeyRing::from_tuf_npm_keys ......................................... → json

6. A compressed body or archive   [net] http/decode.rs (Content-Encoding), the scanning proxy's relay → inflate::Inflater
   └─ DEFLATE, zlib and gzip, bounded by inflate::Limits (output and ratio); nothing below it

Below all of them
   readers:  asn1 (DER), ber (BER, for CMS only), pem, json, util (byte readers, hex, constant-time compare), verify_error
   crypto:   sha2, sha1; bignum → rsa, ecdsa; fe25519 → ed25519       (verification only: public data, no secrets)
```

Which pure module calls which, from `python3 tools/line_counts.py --graph` (it reads `crate::` paths outside comments,
strings and tests, and stops if there is a cycle; there is none: `revocation` calls `x509`, never the reverse, and the
signature code calls no module above it). A call that goes through a type without naming the module is not seen: `cms`
reaches `rsa` through `x509::PublicKey::Rsa`, as the map shows.

<!-- line_counts.py graph: begin -->
```
asn1                 → verify_error
ber                  → asn1, verify_error
pem                  → verify_error
json                 → (nothing)
util                 → (nothing)
verify_error         → (nothing)
crypto::sha2         → crypto::sha2_consts
crypto::sha2_consts  → (nothing)
crypto::sha1         → (nothing)
crypto::bignum       → util
crypto::rsa          → asn1, crypto::bignum, crypto::sha1, crypto::sha2, util, verify_error
crypto::ecdsa        → asn1, crypto::bignum, crypto::sha2
crypto::fe25519      → (nothing)
crypto::ed25519      → crypto::fe25519, crypto::sha2
x509                 → asn1, crypto::ecdsa, crypto::ed25519, crypto::rsa, crypto::sha2, pem, verify_error
revocation           → asn1, crypto::sha1, crypto::sha2, pem, verify_error, x509
cms                  → asn1, ber, crypto::ecdsa, crypto::ed25519, crypto::sha1, crypto::sha2, verify_error, x509
note                 → crypto::ecdsa, crypto::ed25519, crypto::sha2, pem, x509
tlog                 → crypto::sha2, util
sumdb                → note, pem, tlog
ct                   → asn1, crypto::sha2, trust_root, util, verify_error, x509
trust_root           → asn1, crypto::ecdsa, crypto::ed25519, crypto::sha2, json, pem, x509
tuf                  → crypto::ecdsa, crypto::ed25519, crypto::rsa, crypto::sha2, json, pem, trust_root, util, x509
sigstore             → asn1, cms, crypto::sha2, ct, json, note, pem, tlog, trust_root, util, x509
inflate              → (nothing)
idna                 → (nothing)
mozilla_roots        → pem, x509
```
<!-- line_counts.py graph: end -->

### Line counts per module

Lines that are not blank, from `python3 tools/line_counts.py`, which says how it sorts them (`--check` exits 1 when this
table or the graph above is out of date, `--write` brings both up to date). The in-file tests are not all of a module's
tests: the integration suites of section 10 and the fuzz targets add more. The suites matter most for `tuf`
(`tests/tuf_synthetic.rs`), `sigstore` (`tests/sigstore_real.rs`, `tests/sigstore_synthetic.rs`) and `x509`
(`tests/chain_cases.rs`, `tests/real_chains.rs`), which replay data the in-file tests do not carry.

<!-- line_counts.py: begin -->
| layer | file | code | comments | in-file tests |
|---|---|---:|---:|---:|
| readers (untrusted bytes in) | `src/asn1.rs` | 302 | 37 | 156 |
|  | `src/ber.rs` | 248 | 50 | 173 |
|  | `src/pem.rs` | 112 | 11 | 59 |
|  | `src/json.rs` | 483 | 81 | 361 |
|  | `src/util.rs` | 85 | 6 | 72 |
|  | `src/verify_error.rs` | 21 | 8 | 0 |
| | *subtotal* | *1,251* | *193* | *821* |
| signatures (C2) | `src/crypto/sha2.rs` | 305 | 21 | 68 |
|  | `src/crypto/sha2_consts.rs` | 43 | 1 | 0 |
|  | `src/crypto/sha1.rs` | 52 | 13 | 31 |
|  | `src/crypto/bignum.rs` | 665 | 92 | 301 |
|  | `src/crypto/rsa.rs` | 198 | 28 | 143 |
|  | `src/crypto/ecdsa.rs` | 438 | 87 | 712 |
|  | `src/crypto/fe25519.rs` | 200 | 47 | 151 |
|  | `src/crypto/ed25519.rs` | 332 | 101 | 398 |
| | *subtotal* | *2,233* | *390* | *1,804* |
| certificates (C1, C5) | `src/x509.rs` | 1,491 | 338 | 1,323 |
|  | `src/revocation.rs` | 723 | 148 | 518 |
| | *subtotal* | *2,214* | *486* | *1,841* |
| signed objects (C4, C6, C7) | `src/cms.rs` | 658 | 159 | 459 |
|  | `src/note.rs` | 186 | 76 | 459 |
|  | `src/tlog.rs` | 478 | 142 | 863 |
|  | `src/sumdb.rs` | 211 | 127 | 520 |
|  | `src/ct.rs` | 233 | 66 | 127 |
|  | `src/trust_root.rs` | 455 | 124 | 288 |
|  | `src/tuf.rs` | 982 | 191 | 113 |
|  | `src/sigstore.rs` | 917 | 205 | 324 |
| | *subtotal* | *4,120* | *1,090* | *3,153* |
| decompression (C11) | `src/inflate.rs` | 1,006 | 183 | 1,190 |
| | *subtotal* | *1,006* | *183* | *1,190* |
| pure, not on the path | `src/idna.rs` | 249 | 66 | 139 |
|  | `src/mozilla_roots.rs` | 54 | 27 | 0 |
| | *subtotal* | *303* | *93* | *139* |
| callers in the net build (Phase 2) | `src/tls/handshake.rs` | 605 | 116 | 18 |
|  | `src/tls/tls12.rs` | 560 | 75 | 200 |
|  | `src/tls/signature.rs` | 22 | 6 | 68 |
|  | `src/http/ocsp_source.rs` | 82 | 16 | 0 |
|  | `src/http/crl_source.rs` | 140 | 24 | 59 |
|  | `src/http/tuf_source.rs` | 62 | 25 | 82 |
|  | `src/http/decode.rs` | 168 | 52 | 123 |
| | *subtotal* | *1,639* | *314* | *550* |
| | **the verification path (the first five layers)** | **10,824** | **2,342** | **8,809** |
<!-- line_counts.py: end -->

Trust boundaries. Everything that arrives from a network or a file is untrusted. The things the library trusts are what the caller passes in: the **trust anchors** (a `TrustStore`), the **pinned keys** (the Go checksum database key, Sigstore's `trusted_root.json`, npm's key list) and **the time** (the pure code never reads a clock; the caller says what time to validate at). Where a time comes from the data (a time stamp, a log entry), the library only believes it after the authority that vouches for it has been verified.

The pure build knows nothing about revocation *fetching*: `revocation` checks evidence it is given (a staple, a CRL, or what an `OcspSource` or `CrlSource` the caller supplied returns), builds the OCSP request a source sends (`ocsp_request`), and never does I/O itself. Since B-63 and B-64 it also has two switches that change what is demanded: `whole_chain` (sources asked about every certificate below the anchor, and hard-fail wanting evidence for each) and `deferred` (sources not asked and missing evidence not held against the chain, for a check that the async client finishes on a worker after the handshake: a misuse of it is a check that never happens).

## 4. Threat model

**Attackers we assume.**

* One who controls every byte the library reads: a malicious or compromised registry, CDN, proxy or man-in-the-middle, and the publisher of a malicious package.
* One who can pick or craft certificates, signatures, JSON, BER/DER, tiles and proofs freely, including ones no honest tool would write (non-canonical encodings, duplicate fields, huge lengths, deep nesting).
* One who holds a certificate legitimately issued to them by a trusted CA, or a Sigstore identity of their own. The library must say *who* signed; whether that identity is acceptable is the caller's policy and not this review's concern.

**Attackers we do not assume.** One who can modify the machine running the code, the trust anchors or pinned keys the caller supplies, or the caller's clock. One who has stolen a trusted CA's or log's private key (the library cannot tell).

**Out of scope for Phase 1.** Side channels (the verification code handles public data and is variable time by design; the constant-time code is in Phase 2), the TLS handshake, the network stack, denial of service by sending a lot of data (but see claim C3 on bounded work for a given input), and Lazaret's own policy.

## 5. The claims to falsify

These are what the code promises. Each one names where it is enforced, what evidence exists, and how we would try to break it. Please try to break them.

| id | Claim | Where | Evidence so far | Where we'd push |
|---|---|---|---|---|
| C1 | A certificate chain is accepted only if every certificate is signed by the next, each is valid at the time the caller gave, the last is a trust anchor in the store (whose limits, if it was added with any, hold: the leaf issued before its distrust date, names within imposed constraints), every issuing certificate is a CA whose key usage allows signing and whose extended key usage allows the purpose, `pathLenConstraint` holds, name constraints on the leaf's alternative names hold, there is no unknown critical extension, an RSA key below the store's minimum (2048 bits by default, anchors exempt) is refused, SHA-1 signatures are refused, a BOOLEAN that is not `00` or `ff` makes a certificate invalid, building the path takes at most 256 signature checks (and the answer is then a refusal), and for TLS the host name matches a subject alternative name (no common-name fallback) and, unless the store is one of private anchors, the CA/Browser Forum's rules that bind a client hold (`check_web_pki`: the leaf's extendedKeyUsage names serverAuth and not anyExtendedKeyUsage, no Ed25519 key or signature, issuer names byte for byte, matching key identifiers). | `x509.rs`: `TrustStore::verify_chain`, `build_path`, `search`, `check_path`, `Certificate::from_der` | Fixture tests for each rule (OpenSSL and Python `cryptography` made them); a real Fulcio chain at its logged time and a real Apple code-signing chain; all 123 supported self-signatures among the 128 roots of the system store this was recorded on verify (`tests/system_roots.rs` reads whatever store the machine has); 74 real chains captured by OpenSSL on a normal network (55 that verify, ending at 10 different roots, and 19 that must be refused), each replayed at its capture time with every alteration (another host, a time outside the validity, flipped bits) refused (`tests/real_chains.rs`, B-97, B-102); fuzz targets `certificate`, `chain`, `purpose_chain` assert that a changed chain is never accepted; deterministic mutation fuzzers in `cargo test --lib`. | Path building with several candidates for one issuer name (it was exponential before B-93; is 256 the right budget, and can a legitimate chain with cross-signed intermediates need more?); self-issued and cross-signed intermediates; a version 1 anchor, which is a CA by being in the store (the one exemption from the `basicConstraints` rule); names in intermediates (constrained by the CAs above them since the second round, see section 7); unusual encodings of names, times and serial numbers; anything where a *later* check could be skipped because an *earlier* candidate path failed. |
| C2 | A signature verifies if and only if it is valid under the rules written in the module (RSA PKCS#1 v1.5 and PSS, ECDSA P-256, P-384 and P-521 over SHA-256/384/512, Ed25519 with the rules of Go's `crypto/ed25519`; a certificate, CRL or OCSP response signed with RSA-PSS counts only with the Web PKI's three parameter sets, Mozilla Root Store Policy 5.1.1). There is no encoding that makes one signature verify in two forms, except where the module documents it. | `crypto/rsa.rs`, `crypto/ecdsa.rs`, `crypto/ed25519.rs`, `crypto/bignum.rs`, `crypto/fe25519.rs` | RFC and NIST vectors; signatures made by OpenSSL; for Ed25519, 1,048 generated vectors each with Go's verdict (OpenSSL agrees on every one) and 128 known-answer signatures; the ECDSA code is compared on random inputs with an older, simpler implementation kept under `cfg(test)`; the group arithmetic against an independent Python implementation; Project Wycheproof's 542 P-521 vectors and 352 RSA-PSS vectors (`tests/wycheproof.rs`), and a real P-521 root's self-signature. | **Project Wycheproof vectors have been run for P-521 and RSA-PSS only** (B-33), not for P-256, P-384, PKCS#1 v1.5 or Ed25519. DER-encoded ECDSA signatures (leading zeros, negative integers, trailing data, `r` or `s` equal to 0 or at or above the order), the point at infinity, points not on the curve, RSA PKCS#1 padding edge cases (the Bleichenbacher-style "short digest info" and extra-data forms), PSS salt lengths, an RSA exponent of unusual size, Montgomery reduction edge cases in `bignum`. |
| C3 | No input makes the parsers panic, abort, loop without end, recurse deeply or allocate in proportion to something other than the input's own size. | `asn1.rs`, `ber.rs`, `pem.rs`, `json.rs` and every `parse` of the others | Depth limits (BER 48, JSON 32 by default); the 19 Phase 1 coverage-guided fuzz targets (of 43; `der`, `certificate`, `hostname`, `chain`, `purpose_chain`, `ed25519`, `note`, `tlog`, `sumdb`, `ber`, `cms`, `json`, `sigstore`, `trust_root`, `pem`, `crl`, `ocsp`, `revocation_path`, `inflate`) with a counting allocator that reports an input that makes the target allocate far more than its size; deterministic mutation fuzzers; an earlier panic audit (B-13) that found two real panics. | Length fields that are almost the size of the address space; counts that multiply (a SET of many names, each with a constraint); quadratic behaviour in name-constraint checks (path building is bounded by a budget of 256 signature checks since B-93); `usize` arithmetic on 32-bit targets (the code is also built for wasm32). |
| C4 | CMS `SignedData`: a signer is accepted only if its signed attributes carry the digest of the content, the signature over them verifies for the signer's certificate, and the certificate chains at the right time (an RFC 3161 time stamp's time when there is one, else the caller's). SHA-1 is accepted only when the caller says so. | `cms.rs`, `ber.rs` | 45 messages made by OpenSSL and `jarsigner` verify; **1,886 damaged messages judged by `openssl cms -verify`** and replayed, each region of a message pinned as exactly OpenSSL's verdict, stricter, or deliberately more lenient (the leniencies are listed in the test); two fuzz targets. | The "deliberately more lenient" cases (what exactly are they?); the BER-to-DER re-encoding of the signed attributes, which is what the signature covers; certificates found by issuer-and-serial versus subject key identifier; the ESS signing-certificate attribute, which is **not** checked. |
| C5 | Revocation: OCSP and CRL evidence is used only if signed by the certificate's issuer (or a delegated responder the issuer signed that carries the OCSP-signing usage), names this certificate, and is within its window, whether it was stapled, supplied or fetched by a source; CRLs it cannot interpret are never used. Soft-fail is the default and means missing or bad evidence is ignored; must-staple and hard-fail are stricter. A check that was deferred (`Revocation::deferred`) is finished before the connection is used (the async client fails closed if it is missing). `ocsp_response_valid_until` reads a response's window *without* verifying it, for caches only, and decides nothing. | `revocation.rs` | 45 fixture files from an independent implementation; fuzz targets `crl`, `ocsp` (which also feeds the unverified window reader), `revocation_path`; tests through the TLS client against `openssl s_server`; the OCSP request is byte for byte `openssl ocsp`'s, and a live `openssl ocsp` responder decides hard-fail; 20 real OCSP responses and 13 real CRLs from eight public CAs (`tests/real_revocation.rs`, B-65, B-102; three responses and two lists say revoked) replayed at their fetch time, every byte of the small ones altered, tried on other certificates, other shards and the wrong issuer, and nine real list entries revoking a certificate with their serial. | The distance between "ignored because untrustworthy" and "ignored because forged": can a forged response ever *remove* a revocation that a good one established? CRL scope rules (issuing distribution point, delta, indirect). Whether `deferred` can leak into a check that is never finished. The real evidence is two days', and every real response uses a SHA-1 certificate ID: SHA-256 IDs are from generated fixtures only; the real revoked evidence is from the CAs' test sites, signed by the issuer (no delegated responder said revoked). |
| C6 | Transparency logs: a signed note is accepted only if a signature by a key you gave verifies and no bad signature by such a key is present; an inclusion or consistency proof verifies only for the right leaf, index, size and root; tile data is trusted only after every tile has been authenticated against the signed root; two different roots for one size are a fork. | `note.rs`, `tlog.rs`, `sumdb.rs` | Real `sum.golang.org` data (tree heads, a lookup, tiles, real proofs); **2,070 valid and damaged cases judged by Go's own `sumdb` packages** and replayed; a made-up two-history log for forks; three fuzz targets. Stricter than Go in the places listed in the `sumdb` and `note` module docs (canonical Base64, plain decimals, the characters of module paths). | The "stricter than Go" list is the list of places this code could differ from the reference: is each really *only* stricter? Tile arithmetic at the right edge, partial tiles replaced by full ones, trees near 2^62 leaves. The module docs record that Go's `tlog` before x/mod 0.40.0 did not authenticate every tile (they cite CVE-2026-56865): please check that claim and that our replay of it is faithful. |
| C7 | Sigstore: an attestation verifies only if the DSSE envelope's single signature is by the signer's key (the Fulcio certificate's, or a ring key by id), every log entry in the bundle is about this envelope and is authenticated by a signed entry timestamp or an inclusion proof to a signed checkpoint from a log the trusted root lists (a present but wrong proof is an error even if the other is right), every time stamp is over the signature and from a listed authority, the only times believed are those verified, the signer was valid at one of them, a Fulcio certificate carries signed certificate timestamps from enough of the root's CT logs (one by default) and none from a listed log that does not verify, and a subject of the statement has the digest the caller gave. | `sigstore.rs` (the module doc lists the seven steps), `ct.rs`, `trust_root.rs`, `json.rs` | The six real npm attestations of three releases and PyPI's real provenance verify against Sigstore's production trusted root and npm's keys, and every member and string of every one, removed or changed in turn (about 1,700 changes), makes it fail unless nothing authenticates it; the four real Fulcio certificates' SCTs verify, and every byte of one changed is refused or not counted; 108 bundles from a Sigstore of our own cover time stamps, an Ed25519 log, every key type, two CT logs and 78 refusals; a real attestation of Lazaret 0.1.8 is in `tests/data`; four fuzz targets. | The precertificate rebuilt for an SCT (`ct::precertificate_tbs`: the certificate's TBS without the extension, lengths re-encoded); that an SCT from a listed log that fails is an error rather than ignored (stricter than Chrome, as strict as a wrong Rekor promise). What is **not** verified (SCTs delivered in a TLS handshake or OCSP response, `messageSignature` bundles, Rekor v2 entries, consistency between checkpoints). Whether "nothing authenticates it" is ever wrongly true. Identity extraction from the Fulcio certificate (which extension holds which fact, and whether two extensions can disagree). Validity windows read from `trusted_root.json` (rounding of fractional seconds). |
| C8 | JSON that a signature covers has one meaning: duplicate member names, lone surrogates, invalid UTF-8, leading zeros, floating-point numbers and nesting beyond the limit are refused; numbers are kept as text and read exactly; the canonical form follows RFC 8785 for the subset used. | `json.rs` | Vectors in `tests/data/json_vectors.txt`; fuzz target `json` with round-trip and canonical-form properties. | Differentials against `serde_json`, Python's `json` and V8's `JSON.parse` on the same bytes (we have not run these); the canonical form's ordering by UTF-16 code units; Protocol Buffers' string-encoded 64-bit integers. |
| C9 | The pure build has no `unsafe`, no I/O, no threads, no clock and no dependencies, and compiles for `wasm32-unknown-unknown`. | `src/lib.rs` (`#![cfg_attr(not(feature = "net"), forbid(unsafe_code))]`), `tools/check_features.sh` | The script scans the code (before the test module) of each of the 27 files for `unsafe`, `std::{fs,net,io,env,process,thread,os,ffi,path}`, clocks, printing and FFI, for `cfg` on a feature or a target, and for any mention of a `net` module; it checks that `Cargo.toml` has no dependencies; then it builds natively and for wasm32 and runs 338 tests. | That the list of pure files is complete and that the `net` feature cannot be switched on by something in the pure files; that `forbid` really covers every file listed. |
| C11 | Decompression is bounded and has one answer: `inflate` never writes a byte past `Limits::max_output` and refuses (never truncates) a stream that would pass it or the ratio limit; the bytes, or the error, do not depend on how the input and the output are cut; framing is as strict as zlib's (the zlib header and Adler-32, the gzip header, its CRC and its length, the CRC-32 and length of every member, complete Huffman codes but the single code of length one, nothing after the stream). | `inflate.rs` (`Inflater::inflate`, `room_for`, `check_ratio`, `Huff::build`), and its use for `Content-Encoding` in `http/decode.rs` (Phase 2) | 256 streams from zlib, gzip(1), zlib-flate, Go and by hand, each at 7 cuttings; 1,039 damaged copies, each with exactly zlib's verdict and bytes (Go differs only on reserved gzip flag bits, which it ignores); unit tests for every truncation, flipped bits, hand-made bad codes and both limits; a cut-invariance test of the ratio limit that fails on an earlier draft of it; a fuzz target and a mutation fuzzer. | Codes of 15 bits on the slow path with a fast table of 10; the window at its full 32 KiB and a distance of exactly 32,768; stored blocks that straddle the bit buffer; multi-member gzip with empty members; the ratio check's arithmetic near `u64::MAX`; the decoder's state after an error (it is meant to stay failed). |
| C10 | The public API makes the safe thing the easy thing: for example `verify_server_chain` requires a host name, and a verdict carries the path it took. | `x509.rs`, `cms.rs`, `sigstore.rs` public items | Doc comments and tests. | Any public function that returns `Ok` for something a caller would take as "verified" while a check is still the caller's job (revocation is a separate step; time is the caller's; identity policy is the caller's). Are those obligations stated where a caller will see them? |

## 6. The files, in the order we would read them

The line counts of each file, split into code, comments and in-file tests, are in section 3.

| order | file | what it is | note |
|---|---|---|---|
| 1 | `src/asn1.rs` | strict DER reader | the foundation of everything that parses a certificate |
| 2 | `src/ber.rs` | BER reader for CMS | accepts indefinite lengths and constructed OCTET STRINGs; re-encodes to DER |
| 3 | `src/pem.rs`, `src/util.rs`, `src/verify_error.rs` | PEM and Base64, constant-time compare, errors | small |
| 4 | `src/crypto/bignum.rs` | big numbers, Montgomery arithmetic: the general code, and the fixed-size code (`bignum::fixed`: P-256's own reduction; from 32 limbs up, products and squares a column at a time; R^2 mod n by long division, Knuth's algorithm D; the inverse of a public value by the binary extended Euclidean algorithm, `inv_vartime`; B-49, B-103, B-104) | public data only, not constant time; the long division has two rare paths, each with a test input built to take it; the binary inversion is checked against Fermat's for the primes and orders of the three curves |
| 5 | `src/crypto/sha2.rs`, `sha2_consts.rs`, `sha1.rs` | hashes | SHA-1 is `pub(crate)` and used only to name certificates in OCSP and to report weak CMS signatures; `sha2::Accel` is the hook through which the `net` build runs SHA-2 on the CPU's instructions (`sha2_hw.rs`, after a self-test against this code; B-103); the pure build always uses this code; `sha2::Running` is a hash whose digest can be taken and the feeding go on (the TLS transcript, B-104) |
| 6 | `src/crypto/rsa.rs` | PKCS#1 v1.5 and PSS verification | modulus 1024 to 8192 bits, odd exponent of 2 to 64 bits; 1024, 1536, 2048, 3072 and 4096 bits on the fixed-size arithmetic (B-49) |
| 7 | `src/crypto/ecdsa.rs` | P-256, P-384 and P-521 verification | fixed-size limbs (the field arithmetic is in `bignum::fixed`), interleaved windowed NAF, generator table, no conversion to affine for the final check; an older simple version under `cfg(test)`. Since B-104 the point operations of a pass are a trait (`Points`): this file's (`Plain`), or, for P-256 on an x86-64 with BMI2, a copy of the same three functions compiled for it, which the `net` build offers through a hook as `sha2::Accel` does (`ecdsa_hw.rs`, outside Phase 1; checked against `Plain` on the scalar-multiplication and special-case tests of this file) |
| 8 | `src/crypto/fe25519.rs`, `ed25519.rs` | Ed25519 verification | the rules of Go's `crypto/ed25519`, written out in the module doc; [k]A + [s]B by signed windows since B-103, checked against the one-bit-at-a-time code it replaced; the field's products are 64 x 64-bit ones since B-104 (the multiples by 19 made in 64 bits; the bounds in the comments) |
| 9 | `src/x509.rs` | certificates and chains | the centre of C1 |
| 10 | `src/revocation.rs` | OCSP and CRL checking | C5 |
| 11 | `src/json.rs` | strict JSON, canonical writer | C8 |
| 12 | `src/cms.rs` | CMS and RFC 3161 | C4 |
| 13 | `src/note.rs`, `src/tlog.rs`, `src/sumdb.rs` | signed notes, Merkle proofs and tiles, the Go checksum database | C6 |
| 14 | `src/trust_root.rs`, `src/sigstore.rs`, `src/ct.rs`, `src/tuf.rs` | the trust material, the attestation checker, embedded SCTs (B-81) and the TUF client that brings the trust material (B-82) | C7 |
| 15 | `src/inflate.rs` | DEFLATE, zlib and gzip decompression | C11; it reads the bytes of package archives and of compressed HTTP bodies |

Entry points to start from: `x509::TrustStore::verify_chain` and `verify_server_chain`; `cms::SignedData::{parse, verify}`; `revocation` (`check_path`, `ChainEvidence`); `sumdb::Check`; `tlog::{verify_inclusion, verify_consistency, read_nodes}`; `note::open`; the three `verify(&self, trust, artifact) -> Result<Verified, _>` methods of `sigstore` (`NpmAttestation`, `Pep740Attestation` and a lone `Bundle`) with `trust_root::{TrustedRoot::parse, KeyRing::from_npm_keys}`; `crypto::rsa::RsaPublicKey::{verify_pkcs1, verify_pss, verify_pss_with}`, `crypto::ecdsa::{verify, verify_prehashed}` and `crypto::ed25519::verify` (each returns a plain `bool`).

## 7. Decisions we made on purpose, which you should challenge

Each of these is documented in the module where it lives. We would like to hear that a decision is wrong more than we would like to hear that it is documented.

* **Ed25519 follows Go and `ref10`, not RFC 8032's strictest reading.** The check is cofactorless; a non-canonical `y` of `p` or more and a zero `x` with the sign bit set are *accepted* in a public key; a small-order public key is accepted as a key (with the identity as key and `R`, `S` = 0 the equation holds for every message). The reason is that two verifiers that disagree on a signature are a danger where two parties must reach the same verdict (a log and its clients). Is that the right trade for this consumer?
* **Name constraints apply to the subject alternative names, and the `emailAddress` of the subject name (as OpenSSL does), of every certificate below the CA that carries them, intermediates included.** The rest of the subject distinguished name is not checked: a name constraint on directory names refuses the chain outright (this code does not compare names; ignoring the constraint would let a CA issue outside its subtree, which OpenSSL enforces and Go refuses as an unhandled critical extension). A constraint of another kind the code does not know, over a name of that kind, refuses the certificate; so does a name the reader had to leave out (x400Address, ediPartyName, a malformed or non-ASCII e-mail or URI) when a CA has a constraint of its kind. A DNS, e-mail or URI constraint that can never match (a trailing dot, an empty label) refuses the certificate that carries it; an empty one matches every name of its kind.
* **A trust anchor is a CA if it says so (`basicConstraints` with `cA`), or if it is a version 1 certificate**, which cannot carry the extension (some old roots are of that kind). OpenSSL and Go refuse a version 3 anchor without `basicConstraints`, and so does this code since B-93; before, any anchor without it could sign for anything. Anchors are exempt from the minimum RSA size. 
* **Issuer and subject names are compared in a canonical form** (B-34; `x509::canonical_name`, the rules of RFC 5280 section 7.1 as OpenSSL applies them: text string types are equal, ASCII case and white space do not count, nothing else is folded or normalized) to find a certificate's issuer among the anchors and the intermediates sent. A name that does not decode is compared by its bytes. Matching names only nominate a candidate, whose signature must still verify; please check that a canonical match can never stand in for one. Since 2026-10-10 a TLS server's chain must also have each issuer name byte for byte its issuer's subject name (the CA/Browser Forum's rule 7.1.4.1, `check_web_pki`), unless the store is one of private anchors; the canonical match still builds the path for every other purpose. CRL issuers and OCSP responder names are still compared as bytes, so a mismatch there is a missing piece of evidence, not a wrong one.
* **Malformed extra certificates in a chain are skipped**, not fatal, so a bad intermediate cannot sink a chain that is good without it. Self-issued intermediates are never used as intermediates (a cross-signed or key-rollover certificate cannot be part of a path). Chains are at most 8 certificates, and a search for a path stops after 256 signature checks (Go stops after 100); a certificate that the server sends twice is one candidate.
* **There is no common-name fallback** for host names, and an unknown critical extension fails a certificate unless the caller says it interprets that OID.
* **Randomness: the operating system's, on every call, and no state.** On Linux `getrandom(0)`; only if the kernel refuses it (before 3.17, or a sandbox that answers ENOSYS or EPERM) `/dev/urandom`, after waiting up to a minute for `/dev/random` to report a seeded pool. Failure is an error, never a weaker source.
* **Revocation defaults to soft-fail.** Evidence that is missing or untrustworthy is ignored, except for a must-staple leaf. Hard-fail requires evidence only for the leaf.
* **Policy processing and SHA-1 signatures are not supported** (the last is refused on purpose), nor RSA-PSS certificate signatures with parameters other than the Web PKI's three. MD5, DSA and SHA-3 are refused by name in CMS.
* **CMS does not trust `signingTime`**, does not check the ESS signing-certificate attribute, and does not require the time-stamping usage to be the only one.
* **The TUF client is checked against python-tuf, not yet against Sigstore's real repository**: 58 repositories made with python-tuf get python-tuf's verdicts (one difference on purpose), but the sandbox it was written in could not reach `tuf-repo-cdn.sigstore.dev`; the embedded root (version 15) verifies, and `tools/mac_field_check.sh tuf` captures the real repository for `tests/tuf_sigstore.rs`. `succinct_roles` (hash-bin delegations) are refused. As in python-tuf, a role's metadata is whatever its keys signed with the version the snapshot pins: TUF signs no role name, so metadata one key signed for another role or repository stands in for this role's where the snapshot has no hash for it (found by fuzzing, where the synthetic repositories share keys). A repository that gives each role its own keys, or puts hashes in its snapshot, is not exposed.
* **TLS 1.3 sessions are resumed by default** (B-35, `tls::session`). A resumed handshake checks no certificate: it rests on the check of the full handshake it descends from. So a session is used for at most `Resumption::max_age` (one hour by default) after that check, however many resumptions lie between, and only by a connection with the same trust store (the same `Arc`), verification switch and revocation mode; a connection whose revocation check was deferred keeps no tickets; a ticket is used once; the key exchange is always fresh (`psk_dhe_ke`); there is no 0-RTT. The cost is that a certificate revoked within that hour goes unnoticed by a client that holds a session, as it would by one that kept the connection open. Is an hour right for this consumer, and should hard-fail revocation turn resumption off?
* **Certificate transparency is checked only for Fulcio certificates** (the SCTs embedded in them, against the trusted root's CT logs); the TLS client does not ask for or check SCTs. Sigstore believes a time only after the authority behind it has been verified, and needs at least one.
* **A Sigstore bundle is held to the rules of the version it says it is**, and that label (`mediaType`) is not signed: a 0.2 bundle stripped of its inclusion proofs and relabelled 0.1 verifies on its signed entry timestamps, as Sigstore's own clients accept a 0.1 bundle (found by fuzzing; `tests/sigstore_synthetic.rs`). Nothing is forged, since the log signed the promise, but a proof is lost; a caller that wants one checks `VerifiedEntry::inclusion`. **Decided on 2026-10-10 not to demand proofs**, for two reasons. npm still serves 2023-era provenance as 0.1 bundles with signed entry timestamps only (`sigstore@0.2.0`, December 2022, both entries, as in `tests/data`), which would stop verifying; recent releases carry proofs throughout (518 of 518 entries in Lazaret's set of popular packages). And while no checkpoint is checked against witnesses or a tree head kept from before, a proof adds nothing a relabel could get past: the signed entry timestamp and the checkpoint are signed by the same Rekor key. If checkpoints are ever checked, proofs become an opt-in `Trust` setting with a time cutoff, so that bundles from before 0.2 keep verifying (BACKLOG B-118). Please challenge the second reason.
* **JSON and Base64 are stricter than most libraries** (canonical padded Base64; no duplicate names; no floating point), which can refuse bundles that other tools accept.
* **`sumdb` and `note` are stricter than Go in listed ways** and "none looser" is a claim you can test. One of them: a lookup whose record has no line for the module and version asked about is an error (`NoLineForVersion`), where Go's `Lookup` returns no lines and leaves it to the caller. One place where this follows Go and a reader might want it stricter: a repeated signature line by a known key is dropped before it is verified (`note::open`, as in Go's `note.Open`), so a good signature followed by a corrupted copy of one is accepted; the text is unchanged and was genuinely signed.

## 8. Questions we would like answered

1. Reading `build_path` and `check_path` as a whole: is there a way to make `verify_chain` return `Ok` with a path in which some certificate has not had *every* check applied (because it was reached on a different candidate path, as a trust anchor, or as the last element)?
2. Is there any input on which `Certificate::from_der` accepts a certificate that OpenSSL, Go's `crypto/x509` and a browser's verifier would each reject for a *security* reason (as opposed to a policy one), or the reverse?
3. Are the Ed25519 and ECDSA verifiers *complete* as well as sound, i.e. do they accept every signature the reference implementations accept that matters in practice (Sigstore's, Go's `sumdb`'s, CMS's)?
4. In `sigstore`, can an attacker who controls the whole bundle (but not the trusted root) get a `Verified` with a signer that is not the key or certificate that signed the DSSE envelope? What about two entries in one bundle, the first honest and the second not?
5. In `tlog` and `sumdb`: can any sequence of "honest log, one tile altered" or "two heads of different sizes with an inconsistent proof" be accepted?
6. What do the *errors* leak or confuse? (For example, does any error text echo attacker-controlled bytes in a way a caller might log unescaped?)
7. Which claim of section 5 is the least well supported by the evidence in section 10, and what is the cheapest independent check that would support it?

## 9. What is outside this review (and where it is)

For completeness, so you can see the boundary; none of it is Phase 1.

| phase | what | files | state of the evidence |
|---|---|---|---|
| 2 | TLS 1.3 client, record layer, KeyUpdate, HelloRetryRequest, session resumption (B-35: tickets kept per server name, used once, `psk_dhe_ke` only, no 0-RTT), the revocation hooks into the handshake; TLS 1.2 for servers that speak nothing newer (B-36: ECDHE with AEAD suites only, the extended master secret required, the downgrade check of RFC 8446 section 4.1.3, no renegotiation or resumption, the same chain, host-name and revocation checks; a minimum version per client and per request, which a request can only raise) | `src/tls/` (`tls12.rs` for 1.2) | interoperates with OpenSSL (52 tests, 12 of them TLS 1.2, one of resumption on every suite and after a HelloRetryRequest: every suite, key type and group, bulk both ways, revocation, and two men in the middle, one that takes TLS 1.3 out of the ClientHello, which the downgrade check catches, and one that takes the extended master secret out of the ServerHello, which is refused) and with Go's `crypto/tls` over TLS 1.2 (HTTP/1.1 and HTTP/2), and a third-party gateway; reproduces the RFC 8448 trace byte for byte; the TLS 1.2 PRF and records against published vectors and Python's `cryptography`; fuzz targets for records, handshake flights (1.3 and 1.2) and established connections of both versions |
| 2 | Constant-time code: X25519 (and its key generation by a table of base-point multiples, every entry of a row read at each lookup: `x25519_base.rs`, B-103; the ladder compiled a second time for BMI2, chosen at run time, B-104), P-256 and P-384 ECDH, GHASH (on x86-64 reduced by two carry-less products with twisted powers of H since B-104), Poly1305 (four blocks at a time with AVX2 from 2 KiB on x86-64, B-104), ChaCha20, AES (hardware and bitsliced), AEADs (on aarch64 ChaCha20-Poly1305 decrypts as it authenticates and puts the ciphertext back if the tag is wrong, as AES-GCM's one pass does; B-103), SHA-2 on the CPU's instructions (`sha2_hw.rs`) | `src/crypto/` (the rest), `src/zeroize.rs` | a dudect-style timing harness (`src/crypto/timing.rs`) with deliberately leaky positive controls and a negative control (identical classes), on x86-64 and an Apple M5 Max; a row that reads above 4.5 is repeated and fails if it comes back with the same sign (B-95); one row is flagged and unexplained on an Intel Xeon cloud VM (the 32-bit-limb Poly1305 with an all-zero key, a path 64-bit builds do not use); on the M5 the CPU itself made ECDH, SHA-256 and AES key setup faster on zero-heavy inputs until ARM's `DIT` bit was set, which the secret entry points now do (`crypto::dit`, B-99: is every entry point that touches a secret covered?); open on the M5 under macOS: the AES-GCM data row flags (random plaintext slower), mostly the copy of the input that the test timed with the seal (under macOS copying random bytes is slower than copying zeros), and B-85's one-pass seal takes about 0.1 ns longer per KiB for random plaintext than for all-zero plaintext (0.2 before its kernel stopped reading the ciphertext back; the two-pass code shows none), kept as a known macOS-only residual, likely the CPU's load value prediction (B-24, `crypto::timing::aes_gcm_one_pass_against_two_passes`): is that the right trade against a 3.5 times slower two-pass seal?; this is where `unsafe` lives (SIMD kernels, wiping secrets, OS randomness, the `DIT` bit); an `aead` fuzz target compares vector kernels with portable code; since B-57 Poly1305 is in radix 2^64 on 64-bit targets (checked against the 26-bit code at the edges of p, and by the timing harness) and ChaCha20 has AVX2 and AVX-512 kernels chosen at run time (is the choice sound everywhere it is made, and is VBMI2 the right gate for AVX-512?) |
| 2 | HTTP/1.1, HTTP/2, HTTP/3 over QUIC, the egress policy (host rules, URL limits, per-hop credentials, a request's own rule and limits, the rule for the proxy, the `Refused` error), the reading of macOS's and Windows' proxy settings (`http/system_proxy.rs`, FFI to SystemConfiguration and CoreFoundation, and to `advapi32`'s registry calls), and the opt-in extras of B-37: `Content-Encoding` decoding (`http/decode.rs`, over `inflate`), `Expect: 100-continue` and the cookie jar (`http/cookie.rs`, host-only) | `src/http/`, `src/quic/` | interop against Go's HTTP/2 server and aioquic; 52 fuzz targets in all; bombs, broken streams, the 100-continue wait and the cookie rules against scripted servers (47 tests); 205 deliberate bugs, all in the HTTP, QUIC and egress code and one in the ChaCha20-Poly1305 code, each caught by a test or a fuzz target |
| 3 | Signing (B-109): ECDSA P-256/P-384 with RFC 6979 nonces hedged with randomness, Ed25519, RSA-PSS and PKCS#1 v1.5 by the CRT with base blinding and a check of each signature; the constant-time arithmetic under them (`ct_mod.rs`: Montgomery products modulo the group orders and secret primes, by columns from 32 limbs, a secret-exponent power in fixed windows; `ecdh.rs`: [k]G by a table of the generator's multiples, every entry of a row read, since B-115); private keys read from PEM and DER (PKCS#8, SEC 1, PKCS#1) with Base64 decoded without a table or a branch on the data | `crypto/ecdsa_sign.rs`, `ed25519_sign.rs`, `rsa_sign.rs`, `ct_mod.rs`, `src/sign.rs` | RFC 6979, RFC 8032 and OpenSSL's signatures matched exactly (python-ecdsa's deterministic ones too); timing harness clean on x86-64; a fuzz target for key reading; interop with OpenSSL's keys in each format |
| 3 | A TLS server and an HTTP/1.1 and HTTP/2 server, being made ready for production (B-113, B-114 and this review). B-110 gave it real certificates: the choice by name and by the client's signatures, stateless tickets (AES-256-GCM under rotating keys; a ticket that does not open, has expired or is for another name means a full handshake), client certificates checked for client authentication, early data skipped up to 64 KiB, KeyUpdate and empty-record floods refused. B-111 gave it the HTTP server: HTTP/1.1 parsing that refuses every ambiguous framing (the request-smuggling cases), the HTTP/2 engine with its flow control and its budgets for the floods (rapid reset, CONTINUATION, the 2019 advisories, HPACK bombs), upgrades (CONNECT, 101). B-112 gave it its runtime: limits on connections and on HTTP/2 handlers, deadlines for whole phases that a client cannot stretch byte by byte (`runtime::Timed`), graceful shutdown, certificates and OCSP staples kept fresh. B-113 gave it ACME (RFC 8555): the account key and the certificate keys written readable by their owner only, JWS signed with ES256, every challenge (TLS-ALPN-01's certificate is chosen only for a client offering `acme-tls/1`, never resumes a session, and the connection ends after the handshake), a certificate taken up only if it is for exactly the names ordered and the key made for it, renewal by ARI. B-78 put the scanning proxy on it (`pratique::proxy`), with its threat model, `PROXY_THREAT_MODEL.md`: a CA in memory for one run, limited by a critical name constraint to the hosts it intercepts; leaves for the host of the CONNECT alone; requests inside a tunnel parsed strictly and made again; the real host verified, and nothing passed on from one that does not verify; bodies the scanner reads whole before any of it goes on, refused when too large to read. h2spec passes, Pebble validates every challenge, pip, uv, npm, Yarn, pnpm, curl, Python and Go go through the proxy to the real registries, and fuzz targets cover the HTTP parsers and the proxy's reading of registry URLs. B-114 ran tlsfuzzer's TLS 1.3 scripts (1,582 tests passed in 40 scripts; what failed at first, twelve deviations from RFC 8446 in alerts, lengths and what a second ClientHello may carry, is fixed and listed in BACKLOG B-114) and testssl.sh (no finding) | `src/tls/server.rs`, `tls/server_split.rs`, `tls/certs.rs`, `tls/tickets.rs`, `http/server/` (`runtime.rs` for the limits and timeouts, `acme.rs` for ACME), `src/proxy/` (the scanning proxy), feature `server` (`tls/pki.rs` and `http/h2_server.rs` are for tests) | not a production component yet; not to be relied on |

## 10. The evidence, and how to rerun it

### What was done

| kind | what | independent of the author? |
|---|---|---|
| vectors | RFC and NIST vectors for hashes, RSA, ECDSA, Ed25519, ECDH, AEADs; 128 known-answer Ed25519 signatures | yes (published) |
| differential | 1,048 Ed25519 vectors with Go's verdicts; 2,070 `sumdb` cases judged by Go's packages; 1,886 damaged CMS messages judged by `openssl cms -verify`; 45 CMS messages from OpenSSL and `jarsigner`; 45 revocation fixtures from another implementation; HPACK and QPACK against Go, Python and `ls-qpack` | yes |
| real data | real `sum.golang.org` heads, tiles and proofs; six real npm attestations and one PyPI provenance, checked against production trust material; a real Fulcio chain; a real Apple chain; a real attestation of Lazaret 0.1.8; the roots of a system store | yes (the data), no (what we assert about it) |
| fixtures | certificates, CRLs, OCSP responses and Sigstore bundles generated by `tools/gen_*.py` with Python `cryptography` and OpenSSL: expiry, wrong host, non-CA issuer, `pathLen`, name constraints of four kinds, wrong purpose, a past validation time, tampering, 86 synthetic bundles with 62 refusals | partly: the generator and the checker share an author |
| fuzzing | 53 coverage-guided targets in `fuzz/` (18 of them are Phase 1: `der`, `certificate`, `hostname`, `chain`, `purpose_chain`, `ed25519`, `note`, `tlog`, `sumdb`, `ber`, `cms`, `json`, `sigstore`, `trust_root`, `pem`, `crl`, `ocsp`, `revocation_path`), each asserting something about the answer and not only "no panic"; deterministic mutation fuzzers inside `cargo test --lib` | the properties are the author's |
| deliberate bugs | `fuzz/mutate.py` breaks code on purpose and checks something notices: 244 bugs, **232 of them in Phase 2 code (HTTP, QUIC, egress, one in an AEAD); in Phase 1 only twelve: the nine on x509's CA/Browser Forum rules (`webpki_`, 2026-10-10), all killed by `tests/chain_cases.rs`, and three from the fuzz campaign of the same day (`tuf_threshold_off`, `sigstore_set_unchecked`, `idna_kelvin`)**. Some Phase 1 modules did their own one-off checks (five deliberate deviations of the Ed25519 rules each make the tests fail; every member and string of the real Sigstore bundles removed or changed in turn) | the author's |
| triage | two outside reports (6 findings on `tlog`, 11 on `x509`), each claim reproduced or refuted with a probe, the X.509 ones against `openssl verify` and Go's `crypto/x509`; the confirmed ones are fixed, with fixtures that differ in one thing each (`tools/gen_review_fixtures.py`, `tests/data/rv_fixtures.txt`; BACKLOG B-93). What it found in `x509`: an exponential search for a chain (seventeen certificates cost 63 ms, thirty-three ten seconds), a trust anchor without `basicConstraints` that could sign for anything, names the reader skipped escaping name constraints, a BOOLEAN `01` read as "not critical". | partly: OpenSSL and Go were the judges; the choice of cases was ours |
| triage, second round | three more outside reports (note, sumdb and tlog attacks; a side-channel review of `rand`, `timing`, `bignum`; the review summary), claim by claim, with Go's own `note` package as the judge for the note format and OpenSSL and Go for X.509 (BACKLOG B-94). Two claims did not hold (the duplicate signature line is Go's behaviour too; no tile width wraps), several overlapped the first round, and four things were fixed: directory-name constraints, names in intermediates, a lookup that answers a different question, and a timing harness that read a perfectly reproducible leak as none | partly, as above |
| triage, third look | a board of outside review cards (tile planning, `rand` fallback, X.509 acceptance, timing harness, `bignum`, ASN.1 times), each checked against the current tree (BACKLOG B-95, B-96). Most were findings already fixed or shown not to hold; a sweep of 1.27 million tile plans found no misshapen tile; the three bignum cards describe calls outside the contract of a module that is now crate-private, with no path from parsed input (12,000 rounds of malformed RSA and ECDSA input, no panic); the timing card on Ed25519 signing concerns a module that exists only for the test server and says it is not constant time. Fixed: a leap second (`:60`) in a certificate time; and the timing harness now repeats and fails a row that comes back above 4.5 with the same sign, which at once found a generator artifact in the AEAD row and one unexplained flagged row on an Intel Xeon VM (the 32-bit-limb Poly1305, a path 64-bit builds do not use). | the report cards; `src/asn1.rs`, `src/util.rs`, `src/crypto/timing.rs`, `src/tlog.rs` | repeat on a 32-bit host (B-58) |
| differential, chains (B-92 part 3, begun 2026-10-09) | `tools/chain_judges.sh` puts 90 generated chains (`tools/gen_chain_cases.py`: each differs from a good one in one thing: times, host names and wildcards, basic constraints, key usages, name constraints, signatures and algorithms, name chaining, path building, encodings) and the 74 captured real chains before this library, OpenSSL 3 (`-x509_strict`), Go's `crypto/x509` and, on a Mac, Apple's `security verify-cert`, and lists every disagreement with each judge's reason. The library matched what the standards say on all 58 cases they settle and on the 74 real chains, here and on a Mac with Apple's verifier (Go the same; OpenSSL 56 and 72; Apple 57 and 73, accepting a version 2 certificate with extensions and refusing one real chain, DigiCert's revoked-certificate demo); the run found one bug in the library, a version 2 certificate whose extensions were read (fixed: extensions need version 3), and five cases where the library was looser than Apple, closed on 2026-10-10 by following the CA/Browser Forum's rules for a TLS server's chain (an Ed25519 chain, a leaf with no extendedKeyUsage or with anyExtendedKeyUsage, issuer names equal only after RFC 4518's folding, a mismatched authorityKeyIdentifier); the 32 cases the standards leave open (31 when the judges ran) are pinned, each with the library's choice, its reason and what the three others do, in `tests/chain_cases.rs` | yes for the verdicts of OpenSSL, Go and Apple; the cases are ours |
| regressions | what fuzzing and tests found is listed in `fuzz/README.md`: a chunk-size overflow, a parse of `http://a:b:80/`, DER times such as 30 February, an OCSP parser that ignored parameters after the algorithm, two remote panics on multi-byte UTF-8, and a Kelvin sign that `idna::to_ascii` encoded as an A-label | n/a |

### What has not been done

* **No systematic deliberate-bug check of Phase 1** (x509 beyond its CA/Browser Forum rules, revocation, cms, tlog, sumdb, sigstore, the signature code). Adding it is the cheapest way to learn how much the existing tests would notice; see `fuzz/mutants.py` for the format.
* **Project Wycheproof vectors only for P-521 and RSA-PSS** (`tests/wycheproof.rs`, B-33: 542 and 352 vectors, no disagreement); none yet for ECDSA P-256/P-384, RSA PKCS#1 v1.5 or Ed25519.
* **No differential run of the JSON reader** against other parsers. The chain builder has now been run against OpenSSL and Go (and, once run on a Mac, Apple) on 89 generated cases and 74 real chains (`tools/chain_judges.sh`, above), which is more than the triage's 25 but not yet a large corpus: a capture of a few hundred more hosts, and generated cases that vary two things at once, are still to do.
* **Real revocation evidence is one day's** (B-65): 21 OCSP responses and 46 CRLs from public CAs captured on 2026-10-07 all check out (25 are kept as fixtures), but none of the responses says revoked or uses a SHA-256 certificate ID, so those cases rest on generated fixtures and OpenSSL alone.
* **The operating systems' own trust stores are read only when asked, and the macOS reading has not yet run** (B-101): `native_roots` reads the macOS Keychain's trust settings (user, administrator, system) and the Windows `ROOT` store less `Disallowed` and the roots whose usage property leaves out TLS servers, through FFI. A wrong reading of trust settings errs toward accepting, so the code errs the other way (what it cannot read or represent leaves a root out, and an error fails the read), but the macOS half is compile-checked only, and the Windows half has run under Wine, not Windows. `Client::new()` still uses the bundle file (`/etc/ssl/cert.pem` on macOS), `SSL_CERT_FILE` or, on Windows only, the store; the built-in Mozilla roots (`mozilla-roots`, B-31, which carry Mozilla's distrust dates and NSS's imposed name constraints) are a snapshot of NSS 2.90.
* **No sanitizers.** Memory errors cannot occur in the pure build (`forbid(unsafe_code)`), but the fuzzer has no AddressSanitizer for the rest, because those need a nightly compiler.
* **Fuzz campaigns have been hours, not days.** The longest on the verification path is eight hours on an 18-core M5 Max over its 22 targets (2026-10-10, B-92 part 5): it found one bug, in `idna::to_ascii` (a Kelvin sign made a label that is not its own conversion; fixed), and two oracles that were too strict (a relabelled Sigstore bundle, a replayed TUF file; both genuine, both now allowed for exactly that case). Nothing in `x509`, `revocation`, `cms`, the logs or the signature code.
* **No written threat model before this one**, and no external reader.

### Commands

```sh
# the pure build: static checks, native and wasm32 builds, 338 tests (a minute or two the first time, for the builds)
sh tools/check_features.sh
cargo test --lib --no-default-features                 # the 338 pure tests (about 15 s of testing, after the build)
python3 tools/line_counts.py --check                   # section 3's line counts and module graph are the code's

# the whole library suite (about 55 s on two cores; in three parts, `-- http::server`, `-- http:: --skip http::server` and `-- --skip http::`) and the integration suites, one at a time
cargo test --lib
cargo test --test go_vectors          # Ed25519 verdicts from Go
cargo test --test cms_vectors         # 1,886 damaged messages, OpenSSL's verdicts
cargo test --test sigstore_synthetic  # our own Sigstore
cargo test --test sigstore_real       # real npm and PyPI attestations (replayed offline)
cargo test --test rekor_real          # real Rekor data (replayed offline)
cargo test --test system_roots        # the 128 roots of a system store
cargo test --test real_chains         # 74 real chains, replayed at their capture time
cargo test --test real_revocation     # 33 real OCSP responses and CRLs (5 revoked), replayed at their fetch time
cargo test --test wycheproof          # Project Wycheproof: ECDSA P-521 and RSA-PSS
cargo test --test chain_cases         # 90 generated chains, each one thing different; the library's choices where the standards leave it open
tools/chain_judges.sh                 # the same chains and the real ones before OpenSSL, Go and (on a Mac) Apple; field_results/chain_judges/report.txt
cargo test --features mozilla-roots --test mozilla_roots   # the built-in Mozilla roots
cargo test --test inflate_vectors     # 256 streams from other compressors, 1,039 damaged ones with zlib's verdicts
PEBBLE=/path/to/pebble tools/acme_interop.sh   # the server's ACME against Let's Encrypt's test CA (24 checks)
tools/proxy_interop.sh pip                      # the scanning proxy with real package managers (a section at a time: pip uv npm yarn pnpm curl python go tunnel auth gateway)
TLSFUZZER=/path/to/tlsfuzzer tools/tlsfuzzer.sh test-tls13-finished   # tlsfuzzer's TLS 1.3 scripts against the server (one, or all without a name)
PRATIQUE_FUZZ_SCALE=10 cargo test --lib              # ten times the deterministic mutation runs

# coverage-guided fuzzing (stable Rust; no nightly, no cargo-fuzz)
sh fuzz/run_all.sh check                                # does the coverage feedback work (2 s)
sh fuzz/run_all.sh 3600                                 # an hour, every target, all cores
sh tools/mac_field_check.sh fuzz-verify 8               # eight hours, the verification targets alone (FUZZ_TARGETS="..." for others)
sh fuzz/run_all.sh replay chain fuzz/artifacts/chain/crash-XXXX   # replay one saved input
python3 fuzz/mutate.py --list                           # the deliberate bugs (Phase 1's: the nine `webpki_` ones, `tuf_threshold_off`, `sigstore_set_unchecked`, `idna_kelvin`)
```

The generators in `tools/` (`gen_fixtures.py`, `gen_cms_fixtures.py`, `gen_sigstore_fixtures.py`, `gen_revocation_fixtures.py`, `gen_tlog_vectors.sh`, `go_oracle.sh`, `ed25519_vectors.py`) need Python's `cryptography`, `openssl`, the JDK and Go; the committed fixtures are what the tests use, so you do not need any of them to rerun the suites. `tools/go_oracle.sh` runs Go's `sumdb` and `note` packages as an independent judge; note its warning about the `tlog` package of `x/mod` before v0.40.0.

## 11. A suggested plan

If you have a limited budget, here is the order in which we think the hours pay most.

1. **Read `asn1.rs`, then `x509.rs` end to end**, and answer question 1 of section 8. This is the code whose failure is a wrongly accepted chain, and it is where one author's misreading of RFC 5280 is most likely.
2. **Run a deliberate-bug pass over `x509.rs`, `ecdsa.rs`, `ed25519.rs`, `tlog.rs` and `sigstore.rs`** (a one-line change that makes a check weaker, then see whether any test fails). Every change that survives is a missing test, and some will be a missing check.
3. **Feed the signature code the Wycheproof vectors** for ECDSA P-256/P-384 (DER and P1363), RSA PKCS#1 v1.5, and Ed25519 (P-521 and RSA-PSS are done: `tests/wycheproof.rs`), and list every disagreement with the expected verdict.
4. **Differential-test chain validation** against OpenSSL (`openssl verify`) and Go (`crypto/x509`) on generated certificates that vary one thing at a time (names, extensions, validity, key usage, path length, constraints) and on the 128 real roots, and list every disagreement for a security reason.
5. **Attack `sigstore.rs` as a whole**: take the real bundles and change each part in ways the existing "remove or change every member" pass does not (swap an entry between two bundles; two entries; a certificate chain with a different leaf; a timestamp from another envelope).
6. **Read `cms.rs` against `ber.rs`** for the re-encoding of signed attributes, and list the "more lenient than OpenSSL" cases from the test with a one-line judgement of each.
7. **Then** read the transparency-log code against Go's, and the JSON reader against two other parsers.

## 12. Glossary

* **Pure build**: `default-features = false`: the 27 verification files, no `net` feature, no `unsafe`, no I/O.
* **Trust anchor**: a root certificate the caller trusts; `TrustStore` holds them.
* **Oracle**: an implementation the project did not write, used to judge cases (OpenSSL, Go, the JDK, Python `cryptography`).
* **Tile**: a static file of consecutive hashes of a transparency log's Merkle tree; the Go checksum database serves its tree as tiles.
* **DSSE**: the signing envelope Sigstore uses (a payload type, a payload and signatures over their pre-authentication encoding).
* **Fulcio, Rekor**: Sigstore's certificate authority and its transparency log.
* **B-nn**: an item of `BACKLOG.md`. B-23 is the independent review this document prepares for; B-65 is revocation against real CAs; B-71 is Sigstore; B-70 is CMS.
