# Clean-room portable CLMUL optimization provenance

This change revises only the clean-room `clmul64_portable(a, b)` primitive
introduced by pratique PR #8.  It does not connect the primitive to production
GHASH.  A separate integrator must perform that work and the final performance,
timing, compatibility, and attribution review.

## Roles and timeline

- Implementation agent: OpenAI Codex, in Codex desktop session/workspace
  `01a1bdf3-6499-7612-83a6-4fba923442ff`, on November 8, 2026.  The round began
  in a new isolated worktree based directly on PR #8's merge commit
  `55cfa19fb41bbfc503e7e5bf93de39e3189d1127`.
- Git identity: repository owner John A Booth's requested identity,
  `johnabooth@gmail.com`.  This identity is not a claim that John personally
  authored the primitive expression or the implementation-agent affirmation.
- Reviewer and integrator: not yet assigned.  They must be different people or
  agent sessions from the implementation agent and must be named before
  integration begins.

## Sources consulted

- *Lazaret 0.2.0 clean-room portable AES/GHASH replacement requirements*, the
  original supplied Markdown brief, SHA-256
  `773f628ad8a7636f8c7048e3a7a892accde6dadd2470cfe1b4d8b45381fb8a86`.
- The post-PR #8 optimization addendum supplied by the repository owner on
  November 8, 2026.  It reported the integrated throughput below, retained the
  original clean-room boundary, permitted another independently derived
  fixed-work polynomial construction, and required the same function contract,
  tests, structural/timing review, a 25% performance gate, provenance, and
  benchmark output.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/
  Counter Mode (GCM) and GMAC* (November 2007), specifically its interpretation
  of block bits as polynomial coefficients over GF(2).
- Rust language and standard-library semantics for fixed-width unsigned integer
  multiplication, shifts, bitwise operations, fixed-size arrays, `const fn`,
  `std::hint::black_box`, and `std::time::Instant`.
- The PR #8 clean-room files `src/crypto/clmul_clean.rs`,
  `tests/clean_crypto_primitives.rs`, and `CLEAN_ROOM_AES_GHASH.md`, plus
  `Cargo.toml` for the crate and feature configuration.

No third-party implementation source or implementation description was used.
The five-residue construction and its carry bound were derived directly for
this round from elementary polynomial and positional arithmetic.

## Implementation-agent affirmation and limitation

The implementation agent did not inspect:

- the integration branch or its diff;
- the separate integration review report;
- pratique's superseded portable carry-less multiplication;
- pratique's production GHASH implementation source;
- BearSSL source or implementation documentation, or a fork of BearSSL;
- another library's AES, GHASH, or carry-less multiplication source; or
- `lazaret-dev/lazaret#98`'s implementation diff.

The agent did run repository tests by command and observed their names and
results, but did not read the prohibited implementation files.  Generated
assembly inspection was limited to the revised clean primitive's benchmark
wrapper.

As with PR #8, this process cannot prove that relevant third-party source was
absent from model training data.  The stronger evidence is the documented
derivation, the use of five rather than the prohibited existing four residue
classes, the independent bit-polynomial oracle, the targeted carry-boundary
tests, and the generated-code review.

## Independent derivation

For each operand, bit exponents are divided into five classes according to
their value modulo five.  Each class contains at most thirteen coefficients.
Ordinary multiplication of two such sparse integers computes convolution
counts in slots five bits apart.  No count exceeds thirteen, which is less than
the base-32 slot size, so a carry cannot reach an adjacent slot.  The low bit of
each slot is therefore the parity of that polynomial coefficient.

The implementation evaluates all 25 class pairs and masks the appropriate
coefficient-parity positions.  Its work, control flow, and memory addresses are
independent of both operands.  It has no secret-indexed table, branch, loop
bound, allocation, or unsafe code.  This is not the prohibited four-class
integer-multiplication-with-holes construction.

## Tests and generated-code review

The clean primitive tests pass with default features and with
`--no-default-features` under both rustc 1.99.1 and the repository minimum
rustc 1.87.0.  They cover the PR #8 cases plus every pair of five-residue
planes, their complements, and all 65,536 byte pairs.  A
`wasm32-unknown-unknown` no-default-features test build also succeeds under
rustc 1.99.1.

The Rust 1.99.1 release build of a minimal candidate wrapper was inspected for
both `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`.  The ARM64 body
contains 25 `mul`, 25 `umulh`, and no conditional branch or conditional select;
the x86-64 body contains 25 widening multiply sequences and no conditional
branch or conditional move.  Neither body has a secret-selected load address.
Review of the remaining targets, including targets on which integer
multiplication may have operand-dependent latency, remains an integration gate.

The full default-feature repository run reached the crypto, AES-GCM, and GHASH
tests successfully.  Its final result was not clean in the restricted worktree
environment: 1,264 tests passed, 353 socket/network-dependent tests failed, and
24 statistical timing tests were ignored.  This is recorded as an environment
limitation, not as a successful full-suite result.  Because this branch does
not integrate the revision, production GHASH/GCM tests of the revised
primitive remain the separate integrator's responsibility.

## Benchmark output

The addendum reported these integrated PR #8 results on the same class of Apple
ARM64 host with hardware acceleration disabled:

| Benchmark | Acceptance baseline | PR #8 primitive integrated |
|---|---:|---:|
| AES-128-GCM, 1 MiB | 239.1 MB/s | 79.02 MB/s |
| AES-128-GCM, 16 KiB | 237.2 MB/s | 78.79 MB/s |
| AES-256-GCM, 1 MiB | 194.4 MB/s | 67.88 MB/s |
| AES-256-GCM, 16 KiB | 193.3 MB/s | 68.21 MB/s |

The optimization branch adds an ignored, reproducible release-mode microbenchmark:

```text
$ cargo test --release --test clean_crypto_primitives \
    benchmark_against_previous_clean_primitive -- --ignored --nocapture
previous 64-step median: 32.927 ns/product
five-residue median:      6.706 ns/product
speedup:                   4.91x
checksum:                  0x60321522849da28eb1b0b06e919ec57b
  zero input median:       6.561 ns/product
 dense input median:       6.596 ns/product
random input median:       6.535 ns/product
input-class median spread: 0.93%
```

Environment: Apple ARM64, macOS 27.2 build 26B123, rustc 1.99.1 with LLVM
23.1.1, release profile, 32,768 deterministic operand pairs per sample and the
median of nine samples.  This benchmark is evidence of isolated primitive
improvement and similar timing across three coarse input classes; it is not a
substitute for structural review or integrated AES-GCM measurement.

The same command under the repository's rustc 1.87.0 minimum measured 32.585
ns/product for the 64-step primitive and 6.589 ns/product for the revision, a
4.95x speedup.  Its zero/dense/random input-class median spread was 1.17%.

## Required integration gates

Before merge, a separate integrator/reviewer still must:

- connect the revision without changing the clean-room files and run all PR #8
  oracle, production GHASH/GCM, NIST, parity, TLS, fuzz, and authentication-
  failure tests;
- inspect optimized output on x86-64, aarch64, wasm32, i686, armv7, and riscv64,
  including compiler helper routines on targets without native wide multiply;
- run the portable GHASH timing check on at least x86-64 and Apple ARM64;
- verify the integrated build at the repository's minimum Rust version and on
  all supported platforms;
- repeat the four representative hardware-disabled AES-GCM measurements and
  confirm each is within 25% of its acceptance baseline unless the owner
  explicitly approves otherwise;
- confirm the normal hardware path remains within 5% measurement noise; and
- complete the final provenance and attribution audit.

