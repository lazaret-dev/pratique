# Clean-room AES S-box and carry-less multiplication provenance

This commit contains two new primitives written without viewing or copying the
superseded implementations:

- a bitsliced AES forward S-box over `[u64; 8]`; and
- a fixed-work portable `u64` by `u64` carry-less multiplier.

## Roles and timeline

- Implementation agent: OpenAI Codex, in Codex desktop session/workspace
  `01a1bdf3-6499-7612-83a6-4fba923442ff`, on November 8, 2026.  The Git commit
  is recorded under repository owner John A Booth's requested identity,
  `johnabooth@gmail.com`; that commit identity must not be read as a claim that
  John personally authored the primitive expressions or the affirmation below.
- Independent reviewer: Claude, in review text relayed by John A Booth on
  November 8, 2026.  The model version and Claude session identifier were not
  supplied to the implementation agent.  That review independently checked the
  S-box mathematics, the carry-less product, the tests, and the structural
  constant-time properties, and identified the integration gates below.
- Integrator: not yet assigned.  The integrator must be a different person or
  agent session, and must be named here before integration begins.  This commit
  deliberately contains no caller integration or removal of superseded code.

## Sources consulted

- *Lazaret 0.2.0 clean-room portable AES/GHASH replacement requirements*, the
  implementation brief supplied for this work.  The exact supplied Markdown
  file has SHA-256
  `773f628ad8a7636f8c7048e3a7a892accde6dadd2470cfe1b4d8b45381fb8a86`.
- NIST FIPS 197-upd1, *Advanced Encryption Standard (AES)* (May 9, 2023), in
  particular the GF(2^8) representation, the field modulus, Sec. 5.1.1's S-box
  construction and affine transformation, and Table 4's forward S-box values.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC* (November 2007), in particular Sec. 6.3's
  polynomial interpretation of block multiplication.
- The Rust language and standard library behavior for fixed-size arrays,
  integer bitwise operations, shifts, and `wrapping_sub`.

Before this commit, repository inspection was limited to build/module structure
(`Cargo.toml`, `src/lib.rs`, and `src/crypto/mod.rs`).  No cryptographic
implementation was taken from those files.

## Implementation-agent affirmation and limitation

The Codex implementation agent named above did not inspect BearSSL source or
implementation documentation, forks of BearSSL, another library's AES S-box or
GHASH source, the existing `src/crypto/aes_ct.rs` S-box implementation, the
existing `src/crypto/ghash.rs` portable multiplication implementation, the
BearSSL sections of NOTICE files, or `lazaret-dev/lazaret#98`'s implementation
diff.  The two source files in this commit were created from blank files using
only the sources named above.

This process statement cannot establish or promise that BearSSL was absent from
the language model's training data.  The stronger engineering evidence is that
the implementation follows the direct finite-field construction in FIPS 197
and a simple fixed-step polynomial product, is structurally unlike the usual
hand-optimized bitsliced S-box and multiplication circuits, and is checked by
standard-derived exhaustive and property tests.

## Integration and acceptance gates

- Confirm that the existing AES caller packs the least-significant input bit in
  plane zero, as this S-box requires.  NIST AES-128, AES-192, and AES-256
  known-answer tests must exercise the integrated caller and key schedule so an
  opposite plane order cannot pass unnoticed.
- Inspect optimized output for the `wrapping_sub` mask in
  `clmul64_portable`.  A compiler may express the mask as a select and a target
  without a conditional-move instruction may lower that select to a branch on
  a secret bit.  Review x86-64, aarch64, wasm32, i686, armv7, and riscv64 output;
  add an independently justified optimization barrier if any supported target
  introduces secret-dependent control flow.
- Run NIST GCM vectors, portable/hardware parity, authentication-failure tests,
  the existing TLS and AES-GCM suites, relevant fuzz targets, and supported
  cross-platform gates.
- Measure the portable fallback before and after integration, including a
  release-mode 200 MB AES-GCM transfer or equivalent sustained workload with
  hardware acceleration disabled.  The fixed 64-step carry-less multiply is
  the principal performance risk.  Record AES-128-GCM and AES-256-GCM results,
  confirm the hardware path remains within measurement noise, and obtain
  explicit owner acceptance for any portable regression over 25%.
- Audit the final source and artifacts before changing NOTICE or license files.

Integration with the existing AES and GHASH callers, removal of superseded
code, attribution review, assembly review, cross-platform validation, and
performance measurement are deliberately left to the separate reviewer and
integrator required by the implementation brief.
