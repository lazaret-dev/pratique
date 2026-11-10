# Clean-room AES S-box and carry-less multiplication provenance

This file began as the accepted PR #8 primitive provenance record. Its original
implementation-agent sources and affirmation are preserved below. That commit
introduced two primitives without viewing or copying the superseded implementations:

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
- Integrator at the original PR #8 handoff: unassigned in that historical
  commit. The separate integration assignment is recorded below. This file was
  not updated when integration began; this correction reconciles that stale
  administrative record and does not backdate it.

## Current integration assignment and closure record

The current integrator is the separate Codex agent with canonical task identity
`/root/ghash_integrator`, in supplied parent chat/workspace
`01a1be54-c6e9-73d3-8a85-5e6f9a76a492`. Its unique logical integration session is
`20261108-pratique-portable-batch-ghash-integration`. These are logical task and
workspace identifiers; an opaque backend agent/session UUID was not exposed and
is not asserted here.

The independent continuation primitive author is `/root`, logical clean-room
session `20261108-clmul-feasibility` in that parent workspace. The integrator's
separate agent context was assigned before its production inspection. Production
source and diffs were not sent to that primitive author. The original PR #8
implementation-agent workspace above remains a separate historical identity.
The final read-only review context is `/root/pr10_final_review`.

The integrator's isolated workspaces are:

- `/private/tmp/pratique-batch-ghash-integration-20261108`, original integration
  evidence branch `codex/integrate-portable-batch-ghash`;
- `/private/tmp/pratique-portable-crypto-publication-20261108`, publication branch
  `codex/integrate-portable-batch-ghash`; and
- `/private/tmp/pratique-pr10-lifecycle-fix-20261108`, lifecycle closure branch
  `codex/pr10-prepared-secret-lifecycle`.

The production basis is accepted PR #8 merge
`55cfa19fb41bbfc503e7e5bf93de39e3189d1127`. The separately committed clean-only
continuation is `2a1d8553 -> bede170a -> 5e5c9ab9 -> 781ffb62 -> b33b45e1`.
The first published integration is `bc55bcbccb19921838b5b0bdd399d4c247cd26ea`;
`32615a80b43280fb1fef3d36fa7d87261d5617f2` adds CI and evidence corrections.
The borrowed in-place preparation API was committed independently as
`5ecf25250b8c03065b48c673a49a23116bcca76c`, merged without rewriting it, and
wired in integration commit `3db15f5495b6608094102bff87ec36970d1d36aa`.

Git author and committer `John A Booth <johnabooth@gmail.com>` are the owner's
requested contributor metadata. They do not identify John as the personal
human author of agent-written expressions or replace the agent affirmations.

Current integration evidence is in `cleanroom/ghash_integration/`; continuation
math/source provenance is in `cleanroom/clmul_feasibility/PROVENANCE.md` and
`cleanroom/aes_tower/DERIVATION.md`. The lifecycle closure and final scoped
attribution audit are recorded separately there. Performance follow-up remains
tracked in issue #11 and is not a blocker for this lifecycle/provenance repair.

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

The preceding gates were the original PR #8 handoff to the separate integrator.
Current integration, validation, lifecycle closure, and scoped attribution
results are recorded under the identities and evidence paths above. Supported
public AES key sizes remain 128 and 256 bits; AES-192 was not added to the
repository's API. The original implementation-agent affirmation is unchanged.

## November 10 guarded continuation record

The same separate roles continue: clean primitive author `/root` in logical
session `20261109-guarded-clmul`, integrator `/root/ghash_integrator`, and
independent read-only reviewer `/root/pr10_final_review`, associated with parent
workspace `01a1be54-c6e9-73d3-8a85-5e6f9a76a492`. Source and disassembly remain
outside the clean author's view. These administrative identities supplement,
and do not replace or backdate, the original PR #8 affirmation above.

The clean chain extends working-state API `27a1c8ac` with exact guard commit
`404718732544d328e61174963e4cc756b00a7605`, borrowed test observer
`9f8a17c4a181988d3bbd839b415d6b58076b0124`, and retained-copy API
`26af8b776e7aea1ad328333f9a4a1d6cafe7a85f`. They were committed independently
before integration `c87285bc3c2cf5b7ba29e5bdd50a1b05a72563cc`. The production
module/constants are exact copies of the final clean files; integration owns
the GHASH scheduling, fifty-word raw guards and existing volatile cleanup.
The separate administrative audit update is
`ce5c179491d1a2db3ba005a083d44517fbb29dcd`, without production/Cargo changes.

This is an experimental representation, not an accepted timing fix. Fifty
payload lanes and fourteen public guard lanes preserve the exact product after
XOR-removing its known public correction before field reduction. Only the 64-bit
path uses that guard witness; the 32-bit portable path remains scalar. The
circuit invariant does not cover arbitrary platform latency or all caller work.
Compiler-created key Clone/API-return copies, registers/spills and abort paths
retain the existing best-effort erasure limit. Paired 8370C validation is pending
and all previous findings and HOLD remain. NOTICE and LICENSE are unchanged.
See the detailed current [integration provenance](cleanroom/ghash_integration/PROVENANCE.md)
and [guarded candidate record](cleanroom/ghash_integration/GUARDED_COMPARISON.md).
