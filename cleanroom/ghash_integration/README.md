# Portable AES/GHASH integration validation

The independently authored quadratic-field AES S-box is integrated. This
experimental candidate uses fifty payload blocks and fourteen fixed public guard
lanes per portable GHASH batch on 64-bit targets, with the exact public-product
correction removed before reduction. On 32-bit targets it uses the accepted
scalar GHASH recurrence throughout. Hardware kernels retain their existing
behavior. See [GUARDED_COMPARISON.md](GUARDED_COMPARISON.md) for the current
representation, ownership and evidence limits. The earlier integration measurements
passed all four requested portable throughput gates; its same-process hardware
comparison was within 1.51 percent of baseline. These are historical results,
not measurements of the later working-state cleanup or guarded candidate. The
accelerated kernels retain their existing source. Public
key sizes remain AES-128 and AES-256; this repository does not expose AES-192.
No dependency or public API change is included. The lifecycle follow-up amends
the obsolete current-code NOTICE entry after the scoped source/history/package
audit in [ATTRIBUTION_AUDIT.md](ATTRIBUTION_AUDIT.md); unrelated notices and
LICENSE are retained.

**Timing remains on HOLD.** Earlier confirmed native GHASH timing findings are
unresolved. Guarded-candidate validation on the problem Xeon 8370C is pending;
local correctness and circuit/code-generation checks do not predeclare its
outcome or establish whole-path timing independence. The November 9
[working-state repair](WORKING_STATE_REPAIR.md) closes a separate source-owned batch-buffer cleanup gap using committed clean-only
API `27a1c8ac`. Its local correctness, lifecycle and code-generation checks do
not close those timing findings. The original timing test, threshold, crops and
CI gate are unchanged. No new throughput claim or performance campaign is made
for this repair; the owner's performance follow-up remains issue #11.

**Existing default-x86 compiler limitation:** the unchanged ChaCha AVX512 path
already fails with Rust 1.87 (79 errors, reproduced on the baseline). Native
x86 CI therefore checks full software debug/release/timing/assembly with Rust
1.87 and default hardware/full release behavior with stable Rust. A default
x86 Rust 1.87 build is not claimed to pass. No ChaCha kernel or build-system
compatibility change is included in this AES/GHASH work.

## Historical 64-lane integration evidence

The following measurements and lifecycle description refer to the earlier
64-payload path. They are preserved as historical evidence, not substituted for
new candidate measurements.

**Historical key-setup tradeoff:** eager portable preparation and
wiping cost 8.44 microseconds for AES-128 and 8.89 microseconds for AES-256,
compared with 1.50 and 1.90 microseconds in the baseline. The prepared operand
holds 1,536 bytes of secret planes per key. Preparation is amortized by the key
lifetime. The lifecycle repair borrows the caller-owned raw powers and populates
all 192 planes directly inside the retained key field, with in-place transpose.
The raw power array and running scalar receive volatile wipes; retained stored
words and cloned keys follow the existing destruction lifecycle. Final object
moves and compiler-created register/stack copies remain best effort, as stated
by `Zeroize`; this does not guarantee complete physical erasure. The initial
value-taking preparation path's explicit scratch arrays were a real gap and
were removed by the separately committed borrowed API and integration repair.

The original 64-lane integration started exactly at
`2a1d85533505499bffe4b3990921321d2bb0658f`. Both accelerated AES kernels and
existing scalar reduction/composition were preserved. Portable full groups of
64 blocks use prepared powers, with the incoming state folded into the first
block; remaining blocks and partial padding use the accepted scalar primitive.
AAD and ciphertext keep their independent padding and original length framing.
The superseded portable S-box and multiplication expressions were deleted.

The clean-only publication ancestry is
`2a1d8553 -> bede170a -> 5e5c9ab9 -> 781ffb62 -> b33b45e1`, followed by the
separate integration commit. The original integration evidence history is kept
in the temporary integration repository. The publication tree is checked for
identity with the reviewed integration tree. See [PROVENANCE.md](PROVENANCE.md),
[the primitive provenance](../clmul_feasibility/PROVENANCE.md), and
[the S-box derivation](../aes_tower/DERIVATION.md).

The measurements and validation counts below record the initial draft. Earlier
preparation-lifecycle follow-up results are in
[lifecycle_results/SUMMARY.json](lifecycle_results/SUMMARY.json).
The initial measurements use decimal MB/s on Apple ARM64. Throughput is the
median of seven calibrated windows; keys are created outside the timed seal.
The final software build explicitly uses `--cfg pratique_portable` and
`-C target-feature=-aes`; its profile reports AES hardware unavailable and the
runtime platform timing guard available.

| Cipher / size | Baseline MB/s | Integrated MB/s | Required MB/s |
| --- | ---: | ---: | ---: |
| AES-128-GCM / 1 MiB | 241.99 | 219.74 | 179.33 |
| AES-128-GCM / 16 KiB | 239.02 | 223.54 | 177.90 |
| AES-256-GCM / 1 MiB | 197.18 | 182.85 | 145.80 |
| AES-256-GCM / 16 KiB | 196.29 | 182.83 | 144.98 |

The initial component profile identified AES as the limiting cost: wiring the
accepted first S-box alone put CTR below the GCM gates. The clean-room author
then supplied the committed tower circuit. Integrated long-message GHASH is
approximately 1 GB/s; AES remains the largest cost. Initial and intermediate
measurements remain in `results/`.

A same-process, alternating-order comparison used both baseline and integrated
Rust 1.87 libraries and 17 paired windows. Hardware seal changes were -0.22%
(AES-128, 1 MiB), -1.50% (AES-128, 16 KiB), +1.13% (AES-256, 1 MiB), and
+0.42% (AES-256, 16 KiB). `paired_hardware.rs` uses only public APIs. Its
baseline source/library stays outside this shipped tree. Separate-process
measurements showed clock drift, so the paired comparison is the hardware gate.

An additional forced-software timing run found repeatable GHASH differences
when the broad portable configuration disabled ARM's existing DIT guard. The
integration now retains the runtime-checked timing guard independently of
cipher acceleration, including key-power preparation inside public key setup.
The primitive expressions did not change. CPUs without DIT retain the existing
portable fallback. The pre-fix failure is preserved. With the production guard
active, unchanged release timing thresholds pass: native AES/GHASH maximum
absolute t values are 2.5/2.8; forced-software AES/GHASH are 2.1/2.0. The added
batch screens cover message classes and prepared-H classes at 1,024 and 2,049
bytes, with preparation outside the timed batch operation.

Validation completed before draft publication:

- Rust 1.87 ordinary debug crypto: 172 passed; the generated circuit's excessive
  debug-scope depth was fixed by the clean author without changing its ordered
  gate expressions. Both copied production circuit files match their clean
  source byte for byte.
- Rust 1.87 release, all features, native and forced software: each has 1,856
  passed, zero failures, and 26 existing ignored tests across 21 binaries.
  This includes NIST vectors, portable/hardware parity, TLS, authentication
  failure, every-byte/every-lane S-box tests, and new batch/state/padding tests.
- OpenSSL 3.6.5 interoperability passes all 52 tests. OpenSSL 4.1's session-ticket
  assertion fails identically on the unchanged baseline and integrated tree;
  both reproductions are retained. The suite uses the installed OpenSSL 3 oracle.
- Production primitive assembly is checked with Rust 1.87 on Apple ARM64,
  x86-64 Linux, i686 Linux, ARMv7 Linux, RISC-V64 Linux, and WASM, and with stable
  on Apple ARM64, x86-64 Linux, and WASM. No multiplication/division instructions
  occur. Branches use public loop/shift counters; indirect x86 calls select
  fixed memset/memcpy symbols. Fixed-size runtime helpers and public-counter
  WASM shifts are recorded for review. This is structural evidence, not proof.
- Whole-crate Rust 1.87 cross checks pass on x86-64, i686, ARMv7, RISC-V64 Linux,
  and the existing no-default-features WASM configuration. Standalone primitives
  also compile as no_std with unsafe code forbidden and no allocation.
- Three 60-second coverage-guided campaigns completed: AEAD 791,168 executions,
  TLS post-handshake 1,149,440, TLS flight 210,048. No distinct panic or bloat
  input was found. The AEAD seeds and length cap cover both sides of the batch
  threshold and a second full batch.
- Contained Linux ARM64: 187 crypto and 169 TLS tests pass. Native Windows ARM64:
  182 crypto and 161 TLS tests pass. The runner wrapper preserves the source,
  tests, manifest, and other source subtrees exactly beneath `rust/`; only the
  fuzz corpus is excluded. `results/runner-source.json` records the identities.

Windows x64 emulation also passes 183 crypto and 161 TLS tests. Real native
x86-64 CI is pending at initial draft publication. The local workflow
`.github/workflows/portable-crypto.yml` uses native Ubuntu 24.04 x64 for MSRV software debug/full-release/timing/assembly
and stable default full-release/hardware-parity checks. The release timing
thresholds are unchanged. Its checkout
pin was verified against the official actions/checkout v4 ref. Draft status
is retained until those results and the remaining review are complete.

Reproduce the component/throughput profile with the ignored
`crypto::integration_profile::release_profile` test in release mode. Force
software kernels with `RUSTFLAGS='--cfg pratique_portable -C target-feature=-aes'`
on ARM64, or `-aes,-pclmulqdq` on x86-64. Run timing tests sequentially on a quiet
host with `--ignored --nocapture --test-threads=1`, using
`crypto::timing::aes_is_constant_time` and
`crypto::timing::ghash_multiplication_is_constant_time`. Run
`python3 cleanroom/ghash_integration/audit_primitives.py --toolchain 1.87.0`
with repeated `--target` arguments to repeat the assembly checks.

The logs retain every reported result and failure; terminal empty lines and trailing whitespace are
normalized for repository whitespace checks. The initial draft preceded the scoped NOTICE amendment described above. This
follow-up includes that audited amendment; no merge, re-vendor, release, or legal
originality guarantee is included.

The historical preparation-lifecycle continuation starts at public head `32615a80`,
merges independent API commit `5ecf2525`, and wires it in `3db15f54`. Its unique
integrator identity and logical workspace/session are reconciled in
`CLEAN_ROOM_AES_GHASH.md` and the integration provenance. Source-owned preparation
arrays are checked separately from retained-state wiping. Performance issue #11
remains a nonblocking follow-up; this repair does not change its disposition.


## Guarded candidate and administrative audit continuation

The current clean source chain is `27a1c8ac -> 40471873 -> 9f8a17c4 -> 26af8b77`,
merged unchanged before production integration `c87285bc`. The separate audit-only
commit `ce5c1794` recognizes the borrowed fifty-lane API and zero-first RAII
cleanup without changing any production/Cargo or timing input. It preserves the
legacy sixty-four-lane checks. [LIFECYCLE_AUDIT.md](LIFECYCLE_AUDIT.md) separates
source-graph regressions, primitive-wrapper emission and actual whole-crate
normal/unwind evidence. Earlier failed checks remain recorded as failures.

The guard witness is finite, and reviewed compiler output binds only its exact
source/toolchain/flags. The same source-owned raw/work cleanup obligations remain.
An optimized Clone can create a prepared-field temporary and API-return copies;
those compiler-created copies are outside the source-owned workspace contract.
No complete physical erasure, timing/security closure, merge or release readiness
is asserted. All earlier native failures remain evidence, thresholds and judges
are unchanged, and the paired 8370C candidate result is pending.
