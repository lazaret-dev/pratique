# Fixed two-job validation follow-up

This manual-only administrative branch is `codex/pr10-validation-followup`,
based on frozen d06d241d. It reuses the registered
`.github/workflows/pr10-ghash-8370c-class-controls.yml` path with branch-ref
workflow dispatch. No main/PR10 change or default-branch registration is needed.
There are exactly two jobs, with no matrix, configurable refs/commands, CPU
selection, retry, stdin workaround, release or publication step. Token access
is contents:read; official checkout/upload actions remain full-SHA pinned.

The preceding four-lane run42863610327 remains failed evidence. Its MSRV crypto,
full release, AES, GHASH and audit commands passed; packaging failed after an
in-source generated JSON and three untracked Python caches. This follow-up
neither reruns those successful runtime checks nor resets/deletes that evidence.
The hosted Windows full suites each retained13 OpenSSL interoperability
failures; their attribution requires a matched full-target baseline pair.

## Linux MSRV audit and source package only

One ubuntu-24.04 job checks out immutable release auxiliary source
`100dd05739eecbe7695d7a495e5197e447239f28`. It is c637 plus only cache ignore
rules and precise1MiB GCM seal labels. All197 production/Cargo and every test
remain byte-identical to c637/c872; the separate dedicated-msgfile diagnostic
is excluded. There were zero tracked caches to delete. The ignore rule is
hygiene, not a claim that Cargo1.87 accepts an ignored dirty fixture.

Rust1.87.0 and `--cfg pratique_portable -C target-feature=-aes,-pclmulqdq`
are fixed. `PYTHONDONTWRITEBYTECODE=1` is mandatory for ALL descendants;
`CARGO_ENCODED_RUSTFLAGS` presence, even empty, and other target/clock/repetition
overrides are rejected. No runner framework is changed. The existing audit is
invoked as `python3 -B .../audit_primitives.py --toolchain 1.87.0 --output`
with an absolute artifact-directory JSON destination. Primitive/audit source
bytes and assertions remain unchanged. Neither source reports nor bytecode are
written into the canonical checkout. No --allow-dirty or evidence reset occurs.

Then `cargo package --frozen --all-features` verifies a native Linux source
crate. Retain archive SHA256, full member hashes, clean source/Git binding and
required clean-room provenance/attribution/guard files/LICENSE/NOTICE/roots.
Distinguish Cargo's normalized manifest from exact Cargo.toml.orig. VCS metadata,
when supplied, must name the clean source commit; absence is explicit and the
external content binding remains authoritative. No crate is published.

No library, crypto, timing or interop runtime selector is run in this Linux job.
OpenSSL and Go are not prerequisites for the audit/package-only scope.

## One Windows x64 baseline/candidate interoperability pair

One windows-2025 worker uses native Rust1.97.0-x86_64-pc-windows-msvc and default
Rust flags. It retains actual rustc-vV/compiler PE/Cargo/OS architecture and the
resolved OpenSSL path, PE machine/hash and version-a. OpenSSL must run; no silent
have_openssl skip is accepted. This job's sources are A3
`a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf` then c637
`c6377a42e8e30131692e305ca8e016d78def19f0`, not the auxiliary source.

Each has a separate checkout and target directory. Build exactly its existing
release `interop_openssl` test executable once with no-run/message-format=json
and explicit x86_64-pc-windows-msvc target. Verify PE identity/target, then invoke
that executable once with --nocapture, no filter and no test-thread override.
A3 executes first, then c637. Preserve default parallelism and record inherited
RUST_TEST_THREADS rather than inventing thread metadata. Every existing positive
assertion and internal socket/wait deadline remains unchanged. Each invocation
must account for all52 tests (pass+fail52, ignored0) and a consistent Rust footer
and child exit before it can count as complete.

A baseline assertion failure101 does not suppress the candidate when immutable
staging and process cleanup remain safe. There is no rerun after any outcome.
Standard test-binary behavior continues its complete52-test target after ordinary
panics; a timeout/abort/partial footer is retained as incomplete. No full crate,
ARM lane, exactHRR extra diagnostic, stdin adjustment or proposed binary-file
server option is added to this pair.

## Binding, partial results and caps

All source includes are verified against the exact Git blob/mode; candidate197
production/Cargo hashes remain pinned. All non-cone sparse checkouts omit only
tracked fuzz/corpus. Administrative job HEAD/ref is separate from the immutable
source heads. The source is checked again after the window; post-binding or
package failure cannot discard other logs or safely hash-bound binary files.
There are no cleanup resets. Report each case independently with full stdout,
stderr, argv, timestamps, exit/footer/timeout/cleanup flags and before/after PE
hashes. Any source mismatch, partial52 count, inconsistent footer/exit or missing
critical binary makes collection incomplete. Partial metadata remains explicit.

Audit/package have180s/360s command caps; Linux driver11min/outer12min and job20min.
Windows builds retain360s each and targets720s each, matching the previous
hosted full-release command cap. Driver38min/outer39min and job50min include both
builds and target calls. Explicit workflow steps total19/47min respectively,
leaving upload/overhead reserve. These are collection/build ceilings, not relaxed
test assertions or timeouts. No empirical timing criterion is changed or used.

Process groups/taskkill are bounded; cancellation or unsafe post-spawn cleanup
stops later children. Source/package errors still permit final retention of
previously verified outputs. Available relevant binaries are copied with SHA256
verification within the existing80MB/file,240MB/job bounds; every omission is
named and makes complete-binary retention false. Always upload full or partial
records/crates/binaries plus manifest. Job success requires every requested check;
artifact upload alone is collection. Prior findings and erasure/performance
limits remain, with no universal security or release-readiness inference.
