# Fixed manual Linux and Windows validation

This administrative branch is based on main `6f129ec9f92ae0de32654d9eb078af5e16ee435d`
and reuses the already registered workflow path only through an explicit
`workflow_dispatch --ref codex/pr10-linux-windows-validation`. It has no push or
PR trigger, configurable source ref, arbitrary command input, privileged mode
operation, CPU selection, retry, release or publication step. Token permission
is `contents: read`; official checkout/upload actions are pinned to full SHAs.
The four matrix jobs have `fail-fast: false`. Their results are not substituted
for earlier failed runs.

The candidate is exact `c6377a42e8e30131692e305ca8e016d78def19f0`: the reviewed
b8 guarded/audit/documentation candidate, the c131 failure observer, and a
three-Markdown completed-result closure. All 197 production/Cargo inputs still
match c872. The diagnostic baseline is exact A3
`a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf`. Each source is checked out separately,
with separate native target directories, using non-cone sparse checkout to omit
only tracked `fuzz/corpus/`. All included Git blobs/modes and the candidate's
197 expected hashes are checked before and after; no synthetic source HEAD or
substituted `GITHUB_SHA` is used. Administrative HEAD must equal actual job HEAD
on the one declared branch. The workflow/admin head is distinct from both
source heads.

## Linux, matching the existing portable-crypto checks

Two `ubuntu-24.04` jobs select Rust 1.87.0 and current stable respectively.
Actual `rustc -vV`, resolved compiler ELF, Cargo, OpenSSL, Go and `lscpu` output
are retained. MSRV uses exactly
`--cfg pratique_portable -C target-feature=-aes,-pclmulqdq` and
`PRATIQUE_TIMING_SECS=3`. Stable uses default flags. Other repetition/clock/null
overrides and inherited target/encoded-flags overrides are rejected.

MSRV executes the existing debug crypto command, full release
`--all-features` suite, original AES ignored timing selector, original GHASH
ignored timing selector, and existing production primitive audit. Selectors,
three-second budget, clock/probe behavior, generators, crops, judge and test
assertions are unchanged. Stable executes the full release `--all-features`
suite. Both then execute `cargo package --frozen --all-features` on native Linux.
Each failed command is retained and later checks still run when source/process
identity remains valid; no failing test is retried. Standard Cargo's own stopping
behavior within a full-suite invocation is preserved and may leave later test
targets unrun after a failure.

Source crates, hashes and complete member lists are uploaded. Ordinary members
must match candidate bytes; Cargo's normalized manifest is distinguished from
the byte-identical `Cargo.toml.orig`. VCS metadata, when present, must identify
the clean candidate, and its absence is explicit with external source binding.
Required guard sources, original manifests/lock, LICENSE/NOTICE, root bundle and
clean-room provenance/attribution/current comparison documents must be present.
No release upload or crates.io action occurs.

## Windows ARM64 and x64

The fixed labels are `windows-11-arm` and `windows-2025`. Native Rust 1.97.0 is
selected explicitly as `1.97.0-aarch64-pc-windows-msvc` or
`1.97.0-x86_64-pc-windows-msvc`. Actual Rust host/release, resolved compiler PE
machine and every produced test PE machine must agree with that native target;
the runner label alone is insufficient. Python/runner/OS architecture fields
are separately retained.

OpenSSL must exist on PATH and its `version -a` must succeed before tests; no
installer or silent test skip is accepted. Its resolved path, binary hash, PE
machine and full version output are retained, and that directory is prepended
for every child. OpenSSL may be x64-emulated on ARM if supplied that way; this
is recorded separately and never described as native Rust or native OpenSSL
without evidence. Go availability/version is recorded but is not a required
Windows prerequisite. First-party image inventories are expectations, not
substitutes for these runtime records.

Each job builds the baseline's `interop_openssl` test once in the normal
test profile (`opt-level=2`), binds the one PE, then directly runs exactly
`a_server_that_accepts_only_nist_groups_makes_the_client_retry` once with
`--exact --nocapture --test-threads=1`. It repeats that fixed diagnostic once
for the candidate and then invokes the candidate's full default-feature release
suite once. Both exact diagnostics have the supported 45-second external cap;
the unchanged HRR assertion's 15-second deadline is not relaxed. A baseline
exit 101 does not suppress the candidate diagnostic or full suite. An identity
or build error produces explicit unmeasured slots, not a fabricated pass.

The full release suite naturally contains its normal HRR test in addition to
the two predeclared exact diagnostics; this is fixed in advance, not an
outcome-selected retry. Its existing deadlines/assertions remain unchanged.
All failures remain findings, including failures of the OpenSSL trace marker.
The observer changes bounded failure evidence only, never the predicate.

## Bounds, retention and interpretation

Job caps are MSRV 40 minutes, stable 30 minutes, Windows 40 minutes. Explicit
step caps sum to 36, 28 and 36 minutes respectively, leaving extra overhead
inside the job caps. Driver internal budgets are 28, 20 and 27 minutes; outer
driver steps allow one further minute to write records/copy bounded artifacts.
The command caps sum to 23m50s (MSRV), 18m (stable) and 25m30s (Windows), plus
bounded prerequisite probes. This is build/package/collection budget, not a
change to any test's acceptance or internal timing deadline.

Every phase has full separate stdout/stderr, exact argv/working directory,
timestamps, exit/timeout/cleanup state, footers and executable hashes. Selected
HRR/AES/GHASH test-binary before/after identity is enforced. Build phases may
legitimately add binaries and are classified separately. Zero-test/ignored-only
footers cannot pass an exact diagnostic. Partial logs are written before exit;
unsafe timeout cleanup or cancellation prevents later children. Process-tree
cleanup is bounded (`taskkill /T /F` on Windows, process group on Linux).
Abrupt VM loss or hard runner termination cannot guarantee final collection.

Relevant HRR/library executables are retained within explicit 80 MB per-file /
240 MB per-job bounds; discovered Cargo executables in target/deps are hashed
and any size-limited omission is named. Transient rustdoc executables are not
inventoried. No primitive disassembly is generated. Source
binding, compiler/flags, complete stdout/stderr, source-crate members and a
SHA256 file manifest are always uploaded when available. Artifact upload
success alone is collection, never a gate pass. The controller exits nonzero
for any failed/incomplete requested check. Summary counts are observational;
they do not reimplement or relax the original timing judge.

This campaign closes concrete feature/profile/platform/package validation gaps.
It establishes neither universal constant-time behavior nor causal CPU
classification. Earlier public findings, Windows failures, compiler-copy/
physical-erasure limits and the measured guarded performance cost remain in
the record. No main/PR10/version/tag/release mutation is part of execution.
