# One current-main / prospective-test-fix Windows pair

This manual-only administrative branch is `codex/pr10-windows-main-interop-pair`,
based on frozen follow-up admin001a8cc4. It reuses the already registered
`.github/workflows/pr10-ghash-8370c-class-controls.yml` path with branch-ref
workflow dispatch. There is exactly one windows-2025 job, no matrix, inputs,
CPU selection, retry, Linux job, release/publication step or default-main change.
The token is contents:read; official checkout/upload actions stay full-SHA pinned.

## Fixed sources and scope

The first immutable source is current main
`6f129ec9f92ae0de32654d9eb078af5e16ee435d`. Its existing interoperability target
has exactly52 tests. It is neither patched nor relabelled as A3.

The second immutable source is
`850be15094c6717cfd525c61f60a63f51b16caa2`. Its ancestry is reviewed c637,
release auxiliary100dd, binary-file-serving patch2f9 and the failure observer850.
All197 production/Cargo inputs still match c872. The ten existing -WWW argument
lists add the documented -http_server_binmode option. There are no -HTTP sites;
lowercase -www status-page sites stay unchanged. Payloads, positive byte
assertions, waits, socket deadlines and skip behavior are retained.

The observer gives each s_server a new create_new stderr file instead of null.
When its existing Server owner drops during panic unwinding, it obtains a
nonblocking child status BEFORE the original unconditional kill+wait. After
cleanup, it seeks to the last4096 file bytes, reads at most4096, then converts
lossily to UTF-8. Empty data and read errors remain distinct. Diagnostic Write
errors are ignored to avoid a second panic. It launches no new subprocess and
changes no stdin/stdout data path, command flags, payload or deadline. Existing
OCSP responder stderr remains null. Temporary files have the existing Fixture
lifetime; only the bounded failure text is retained in the test logs.

The original hosted c637 full-suite failures, matched A3/c637 release pair, and
private HRR failures are retained. The new option remains prospective until this
job measures it; the observer is evidence collection, not a timeout fix. In the
preceding A3/c637 pair both versions completed39pass/13fail. That result bounds
the newly guarded candidate versus A3, not whole-PR10 versus main. This new main
control addresses that attribution gap. Because the candidate also has explicit
test-harness differences, the pair cannot uniquely attribute every changed
result to production crypto.

## Exact execution

One windows-2025 worker uses native Rust1.97.0-x86_64-pc-windows-msvc and empty
RUSTFLAGS. Actual rustc-vV, compiler PE/Cargo/OS architecture and resolved OpenSSL
path, PE/hash and version-a are retained. OpenSSL must execute successfully;
missing OpenSSL is an explicit prerequisite error, never a silent test skip.
Inherited encoded flags, target directories and timing overrides are rejected;
PYTHONDONTWRITEBYTECODE=1 is mandatory for all descendants. No tool is installed
beyond the fixed Rust toolchain already used by the preceding pair.

Main then850 have separate non-cone sparse checkouts and target directories.
Only tracked fuzz/corpus is omitted. Each source's existing interop_openssl
release test executable is built once using:

    cargo test --release --target x86_64-pc-windows-msvc --test interop_openssl --no-run --message-format=json

The selected PE is verified against the native target, then invoked exactly once
with --nocapture, no filter and no test-thread override. Actual inherited
RUST_TEST_THREADS is recorded. All52 tests must be accounted for by one
consistent footer (pass+fail52, ignored0) and child exit. An ordinary main
assertion failure101 does not suppress850 when staging and cleanup remain safe.
No outcome triggers a rerun, substitute source or additional test. Timeout,
abort or partial footer stays incomplete. Existing internal assertions and
deadlines are unchanged. There is no full-crate, timing, AES/GHASH selector,
extra exact-HRR invocation, baseline A3 repetition, CLI workaround, proxy or PTY.

## Identity, retention and fixed limits

All included source blobs/modes are checked against their exact immutable Git
objects, and candidate197 hashes against the unchanged reviewed inventory.
Administrative workflow HEAD/ref is separate from both checked-out source heads;
no GitHub SHA is impersonated. Source binding is checked again after the window.
Every build/invocation retains full stdout/stderr, argv, timestamps,
exit/footer/timeout/cleanup flags and before/after binary identities.

Available test binaries are retained with verified hashes under the inherited
80MB/file and240MB/job limits; each omission is named. Post-binding errors do not
discard partial logs or safely bound binaries. Job success requires all requested
checks, while artifact upload is unconditional. There is no reset/allow-dirty,
assertion waiver or suppression. Unsafe post-spawn cleanup stops later children
rather than overlapping native processes.

Build caps remain360s each; each target cap remains720s. These are external
collection ceilings, not longer socket or test deadlines. The inherited driver
cap is38min, workflow call39min and job50min; explicit workflow steps total47min,
leaving upload/overhead reserve. Neither the dormant inherited Linux audit/package
plan nor any other selector is used by the single fixed workflow job.

No result from this diagnostic alone establishes release readiness, universal
constant-time behavior, a CPU mechanism or erasure of compiler-generated copies.
PR10 HOLD and all historical failures remain until separately assessed.
