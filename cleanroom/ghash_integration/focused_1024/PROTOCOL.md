# Abbreviated exploratory portable GHASH DATA1024 run

This runs exactly one existing ignored selector,
`crypto::timing::pr10_batch_data_controls`, from the independently reviewed
Linux ELF. No Rust source, compiler, crate build, Valgrind, AES, KEY, H128,
2049-byte comparison or sealed all-eight GHASH gate is run. The selector itself
is unchanged: three seconds per row/seed, seeds 0 and 1, five rows in order:
literal reference, identical bytes with asymmetric original history, equal-work
variable data, identical/equal-work negative, and matched positive. Its existing
generic sensitivity/early-exit checks and bounded four-round calibration remain.
The final matched-positive band stays 1.5–2.5%; false health is retained as false.

The immutable input is public artifact 13685577428 from run 42641304983,
115643042 bytes, ZIP SHA256
316b529d8fbcdcaa358b091ffe352ea8fd81aee99385db2fbd8e6fb725c1a144.
`frozen_identity.json` pins the complete original manifest, all thirteen original
source inputs, compiler flags and actual ELF hashes. The DATA companion is
d8a2f88724e6c535d81cb0f43832694ed6d92c8243e8904b805a29b2d7e50d97;
the same-core metadata probe is
0ec7429c0d44c19f8a8a2fdec1f6c98fe27c235fafd56c3b1653608b1fba830c.
The artifact diagnostic source head is 664ea2ce0d0ef61ada9f7704580d50f46738de53;
the production source compiled into it is exact e2dd9a91b3d2af6495faa6319fb5384c374dd82f.
Both remain separate from the new adapter/workflow job head. No environment SHA
is substituted and the old `prepare` function is never invoked.

The adapter verifies immutable archive/manifest/source/ELF bytes, selects the
first allowed native x86 Linux core, records CPU/features/XCR0, default libc
dispatch, library hash, environment and frequency metadata, and directly calls
the unchanged old `run_case(DATA)` helper once. This reuses its exact selector,
three-second environment, taskset, 170-second child timeout, early process-map
capture and original exit/status recorder. There are no model searches,
replacement hosts, masks or retries. Ubuntu 24.04 supplies glibc 2.39 required
by these exact existing ELFs; unsupported execution is retained as incomplete.

This is an explicitly authorized **ungated exploratory** invocation. The old
ignore annotation describes the earlier sealed-failure-triggered experiment;
that annotation is not a claim that this run met its old precondition. The
companion literal is always measured first. Sealed original co-reproduction
is **unmeasured**, so neither a quiet literal nor quiet counterfactuals exclude
earlier failures or establish security readiness. PR10 stays e2dd/HOLD. All
9V74/9V45/8370C failures and the unhealthy 8573C calibration remain evidence.
The broader reviewed A+B0 implementation remains local and deferred.

All ten CSVs, ten matching fixture files, literal/reference outcomes, unchanged
Rust judge/status records, full calibration history, child exit and partial
files are retained. The wrapper checks exact row/seed sets, complete 1024-sample
batches/16-sample class balance, matching measured/warmup fixture records,
original metadata, one successful Rust-test footer and exit0. The raw DATA
`fixture_h_value` field is an unused zero sentinel; actual fixed H is the
original nonzero fixture. Fixture validation is structural binding, not a new
claim to observe memory history or privately reconstruct a generator state.
The existing analyzer supplies descriptive signed random-minus-fixed statistics
without changing the original Rust judge. Completion and control health are
separate. Missing/malformed/incomplete data, a panic/timeout, failed sensitivity,
or out-of-band final calibration cannot become passing evidence. Partial uploads
are unconditional. No stage is a pure instruction-latency claim; prior cache,
store and register history remain possible influences.

Only the new `codex/pr10-ghash-1024-focused` branch triggers this workflow.
One default Ubuntu 24.04 job has a ten-minute cap. Pre-upload step caps total
nine minutes: checkout1, source-only fixtures1, artifact staging/metadata2,
measurement3, analysis2; one nominal minute remains for upload/overhead. The
actual timed row budget is thirty seconds plus existing health/calibration work.
There is no build or analysis alongside measurement. Independent exact adapter,
workflow and immutable-identity review precedes any publication/native run;
runtime artifact/outcome review precedes interpretation. Local validation only
stages inert bytes and executes owned source-only schema fixtures, never the
downloaded ELFs or other archived code.
