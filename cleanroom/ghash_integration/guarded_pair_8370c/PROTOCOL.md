# Fixed software comparison on the first Xeon8370C

This manual-only administration compares immutable A3 baseline source with a
separately reviewed guarded software candidate. `config.json` is frozen before
publication. No production code, statistical threshold, test generator or judge
is changed by this administration. No privileged CPU register is read or set.

Select by reported CPU model only, at most40 sequential assignments. A mismatch
records eight host metadata files and performs no checkout/build/native work.
Stop at the first reported8370C regardless of build, test or collection outcome;
never replace it because a measurement is inconvenient. Retain every skip.

On that one host, build each immutable source once with Rust1.87.0, all features,
release optimization, `--cfg pratique_portable -C target-feature=-aes,-pclmulqdq`
and the unchanged three-second test budget. All timing.rs bytes must match A3.
Retain both exact ELF files, input inventories, compiler identity and relevant
linked-code evidence before testing. Constructors, calls and cleanup require
independent review of those actual ELFs after collection.

Before timing, execute each exact ELF's existing unignored `crypto::` correctness
group once; require a complete successful footer with nonzero passes. Timing
and profile tests remain ignored in that group. After the twenty timing calls,
run each ELF's existing `crypto::integration_profile::release_profile` once to
obtain matched native performance. These four auxiliary invocations are stored
separately from the twenty timing slots, bounded at60seconds each, and do not
recompile or introduce new tests. The profile uses its exact ignored selector;
it does not supply a new timing or performance judge.

Run five predetermined rounds. Baseline then candidate in rounds1/3/5;
candidate then baseline in rounds2/4. Within each version run the original
`ghash_multiplication_is_constant_time` then `ghash_batch_hot_key_swap_controls`.
This makes twenty calls total and alternates gate/swap within each version.
Use the exact original selectors and `--exact --ignored --nocapture
--test-threads=1` arguments. Each call is bounded at55seconds. Failures remain
results; they do not stop later slots. Cancellation or unsafe process cleanup
stops later work and makes the collection incomplete. No call is retried.

Keep all stdout/stderr, exact argument vectors, source and before/after binary
hashes, timestamps and exit codes. The frozen A3 administrative parser preserves
the existing Rust judge and signed per-call figures. Derive value/slot contrasts
separately for each source and round; never combine versions or confuse seeds
with independent repetitions. The covariance limitation on derived standard
errors remains unchanged. No new statistical judge is introduced.

A complete collection does not itself declare security closure. The intended
comparison is repeated current-behavior reproduction and quiet candidate gates
on the same host, supported by correctness/lifecycle and compiler-retention
review. Failure to reproduce the baseline limits any mitigation conclusion;
candidate failures must be retained and investigated without threshold changes.
