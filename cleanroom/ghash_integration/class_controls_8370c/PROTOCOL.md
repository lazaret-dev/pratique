# Exact attached class controls on one Xeon 8370C assignment

This is the user's requested exploratory diagnostic. It does not replace a production timing gate or explain any earlier failure. PR10 stays on hold. No sampler trace is added.

The diagnostic source starts at public commit 4848bea7c7e39b34ed1c74435823197dfd945cc4 and applies the exact attached patch (SHA256 96159ef4faec2bc3889d69b23fc41817f376394b16f5bf928501d07ee9f105b2). Its 97 added lines in src/crypto/timing.rs are unchanged. The resulting timing file SHA256 is 27eb52a9346b994a9c4fdfb59c7a74eef3eea16f57203fb145514a5e79956ffd. All other pre-existing tracked file bytes and modes remain identical to 4848. The added Python runner and protocol are administrative files only.

## Publication and model selection

GitHub requires a workflow_dispatch definition on the default branch. A separate main-based administrative change adds only that manual-only YAML. It hardcodes this reviewed diagnostic source commit; there are no configurable refs, commands or test inputs. This does not merge PR10 crypto into main. Workflow/default-branch identity and checked-out diagnostic-source identity are recorded separately; GITHUB_SHA is never replaced.

One manual dispatch allocates one Ubuntu 24.04 job. That same job records complete lscpu text/JSON and selection metadata before any checkout, Rust installation or compilation. It stops the test stages unless the reported model contains Xeon and the separate model token 8370C. Every nonmatching assignment retains its lscpu, skip reason, workflow/run identity and six unattempted slot declarations. The parent may manually redispatch solely to obtain the first matching assignment, as the user expressly requested. All skipped assignments are retained in the census. Once the first matching model is assigned, no replacement or outcome-selected redispatch is allowed, including after build failure, timeout, quiet results or incomplete collection.

This records an advertised CPU model, not a bare-metal guarantee. There is no new affinity, governor, feature-mask or SIMD-state intervention. The original one-test Rust harness uses one test thread. The public host and scheduling environment may differ between the original and control intervals.

## Build and fixed native order

The matching job checks out the immutable reviewed diagnostic commit with full history. Before building, run.py verify checks the exact source commit, raw-patch hash, patched timing hash, unchanged pre-existing source/tree entries, allowed additive paths and flags. The native build is one cargo test --release --all-features --lib --no-run --message-format=json invocation under Rust 1.87.0, with RUSTFLAGS exactly --cfg pratique_portable -C target-feature=-aes,-pclmulqdq. PRATIQUE_TIMING_SECS is exactly 3; forced repetition/tick overrides are absent. The job records rustc -vV, cargo version, build events/stderr, source inventories and the selected release test ELF path/size/SHA256. It runs that one ELF directly thereafter; no warm cargo rebuild is hidden between measurements.

The immutable six-call order is:

1. crypto::timing::ghash_multiplication_is_constant_time
2. crypto::timing::ghash_batch_class_controls
3. crypto::timing::ghash_multiplication_is_constant_time
4. crypto::timing::ghash_batch_class_controls
5. crypto::timing::ghash_multiplication_is_constant_time
6. crypto::timing::ghash_batch_class_controls

Every ELF call appends --exact --ignored --nocapture --test-threads=1. The three original calls retain all eight logical GHASH comparisons, automatic fresh rechecks, thresholds, crops and original judge. The three control calls retain the exact patch's seven rows, two always-measured seeds per row and unchanged judge. Calls continue after an original exit101, a control finding, a completed nonzero exit or a caught collector error. Each case has a 55-second outer safety cap; this does not change the three-second statistical budget. A timeout is incomplete evidence. The runner terminates and reaps its owned process group before the next call; an unsafe cleanup or job cancellation prevents overlap and leaves all later planned slots explicit and unattempted. Full combined stdout and stderr, case headers/commands/timestamps/exit codes and partial output are retained for every attempted call. No parsing or CSV export occurs between native calls.

The nominal statistical duration is 72 seconds for the three original sets plus their actual conditional rechecks (up to another 72 seconds), and 126 seconds for the three controls, plus the existing probe/warmup/overshoot and output costs. These are not hard duration promises. The separate workflow caps checkout/install/build/native/report phases and preserves an unconditional artifact-upload allowance within its job cap. A build failure runs no test and is never called a quiet result.

## Reporting contract

The parser reads complete logs, including expected panic text before buffered stdout. An original exit101 is a complete timing finding only with all eight rows, matching announced rechecks, one failed single-test footer and the unchanged final summary naming confirmed rows. Original maxima and signed crop displays are rounded: the parser does not replay the judge from rounded maxima or select a different crop after the fact. In particular, a large repeated p95 pair cannot replace an original strongest p99 that did not repeat.

The control test prints findings but normally exits0. Its exit0 is not a gate pass. A complete control collection requires all seven names in the exact order, two report records per row, seven signed t displays per report, exactly four mean/standard-error displays per report, one unchanged judge line per row and one successful single-test footer. The printed unchanged judge is authoritative; rounded values do not establish its exact full-precision calculation. Both seeds are known from the fixed patch call order, not an extra runtime observation. Actual reported reps, sample counts, medians and all available strings are retained.

The difference is class1 minus class0 per call in nanoseconds. Class1 is random and class0 is the row's fixed zero, all-ones, fixed pattern or fixed nonzero value. The raw patch prints signed t at one decimal and mean/standard-error at three decimals for keep1.0, keep0.95, keep0.75 and keep0.5. It does not print the other three mean/SE views, raw duration samples, input addresses, clock-probe choice or RNG state. Missing fields stay unavailable. Nonfinite tokens are retained as display strings with JSON null numeric values, never nonstandard JSON NaN/Infinity.

For complete collection, control-per-call.csv has 168 rows (3 iterations ×7 rows ×2 seeds ×4 views) and control-signed-t.csv has 294 rows (3 ×7 ×2 ×7). results.json retains all six parsed cases and all printed judge decisions. Partial collection exports every available record without pretending it is complete. SHA256SUMS.json binds all retained output files. No generic positive/identical negative/sensitivity control is added to the exact patch; control health is unmeasured, not passed. Statistical findings do not make the collector fail; malformed or incomplete collection does.

## Interpretation limits retained from the exact patch

The two rows called repro use different logical names from the production test. The DATA name has 35 characters rather than 45, and the prepared-H name41 rather than51. The existing harness seeds its RNG partly from the logical name length. Thus these controls do not reproduce the original RNG initialization, class order or fixtures merely because generator expressions match. The original and diagnostic dynamic clock probes can also consume different RNG inputs. No probe branch is inferred from tick0 or reps1, and no fixture fitting is performed.

The fixed DATA class writes RNG bytes and then adds a zero-fill, all-ones-fill or fixed-pattern copy; random keeps the generated bytes. Fixed prepared-H classes skip the random branch's temporary RNG Vec allocation and filling. The scalar H row stores a reflected scalar rather than the prepared-key object. Changed generic monomorphization, frame/layout, row order, always-seed1 work and between-row printing are additional observer differences. Zero versus nonzero timing differences are not automatically a CPU-only effect or harmless: these fixtures include secrets under the production threat model. Quiet controls cannot erase any earlier confirmed production timing failure, and this six-call job establishes no causal or security closure.
