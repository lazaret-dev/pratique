# Two exact GHASH diagnostic patches on the first selected 8370C

This branch is an exploratory follow-up to run42733158775. It starts at exact diagnostic9ba854cf5b793f5ff9525964d58519018ed9f275 (production base4848bea7c7e39b34ed1c74435823197dfd945cc4 plus the exact first user patch). It adds the exact second user patch and changes only diagnostic administration beyond it. No production expression, public API, threshold, crop, original judge or original measurement loop is changed. No sampler trace, masking, MSR operation or DOITM intervention is added. PR10 remains on hold.

## Source and manual registration

The first raw patch SHA256 remains96159ef4faec2bc3889d69b23fc41817f376394b16f5bf928501d07ee9f105b2; its timing module hash is27eb52a9346b994a9c4fdfb59c7a74eef3eea16f57203fb145514a5e79956ffd. The second raw patch SHA256 isf9c4e6c4aba2e6d249ba8865dc9264847847be2e41a7ac7de6b64c78546e9b4e. It adds63 lines and removes none, only in src/crypto/timing.rs. The combined timing module hash ise87ac2fab8366e8977f981f645c51c798c9454d4dae105a362074b425117fe43. Both raw inputs are retained unchanged here. Removing each exact insertion recovers its exact preceding timing module.

The existing workflow path .github/workflows/pr10-ghash-8370c-class-controls.yml is already registered on default main6f129ec9f92ae0de32654d9eb078af5e16ee435d as workflow412738401. A separate workflow-only branch based on that exact main commit changes this existing YAML to the fixed nine-call contract and hardcodes the reviewed new diagnostic source commit. It is manually dispatched with ref codex/pr10-ghash-8370c-intermediate-workflow. The job guard accepts only that exact ref. No new main merge or PR10 source change is required. There are no configurable refs, commands, selectors or budgets in the workflow. Workflow-branch HEAD and checked-out diagnostic HEAD are different recorded identities; GITHUB_SHA is never impersonated.

The parent owns publication and the CPU-only dispatch controller. The campaign is capped at20 sequential assignments, stops after the FIRST reported Xeon8370C, and retains every skipped assignment. The first matching assignment ends selection even if checkout, build, capture or measurement fails or is incomplete. There are no outcome-selected retries, replacements, alternate models or repeat campaigns under this plan. Each assignment captures lscpu text/JSON, proc/cpuinfo, uname and selection metadata in the SAME job before checkout or compilation. Nonmatching models skip checkout/compiler/tests and upload those records plus nine unattempted slot declarations. No CPU affinity, governor or feature mask is changed.

## One build and nine fixed calls

On the selected host, verify binds the immutable diagnostic commit, both raw patches, combined timing hash, all source inputs and flags. All pre-existing production/base files and modes other than the two additive timing insertions remain unchanged. Build once with Rust1.87.0 and:

    cargo test --release --all-features --lib --no-run --message-format=json

RUSTFLAGS is exactly --cfg pratique_portable -C target-feature=-aes,-pclmulqdq. PRATIQUE_TIMING_SECS is exactly3. Forced reps/tick overrides and CARGO_ENCODED_RUSTFLAGS are absent. rustc-vV, cargo version, source hashes, compile output and selected ELF path/size/SHA256 are retained.

Before any native timing, capture_linked.py copies the SAME compiled ELF as inert artifact data and captures tool versions, raw/demangled symbols and bounded relevant timing/GHASH/clock disassembly. It never executes the retained copy. ELF is capped60MB, each symbol listing5MB, selected disassembly16MB and the pre-timing output payload90MB, below the100MB collector limit. Omitted symbols and label/coverage limits are explicit; the complete ELF permits later read-only inspection. The capture helper does NOT certify that hashes remain inside timers. An independent actual-linked loop/ctor/drop review must establish that before interpreting the hot-key stages. This fixed compiler/capture observer work finishes before the native window; none runs concurrently or between calls.

The same original compiled ELF is directly invoked in this predetermined order:

1. original gate, iteration1
2. first-patch controls, iteration1
3. intermediate controls, iteration1
4. original gate, iteration2
5. first-patch controls, iteration2
6. intermediate controls, iteration2
7. original gate, iteration3
8. first-patch controls, iteration3
9. intermediate controls, iteration3

The exact selectors are crypto::timing::ghash_multiplication_is_constant_time, crypto::timing::ghash_batch_class_controls and crypto::timing::ghash_batch_intermediate_controls. Every call appends --exact --ignored --nocapture --test-threads=1. The original keeps all eight GHASH rows and its conditional fresh rechecks; each print-only test always measures seeds0 and1 in its original control_row helper. A confirmed diagnostic row normally still exits0. Original exit101 with a complete unchanged final summary is an expected timing finding, not a collector failure.

All nine calls are attempted regardless of earlier0/101 findings or collector errors while immutable staging remains valid and process cleanup is safe. Each child has a55-second safety cap, preserving the existing three-second statistical budget. Each owned process group is terminated/reaped before the next; unsafe cleanup or cancellation leaves later slots explicitly unattempted rather than overlapping them. Full merged stdout/stderr, exact commands, timestamps, per-case exits and every partial output are retained. No parsing, CSV export, disassembly or ELF checksum occurs between native calls. The reviewed runner compares the ELF digest before and after the whole window.

Nominal statistical time is270seconds for three original sets without rechecks plus both print-only sets, up to342seconds if all eight original rows recheck each time, before existing warmup/probe/overshoot costs. This is not a hard runtime promise. The job cap is25minutes; step caps are CPU1, checkout1, install2, build/capture6, native9, report1 and upload2minutes:22total with3minutes additional overhead. The nine55-second child caps plus bounded cleanup fit the nine-minute native phase. Every stage and artifact remain visible on failures. Job success is collection status, never a timing-gate pass.

## Four new rows and their limitations

All differences are class1 minus class0 per call in nanoseconds. The actual class meanings are stored per report and CSV row, rather than calling every comparison random versus fixed:

| New row | Class0 | Class1 | Timed operation and limits |
| --- | --- | --- | --- |
| Hot H0 versus nonzero | index0 selecting retained zero-H key | index1 selecting retained fixed other nonzero-H key | Index/bounds/address selection and hash are inside the timer. Keys and shared DATA are constructed outside. Prepared once does not guarantee every cache line is hot. |
| Two hot nonzero keys | index0 selecting retained fixed-H key | index1 selecting retained fixed other-H key | A separate two-key array/base, different row name and RNG schedule. This is a useful comparison, not an exact address/value crossover or a proof that addresses never contribute. |
| Repeated word DATA | one random8-byte word repeated128times | full random1024-byte DATA | Both initially generate1024 RNG bytes. Class0 then adds128 copy stores. Equal halves/lane patterns and prior write history both change; a flag alone does not localize an arithmetic cause. |
| Zero DATA with varied H | prepared fixed other nonzero-H key | prepared random-H key | Shared1024 zero DATA in both classes, with nonempty AAD and length processing. Per-sample preparation and key Drop/deallocation are outside the timer; random-H RNG/heap history remains asymmetric. Internal hash workspace cleanup stays timed. |

The second patch prints one fresh Clock::new().coarse_tick() call before its rows. The parser retains that exact None or Some(tick) display as one observation. It is NOT the actual branch choice of any earlier or later measure_seeded call. A repetition count1 or fine-grained median does not reconstruct those unobserved branches. There are no new live draws, private RNG getters, fixture fitting or raw-sample hooks.

The exact first patch's seven logical names and generators remain unchanged, including its35/41-character repro names versus the original45/51-character names. Name-length-derived RNG initialization therefore differs from the original reference, even when generator expressions match. New row names and operations have their own fixture/probe contexts. Fixed-pattern copying versus zero/ones filling, prepared-key class histories, static arrays, generic code placement, frame/heap layout and retained object lifetimes remain observer differences. A quiet comparison is non-confirmation at this budget, not an equivalence bound, proof of no realistic-key effect, harmless CPU classification or merge waiver. H0 remains in the original gate. No masking design or informational-row reclassification is implemented.

## Complete and partial result contract

The parser consumes full logs, including expected assertion text before buffered stdout. It requires all eight original row names, matching announced rechecks, one appropriate single-test footer and the unchanged final summary; rounded maxima never select a new crop or reconstruct its judge. It retains all first/repeat reports and final reasons, including unconfirmed rechecks.

For first-patch controls, each call requires seven names/two reports each, and for intermediate controls four names/two reports each. Both require all seven signed t displays, four mean/SE displays, one printed unchanged judge per pair and one successful single-test footer. Intermediate controls additionally require exactly one printed fresh coarse_tick observation, irrespective of its value. All prints retain original rounding: one decimal for t, three for means/SE at keep1.0,0.95,0.75,0.5. No other means, raw durations, RNG states, per-sample addresses or CPU IDs are invented. Nonfinite displays remain strings with null numeric values in strict JSON.

A complete artifact has nine canonical case slots, three original invocations,42 first-patch reports and24 intermediate reports:66 control reports,33 pair-judge decisions,264 mean/SE CSV rows and462 signed-t CSV rows. CSV group and per-row class descriptions prevent sign/selector ambiguity. Completeness also requires exact source/binary/window bindings; missing, malformed, reordered, duplicate or mismatched records are incomplete. All available partials remain retained. SHA256SUMS binds output files. Print-only tests add no calibrated positive/identical negative health set, so no generic health pass is claimed.

Every numerical outcome stays exploratory until the exact same-built ELF and relevant timed loops are independently reviewed. No native result here erases earlier public/private failures, establishes an instruction-level mechanism, or changes PR10's HOLD status.
