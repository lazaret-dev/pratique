# Exact hot-key-swap diagnostic: six fixed calls

This campaign applies the exact third user patch on exact d9a8983b69cadde904f07ba5289562a61bfdcacd, which already retains the first two exact patches and production base4848bea7c7e39b34ed1c74435823197dfd945cc4. Third patch SHA256:8b8a5be70d99ef7f32ac3ddf7d24e151288bf1abbd5faca0033b2d516252ccd3. It adds54 lines, removes none, only in src/crypto/timing.rs. The resulting timing hash is11f3d7da0bdfc636443f3b569836f879cb9fc267fed54ad344e5fafbff9b20a4. No existing production code, API, timing loop, threshold, crop or judge is changed. No sampler trace, masking or MSR/DOITM operation is added. PR10 remains on hold.

## Registered manual workflow and bounds

Reuse registered workflow412738401 at .github/workflows/pr10-ghash-8370c-class-controls.yml, already on default main6f129ec9f92ae0de32654d9eb078af5e16ee435d. The separate workflow branch is based on that exact main and modifies only this existing YAML. Dispatch ref is codex/pr10-ghash-8370c-hot-key-swap-workflow; its exact branch guard and immutable reviewed source commit are fixed, with no configurable inputs or commands. Workflow HEAD and source checkout HEAD are separately recorded; GITHUB_SHA is never replaced. No default-main or PR10 mutation is needed. Source workflows have no push trigger; the new YAML remains workflow_dispatch only.

The parent owns at most20 sequential CPU assignments, records all skips and stops at the FIRST reported Xeon8370C regardless of checkout/build/measurement outcome. No outcome-based retries, replacements or alternate model are allowed. Each job records lscpu text/JSON, proc/cpuinfo, uname and selection metadata before checkout/compiler. Other models upload metadata with six unattempted slots and run no tests. No affinity, governor, feature mask or processor mode is changed.

On the selected host build once under Rust1.87.0, RUSTFLAGS exactly --cfg pratique_portable -C target-feature=-aes,-pclmulqdq, PRATIQUE_TIMING_SECS exactly3, and no forced tick/reps or encoded-rustflags overrides:

    cargo test --release --all-features --lib --no-run --message-format=json

Record compiler/cargo identity, source hashes, build stdout/stderr and the selected ELF path/size/SHA256. The proven capture helper retains the actual same-built ELF, nm maps and bounded relevant disassembly BEFORE native timing. The only selection change prioritizes the new swap entry. ELF copy/hash/payload safety is mandatory; optional missing/failing nm/objdump is honestly partial/unavailable and does not suppress the fixed calls if ELF is retained. Limits remain ELF60MB, each listing5MB, disassembly16MB, total pre-timing payload90MB, optional capture90s, collector100MB. Never execute retained artifacts locally.

The same original compiled ELF is directly invoked in exactly this order:

1. crypto::timing::ghash_multiplication_is_constant_time
2. crypto::timing::ghash_batch_hot_key_swap_controls
3. original gate
4. swap controls
5. original gate
6. swap controls

Each command appends --exact --ignored --nocapture --test-threads=1. The three-second budget, original eight comparisons and automatic fresh rechecks remain unchanged. Each swap row always measures seeds0 and1 through the exact existing control_row helper. Only these two selectors run; earlier diagnostic tests remain compiled reference source, not additional invocations.

All six calls continue after original0/101, printed findings or collector errors while staging/cleanup is safe. Each child has a55s outer safety cap. Owned process groups are terminated/reaped before the next call; unsafe cleanup/cancellation leaves explicit unattempted slots rather than overlap. Full merged stdout/stderr, commands, timestamps, exits and partials are retained. No parsing, arithmetic export, capture or checksum occurs between native calls. ELF digest is compared before/after the whole window.

Job cap25min. Step caps: CPU1, checkout1, install2, build/capture6, native6, report1, upload2 =19min, leaving6min additional overhead. Nominal statistical duration is144s without original rechecks, up to216s if all eight gate rows recheck each time, before warmup/probes/overshoot. A timeout is incomplete evidence, never a quiet result. Job success means collection only.

## Four rows, actual storage and direction

PageAligned uses4096-byte virtual alignment. Each pair's source array is measured forward, mutated by pair.swap(0,1) or both.swap(0,1), then measured in reverse. Values are moved outside the timed measurement calls. Keys/data are prepared outside; dynamic index/key selection, hash and internal workspace cleanup remain timed. Key-object drop is outside the measured operation. The exact source contains no explicit move to a different pair object between forward/reverse rows, but compiler layout/rematerialization is not established by typecheck.

| Pair/row | Class0: slot0 | Class1: slot1 | Raw signed d |
|---|---|---|---|
| Zero/nonzero forward | zero H | fixed other nonzero H | nonzero-at1 minus zero-at0 |
| Zero/nonzero reverse | fixed other nonzero H | zero H | zero-at1 minus nonzero-at0 |
| A/B forward | fixed nonzero A | fixed nonzero B | B-at1 minus A-at0 |
| A/B reverse | fixed nonzero B | fixed nonzero A | A-at1 minus B-at0 |

The parser binds exactly two printed slot-address lines before the two forward rows (after0 and4 report records). These observe outer-wrapper virtual addresses BEFORE each pair; no address is printed after swap or per sample. Page/line offset equality is recorded, not physical page/cache-set/TLB equality. The full actual ELF must later verify same base/stride and key-content exchange after each swap, matching timed-code shape and one actual hash per repetition. Work/slot reuse is an interpretation prerequisite; collection completeness never asserts it.

All four raw names are ASCII length56 and index generation consumes no RNG. This supports a common schedule prefix per seed when actual probe behavior matches; it is not observed sample pairing, equal sample counts, equal timing state or proof of matching probe branches. One newly printed coarse_tick call observes only itself. No branch identity or fixture is reconstructed from reps1/medians; raw durations and actual per-sample addresses remain unavailable.

## Required means, contrasts and uncertainty

Retain all seven signed t displays and four mean/SE views at keep1.0,0.95,0.75,0.5 with the patch's original1/3 decimal precision. The printed unchanged pair judge remains authoritative; the print-only test normally exits0 even on CONFIRMED. Original exit101 is a complete timing finding only with all rows/rechecks, appropriate footer and unchanged final summary. Rounded maxima never select another crop or rewrite the original first-peak rule.

Join forward/reverse only within the SAME iteration, seed, pair and keep level. Let F be forward slot1-minus-slot0 and R reverse slot1-minus-slot0. Report:

    V = (F - R) / 2
    S = (F + R) / 2

For zero/nonzero, V points nonzero minus zero; for A/B, V points B minus A. S points slot1 minus slot0 within its OWN pair, never between different arrays. These always define algebraic antisymmetric/symmetric contrasts. With stable comparable four cell means they are marginal value/slot contrasts even with interaction; interaction itself is not identified. They are not unique physical or causal components. Each row uses its OWN pooled crop cutoff, so these compare separately cropped estimators, not jointly paired raw samples. Time/order/history/probe differences remain.

If covariance is unknown, report only the explicitly conditional approximation:

    SE_Cov0(V) = SE_Cov0(S) = sqrt(SE_F^2 + SE_R^2) / 2

This assumes zero cross-row covariance, which the data do not establish; do not call the rows independent. General variances include minus2Cov for V and plus2Cov for S before division by4. No raw joint samples are available to estimate Cov. Inputs are rounded printed means/SEs; derived4-decimal displays preserve algebra on those rounded inputs, not extra measurement precision. No derived t, confidence interval, confirmation judge or gate is introduced. Do not pool seeds/iterations or borrow second-patch rows/different arrays. Nonfinite/missing inputs produce unavailable contrasts, not zeros.

A complete campaign retains six canonical slots, three original gates and24 swap seed reports/12 original pair judges. Raw all-view exports contain96 mean/SE rows and168 signed-t rows. Derived all-view exports contain48 records, each with V/S plus conditional SE; required95/75 export contains24 such records (48 underlying reported mean/SE inputs). All source/binary/window/retained-ELF bindings and slot-print positions must be valid for collection completeness. Keep every partial and checksum. No calibrated positive/identical negative health set is added. Quiet rows are non-confirmation at this budget, not equivalence bounds or security closure; all earlier failures and PR10HOLD remain.
