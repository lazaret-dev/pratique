# Completed guarded GHASH comparison, 2026-11-10

The fixed same-host experiment is [run 42839794046](https://github.com/lazaret-dev/pratique/actions/runs/42839794046),
with [retained artifact 13776698022](https://github.com/lazaret-dev/pratique/actions/runs/42839794046/artifacts/13776698022).
The first reported Xeon 8370C was assignment 19. All eighteen preceding CPU-only
skips were retained; selection ended at that match without an outcome-based
replacement. No privileged mode or processor control change was used.

The baseline was exact A3 `a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf`;
the candidate was `c87285bc3c2cf5b7ba29e5bdd50a1b05a72563cc`.
Each was built once with Rust 1.87, all features, release optimization and the
same forced-portable flags. Five counterbalanced rounds retained the unchanged
original gate and hot-key swap selectors for each version: twenty timing calls
in total. Logical rows, seeds, budget 3, clocks, crops, threshold and confirmation
rule were unchanged.

| Recorded outcome | A3 baseline | Guarded candidate |
| --- | ---: | ---: |
| Original GHASH gate invocations passing | 0 / 5 | 5 / 5 |
| Confirmed original-row findings | 14 | 0 |
| Confirmed swap-row judgments | 12 / 20 | 0 / 20 |
| Unignored crypto subset passing | 188 | 195 |

The baseline's H0 swap pairs confirmed in all ten judgments; its two nonzero-key
comparisons confirmed only in round two, two of ten judgments. All results are
retained. A quiet candidate row or successful collection is not a proof of
whole-path constant-time behavior.

The actual retained candidate ELF has SHA256
`193c85cf1d6e99d948b85221005116a3fd478a35e121fad12106376bdb849a0b`.
Its packing and fourteen public lane signatures, exact correction, lowered hot
circuit, runtime-selected timed hash work, within-pair content exchanges and
source-owned normal/unwind cleanup were independently checked against the
captured executable. The final independent source-free receipt is
`FINAL-42839794046-INDEPENDENT-PAIRED-NATIVE-REVIEW.json`, SHA256
`13357015d30e49695b0b7d1fe3148c52ae9b914a57d5c938603f5f20d5f77981`.
That review does not claim complete stack-frame erasure, physical cache/address
equivalence, or timing independence of every instruction or platform.

One existing release-profile invocation per version followed the twenty timing
calls. At 1 MiB the recorded GHASH throughput changed from 229.791 to
184.677 MB/s, a 19.6% reduction. At the same 1 MiB size, AES128-GCM seal throughput
declined by about 8.4%, and AES256-GCM seal by about 7.2%. These are matched observations on this host, not a
multi-host benchmark or a waived performance requirement.

The earlier b8 audit/documentation closure and the c131 failure-observability
patch preserve all 197 production/Cargo input bytes from c872. The observer
retains bounded OpenSSL failure evidence without changing the HRR assertion or
its deadline. Full final-candidate Linux release/all-feature CI, source-crate
verification on native Linux, and hosted Windows ARM64/x64 validation remain
pending. No Windows success or broad release readiness is claimed here. All
historical failed measurements and explicit erasure/compiler-copy limits remain
part of the record; PR10 stays on HOLD pending the remaining review.

For provenance, the pre-experiment README recorded that the guarded
representation was “awaiting the fixed paired Xeon 8370C experiment.” That was a
historical pending status, superseded only by the bounded result above. Clean
author affirmations, ordered-circuit ancestry and attribution remain unchanged.
