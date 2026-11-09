# Portable GHASH batching feasibility

A multiplication-free Boolean circuit has a plausible performance path when
64 weighted polynomial products are combined in one batch. The measured
128-bit aggregation costs 15.38 ns per block with Rust 1.87 and 16.51 ns with
Rust 1.99.1 on this Apple ARM64 host. Those measurements exclude field
reduction, generation of key powers, byte conversion, AES, and GCM framing.
They establish a candidate for an independent integrator to evaluate. They
do not establish the required AES-GCM throughput or production timing gates.

The original single-product function remains unchanged. No faster drop-in
single-product or three-product replacement is supplied. The experiment
requires a wider private interface, prepared operands, and block scheduling
by a separate integrator. No production crypto file has been edited.

## Construction

Each of 64 polynomial coefficients occupies a `u64` whose bits represent
64 independent products. Coefficient multiplication is a bitwise AND;
coefficient addition is a bitwise XOR. A fixed bit-matrix transpose converts
64 input words into this representation.

The generator derives its circuit recursively from this identity, where
`A = A0 + x^m A1`, `B = B0 + x^m B1`, and addition is XOR:

```text
L = A0 B0
H = A1 B1
M = (A0 + A1)(B0 + B1) + L + H
AB = L + x^m M + x^(2m) H
```

For 64 coefficients, the circuit has 729 AND and 3,864 XOR operations.
Every operation computes 64 lanes simultaneously. The circuit is generated
from blank files by `generate.py`; `circuit.rs` is the resulting Rust source.
All array subscripts in the generated circuit are literal constants.

Returning every product requires two output transposes. If the caller only
needs their XOR, the parity of each output plane supplies its corresponding
coefficient directly. Preparing the other operand also avoids repeating
its input transpose. These two savings explain the useful result; increasing
the number of independent lanes alone did not suffice.

`clmul128_batch_xor_prepared` uses three such batches and the same polynomial
identity to return the XOR of 64 exact, unreduced 128 by 128 products as
`[low_u128, high_u128]`. Preparation occupies 1,536 bytes. Ownership and
zeroization of that prepared state are integration work.

## Why the wider interface can help GHASH

Expanding the GHASH recurrence over 64 blocks gives:

```text
Y_next = (Y_previous XOR X1) H^64 XOR X2 H^63 XOR ... XOR X64 H
```

An integrator can supply those powers as the prepared operand, calculate
the XOR of unreduced products, and reduce the aggregate once. Polynomial
reduction is linear, so this preserves the recurrence specified in
[NIST SP 800-38D, sections 6.3 and 6.4](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
The test `weighted_batch_matches_nist_recurrence` compares this identity
against a newly written Algorithm 1 oracle for five hash keys and three
consecutive batches per key, including nonzero incoming state. Bit reversal
in that test explicitly relates the supplied coefficient convention to
NIST's bit-string convention.

## Measurements

Each entry is the median of nine measurements of 100,000 calls. Inputs and
outputs pass through `black_box`. Builds use `-O` and `-C target-feature=-aes`.
The candidate uses neither AES nor native polynomial multiplication.
Benchmarks run sequentially after compilation. Raw logs, exact compiler
versions, commands, and source hashes are in `results/`.

| Operation | Rust 1.87 ns per call | Rust 1.99.1 ns per call | Interpretation |
| --- | ---: | ---: | --- |
| Accepted scalar primitive called three times | 102.52 | 107.27 | Three individual products |
| 64 independent products, all outputs returned | 500.87 | 531.26 | 23.48 / 24.90 ns per three products, amortized |
| Prepared 64-product XOR | 319.27 | 338.40 | 14.97 / 15.86 ns per three products, amortized |
| Prepared 128-bit product aggregation for 64 blocks | 984.27 | 1,056.73 | **15.38 / 16.51 ns per block**, amortized |
| Prepare 64 sets of three operands | 201.19 | 214.50 | Once per prepared operand set; excludes generating powers |

The reported 20–24 ns result for PR #9 is a handoff summary, not a locally
reproduced comparator. The prepared XOR batch has different calling and
output semantics, so these figures do not demonstrate a faster three-call
replacement. Performance also depends on host load and compiler scheduling.

## Overall throughput budget

The handoff gives overall regressions of 43–48 percent for PR #9 and a
20–24 ns isolated cost for its three products. Under an additive model,
these values suggest that multiplier replacement alone could be insufficient.

Assume decimal MB/s, one group of three products per 16-byte block, an
integrated cost equal to the isolated cost, comparable hardware and builds,
and unchanged remaining work. Let `B = 16000 / baseline_MBps` nanoseconds
per block. The acceptance budget is `B / 0.75`. Use the most optimistic
failed throughput, `0.57` of baseline, and delete the full 24 ns:

| Benchmark | Acceptance budget ns per block | Hypothetical time with zero-cost products ns per block |
| --- | ---: | ---: |
| AES-128-GCM 1 MiB | 89.22 | 93.40 |
| AES-128-GCM 16 KiB | 89.94 | 94.34 |
| AES-256-GCM 1 MiB | 109.74 | 120.39 |
| AES-256-GCM 16 KiB | 110.36 | 121.22 |

The model misses all four gates even with free products. Its assumptions
need profiling by the integrator: isolated timings can differ from integrated
costs because of inlining, spills, overlap, composition, and reduction. This
is a conditional diagnostic, not an impossibility proof. It explains why
beating an isolated primitive target cannot establish acceptance.

The wider batch changes the remaining work as well: one reduction and
composition per batch can replace per-block work. With the observed 16.51 ns
aggregation cost, the 1 MiB budgets leave approximately 72.71 ns per block
for AES and everything else with AES-128, and 93.23 ns with AES-256.
Whether the integrated implementation fits those budgets is unmeasured.

## Correctness and structural checks

All ten tests pass with Rust 1.87.0 and 1.99.1. They include the four accepted
PR #8 tests, every single-bit pair, mixed lanes, boundaries, 12,288 new
deterministic 64-bit pairs, 8,192 128-bit pairs checked by a separate
bit-polynomial oracle, and the NIST recurrence comparison. Every bit in
every lane of the transpose is tested separately.

The library compiles as `no_std` and forbids unsafe code. It has no dependency,
allocation, secret-dependent source branch, secret-dependent loop bound,
secret-dependent address, secret-indexed table, ordinary operand
multiplication, or native carry-less multiplication. Source uses fixed
shifts, AND, XOR, and `count_ones`; their language behavior is documented in
the [Rust Reference](https://doc.rust-lang.org/reference/expressions/operator-expr.html)
and [core integer documentation](https://doc.rust-lang.org/stable/core/primitive.u64.html).

Optimized assembly is emitted for Apple ARM64 with both compilers, and for
x86-64 Linux and wasm32 with Rust 1.99.1. The scan rejects multiplication and
division instructions and records branches and calls for review. On the
inspected builds, conditional branches use public counters and x86 indirect
calls load fixed symbols. The scan is not a proof of constant time. Code,
public counter branches, address
formation, and runtime helpers require structural review for every supported
compiler and target; i686, ARMv7, and RISC-V remain unvalidated. Cross-compilation
does not establish runtime correctness or timing on those machines.

Local Welch timing screens compare zero and random message operands and zero
and random prepared operands, with preparation outside the timed region.
They are independent screening experiments, not the production timing tests.
The initial Rust 1.87 message screen had `t = -4.315`. Three longer runs of
100,000 samples per class had maximum absolute t values of 3.207 for messages
and 2.556 for prepared operands. None crossed the screening threshold of 4.5.
All of these statistics are retained in `results/`; they do not certify
production constant-time behavior.

## Integration handoff

The smallest useful extension is a wider private batch and prepared-operand
interface, together with permission for the separate integrator to aggregate
reduction. This preserves the single-product contract, provenance boundary,
security constraints, dependencies, public APIs, and performance thresholds.
If the owner's existing authorization of batched primitives includes this
scope, no further algorithm restriction needs to change.

The integrator should first profile portable AES and the remaining GHASH
work. Then evaluate full groups of 64 blocks with prepared powers, amortize
preparation over the key lifetime, and measure power generation and key setup.
Preserve streaming behavior and use the existing primitive for tails and short
messages while measuring their cost. Preserve and extend key zeroization to
the prepared representation. Keep normal hardware dispatch on its existing
path and verify its approximately five-percent performance gate.

Acceptance still requires all four supplied portable throughput gates,
production portable timing on Apple ARM64 and x86-64, all supported-target
checks, NIST/GCM and hardware parity tests, TLS, relevant fuzzing, and
authentication-failure tests. No integration, release, attribution removal,
or Lazaret re-vendor is included in this experiment.

## Reproduction

From this isolated checkout:

```sh
python3 cleanroom/clmul_feasibility/check.py --toolchain 1.87.0 --timing
python3 cleanroom/clmul_feasibility/check.py --toolchain stable --target x86_64-unknown-linux-gnu --target wasm32-unknown-unknown --timing
```

The first command needs the Rust 1.87 toolchain. Cross-compilation needs the
named targets already installed for the selected compiler. The script compiles
only this experiment and the permitted PR #8 primitive. It never loads the
production crate, GHASH, integration source, or PR #9. Artifacts go to a new
temporary directory; the JSON record identifies its location.

See [PROVENANCE.md](PROVENANCE.md) for the clean-room affirmation and consulted
sources.
