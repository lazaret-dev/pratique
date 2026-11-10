# Lifecycle audit helper scope

The audit supports two explicit caller graphs. The existing sixty-four-lane
preparation and workspace rules, clean-expression comparison and negative
controls remain active. The fifty-lane caller additionally requires the exact
committed guarded API, fifty borrowed raw words, zero-only construction of the
raw-powers/running-scalar/raw-block/workspace guards, last borrowed output use
before scope exit, and complete retained-key/workspace wipe exposure.

The RAII source check follows the existing generic `Drop` through array and slice
cleanup to unconditional volatile integer stores. It rejects missing cleanup,
forgotten or moved guards, shortened lifetimes, populated guard-constructor
moves, by-value inputs/returns and incomplete wipe exposure. Missing guarded
module/constants inputs fail closed. These are deliberately narrow structural
regressions, not a general Rust parser.

Run source-only regressions with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 cleanroom/ghash_integration/lifecycle_audit_unit.py
```

Run the original host audit plus Linux x86-64 emission with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 cleanroom/ghash_integration/audit_primitives.py --toolchain 1.87.0 --target x86_64-unknown-linux-gnu --output /tmp/production-assembly-1.87.0.json
```

The primitive wrapper now emits the actual guarded preparation, aggregation and
borrowed-copy operations on sixty-four-bit targets as well as the original
primitive graph. Only module path attributes are relocated in a temporary audit
copy so Rust can resolve the nested modules; production files remain unchanged.
The record includes all production/Cargo input hashes, helper hashes, actual
compiler commands, emitted guarded-entry checks and the existing multiplication/
division scan. Calls and branches remain recorded for manual review.

Source checks and primitive-wrapper assembly do not alone prove normal/unwind
cleanup. Bind actual whole-crate LLVM from the same production inputs and flags
for that review. The existing c872 debug/release x86-64 emissions can be reused
when all 197 source/Cargo hashes match. Their lexical Drop edges and optimized
volatile stores are distinct evidence from the source-only mutant fixtures.
This audit does not certify arbitrary operand latency, security closure, stack
frame erasure, compiler-created Clone/API-return copies, registers/spills, abort,
SIGKILL, or identity with a future linked native test executable. No timing row,
threshold, crop, judge, primitive expression or source-owned cleanup is changed
by these administrative helpers.
