# Source-owned portable batch working state

The public `e2dd9a91` batch path wiped its caller's block array, but value-taking
input and transpose routes left other coefficient and product arrays outside
that cleanup. This is distinct from the earlier, correctly repaired key-power
preparation lifecycle. Incoming GHASH state and product planes can be
key-derived even when ciphertext is public.

Clean-only commit `27a1c8acfc42f41779c9e8bb2506c27615de9ede` replaces the used
path's populated aggregate returns with borrowed inputs and caller-owned
working storage. The integration copies those expressions unchanged. The
generated circuit changes its output destination, retaining all 4,593 ordered
gate expressions and 128 output expressions. The accepted scalar primitive
and S-box are unchanged.

The workspace contains 320 `u64` words and five `u128` words (2,640 bytes): three
coefficient arrays, product planes, partial sums and the two-word output. Its
constructor returns only zero state; the type has no `Clone` or `Copy`.
Coefficient, product and output accesses borrow retained storage. No used
production path calls the old value-taking transpose wrapper.

For each full batch, the caller creates the raw 64-word block buffer and the
workspace inside existing `Zeroizing` guards while they contain only zeros.
The operation then borrows them. Output words are read to update the existing
scalar accumulator. The workspace's lexical scope ends immediately afterward,
so its guard calls the existing volatile `Zeroize` over all four `u64` slices
and both `u128` slices. The raw-block guard wipes its retained 64 `u128` words
at the iteration boundary. Rust scope cleanup also covers unwinding while an
initialized guard is live. No populated workspace is moved into `drop(value)`
or returned to another owner.

The key preparation and retained-key/clone destruction paths are unchanged,
including raw-power/running-power wipes. Existing scalar accumulator cleanup
is retained. Hardware paths, short-message selection, independent AAD and
ciphertext padding, incoming-state semantics and tail processing are unchanged.

The new lifecycle fixture directly fills every exposed workspace word, invokes
the production `Zeroize` implementation, and checks zero contents and retained
addresses. It verifies direct cleanup, not post-drop access to expired storage.
Guard destruction is checked separately through the existing generic guard
tests, source ownership graph and actual whole-crate Rust 1.87 IR/assembly.
The structural checks include negative controls and compare used primitive
expressions with the separately committed clean source.

Local focused validation includes 174 forced-portable crypto tests in ordinary
MSRV debug and release builds, six target families of primitive assembly/source
audits, and a Rust 1.87 no-default-features WASM check. Full release testing was
also attempted before narrowing to that scope: 1,279 library tests passed and
353 unrelated environment tests failed (352 with sandbox `Operation not
permitted` errors, plus native-root access); no crypto test failed. This is
not reported as a full-suite pass. Detailed logs and source-bound artifacts
are kept outside the shipped tree.

The actual generic-x86 normal-library Rust 1.87 emission retains volatile
workspace and block wipes. Debug IR retains typed guard cleanup on unwind
edges. Optimized output loads precede workspace cleanup; LLVM can perform the
scalar reduction using those loaded values afterward. A separate temporary
workspace exists only while entirely zero and ends before computation. The
wide and narrow aggregate helpers have borrowed destinations and no local
array allocations in optimized IR. The primitive audit reports no ordinary
multiplication/division on Apple ARM64, x86-64, WASM, i686, ARMv7 and RISC-V64.

These are source-aggregate and retained-store guarantees, not a complete
physical-erasure claim. Scalar circuit nodes, compiler-created moves, register
contents and spills, process aborts, swapped pages and other OS copies remain
best effort. Static volatile instruction counts alone are not dynamic word
coverage or evidence that a whole stack frame is erased.

Earlier native timing failures remain unresolved and merge remains on HOLD.
The original timing screen, thresholds, crops, repeats and CI configuration are
unchanged. No new timing closure or throughput claim is made by this repair;
the owner's performance follow-up remains issue #11. This lifecycle branch is
separate from both the frozen diagnostic references and the additive local
class-control experiment.
