# Guarded portable GHASH comparison candidate

This experimental integration starts at diagnostic A3
`a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf` and merges the clean author's exact
guard commit `40471873`, borrowed test observer `9f8a17c4` and retained-copy API
`26af8b77` before integration `c87285bc`. Those commits remain ancestors.
Production guard code/constants are exact byte copies of the final committed
clean files; the original ordered polynomial circuit and accepted scalar
primitive are unchanged. The scalar comparison is a separate branch. PR10
remains draft/HOLD and every previous failure remains evidence. No privileged
mode is required or used.

On 64-bit targets each public batch has 50 payload blocks and 14 fixed public
guard lanes. The retained key contains descending H^50 through H, prepared in
place from a borrowed 50-element raw-power guard. Each 800-byte batch folds the
incoming state into its first real block, invokes the borrowed retained
workspace, XOR-removes the exact known public guard-product correction, then
reduces the borrowed output. AAD and ciphertext retain independent padding.
Remainders, short data and the final length block retain the accepted scalar
recurrence. On 32-bit targets the entire portable GHASH path is scalar; split
32-bit lowering is not claimed to preserve the 64-bit guard witness. Hardware
arithmetic/dispatch remain unchanged.

Raw powers, the running scalar, raw blocks, all 320 `u64` plus 5 `u128` workspace
words and the retained 192 prepared words use the existing volatile cleanup
machinery. Raw power/scalar preparation uses zero-initialized retained guards
on normal and unwind paths. Output reduction finishes before workspace cleanup.
Clone constructs an empty prepared field inside the retained destination key,
then copies from the borrowed source; no source-owned populated transient
prepared array is returned. The copy preserves deliberately wiped state.

The optimized Clone is known to create a 1,536-byte prepared-field temporary and
return-key copies, in addition to the existing hardware-field copy. These are
compiler/API-return copies of an intentional retained clone, distinct from the
source-owned preparation/work arrays. Final key/API moves, scalar/circuit
temporaries, compiler registers and spills remain best effort; there is no
complete-frame, abort or OS-copy erasure promise.

All A3 `timing.rs` bytes remain exact: the original eight rows, all supplied
patches, logical names, generators, seeds, clocks, budgets, crops, thresholds and
confirmation rules. Original 1,024-byte rows exercise one 50-block group plus
14 scalar blocks. The 2,049-byte rows exercise two groups plus 28 full scalar
blocks and one partial byte, in addition to AAD/final-length processing. All
four swap rows invoke the actual candidate hash on retained runtime-selected
4,096-byte wrappers. Existing correctness oracles cover 799/800/801 and
1,599/1,600/1,601 bytes, plus later group boundaries, preserving the previous
cases and expected calculations. A zero-key clone/wipe unit checks retained
copying.

The clean witness establishes abstract nonconstant circuit-wire guard coverage.
The integrated whole-crate Rust 1.87 generic-x86 circuit trace is separately
bound and reviewed. A later actual Linux test ELF requires its own identity and
work-retention review; source/whole-crate emission is not linked-ELF identity.
Packing, scalar preparation/tails/reduction, aggregation, cache/address history
and arbitrary operand-dependent platform behavior are outside the circuit
invariant alone. Functional success or a quiet timing sample does not establish
security closure. Local integrated performance is recorded separately and is not
a Xeon 8370C measurement. Fixed paired 8370C validation is pending; no result or
readiness is predeclared. The administrative audit continuation is documented in
[LIFECYCLE_AUDIT.md](LIFECYCLE_AUDIT.md).
