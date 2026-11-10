This experimental integration starts at diagnosticA3
`a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf` and merges the clean author's exact
guard commit40471873, borrowed test observer9f8a17c4 and retained-copy API26af8b77.
Those commits remain ancestors. Production guard code/constants are exact byte
copies of those committed clean files; the original ordered polynomial circuit
and accepted scalar primitive are unchanged. The scalar comparison is a separate
branch, not part of this candidate. PR10 remains draft/HOLD and every previous
failure remains evidence. No privileged mode is required or used.

On64-bit targets each public batch has50 payload blocks and14 fixed public guard
lanes. The retained key contains descending H^50 throughH, prepared in place from
a borrowed50-element raw-power guard. Each800-byte batch folds the incoming
state into its first real block, invokes the borrowed retained workspace, removes
the known fixed guard-product correction internally, then reduces the borrowed
output. AAD and ciphertext retain independent padding. Remainders, short data and
the final length block retain the accepted scalar recurrence. On32-bit targets
the entire portable GHASH path is scalar; there is no claim that split32-bit
lowering preserves the64-bit guard witness. Hardware arithmetic/dispatch remain
unchanged.

Raw powers, the running scalar, raw blocks, every320u64+5u128 work word and the
retained192 prepared words use the existing volatile cleanup machinery. Raw
power/scalar preparation now uses zero-initialized retained guards on normal and
unwind paths. Output reduction finishes before workspace cleanup. Clone first
constructs an empty prepared field inside the retained destination key, then
copies directly from the borrowed source; no populated transient prepared array
is returned. The copy preserves deliberately wiped state. Final key/API moves,
scalar/circuit temporaries, compiler registers and spills remain best effort;
there is no complete-frame/abort erasure promise.

All A3 timing.rs bytes remain exact, including original8 rows, all supplied
patches, logical names, generators, seeds, clocks, budgets, crops, thresholds and
confirmation rules. Original1024-byte rows now exercise one50-block group plus
14 scalar blocks;2049-byte rows exercise two groups plus28 full scalar blocks and
one partial byte, in addition to AAD/final-length processing. All4 swap rows
invoke the actual candidate hash on the retained runtime-selected4096-byte
wrapper. The existing correctness oracle tests are extended around799/800/801
and1599/1600/1601 (and third-group boundaries), preserving existing cases and
expected calculations. A zero-key clone/wipe unit checks the new retained copy.

The clean witness establishes abstract circuit guard coverage, and a standalone
generic-x86 trace establishes retained guards in that exact compiled circuit.
Normal integrated code and the later actual Linux test ELF require their own
binding/review. Packing, scalar preparation/tails/reduction, aggregation, cache
and address history and arbitrary operand-dependent platform behavior are not
covered by the circuit invariant alone. Successful functional checks or a quiet
timing sample do not establish security closure. Integrated performance and
fixed paired8370C tests are pending separate reviewed receipts.
