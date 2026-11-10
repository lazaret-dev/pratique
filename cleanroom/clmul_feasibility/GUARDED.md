# Fixed public guard-lane candidate

This is an experimental software correction authored independently by `/root`
in logical clean-room session `20261109-guarded-clmul`, parent workspace
`01a1be54-c6e9-73d3-8a85-5e6f9a76a492`. No production GHASH implementation,
third-party cryptographic implementation, supplied timing-patch body or
production disassembly was consulted. The sources are the author's earlier
polynomial circuit, its borrowed API at `27a1c8ac`, the source-free timing
observations and SP800-38D's polynomial arithmetic.

The observed timing difference tracked a zero hash key across two fixed memory
slots. The candidate prevents all-zero/all-one machine words at each abstract
Boolean circuit input and gate by reserving fourteen of its64 independent
lanes for fixed public operand pairs. Fifty lanes carry real128-bit polynomial
products. The guard inputs are independent of every real key and data block.
They require no random source or privileged mode.

For public pairs `(u_j,v_j)` and real pairs `(a_i,b_i)`, the circuit computes

`P = XOR_i (a_i * b_i) XOR_j (u_j * v_j)`.

The two-word constant `C = XOR_j(u_j*v_j)` is removed after aggregation,
so the returned unreduced256-bit polynomial is exactly `P XOR C`.
`guard_generate.py` derives C by independent bit-loop multiplication, without
reducing it in the field. Low, high and low-XOR-high Karatsuba operands all
derive from each same128-bit public pair, so recombination uses the usual
identity without a second mathematical convention.

`guard_witness.py` searches a deterministic public pool. `guard-witness.json`
records the fourteen pairs. Evaluating the actual generated Boolean circuit
on only these guard lanes verifies all128 input planes and all4593 gates in
each of the three64-bit subproducts: the fourteen guard bits contain both0
and1 at every nonconstant wire. The last output coefficient is identically
zero and intentionally exempt. Real payload bits cannot change guard bits.
Rust tests independently instrument the circuit's bitwise operations to check
this property and compare the resulting products and fifty-block GHASH
recurrence against independent polynomial/SP800-38D oracles.

The API borrows fifty raw powers/blocks and retains prepared planes and the
existing caller-owned working container in place. All192 prepared words and
all working aggregates remain exposed to the existing caller wipe APIs. No
populated aggregate is returned or cloned. The caller must wipe its raw
inputs when those are secret. Scalar registers and compiler-created spills
remain outside the source-owned aggregate-erasure claim.

This finite circuit witness is not an optimized-code proof. A compiler may
reassociate expressions into different intermediate words. Opaque borrowed
input/output boundaries are used, but actual MSRV1.87 optimized instruction
dataflow must still be checked. Packing, parity aggregation, reduction, power
generation, scalar tails and cleanup are outside the abstract circuit guard
proof and remain subject to unchanged whole-path timing tests. The design
does not claim protection against arbitrary differences among nonzero
operands or power/frequency behavior on every CPU.

The guard bits occupy bit positions50 through63 in each logical64-bit word.
They do not protect a separately lowered low32-bit half on32-bit targets.
Compilation/correctness on those targets must not be reported as a guard
timing guarantee. The first candidate is scoped to64-bit software; existing
scalar handling is the comparison for other word widths until separately
guarded packing is designed and validated.

Integration must use descending powers H^50 through H, carry the previous
accumulator into the first real block, remove the public correction before
field reduction, and handle tails/padding/lengths exactly. A repeated
8370C experiment, correctness/lifecycle checks and measured throughput are
required before this candidate can be recommended. DOITM is not required.

Reproduce the public witness with `python3 guard_witness.py --pool 2048` and
the constants with `python3 guard_generate.py` from this directory. The
optimized Rust1.87 checks and benchmark use `python3 check.py --iterations
20000` with additional `--target` arguments for supported cross targets.
