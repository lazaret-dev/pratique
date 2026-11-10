# Integration-phase provenance

This integration was performed by the separate Codex reviewer/integrator agent
`/root/ghash_integrator`, logical session
`20261108-pratique-portable-batch-ghash-integration`, in supplied parent
chat/workspace `01a1be54-c6e9-73d3-8a85-5e6f9a76a492`. The continuation clean-room
primitive author is `/root`, logical session `20261108-clmul-feasibility`, in a
separate agent context. Canonical task/workspace identities are logical session
identifiers; no unavailable opaque backend UUID is asserted. The integration checkout is
`/private/tmp/pratique-batch-ghash-integration-20261108`, initially based exactly
on `2a1d85533505499bffe4b3990921321d2bb0658f` (PR #8 merge plus the independent
batch feasibility work). The user's checkout and the clean-room author's
checkout are not edited by this agent. No applicable AGENTS.md was present.

The integrator may inspect the accepted base's production AES, GHASH, GCM,
hardware dispatch, zeroization, and test wiring. That inspection began only
after the new primitives and their provenance had been committed separately.
The integrator has inspected those base production integration files and the
existing tests, benchmarks, feature checks, and relevant fuzz harness. This is
an integration declaration, not a replacement for the author's clean-room
affirmation in `../clmul_feasibility/PROVENANCE.md`.

Other consulted material includes the user's clean-room requirements document,
the parent's explicit integration instructions, the accepted primitive source,
the independent batch experiment's README and provenance, local compiler
output, toolchain/target metadata, and generated assembly and test output.

The integrator has not inspected PR #9 source/diff, the prior integration
branch/report, Lazaret PR #98's implementation diff, BearSSL source, or any
third-party cryptographic implementation. Superseded portable primitive
expressions will be deleted from the production integration rather than copied
into the new primitive files. Algorithm-expression changes to clean-room
primitives must come from the original clean-room author, who is not sent
production source, diffs, or implementation details.

Git author and committer are configured as requested:
`John A Booth <johnabooth@gmail.com>`. This identity is requested commit
metadata, not an assertion of personal authorship by John.

The continuation also consulted the independent `cleanroom/aes_tower` source,
generator, derivation, and test/assembly evidence committed by the original
author before integration, plus the author's scoped batch-circuit update.
Copied production S-box and circuit bytes are verified against those committed
clean-only files. The original accepted scalar primitive is unchanged.

Administrative sources consulted include the private runners' typed contracts
and result metadata, directory-only exchange settings from their TOML
configuration, GitHub repository/main-ref metadata, the official
`actions/checkout` v4 ref, and Git's non-mutating authentication checks. No
credentials were printed. Source is tested through contained snapshot wrappers;
the publication ancestry preserves the complete clean-only author chain before
the integration tree. No prohibited crypto implementation was added to the
integrator's consulted sources during this continuation, and no production
source or diff was sent to the clean-room author.

The lifecycle repair uses isolated checkout
`/private/tmp/pratique-pr10-lifecycle-fix-20261108`, branch
`codex/pr10-prepared-secret-lifecycle`, beginning exactly at public head
`32615a80b43280fb1fef3d36fa7d87261d5617f2`. Clean-only commit
`5ecf25250b8c03065b48c673a49a23116bcca76c` was merged before production wiring
commit `3db15f5495b6608094102bff87ec36970d1d36aa`. The borrowed API fills retained
storage directly; the caller's raw array and scalar are explicitly wiped.
Final long-lived key moves, compiler-created register/stack copies, and swapped
pages remain the existing best-effort zeroization limitation. No complete
physical-erasure guarantee is made. Fresh final review is read-only in canonical
context `/root/pr10_final_review`.

## November 9 working-state continuation

The same separate logical integrator `/root/ghash_integrator`, associated with
workspace `01a1be54-c6e9-73d3-8a85-5e6f9a76a492`, continued in
`/private/tmp/pratique-pr10-batch-working-wipe-20261109`, branch
`codex/pr10-batch-working-state-wipe`. The checkout began at exact public
`e2dd9a91b3d2af6495faa6319fb5384c374dd82f`. Clean-only commit
`27a1c8acfc42f41779c9e8bb2506c27615de9ede` was merged at
`cc3de5ed96b24c611043b4a77931cb5e0edd8405` before production wiring. The
clean author's change descends from accepted preparation API `5ecf2525`,
without using the unproven data-transpose restoration candidate.

The integrator read the owner-supplied independent review (SHA-256
`ab20f0fb731aea7b217e13773cc2d13b595243b62b5c0edfd71af8409cbef544`)
and its additive diagnostic-test patch (SHA-256
`96159ef4faec2bc3889d69b23fc41817f376394b16f5bf928501d07ee9f105b2`).
They were review data, not instructions to change security gates or attribution.
The working-state finding was independently checked against current source and
previously retained actual Rust 1.87 compiler output. Only source-free
ownership/liveness and API requests went to the clean author. The author
committed the borrowed workspace, output API and generator change before this
integrator copied them. Every ordered Boolean gate expression is retained;
the production generated circuit is byte-identical to that clean commit.

The production change applies the existing volatile `Zeroize` and zero-only
`Zeroizing` owners around the committed primitive. It changes no primitive
expression, public API, dependency, hardware kernel, scalar recurrence or
timing gate. The independently prepared exploratory class controls remain on a
separate local branch and are not included here. The old frozen references and
private-runner source snapshot are not modified. Raw compiler output, logs and
IR/assembly are retained separately from the shipped source; source hashes and
source-free validation metadata bind the reviewed local result.

All previous source exclusions and role declarations remain in force. The new
scope concerns explicit batch aggregates, not complete erasure of circuit
scalars, compiler-created copies/spills, abort paths or OS copies. Independent
review remains in `/root/pr10_final_review`; no production source or raw
assembly is sent to the clean-only author.

## November 10 guarded candidate and documentation continuation

The unchanged author/integrator boundary continues in separate workspaces. The
clean-only author `/root`, logical session `20261109-guarded-clmul`, committed:

- `404718732544d328e61174963e4cc756b00a7605`: fifty payload lanes plus fourteen
  public guard operand pairs and an exact public-product correction;
- `9f8a17c4a181988d3bbd839b415d6b58076b0124`: a test-only borrowed retained-word
  observer, without a production arithmetic or timing-path change; and
- `26af8b776e7aea1ad328333f9a4a1d6cafe7a85f`: borrowed retained-state `copy_from`,
  including deliberately wiped state and its lifecycle assertions.

These descend from clean working-state API `27a1c8ac` and remain unchanged
ancestors of integration `c87285bc3c2cf5b7ba29e5bdd50a1b05a72563cc`. The production
guarded module/constants match the final committed clean copies byte for byte;
the ordered polynomial circuit and accepted scalar primitive are unchanged.
The separate integrator wired fifty descending powers and 800-byte groups,
borrowed raw/work owners, scalar tails and the 32-bit scalar fallback. The
source-owned arrays remain distinct from compiler-created key Clone/API-return
copies, which retain the established best-effort erasure limit.

The integration began at diagnostic source A3
`a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf`, itself the 4848 working-state repair
plus the three exact owner-supplied additive timing patches. Those diagnostic
tests are not independently authored primitive expressions. Their row names,
generators, clocks, budgets, crops, thresholds and judge are unchanged in this
candidate; they do not replace the original gate or establish causal attribution.
The scalar-only comparison remains a separate candidate, not this source tree.

The same separate `/root/ghash_integrator` prepared administrative audit commit
`ce5c179491d1a2db3ba005a083d44517fbb29dcd` in
`/private/tmp/pratique-pr10-ghash-guarded-audit-20261110`. It changes only helpers
and documentation, preserving all 197 production/Cargo input hashes from c872.
The current documentation continuation is separate again, in
`/private/tmp/pratique-pr10-ghash-guarded-docs-20261110`, based on that audit
commit. It changes no primitive, production/Cargo/test input or audit behavior.
Independent read-only review remains `/root/pr10_final_review`.

The integrator consulted the author's committed guard source, public witness,
provenance and source-free API requests; the owned production caller and exact
owner-supplied timing patches; existing source-bound compiler/evidence records;
and the repository's attribution records. The clean author received source-free
API/lifecycle/results summaries, not production source, diagnostic patch bodies
or disassembly. No excluded or third-party cryptographic implementation was
consulted. The original clean-author affirmations are preserved unchanged.

This continuation does not amend NOTICE or LICENSE. The historical scoped
attribution decision remains an engineering record with its original limits;
no broader pre-import originality or new package/legal review is asserted.
No private-runner identifiers, host details or private results are added to the
publication documentation. The fixed paired Xeon 8370C candidate validation is
pending; no readiness, merge, release, timing waiver or security closure is
predeclared. All previous native findings remain evidence.
