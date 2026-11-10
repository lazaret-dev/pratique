# Portable polynomial multiplier provenance

Agent: Codex, a GPT-6-based implementation agent, in the current chat.
Working session label: `20261108-clmul-feasibility`, associated with supplied
workspace identifier `01a1be54-c6e9-73d3-8a85-5e6f9a76a492`.
Date: November 8, 2026, America/Chicago, as supplied by the client.

The checkout begins at PR #8 merge commit
`55cfa19fb41bbfc503e7e5bf93de39e3189d1127`. It was created as a separate local
clone with no initial checkout, then restricted by sparse checkout to
`src/crypto/clmul_clean.rs` before checking out that commit. The new experiment
was written from blank files in `cleanroom/clmul_feasibility/`. The original
primitive was read and remains unchanged.

## Algorithm and requirements sources

1. The user's attached handoff, read from
   `/Users/johnabooth/.codex/attachments/3a627378-54a0-4da0-a1ec-90b8ff6e76b0/Pasted text.txt`.
   Its failed-approach descriptions were used only as supplied outcome summaries.
2. The authoritative brief supplied by the user,
   `/Users/johnabooth/Downloads/Lazaret 0.2.0 clean-room portable AES GHASH requirements.md`.
3. The permitted PR #8 `src/crypto/clmul_clean.rs`, including its four tests,
   read directly from the exact base commit above. Its existing tests are
   included unchanged in this standalone test build.
4. [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
   particularly sections 6.3 and 6.4, for polynomial interpretation and the
   reference multiplication/GHASH recurrence. The test oracle was written
   from the mathematical algorithm, not copied from another implementation.
5. [Rust Reference operator expressions](https://doc.rust-lang.org/reference/expressions/operator-expr.html)
   and [Rust core u64 documentation](https://doc.rust-lang.org/stable/core/primitive.u64.html).
   An attempted access to the versioned Rust 1.87 operator-expression URL
   failed; compatibility was checked with the installed Rust 1.87 compiler.

The Boolean Karatsuba identity, generator, fixed transpose, parity aggregation,
new tests, benchmark, timing harness, and standalone check script were derived
and written during this session. Other than the explicitly permitted PR #8
primitive and tests, no implementation outside this new experiment was
consulted. Compiler output and
assembly inspected were generated from the permitted base primitive and
this session's own files.

## Administrative sources and metadata

The session's supplied operating instructions, filesystem permissions, and
environment context were consulted. The Pages `write-page/SKILL.md` and its
`writing_quality.md` reference were consulted for writing this repository
report; no Page was created or edited.

Git metadata inspected included status, object existence, tracked path names,
worktree registrations, and the origin URL. Worktree inventory exposed names
and commit identifiers of other registered branches, including an integration
checkout. No file body, commit body, patch, report, or implementation from
those checkouts was opened. Toolchain, target, platform, and generated-output
metadata were inspected for local validation. Searches for applicable ancestor
or repository `AGENTS.md` files found none applicable to this checkout.

## Clean room affirmation

I, the Codex agent operating in the session identified above, affirm that
I did not view BearSSL source or implementation descriptions, another
library's AES/GHASH/carry-less multiplier implementation, Pratique's
superseded portable multiplication, production GHASH source, integration
implementation or diff, the separate integration review report, Lazaret
PR #98's implementation diff, or PR #9 source or diff during this session.
No prohibited expression was intentionally copied or adapted. This
affirmation concerns the sources consulted and work performed in this
session; it is not a claim about the model's pretraining corpus.

Git author and committer are configured as requested:
`John A Booth <johnabooth@gmail.com>`.
That identity is commit metadata selected by the owner. It is not a claim
that John personally authored the expressions, generated the circuit, or
made the agent's clean-room affirmation. The affirmation is made by the
Codex agent.

## Integration continuation

On the user's request to continue toward a working implementation, a separate
integration agent was assigned fresh context and a separate checkout. This
clean-room author received interface requests and performance/test summaries
only. The prepared-state accessors and Clone support were added so the
integrator can apply existing key zeroization without exposing representation
outside the crate. Rust 1.87 assembly compilation was extended to all six
specified target families.

Integrated profiling showed the accepted S-box itself prevented reaching the
throughput gates. This author then consulted the permitted PR #8
`src/crypto/aes_sbox_clean.rs` and its tests, and NIST FIPS 197 at
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf. A new independent
field-tower S-box was derived in `cleanroom/aes_tower/`; its separate
derivation records the identity, basis search, and validation. The prohibited
implementation sources remain unviewed by this author.

Administrative continuation sources included runner contract/liveness tools,
Claude Desktop MCP configuration and the Lazaret runner's `config.toml` and
`config.windows.toml` directory settings, and GitHub capability/authentication
status metadata. Only non-secret exchange paths were selected from those
settings. The newly prepared `portable-crypto.yml` CI workflow was reviewed
for test commands, event triggers, and read-only token permissions. These
were administrative sources, not cryptographic implementation sources.
Production AES/GHASH bodies and all prohibited implementation sources remain
unviewed by this author. The separate integrator reports validation outcomes
and retains its own integration-phase provenance.

Independent pre-merge review subsequently identified deliberate by-value
preparation copies outside the caller's and retained-state wipes. This
clean-room author replaced those preparation APIs with zero-only construction,
borrowed raw input, direct destination filling, and in-place transposition.
No polynomial identities, gate expressions, or S-box expressions changed.
The integration author must wire the destination and retain existing volatile
raw/stored wipes; a separate reviewer checks the frozen repair. This removes
source-owned preparation scratch copies without claiming erasure of every
compiler-generated copy, register, or spill. Production sources remain
unviewed by this author.


## November 9 batch working-state continuation

The same clean-only author /root, workspace
01a1be54-c6e9-73d3-8a85-5e6f9a76a492, continued from accepted clean preparation
commit 5ecf25250b8c03065b48c673a49a23116bcca76c in the isolated worktree
/private/tmp/pratique-clean-batch-working-wipe-20261109. The unproven later
data-transpose restoration candidate was not used as this change's base.

The user supplied PRATIQUE-PR10-REVIEW-2026-11-09.md (SHA-256
ab20f0fb731aea7b217e13773cc2d13b595243b62b5c0edfd71af8409cbef544)
and pratique-pr10-ghash-class-controls-e2dd9a91.patch (SHA-256
96159ef4faec2bc3889d69b23fc41817f376394b16f5bf928501d07ee9f105b2).
The author read the report as findings: it contains ownership/interface
descriptions, source line references, mathematical summaries and assembly
counts/mnemonic names. The author did not inspect the attached production
test patch body, production AES/GHASH implementation, production diff or raw
production disassembly. The report's suggested causal classifications, gate
changes and other actions were not treated as instructions.

Separate integrator /root/ghash_integrator and reviewer
/root/pr10_final_review checked the working-aggregate finding and sent
source-free ownership/liveness and borrowed-workspace API requests. The
author inspected only the permitted, previously authored clean primitive,
generator and standalone adapters. The integrator's current API request is
preserved verbatim in results/working-state-1.87.0-20261109.json; this is not
a reconstruction or completeness claim for messages from earlier phases.

The clean-only change retains the polynomial identities and every generated
gate expression in the same order. It replaces the circuit's aggregate return
with a borrowed output and the used batch path's aggregate copies with
borrowed inputs and caller-owned zero-initialized working storage. No unsafe
code or external zeroization implementation is introduced into this primitive.
The integrator must apply the existing volatile wipes to all exposed working
buffers after final use and verify that emitted code retains them. Generated
node values, scalar temporaries, object moves and compiler spills are not
claimed to be completely erased. No timing or security finding is closed by
this clean-only API change or by quiet measurements on another machine.

## November 9 fixed public guard-lane continuation

The same independent author `/root`, parent workspace
`01a1be54-c6e9-73d3-8a85-5e6f9a76a492`, authored this candidate in isolated
clean-only workspace `/private/tmp/pratique-clean-guarded-batch-20261109`,
logical session `20261109-guarded-clmul`, based on clean commit
`27a1c8acfc42f41779c9e8bb2506c27615de9ede`. The owner requested an algorithm
compatible with the observed value-dependent runtime behavior, with repeated
testing on the problem processor and no dependence on a privileged CPU mode.

New sources consulted are source-free outcome summaries of the unchanged
gate, intermediate controls and fixed-slot key-swap controls; messages from
the previously assigned separate integrator/reviewer; and the author's own
clean circuit/generator and earlier SP800-38D test oracles. The root author
did not read the supplied timing patch bodies, production AES/GHASH code or
diffs, or production disassembly. No third-party cryptographic implementation
was consulted. The earlier unaccepted data-transpose candidate is not a base
or source for this work.

The new representation reserves fourteen public independent lanes in the
author's64-lane polynomial circuit and uses fifty real lanes. A deterministic
public finite witness covers each input and AND/XOR gate in the low, high and
mixed products with both sentinel bit values. Independent polynomial
multiplication derives the public guard-product correction. `GUARDED.md`
states the arithmetic, borrowed/in-place lifecycle API, finite proof and its
limits, including32-bit lowering and compiler reassociation. This source-only
continuation does not integrate GHASH or change its timing tests/thresholds.
Optimized-code review and unchanged whole-path8370C measurements remain
mandatory before recommending the candidate. It does not establish that the
observed effect is a CPU erratum or grant any timing/security waiver.

The separate integrator then requested a test-only borrowed read observer for
existing post-wipe and clone lifecycle assertions. The author added
`words(&self)` returning references to the same retained arrays, matching the
earlier API's test-only observer. It makes no populated copy and adds no
production operation or timing-path change.

The integrator also requested exact retained-state cloning, including already
wiped keys. The author added `copy_from(&mut self, &Self)` as three direct
slice copies into the caller's final retained destination. This deliberately
creates a second long-lived owner, each with its own wipe obligation, and
creates no source-owned scratch array or populated return. A lifecycle test
checks destination addresses, independence and preservation of wiped state.
