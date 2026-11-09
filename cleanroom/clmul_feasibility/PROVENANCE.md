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
