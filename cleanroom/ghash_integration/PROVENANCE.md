# Integration-phase provenance

This integration was performed by a separate Codex reviewer/integrator agent,
not by the clean-room primitive author. The integration checkout is
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
