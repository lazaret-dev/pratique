# Scoped current-code attribution audit

This is an engineering audit of the two implementation techniques named by the
former BearSSL entry in Pratique's NOTICE. It is not a legal originality
opinion, a comparison against third-party implementation source, or a claim
about every dependency/test fixture or downstream release. No BearSSL,
third-party cryptographic implementation, or PR #9 source was consulted.

The separate integrator is `/root/ghash_integrator`; independent read-only
review is `/root/pr10_final_review`, in the logical contexts identified by
`CLEAN_ROOM_AES_GHASH.md`. The primitive author's original affirmations remain
unchanged. The relevant integration code is frozen in
`3db15f5495b6608094102bff87ec36970d1d36aa`, after merging the independent
borrowed API commit `5ecf25250b8c03065b48c673a49a23116bcca76c`.

The source review did more than search names. It traced the documented scope
of NOTICE-introduction commit `7d7bc1090be6ae379daec2dcabd82a80492719c8` and
initial import `f61cfe5c`, with accepted baseline `55cfa19f`. The former entry
identified the removed S-box gate sequence and portable multiplication
technique. The reviewer inspected the retained AES packing, row/column maps,
key schedule, and GHASH composition, reduction and recurrence against their
mathematical/standard roles. All 22 retained core bodies were unchanged from
the initial import apart from formatting; no evidence tied those retained
bodies to the removed expressions. All 45 checked 48-token windows from the
three removed bodies had zero matches across current Rust source.

History begins at that initial import. These observations establish the
repository's documented attribution scope and removal of the identified
expressions; they cannot prove pre-import originality or exclude unknown
external resemblance. The code-author provenance statements and this limitation
are retained explicitly.

The package was audited BEFORE NOTICE changed. Candidate source archive
`/private/tmp/pratique-lifecycle-package/package/pratique-0.1.0.crate` had
SHA-256 `87a3496034df055261234b638572fb888bf749bebbab30771b86d56f129a9165`
and 909 entries. Independent review verified all 193 `src/` files and their
inventory byte for byte against frozen code `3db15f54`; all 237 Rust files in
the archive had zero removed-expression fingerprint matches. Packaged current
README/role/provenance descriptions were checked. Remaining names were
historical/provenance records, completed BACKLOG items, and the then-unchanged
NOTICE entry. The source package contains no Git history or external review
patch. The candidate's dirty VCS marker reflects staged documentation and is
not represented as a frozen final artifact.

The prepared-key lifecycle was independently reviewed in source and whole-crate
MSRV debug/release IR. Its only deliberate raw preparation array belongs to the
caller. The raw 64-word array and running scalar reach volatile zeroization;
retained planes are populated and transposed in place. No returning-populated
preparation aggregate or large callee scratch-array route remains. Final key
object moves and compiler register/stack copies retain the established
best-effort `Zeroize` limitation; complete physical erasure is not promised.

On that source/history/artifact evidence, the obsolete current-code BearSSL
entry was removed from NOTICE. Mozilla, Sigstore and test-data notices are
preserved verbatim apart from section renumbering. No unrelated licence,
Lazaret re-vendor, package expression, merge or release is changed by this audit.
Final readiness requires a second frozen-package check after the scoped NOTICE
amendment; its immutable hash and VCS identity are recorded with final review/PR
evidence.

The independent source-free evidence records are retained in
`lifecycle_results/production-lifecycle-repair-evidence.json` and
`lifecycle_results/pre-notice-package-attribution-audit.json`. Their original
SHA-256 values are respectively
`98c15252b05dec2a86d28b24ae1d5bef59ac987e49cd5c12dc8df8955ab76134` and
`278292d71009a487995ecdea2b9f416eb951a85c775c98eda6eb33bba8c16682`.
