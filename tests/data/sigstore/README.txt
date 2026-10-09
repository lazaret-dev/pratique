Sigstore attestations, real and made up. Used by tests/sigstore_real.rs, tests/sigstore_synthetic.rs, the
`sigstore` and `trust_root` fuzz targets and examples/sigstore_verify.rs. No secrets: everything here is public
data (the synthetic keys are throwaway and are not written to disk).

REAL DATA, byte for byte as served (fetched 2026-10-05 from the npm registry and PyPI and handed over with their
checksums; each statement's subject digest was checked against its artifact when fetched; every artifact is
Apache-2.0):

  sigstore-{0.2.0,2.2.0,4.0.0}.attestations.json
                 the response of https://registry.npmjs.org/-/npm/v1/attestations/sigstore@VERSION: two
                 attestations each, npm's publish attestation (signed with the registry's own key: a
                 `publicKey.hint`, no certificate) and SLSA provenance (a Fulcio certificate). One version per
                 bundle format: 0.2.0 is `bundle+json;version=0.1` (signed entry timestamps only), 2.2.0 is
                 `version=0.2` (with inclusion proofs, to a Rekor shard that has since been closed), 4.0.0 has a
                 `bundle.v0.3+json` provenance and a `version=0.2` publish attestation, signed with npm's
                 second key.
  sigstore-{0.2.0,2.2.0,4.0.0}.tgz
                 the tarballs the attestations are about (their SHA-512 is the subject digest)
  npm-registry-keys.json
                 https://registry.npmjs.org/-/npm/v1/keys: npm's two keys. The first (SHA256:jl3bwswu...) expired
                 2025-01-29 yet signed the 0.2.0 and 2.2.0 publish attestations, so a key counts at the time the
                 log vouches for, not now.
  pypi_attestations-0.0.30-py3-none-any.whl, ...whl.provenance.json
                 a PyPI wheel and PyPI's PEP 740 provenance for it
                 (https://pypi.org/integrity/pypi-attestations/0.0.30/<wheel>/provenance): not a Sigstore bundle
                 but the same parts (a certificate, transparency entries, a DSSE statement and signature).
  trusted_root.json
                 Sigstore's production trusted root (Fulcio CAs, Rekor and certificate transparency logs, the
                 time-stamp authority), the copy that sigstore-python 4.5.0 embeds from its TUF repository
                 (tuf-repo-cdn.sigstore.dev, which the network policy of the machine that made this blocked).
                 To refresh it, fetch the current `trusted_root.json` from that TUF repository (and verify it with
                 TUF); the real-data tests should pass with it unchanged, because a root only ever gains keys and
                 authorities with their periods (the old Fulcio CA and Rekor key are needed for the 2022 to 2024
                 releases).

  sha256 checksums:
    4d921453664f96b4265f6812faec516ee46418c827ee58b83688b8218bca9288  sigstore-0.2.0.tgz
    59e1ee9d7f748ddb3fe0fb6c590f3400b32632aaf0783ebd21a8e96d93082ef6  sigstore-2.2.0.tgz
    93fbc9c49095481a2ca4a73875505351b27554c04f64e66122cb5d8ae5450afa  sigstore-4.0.0.tgz
    51ddf94d76d929591976ce9c6bf215a606a10b40dddaf170f1d7e61590ed42c9  sigstore-0.2.0.attestations.json
    63c83094c2e14360175aee1c6b9266c5f1734188a7fd3a483b66170d05ec377e  sigstore-2.2.0.attestations.json
    261d36a82e7b96193de4502d2afa8ab73378cb3346b6d22c8a39f9bf5bf1492f  sigstore-4.0.0.attestations.json
    faf23d8753d5bb79df250f10391ac89b63ecf7743e48487a544a99c847f9c8df  npm-registry-keys.json
    b3a9c53f6cb89e5e7b5b70e6cfca97cfc66008c1ed54087355e06e40071cef21  pypi_attestations-0.0.30-py3-none-any.whl
    661bcb3ac9507c5da215f38e25a0a19725cf6bda53660a9b3616458e413c2f0d  pypi_attestations-0.0.30-py3-none-any.whl.provenance.json
    6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66  trusted_root.json

MADE UP:

  synthetic.json
                 made by tools/gen_sigstore_fixtures.py (Python `cryptography` and `openssl`; run it from the
                 repository root; the keys are new on every run, so rerunning changes the file): a Sigstore of
                 our own with a Fulcio-like CA, a Rekor-like log that signs with ECDSA, a second log that signs
                 with Ed25519 and gives inclusion proofs only (Rekor v2's way), and an RFC 3161 time-stamp
                 authority whose tokens carry the time the generator chooses, and two CT logs (P-256 and RSA) whose SCTs are
                 embedded in every leaf it issues. 108 bundles, each with the
                 trusted root to check it against and the verdict to expect (`ok` and the facts, or the kind of
                 error and a part of its message); they cover what the real data does not reach: time stamps
                 and what a time is, proof-only entries, certificates of every key type, e-mail and username
                 identities, the end of a validity to the second, and about 55 refusals that a real signer never
                 produces (an entry body that binds another signature, a checkpoint from another key, a time
                 stamp from a rogue authority, a leaf used as a time-stamp authority, ...).
