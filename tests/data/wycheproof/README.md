# Project Wycheproof vectors

From https://github.com/C2SP/wycheproof, directory `testvectors_v1`, downloaded on 2026-10-07 (branch `main`) and
compressed with `gzip -9 -n`. Licensed under the Apache License 2.0 by their authors (Google and the C2SP project).
`tests/wycheproof.rs` replays them.

| File | SHA-256 of the JSON before compression |
|------|-----------------------------------------|
| `ecdsa_secp521r1_sha512_test.json` | `0fa3bb09a2319242253028b53d555fb8ec2081d891271321205cdaeabb3eef3e` |
| `rsa_pss_2048_sha256_mgf1_32_test.json` | `7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c` |
| `rsa_pss_2048_sha384_mgf1_48_test.json` | `66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c` |
| `rsa_pss_4096_sha512_mgf1_64_test.json` | `c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547` |

To refresh one: download it again from the same directory, check what changed, compress it the same way, and update the
hash here.
