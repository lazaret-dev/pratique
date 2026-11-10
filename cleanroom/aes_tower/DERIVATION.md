# AES S box field tower derivation

The accepted PR #8 S-box uses four full GF(256) multiplications for inversion.
Its integrated AES CTR performance was below the requested GCM gates even
before GHASH. This independently derived circuit evaluates the same inverse
through three quadratic fields, then applies the same AES affine map. It
contains 36 AND and 124 XOR or NOT source operations for 64 simultaneous lanes.

## Field representation

The AES field has modulus `x^8+x^4+x^3+x+1`, and its S-box applies inversion
followed by the affine map in [NIST FIPS 197, sections 4.4 and 5.1.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).
The equivalent tower used here is:

```text
GF4   = GF2[u] / (u^2 + u + 1)
GF16  = GF4[z] / (z^2 + z + (u + 1))
GF256 = GF16[w] / (w^2 + w + (u + 1)z)
```

In AES polynomial coordinates, the chosen roots are `u=0xbc`, `z=0xe0`, and
`w=0x42`. The basis `1,u,z,uz,w,uw,zw,uzw` is consequently
`01 bc e0 0d 42 b7 e5 77`. The generator checks all 256 embeddings are unique,
finds the roots using only polynomial arithmetic, and restricts extension
constants to absolute trace one. The quadratic extensions are therefore
fields, and the mapping preserves sums, products, and inverses.

## Inversion identity

For `t=a+bw` with `w^2+w+lambda=0`, conjugation replaces `w` by `w+1`.
Multiplying the two conjugates cancels the coefficient of `w`:

```text
norm = a^2 + ab + lambda b^2
inverse(t) = ((a+b) + bw) / norm
```

The GF16 inverse of the norm uses the same identity over GF4. In GF4,
inversion is squaring because its nonzero group has order three. Each
operation maps zero to zero naturally. Squaring and multiplication by a
fixed field constant are linear maps over GF2, so they need XORs only.

At the bottom of the tower, write the GF4 inputs as `a0+a1u` and `b0+b1u`.
The three products `p0=a0b0`, `p1=a1b1`, and `pm=(a0+a1)(b0+b1)` give the
two result coefficients `p0+p1` and `pm+p0`. Thus each GF4 multiply needs
three AND operations, and each GF16 multiply uses three GF4 multiplies.
The outer inverse uses three GF16 multiplies and the inner inverse three
GF4 multiplies, for 36 AND operations altogether.

The input basis conversion is a fixed binary matrix. Output conversion and
the AES affine map are combined into another fixed matrix, plus `0x63`.
The generator flattens linear expressions and shares repeated XOR pairs.
It enumerates 128 valid basis choices and selects the one with the smallest
source operation count. All search, dictionaries, and tables occur during
generation. The Rust circuit uses literal plane indices and fixed Boolean
expressions, with no runtime table, branch, loop, allocation, unsafe code,
integer multiplication, or target-specific intrinsic.

## Validation and provenance

The six standalone tests pass on Rust 1.87.0 and 1.99.1. They include the
accepted PR #8 tests against the FIPS table, every byte in every lane,
and 10,000 deterministic mixed-plane inputs. The S-box is used on a dependent
chain in the benchmark to expose latency between successive calls.

| Compiler | Accepted PR #8 ns per 64-lane call | Tower ns per call |
| --- | ---: | ---: |
| Rust 1.87.0 | 28.863 | 13.193 |
| Rust 1.99.1 | 29.048 | 11.992 |

These are medians of nine million-call windows on the local Apple ARM64
machine, not an integrated GCM measurement. The integrator must establish
the full portable throughput and timing gates, hardware parity, normal
hardware performance, TLS, authentication-failure behavior, and fuzz results.

This circuit and its generator were written from blank files by Codex in
clean-room session `20261108-clmul-feasibility`, November 8, 2026, America/Chicago
(client date). Sources consulted for this continuation were the supplied
requirements, PR #8 `aes_sbox_clean.rs` and its tests, FIPS 197 at the URL
above, and mathematics derived here. No production AES/GHASH, previous
integration implementation, PR #9, BearSSL, or third-party implementation
was viewed by this agent. The separate integration agent receives the
committed circuit and reports results without sending production code back.

Git identity remains `John A Booth <johnabooth@gmail.com>` as requested by
the owner. It does not claim John personally authored these expressions or
made the Codex agent's clean-room affirmation.

Reproduce with `python3 cleanroom/aes_tower/generate.py`, then compile
`probe.rs` with `rustc +1.87.0 --edition=2024 -O --test` for tests or without
`--test` for the benchmark. `assembly.rs` is a no_std wrapper for cross-target
assembly review. The checked-in generated Rust needs no generator or build
dependency to compile.
