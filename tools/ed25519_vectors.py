#!/usr/bin/env python3
"""Generates tests/data/ed25519_vectors.txt: Ed25519 verification vectors that exercise the places where
verifiers differ, each with the verdict of Go's crypto/ed25519 (and, for information, of OpenSSL).

    python3 tools/ed25519_vectors.py            # needs `go` (the verdicts) and, optionally, the Python
                                                # `cryptography` package (the OpenSSL column)

Line format:   family:A:sig:message:go:openssl      (all hex, `go` and `openssl` are 1 or 0, or ? if the
                                                     package is not installed)

The families are the ones in https://hdevalence.ca/blog/2020-10-04-its-25519am, built from scratch here:

  small-order    A and R each one of the 14 encodings of a point of small order (the eight points of the
                 torsion subgroup, plus six non-canonical encodings of four of them), S in {0, 1, L-1, L}
  mixed-order    A = A0 + T for each of the seven non-zero torsion points T, with signatures that are valid
                 for A0 (so they verify only if k*T = 0, which depends on whether the verifier reduces k
                 modulo L before multiplying: both outcomes are present)
  residue-R      R = R0 + T with the S of the honest signature (rejected by a cofactorless verifier)
  malleable      S + L, and S with a high bit set
  invalid-A      encodings that are not on the curve; odd-A: a few other awkward key encodings
  valid          ordinary signatures, and single bit flips in the key, message and signature

Everything is deterministic (fixed seed). Nothing here is used by the library: it only produces data."""

import hashlib
import os
import random
import subprocess
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
I = pow(2, (P - 1) // 4, P)
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
B = (BX, BY)
IDENT = (0, 1)


def add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P
    return (x3, y3)


def neg(p):
    return ((-p[0]) % P, p[1])


def mul(k, p):
    r = IDENT
    q = p
    while k:
        if k & 1:
            r = add(r, q)
        q = add(q, q)
        k >>= 1
    return r


def enc(p, sign=None, add_p=False):
    """Encodes a point; `sign` overrides the parity bit and `add_p` writes y + p (when it fits)."""
    x, y = p
    if add_p:
        y += P
        assert y < 2**255
    s = (x & 1) if sign is None else sign
    return (y | (s << 255)).to_bytes(32, "little")


def decode(b):
    """A strict decoder, for building test points (not the one under test)."""
    v = int.from_bytes(b, "little")
    y = v & ((1 << 255) - 1)
    s = v >> 255
    if y >= P:
        return None
    u = (y * y - 1) % P
    w = (D * y * y + 1) % P
    x2 = u * pow(w, -1, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * I % P
    if (x * x - x2) % P:
        return None
    if x == 0 and s:
        return None
    if (x & 1) != s:
        x = (-x) % P
    return (x, y)


def torsion():
    """All eight points of E[8], found by clearing the large-order part of random points."""
    rng = random.Random(8)
    found = {IDENT}
    while len(found) < 8:
        y = rng.randrange(P)
        pt = decode(y.to_bytes(32, "little"))
        if pt is None:
            continue
        found.add(mul(L, pt))
    return sorted(found)


def order(p):
    k, q = 1, p
    while q != IDENT:
        q = add(q, p)
        k += 1
    return k


def small_order_encodings():
    """The 14 encodings: 8 canonical, 6 non-canonical (y + p for y in {0, 1}, and x = 0 with the sign bit set)."""
    t = torsion()
    out = []
    for pt in t:
        out.append(("canon", pt, enc(pt)))
    # y = 0 (the two points of order 4) and y = 1 (the identity) also encode as y + p
    for pt in t:
        if pt[1] in (0, 1):
            out.append(("y+p", pt, enc(pt, add_p=True)))
    # x = 0 with the sign bit set: the identity and the point of order 2
    for pt in t:
        if pt[0] == 0:
            out.append(("x0-sign", pt, enc(pt, sign=1)))
    # ... and the identity with both: y + p and the sign bit set
    out.append(("y+p-x0-sign", IDENT, enc(IDENT, sign=1, add_p=True)))
    assert len(out) == 8 + 3 + 2 + 1, len(out)
    return out


def h512(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def sign_with_scalar(a, a_enc, msg, r, torsion_for_R=None):
    """A signature for the (possibly mixed-order) key encoding `a_enc` whose discrete log relative to the
    prime-order part is `a`. Returns (sig, k_reduced, k_full)."""
    R = mul(r, B)
    r_enc = enc(R)
    kfull = h512(r_enc, a_enc, msg)
    k = kfull % L
    S = (r + k * a) % L
    return r_enc + S.to_bytes(32, "little"), k, kfull, R, S


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rng = random.Random(25519)
    rows = []

    def row(family, a, sig, msg):
        assert len(a) == 32 and len(sig) == 64, (family, len(a), len(sig))
        rows.append((family, a.hex(), sig.hex(), msg.hex()))

    so = small_order_encodings()
    msg = b"Zcash"
    s_values = [0, 1, L - 1, L]
    for na, pa, ea in so:
        for nr, pr, er in so:
            for s in s_values:
                row("small-order", ea, er + s.to_bytes(32, "little"), msg)

    # an ordinary key: scalar a, public A = aB
    def keypair():
        a = rng.randrange(1, L)
        return a, enc(mul(a, B))

    tors = [t for t in torsion() if t != IDENT]
    # valid signatures and bit flips
    for n in range(12):
        a, A = keypair()
        m = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 5, 32, 33, 100, 300])))
        sig, _, _, _, _ = sign_with_scalar(a, A, m, rng.randrange(1, L))
        row("valid", A, sig, m)
        if n < 6:
            for bit in rng.sample(range(512), 12):
                bad = bytearray(sig)
                bad[bit // 8] ^= 1 << (bit % 8)
                row("flip-sig", A, bytes(bad), m)
            for bit in rng.sample(range(256), 6):
                bad = bytearray(A)
                bad[bit // 8] ^= 1 << (bit % 8)
                row("flip-key", bytes(bad), sig, m)
            if m:
                bad = bytearray(m)
                bad[0] ^= 1
                row("flip-msg", A, sig, bytes(bad))
            row("extend-msg", A, sig, m + b"\0")

    # malleability: S + L, and S with high bits set
    for n in range(6):
        a, A = keypair()
        m = b"malleable %d" % n
        sig, _, _, _, S = sign_with_scalar(a, A, m, rng.randrange(1, L))
        r_enc = sig[:32]
        row("malleable", A, r_enc + (S + L).to_bytes(32, "little"), m)
        row("malleable", A, r_enc + (S + 2 * L).to_bytes(32, "little"), m)
        row("malleable", A, r_enc + (S + 8 * L).to_bytes(32, "little"), m)
        row("malleable", A, r_enc + (S | (1 << 253)).to_bytes(32, "little"), m)
        row("malleable", A, r_enc + (S | (1 << 255)).to_bytes(32, "little"), m)

    # mixed-order keys: A' = A0 + T, signed as if for A0. Valid iff [k]T = 0, and k is the reduced one.
    for t in tors:
        o = order(t)
        a, A0 = keypair()
        Aprime = enc(add(decode(A0), t))
        want = {"both": 3, "reduced-only": 2, "full-only": 2, "neither": 2}
        tries = 0
        while any(want.values()) and tries < 20000:
            tries += 1
            m = b"mixed %d %d" % (o, tries)
            sig, k, kfull, _, _ = sign_with_scalar(a, Aprime, m, rng.randrange(1, L))
            kind = {(True, True): "both", (True, False): "reduced-only", (False, True): "full-only", (False, False): "neither"}[
                (k % o == 0, kfull % o == 0)
            ]
            if want[kind]:
                want[kind] -= 1
                # "reduced-only": accepted by a verifier that reduces k modulo L and rejected by one that does not
                row("mixed-order-" + kind, Aprime, sig, m)
        assert not any(want.values()), (o, want)

    # a torsion component in R: the honest S, R + T (rejected by a cofactorless verifier)
    for t in tors:
        a, A = keypair()
        m = b"residue-R"
        sig, k, _, R, S = sign_with_scalar(a, A, m, rng.randrange(1, L))
        row("residue-R", A, enc(add(R, t)) + S.to_bytes(32, "little"), m)

    # torsion in both R and A, arranged so that [k]T_A + T_R = 0 and the cofactorless equation balances
    for t in tors:
        a, A0 = keypair()
        Aprime = enc(add(decode(A0), t))
        m = b"residue-RA"
        found = 0
        tries = 0
        while found < 2 and tries < 20000:
            tries += 1
            r = rng.randrange(1, L)
            R0 = mul(r, B)
            for tr in [IDENT] + tors:
                Rp = enc(add(R0, tr))
                k = h512(Rp, Aprime, m) % L
                if add(tr, mul(k, t)) == IDENT:
                    S = (r + k * a) % L
                    row("residue-RA-cancels", Aprime, Rp + S.to_bytes(32, "little"), m)
                    found += 1
                    break
        assert found == 2
        # the same key and R, but a message for which it does not cancel
        sig, k, _, R, S = sign_with_scalar(a, Aprime, b"residue-RA other", rng.randrange(1, L))
        row("residue-RA-fails", Aprime, enc(add(R, t)) + S.to_bytes(32, "little"), b"residue-RA other")

    # keys that are not on the curve
    bad = 0
    y = 2
    while bad < 8:
        if decode(y.to_bytes(32, "little")) is None:
            row("invalid-A", y.to_bytes(32, "little"), enc(IDENT) + bytes(32), b"invalid")
            bad += 1
        y += 1
    # odd keys: all ones (y = 2^255 - 1 reduces to 18 with the sign bit set), y = 0 (a point of order 4), and
    # y = 0 with the sign bit set (the other one)
    for a in (b"\xff" * 32, b"\x00" * 32, b"\x00" * 31 + b"\x80"):
        row("odd-A", a, enc(IDENT) + bytes(32), b"odd")

    # run Go (and OpenSSL) over them
    inp = "".join("%s:%s:%s:%s\n" % r for r in rows)
    go = subprocess.run(
        ["go", "run", os.path.join(root, "tools", "ed25519_verdicts.go")],
        input=inp, capture_output=True, text=True, check=True,
    ).stdout.split()
    assert len(go) == len(rows), (len(go), len(rows))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        def openssl(a, sig, m):
            try:
                Ed25519PublicKey.from_public_bytes(a).verify(sig, m)
                return "1"
            except (InvalidSignature, ValueError):
                return "0"
    except ImportError:
        openssl = None

    out = [
        "# Ed25519 verification vectors, generated by tools/ed25519_vectors.py (fixed seed). Fields, all hex:",
        "#   family : public key : signature (R || S) : message : go : openssl",
        "# `go` is the verdict of Go's crypto/ed25519 (go1.24), which this crate's verifier must reproduce exactly;",
        "# `openssl` is the verdict of OpenSSL, for information; where the two differ, `go` is the reference.",
        "# 1 means the signature verifies. Every family is described in the generator.",
    ]
    stats = {}
    for r, g in zip(rows, go):
        o = openssl(bytes.fromhex(r[1]), bytes.fromhex(r[2]), bytes.fromhex(r[3])) if openssl else "?"
        out.append("%s:%s:%s:%s:%s:%s" % (r + (g, o)))
        s = stats.setdefault(r[0], [0, 0, 0, 0])
        s[0] += 1
        s[1] += g == "1"
        s[2] += o == "1"
        s[3] += g != o
    path = os.path.join(root, "tests", "data", "ed25519_vectors.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("family            vectors  go-accepts  openssl-accepts  differ")
    for k, s in stats.items():
        print("%-17s %7d %11d %16d %7d" % (k, *s))
    print("total", len(rows), "written to", path)


if __name__ == "__main__":
    main()
