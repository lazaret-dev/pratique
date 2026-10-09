#!/usr/bin/env python3
"""Candidate cases for tests/data/tlog_vectors.txt: Merkle inclusion and consistency proofs (RFC 6962
section 2.1, RFC 9162 section 2.1), valid ones made from an independent reference implementation of
the RFC's recursive definitions, and damaged ones. Each line ends in this script's own verdict (from
a verifier written after RFC 9162 section 2.1.3.2 / 2.1.4.2); tools/tlog_oracle.go replaces it with
the verdict of Go's golang.org/x/mod/sumdb/tlog and fails if the two disagree. See
tools/gen_tlog_vectors.sh.

  incl SIZE INDEX LEAFHASH ROOT PROOF VERDICT      (PROOF: comma-separated hex hashes, or -)
  cons OLDSIZE OLDROOT NEWSIZE NEWROOT PROOF VERDICT

Trees: the first kind has leaf i = SHA-256(0x00 || "tiny_https tlog vector leaf i"); the second kind
(`const`) has the same leaf hash for every leaf, which makes trees of 2^62 leaves cheap, to get
proofs with 60 hashes and sizes near the end of the range.
"""
import hashlib
import sys

SEED = b"tiny_https tlog vectors 2026-10-05"
_ctr = 0


def rnd(n):
    """A deterministic number in [0, n), the same on every Python version."""
    global _ctr
    _ctr += 1
    d = hashlib.sha256(SEED + b"%d" % _ctr).digest()
    return int.from_bytes(d, "big") % n


def pick(seq):
    return seq[rnd(len(seq))]


def sha(b):
    return hashlib.sha256(b).digest()


def leaf_hash(rec):
    return sha(b"\x00" + rec)


def node(l, r):
    return sha(b"\x01" + l + r)


def lpt(n):
    """The largest power of two smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class Tree:
    """Leaves 0..n-1; mth(lo, hi) is the hash of the subtree over leaves lo..hi-1."""

    def __init__(self, n):
        self.n = n
        self.levels = [[leaf_hash(b"tiny_https tlog vector leaf %d" % i) for i in range(n)]]
        while len(self.levels[-1]) > 1:
            prev = self.levels[-1]
            self.levels.append([node(prev[i], prev[i + 1]) for i in range(0, len(prev) - 1, 2)])

    def leaf(self, i):
        return self.levels[0][i]

    def mth(self, lo, hi):
        n = hi - lo
        if n & (n - 1) == 0 and lo % n == 0:
            return self.levels[n.bit_length() - 1][lo // n]
        k = lpt(n)
        return node(self.mth(lo, lo + k), self.mth(lo + k, hi))


class ConstTree:
    """A tree of n leaves that all have the same hash."""

    def __init__(self, n):
        self.n = n
        self.l = leaf_hash(b"tiny_https tlog vector constant leaf")
        self.memo = {1: self.l}

    def leaf(self, i):
        return self.l

    def mth(self, lo, hi):
        return self.size_hash(hi - lo)

    def size_hash(self, n):
        if n not in self.memo:
            k = lpt(n)
            self.memo[n] = node(self.size_hash(k), self.size_hash(n - k))
        return self.memo[n]


def inclusion_proof(t, m, lo, hi):
    """RFC 6962 PATH(m, D[lo:hi])."""
    n = hi - lo
    if n == 1:
        return []
    k = lpt(n)
    if m < k:
        return inclusion_proof(t, m, lo, lo + k) + [t.mth(lo + k, hi)]
    return inclusion_proof(t, m - k, lo + k, hi) + [t.mth(lo, lo + k)]


def subproof(t, m, lo, hi, b):
    """RFC 6962 SUBPROOF(m, D[lo:hi], b)."""
    n = hi - lo
    if m == n:
        return [] if b else [t.mth(lo, hi)]
    k = lpt(n)
    if m <= k:
        return subproof(t, m, lo, lo + k, b) + [t.mth(lo + k, hi)]
    return subproof(t, m - k, lo + k, hi, False) + [t.mth(lo, lo + k)]


def verify_inclusion(proof, size, root, index, leaf):
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(proof, old, old_root, new, new_root):
    if old < 1 or old > new:
        return False
    if old == new:
        return not proof and old_root == new_root
    path = ([old_root] if old & (old - 1) == 0 else []) + list(proof)
    if not path:
        return False
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node(c, fr)
            sr = node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def hx(b):
    return b.hex()


def plist(proof):
    return ",".join(hx(p) for p in proof) if proof else "-"


def incl_line(proof, size, root, index, leaf):
    v = "ok" if verify_inclusion(proof, size, root, index, leaf) else "bad"
    return f"incl {size} {index} {hx(leaf)} {hx(root)} {plist(proof)} {v}"


def cons_line(proof, old, old_root, new, new_root):
    v = "ok" if verify_consistency(proof, old, old_root, new, new_root) else "bad"
    return f"cons {old} {hx(old_root)} {new} {hx(new_root)} {plist(proof)} {v}"


def flip(h):
    b = bytearray(h)
    b[rnd(len(b))] ^= 1 << rnd(8)
    return bytes(b)


def random_hash():
    return sha(b"random hash %d" % rnd(1 << 60))


# ------------------------------------------------------------------------------------ mutations


def mutate_inclusion(case):
    """A damaged copy of (proof, size, root, index, leaf)."""
    proof, size, root, index, leaf = case
    proof = list(proof)
    kind = rnd(13)
    if kind == 0 and proof:
        i = rnd(len(proof))
        proof[i] = flip(proof[i])
    elif kind == 1:
        root = flip(root)
    elif kind == 2:
        leaf = flip(leaf)
    elif kind == 3 and proof:
        proof.pop()
    elif kind == 4 and proof:
        proof.pop(0)
    elif kind == 5:
        proof.append(random_hash())
    elif kind == 6 and proof:
        proof.append(proof[-1])
    elif kind == 7 and len(proof) >= 2:
        i = rnd(len(proof) - 1)
        proof[i], proof[i + 1] = proof[i + 1], proof[i]
    elif kind == 8:
        index = index + 1 if index + 1 < size and rnd(2) else max(index - 1, 0) if index else index + 1
    elif kind == 9:
        size = size + 1 if rnd(2) or size == 1 else size - 1
    elif kind == 10:
        proof = []
    elif kind == 11 and proof:
        # the leaf and the first hash of the proof exchanged: a classic second-preimage move
        leaf, proof[0] = proof[0], leaf
    else:
        index = size + rnd(3)
    return proof, size, root, index, leaf


def mutate_consistency(case):
    proof, old, old_root, new, new_root = case
    proof = list(proof)
    kind = rnd(13)
    if kind == 0 and proof:
        i = rnd(len(proof))
        proof[i] = flip(proof[i])
    elif kind == 1:
        old_root = flip(old_root)
    elif kind == 2:
        new_root = flip(new_root)
    elif kind == 3 and proof:
        proof.pop()
    elif kind == 4 and proof:
        proof.pop(0)
    elif kind == 5:
        proof.append(random_hash())
    elif kind == 6 and proof:
        proof.append(proof[-1])
    elif kind == 7 and len(proof) >= 2:
        i = rnd(len(proof) - 1)
        proof[i], proof[i + 1] = proof[i + 1], proof[i]
    elif kind == 8:
        old = old + 1 if old + 1 <= new and rnd(2) else max(old - 1, 1)
    elif kind == 9:
        new = new + 1 if rnd(2) else max(new - 1, 1)
    elif kind == 10:
        proof = []
    elif kind == 11:
        old_root, new_root = new_root, old_root
    else:
        # a proof for a different old size
        old = max(1, old // 2) if old > 1 else old + 1
    return proof, old, old_root, new, new_root


# ------------------------------------------------------------------------------------ the cases


def main():
    out = []
    emit = out.append
    emit("# generated by tools/tlog_vectors.py; the verdict on each line is Go's (tools/tlog_oracle.go)")

    big = 100037
    t = Tree(big)

    def root_of(n):
        return t.mth(0, n)

    # inclusion proofs
    sizes_all = list(range(1, 10))
    sizes_some = [13, 16, 17, 31, 33, 64, 100, 129, 257, 1000, 4097, big]
    valid = []
    for n in sizes_all:
        for i in range(n):
            valid.append((n, i))
    for n in sizes_some:
        for i in sorted({0, n - 1, n // 2, rnd(n)}):
            valid.append((n, i))
    for n, i in valid:
        case = (inclusion_proof(t, i, 0, n), n, root_of(n), i, t.leaf(i))
        emit(incl_line(*case))
        emit(incl_line(*mutate_inclusion(case)))
    # a leaf of the wrong tree position and a root of the wrong size
    for n in (5, 8, 100):
        case = (inclusion_proof(t, 2, 0, n), n, root_of(n), 2, t.leaf(3))
        emit(incl_line(*case))
        case = (inclusion_proof(t, 2, 0, n), n, root_of(n + 1), 2, t.leaf(2))
        emit(incl_line(*case))

    # consistency proofs
    pairs = [(m, n) for n in range(1, 10) for m in range(1, n + 1)]
    for n in sizes_some:
        for m in sorted({1, n // 2, n - 1, n, lpt(n) if n > 1 else 1, rnd(n) + 1}):
            if 1 <= m <= n:
                pairs.append((m, n))
    for m, n in pairs:
        proof = subproof(t, m, 0, n, True) if m < n else []
        case = (proof, m, root_of(m), n, root_of(n))
        emit(cons_line(*case))
        emit(cons_line(*mutate_consistency(case)))
    # empty old tree, and old larger than new
    emit(cons_line([], 0, sha(b""), 5, root_of(5)))
    emit(cons_line([], 7, root_of(7), 5, root_of(5)))
    emit(cons_line([], 0, sha(b""), 0, sha(b"")))

    # huge trees whose leaves all have one hash (Go cannot go past 2^62: its maxpow2 never ends)
    for n in ((1 << 40) + 12345, 1 << 62):
        c = ConstTree(n)
        root = c.mth(0, n)
        for i in (n // 2 + 7, n - 1):
            case = (inclusion_proof(c, i, 0, n), n, root, i, c.l)
            emit(incl_line(*case))
            emit(incl_line(*mutate_inclusion(case)))
        for m in ((1 << 39) + 5, n - 1):
            case = (subproof(c, m, 0, n, True), m, c.mth(0, m), n, root)
            emit(cons_line(*case))
            emit(cons_line(*mutate_consistency(case)))
    # random hashes of the right and wrong lengths are refused
    c = ConstTree(1 << 62)
    for length in (0, 62, 63):
        emit(incl_line([random_hash() for _ in range(length)], 1 << 62, c.mth(0, 1 << 62), 1 << 61, c.l))

    for line in out:
        print(line)


if __name__ == "__main__":
    sys.exit(main())
