#!/usr/bin/env python3
"""Independently derive a bitsliced AES inverse in a quadratic field tower.

Sources: NIST FIPS 197 field modulus and affine map, accepted PR #8 primitive
and tests, and algebra derived in this clean-room session. No third-party
circuit or implementation source was consulted. All search is development
time; generated Rust contains only fixed AND/XOR/NOT expressions.
"""

from collections import Counter
from itertools import combinations
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def aes_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11B
        b >>= 1
    return p


def mul4(a, b):
    p = 0
    for _ in range(2):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 4:
            a ^= 7
        b >>= 1
    return p


def mul16(a, b, mu):
    a0, a1, b0, b1 = a & 3, a >> 2, b & 3, b >> 2
    low = mul4(a0, b0) ^ mul4(mu, mul4(a1, b1))
    high = mul4(a0, b1) ^ mul4(a1, b0) ^ mul4(a1, b1)
    return low ^ (high << 2)


def embed(value, basis):
    out = 0
    for i, column in enumerate(basis):
        if (value >> i) & 1:
            out ^= column
    return out


def affine_linear(value):
    out = value
    for shift in range(1, 5):
        out ^= ((value << shift) | (value >> (8 - shift))) & 255
    return out


class Circuit:
    def __init__(self):
        self.nodes = {}
        self.and_cache = {}
        self.count = 0

    def and_(self, a, b):
        if not a or not b:
            return frozenset()
        if a == b:
            return a
        if a == frozenset(["ONE"]):
            return b
        if b == frozenset(["ONE"]):
            return a
        key = tuple(sorted([a, b], key=lambda x: tuple(sorted(x))))
        if key not in self.and_cache:
            name = f"a{self.count}"
            self.count += 1
            self.nodes[name] = ["&", a, b]
            self.and_cache[key] = name
        return frozenset([self.and_cache[key]])

    def multiply4(self, a, b):
        p0 = self.and_(a[0], b[0])
        p1 = self.and_(a[1], b[1])
        pm = self.and_(a[0] ^ a[1], b[0] ^ b[1])
        return [p0 ^ p1, pm ^ p0]

    @staticmethod
    def linear(columns, value, width):
        out = []
        for bit in range(width):
            form = frozenset()
            for index, column in enumerate(columns):
                if (column >> bit) & 1:
                    form ^= value[index]
            out.append(form)
        return out

    def multiply16(self, a, b, mu):
        lo = self.multiply4(a[:2], b[:2])
        hi = self.multiply4(a[2:], b[2:])
        mid = self.multiply4([a[0] ^ a[2], a[1] ^ a[3]],
                             [b[0] ^ b[2], b[1] ^ b[3]])
        scaled = self.linear([mul4(mu, 1), mul4(mu, 2)], hi, 2)
        return [lo[0] ^ scaled[0], lo[1] ^ scaled[1], mid[0] ^ lo[0], mid[1] ^ lo[1]]

    def inverse16(self, value, mu):
        a, b = value[:2], value[2:]
        square_a = self.linear([mul4(1, 1), mul4(2, 2)], a, 2)
        square_b = self.linear([mul4(1, 1), mul4(2, 2)], b, 2)
        product = self.multiply4(a, b)
        scaled_b = self.linear([mul4(mu, 1), mul4(mu, 2)], square_b, 2)
        norm = [square_a[i] ^ product[i] ^ scaled_b[i] for i in range(2)]
        inv_norm = self.linear([mul4(1, 1), mul4(2, 2)], norm, 2)
        return (self.multiply4([a[i] ^ b[i] for i in range(2)], inv_norm)
                + self.multiply4(b, inv_norm))

    def sbox(self, basis, mu, lam):
        inverse_map = {embed(value, basis): value for value in range(256)}
        assert len(inverse_map) == 256
        q = [frozenset([f"q[{i}]"]) for i in range(8)]
        tower = self.linear([inverse_map[1 << i] for i in range(8)], q, 8)
        a, b = tower[:4], tower[4:]
        sq_columns = [mul16(1 << i, 1 << i, mu) for i in range(4)]
        aa, bb = self.linear(sq_columns, a, 4), self.linear(sq_columns, b, 4)
        ab = self.multiply16(a, b, mu)
        scaled = self.linear([mul16(lam, 1 << i, mu) for i in range(4)], bb, 4)
        norm = [aa[i] ^ ab[i] ^ scaled[i] for i in range(4)]
        inv_norm = self.inverse16(norm, mu)
        inverse = (self.multiply16([a[i] ^ b[i] for i in range(4)], inv_norm, mu)
                   + self.multiply16(b, inv_norm, mu))
        out = self.linear([affine_linear(column) for column in basis], inverse, 8)
        return [form ^ (frozenset(["ONE"]) if (0x63 >> i) & 1 else frozenset())
                for i, form in enumerate(out)]

    def optimize(self, outputs):
        # All XOR expressions are linear combinations of input bits and earlier
        # AND outputs. Sharing a repeated pair saves one XOR per extra use.
        forms = []
        slots = []
        for name, node in self.nodes.items():
            for index in [1, 2]:
                forms.append(node[index])
                slots.append((name, index))
        forms.extend(outputs)
        next_xor = 0
        while True:
            counts = Counter(pair for form in forms
                             for pair in combinations(sorted(form), 2))
            if not counts:
                break
            pair, uses = min(counts.items(), key=lambda item: (-item[1], item[0]))
            if uses < 2:
                break
            name = f"x{next_xor}"
            next_xor += 1
            pair_set = frozenset(pair)
            forms = [(form - pair_set) | frozenset([name]) if pair_set <= form else form
                     for form in forms]
            forms.append(pair_set)
        for (name, index), form in zip(slots, forms):
            self.nodes[name][index] = form
        output_start = len(slots)
        optimized_outputs = forms[output_start:output_start + 8]
        for index, form in enumerate(forms[output_start + 8:]):
            self.nodes[f"x{index}"] = ["^", form]
        xor_count = sum(max(0, len(form) - 1) for form in forms)
        return optimized_outputs, xor_count

    def emit(self, outputs):
        lines, visited, active = [], set(), set()

        def expression(form):
            for token in sorted(form):
                visit(token)
            return " ^ ".join(sorted(form)) if form else "0"

        def visit(token):
            if token not in self.nodes or token in visited:
                return
            assert token not in active, "cyclic expression"
            active.add(token)
            node = self.nodes[token]
            if node[0] == "&":
                expr = f"({expression(node[1])}) & ({expression(node[2])})"
            else:
                expr = expression(node[1])
            lines.append(f"    let {token} = {expr};")
            active.remove(token)
            visited.add(token)

        out = [expression(form) for form in outputs]
        lines.append("    [" + ", ".join(out) + "]")
        return lines


def main():
    best = None
    candidates = 0
    for u in range(256):
        if aes_mul(u, u) ^ u ^ 1:
            continue
        for mu in [2, 3]:
            mu_aes = embed(mu, [1, u])
            for z in range(256):
                if aes_mul(z, z) ^ z ^ mu_aes:
                    continue
                small_basis = [1, u, z, aes_mul(u, z)]
                for lam in range(1, 16):
                    power, trace = lam, 0
                    for _ in range(4):
                        trace ^= power
                        power = mul16(power, power, mu)
                    if trace != 1:
                        continue
                    lam_aes = embed(lam, small_basis)
                    for w in range(256):
                        if aes_mul(w, w) ^ w ^ lam_aes:
                            continue
                        basis = small_basis + [aes_mul(w, b) for b in small_basis]
                        circuit = Circuit()
                        outputs = circuit.sbox(basis, mu, lam)
                        outputs, xors = circuit.optimize(outputs)
                        record = {"u": u, "mu": mu, "z": z, "lambda": lam, "w": w,
                                  "basis_aes": basis, "and_count": circuit.count,
                                  "xor_count": xors}
                        score = (circuit.count + xors, xors, basis)
                        candidates += 1
                        if best is None or score < best[0]:
                            best = score, record, circuit.emit(outputs)
    _, record, lines = best
    record["candidates"] = candidates
    header = [
        "//! Independently generated AES S-box from a quadratic field tower.",
        "//! Generated by cleanroom/aes_tower/generate.py in the Codex clean-room session.",
        "//! Source standard: NIST FIPS 197; see DERIVATION.md for the field isomorphism.",
        f"//! Tower basis in AES polynomial coordinates: {record['basis_aes']}.",
        f"//! GF4 u^2+u+1; GF16 z^2+z+{record['mu']}; GF256 w^2+w+{record['lambda']}.",
        f"//! {record['and_count']} AND and {record['xor_count']} XOR/NOT source operations.",
        "", "pub(crate) type Planes = [u64; 8];", "",
        "#[inline(always)]", "pub(crate) fn sbox(q: &Planes) -> Planes {",
        "    const ONE: u64 = !0;", *lines, "}", "",
    ]
    (HERE / "sbox.rs").write_text("\n".join(header))
    (HERE / "parameters.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
