#!/usr/bin/env python3
"""Clean Boolean witness experiment; no production source is read.

Independently derived by /root in clean-room continuation workspace
01a1be54-c6e9-73d3-8a85-5e6f9a76a492, 2026-11-09 America/Chicago.
This is feasibility tooling, not a mitigation or a constant-time proof.
"""
import argparse
import hashlib
import json
import random
import time
from pathlib import Path


def circuit():
    gates = []

    def op(a, symbol, b):
        if a == "0":
            return b if symbol == "^" else "0"
        if b == "0":
            return a if symbol == "^" else "0"
        name = f"v{len(gates)}"
        gates.append((name, a, symbol, b))
        return name

    def product(a, b):
        if len(a) == 1:
            return [op(a[0], "&", b[0])]
        h = len(a) // 2
        lo, hi = product(a[:h], b[:h]), product(a[h:], b[h:])
        mid = product([op(x, "^", y) for x, y in zip(a[:h], a[h:])],
                      [op(x, "^", y) for x, y in zip(b[:h], b[h:])])
        cross = [op(op(m, "^", l), "^", r) for m, l, r in zip(mid, lo, hi)]
        out = ["0"] * (len(a) * 2 - 1)
        for off, p in ((0, lo), (h, cross), (2*h, hi)):
            for j, x in enumerate(p, off):
                out[j] = op(out[j], "^", x)
        return out

    output = product([f"a{i}" for i in range(64)], [f"b{i}" for i in range(64)])
    return gates, output


def evaluate(a, b, gates):
    v = {**{f"a{i}": x for i, x in enumerate(a)},
         **{f"b{i}": x for i, x in enumerate(b)}, "0": 0}
    for name, x, symbol, y in gates:
        v[name] = v[x] ^ v[y] if symbol == "^" else v[x] & v[y]
    return v


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", type=int, default=2048)
    parser.add_argument("--nonzero-only", action="store_true")
    parser.add_argument("--output", default="guard-witness.json")
    args = parser.parse_args()
    started = time.monotonic()
    gates, output = circuit()
    rng = random.Random(0x5052415449515545)
    pairs = [(rng.getrandbits(128), rng.getrandbits(128)) for _ in range(args.pool)]
    full = (1 << args.pool) - 1
    constraints = set()
    rows = []
    for group in ("low", "high", "mixed"):
        def part(x):
            lo, hi = x & ((1 << 64)-1), x >> 64
            return lo if group == "low" else hi if group == "high" else lo ^ hi
        a = [sum(((part(x) >> i) & 1) << j for j, (x, _) in enumerate(pairs)) for i in range(64)]
        b = [sum(((part(y) >> i) & 1) << j for j, (_, y) in enumerate(pairs)) for i in range(64)]
        values = evaluate(a, b, gates)
        for name, x in values.items():
            if name == "0":
                continue
            assert x != 0 and x != full, (group, name, "constant or insufficient public pool")
            constraints.add(x)
            if not args.nonzero_only:
                constraints.add(full ^ x)
            rows.append((group, name, x))
    initial_constraints = len(constraints)
    selected = []
    while constraints:
        # Binary addition across candidate bitsets counts uncovered constraints
        # without a Python-level loop over every candidate assignment.
        counts = []
        for mask in constraints:
            carry, i = mask, 0
            while carry:
                if i == len(counts):
                    counts.append(carry)
                    break
                carry, counts[i] = counts[i] & carry, counts[i] ^ carry
                i += 1
        eligible, score = full, 0
        for i in range(len(counts)-1, -1, -1):
            both = eligible & counts[i]
            if both:
                eligible = both
                score |= 1 << i
        bit = eligible & -eligible
        selected.append(bit.bit_length()-1)
        constraints = {x for x in constraints if not x & bit}
        print(f"guard {len(selected)} covers {score}; remaining {len(constraints)}", flush=True)
    chosen = sum(1 << i for i in selected)
    assert all(x & chosen for _, _, x in rows)
    if not args.nonzero_only:
        assert all((full ^ x) & chosen for _, _, x in rows)
    record = {"status": "abstract-circuit-feasibility-only", "pool": args.pool,
              "nonzero_only": args.nonzero_only,
              "gates": len(gates), "wires_including_inputs": len(rows),
              "deduplicated_constraints": initial_constraints,
              "guard_lanes": len(selected), "payload_lanes": 64-len(selected),
              "selected_pool_indices": selected,
              "public_pairs_hex": [[f"{pairs[i][0]:032x}", f"{pairs[i][1]:032x}"] for i in selected],
              "elapsed_seconds": time.monotonic()-started,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "limitations": ["No optimized-code coverage", "No packing/reduction/setup coverage",
                              "No timing result", "Not protection against arbitrary value-dependent timing"]}
    path = Path(__file__).with_name(args.output)
    path.write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps({k: record[k] for k in ("guard_lanes", "payload_lanes", "elapsed_seconds")}))


if __name__ == "__main__":
    main()
