#!/usr/bin/env python3
"""Line counts and the module graph of the verification path, for SECURITY_REVIEW.md (section 3).

    python3 tools/line_counts.py            # the table of line counts, in Markdown
    python3 tools/line_counts.py --graph    # which module of the pure build calls which
    python3 tools/line_counts.py --check    # exits 1 if SECURITY_REVIEW.md's table or graph is not what this prints
    python3 tools/line_counts.py --write    # puts both into SECURITY_REVIEW.md, between their markers

Line counts. Every line of a file that is not blank is one of three kinds: a test (a line of a top-level item marked
`#[cfg(test)]`, which is the module of in-file tests and, in a few files, a helper only the tests use; the item ends at the
next line that starts with `}`), a comment (`//`, `///` or `//!` first on the line, outside the tests) or code (the rest).
Nothing is parsed beyond that, so a comment at the end of a line of code counts as code, and a line inside a multi-line
string that starts with `//` would count as a comment.

The graph. Module A calls module B if the code of A (comments, strings and the tests left out) names `crate::B`, or
`super::B` from inside `crypto`, or B in a `use crate::{...}` list. A use that goes through a type and names no module (a
method of `x509::PublicKey::Rsa` that is `rsa`'s) is not seen; the map in SECURITY_REVIEW.md writes those out. The script
stops if the graph has a cycle.

The groups of the table are the layers of the map, from the bytes up; the last group is the code of the `net` build that
hands untrusted bytes to the path (Phase 2, listed for scope).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (layer, claims, on the verification path, files)
GROUPS = [
    ("readers", "untrusted bytes in", True,
     ["src/asn1.rs", "src/ber.rs", "src/pem.rs", "src/json.rs", "src/util.rs", "src/verify_error.rs"]),
    ("signatures", "C2", True,
     ["src/crypto/sha2.rs", "src/crypto/sha2_consts.rs", "src/crypto/sha1.rs", "src/crypto/bignum.rs", "src/crypto/rsa.rs",
      "src/crypto/ecdsa.rs", "src/crypto/fe25519.rs", "src/crypto/ed25519.rs"]),
    ("certificates", "C1, C5", True, ["src/x509.rs", "src/revocation.rs"]),
    ("signed objects", "C4, C6, C7", True,
     ["src/cms.rs", "src/note.rs", "src/tlog.rs", "src/sumdb.rs", "src/ct.rs", "src/trust_root.rs", "src/tuf.rs", "src/sigstore.rs"]),
    ("decompression", "C11", True, ["src/inflate.rs"]),
    ("pure, not on the path", "", False, ["src/idna.rs", "src/mozilla_roots.rs"]),
    ("callers in the net build", "Phase 2", False,
     ["src/tls/handshake.rs", "src/tls/tls12.rs", "src/tls/signature.rs", "src/http/ocsp_source.rs", "src/http/crl_source.rs",
      "src/http/tuf_source.rs", "src/http/decode.rs"]),
]

MARKERS = {"table": ("<!-- line_counts.py: begin -->", "<!-- line_counts.py: end -->"),
           "graph": ("<!-- line_counts.py graph: begin -->", "<!-- line_counts.py graph: end -->")}


def read(path):
    return open(os.path.join(ROOT, path), encoding="utf-8").read().rstrip("\n").split("\n")


def test_lines(path, lines):
    """Which lines belong to a top-level `#[cfg(test)]` item."""
    test = [False] * len(lines)
    i = 0
    while i < len(lines):
        if not lines[i].startswith("#[cfg(test)]"):
            i += 1
            continue
        # a top-level item: it ends at the next line that starts with `}`, or, if it has no body, at its `;`
        j = i + 1
        while j < len(lines) and lines[j].startswith(("#[", "//")):
            j += 1
        if j < len(lines) and lines[j].rstrip().endswith(";"):
            end = j
        else:
            end = next((k for k in range(j, len(lines)) if lines[k].startswith("}")), None)
            if end is None:
                sys.exit(f"{path}:{i + 1}: no end found for the #[cfg(test)] item; teach tools/line_counts.py about it")
        for k in range(i, end + 1):
            test[k] = True
        i = end + 1
    return test


def count(path):
    """(code, comments, tests) of one file: lines that are not blank."""
    lines = read(path)
    code = comments = tests = 0
    for line, t in zip(lines, test_lines(path, lines)):
        s = line.strip()
        if not s:
            continue
        if t:
            tests += 1
        elif s.startswith("//"):
            comments += 1
        else:
            code += 1
    return code, comments, tests


def module(path):
    return path[len("src/"):-len(".rs")].replace("/", "::")


def graph():
    """{module: set of the modules it calls}, for the pure files of the table."""
    pure = [f for _, _, _, files in GROUPS for f in files if not f.startswith(("src/tls/", "src/http/"))]
    names = {module(f) for f in pure}
    calls = {}
    for f in pure:
        me = module(f)
        lines = read(f)
        code = "\n".join(l for l, t in zip(lines, test_lines(f, lines)) if not t and not l.lstrip().startswith("//"))
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
        found = set(re.findall(r"crate::((?:crypto::)?[a-z0-9_]+)", code))
        if me.startswith("crypto::"):
            found |= {"crypto::" + m for m in re.findall(r"super::([a-z0-9_]+)", code)}
        for group in re.findall(r"use crate::\{([^}]*)\}", code):
            found |= set(re.findall(r"(?<![:\w])([a-z0-9_]+)(?=\s*(?:::|,|$|\}))", group))
            found |= {"crypto::" + m for m in re.findall(r"crypto::(?:\{([^}]*)\}|([a-z0-9_]+))", group) for m in m if m}
        calls[me] = {d for d in found if d in names and d != me}
    # no cycles
    state = {}

    def visit(m, stack):
        state[m] = 1
        for d in sorted(calls[m]):
            if state.get(d) == 1:
                sys.exit("a cycle in the module graph: " + " -> ".join(stack + [m, d]))
            if not state.get(d):
                visit(d, stack + [m])
        state[m] = 2

    for m in calls:
        if not state.get(m):
            visit(m, [])
    return calls


def graph_text():
    calls = graph()
    order = [module(f) for _, _, _, files in GROUPS for f in files if module(f) in calls]
    width = max(len(m) for m in order)
    return "\n".join(f"{m:<{width}}  → {', '.join(sorted(calls[m])) or '(nothing)'}" for m in order)


def table():
    out = ["| layer | file | code | comments | in-file tests |", "|---|---|---:|---:|---:|"]
    path_total = [0, 0, 0]
    for name, claims, on_path, files in GROUPS:
        sub = [0, 0, 0]
        label = f"{name} ({claims})" if claims else name
        for f in files:
            c = count(f)
            sub = [a + b for a, b in zip(sub, c)]
            out.append(f"| {label} | `{f}` | {c[0]:,} | {c[1]:,} | {c[2]:,} |")
            label = ""
        out.append(f"| | *subtotal* | *{sub[0]:,}* | *{sub[1]:,}* | *{sub[2]:,}* |")
        if on_path:
            path_total = [a + b for a, b in zip(path_total, sub)]
    t = path_total
    out.append(f"| | **the verification path (the first five layers)** | **{t[0]:,}** | **{t[1]:,}** | **{t[2]:,}** |")
    return "\n".join(out)


def main():
    parts = {"table": table(), "graph": "```\n" + graph_text() + "\n```"}
    if "--check" in sys.argv or "--write" in sys.argv:
        path = os.path.join(ROOT, "SECURITY_REVIEW.md")
        doc = open(path, encoding="utf-8").read()
        stale = []
        for key, (begin, end) in MARKERS.items():
            pattern = re.escape(begin) + r"\n(.*?)\n" + re.escape(end)
            m = re.search(pattern, doc, re.S)
            if not m:
                sys.exit(f"SECURITY_REVIEW.md has no {begin} ... {end}")
            if m.group(1) != parts[key]:
                stale.append(key)
                doc = doc[:m.start(1)] + parts[key] + doc[m.end(1):]
        if "--write" in sys.argv:
            open(path, "w", encoding="utf-8").write(doc)
            print(f"SECURITY_REVIEW.md: {', '.join(stale) or 'nothing'} brought up to date")
            return
        if stale:
            print(f"SECURITY_REVIEW.md is out of date ({', '.join(stale)}): run python3 tools/line_counts.py --write")
            sys.exit(1)
        print("SECURITY_REVIEW.md's line counts and module graph are current")
        return
    print(parts["graph"][4:-4] if "--graph" in sys.argv else parts["table"])


if __name__ == "__main__":
    main()
