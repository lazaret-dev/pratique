#!/usr/bin/env python3
"""Generates tests/data/cms_vectors.txt: damaged copies of the messages in tests/data/cms_fixtures.txt,
each with the verdict of OpenSSL (`openssl cms -verify -noverify`: the signatures and digests of every
signer, and nothing about trust or time, which is what `SignedData::verify_signature` says too).
tests/cms_vectors.rs replays them. Run from the repository root, after tools/gen_cms_fixtures.py:

    python3 tools/gen_cms_vectors.py

One case per line:

  case BASE REGION EDITS VERDICT

BASE is a blob of cms_fixtures.txt (whose detached content, if it has any, is the content of the same
name, or `hello`), EDITS is a comma-separated list of changes to apply to it in order (`x:OFFSET:HEXBYTE`
xor, `d:OFFSET:LENGTH` delete, `i:OFFSET:HEX` insert, `t:LENGTH:` cut to a length; `-` for none),
REGION says what the first change touched (see ROLES) and VERDICT is `ok` or `bad`.
"""
import hashlib
import os
import subprocess
import sys
import tempfile

FIX = "tests/data/cms_fixtures.txt"
OUT = "tests/data/cms_vectors.txt"
SEED = b"tiny_https cms vectors 2026-10-05"
_ctr = 0


def rnd(n):
    global _ctr
    _ctr += 1
    return int.from_bytes(hashlib.sha256(SEED + b"%d" % _ctr).digest(), "big") % n


# ------------------------------------------------------------------------------------ the fixtures

blobs, contents = {}, {}
for line in open(FIX):
    p = line.split()
    if p and p[0] == "blob":
        blobs[p[1]] = bytes.fromhex(p[2])
    elif p and p[0] == "content":
        contents[p[1]] = bytes.fromhex(p[2])

# (message, detached content or None); OpenSSL 3.0 cannot verify Ed25519, so that one is not here
BASES = [
    ("rsa_sha256", None),
    ("rsa_sha256_detached", "hello"),
    ("rsa_noattr", None),
    ("rsa_noattr_detached", "hello"),
    ("rsa_sha1", None),
    ("rsa_keyid", None),
    ("rsa_pss_sha256", None),
    ("rsa_pss_sha384", None),
    ("p256_sha256", None),
    ("p256_noattr", None),
    ("p384_sha384", None),
    ("two_signers", None),
    ("rsa_stream", None),
    ("pkcs7_attached", None),
    ("pkcs7_detached", "hello"),
    ("jar_rsa", "jar_rsa"),
    ("jar_p256", "jar_p256"),
    ("rsa_econtent_type", None),
]

# ------------------------------------------------------------------------------ a BER reader with offsets


class N:
    def __init__(self, tag, start, cs, ce, end, kids):
        self.tag, self.start, self.cs, self.ce, self.end, self.kids = tag, start, cs, ce, end, kids


def parse(buf, pos, limit):
    start = pos
    tag = buf[pos]
    n = buf[pos + 1]
    pos += 2
    if n == 0x80:
        kids = []
        while buf[pos : pos + 2] != b"\x00\x00":
            k = parse(buf, pos, limit)
            kids.append(k)
            pos = k.end
        return N(tag, start, start + 2, pos, pos + 2, kids)
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos : pos + k], "big")
        pos += k
    cs, ce = pos, pos + n
    kids = None
    if tag & 0x20:
        kids = []
        q = cs
        while q < ce:
            k = parse(buf, q, ce)
            kids.append(k)
            q = k.end
    return N(tag, start, cs, ce, ce, kids)


def roles_of(buf):
    """The role of every byte of a message: what it is part of, or `wrapper` for the identifier and
    length octets of the elements that hold the parts together."""
    roles = ["wrapper"] * len(buf)

    def paint(node, role, wrapper=False):
        for i in range(node.start, node.cs):
            roles[i] = "wrapper" if wrapper else role
        if node.kids is None:
            if node.tag != 0:
                for i in range(node.cs, node.ce):
                    roles[i] = role
        else:
            for k in node.kids:
                paint(k, role)
            for i in range(node.ce, node.end):  # the end-of-contents octets of an indefinite length
                roles[i] = "wrapper" if wrapper else role

    root = parse(buf, 0, len(buf))
    sd = root.kids[1].kids[0]
    paint(root.kids[0], "wrapper", True)
    for i in range(root.start, root.cs):
        roles[i] = "wrapper"
    for i in range(root.kids[1].start, root.kids[1].cs):
        roles[i] = "wrapper"
    for i in range(sd.start, sd.cs):
        roles[i] = "wrapper"
    k = sd.kids
    paint(k[0], "version")
    paint(k[1], "digest_algs_set")
    eci = k[2]
    for i in range(eci.start, eci.cs):
        roles[i] = "wrapper"
    paint(eci.kids[0], "econtent_type")
    if len(eci.kids) > 1:
        paint(eci.kids[1].kids[0], "content")
        for j in range(eci.kids[1].start, eci.kids[1].cs):
            roles[j] = "wrapper"
    i = 3
    if k[i].tag == 0xA0:
        paint(k[i], "certs")
        i += 1
    if k[i].tag == 0xA1:
        paint(k[i], "crls")
        i += 1
    for j in range(k[i].start, k[i].cs):
        roles[j] = "wrapper"
    for si in k[i].kids:
        for j in range(si.start, si.cs):
            roles[j] = "wrapper"
        sk = si.kids
        paint(sk[0], "signer_version")
        paint(sk[1], "signer_sid")
        paint(sk[2], "signer_algs")
        j = 3
        if sk[j].tag == 0xA0:
            paint(sk[j], "attrs")
            for q in range(sk[j].start, sk[j].cs):  # the [0] of the set: OpenSSL does not mind its constructed bit
                roles[q] = "wrapper"
            j += 1
        paint(sk[j], "signer_algs")
        paint(sk[j + 1], "sig")
        if j + 2 < len(sk):
            paint(sk[j + 2], "unsigned")
    return roles


# ------------------------------------------------------------------------------------------ OpenSSL

W = tempfile.mkdtemp(prefix="cmsvec")


def openssl_verdict(blob, content):
    with open(os.path.join(W, "m.der"), "wb") as f:
        f.write(blob)
    args = ["openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", "m.der", "-binary", "-out", os.devnull]
    if content is not None:
        with open(os.path.join(W, "c.bin"), "wb") as f:
            f.write(content)
        args += ["-content", "c.bin"]
    p = subprocess.run(args, cwd=W, capture_output=True, timeout=30)
    return "ok" if p.returncode == 0 else "bad"


def apply(base, edits):
    b = bytearray(base)
    for kind, off, arg in edits:
        if kind == "x":
            b[off] ^= arg
        elif kind == "d":
            del b[off : off + arg]
        elif kind == "i":
            b[off:off] = arg
        elif kind == "t":
            del b[off:]
    return bytes(b)


def fmt(edits):
    if not edits:
        return "-"
    out = []
    for kind, off, arg in edits:
        if kind == "x":
            out.append(f"x:{off}:{arg:02x}")
        elif kind == "d":
            out.append(f"d:{off}:{arg}")
        elif kind == "i":
            out.append(f"i:{off}:{arg.hex()}")
        else:
            out.append(f"t:{off}:")
    return ",".join(out)


def main():
    lines = ["# generated by tools/gen_cms_vectors.py; the verdict on each line is OpenSSL's (`openssl cms -verify -noverify`)"]
    stats = {}
    for name, cname in BASES:
        base = blobs[name]
        content = contents[cname] if cname else None
        roles = roles_of(base)
        by_role = {}
        for i, r in enumerate(roles):
            by_role.setdefault(r, []).append(i)
        cases = [("none", [])]
        for role, offs in sorted(by_role.items()):
            if role in ("wrapper", "other"):
                continue
            # a few bit flips, a deleted byte, an inserted byte inside the region
            for _ in range(3):
                cases.append((role, [("x", offs[rnd(len(offs))], 1 << rnd(8))]))
            cases.append((role, [("d", offs[rnd(len(offs))], 1)]))
            cases.append((role, [("i", offs[rnd(len(offs))], bytes([rnd(256)]))]))
        for _ in range(30):
            off = rnd(len(base))
            cases.append((roles[off], [("x", off, 1 << rnd(8))]))
        for _ in range(10):
            off = rnd(len(base))
            cases.append((roles[off], [("x", off, 1 + rnd(255))]))
        for _ in range(6):
            off = rnd(len(base) - 1)
            cases.append((roles[off], [("d", off, 1 + rnd(8))]))
        for _ in range(4):
            off = rnd(len(base))
            cases.append((roles[off], [("i", off, bytes(rnd(256) for _ in range(1 + rnd(4))))]))
        for _ in range(4):
            cut = rnd(len(base))
            cases.append((roles[cut], [("t", cut, 0)]))
        # bytes after the message
        cases.append(("tail", [("i", len(base), b"\x00\x00")]))
        cases.append(("tail", [("i", len(base), b"\x01")]))
        for role, edits in cases:
            verdict = openssl_verdict(apply(base, edits), content)
            lines.append(f"case {name} {role} {fmt(edits)} {verdict}")
            stats[(role, verdict)] = stats.get((role, verdict), 0) + 1
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {OUT}: {len(lines) - 1} cases, {os.path.getsize(OUT)} bytes")
    for (role, verdict), n in sorted(stats.items()):
        print(f"  {role:16} {verdict:4} {n}")


if __name__ == "__main__":
    sys.exit(main())
