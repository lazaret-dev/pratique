#!/usr/bin/env python3
"""Generates tests/data/inflate_vectors.txt: compressed streams made by programs other than this crate, and damaged copies
of some of them, with what two independent decoders (Python's zlib and Go's compress/*) say about each.
tests/inflate_vectors.rs replays them against src/inflate.rs. Run from the repository root:

    python3 tools/gen_inflate_vectors.py

Needs Python 3 with zlib, a Go toolchain (tools/inflate_oracle.go), and, if present, the `gzip` and `zlib-flate` programs.
Nothing here is random: the corpora and the damage come from fixed seeds, so a rerun gives the same file unless a compressor
changed (which is the point of keeping the streams in the repository).

Lines:

    # ...
    ok    NAME FORMAT LENGTH SHA256 HEX         a valid stream of FORMAT (deflate, zlib or gzip) and what it decompresses to;
                                                 both references were checked to say the same
    base  NAME FORMAT HEX                       a stream that is the base of damaged copies
    mut   BASE EDITS ZLIB GO                    BASE with EDITS applied, and the verdicts of zlib and Go:
                                                 `err`, or `ok:LENGTH:SHA256` for what they decompress to

EDITS is `-` or a comma-separated list of  x:OFFSET:HEXBYTE (xor)  d:OFFSET:LENGTH (delete)  i:OFFSET:HEX (insert)
t:LENGTH: (cut to that length)  a:HEX: (append). Offsets refer to the stream as edited so far.
"""
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "data", "inflate_vectors.txt")
GO = shutil.which("go") or "/usr/local/go/bin/go"


# what is too big to keep stored or Huffman-only in the file: the stream is as long as the data
BIG = 3000


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------------------------------------- corpora


def corpora():
    rng = random.Random(0x1F1A7E)
    c = {}
    c["empty"] = b""
    c["one"] = b"x"
    c["hello"] = b"hello hello hello hello\n"
    words = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))) for _ in range(300)]
    c["text"] = b" ".join(rng.choice(words) for _ in range(900))[:5000]
    c["zeros"] = bytes(1 << 20)
    c["ff"] = b"\xff" * 70000
    c["random"] = bytes(rng.getrandbits(8) for _ in range(1500))
    c["ab"] = b"ab" * 50000
    c["bytes256"] = bytes(range(256)) * 40
    c["counters"] = b"".join(struct.pack(">I", i) for i in range(800))
    # a copy at a distance of 32000 (the last distance code, 24577 to 32768) out of a source of two letters
    four = bytes(rng.choice(b"01") for _ in range(32000))
    c["far"] = four + four[:400]
    # symbol counts that follow the Fibonacci numbers: the Huffman code wants lengths past 15, and has to be cut to 15
    fib, a, b = [], 1, 1
    for _ in range(17):
        fib.append(a)
        a, b = b, a + b
    sym = [s for s, n in enumerate(fib) for _ in range(n)]
    rng.shuffle(sym)
    c["fibonacci"] = bytes(sym)
    runs = bytearray()
    while len(runs) < 6000:
        runs += bytes([rng.getrandbits(8)]) * rng.choice([1, 2, 3, 5, 17, 258, 259, 300, 600])
    c["runs"] = bytes(runs)
    recs = bytearray()
    for i in range(200):
        recs += struct.pack("<HHIQ", i % 7, rng.getrandbits(4), i * 31, 0xDEADBEEF00000000 | (i % 5))
    c["records"] = bytes(recs)
    return c


def small_corpora():
    """Short inputs that are the bases of damaged copies."""
    rng = random.Random(0xBADBEEF)
    s = {}
    s["hello"] = b"hello hello hello hello\n"
    words = [bytes(rng.choice(b"abcdefghij") for _ in range(rng.randint(2, 5))) for _ in range(40)]
    s["text"] = b" ".join(rng.choice(words) for _ in range(120))
    s["runs"] = b"".join(bytes([rng.getrandbits(8)]) * rng.choice([1, 2, 3, 9, 40, 258, 300]) for _ in range(14))
    s["skew"] = bytes(rng.choice([0] * 20 + [1] * 10 + [2] * 5 + [3] * 3 + [4, 5, 6, 7]) for _ in range(500))
    s["one"] = b"z"
    s["empty"] = b""
    return s


# ---------------------------------------------------------------------------------------------------------- makers


def raw(data, level=6, wbits=-15, mem=8, strategy=zlib.Z_DEFAULT_STRATEGY, flush=None, every=1000):
    c = zlib.compressobj(level, zlib.DEFLATED, wbits, mem, strategy)
    if flush is None:
        return c.compress(data) + c.flush()
    out = b""
    for i in range(0, len(data), every):
        out += c.compress(data[i : i + every]) + c.flush(flush)
    return out + c.flush()


def gzip_member(data, level=6, mtime=0, xfl=0, os_=3, extra=None, name=None, comment=None, hcrc=False, ftext=False):
    flags = (1 if ftext else 0) | (2 if hcrc else 0) | (4 if extra is not None else 0) | (8 if name is not None else 0) | (16 if comment is not None else 0)
    h = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", mtime) + bytes([xfl, os_])
    if extra is not None:
        h += struct.pack("<H", len(extra)) + extra
    if name is not None:
        h += name + b"\0"
    if comment is not None:
        h += comment + b"\0"
    if hcrc:
        h += struct.pack("<H", zlib.crc32(h) & 0xFFFF)
    return h + raw(data, level) + struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)


def stored_blocks(data, sizes):
    """Hand-made DEFLATE: stored blocks of the given sizes (the last one final), then the rest of the data in one more."""
    out, pos = b"", 0
    for n in sizes:
        out += b"\x00" + struct.pack("<HH", n, n ^ 0xFFFF) + data[pos : pos + n]
        pos += n
    rest = data[pos:]
    return out + b"\x01" + struct.pack("<HH", len(rest), len(rest) ^ 0xFFFF) + rest


def zlib_wrap(body, data, header=b"\x78\x9c"):
    return header + body + struct.pack(">I", zlib.adler32(data))


def tool(cmd, data):
    exe = shutil.which(cmd[0])
    if exe is None:
        return None
    return subprocess.run([exe] + cmd[1:], input=data, stdout=subprocess.PIPE, check=True).stdout


def python_streams(corp):
    """(name, format, stream, corpus name)"""
    out = []
    rich = ["text", "fibonacci", "runs", "records", "counters"]
    light = [k for k in corp if k not in rich]
    for k, d in corp.items():
        out.append((f"py.raw6.{k}", "deflate", raw(d), k))
        out.append((f"py.zlib9.{k}", "zlib", raw(d, 9, 15), k))
        out.append((f"py.gzip6.{k}", "gzip", raw(d, 6, 31), k))
    for k in rich:
        d = corp[k]
        for level in (0, 1, 9):
            if level == 0 and len(d) > BIG:
                continue
            out.append((f"py.raw{level}.{k}", "deflate", raw(d, level), k))
        for name, strat in (("filtered", zlib.Z_FILTERED), ("huffman", zlib.Z_HUFFMAN_ONLY), ("rle", zlib.Z_RLE), ("fixed", zlib.Z_FIXED)):
            if name == "huffman" and len(d) > BIG:
                continue
            out.append((f"py.{name}.{k}", "deflate", raw(d, 6, -15, 8, strat), k))
        out.append((f"py.mem1.{k}", "deflate", raw(d, 6, -15, 1), k))
        out.append((f"py.zlib1win9.{k}", "zlib", raw(d, 1, 9), k))
        out.append((f"py.zlib6win12.{k}", "zlib", raw(d, 6, 12), k))
        out.append((f"py.sync1000.{k}", "deflate", raw(d, 6, -15, 8, 0, zlib.Z_SYNC_FLUSH), k))
        out.append((f"py.full1000.{k}", "zlib", raw(d, 6, 15, 8, 0, zlib.Z_FULL_FLUSH), k))
    out.append(("py.fixed.far", "deflate", raw(corp["far"], 6, -15, 8, zlib.Z_FIXED), "far"))
    for k in light:
        d = corp[k]
        out.append((f"py.raw1.{k}", "deflate", raw(d, 1), k))
        if len(d) <= BIG:
            out.append((f"py.huffman.{k}", "deflate", raw(d, 6, -15, 8, zlib.Z_HUFFMAN_ONLY), k))
    # stored blocks by hand: empty ones in front, in between and behind
    t = corp["text"]
    out.append(("hand.stored.empties", "deflate", stored_blocks(t[:5000], [0, 0, 1, 0, 2000, 0, 2999]), "text5000"))
    out.append(("hand.stored.zlib", "zlib", zlib_wrap(stored_blocks(t[:5000], [0, 2500]), t[:5000], b"\x78\x01"), "text5000"))
    # zlib headers of every level hint and window size
    for hdr, wbits in ((b"\x08\x1d", 8), (b"\x18\x19", 9), (b"\x28\x15", 10), (b"\x38\x11", 11), (b"\x48\x0d", 12), (b"\x58\x09", 13), (b"\x68\x05", 14), (b"\x78\x01", 15), (b"\x78\x5e", 15), (b"\x78\xda", 15)):
        assert (hdr[0] * 256 + hdr[1]) % 31 == 0, hdr
        d = corp["hello"]
        out.append((f"hand.zlibhdr{hdr.hex()}", "zlib", zlib_wrap(raw(d), d, hdr), "hello"))
    # gzip headers
    d = corp["text"][:3000]
    g = [
        ("plain", {}),
        ("name", dict(name=b"report.txt")),
        ("comment", dict(comment=b"made by hand")),
        ("extra", dict(extra=b"AB" + struct.pack("<H", 5) + b"12345" + b"xy" + struct.pack("<H", 0))),
        ("emptyextra", dict(extra=b"")),
        ("emptyname", dict(name=b"")),
        ("hcrc", dict(hcrc=True)),
        ("all", dict(extra=b"\x01\x02\x03", name=b"a.txt", comment=b"c", hcrc=True, ftext=True, mtime=1_700_000_000, xfl=2, os_=255)),
        ("ftext", dict(ftext=True, mtime=0xFFFFFFFF, xfl=4, os_=0)),
    ]
    for name, kw in g:
        out.append((f"hand.gzip.{name}", "gzip", gzip_member(d, **kw), "text3000"))
    # members one after the other: with an empty one first, in the middle and last
    parts = [d[:1000], b"", d[1000:2000], d[2000:], b""]
    multi = b"".join(gzip_member(p, level=lv, name=(b"n" if i % 2 else None)) for i, (p, lv) in enumerate(zip(parts, (6, 1, 9, 0, 6))))
    out.append(("hand.gzip.members", "gzip", multi, "text3000"))
    # programs: gzip(1) at its levels, with and without the name, and zlib-flate
    for k in ("text", "runs", "counters"):
        for lv in (1, 6, 9):
            s = tool(["gzip", "-c", f"-{lv}", "-n"], corp[k])
            if s is not None:
                out.append((f"gzipcli.n{lv}.{k}", "gzip", s, k))
        s = tool(["zlib-flate", "-compress"], corp[k])
        if s is not None:
            out.append((f"zlibflate.{k}", "zlib", s, k))
    if shutil.which("gzip"):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "named.txt")
            with open(p, "wb") as f:
                f.write(corp["text"])
            os.utime(p, (1_700_000_000, 1_700_000_000))
            s = subprocess.run(["gzip", "-c", "-N", "-9", p], stdout=subprocess.PIPE, check=True).stdout
            out.append(("gzipcli.N9.text", "gzip", s, "text"))
    return out


# ------------------------------------------------------------------------------------------------- the references


def zlib_verdict(fmt, data):
    """What Python's zlib makes of data as exactly one stream of fmt: None, or the bytes."""
    try:
        if fmt in ("deflate", "zlib"):
            d = zlib.decompressobj(-15 if fmt == "deflate" else 15)
            out = d.decompress(data)
            return out if d.eof and not d.unused_data else None
        out, rest, first = b"", data, True
        while first or rest:
            d = zlib.decompressobj(31)
            out += d.decompress(rest)
            if not d.eof:
                return None
            rest, first = d.unused_data, False
        return out
    except zlib.error:
        return None


def go_verdicts(items):
    """items: list of (key, fmt, data) -> {key: None or (length, sha)} from Go's readers."""
    text = "".join(f"{k} {f} {d.hex() or '-'}\n" for k, f, d in items)
    r = subprocess.run([GO, "run", os.path.join(ROOT, "tools", "inflate_oracle.go"), "judge"], input=text.encode(), stdout=subprocess.PIPE, check=True)
    out = {}
    for line in r.stdout.decode().splitlines():
        f = line.split()
        out[f[0]] = (int(f[2]), f[3]) if f[1] == "ok" else None
    return out


def go_streams(corp, names):
    with tempfile.TemporaryDirectory() as td:
        for n in names:
            with open(os.path.join(td, n), "wb") as f:
                f.write(corp[n])
        r = subprocess.run([GO, "run", os.path.join(ROOT, "tools", "inflate_oracle.go"), "gen", td], stdout=subprocess.PIPE, check=True)
    out = []
    for line in r.stdout.decode().splitlines():
        name, fmt, hx = line.split()
        out.append((name, fmt, bytes.fromhex(hx), name.rsplit(".", 1)[1]))
    return out


def verdict_text(v):
    return "err" if v is None else f"ok:{len(v)}:{sha(v)}"


# ------------------------------------------------------------------------------------------------------ the damage


def damage(base, fmt, rng):
    """Lists of edits (as in the module comment) that make copies of base, and the copies."""
    n = len(base)
    edits = []
    for _ in range(8):  # a flipped bit
        edits.append([("x", rng.randrange(n), 1 << rng.randrange(8))])
    for _ in range(3):  # a byte replaced
        edits.append([("x", rng.randrange(n), rng.randrange(1, 256))])
    for _ in range(3):
        edits.append([("d", rng.randrange(n), 1)])
    for _ in range(3):
        edits.append([("i", rng.randrange(n + 1), bytes([rng.getrandbits(8)]))])
    for cut in sorted({n - 1, n - 4, n - 8, n // 2, rng.randrange(n)} - {n}):
        if cut >= 0:
            edits.append([("t", cut, None)])
    edits.append([("a", 0, b"\x00")])
    edits.append([("a", 0, bytes(8))])
    edits.append([("a", 0, base[: min(n, 10)])])  # the start of another stream
    for _ in range(4):  # two flips
        edits.append([("x", rng.randrange(n), 1 << rng.randrange(8)), ("x", rng.randrange(n), 1 << rng.randrange(8))])
    if n >= 2:  # the first two bytes: a header
        for i in (0, 1):
            edits.append([("x", i, 0x01)])
            edits.append([("x", i, 0x80)])
    # the places a format keeps its own: the header and the check at the end
    if fmt == "gzip" and n >= 18:
        for bit in range(8):  # the flags (and so the reserved ones)
            edits.append([("x", 3, 1 << bit)])
        edits.append([("x", 2, 1)])  # the method
        for off in (n - 8, n - 5, n - 4, n - 1):  # the CRC and the length
            edits.append([("x", off, 0x40)])
    if fmt == "zlib" and n >= 6:
        edits.append([("x", 1, 0x20)])  # a preset dictionary asked for (and the check bits broken)
        edits.append([("x", 0, 0x10), ("x", 1, 0x10)])  # a window of 2^16, with the check bits kept
        for off in (n - 4, n - 1):  # the Adler-32
            edits.append([("x", off, 0x40)])
    seen, out = set(), []
    for e in edits:
        s = ",".join(spell(x) for x in e)
        if s not in seen:
            seen.add(s)
            out.append((s, apply(base, e)))
    return out


def spell(e):
    kind, off, arg = e
    if kind == "x":
        return f"x:{off}:{arg:02x}"
    if kind == "d":
        return f"d:{off}:{arg}"
    if kind == "i":
        return f"i:{off}:{arg.hex()}"
    if kind == "t":
        return f"t:{off}:"
    return f"a:{arg.hex()}:"


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
        elif kind == "a":
            b += arg
    return bytes(b)


def base_streams(small):
    out = []
    for k, d in small.items():
        out.append((f"{k}.fixed", "deflate", raw(d, 9, -15, 8, zlib.Z_FIXED)))
        out.append((f"{k}.dynamic", "deflate", raw(d, 9)))
        out.append((f"{k}.stored", "deflate", raw(d, 0)))
        out.append((f"{k}.zlib", "zlib", raw(d, 6, 15)))
        out.append((f"{k}.gzip", "gzip", raw(d, 6, 31)))
    d = small["text"]
    out.append(("text.gzipfull", "gzip", gzip_member(d, extra=b"EX\x03\x00abc", name=b"f", comment=b"c", hcrc=True)))
    out.append(("text.gzipmembers", "gzip", gzip_member(d[:300]) + gzip_member(b"") + gzip_member(d[300:])))
    # keep the ones that are not too long
    return [s for s in out if len(s[2]) <= 420]


# ------------------------------------------------------------------------------------------------------------ main


def main():
    corp = corpora()
    corp["text3000"] = corp["text"][:3000]
    corp["text5000"] = corp["text"][:5000]
    vectors = python_streams(corp)
    go_names = ["hello", "text3000", "text", "runs", "records", "fibonacci", "zeros", "empty", "one"]
    vectors += go_streams(corp, go_names)

    # every valid stream is checked against both references and the corpus it came from
    items = [(n, f, s) for n, f, s, _ in vectors]
    goes = go_verdicts(items)
    lines = []
    for name, fmt, stream, k in vectors:
        want = corp[k]
        z = zlib_verdict(fmt, stream)
        assert z == want, f"zlib disagrees on {name}"
        g = goes[name]
        assert g == (len(want), sha(want)), f"Go disagrees on {name}: {g}"
        lines.append(f"ok {name} {fmt} {len(want)} {sha(want)} {stream.hex()}")

    small = small_corpora()
    bases = base_streams(small)
    rng = random.Random(0xD00D)
    muts = []
    for name, fmt, stream in bases:
        z = zlib_verdict(fmt, stream)
        assert z == small[name.split(".")[0]], name
        for edits, copy in damage(stream, fmt, rng):
            muts.append((name, fmt, edits, copy))
    gv = go_verdicts([(str(i), m[1], m[3]) for i, m in enumerate(muts)])
    mlines, tally = [], {}
    for i, (name, fmt, edits, copy) in enumerate(muts):
        z, g = zlib_verdict(fmt, copy), gv[str(i)]
        zv = None if z is None else (len(z), sha(z))
        key = ("zlib ok" if z is not None else "zlib err", "go ok" if g is not None else "go err", "same" if (zv == g) else "differ")
        tally[key] = tally.get(key, 0) + 1
        mlines.append(f"mut {name} {edits} {verdict_text(z)} {'err' if g is None else 'ok:%d:%s' % g}")

    with open(OUT, "w") as f:
        f.write("# Compressed streams from zlib, gzip(1), zlib-flate, Go and hand-made ones, and damaged copies of some of them, with\n")
        f.write("# the verdicts of Python's zlib and Go's compress/*. Made by tools/gen_inflate_vectors.py; see there for the format.\n")
        f.write(f"# {sys.version.split()[0]} zlib {zlib.ZLIB_VERSION}; {subprocess.run([GO, 'version'], stdout=subprocess.PIPE).stdout.decode().strip()}\n")
        for line in lines:
            f.write(line + "\n")
        for name, fmt, stream in bases:
            f.write(f"base {name} {fmt} {stream.hex()}\n")
        for line in mlines:
            f.write(line + "\n")
    print(f"{len(lines)} valid streams, {len(bases)} bases, {len(mlines)} damaged copies; {os.path.getsize(OUT)} bytes", file=sys.stderr)
    for k in sorted(tally):
        print("  ", *k, tally[k], file=sys.stderr)


if __name__ == "__main__":
    main()
