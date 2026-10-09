#!/usr/bin/env python3
"""Generates tests/data/json_vectors.txt: JSON texts with the verdict of a strict reader built on Python's
`json` (UTF-8 decoded strictly, no byte order mark, no NaN/Infinity, duplicate names refused, lone
surrogates refused) and, where there is one, the canonical form made by the independent `rfc8785`
package (`pip install rfc8785`). src/json.rs's test `agrees_with_python_and_rfc8785` replays them.
Run from the repository root:

    python3 tools/gen_json_vectors.py

One case per line:   case HEXOFTEXT ok|bad CANONICALHEX|-

(`-`: no canonical form: a number that is not a safe integer.) Nesting is kept to a few levels here;
the depth limit is tested by the unit tests.
"""
import hashlib
import json
import sys

import rfc8785

OUT = "tests/data/json_vectors.txt"
SEED = b"tiny_https json vectors 2026-10-06"
_ctr = 0


def rnd(n):
    global _ctr
    _ctr += 1
    return int.from_bytes(hashlib.sha256(SEED + b"%d" % _ctr).digest(), "big") % n


def has_surrogate(v):
    if isinstance(v, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, list):
        return any(has_surrogate(x) for x in v)
    if isinstance(v, dict):
        return any(has_surrogate(k) or has_surrogate(x) for k, x in v.items())
    return False


def strict(b):
    """The value, or None if a strict reader refuses the text."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if s.startswith("\ufeff"):
        return None

    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise ValueError("duplicate name")
            d[k] = v
        return d

    def refuse(c):
        raise ValueError(c)

    try:
        v = json.loads(s, object_pairs_hook=pairs, parse_constant=refuse)
    except (ValueError, RecursionError):
        return None
    if has_surrogate(v):
        return None
    return (v,)


def canon(v):
    """rfc8785's canonical form, or None if it holds a number that is not a safe integer."""
    def ok(x):
        if isinstance(x, bool) or x is None or isinstance(x, str):
            return True
        if isinstance(x, int):
            return abs(x) <= (1 << 53) - 1
        if isinstance(x, float):
            return False
        if isinstance(x, list):
            return all(ok(i) for i in x)
        return all(ok(i) for i in x.values())
    # a float that happens to be integral (1.0, 1e3) is a different token from the integer: this reader does not canonicalize it
    if not ok(v):
        return None
    return rfc8785.dumps(v)


# ------------------------------------------------------------------------------------- the cases
cases = []


def add(b):
    cases.append(b if isinstance(b, bytes) else b.encode("utf-8"))


HAND = [
    # valid
    "null", "true", "false", "0", "-0", "1", "-1", "123456789", "0.5", "-0.5e+10", "1E2", "1e-2", "\"\"", "\"a\"", "[]", "{}", "[[]]", "[{}]", "{\"a\":[]}", " \t\r\n[ 1 , 2 ] \n",
    "\"\\u0041\"", "\"\\ud83d\\ude00\"", "\"\\uD83D\\uDE00\"", "\"\U0001f600\"", "\"\\u0000\"", "\"\\/\"", "\"\u2028\u2029\"", "\"\ufeff\"", "{\"\":1}", "{\"a\":1,\"A\":2}", "{\"é\":1,\"e\\u0301\":2}",
    "9007199254740991", "-9007199254740991", "9007199254740992", "9007199254740993", "9223372036854775807", "9223372036854775808", "-9223372036854775808", "18446744073709551616",
    "{\"\U0001f600\":1,\"\u20ac\":2,\"\uffff\":3,\"a\":4}", "{\"b\":2,\"a\":1,\"c\":{\"z\":1,\"y\":2}}",
    # invalid
    "", " ", "nul", "NULL", "True", "NaN", "Infinity", "-Infinity", "[NaN]", "[1,]", "[,1]", "{\"a\":1,}", "{'a':1}", "{a:1}", "[1 2]", "01", "-01", "+1", "1.", ".5", "1e", "1e+", "0x1", "--1", "-", "1 2", "[1]]",
    "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "{\"é\":1,\"\\u00e9\":2}", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\\udc00\\ud800\"", "\"\\x41\"", "\"\\u12\"", "\"\\'\"", "\"a\nb\"", "\"a\tb\"",
    "\"\x01\"", "/* c */ 1", "1 // c", "\u00a01", "\x0b1", "\x0c1", "[\"a\" \"b\"]", "{\"a\" 1}", "{\"a\":1 \"b\":2}", "{1:2}", "{\"a\"}", "[1,,2]", "[", "{", "\"", "\"\\", "\ufeff1", "{\"a\":01}",
]
for h in HAND:
    add(h)
for h in [b"\"\xff\"", b"\"\xc0\xaf\"", b"\"\xed\xa0\x80\"", b"\"\xed\xbf\xbf\"", b"\"\xf4\x90\x80\x80\"", b"\"\x80\"", b"\"\xe2\x82\"", b"\xef\xbb\xbf1", b"\xff\xfe1\x00", b"1\x00", b"\x001"]:
    add(h)


def gen(depth):
    k = rnd(7 if depth < 3 else 5)
    if k == 0:
        return "null"
    if k == 1:
        return ["true", "false"][rnd(2)]
    if k == 2:
        return str(rnd(1 << 40) - (1 << 39))
    if k == 3:
        parts = ["a", "b", "\\n", "\\u00e9", "\\ud83d\\ude00", "é", "\U0001f600", "\\\"", " ", "\\/", "\\u001f", "\\u007f", "\u2028"]
        return '"' + "".join(parts[rnd(len(parts))] for _ in range(rnd(6))) + '"'
    if k == 4:
        return ["0", "-0", "1.5", "1e3", "-2.5E-3", "0.0", "9007199254740993", "1E400"][rnd(8)]
    if k == 5:
        return "[" + ",".join(gen(depth + 1) for _ in range(rnd(4))) + "]"
    names = ["a", "b", "\\u0061", "é", "\U0001f600", "\u20ac", "\\ud83d\\ude00", "k", ""]
    return "{" + " , ".join('"%s" : %s' % (names[rnd(len(names))], gen(depth + 1)) for _ in range(rnd(5))) + "}"


for _ in range(1500):
    add(gen(0))

# damaged copies of generated and hand-written texts
base = list(cases)
JUNK = b'{}[]",:\\0e-+. \n\t'
for _ in range(2500):
    b = bytearray(base[rnd(len(base))])
    for _ in range(1 + rnd(3)):
        if not b:
            break
        i = rnd(len(b))
        m = rnd(5)
        if m == 0:
            b[i] ^= 1 << rnd(8)
        elif m == 1:
            del b[i]
        elif m == 2:
            b.insert(i, JUNK[rnd(len(JUNK))])
        elif m == 3:
            del b[i:]
        else:
            b[i:i] = bytes([rnd(256)])
    cases.append(bytes(b))

seen = set()
lines = ["# generated by tools/gen_json_vectors.py: case HEXOFTEXT ok|bad CANONICALHEX|-"]
nok = 0
for c in cases:
    if c in seen:
        continue
    seen.add(c)
    r = strict(c)
    if r is None:
        lines.append("case %s bad -" % c.hex())
    else:
        cf = canon(r[0])
        lines.append("case %s ok %s" % (c.hex(), cf.hex() if cf is not None else "-"))
        nok += 1
with open(OUT, "w") as f:
    f.write("\n".join(lines) + "\n")
print("wrote %s: %d cases, %d accepted, %d refused" % (OUT, len(lines) - 1, nok, len(lines) - 1 - nok))
