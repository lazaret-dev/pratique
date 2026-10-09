#!/usr/bin/env python3
"""Cross-checks pratique's HPACK (src/http/h2/hpack.rs) against Python's `hpack` package (4.x).

  python3 tools/hpack_oracle.py gen tests/data/hpack_python.txt
      writes header blocks made by the Python encoder, with the fields they must decode to; the Rust unit test
      `decodes_what_python_encoded` reads that file. (Deterministic: the same file comes out each time.)

  python3 tools/hpack_oracle.py check corpus.txt
      reads the blocks that pratique's encoder wrote (run the Rust test `emit_oracle_corpus` with
      HPACK_ORACLE_OUT=corpus.txt) and decodes them with the Python decoder; fails if a field differs.

  python3 tools/hpack_oracle.py rfc
      decodes the examples of RFC 7541 appendix C with the Python decoder and prints what they give (what the
      expected values in the Rust tests were checked against).

Install the oracle with `pip install hpack` (4.2.0 was used). The text format, one item per line:
  seq ALLOWED_TABLE_SIZE
  block HEX
  field NAME_HEX VALUE_HEX     (after its block; zero or more, then the next block or `end`)
  end
"""
import random
import sys

from hpack import Decoder, Encoder, HeaderTuple, NeverIndexedHeaderTuple

COMMON = [
    (b":method", b"GET"), (b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/"), (b":path", b"/index.html"),
    (b":authority", b"www.example.com"), (b":status", b"200"), (b":status", b"404"), (b"accept-encoding", b"gzip, deflate"),
    (b"user-agent", b"tiny_https/0.1"), (b"content-type", b"application/json"), (b"content-length", b"0"),
    (b"cache-control", b"no-cache"), (b"cache-control", b"max-age=3600"), (b"etag", b"\"abc123\""),
    (b"x-request-id", b"7f3a9c"), (b"set-cookie", b"a=b; Path=/; HttpOnly"),
]


def rand_bytes(rng, lo, hi, alphabet):
    return bytes(rng.choice(alphabet) for _ in range(rng.randint(lo, hi)))


LOWER = b"abcdefghijklmnopqrstuvwxyz-"
VALUE = bytes(range(0x20, 0x7f))
ANY = bytes(range(0, 256))


def make_fields(rng, pool):
    n = rng.randint(0, 12)
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.45:
            name, value = rng.choice(COMMON)
        elif r < 0.65 and pool:
            name, value = rng.choice(pool)  # something sent before: exercises the dynamic table
        elif r < 0.85:
            name, value = rand_bytes(rng, 1, 14, LOWER), rand_bytes(rng, 0, 40, VALUE)
        elif r < 0.95:
            name, value = rng.choice(COMMON)[0], rand_bytes(rng, 0, 30, VALUE)
        else:
            name, value = rand_bytes(rng, 1, 6, LOWER), rand_bytes(rng, 0, 20, ANY)  # binary values
        out.append((name, value, rng.random() < 0.1))
        if len(pool) < 40:
            pool.append((name, value))
        else:
            pool[rng.randrange(40)] = (name, value)
    return out


def gen(path):
    rng = random.Random(7541)
    lines = []
    for s in range(40):
        enc = Encoder()
        size = rng.choice([4096, 4096, 256, 64, 0, 100])
        enc.header_table_size = size
        pool = []
        lines.append("seq 4096")
        for b in range(rng.randint(2, 6)):
            if b > 0 and rng.random() < 0.2:
                enc.header_table_size = rng.choice([0, 32, 64, 256, 1000, 4096])
            fields = make_fields(rng, pool)
            headers = [NeverIndexedHeaderTuple(n, v) if sens else HeaderTuple(n, v) for n, v, sens in fields]
            block = enc.encode(headers, huffman=rng.random() < 0.7)
            lines.append("block " + block.hex())
            for n, v, _ in fields:
                lines.append("field %s %s" % (n.hex(), v.hex()))
        lines.append("end")
    open(path, "w").write("\n".join(lines) + "\n")
    print("wrote", path, len([l for l in lines if l.startswith("block")]), "blocks")


def parse(path):
    seqs = []
    cur = None
    for line in open(path):
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "seq":
            cur = {"allowed": int(parts[1]), "blocks": []}
        elif parts[0] == "block":
            cur["blocks"].append({"block": bytes.fromhex(parts[1]) if len(parts) > 1 else b"", "fields": []})
        elif parts[0] == "field":
            cur["blocks"][-1]["fields"].append((bytes.fromhex(parts[1]), bytes.fromhex(parts[2]) if len(parts) > 2 else b""))
        elif parts[0] == "end":
            seqs.append(cur)
    return seqs


def check(path):
    bad = 0
    total = 0
    for i, seq in enumerate(parse(path)):
        dec = Decoder()
        dec.max_allowed_table_size = seq["allowed"]
        for j, blk in enumerate(seq["blocks"]):
            total += 1
            try:
                got = [(bytes(n), bytes(v)) for n, v in dec.decode(blk["block"], raw=True)]
            except Exception as e:  # noqa
                print("FAIL seq %d block %d: %s: %s" % (i, j, type(e).__name__, e))
                bad += 1
                continue
            if got != blk["fields"]:
                print("FAIL seq %d block %d: fields differ\n  want %r\n  got  %r" % (i, j, blk["fields"], got))
                bad += 1
    print("%d blocks checked by Python hpack, %d failed" % (total, bad))
    sys.exit(1 if bad else 0)


RFC = {
    "C.2.1": "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
    "C.2.2": "040c2f73616d706c652f70617468",
    "C.2.3": "100870617373776f726406736563726574",
    "C.2.4": "82",
    "C.3.1": "828684410f7777772e6578616d706c652e636f6d",
    "C.3.2": "828684be58086e6f2d6361636865",
    "C.3.3": "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    "C.4.1": "828684418cf1e3c2e5f23a6ba0ab90f4ff",
    "C.4.2": "828684be5886a8eb10649cbf",
    "C.4.3": "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
    "C.5.1": "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
    "C.5.2": "4803333037c1c0bf",
    "C.5.3": "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
    "C.6.1": "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
    "C.6.2": "4883640effc1c0bf",
    "C.6.3": "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
}


def rfc():
    # each group is one connection (C.2.x are separate), the responses use a 256-byte table
    groups = [["C.2.1"], ["C.2.2"], ["C.2.3"], ["C.2.4"], ["C.3.1", "C.3.2", "C.3.3"], ["C.4.1", "C.4.2", "C.4.3"],
              ["C.5.1", "C.5.2", "C.5.3"], ["C.6.1", "C.6.2", "C.6.3"]]
    for g in groups:
        dec = Decoder()
        if g[0].startswith(("C.5", "C.6")):
            dec.max_allowed_table_size = 256
            dec.header_table_size = 256
        for name in g:
            fields = dec.decode(bytes.fromhex(RFC[name]), raw=True)
            print(name, [(bytes(n).decode(), bytes(v).decode()) for n, v in fields])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "gen":
        gen(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "rfc":
        rfc()
    else:
        print(__doc__)
        sys.exit(2)
