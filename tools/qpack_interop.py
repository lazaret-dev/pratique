#!/usr/bin/env python3
"""Live cross-check of pratique's QPACK (src/http/h3/qpack.rs) against ls-qpack, through the `pylsqpack` package.

    python3 tools/qpack_interop.py [--sessions N] [--seed S] [--steps N] [--exe TEST_BINARY] [--record FILE]

Two directions, with the acknowledgments flowing back so that the dynamic table, blocked streams, evictions, Section
Acknowledgments, Stream Cancellations and Insert Count Increments all happen:

  A. ls-qpack's encoder -> our decoder. Sections and encoder-stream bytes are delivered late, out of step with each other (so some
     sections block) and cut in the middle of instructions; our decoder's decoder-stream bytes go back into ls-qpack's encoder.
     The fields our decoder gives must be the ones ls-qpack was given, and ls-qpack must accept what our decoder says.
  B. our encoder -> ls-qpack's decoder, the same way. (pylsqpack's decoder gives back Section Acknowledgments only, no Insert Count
     Increments; those are what A tests.)

Our side runs as the ignored test `qpack_peer` of the library (it reads commands on standard input; see the comment there), found
by building the tests with cargo unless --exe names the binary. With --record the part of A that our decoder saw is written as a
fixture: `tests/data/qpack_lsqpack.txt`, which the test `decodes_what_lsqpack_encoded` replays, so the fixture needs neither Python
nor ls-qpack to be checked again. Its format, one item a line:

  session DECODER_CAPACITY DECODER_BLOCKED
  enc HEX                  bytes of the encoder stream, delivered to the decoder
  block STREAM HEX         a field section; it decodes, or it waits for what later `enc` lines bring
  field NAME_HEX VALUE_HEX the fields the section must decode to (after its `block`)
  cancel STREAM            the stream was abandoned
  end

Install the oracle with `pip install pylsqpack` (0.3.24 was used).
"""
import argparse
import json
import os
import random
import subprocess
import sys

import pylsqpack


def hx(b):
    return bytes(b).hex() or "-"


def unhx(s):
    return b"" if s == "-" else bytes.fromhex(s)


class Peer:
    """Our side: the `qpack_peer` test, spoken to over a pipe."""

    def __init__(self, exe):
        self.p = subprocess.Popen([exe, "--ignored", "--exact", "http::h3::qpack::tests::qpack_peer", "--nocapture", "--test-threads=1"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        while True:
            reply = self.p.stdout.readline()
            if not reply:
                raise SystemExit("the peer ended (did the test fail to start?)")
            i = reply.find("@@ ")  # (the first reply follows the harness's "test ... " on the same line)
            if i >= 0:
                return reply[i + 3:].rstrip("\n")

    def close(self):
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
            self.p.wait(timeout=20)
        except Exception:  # noqa
            self.p.kill()


def find_exe():
    out = subprocess.run(["cargo", "test", "--lib", "--no-run", "--message-format=json"], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    exe = None
    for line in out.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("target", {}).get("name") == "pratique" and m.get("profile", {}).get("test"):
            exe = m["executable"]
    if not exe:
        raise SystemExit("could not build the test binary:\n" + out.stderr[-2000:])
    return exe


NAMES = [b":authority", b":path", b"user-agent", b"accept", b"accept-encoding", b"accept-language", b"content-type", b"cache-control",
         b"cookie", b"referer", b"x-request-id", b"if-none-match", b"range", b":method", b":scheme", b"content-length", b"authorization",
         b"x-custom-header", b"x-another-longer-custom-header-name"]


def make_headers(rng, pools, small=False):
    out = []
    # (at least one: ls-qpack's decoder refuses a section with no field lines at all, which no HTTP/3 message has)
    for _ in range(rng.randint(1, 5 if small else 9)):
        name = rng.choice(NAMES)
        pool = pools.setdefault(name, [])
        r = rng.random()
        if pool and r < 0.6:
            value = rng.choice(pool)
        else:
            kind = rng.random()
            if kind < 0.1:
                value = b""
            elif kind < 0.2:
                value = bytes(rng.randrange(256) for _ in range(rng.randint(0, 12 if small else 30)))
            elif kind < 0.3:
                value = bytes(rng.choice(b"abcdefghij/-.") for _ in range(rng.randint(20, 40) if small else rng.randint(100, 300)))
            else:
                value = ("v%d-" % rng.randrange(10 ** 6)).encode() + bytes(rng.choice(b"abcdefghijklmnop ") for _ in range(rng.randint(0, 10 if small else 25)))
            if len(pool) < 6:
                pool.append(value)
            else:
                pool[rng.randrange(6)] = value
        out.append((name, value))
    return out


def dump(trace):
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "qpack_interop_trace.txt")
    with open(path, "w") as f:
        f.write("\n".join(trace) + "\n")
    return path


def part(rng, buf):
    """A prefix of the buffer to deliver now (taken out of it): often all of it, sometimes cut anywhere."""
    n = len(buf) if rng.random() < 0.4 else rng.randint(0, len(buf))
    chunk = bytes(buf[:n])
    del buf[:n]
    return chunk


def session_a(peer, rng, steps, record, stats):
    small = record is not None  # (a fixture is kept small)
    dec_cap = rng.choice([0, 220, 512, 1024, 4096])
    dec_blocked = rng.choice([0, 1, 3, 16])
    assert peer.ask("init %d %d 0 0 0 0 1" % (dec_cap, dec_blocked)) == "ok"
    enc = pylsqpack.Encoder()
    to_dec = bytearray(enc.apply_settings(dec_cap, dec_blocked))
    to_enc = bytearray()
    pending = []
    pools = {}
    next_stream = 0
    if record is not None:
        record.append("session %d %d" % (dec_cap, dec_blocked))

    def deliver_enc(chunk):
        if not chunk:
            return
        assert peer.ask("enc-stream " + hx(chunk)) == "ok", "our decoder refused what ls-qpack's encoder wrote"
        if record is not None:
            record.append("enc " + hx(chunk))
        stats["enc_bytes"] += len(chunk)
        for s in list(pending):
            if s["blocked"]:
                attempt(s, False)

    def attempt(s, first):
        reply = peer.ask("decode %d %s" % (s["stream"], hx(s["block"])))
        if first and record is not None:
            record.append("block %d %s" % (s["stream"], hx(s["block"])))
            record.extend("field %s %s" % (hx(n), hx(v)) for n, v in s["headers"])
        if reply.startswith("blocked"):
            s["blocked"] = True
            stats["blocked"] += 1
        elif reply.startswith("done"):
            got = [(unhx(a), unhx(b)) for a, b in (tok.split("/") for tok in reply.split()[1:])]
            assert got == s["headers"], "stream %d: ls-qpack encoded %r, our decoder read %r" % (s["stream"], s["headers"], got)
            pending.remove(s)
            stats["sections"] += 1
        else:
            raise AssertionError("our decoder refused a section of ls-qpack's (%s): stream %d, block %s, wire so far %s" % (reply, s["stream"], hx(s["block"]), reply))

    def drain_decoder(everything):
        reply = peer.ask("dec-out")
        to_enc.extend(unhx(reply.split()[1]))
        chunk = bytes(to_enc) if everything else part(rng, to_enc)
        if everything:
            to_enc.clear()
        if chunk:
            enc.feed_decoder(chunk)

    for _ in range(steps):
        r = rng.random()
        if r < 0.3:
            headers = make_headers(rng, pools, small)
            ed, block = enc.encode(next_stream, headers)
            to_dec.extend(ed)
            pending.append({"stream": next_stream, "block": block, "headers": headers, "blocked": False, "sent": False})
            next_stream += 4
        elif r < 0.5:
            deliver_enc(part(rng, to_dec))
        elif r < 0.8:
            fresh = [s for s in pending if not s["sent"]]
            if fresh:
                s = rng.choice(fresh)
                s["sent"] = True
                attempt(s, True)
        elif r < 0.85:
            waiting = [s for s in pending if s["blocked"]]
            if waiting:
                s = rng.choice(waiting)
                pending.remove(s)
                assert peer.ask("cancel %d" % s["stream"]) == "ok"
                if record is not None:
                    record.append("cancel %d" % s["stream"])
                stats["cancelled"] += 1
        else:
            drain_decoder(False)
    # everything is delivered
    deliver_enc(bytes(to_dec))
    to_dec.clear()
    for s in list(pending):
        if not s["sent"]:
            s["sent"] = True
            attempt(s, True)
    assert not pending, "sections are still blocked with all of the encoder stream delivered: %r" % [(s["stream"]) for s in pending]
    drain_decoder(True)
    if record is not None:
        record.append("end")
    stats["sessions"] += 1


def session_b(peer, rng, steps, stats):
    peer_cap = rng.choice([0, 220, 512, 1024, 4096])
    peer_blocked = rng.choice([0, 1, 3, 16])
    enc_cap = rng.choice([0, 100, 300, 4096])
    enc_blocked = rng.choice([0, 1, 4])
    safe = rng.choice([0, 1])
    assert peer.ask("init 0 0 %d %d %d %d %d" % (enc_cap, enc_blocked, peer_cap, peer_blocked, safe)) == "ok"
    dec = pylsqpack.Decoder(peer_cap, peer_blocked)
    trace = ["session B: decoder capacity %d, blocked %d; encoder capacity %d, blocked %d, safe %d" % (peer_cap, peer_blocked, enc_cap, enc_blocked, safe)]
    to_dec = bytearray()
    to_enc = bytearray()
    pending = []
    pools = {}
    next_stream = 0

    def check(s, ctrl, headers):
        got = [(bytes(n), bytes(v)) for n, v in headers]
        assert got == s["headers"], "stream %d: we encoded %r (block %s), ls-qpack read %r" % (s["stream"], s["headers"], hx(s["block"]), got)
        to_enc.extend(ctrl)
        pending.remove(s)
        stats["sections"] += 1

    def deliver_enc(chunk):
        if not chunk:
            return
        try:
            unblocked = dec.feed_encoder(chunk)
        except pylsqpack.EncoderStreamError as e:
            raise AssertionError("ls-qpack's decoder refused our encoder stream (%s): %s" % (e, hx(chunk)))
        stats["enc_bytes"] += len(chunk)
        trace.append("encoder stream to ls-qpack: " + hx(chunk) + " unblocked " + repr(unblocked))
        for sid in unblocked:
            s = next(x for x in pending if x["stream"] == sid)
            try:
                ctrl, headers = dec.resume_header(sid)
            except pylsqpack.StreamBlocked:
                continue
            check(s, ctrl, headers)

    def feed(s):
        s["sent"] = True
        trace.append("section to ls-qpack: stream %d %s" % (s["stream"], hx(s["block"])))
        try:
            ctrl, headers = dec.feed_header(s["stream"], s["block"])
        except pylsqpack.StreamBlocked:
            stats["blocked"] += 1
            return
        except pylsqpack.DecompressionFailed as e:
            raise AssertionError("ls-qpack's decoder refused our section (%s): fields %r, block %s\n  " % (e, s["headers"], hx(s["block"])) + trace[0] + "\n  blocked now in ls-qpack: %r\n  " % sorted(x["stream"] for x in pending if x["sent"]) + "\n  ".join(trace[-12:]) + ("\n  (full trace in %s)" % dump(trace)))
        check(s, ctrl, headers)

    def deliver_dec(chunk):
        if chunk:
            trace.append("decoder stream to us: " + hx(chunk))
            reply = peer.ask("dec-stream " + hx(chunk))
            assert reply == "ok", "our encoder refused what ls-qpack's decoder said: %s (%s)" % (reply, hx(chunk))

    for _ in range(steps):
        r = rng.random()
        if r < 0.3:
            headers = make_headers(rng, pools)
            sens = [rng.random() < 0.08 for _ in headers]
            toks = " ".join("%s/%s%s" % (hx(n), hx(v), "/s" if s else "") for (n, v), s in zip(headers, sens))
            reply = peer.ask(("encode %d %s" % (next_stream, toks)).rstrip()).split()
            assert reply[0] == "block" and len(reply) == 3, reply
            to_dec.extend(unhx(reply[2]))
            pending.append({"stream": next_stream, "block": unhx(reply[1]), "headers": headers, "sent": False})
            next_stream += 4
        elif r < 0.5:
            deliver_enc(part(rng, to_dec))
        elif r < 0.8:
            fresh = [s for s in pending if not s["sent"]]
            if fresh:
                feed(rng.choice(fresh))
        else:
            deliver_dec(part(rng, to_enc))
    deliver_enc(bytes(to_dec))
    to_dec.clear()
    for s in list(pending):
        if not s["sent"]:
            feed(s)
    assert not pending, "sections are still blocked with all of the encoder stream delivered: %r" % [s["stream"] for s in pending]
    deliver_dec(bytes(to_enc))
    stats["sessions"] += 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=100)
    ap.add_argument("--steps", type=int, default=250)
    ap.add_argument("--seed", type=int, default=9204)
    ap.add_argument("--exe")
    ap.add_argument("--record")
    args = ap.parse_args()
    peer = Peer(args.exe or find_exe())
    record = [] if args.record else None
    rng = random.Random(args.seed)
    for name, run in (("A (ls-qpack encodes, we decode)", lambda st: session_a(peer, rng, args.steps, record, st)),
                      ("B (we encode, ls-qpack decodes)", lambda st: session_b(peer, rng, args.steps, st))):
        stats = {"sessions": 0, "sections": 0, "blocked": 0, "cancelled": 0, "enc_bytes": 0}
        for _ in range(args.sessions):
            run(stats)
        print("%s: %s" % (name, ", ".join("%d %s" % (v, k) for k, v in stats.items())))
    peer.close()
    if record is not None:
        with open(args.record, "w") as f:
            f.write("\n".join(record) + "\n")
        print("wrote", args.record, sum(1 for l in record if l.startswith("block")), "sections")


if __name__ == "__main__":
    main()
