#!/bin/bash
# Measures pratique against Go's net/http client (the yardstick, tools/bench_client.go) and HTTP/2 against HTTP/1.1,
# on the same server and the same cores, and prints the median wall time and CPU time of each.
#
#   bash tools/bench_h2.sh [ROUNDS] [MODE...]
#
# ROUNDS (default 7) runs of each variant, interleaved; MODEs (default: all):
#   single   one 100 MB download
#   stream   one 100 MB download, read in pieces of 64 KiB and thrown away (how a download to a file reads it)
#   par      eight 47 MB downloads at once (one HTTP/2 connection, eight HTTP/1.1 connections)
#   small    2000 requests of 1 KB in a row, one thread
#   small8   4000 requests of 1 KB on eight threads
#   cold     128 requests of 1 KB at once, to a server 20 ms away (round trip), with no connection open yet: handshakes
#   rtt      one 47 MB download from a server 20 ms away
#
# The server is Go's net/http (tools/h2_oracle_server.go), once with HTTP/2 and once HTTP/1.1 only, pinned to CPU 0 with
# `taskset` when there is one; the clients may use CPUS (default "0,1"), which is what makes the two cores the machine has
# the limit. The far server of `cold` and `rtt` is the same one behind tools/bench_delay_proxy.go. CPU time is the sum of
# user and system time of the client process (from /proc, in ticks of 10 ms, so look at the medians over many rounds, not
# at a single run). What the wall time of a download over HTTP/2 is bounded by here is the Go server, whose HTTP/2 costs
# more CPU than its HTTP/1.1 does: compare the Go client's two lines as well as ours.
#
# Needs: cargo, go, python3. Takes a minute or two per mode.
set -eu
cd "$(dirname "$0")/.."
ROUNDS=${1:-7}
[ $# -gt 0 ] && shift
MODES=${*:-single stream par small small8 cold rtt}
CPUS=${CPUS:-0,1}
T=$(mktemp -d)
PIDS=""
cleanup() { [ -n "$PIDS" ] && kill $PIDS 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

cargo build --release --example fetch >/dev/null 2>&1 || cargo build --release --example fetch
FETCH=$PWD/target/release/examples/fetch
go build -o "$T/oracle" tools/h2_oracle_server.go
go build -o "$T/gobench" tools/bench_client.go
go build -o "$T/delay" tools/bench_delay_proxy.go

PIN=""
if command -v taskset >/dev/null 2>&1 && [ "$(nproc)" -ge 2 ]; then PIN="taskset -c 0"; fi

start() { # logfile, command... : starts it in the background and prints the "listening ADDR" it announces
    local log=$1; shift
    "$@" >"$log" 2>&1 &
    PIDS="$PIDS $!"
    for _ in $(seq 1 100); do
        if grep -q '^listening' "$log" 2>/dev/null; then sed -n 's/^listening //p' "$log" | head -1; return; fi
        sleep 0.1
    done
    echo "could not start: $*" >&2; cat "$log" >&2; exit 1
}
cd "$T"
H2=$(start h2.log $PIN ./oracle -ca root-h2.pem -port 0)
H1=$(start h1.log $PIN ./oracle -ca root-h1.pem -port 0 -h1)
D2=$(start d2.log ./delay -listen 127.0.0.1:0 -target "$H2" -delay 10ms)
D1=$(start d1.log ./delay -listen 127.0.0.1:0 -target "$H1" -delay 10ms)

echo "client cores: $CPUS; server: ${PIN:-not pinned}; $ROUNDS rounds, medians"
export FETCH_TIMES=1 FETCH CPUS ROUNDS H1 H2 D1 D2 T
python3 - $MODES <<'PY'
import os, re, statistics, subprocess, sys
fetch, cpus, rounds, tmp = os.environ["FETCH"], os.environ["CPUS"], int(os.environ["ROUNDS"]), os.environ["T"]
h1, h2, d1, d2 = (os.environ[k] for k in ("H1", "H2", "D1", "D2"))
pin = ["taskset", "-c", cpus] if subprocess.run(["which", "taskset"], capture_output=True).returncode == 0 else []
env = dict(os.environ)

def variants(addr1, addr2, path, ours, go):
    base = [fetch, "--no-proxy", "--max-bytes", "1000000000"]
    return {
        "ours h1": pin + base + ["--cacert", f"{tmp}/root-h1.pem"] + ours + [f"https://{addr1}{path}"],
        "go   h1": pin + [f"{tmp}/gobench", "-ca", f"{tmp}/root-h1.pem", "-h1"] + go + [f"https://{addr1}{path}"],
        "ours h2": pin + base + ["--http2", "--cacert", f"{tmp}/root-h2.pem"] + ours + [f"https://{addr2}{path}"],
        "go   h2": pin + [f"{tmp}/gobench", "-ca", f"{tmp}/root-h2.pem"] + go + [f"https://{addr2}{path}"],
    }

def one(cmd):
    err = subprocess.run(cmd, capture_output=True, text=True, env=env).stderr.strip().splitlines()
    t = err[-1] if err else ""
    m = re.search(r"wall ([0-9.]+) s, cpu ([0-9.]+) s", t)
    if m:
        return float(m.group(1)) * 1000, float(m.group(2)) * 1000
    m = re.search(r"in ([0-9.]+)(ms|s) \(cpu ([0-9.]+) s\)", t)
    if m:
        return float(m.group(1)) * (1 if m.group(2) == "ms" else 1000), float(m.group(3)) * 1000
    raise SystemExit(f"no timing in the output of {' '.join(cmd)}: {t}")

MODES = {
    "single": ("one 100 MB download", h1, h2, "/size/100000000", [], []),
    "stream": ("one 100 MB download, read in pieces", h1, h2, "/size/100000000", ["--stream"], ["-stream"]),
    "par": ("8 x 47 MB at once", h1, h2, "/size/47000000", ["--parallel", "8"], ["-parallel", "8"]),
    "small": ("2000 requests of 1 KB in a row, 1 thread", h1, h2, "/size/1000", ["--repeat", "2000"], ["-repeat", "2000"]),
    "small8": ("4000 requests of 1 KB, 8 threads", h1, h2, "/size/1000", ["--parallel", "8", "--repeat", "4000"], ["-parallel", "8", "-repeat", "4000"]),
    "cold": ("128 requests of 1 KB at once, no connection yet, 20 ms round trip", d1, d2, "/size/1000", ["--parallel", "128"], ["-parallel", "128"]),
    "rtt": ("one 47 MB download, 20 ms round trip", d1, d2, "/size/47000000", [], []),
}
for mode in sys.argv[1:]:
    title, a1, a2, path, ours, go = MODES[mode]
    vs = variants(a1, a2, path, ours, go)
    res = {k: [] for k in vs}
    for _ in range(rounds):
        for k, cmd in vs.items():
            res[k].append(one(cmd))
    print(f"== {mode}: {title}")
    for k, v in res.items():
        print(f"   {k}   wall {statistics.median(x[0] for x in v):7.0f} ms   cpu {statistics.median(x[1] for x in v):6.0f} ms")
PY
