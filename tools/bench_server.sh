#!/bin/sh
# The load test of pratique's HTTP server (BACKLOG B-112) against Go's net/http: the same pages, the same certificate (a
# P-256 key made by OpenSSL), the same load generator (tools/bench_server.go), on this machine's cores (the servers and
# the generator share them, so the numbers are for comparing the two servers, not for capacity).
#
#   sh tools/bench_server.sh [SECONDS] [WORKERS]     (default 5 and 32)
#
# For each protocol (HTTP/1.1, a connection per worker; HTTP/2, one connection with a stream per worker) and page (a short
# text; 100 KB): requests per second, latency percentiles, and the server's CPU time per thousand requests.
set -u
cd "$(dirname "$0")/.." || exit 2
D=${1:-5}
C=${2:-32}
command -v go >/dev/null && command -v openssl >/dev/null || { echo "needs go and openssl"; exit 2; }
cargo build --release --features server --example serve 2>&1 | tail -1
WORK=$(mktemp -d)
SERVERS=""
trap 'kill $SERVERS 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
    -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
go build -o "$WORK/bench" tools/bench_server.go || exit 2

target/release/examples/serve certfile="$WORK/cert.pem" keyfile="$WORK/key.pem" alpn=h2,http/1.1 quiet=1 > "$WORK/p.log" 2>&1 &
P=$!
"$WORK/bench" serve -cert "$WORK/cert.pem" -key "$WORK/key.pem" > "$WORK/g.log" 2>&1 &
G=$!
SERVERS="$P $G"
for f in p g; do
    n=0
    while ! grep -q '^listening' "$WORK/$f.log"; do n=$((n + 1)); [ $n -gt 100 ] && { cat "$WORK/$f.log"; exit 2; }; sleep 0.1; done
done
PPORT=$(sed -n 's/^listening 127.0.0.1:\([0-9]*\).*/\1/p' "$WORK/p.log")
GPORT=$(sed -n 's/^listening 127.0.0.1:\([0-9]*\).*/\1/p' "$WORK/g.log")
TCK=$(getconf CLK_TCK)
ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }

printf '%-9s %-10s %-9s %s\n' protocol page server "result (and server CPU per 1000 requests)"
for proto in h1 h2; do
    flag=""; [ $proto = h1 ] && flag="-h1"
    for page in / /size/100000; do
        for s in pratique go; do
            if [ $s = pratique ]; then pid=$P; port=$PPORT; else pid=$G; port=$GPORT; fi
            # a short warm-up, then the run
            "$WORK/bench" load -ca "$WORK/cert.pem" $flag -c "$C" -d 1s "https://127.0.0.1:$port$page" > /dev/null
            before=$(ticks $pid)
            out=$("$WORK/bench" load -ca "$WORK/cert.pem" $flag -c "$C" -d "${D}s" "https://127.0.0.1:$port$page")
            after=$(ticks $pid)
            rps=$(echo "$out" | awk '{print $1}')
            cpu=$(awk -v a="$after" -v b="$before" -v t="$TCK" -v r="$rps" -v d="$D" 'BEGIN { n = r * d; if (n > 0) printf "%.1f ms", (a - b) * 1000 / t / (n / 1000); else print "-" }')
            printf '%-9s %-10s %-9s %s  (CPU %s)\n' $proto "$page" $s "$out" "$cpu"
        done
    done
done
