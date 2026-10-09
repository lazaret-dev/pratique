#!/bin/sh
# Checks pratique's HTTP/2 servers against clients that are not ours: curl (nghttp2), Go's net/http
# (tools/h2_interop.go) and python-h2 (tools/h2_interop.py). Each check starts the `serve` example with some settings,
# connects, and compares what came back with what the server must have sent. Also reads the server's own log: a
# request it found fault with is reported there.
#
# Every check runs twice: against the production server (src/http/server, B-111), and against the test server the
# client's tests script (src/http/h2_server.rs, `serve server=test`). The production server never pushes, so the
# PUSH_PROMISE checks are the test server's alone.
#
#   sh tools/h2_interop.sh            all the checks that the installed tools allow (skips the others)
#   H2SPEC=/path/to/h2spec sh tools/h2_interop.sh   with h2spec too, if it is not on the PATH
#   RELEASE=1 sh tools/h2_interop.sh  build with --release first
#
# python-h2 is found if `import h2` works; PYTHONPATH may point at a directory that has h2, hpack and hyperframe.
set -u
cd "$(dirname "$0")/.." || exit 2

PROFILE=debug
CARGO_FLAGS=""
if [ "${RELEASE:-0}" = 1 ]; then PROFILE=release; CARGO_FLAGS="--release"; fi
cargo build $CARGO_FLAGS --features server --example serve 2>&1 | tail -2
SERVE="target/$PROFILE/examples/serve"
[ -x "$SERVE" ] || { echo "no $SERVE"; exit 2; }

WORK=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM
SERVER_PID=""
fail=0
passed=0
skipped=""

have() { command -v "$1" >/dev/null 2>&1; }

# start_server OPTION... : starts the example with h2 offered first; sets PORT and CA
start_server() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    : > "$WORK/log"
    "$SERVE" ca="$WORK/root.pem" alpn=h2,http/1.1 server=$MODE "$@" > "$WORK/log" 2>&1 &
    SERVER_PID=$!
    n=0
    while ! grep -q '^listening' "$WORK/log"; do
        n=$((n + 1)); [ $n -gt 100 ] && { echo "the server did not start"; cat "$WORK/log"; exit 2; }
        sleep 0.1
    done
    PORT=$(sed -n 's/^listening 127.0.0.1:\([0-9]*\).*/\1/p' "$WORK/log")
    CA="$WORK/root.pem"
}

ok() { passed=$((passed + 1)); echo "ok   [$MODE] $*"; }
bad() { fail=1; echo "FAIL [$MODE] $*"; echo "---- server log"; sed 's/^/     /' "$WORK/log" | tail -40; echo "----"; }

# the server's log must not say that it found fault with anything (the pages /reset, /goaway, /push are on purpose)
log_clean() {
    ! grep -q 'complain\|fault' "$WORK/log"
}

for MODE in production test; do
if [ "$MODE" = production ]; then NOPUSH_GO="-no-push"; NOPUSH_PY="--no-push"; else NOPUSH_GO=""; NOPUSH_PY=""; fi
echo "======== the $MODE server"
# ------------------------------------------------------------------------------------------------------ curl
if have curl && curl --version | grep -q HTTP2; then
    echo "== curl ($(curl --version | head -1 | cut -d' ' -f1-2), $(curl --version | grep -o 'nghttp2/[0-9.]*'))"
    start_server
    U="https://localhost:$PORT"
    R="--resolve localhost:$PORT:127.0.0.1"
    out=$(curl -sS --http2 --cacert "$CA" $R "$U/size/100000" "$U/size/0" "$U/chunked/7000" "$U/status/404" \
        -o "$WORK/a" -o "$WORK/b" -o "$WORK/c" -o "$WORK/d" -w '%{http_version} %{http_code} %{size_download} %{num_connects}\n' 2>&1 | tr '\n' ';')
    if [ "$out" = "2 200 100000 1;2 200 0 0;2 200 7000 0;2 404 0 0;" ] && [ "$(wc -c < "$WORK/a")" = 100000 ]; then
        ok "curl: four requests on one HTTP/2 connection ($out)"
    else
        bad "curl multiplexing: $out"
    fi
    head -c 300000 /dev/urandom > "$WORK/payload"
    curl -sS --http2 --cacert "$CA" $R --data-binary "@$WORK/payload" "$U/echo" -o "$WORK/echoed" 2>"$WORK/err"
    if cmp -s "$WORK/payload" "$WORK/echoed"; then ok "curl: a 300000-byte POST comes back unchanged"; else bad "curl POST"; fi
    out=$(curl -sS --http2 --parallel --parallel-immediate --cacert "$CA" $R "$U/size/200000" "$U/size/300000" "$U/slow/30" "$U/echo" \
        -o "$WORK/p1" -o "$WORK/p2" -o "$WORK/p3" -o "$WORK/p4" -w '%{http_code}:%{size_download}:%{num_connects} ' 2>&1)
    if [ "$out" = "200:200000:1 200:300000:1 200:30:1 200:0:1 " ] || { echo "$out" | grep -q '200:200000' && echo "$out" | grep -q '200:300000' && echo "$out" | grep -q '200:30:'; }; then
        ok "curl: four parallel transfers ($out)"
    else
        bad "curl parallel: $out"
    fi
    h=$(curl -sS --http2 -I --cacert "$CA" $R "$U/size/1000" | tr -d '\r')
    echo "$h" | grep -q '^HTTP/2 200' && echo "$h" | grep -q '^content-length: 1000' && ok "curl: HEAD" || bad "curl HEAD: $h"
    n=$(curl -sS --http2 -D - --cacert "$CA" $R "$U/headers/200" -o /dev/null | grep -c '^x-header-')
    [ "$n" = 200 ] && ok "curl: 200 response header fields (CONTINUATION frames)" || bad "curl /headers/200: $n"
    t=$(curl -sS --http2 --cacert "$CA" $R "$U/trailers" --trace-ascii - 2>&1 | grep -c 'x-sum: 21')
    [ "$t" -ge 1 ] && ok "curl: trailers" || bad "curl trailers"
    h=$(curl -sS --http2 -D - --cacert "$CA" $R "$U/interim" | tr -d '\r')
    echo "$h" | grep -q '^HTTP/2 103' && echo "$h" | grep -q '^HTTP/2 200' && echo "$h" | grep -q 'after the interim response' && ok "curl: 103 and then 200" || bad "curl interim: $h"
    curl -sS --http2 --cacert "$CA" $R "$U/reset" -o /dev/null 2>"$WORK/err"
    [ $? = 92 ] && ok "curl: RST_STREAM INTERNAL_ERROR is exit 92" || bad "curl /reset: $(cat "$WORK/err")"
    out=$(curl -sS --http2 --cacert "$CA" $R "$U/goaway" "$U/size/10" -o /dev/null -o /dev/null -w '%{http_code} ' 2>&1)
    [ "$out" = "200 200 " ] && ok "curl: GOAWAY after an answer, the next request goes to a new connection" || bad "curl goaway: $out"
    if [ "$MODE" = test ]; then
        curl -sS --http2 --cacert "$CA" $R "$U/push" -o /dev/null 2>/dev/null
        [ $? != 0 ] && ok "curl: a PUSH_PROMISE it did not ask for is an error" || bad "curl accepted a PUSH_PROMISE"
    fi
    log_clean && ok "curl: the server found nothing to complain of" || bad "the server complained"
    # records of 100 bytes: HTTP/2 frames split across TLS records
    start_server fragment=100
    curl -sS --http2 --cacert "$CA" --resolve "localhost:$PORT:127.0.0.1" --data-binary "@$WORK/payload" "https://localhost:$PORT/echo" -o "$WORK/echoed" 2>"$WORK/err"
    cmp -s "$WORK/payload" "$WORK/echoed" && ok "curl: POST and echo with TLS records of 100 bytes" || bad "curl with fragment=100"
    # http/1.1 first: curl --http2 gets HTTP/1.1
    start_server alpn=http/1.1,h2
    v=$(curl -sS --http2 --cacert "$CA" "https://127.0.0.1:$PORT/size/5" -o /dev/null -w '%{http_version}' 2>&1)
    [ "$v" = 1.1 ] && ok "curl: the server's ALPN order decides (http/1.1 first)" || bad "curl alpn order: $v"
else
    skipped="$skipped curl(http2)"
fi

# ------------------------------------------------------------------------------------------------------- Go
if have go; then
    echo "== Go ($(go version | cut -d' ' -f3))"
    go build -o "$WORK/h2_go" tools/h2_interop.go 2>"$WORK/err" || { cat "$WORK/err"; exit 2; }
    for opts in "" "fragment=100" "rekey=5" "suite=chacha group=p256" "suite=aes256 tickets=0"; do
        start_server $opts
        if timeout 120 "$WORK/h2_go" -ca "$CA" -addr "127.0.0.1:$PORT" $NOPUSH_GO > "$WORK/go.out" 2>&1; then
            ok "go net/http HTTP/2 client with [$opts] ($(grep -c '^ok' "$WORK/go.out") checks)"
        else
            echo "---- go output"; cat "$WORK/go.out"; bad "go with [$opts]"
        fi
    done
else
    skipped="$skipped go"
fi

# --------------------------------------------------------------------------------------------------- Python
if have python3 && python3 -c 'import h2.connection' 2>/dev/null; then
    echo "== python-h2 ($(python3 -c 'import h2; print(h2.__version__)'))"
    for opts in "" "fragment=100" "rekey=5"; do
        start_server $opts
        if timeout 120 python3 tools/h2_interop.py --ca "$CA" --addr "127.0.0.1:$PORT" $NOPUSH_PY > "$WORK/py.out" 2>&1; then
            ok "python-h2 client with [$opts] ($(grep -c '^ok' "$WORK/py.out") checks)"
        else
            echo "---- python output"; cat "$WORK/py.out"; bad "python-h2 with [$opts]"
        fi
    done
else
    skipped="$skipped python-h2"
fi
done

# --------------------------------------------------------------------------------------------------- h2spec
# The HTTP/2 conformance suite (github.com/summerwind/h2spec), against the production server over plain TCP with prior
# knowledge (h2spec's client offers only TLS 1.2, and the server speaks TLS 1.3), in its normal and its strict mode.
H2SPEC=${H2SPEC:-$(command -v h2spec || true)}
MODE=production
if [ -n "$H2SPEC" ] && [ -x "$H2SPEC" ]; then
    echo "== h2spec ($("$H2SPEC" --version 2>&1 | head -1))"
    for strict in "" "--strict"; do
        start_server plain=h2
        out=$(timeout 170 "$H2SPEC" -h 127.0.0.1 -p "$PORT" -o 3 $strict 2>&1 | tail -1)
        case $out in
            *" 0 failed") ok "h2spec $strict: $out" ;;
            *) bad "h2spec $strict: $out" ;;
        esac
    done
else
    skipped="$skipped h2spec"
fi

echo
echo "$passed checks passed"
[ -n "$skipped" ] && echo "skipped (not installed):$skipped"
[ "$fail" = 0 ] && echo "h2 interop: PASS" || echo "h2 interop: FAIL"
exit $fail
