#!/bin/sh
# Checks pratique's TLS server against clients that are not ours: openssl s_client, curl and a Go program
# (tools/server_interop.go, crypto/tls and net/http). Each check starts the `serve` example with some settings,
# connects, and compares what came back, byte for byte, with what the server must have sent.
#
#   sh tools/server_interop.sh            all the checks that the installed tools allow (skips the others)
#   RELEASE=1 sh tools/server_interop.sh  build with --release first
#
# The server is the example in examples/serve.rs (feature `server`; experimental, for tests).
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

# start_server OPTION... : starts the example; sets PORT and CA
start_server() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    : > "$WORK/log"
    "$SERVE" ca="$WORK/root.pem" "$@" > "$WORK/log" 2>&1 &
    SERVER_PID=$!
    n=0
    while ! grep -q '^listening' "$WORK/log"; do
        n=$((n + 1)); [ $n -gt 100 ] && { echo "the server did not start"; cat "$WORK/log"; exit 2; }
        sleep 0.1
    done
    PORT=$(sed -n 's/^listening 127.0.0.1:\([0-9]*\).*/\1/p' "$WORK/log")
    CA="$WORK/root.pem"
}

ok() { passed=$((passed + 1)); echo "ok   $*"; }
bad() { fail=1; echo "FAIL $*"; echo "---- server log"; sed 's/^/     /' "$WORK/log"; echo "----"; }

# --------------------------------------------------------------------------------------------------- openssl
if have openssl; then
    echo "== openssl s_client ($(openssl version))"
    # request PATH EXPECTED_BYTES: one request, with the server closing at the end
    s_client() {
        path=$1
        shift
        printf 'GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' "$path" |
            timeout 30 openssl s_client -connect "127.0.0.1:$PORT" -CAfile "$CA" -servername localhost \
                -verify_return_error -verify_hostname localhost -ign_eof "$@" 2>&1
    }
    for suite in aes128 aes256 chacha; do
        for group in x25519 p256 p384; do
            case $suite in
                aes128) name=TLS_AES_128_GCM_SHA256 ;;
                aes256) name=TLS_AES_256_GCM_SHA384 ;;
                chacha) name=TLS_CHACHA20_POLY1305_SHA256 ;;
            esac
            start_server suite=$suite group=$group
            out=$(s_client /size/70000 -alpn http/1.1 -quiet | tr -d '\r' | sed -n '/^abc/,$p' | tr -d '\n')
            want=$(python3 -c "print(''.join(chr(97+i%26) for i in range(70000)),end='')")
            full=$(s_client /size/10 -alpn http/1.1)
            if [ "$out" = "$want" ] && echo "$full" | grep -q "Cipher is $name" && echo "$full" | grep -q "Verification: OK"; then
                ok "openssl $suite/$group: 70000 bytes, $name, verified"
            else
                bad "openssl $suite/$group"
            fi
        done
    done
    # records of one byte, a hundred bytes, tickets before and after the data, key updates
    for opts in "fragment=1" "fragment=100" "tickets=0" "tickets=3" "tickets=2 late_tickets=1" "rekey=3" "alpn=http/1.1,h2"; do
        start_server $opts
        out=$(s_client /size/3000 -quiet -alpn http/1.1 | tr -d '\r' | sed -n '/^abc/,$p' | tr -d '\n')
        want=$(python3 -c "print(''.join(chr(97+i%26) for i in range(3000)),end='')")
        if [ "$out" = "$want" ]; then ok "openssl with $opts"; else bad "openssl with $opts"; fi
    done
    # the root is not trusted: s_client must refuse
    start_server
    if printf 'x' | timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost -verify_return_error \
        -CAfile /dev/null > "$WORK/out" 2>&1; then bad "openssl accepted a root it does not trust"; else ok "openssl refuses a root it does not trust"; fi
    # TLS 1.2 only: refused with protocol_version
    if printf 'x' | timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -tls1_2 -CAfile "$CA" > "$WORK/out" 2>&1; then
        bad "a TLS 1.2 handshake succeeded"
    else
        grep -qi "alert protocol version\|protocol version\|no protocols available\|wrong version" "$WORK/out" && ok "openssl -tls1_2 is refused (protocol_version)" || bad "openssl -tls1_2: $(tail -3 "$WORK/out")"
    fi
else
    skipped="$skipped openssl"
fi

# --------------------------------------------------------------------------------------------------- curl
if have curl; then
    echo "== curl ($(curl --version | head -1 | cut -d' ' -f1-2))"
    start_server
    out=$(curl -sS --http1.1 --cacert "$CA" --resolve "localhost:$PORT:127.0.0.1" \
        "https://localhost:$PORT/size/100000" "https://localhost:$PORT/size/0" "https://localhost:$PORT/chunked/7000" \
        -o "$WORK/a" -o "$WORK/b" -o "$WORK/c" -w '%{http_code} %{size_download} %{num_connects}\n' 2>&1 | tr '\n' ';')
    if [ "$out" = "200 100000 1;200 0 0;200 7000 0;" ] && [ "$(wc -c < "$WORK/a")" = 100000 ]; then
        ok "curl: three requests on one connection ($out)"
    else
        bad "curl keep-alive: $out"
    fi
    head -c 300000 /dev/urandom > "$WORK/payload"
    curl -sS --http1.1 --cacert "$CA" --resolve "localhost:$PORT:127.0.0.1" --data-binary "@$WORK/payload" \
        "https://localhost:$PORT/echo" -o "$WORK/echoed" 2>"$WORK/err"
    if cmp -s "$WORK/payload" "$WORK/echoed"; then ok "curl: a 300000-byte POST comes back unchanged"; else bad "curl POST"; fi
    # the same by IP address (the certificate has IP names too)
    code=$(curl -sS --http1.1 --cacert "$CA" "https://127.0.0.1:$PORT/size/5" -o /dev/null -w '%{http_code}' 2>&1)
    [ "$code" = 200 ] && ok "curl by IP address" || bad "curl by IP address: $code"
    # a root it does not know (the system's roots, not ours): curl exit code 60
    curl -sS --http1.1 "https://localhost:$PORT/" --resolve "localhost:$PORT:127.0.0.1" -o /dev/null 2>/dev/null
    [ $? = 60 ] && ok "curl refuses a root it does not trust (exit 60)" || bad "curl accepted an untrusted root"
    # HTTP/2 is offered by curl; a server that picks no ALPN protocol gets HTTP/1.1
    start_server alpn=http/1.1
    v=$(curl -sS --http2 --cacert "$CA" "https://127.0.0.1:$PORT/size/5" -o /dev/null -w '%{http_version}' 2>&1)
    [ "$v" = 1.1 ] && ok "curl --http2 falls back to HTTP/1.1 when the server picks http/1.1" || bad "curl --http2: $v"
    for suite in aes128 aes256 chacha; do
        start_server suite=$suite fragment=777
        code=$(curl -sS --http1.1 --cacert "$CA" "https://127.0.0.1:$PORT/size/200000" -o "$WORK/a" -w '%{http_code} %{size_download}' 2>&1)
        [ "$code" = "200 200000" ] && ok "curl $suite with records of 777 bytes" || bad "curl $suite: $code"
    done
else
    skipped="$skipped curl"
fi

# --------------------------------------------------------------------------------------------------- Go
if have go; then
    echo "== Go ($(go version | cut -d' ' -f3))"
    go build -o "$WORK/interop_go" tools/server_interop.go 2>"$WORK/err" || { cat "$WORK/err"; exit 2; }
    for config in "suite=aes128:TLS_AES_128_GCM_SHA256" "suite=aes256:TLS_AES_256_GCM_SHA384" "suite=chacha:TLS_CHACHA20_POLY1305_SHA256" \
                  "group=p256:" "group=p384:" "fragment=100:" "rekey=5:" "tickets=0:" "tickets=3 late_tickets=1:"; do
        opts=${config%%:*}; want=${config#*:}
        start_server $opts
        if "$WORK/interop_go" -ca "$CA" -addr "127.0.0.1:$PORT" -suite "$want" > "$WORK/go.out" 2>&1; then
            ok "go with $opts ($(grep -c '^ok' "$WORK/go.out") checks)"
        else
            echo "---- go output"; cat "$WORK/go.out"; bad "go with $opts"
        fi
    done
    start_server alpn=http/1.1,h2
    if "$WORK/interop_go" -ca "$CA" -addr "127.0.0.1:$PORT" -alpn http/1.1 > "$WORK/go.out" 2>&1; then ok "go with ALPN http/1.1"; else cat "$WORK/go.out"; bad "go with ALPN"; fi
else
    skipped="$skipped go"
fi

echo
echo "$passed checks passed"
[ -n "$skipped" ] && echo "skipped (not installed):$skipped"
[ "$fail" = 0 ] && echo "server interop: PASS" || echo "server interop: FAIL"
exit $fail
