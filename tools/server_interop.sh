#!/bin/sh
# Checks pratique's TLS server against clients that are not ours: openssl s_client, curl, headless Chromium
# (tools/server_interop_browser.py, through Playwright) and a Go program (tools/server_interop.go, crypto/tls and
# net/http). Each check starts the `serve` example with some settings,
# connects, and compares what came back, byte for byte, with what the server must have sent.
#
#   sh tools/server_interop.sh            all the checks that the installed tools allow (skips the others)
#   RELEASE=1 sh tools/server_interop.sh  build with --release first
#
# The server is the example in examples/serve.rs (feature `server`).
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
    # the server's key: the throwaway certificate with each kind the server makes (B-109)
    for kt in ed25519:Ed25519 p256:ECDSA p384:ECDSA; do
        start_server keytype=${kt%%:*}
        full=$(s_client /size/10 -alpn http/1.1)
        if echo "$full" | grep -q "Verification: OK" && echo "$full" | grep -qi "Peer signature type: ${kt#*:}"; then
            ok "openssl, server key ${kt%%:*}: verified, $(echo "$full" | grep -i 'Peer signature type' | head -1 | tr -d '\r')"
        else
            bad "openssl, server key ${kt%%:*}"
        fi
    done
    # certificates and keys OpenSSL made, in each of the PEM formats it writes: served from the files
    SAN="subjectAltName=DNS:localhost,IP:127.0.0.1"
    for kind in rsa2048-pkcs8 rsa3072-pkcs1 rsa4096-pkcs8 p256-sec1 p384-pkcs8 ed25519-pkcs8; do
        k="$WORK/$kind.key"
        case $kind in
            rsa2048-pkcs8) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$k" 2>/dev/null; sig=RSA-PSS ;;
            rsa3072-pkcs1) openssl genrsa -traditional -out "$k" 3072 2>/dev/null || openssl genrsa -out "$k" 3072 2>/dev/null; sig=RSA-PSS ;;
            rsa4096-pkcs8) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$k" 2>/dev/null; sig=RSA-PSS ;;
            p256-sec1) openssl ecparam -name prime256v1 -genkey -out "$k" 2>/dev/null; sig=ECDSA ;;
            p384-pkcs8) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$k" 2>/dev/null; sig=ECDSA ;;
            ed25519-pkcs8) openssl genpkey -algorithm ED25519 -out "$k" 2>/dev/null; sig=Ed25519 ;;
        esac
        openssl req -x509 -key "$k" -out "$WORK/$kind.crt" -days 2 -subj /CN=localhost -addext "$SAN" 2>/dev/null
        label=$(sed -n 's/^-----BEGIN \(.*\)-----$/\1/p' "$k" | tr '\n' '+' | sed 's/+$//')
        start_server certfile="$WORK/$kind.crt" keyfile="$k"
        CA="$WORK/$kind.crt"
        full=$(s_client /size/10 -alpn http/1.1)
        if echo "$full" | grep -q "Verification: OK" && echo "$full" | grep -qi "Peer signature type: $sig"; then
            ok "openssl, a $kind key from OpenSSL ($label): verified, $sig"
        else
            bad "openssl, a $kind key from OpenSSL ($label)"
        fi
    done
    # a key that is not the certificate's: the server must not start
    if "$SERVE" certfile="$WORK/p256-sec1.crt" keyfile="$WORK/p384-pkcs8.key" > "$WORK/mismatch" 2>&1; then
        bad "the server started with a key that is not its certificate's"
    else
        grep -q "not the key of the first certificate" "$WORK/mismatch" && ok "a key that is not the certificate's is refused at start" || bad "mismatched key: $(tail -2 "$WORK/mismatch")"
    fi
    # SNI picks the certificate (B-110): a second certificate under the same root for second.localhost
    start_server names2=second.localhost,second.test
    out=$(printf 'GET /size/3 HTTP/1.1\r\nHost: second.localhost\r\nConnection: close\r\n\r\n' |
        timeout 30 openssl s_client -connect "127.0.0.1:$PORT" -CAfile "$CA" -servername second.localhost \
            -verify_return_error -verify_hostname second.localhost -ign_eof 2>&1)
    if echo "$out" | grep -q "Verification: OK" && echo "$out" | grep -qi "subject=.*second.localhost"; then
        ok "openssl: SNI second.localhost gets the second certificate, verified for that name"
    else
        bad "openssl SNI: $(echo "$out" | grep -i 'subject=\|verif' | head -3)"
    fi
    # session resumption from a ticket (stateless tickets under the server's ticket keys)
    start_server
    s_client /size/3 -sess_out "$WORK/sess" > /dev/null
    out=$(s_client /size/3 -sess_in "$WORK/sess")
    if echo "$out" | grep -q "Reused, TLSv1.3" && grep -q "resumed true" "$WORK/log"; then
        ok "openssl resumes a session from the server's ticket"
    else
        bad "openssl resumption: $(echo "$out" | grep -i 'reused\|new,' | head -2)"
    fi
    # client certificates (mutual TLS): a client CA and certificates under it, made by OpenSSL
    printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign\n' > "$WORK/ca.ext"
    printf 'extendedKeyUsage=clientAuth\n' > "$WORK/client.ext"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/cca.key" -out "$WORK/cca.pem" \
        -subj /CN=interop-client-ca -days 2 -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign 2>/dev/null
    for ck in p256 rsa2048; do
        case $ck in
            p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/c-$ck.key" 2>/dev/null ;;
            rsa2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/c-$ck.key" 2>/dev/null ;;
        esac
        openssl req -new -key "$WORK/c-$ck.key" -subj "/CN=interop-client-$ck" -out "$WORK/c-$ck.csr" 2>/dev/null
        openssl x509 -req -in "$WORK/c-$ck.csr" -CA "$WORK/cca.pem" -CAkey "$WORK/cca.key" -CAcreateserial -days 2 \
            -extfile "$WORK/client.ext" -out "$WORK/c-$ck.pem" 2>/dev/null
    done
    start_server clientca="$WORK/cca.pem"
    for ck in p256 rsa2048; do
        out=$(s_client /size/3 -cert "$WORK/c-$ck.pem" -key "$WORK/c-$ck.key")
        if echo "$out" | grep -q "Verification: OK" && grep -q "client certificates 1" "$WORK/log"; then
            ok "openssl presents a $ck client certificate; the server checks it and sees it"
        else
            bad "openssl client certificate $ck"
        fi
    done
    out=$(s_client /size/3)
    if echo "$out" | grep -qi "certificate required"; then ok "openssl without a client certificate is refused (certificate_required)"; else bad "openssl without a client certificate: $(echo "$out" | grep -i alert | head -2)"; fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/stranger.key" -out "$WORK/stranger.pem" -subj /CN=stranger -days 2 -addext extendedKeyUsage=clientAuth 2>/dev/null
    out=$(s_client /size/3 -cert "$WORK/stranger.pem" -key "$WORK/stranger.key")
    if echo "$out" | grep -qi "bad certificate"; then ok "openssl with a certificate from another CA is refused (bad_certificate)"; else bad "openssl stranger certificate: $(echo "$out" | grep -i alert | head -2)"; fi
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
    # a client certificate with curl (the files of the openssl section, if it ran)
    if [ -f "$WORK/c-p256.pem" ]; then
        start_server clientca="$WORK/cca.pem"
        code=$(curl -sS --http1.1 --cacert "$CA" --cert "$WORK/c-p256.pem" --key "$WORK/c-p256.key" "https://127.0.0.1:$PORT/size/5" -o /dev/null -w '%{http_code}' 2>&1)
        [ "$code" = 200 ] && grep -q "client certificates 1" "$WORK/log" && ok "curl presents a client certificate" || bad "curl client certificate: $code"
        code=$(curl -sS --http1.1 --cacert "$CA" "https://127.0.0.1:$PORT/size/5" -o /dev/null -w '%{http_code}' 2>&1)
        [ "$code" != 200 ] && ok "curl without a client certificate is refused" || bad "curl without a client certificate got 200"
    fi
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

# --------------------------------------------------------------------------------------------------- Chromium
# Headless Chromium through Playwright, trusting the test root through its NSS database (a throwaway $HOME), so it
# verifies the server as it would any site. Browsers take no Ed25519 in a chain, hence rootkey=p256.
if have certutil && python3 -c 'import playwright.sync_api' 2>/dev/null; then
    echo "== Chromium ($(python3 -c 'from playwright.sync_api import sync_playwright as s; p=s().start(); b=p.chromium.launch(); print(b.version); b.close(); p.stop()' 2>/dev/null))"
    # chromium_trust FILE: a fresh NSS database that trusts the certificate in FILE
    chromium_trust() {
        rm -rf "$WORK/home"; mkdir -p "$WORK/home/.pki/nssdb"
        certutil -N -d "sql:$WORK/home/.pki/nssdb" --empty-password &&
            certutil -A -a -d "sql:$WORK/home/.pki/nssdb" -t "C,," -n "pratique interop" -i "$1"
    }
    # chromium URL BYTES...: loads each page in a new connection; the output is one line per page
    chromium() { HOME="$WORK/home" timeout 45 python3 -I tools/server_interop_browser.py "$@" 2>&1; }

    start_server keytype=p256 rootkey=p256 alpn=h2,http/1.1
    rm -rf "$WORK/home"; mkdir -p "$WORK/home"
    out=$(chromium "https://localhost:$PORT/size/10" 10)
    echo "$out" | grep -q ERR_CERT_AUTHORITY_INVALID && ok "chromium refuses a root it does not trust" || bad "chromium, untrusted root: $out"
    chromium_trust "$CA"
    out=$(chromium "https://localhost:$PORT/size/100000" 100000 "https://127.0.0.1:$PORT/size/7000" 7000)
    [ "$(echo "$out" | tr '\n' ';')" = "ok h2 100000;ok h2 7000;" ] && ok "chromium over HTTP/2, by name and by IP address" || bad "chromium h2: $out"
    for opts in suite=aes256 suite=chacha "group=p256" "group=p384" "fragment=100" "rekey=3" "alpn=http/1.1"; do
        start_server keytype=p256 rootkey=p256 alpn=h2,http/1.1 $opts
        chromium_trust "$CA"
        want=h2; [ "$opts" = alpn=http/1.1 ] && want=http/1.1
        out=$(chromium "https://localhost:$PORT/size/70000" 70000)
        what=$opts; case $opts in group=*) what="$opts (a HelloRetryRequest: Chromium sends X25519 shares)" ;; esac
        [ "$out" = "ok $want 70000" ] && ok "chromium with $what" || bad "chromium with $opts: $out"
    done
    # P-384 and RSA certificates (RSA from the OpenSSL section, if it ran)
    start_server keytype=p384 rootkey=p384 alpn=h2
    chromium_trust "$CA"
    out=$(chromium "https://localhost:$PORT/size/5000" 5000)
    [ "$out" = "ok h2 5000" ] && ok "chromium, P-384 leaf and root" || bad "chromium p384: $out"
    if [ -f "$WORK/rsa2048-pkcs8.crt" ]; then
        start_server certfile="$WORK/rsa2048-pkcs8.crt" keyfile="$WORK/rsa2048-pkcs8.key" alpn=h2
        chromium_trust "$WORK/rsa2048-pkcs8.crt"
        out=$(chromium "https://localhost:$PORT/size/5000" 5000)
        [ "$out" = "ok h2 5000" ] && ok "chromium, an RSA-2048 certificate and key from OpenSSL (RSA-PSS)" || bad "chromium rsa: $out"
    fi
    # Chromium signs nothing with Ed25519: a server with only an Ed25519 key says so; with a P-256 certificate
    # for the same name next to it, Chromium gets that one (the store picks by what the client verifies)
    start_server keytype=ed25519 rootkey=p256 alpn=h2
    chromium_trust "$CA"
    out=$(chromium "https://localhost:$PORT/size/10" 10)
    case $out in error*) grep -q "no certificate whose signatures" "$WORK/log" && ok "chromium and an Ed25519-only server: refused, the server says why" || bad "chromium ed25519: server log" ;; *) bad "chromium ed25519 only: $out" ;; esac
    start_server keytype=ed25519 rootkey=p256 alpn=h2 names2=localhost
    chromium_trust "$CA"
    out=$(chromium "https://localhost:$PORT/size/10" 10)
    [ "$out" = "ok h2 10" ] && ok "chromium gets the P-256 certificate of a name that also has an Ed25519 one" || bad "chromium two certificates: $out"
else
    skipped="$skipped chromium"
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
