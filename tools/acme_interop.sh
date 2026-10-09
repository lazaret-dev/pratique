#!/usr/bin/env bash
# ACME interop (B-113): examples/acme_serve getting, serving and reloading certificates from Pebble, Let's Encrypt's
# test CA (https://github.com/letsencrypt/pebble, the same API as Let's Encrypt's own Boulder, stricter in places), with
# each challenge validated by Pebble for real: TLS-ALPN-01 and HTTP-01 against the example's own listeners, DNS-01
# through tools/acme_dns.py (Pebble's DNS, and the example's hook). Pebble refuses a share of the nonces on purpose, and
# reuses some authorizations, so those paths are taken too. Then: IP addresses, a certificate profile, the state
# directory (a restart loads, and orders nothing), renewal information, external account binding (a second Pebble
# that requires it), and a CA that has never seen the saved account key (Pebble restarted).
#
#   PEBBLE=/path/to/pebble tools/acme_interop.sh
#
# Needs openssl, curl and python3. Uses the ports 14000, 14001, 15000, 15001 (Pebble), 5001 and 5002 (the example) and
# 8053 (DNS) on 127.0.0.1, and 5001 and 5002 on 127.0.0.2.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PEBBLE=${PEBBLE:?set PEBBLE to the pebble binary}
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build --release --features server --example acme_serve 2>&1 | tail -1)
  BIN=$ROOT/target/release/examples/acme_serve
fi
W=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
pass=0
fail=0
check() {
  if eval "$2"; then echo "ok   $1"; pass=$((pass + 1)); else echo "FAIL $1"; fail=$((fail + 1)); fi
}

# Pebble's own HTTPS certificate, under a CA of ours that the example is told to trust (ca_file=)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/api-ca.key" -out "$W/api-ca.pem" -days 2 \
  -subj /CN=pebble-api-ca -addext basicConstraints=critical,CA:true 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/api.key" -out "$W/api.csr" -subj /CN=localhost 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$W/api.ext"
openssl x509 -req -in "$W/api.csr" -CA "$W/api-ca.pem" -CAkey "$W/api-ca.key" -CAcreateserial -days 2 -extfile "$W/api.ext" -out "$W/api.pem" 2>/dev/null

python3 "$ROOT/tools/acme_dns.py" serve "$W/records.json" 127.0.0.1 8053 > "$W/dns.log" 2>&1 &
PIDS+=($!)
printf '#!/bin/sh\nexec python3 %s hook %s "$@"\n' "$ROOT/tools/acme_dns.py" "$W/records.json" > "$W/hook.sh"
chmod +x "$W/hook.sh"

pebble() { # name port management-port extra-config
  cat > "$W/$1.json" <<EOF
{"pebble": {"listenAddress": "127.0.0.1:$2", "managementListenAddress": "127.0.0.1:$3",
  "certificate": "$W/api.pem", "privateKey": "$W/api.key", "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "",
  "retryAfter": {"authz": 1, "order": 1},
  "profiles": {"default": {"description": "the usual", "validityPeriod": 7776000},
               "shortlived": {"description": "six days", "validityPeriod": 518400}}$4}}
EOF
  PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=20 PEBBLE_AUTHZREUSE=50 "$PEBBLE" -config "$W/$1.json" -dnsserver 127.0.0.1:8053 > "$W/$1.log" 2>&1 &
  LAST_PEBBLE=$!
  PIDS+=($!)
  for _ in $(seq 1 100); do grep -q "Listening on: 127.0.0.1:$2" "$W/$1.log" && return 0; sleep 0.1; done
  echo "Pebble did not start:"; cat "$W/$1.log"; exit 1
}
pebble pebble 14000 15000 ""
MAIN_PEBBLE=$LAST_PEBBLE
pebble pebble-eab 14001 15001 ', "externalAccountBindingRequired": true, "externalAccountMACKeys": {"kid-1": "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}'
curl -s --noproxy "*" --cacert "$W/api-ca.pem" https://127.0.0.1:15000/roots/0 > "$W/root.pem"
check "Pebble's issuing root" 'grep -q "BEGIN CERTIFICATE" "$W/root.pem"'

SPID=
# serve LABEL N ARGS...: runs the example until N certificates are got or loaded (or one fails); it keeps running
serve() {
  local label=$1 want=$2
  shift 2
  "$BIN" directory=https://127.0.0.1:14000/dir ca_file="$W/api-ca.pem" state="$W/state" https=127.0.0.1:5001 http=127.0.0.1:5002 \
    contact=mailto:admin@example.test "$@" > "$W/$label.log" 2>&1 &
  SPID=$!
  for _ in $(seq 1 400); do
    [ "$(grep -cE '^acme: certificate for .* (obtained|loaded from|renewed)' "$W/$label.log")" -ge "$want" ] && return 0
    grep -q 'trying again at' "$W/$label.log" && break
    kill -0 "$SPID" 2>/dev/null || break
    sleep 0.1
  done
  echo "  --- $label:"; sed 's/^/  /' "$W/$label.log"
  return 1
}
stop() { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; }
fetch() { # NAME [curl options]: the page over HTTPS from the example, trusting Pebble's root
  local name=$1
  shift
  curl -s --noproxy "*" --max-time 5 --cacert "$W/root.pem" --resolve "$name:5001:127.0.0.1" "$@" "https://$name:5001/"
}

check "tls-alpn-01: a.test and b.test" 'serve alpn 1 names=a.test,b.test challenges=tls-alpn-01'
check "the certificate is served (HTTP/2) and Pebble's root verifies it" 'fetch b.test --http2 | grep -q "hello from b.test over Http2"'
check "and over HTTP/1.1" 'fetch a.test --http1.1 | grep -q "hello from a.test over Http11"'
check "the chain is the leaf and Pebble's intermediate" \
  'echo | openssl s_client -connect 127.0.0.1:5001 -servername a.test -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE" | grep -qx 2'
check "renewal information (ARI): the renewal is set in Pebble's window" 'sleep 1; grep -q "in the CA.s window" "$W/alpn.log" && ! grep -q "renewal information for" "$W/alpn.log"'
stop

check "http-01: c.test" 'serve http 1 names=c.test challenges=http-01'
check "the certificate is served" 'fetch c.test | grep -q "hello from c.test"'
check "the plain listener sends the rest to HTTPS" \
  '[ "$(curl -s --noproxy "*" -o /dev/null -w "%{http_code} %{redirect_url}" -H "Host: c.test" http://127.0.0.1:5002/x?y)" = "301 https://c.test:5001/x?y" ]'
stop

check "dns-01: *.w.test and w.test" 'serve dns 1 "names=*.w.test,w.test" challenges=dns-01 dns01_cmd=$W/hook.sh'
check "the wildcard certificate is served" 'fetch x.w.test | grep -q "hello from x.w.test"'
check "the TXT records were taken back" '[ "$(cat "$W/records.json")" = "{}" ]'
stop

check "an IP address with http-01" 'serve ip 1 names=127.0.0.1 challenges=http-01'
check "the certificate is served for it" 'curl -s --noproxy "*" --max-time 5 --cacert "$W/root.pem" https://127.0.0.1:5001/ | grep -q "hello from  over"'
stop

check "an IP address with tls-alpn-01" 'serve ip2 1 names=127.0.0.2 challenges=tls-alpn-01 https=127.0.0.2:5001 http=127.0.0.2:5002'
stop

check "the shortlived profile" 'serve short 1 names=s.test profile=shortlived'
check "a six-day certificate" '
  dates=$(echo | openssl s_client -connect 127.0.0.1:5001 -servername s.test 2>/dev/null | openssl x509 -noout -startdate -enddate)
  start=$(date -d "$(echo "$dates" | sed -n "s/notBefore=//p")" +%s); end=$(date -d "$(echo "$dates" | sed -n "s/notAfter=//p")" +%s)
  [ $((end - start)) -le 518400 ] && [ $((end - start)) -ge 518000 ]'
stop

check "a restart loads the saved certificates (two at once)" 'serve again 2 "names=a.test,b.test;c.test"'
check "and orders nothing" 'sleep 1; ! grep -qE "obtained|renewed" "$W/again.log"'
check "the first set is the default certificate" 'fetch a.test | grep -q "hello from a.test"'
stop

check "a CA that requires external account binding refuses an account without it" '
  ! timeout 30 "$BIN" directory=https://127.0.0.1:14001/dir ca_file="$W/api-ca.pem" state="$W/state-eab" https=127.0.0.1:5001 \
    http=127.0.0.1:5002 names=e.test challenges=http-01 once=1 > "$W/eab-none.log" 2>&1 && grep -q "external account binding" "$W/eab-none.log"'
check "and takes one with it" '
  timeout 30 "$BIN" directory=https://127.0.0.1:14001/dir ca_file="$W/api-ca.pem" state="$W/state-eab" https=127.0.0.1:5001 \
    http=127.0.0.1:5002 names=e.test challenges=http-01 once=1 eab_kid=kid-1 \
    eab_key=zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W > "$W/eab.log" 2>&1 && grep -q "^saved " "$W/eab.log"'

# Pebble keeps its accounts in memory: a new one has never heard of the account the client saved
kill "$MAIN_PEBBLE"
wait "$MAIN_PEBBLE" 2>/dev/null
pebble pebble 14000 15000 ""
check "a CA that has never seen the saved account key: the account made again, the certificate got" 'serve lost 1 names=f.test challenges=http-01'
stop

check "the account key and certificate keys are the owner's alone" '
  [ "$(find "$W/state" -name "*.pem" -path "*key*" -perm -o=r | wc -l)" = 0 ] && [ "$(stat -c %a "$W"/state/*/account.key)" = 600 ]'

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
