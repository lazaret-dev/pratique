#!/usr/bin/env bash
# tlsfuzzer against the TLS 1.3 server (B-114): every test-tls13-* script of tlsfuzzer
# (https://github.com/tlsfuzzer/tlsfuzzer, the conformance suite of Red Hat's TLS libraries) against examples/serve, each
# alone against a fresh server, with the certificates, client certificates and options it needs. The tests a script has
# for what this server does not do (FFDHE, X448, P-521 key exchange, AES-CCM, TLS 1.2, external PSKs, post-handshake
# authentication, ...) are named below with the reason, and only those may fail; scripts that are about such a feature
# alone are skipped, with the reason. Anything else that fails is a failure of this run.
#
#   TLSFUZZER=/path/to/tlsfuzzer [PYTHON=python3] tools/tlsfuzzer.sh [test-tls13-NAME ...]
#
# Needs a checkout of tlsfuzzer, a Python with tlslite-ng and ecdsa (tlsfuzzer's master wants a pre-release tlslite-ng:
# `pip install --pre tlslite-ng ecdsa`), and openssl. Uses port 4433 on 127.0.0.1 (PORT= to change it). Each script runs
# within 40 seconds.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TF=$(cd "${TLSFUZZER:?set TLSFUZZER to a tlsfuzzer checkout}" && pwd)
PY=${PYTHON:-python3}
PORT=${PORT:-4433}
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build --release --features server --example serve 2>&1 | tail -1)
  BIN=$ROOT/target/release/examples/serve
fi
W=$(mktemp -d)
SERVER=
cleanup() { [ -n "$SERVER" ] && kill -9 "$SERVER" 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

# the server's certificates (one key each: RSA, P-256, P-384, Ed25519) and a client CA with an RSA, a P-256 and an
# Ed25519 client certificate
leaf() { # NAME, genpkey arguments...
  local n=$1; shift
  openssl genpkey "$@" -out "$W/$n.key" 2>/dev/null
  openssl req -new -x509 -key "$W/$n.key" -out "$W/$n.pem" -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null
}
leaf rsa -algorithm rsa -pkeyopt rsa_keygen_bits:2048
leaf p256 -algorithm ec -pkeyopt ec_paramgen_curve:P-256
leaf p384 -algorithm ec -pkeyopt ec_paramgen_curve:P-384
leaf ed25519 -algorithm ed25519
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/client-ca.key" -out "$W/client-ca.pem" -days 2 -subj "/CN=tlsfuzzer client CA" \
  -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign 2>/dev/null
printf 'basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$W/client.ext"
client() { # NAME, genpkey arguments...
  local n=$1; shift
  openssl genpkey "$@" -out "$W/client-$n.key" 2>/dev/null
  openssl req -new -key "$W/client-$n.key" -out "$W/client-$n.csr" -subj "/CN=tlsfuzzer client $n" 2>/dev/null
  openssl x509 -req -in "$W/client-$n.csr" -CA "$W/client-ca.pem" -CAkey "$W/client-ca.key" -CAcreateserial -days 2 \
    -extfile "$W/client.ext" -out "$W/client-$n.pem" 2>/dev/null
}
client rsa -algorithm rsa -pkeyopt rsa_keygen_bits:2048
client p256 -algorithm ec -pkeyopt ec_paramgen_curve:P-256
client ed25519 -algorithm ed25519
# what the server's CertificateRequest offers (CLIENT_SIGNATURE_SCHEMES)
SIGALGS="ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512 ed25519 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512"
CLIENTAUTH="clientca=$W/client-ca.pem clientauth=optional"

# script ; server key, or "skip" ; server options ; script arguments ; tests that may fail (an extended regular expression
# over the test's name) ; why
TABLE=$(cat <<'EOF'
0rtt-garbage ; rsa ; ; ; downgrade to TLS 1\.2 ; TLS 1.3 only (B-116)
ccs ; rsa ; ; ; ;
certificate-compression ; skip ; ; ; ; certificate compression (RFC 8879) is not supported
certificate-request ; rsa ; $CLIENTAUTH ; -k $W/client-rsa.key -c $W/client-rsa.pem -s "$SIGALGS" ; ;
certificate-verify ; rsa ; $CLIENTAUTH ; -k $W/client-rsa.key -c $W/client-rsa.pem -s "$SIGALGS" ; ;
client-certificate-compression ; skip ; ; ; ; certificate compression (RFC 8879) is not supported
connection-abort ; rsa ; ; ; ;
conversation ; rsa ; ; ; ;
count-tickets ; rsa ; ; -t 1 ; ;
crfg-curves ; rsa ; ; ; x448 ; X448 key exchange is not offered
dhe-shared-secret-padding ; skip ; ; ; ; FFDHE key exchange is not offered
ecdhe-brainpool-curves ; skip ; ; ; ; brainpool curves are not offered
ecdhe-curves ; rsa ; ; ; secp521r1|x448 ; P-521 and X448 key exchange are not offered
ecdsa-brainpool-in-certificate-verify ; skip ; ; ; ; brainpool curves are not taken
ecdsa-in-certificate-verify ; rsa ; $CLIENTAUTH ; -k $W/client-p256.key -c $W/client-p256.pem -s "$SIGALGS" ; ;
ecdsa-support ; p256 ; ; ; brainpool|secp384r1|secp521r1 ; the key is P-256: only its scheme can sign
ecdsa-support ; p384 ; ; ; brainpool|secp256r1|secp521r1 ; the key is P-384: only its scheme can sign
eddsa-in-certificate-verify ; rsa ; $CLIENTAUTH ; -k $W/client-ed25519.key -c $W/client-ed25519.pem -s "$SIGALGS" ; ;
eddsa ; ed25519 ; ; ; ed448 ; Ed448 is not supported
empty-alert ; rsa ; ; ; ;
ffdhe-groups ; skip ; ; ; ; FFDHE key exchange is not offered
ffdhe-sanity ; skip ; ; ; ; FFDHE key exchange is not offered
finished-plaintext ; rsa ; ; ; ;
finished ; rsa ; ; -e "padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16777183" -e "padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16777167" ; ;
hrr ; rsa ; ; ; ;
invalid-ciphers ; rsa ; ; ; ;
keyshare-omitted ; rsa ; ; ; ;
keyupdate-from-server ; skip ; ; ; ; needs a server that sends a KeyUpdate when asked (GET /keyupdate); the server's own rotation is in the unit tests
keyupdate ; rsa ; ; ; ;
large-number-of-extensions ; rsa ; ; ; ;
legacy-version ; rsa ; ; ; ;
lengths ; skip ; ; ; ; needs a server that echoes what it is sent; record sizes are in record-layer-limits and zero-length-data
minerva ; skip ; ; ; ; a timing measurement (tcpdump, 100,000 samples a test), not a pass or fail run
mldsa-in-certificate-verify ; skip ; ; ; ; ML-DSA is not supported
mlkem ; skip ; ; ; ; ML-KEM key exchange is not offered
multiple-ccs-messages ; rsa ; ; ; ;
no-unknown-groups ; rsa ; ; --groups x25519,secp256r1,secp384r1 ; ;
nociphers ; rsa ; ; ; ;
non-support ; skip ; ; ; ; for servers without TLS 1.3
obsolete-curves ; rsa ; ; --relaxed -a handshake_failure ; inconsistent extensions|secp521r1|x448 ; a share for a group unknown here is passed over, as OpenSSL does (RFC 8446 4.2.8 lets a server refuse it; this one refuses a share for one of its own groups that supported_groups does not list); P-521 and X448 are not offered
pkcs-signature ; rsa ; ; ; ;
post-handshake-auth ; skip ; ; ; ; post-handshake client authentication is not supported (certificates are asked for in the handshake)
psk_dhe_ke ; skip ; ; ; ; external PSKs are not supported (session tickets are)
psk_ke ; skip ; ; ; ; external PSKs, and resumption without (EC)DHE, are not supported
record-layer-limits ; rsa ; ; ; ;
record-padding ; rsa ; ; ; ;
rsa-signatures ; rsa ; ; ; ;
rsapss-signatures ; skip ; ; ; ; RSA-PSS-only keys (id-RSASSA-PSS) are not supported; rsa_pss_rsae is in rsa-signatures and signature-algorithms
serverhello-random ; rsa ; ; ; ffdhe|secp521r1|x448 ; FFDHE, P-521 and X448 key exchange are not offered
session-resumption ; rsa ; ; ; TLS 1\.2|PSK_ONLY ; TLS 1.3 only; resumption is with (EC)DHE alone (psk_dhe_ke)
shuffled-extentions ; rsa ; ; ; ^HRR  ; the second ClientHello after a HelloRetryRequest is checked for what it must repeat (random, session id, suites, the share asked for), not for the order of its extensions
signature-algorithms ; rsa ; ; ; ;
symetric-ciphers ; rsa ; ; ; CCM ; the AES-CCM suites are not offered
unencrypted-alert ; rsa ; ; ; ;
unrecognised-groups ; rsa ; ; ; ffdhe2048 ; FFDHE key exchange is not offered
version-negotiation ; rsa ; ; ; to 1\.[0-2]$|in client hello legacy field ; TLS 1.3 only (B-116)
zero-content-type ; rsa ; ; ; ;
zero-length-data ; rsa ; ; ; ;
EOF
)

trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
pass=0; fail=0; skipped=0
while IFS=';' read -r script key opts args allowed why; do
  script=$(trim "$script"); key=$(trim "$key"); why=$(trim "$why"); allowed=$(trim "$allowed")
  name=test-tls13-$script
  if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx -- "$name"; then continue; fi
  if [ "$key" = skip ]; then echo "skip $name: $why"; skipped=$((skipped + 1)); continue; fi
  eval "serve_opts=($opts)"; eval "script_args=($args)"
  "$BIN" port="$PORT" certfile="$W/$key.pem" keyfile="$W/$key.key" ca="$W/root.pem" "${serve_opts[@]}" > "$W/serve.log" 2>&1 &
  SERVER=$!
  for _ in $(seq 1 50); do grep -q listening "$W/serve.log" && break; sleep 0.1; done
  (cd "$TF" && PYTHONPATH=. timeout 40 "$PY" "scripts/$name.py" -p "$PORT" "${script_args[@]}") > "$W/out.log" 2>&1
  kill -9 "$SERVER" 2>/dev/null; wait "$SERVER" 2>/dev/null; SERVER=
  total=$(sed -n 's/^TOTAL: //p' "$W/out.log" | tail -1)
  passed=$(sed -n 's/^PASS: //p' "$W/out.log" | tail -1)
  if [ -z "$total" ]; then
    echo "FAIL $name ($key): no summary (crashed or over 40 s)"; tail -3 "$W/out.log" | sed 's/^/       /'; fail=$((fail + 1)); continue
  fi
  failed=$(sed -n '/^FAILED:/,/^$/p' "$W/out.log" | sed -n "s/^\t['\"]\(.*\)['\"]$/\1/p" | sort -u)
  if [ -n "$allowed" ]; then
    unexpected=$(printf '%s\n' "$failed" | grep -Ev -- "$allowed" | grep -v '^$')
  else
    unexpected=$failed
  fi
  expected=$(printf '%s\n' "$failed" | grep -c . )
  if [ -n "$unexpected" ]; then
    echo "FAIL $name ($key): $passed passed; failed:"; printf '%s\n' "$unexpected" | sed 's/^/       /'; fail=$((fail + 1))
  elif [ "$expected" -gt 0 ]; then
    echo "ok   $name ($key): $passed passed, $expected not supported here ($why)"; pass=$((pass + 1))
  else
    echo "ok   $name ($key): $passed passed"; pass=$((pass + 1))
  fi
done <<< "$TABLE"
echo "$pass scripts passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]
