#!/bin/bash
# The scanning proxy behind a gateway that inspects TLS (Zscaler, Netskope), on a Mac that has no such gateway
# (B-78, PROXY_CONFIGURATION.md): what matters for the proxy is that the company's root is trusted in the macOS
# Keychain and nowhere else, so this plays the gateway (a second scan_proxy that re-signs PyPI and index.crates.io with a
# root of its own), puts that root in the Keychain for the length of the run, and checks that the scanning proxy finds
# it there and nowhere else:
#
#   1. with the root in no store and no variable, the scanning proxy passes nothing on (502), which shows that nothing
#      else on this Mac supplies it;
#   2. with the root in the Keychain alone (SSL_CERT_FILE and the other variables unset), pip gets a package through the
#      scanning proxy and the gateway;
#   3. a host the scanning proxy tunnels, which the gateway re-signs, verifies against the bundle the proxy wrote (so the
#      Keychain's root went into the programs' bundle too), checked by Python with that bundle alone;
#   4. with the root taken out of the Keychain again, 502 again.
#
#   tools/gateway_check_mac.sh            the root in your login keychain, with your own trust settings: macOS asks for
#                                         your password (or Touch ID) once to add it and once to take it out
#   tools/gateway_check_mac.sh --admin    the root in the System keychain with the administrator's trust settings, where
#                                         device management puts a company's root (sudo, and macOS may ask as well)
#
# Run it in Terminal on the Mac itself (not in a VM: the Keychain is the point), from the repository. Needs cargo,
# python3 with pip, openssl and the network (pypi.org, files.pythonhosted.org, index.crates.io). The root it adds is a
# CA made for this run, valid for a day and limited by a name constraint to those three hosts; it is taken out of the
# Keychain when the script ends, however it ends.
set -u
[ "$(uname -s)" = Darwin ] || { echo "this check is for macOS"; exit 2; }
ADMIN=0
[ "${1:-}" = --admin ] && ADMIN=1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build --release --features server --example scan_proxy 2>&1 | tail -1)
  BIN=$ROOT/target/release/examples/scan_proxy
fi
python3 -m pip --version > /dev/null 2>&1 || { echo "python3 with pip is needed"; exit 2; }
W=$(mktemp -d)
GW=
SHA1=
ADDED=0
pass=0
fail=0
# a command with a time limit (macOS has no timeout(1)): perl's alarm survives the exec
limit() { perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$@"; }
keychain_remove() {
  [ "$ADDED" = 1 ] || return 0
  if [ "$ADMIN" = 1 ]; then
    sudo security remove-trusted-cert -d "$W/gw-ca.pem"
    sudo security delete-certificate -Z "$SHA1" /Library/Keychains/System.keychain > /dev/null
  else
    security remove-trusted-cert "$W/gw-ca.pem"
    security delete-certificate -Z "$SHA1" "$HOME/Library/Keychains/login.keychain-db" > /dev/null
  fi
  if security find-certificate -a -Z 2> /dev/null | grep -q "$SHA1"; then
    echo "WARNING: the gateway's root ($SHA1) is still in a keychain: remove it in Keychain Access"
  else
    ADDED=0
  fi
}
cleanup() {
  keychain_remove
  [ -n "$GW" ] && kill "$GW" 2> /dev/null
  wait 2> /dev/null
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
check() {
  if eval "$2"; then echo "ok   $1"; pass=$((pass + 1)); else echo "FAIL $1"; fail=$((fail + 1)); fi
}
log() { sed 's/^/    /' "$W/$1.log" | tail -15; }

# the gateway: re-signs the hosts with a root of its own, scans nothing
(cd "$W" && exec "$BIN" intercept=pypi.org,files.pythonhosted.org,index.crates.io ca_name="pratique gateway check $(date +%Y%m%d%H%M%S)" dir="$W/gw") > "$W/gw.log" 2>&1 &
GW=$!
for _ in $(seq 1 100); do grep -q listening "$W/gw.log" && [ -s "$W/gw/ca.pem" ] && break; sleep 0.1; done
port=$(sed -n 's/.*listening 127.0.0.1:\([0-9]*\).*/\1/p' "$W/gw.log" | head -1)
[ -n "$port" ] && [ -s "$W/gw/ca.pem" ] || { echo "the gateway did not start:"; log gw; exit 1; }
cp "$W/gw/ca.pem" "$W/gw-ca.pem"
SHA1=$(openssl x509 -in "$W/gw-ca.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
echo "the gateway listens on 127.0.0.1:$port; its root: $(openssl x509 -in "$W/gw-ca.pem" -noout -subject) (SHA-1 $SHA1)"

# the scanning proxy on the company's Mac: the gateway in HTTPS_PROXY, and none of the variables that could carry a root
corp() { # LABEL [scan_proxy options] -- command...
  local label=$1
  shift
  (cd "$W" && limit 60 env -u SSL_CERT_FILE -u REQUESTS_CA_BUNDLE -u CURL_CA_BUNDLE -u NODE_EXTRA_CA_CERTS -u PIP_CERT \
    -u GIT_SSL_CAINFO -u AWS_CA_BUNDLE HTTPS_PROXY="http://127.0.0.1:$port" https_proxy="http://127.0.0.1:$port" \
    HTTP_PROXY= http_proxy= ALL_PROXY= all_proxy= NO_PROXY= no_proxy= "$BIN" dir="$W/trust-$label" "$@") > "$W/$label.log" 2>&1
}
pip_six() { # LABEL [scan_proxy options]: pip download six through the scanning proxy, with no pip configuration of yours
  local label=$1
  shift
  corp "$label" "$@" -- env PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
    python3 -m pip download --no-deps --no-cache-dir --retries 0 --timeout 20 -d "$W/$label" six==1.16.0
}

check "the root in no store and no variable: nothing is passed on (502)" \
  '! pip_six before && grep -q "Fail GET https://pypi.org/simple/six/ 502" "$W/before.log" || { log before; false; }'

echo "adding the gateway's root to the Keychain (macOS will ask)..."
if [ "$ADMIN" = 1 ]; then
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$W/gw-ca.pem" && ADDED=1
else
  security add-trusted-cert -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "$W/gw-ca.pem" && ADDED=1
fi
[ "$ADDED" = 1 ] || { echo "the root was not added; nothing more to check"; exit 1; }

check "the root in the Keychain alone: pip gets six through the scanning proxy and the gateway" \
  'pip_six keychain inspect=1 && ls "$W/keychain"/six-*.whl > /dev/null && grep -q "Inspect GET https://files.pythonhosted.org/" "$W/keychain.log" &&
   grep -q "Pass GET https://files.pythonhosted.org/" "$W/gw.log" || { log keychain; false; }'
check "a host the scanning proxy tunnels, re-signed by the gateway, verifies with the bundle the proxy wrote" \
  'corp tunnel -- python3 -c "import os, ssl, urllib.request as u
ctx = ssl.create_default_context(cafile=os.environ[\"SSL_CERT_FILE\"])
print(u.build_opener(u.ProxyHandler(), u.HTTPSHandler(context=ctx)).open(\"https://index.crates.io/config.json\", timeout=20).status)" &&
   grep -q "^200" "$W/tunnel.log" && grep -q "Tunnel CONNECT index.crates.io:443" "$W/tunnel.log" || { log tunnel; false; }'

echo "taking the gateway's root out of the Keychain (macOS may ask)..."
keychain_remove
check "the root taken out of the Keychain again: 502 again" \
  '[ "$ADDED" = 0 ] && ! pip_six after && grep -q "Fail GET https://pypi.org/simple/six/ 502" "$W/after.log" || { log after; false; }'

echo "$pass passed, $fail failed ($([ "$ADMIN" = 1 ] && echo "the administrator's trust settings, System keychain" || echo "your trust settings, login keychain"))"
[ "$fail" -eq 0 ]
