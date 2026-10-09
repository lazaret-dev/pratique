#!/usr/bin/env bash
# The scanning proxy (B-78) with real package managers and the real registries: examples/scan_proxy in front of PyPI
# and npm, with pip, uv, npm, Yarn, pnpm, curl, Python's urllib and Go's net/http going through it as its variables
# tell them (HTTPS_PROXY and the rest, and the CA: NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, PIP_CERT,
# CURL_CA_BUNDLE). Each must get what it asks for, through the proxy (its log must show the host intercepted and the
# files inspected), and must fail for a package on the block list; another host is tunnelled, or refused; credentials
# are asked for; and all of it works behind a gateway that re-signs TLS (Zscaler, Netskope), played by another
# scan_proxy.
#
#   tools/proxy_interop.sh [section ...]      sections: pip uv npm yarn pnpm curl python go tunnel auth gateway (default: all)
#
# Needs the network (pypi.org, files.pythonhosted.org, registry.npmjs.org and, for the tunnel, index.crates.io) and
# whichever of the tools are installed (a section whose tool is missing is skipped). Each command has 40 seconds.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build --release --features server --example scan_proxy 2>&1 | tail -1)
  BIN=$ROOT/target/release/examples/scan_proxy
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0
fail=0
skip=0
check() {
  if eval "$2"; then echo "ok   $1"; pass=$((pass + 1)); else echo "FAIL $1"; fail=$((fail + 1)); fi
}
have() {
  command -v "$1" > /dev/null 2>&1 || { echo "skip $1 (not installed)"; skip=$((skip + 1)); return 1; }
}
# run LABEL [options] -- command...: the command through a fresh proxy; its output and the proxy's log in $W/LABEL.log
run() {
  local label=$1
  shift
  (cd "$W" && timeout 40 "$BIN" dir="$W/trust-$label" "$@") > "$W/$label.log" 2>&1
}
log() { sed 's/^/    /' "$W/$1.log" | tail -${2:-15}; }

sections=${*:-pip uv npm yarn pnpm curl python go tunnel auth gateway}

for s in $sections; do
  case $s in
  pip)
    have pip || continue
    check "pip: six from PyPI, its wheel inspected" \
      'run pip inspect=1 -- pip download --no-deps --no-cache-dir -d "$W/pip" six==1.16.0 && ls "$W/pip"/six-1.16.0-*.whl > /dev/null &&
       grep -q "Intercept CONNECT pypi.org:443" "$W/pip.log" && grep -q "Inspect GET https://files.pythonhosted.org/.*six-1.16.0" "$W/pip.log" || { log pip; false; }'
    check "pip: a blocked package is refused" \
      '! run pipb block=six -- pip download --no-deps --no-cache-dir -d "$W/pipb" six==1.16.0 && grep -q "Block GET https://pypi.org/simple/six/" "$W/pipb.log" && ! ls "$W/pipb"/*.whl 2> /dev/null || { log pipb; false; }'
    # a proxy in pip.conf wins over HTTPS_PROXY: PIP_PROXY, which the variables set, wins over it (here it names a port
    # where nothing listens, so pip would fail without it; a working one would have gone around the scanner)
    printf '[global]\nproxy = http://127.0.0.1:9\n' > "$W/pip.conf"
    check "pip: a proxy in pip.conf does not take pip around the scanning proxy" \
      'PIP_CONFIG_FILE="$W/pip.conf" run pipc -- pip download --no-deps --no-cache-dir --retries 0 -d "$W/pipc" six==1.16.0 &&
       grep -q "GET https://files.pythonhosted.org/.*six-1.16.0" "$W/pipc.log" || { log pipc; false; }'
    ;;
  uv)
    have uv || continue
    check "uv: six into a target directory" \
      'run uv inspect=1 -- uv pip install --no-cache --no-deps --target "$W/uv" --python python3 six==1.16.0 && ls "$W/uv/six.py" > /dev/null &&
       grep -q "Inspect GET https://files.pythonhosted.org/" "$W/uv.log" || { log uv; false; }'
    check "uv: a blocked version is refused, the other versions are not" \
      '! run uvb block=six@1.16.0 -- uv pip install --no-cache --no-deps --target "$W/uvb" --python python3 six==1.16.0 && grep -q "Block GET https://files.pythonhosted.org/.*six-1.16.0" "$W/uvb.log" || { log uvb; false; }'
    ;;
  npm)
    have npm || continue
    mkdir -p "$W/npm" && echo '{"name":"t","version":"1.0.0"}' > "$W/npm/package.json"
    check "npm: left-pad, its tarball inspected (npm checks its integrity too)" \
      'run npm inspect=1 -- npm install --prefix "$W/npm" --no-audit --no-fund --cache "$W/npm-cache" left-pad@1.3.0 && [ -f "$W/npm/node_modules/left-pad/package.json" ] &&
       grep -q "Inspect GET https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" "$W/npm.log" || { log npm; false; }'
    mkdir -p "$W/npmb" && echo '{"name":"t","version":"1.0.0"}' > "$W/npmb/package.json"
    check "npm: a blocked package is refused" \
      '! run npmb block=left-pad -- npm install --prefix "$W/npmb" --no-audit --no-fund --cache "$W/npmb-cache" left-pad && grep -q "Block GET https://registry.npmjs.org/left-pad" "$W/npmb.log" && [ ! -d "$W/npmb/node_modules/left-pad" ] || { log npmb; false; }'
    ;;
  yarn)
    have yarn || continue
    mkdir -p "$W/yarn" && echo '{"name":"t","version":"1.0.0"}' > "$W/yarn/package.json"
    check "yarn: is-number through registry.yarnpkg.com" \
      'run yarn inspect=1 -- yarn --cwd "$W/yarn" add --no-lockfile --cache-folder "$W/yarn-cache" is-number@7.0.0 && [ -f "$W/yarn/node_modules/is-number/package.json" ] &&
       grep -q "Intercept CONNECT registry.yarnpkg.com:443" "$W/yarn.log" || { log yarn; false; }'
    ;;
  pnpm)
    have pnpm || continue
    mkdir -p "$W/pnpm" && echo '{"name":"t","version":"1.0.0"}' > "$W/pnpm/package.json"
    check "pnpm: is-number" \
      'run pnpm inspect=1 -- pnpm --dir "$W/pnpm" add --store-dir "$W/pnpm-store" is-number@7.0.0 && [ -e "$W/pnpm/node_modules/is-number" ] &&
       grep -q "Inspect GET https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz" "$W/pnpm.log" || { log pnpm; false; }'
    ;;
  curl)
    have curl || continue
    check "curl: HTTP/1.1 through the proxy" \
      'run curl -- curl -sS --http1.1 -o "$W/curl.out" -w "%{http_code}" https://pypi.org/simple/six/ && grep -q "^200" "$W/curl.log" && grep -q "six-1.16.0" "$W/curl.out" || { log curl; false; }'
    check "curl: HTTP/2 inside the tunnel" \
      'run curl2 -- curl -sS --http2 -o /dev/null -w "%{http_version}" https://registry.npmjs.org/left-pad && grep -q "^2" "$W/curl2.log" || { log curl2; false; }'
    ;;
  python)
    have python3 || continue
    check "python urllib: SSL_CERT_FILE and https_proxy" \
      'run py -- python3 -c "import urllib.request,json; print(json.load(urllib.request.urlopen(\"https://pypi.org/pypi/six/json\"))[\"info\"][\"name\"])" && grep -q "^six$" "$W/py.log" || { log py; false; }'
    ;;
  go)
    have go || continue
    cat > "$W/get.go" << 'EOF'
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	r, err := http.Get(os.Args[1])
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(r.Body)
	fmt.Println(r.StatusCode, r.Proto, len(b))
}
EOF
    check "go net/http: HTTPS_PROXY and SSL_CERT_FILE (HTTP/2)" \
      'run go -- go run "$W/get.go" https://registry.npmjs.org/left-pad && grep -q "^200 HTTP/2.0" "$W/go.log" || { log go; false; }'
    ;;
  tunnel)
    have curl || continue
    check "another host: tunnelled, its own certificate verified by the client" \
      'run tun -- curl -sS -o /dev/null -w "%{http_code}" https://index.crates.io/config.json && grep -q "^200" "$W/tun.log" && grep -q "Tunnel CONNECT index.crates.io:443" "$W/tun.log" || { log tun; false; }'
    check "another host: refused by a proxy that tunnels nothing" \
      '! run tunr others=refuse -- curl -sS -o /dev/null https://index.crates.io/config.json && grep -q "Refuse CONNECT index.crates.io:443 403" "$W/tunr.log" || { log tunr; false; }'
    check "a port that is not allowed" \
      '! run port -- curl -sS -o /dev/null https://pypi.org:8443/ && grep -q "Refuse CONNECT pypi.org:8443 403" "$W/port.log" || { log port; false; }'
    ;;
  auth)
    have pip || continue
    check "credentials: in the proxy URL of the variables, pip gets through" \
      'run auth user=lazaret "pass=s3cr@t" -- pip download --no-deps --no-cache-dir -d "$W/auth" six==1.16.0 && ls "$W/auth"/six-*.whl > /dev/null || { log auth; false; }'
    check "credentials: a client without them is refused (407)" \
      'run authn user=lazaret pass=x -- sh -c "curl -sS -o /dev/null -w %{http_code} --proxy \"http://\${HTTPS_PROXY##*@}\" https://pypi.org/simple/six/; true" && grep -q "Refuse CONNECT pypi.org:443 407" "$W/authn.log" || { log authn; false; }'
    ;;
  gateway)
    have pip || continue
    have curl || continue
    # a gateway that inspects TLS, as Zscaler or Netskope would be: another scan_proxy that re-signs the registries and
    # index.crates.io with a root of its own (and scans nothing); the company's machine has that root in SSL_CERT_FILE
    # and the gateway in HTTPS_PROXY. The scanning proxy must go through it, trust its root, and hand the programs a
    # bundle that trusts it too (for index.crates.io, which the scanning proxy tunnels and the gateway re-signs).
    (cd "$W" && exec "$BIN" intercept=pypi.org,files.pythonhosted.org,registry.npmjs.org,index.crates.io dir="$W/gw") > "$W/gw.log" 2>&1 &
    gw=$!
    for _ in $(seq 1 50); do grep -q "listening" "$W/gw.log" && break; sleep 0.1; done
    gwport=$(sed -n 's/.*listening 127.0.0.1:\([0-9]*\).*/\1/p' "$W/gw.log" | head -1)
    corp() { # LABEL ROOTS [options] -- command: the scanning proxy on the company's machine
      local label=$1 roots=$2
      shift 2
      (cd "$W" && env HTTPS_PROXY="http://127.0.0.1:$gwport" https_proxy="http://127.0.0.1:$gwport" NO_PROXY= no_proxy= SSL_CERT_FILE="$roots" \
        timeout 40 "$BIN" dir="$W/trust-$label" "$@") > "$W/$label.log" 2>&1
    }
    check "behind the gateway: pip gets six, through the gateway, which re-signed PyPI" \
      'corp gwpip "$W/gw/bundle.pem" inspect=1 -- pip download --no-deps --no-cache-dir -d "$W/gwpip" six==1.16.0 && ls "$W/gwpip"/six-*.whl > /dev/null &&
       grep -q "Inspect GET https://files.pythonhosted.org/" "$W/gwpip.log" && grep -q "Pass GET https://files.pythonhosted.org/" "$W/gw.log" || { log gwpip; false; }'
    check "behind the gateway: a host the scanning proxy tunnels, re-signed by the gateway, verifies with the bundle" \
      'corp gwtun "$W/gw/bundle.pem" -- curl -sS -o /dev/null -w "%{http_code}" https://index.crates.io/config.json && grep -q "^200" "$W/gwtun.log" &&
       grep -q "Tunnel CONNECT index.crates.io:443" "$W/gwtun.log" || { log gwtun; false; }'
    printf '%s' "$(head -c 0 /dev/null)" > "$W/empty.pem"
    check "behind the gateway: without its root, nothing is passed on (502)" \
      '! corp gwno "$W/empty.pem" -- pip download --no-deps --no-cache-dir --retries 0 -d "$W/gwno" six==1.16.0 && grep -q "Fail GET https://pypi.org/simple/six/ 502" "$W/gwno.log" || { log gwno; false; }'
    kill "$gw" 2>/dev/null
    wait "$gw" 2>/dev/null
    ;;
  *) echo "no section $s" ;;
  esac
done

echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
