#!/bin/bash
# The scanning proxy on a Mac whose proxy is set in the network settings and nowhere else (B-117, PROXY_CONFIGURATION.md): a company
# that sets its proxy through device management puts it there, not in HTTPS_PROXY, and the scanning proxy has to go where the Mac's
# other programs go. This plays the company's proxy (a second scan_proxy that tunnels everything and notes each CONNECT), sets it as the
# secure web proxy of the network service in use for the length of the run, and checks:
#
#   1. with no proxy in the settings or the environment, the scanning proxy goes direct (the company's proxy sees nothing);
#   2. with the secure web proxy set and the environment silent, pip gets a package through the scanning proxy, which reaches PyPI
#      through the company's proxy (it sees the CONNECTs), and says at start which proxy it took from the settings;
#   3. a host in the list of hosts that go direct (files.pythonhosted.org) goes direct, and the others through the proxy;
#   4. when the environment says anything about proxies (NO_PROXY alone), the settings are not looked at: direct;
#   5. a proxy auto-config file in the settings is reported at start and not followed.
#
#   tools/system_proxy_check_mac.sh
#
# Run it in Terminal on the Mac itself (not in a VM: the network settings are the point), from the repository, on a network that needs
# no proxy (it refuses to run if a secure web proxy or a PAC file is set already). It changes the settings of the network service that
# has the default route (sudo networksetup: macOS asks for your password) and puts them back when it ends, however it ends. While it runs,
# programs that use the system's proxy go through a local proxy that goes direct; for a few seconds in step 5 they are given a PAC
# file that does not exist. Needs cargo, python3 with pip and the network (pypi.org, files.pythonhosted.org).
set -u
[ "$(uname -s)" = Darwin ] || { echo "this check is for macOS"; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build --release --features server --example scan_proxy 2>&1 | tail -1)
  BIN=$ROOT/target/release/examples/scan_proxy
fi
python3 -m pip --version > /dev/null 2>&1 || { echo "python3 with pip is needed"; exit 2; }

# the network service that has the default route (Wi-Fi, Ethernet, ...)
DEV=$(route -n get default 2> /dev/null | awk '/interface:/ {print $2}')
SVC=$(networksetup -listnetworkserviceorder | awk -v dev="$DEV" '
  /^\([0-9*]+\) / { name = $0; sub(/^\([0-9*]+\) /, "", name) }
  /Device: / { d = $0; sub(/.*Device: /, "", d); sub(/\).*/, "", d); if (d == dev) { print name; exit } }')
[ -n "$SVC" ] || { echo "no network service has the default route ($DEV)"; exit 2; }
SECURE=$(networksetup -getsecurewebproxy "$SVC")
PAC=$(networksetup -getautoproxyurl "$SVC")
BYPASS=$(networksetup -getproxybypassdomains "$SVC")
echo "network service: $SVC ($DEV)"
if echo "$SECURE" | grep -q "^Enabled: Yes" || echo "$PAC" | grep -q "^Enabled: Yes"; then
  echo "a secure web proxy or a PAC file is set on $SVC already; this check would replace it: run it on a network that needs no proxy"
  echo "$SECURE"; echo "$PAC"
  exit 2
fi
OLD_SERVER=$(echo "$SECURE" | sed -n 's/^Server: //p')
OLD_PORT=$(echo "$SECURE" | sed -n 's/^Port: //p')
OLD_PAC_URL=$(echo "$PAC" | sed -n 's/^URL: //p')
echo "macOS asks for your password to change the network settings..."
sudo -v || exit 2

W=$(mktemp -d)
CORP=
CHANGED=0
pass=0
fail=0
# a command with a time limit (macOS has no timeout(1)): perl's alarm survives the exec
limit() { perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$@"; }
restore() {
  [ "$CHANGED" = 1 ] || return 0
  sudo networksetup -setsecurewebproxystate "$SVC" off
  if [ -n "$OLD_SERVER" ] && [ "${OLD_PORT:-0}" != 0 ]; then
    sudo networksetup -setsecurewebproxy "$SVC" "$OLD_SERVER" "$OLD_PORT" && sudo networksetup -setsecurewebproxystate "$SVC" off
  else
    echo "(the secure web proxy of $SVC is off again; its server field, which networksetup cannot empty, still says 127.0.0.1)"
  fi
  sudo networksetup -setautoproxystate "$SVC" off
  case "$OLD_PAC_URL" in "" | "(null)") ;; *) sudo networksetup -setautoproxyurl "$SVC" "$OLD_PAC_URL" && sudo networksetup -setautoproxystate "$SVC" off ;; esac
  if echo "$BYPASS" | grep -q "aren't any"; then
    sudo networksetup -setproxybypassdomains "$SVC" Empty
  else
    # (one domain a line, as -getproxybypassdomains gives them)
    IFS=$'\n' read -r -d '' -a domains <<< "$BYPASS"
    sudo networksetup -setproxybypassdomains "$SVC" "${domains[@]}"
  fi
  if networksetup -getsecurewebproxy "$SVC" | grep -q "^Enabled: Yes" || networksetup -getautoproxyurl "$SVC" | grep -q "^Enabled: Yes"; then
    echo "WARNING: the proxy settings of $SVC were not put back: turn the secure web proxy and the PAC file off in System Settings"
  else
    CHANGED=0
  fi
}
cleanup() {
  restore
  [ -n "$CORP" ] && kill "$CORP" 2> /dev/null
  wait 2> /dev/null
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
check() {
  if eval "$2"; then echo "ok   $1"; pass=$((pass + 1)); else echo "FAIL $1"; fail=$((fail + 1)); fi
}
log() { sed 's/^/    /' "$W/$1.log" | tail -15; }
settle() { sleep 2; } # (configd hands a change to SCDynamicStore in a moment)

# the company's proxy: tunnels everything (it opens no host it is asked for), goes direct itself, and notes each CONNECT
(cd "$W" && exec env -u HTTPS_PROXY -u https_proxy "$BIN" intercept=intercept.invalid upstream_proxy=none dir="$W/corp") > "$W/corp.log" 2>&1 &
CORP=$!
for _ in $(seq 1 100); do grep -q listening "$W/corp.log" && break; sleep 0.1; done
port=$(sed -n 's/.*listening 127.0.0.1:\([0-9]*\).*/\1/p' "$W/corp.log" | head -1)
[ -n "$port" ] || { echo "the company's proxy did not start:"; log corp; exit 1; }
echo "the company's proxy listens on 127.0.0.1:$port"
seen() { grep -c "Tunnel CONNECT $1:443" "$W/corp.log"; }

# the scanning proxy with none of the proxy variables (or the ones that carry roots) in its environment, and what EXTRA adds
EXTRA=()
pip_six() { # LABEL: pip download six through the scanning proxy, with no pip configuration of yours
  local label=$1
  (cd "$W" && limit 90 env -u SSL_CERT_FILE -u REQUESTS_CA_BUNDLE -u CURL_CA_BUNDLE -u PIP_CERT -u HTTPS_PROXY -u https_proxy \
    -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy -u PIP_PROXY ${EXTRA[@]+"${EXTRA[@]}"} \
    "$BIN" dir="$W/trust-$label" -- env PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
    python3 -m pip download --no-deps --no-cache-dir --retries 0 --timeout 20 -d "$W/$label" six==1.16.0) > "$W/$label.log" 2>&1
}

check "no proxy in the settings or the environment: direct, and the company's proxy sees nothing" \
  'pip_six direct && ls "$W/direct"/six-*.whl > /dev/null && [ "$(seen pypi.org)" = 0 ] || { log direct; false; }'

echo "setting 127.0.0.1:$port as the secure web proxy of $SVC..."
CHANGED=1
sudo networksetup -setsecurewebproxy "$SVC" 127.0.0.1 "$port" && sudo networksetup -setsecurewebproxystate "$SVC" on
sudo networksetup -setproxybypassdomains "$SVC" "*.local" "169.254/16"
settle
check "the secure web proxy set, the environment silent: pip gets six, and the scanning proxy reaches PyPI through the company's proxy" \
  'pip_six system && ls "$W/system"/six-*.whl > /dev/null && [ "$(seen pypi.org)" -ge 1 ] && [ "$(seen files.pythonhosted.org)" -ge 1 ] &&
   grep -q "network settings name 127.0.0.1:$port as the proxy for https" "$W/system.log" || { log system; log corp; false; }'

sudo networksetup -setproxybypassdomains "$SVC" "*.local" "169.254/16" "files.pythonhosted.org"
settle
before_index=$(seen pypi.org)
before_files=$(seen files.pythonhosted.org)
check "a host in the list of hosts that go direct goes direct, and the others through the proxy" \
  'pip_six bypass && ls "$W/bypass"/six-*.whl > /dev/null && [ "$(seen pypi.org)" -gt "$before_index" ] &&
   [ "$(seen files.pythonhosted.org)" = "$before_files" ] || { log bypass; log corp; false; }'

before_index=$(seen pypi.org)
EXTRA=(NO_PROXY=intercept.invalid)
check "the environment says something about proxies (NO_PROXY alone): the settings are not looked at, and it goes direct" \
  'pip_six environment && ls "$W/environment"/six-*.whl > /dev/null && [ "$(seen pypi.org)" = "$before_index" ] || { log environment; false; }'
EXTRA=()

echo "setting a PAC file (that does not exist) for a few seconds..."
sudo networksetup -setautoproxyurl "$SVC" "http://127.0.0.1:9/proxy.pac?key=not-shown" && sudo networksetup -setautoproxystate "$SVC" on
settle
(cd "$W" && limit 30 env -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy "$BIN" dir="$W/trust-pac" -- true) > "$W/pac.log" 2>&1
sudo networksetup -setautoproxystate "$SVC" off
check "a PAC file in the settings is reported at start, not followed, and its query not shown" \
  'grep -q "proxy auto-config file (at http://127.0.0.1:9/proxy.pac), which is not followed" "$W/pac.log" && ! grep -q "not-shown" "$W/pac.log" || { log pac; false; }'

echo "putting the proxy settings of $SVC back..."
restore
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
