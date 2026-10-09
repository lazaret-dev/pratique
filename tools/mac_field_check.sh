#!/bin/sh
# The checks that need a real network, a real machine or hours of CPU, in one script for the Mac:
#
#   B-06  smoke test against real public sites              (smoke)
#   B-35  TLS 1.3 session resumption with the same sites     (smoke)
#   B-08  real certificate chains, kept as test fixtures     (capture, verify)
#   B-65  real OCSP responses and CRLs, checked as fixtures  (revocation)
#   B-82  Sigstore's TUF repository, refreshed and captured  (tuf)
#   B-91  QUIC key updates and keep-alive, real HTTP/3 servers (quic)
#   B-66  long fuzz campaigns                                (fuzz)
#
#   sh tools/mac_field_check.sh                 smoke, roots, native, capture, verify, revocation, tuf and quic (about 12 minutes, a few of them compiling)
#   sh tools/mac_field_check.sh smoke           B-06 alone
#   sh tools/mac_field_check.sh roots           B-31: the same hosts' handshakes against the crate's built-in Mozilla roots
#   sh tools/mac_field_check.sh native          B-101: the same hosts' handshakes against the Keychain's trust settings
#   sh tools/mac_field_check.sh capture         fetch the chains with OpenSSL, then verify them with the library
#   sh tools/mac_field_check.sh revocation      OCSP responses and CRLs of the chains that were captured
#   sh tools/mac_field_check.sh tuf             B-82: Sigstore's trusted root and npm's keys through TUF, every file kept
#   sh tools/mac_field_check.sh quic            B-91: four HTTP/3 servers of other implementations follow the client's key updates,
#                                               and keep-alive PINGs hold a connection open through a quiet spell (needs UDP to port 443)
#   sh tools/mac_field_check.sh fuzz [HOURS]    B-66: a fuzz campaign (default 8 hours; HOURS may be 0.5); Ctrl-C ends it early and keeps what it found
#   sh tools/mac_field_check.sh package         only (re)make field_results.tgz
#
# Run it from the project root, on the Mac, on a network that does NOT re-sign TLS (not a company VPN or proxy with
# inspection; a phone hotspot is fine). It stops at the start if the network looks like it re-signs. FORCE=1 overrides.
#
# For the fuzz run: plug the Mac in, and leave the lid open. caffeinate keeps it from sleeping while the script runs, but a
# closed lid on a laptop sleeps whatever caffeinate says. Nothing needs the network.
#
# What it writes (everything under field_results/, and field_results.tgz, which is what to send back):
#   report.txt        what was run and what came of it
#   environment.txt   machine, toolchain, CA bundle (the NAMES of proxy variables that are set, never their values)
#   smoke.tsv         B-06: one line per site (and B-35: whether the handshake made again after the GET resumed)
#   smoke_mozilla.tsv B-31: the same, handshakes only, against the built-in roots
#   smoke_native.tsv native_roots.txt  B-101: the same against the Keychain, and what the Keychain trusts and leaves out
#   chains/ manifest.tsv raw/    B-08: what OpenSSL saw
#   real_chains/      B-08: the fixtures: copy this directory to tests/data/real_chains/ in the project
#   revocation/       B-65: OCSP responses (asked of the responders) and CRLs (downloaded) for the captured chains
#   real_revocation/ revocation.txt  B-65: each checked by the library at the time it was fetched; the fixture candidates
#   tuf/ tuf.txt      B-82: every file Sigstore's TUF repository served (copy tuf/ to tests/data/tuf/sigstore/), and the log
#   quic/             B-91: what the QUIC probe printed for each server and check
#   fuzz-results.tgz fuzz-summary.txt    B-66
# Nothing is read from or written to anywhere else, except the build directories of cargo (target/ and fuzz/target/) and
# the fuzzer's own work files (fuzz/work/, fuzz/logs/, fuzz/corpus/), which can be deleted afterwards. No secret is read.
#
# Uses nothing newer than POSIX sh and tools every Mac has (awk, sed, tar, curl, perl or timeout), plus the Rust toolchain.

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
OUT=${FIELD_OUT:-field_results}
HOSTS=${FIELD_HOSTS:-tools/field_hosts.txt}
FC="$ROOT/target/release/examples/field_check"
NR="$ROOT/target/release/examples/native_roots"
QP="$ROOT/target/release/examples/quic_probe"
MODE=${1:-all}

case "$OUT" in
    ""|"/"|"."|"..") echo "FIELD_OUT must be a directory name of its own, not '$OUT'" >&2; exit 2 ;;
esac

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

case "$MODE" in
    all|smoke|roots|native|capture|revocation|tuf|quic|fuzz|package) ;;
    -h|--help|help) usage ;;
    *) echo "unknown mode: $MODE" >&2; usage ;;
esac

mkdir -p "$OUT"
REPORT="$OUT/report.txt"
say() { echo "$*" | tee -a "$REPORT"; }

# tmo SECONDS COMMAND...: the command, ended after SECONDS (macOS has no timeout(1)).
tmo() {
    secs=$1
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    elif command -v perl >/dev/null 2>&1; then
        perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$secs" "$@"
    else
        "$@"
    fi
}

# run_logged LOG COMMAND...: runs the command, shows and keeps its output, leaves its exit status in RC.
run_logged() {
    log=$1
    shift
    { "$@"; echo $? >"$OUT/.rc"; } 2>&1 | tee "$log"
    RC=$(cat "$OUT/.rc" 2>/dev/null || echo 1)
    rm -f "$OUT/.rc"
}

# --- the same CA bundle the library will pick (see sys.rs), and an OpenSSL to compare with
find_bundle() {
    BUNDLE=""
    if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
        BUNDLE=$SSL_CERT_FILE
        return
    fi
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem \
        /usr/local/etc/openssl@3/cert.pem /usr/local/etc/openssl/cert.pem /opt/homebrew/etc/openssl@3/cert.pem \
        /usr/local/share/certs/ca-root-nss.crt; do
        if [ -r "$f" ]; then
            BUNDLE=$f
            return
        fi
    done
}

# An OpenSSL 3 if there is one (Homebrew's, usually): the LibreSSL that macOS ships prints "Verify return code: 0 (ok)" for a TLS 1.3
# connection whose chain it could not verify (found on a real run: ISRG Root X2), so its verdict is read from the "verify error" lines
# (see verify_code_of) and not trusted alone.
find_openssl() {
    OPENSSL=""
    for c in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl \
        "$(command -v openssl 2>/dev/null)"; do
        if [ -n "$c" ] && [ -x "$c" ]; then
            case $("$c" version 2>&1) in
            OpenSSL\ [3-9]*)
                OPENSSL=$c
                return
                ;;
            esac
        fi
    done
    if [ -x /usr/bin/openssl ]; then
        OPENSSL=/usr/bin/openssl
    elif command -v openssl >/dev/null 2>&1; then
        OPENSSL=$(command -v openssl)
    fi
}

# The verdict of an s_client run: the first "verify error:num=N" line if there is one (any such line means the chain was not accepted,
# whatever the last line says), else the "Verify return code".
verify_code_of() { # FILE
    e=$(sed -n 's/^verify error:num=\([0-9]*\):.*/\1/p' "$1" | head -n 1)
    if [ -n "$e" ]; then
        echo "$e"
    else
        sed -n 's/^ *Verify return code: \([0-9]*\).*/\1/p' "$1" | tail -n 1
    fi
}

environment() {
    {
        echo "date:     $(date -u '+%Y-%m-%d %H:%M UTC')"
        echo "uname:    $(uname -a)"
        echo "arch:     $(uname -m)"
        if command -v sw_vers >/dev/null 2>&1; then echo "macOS:    $(sw_vers -productVersion) ($(sw_vers -buildVersion))"; fi
        brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
        if [ -n "$brand" ]; then
            echo "cpu:      $brand ($(sysctl -n hw.ncpu 2>/dev/null) cores)"
        elif [ -r /proc/cpuinfo ]; then
            echo "cpu:      $(grep -m1 -E 'model name|Hardware' /proc/cpuinfo | sed 's/^[^:]*: *//') ($(grep -c '^processor' /proc/cpuinfo) cores)"
        fi
        echo "rustc:    $(rustc --version 2>&1)"
        echo "library:  $(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)"
        echo "openssl:  ${OPENSSL:-none} ($("${OPENSSL:-true}" version 2>&1))"
        if [ -n "$BUNDLE" ]; then
            echo "bundle:   $BUNDLE ($(grep -c 'BEGIN CERTIFICATE' "$BUNDLE") certificates)"
        else
            echo "bundle:   none found"
        fi
        for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy NO_PROXY no_proxy SSL_CERT_FILE; do
            eval "val=\${$v:-}"
            if [ -n "$val" ]; then echo "set:      $v (value not recorded)"; fi
        done
    } >"$OUT/environment.txt"
}

build() {
    say "building the example (release)..."
    if ! cargo build --release --example field_check --example tuf_refresh --example native_roots --example quic_probe --features mozilla-roots >"$OUT/build.log" 2>&1; then
        say "the build failed; see $OUT/build.log"
        tail -n 20 "$OUT/build.log"
        exit 1
    fi
}

# --- is this a network that leaves TLS alone? www.google.com is always issued by Google Trust Services.
check_network() {
    probe="$OUT/network_probe.txt"
    tmo 25 "$OPENSSL" s_client -connect www.google.com:443 -servername www.google.com -CAfile "$BUNDLE" </dev/null >"$probe" 2>&1
    if ! grep -q 'BEGIN CERTIFICATE' "$probe"; then
        say "cannot reach www.google.com:443 directly (see $probe). Is the network proxy-only or offline?"
        [ "${FORCE:-0}" = 1 ] || exit 1
    elif ! grep -q 'Google Trust Services' "$probe"; then
        say "This network seems to re-sign TLS: the certificate for www.google.com was not issued by Google Trust Services:"
        grep -E '^ *(i|s):|issuer=' "$probe" | head -n 6 | sed 's/^/    /' | tee -a "$REPORT"
        say "The results would describe the network, not the library. Use another network (a phone hotspot), or FORCE=1 to run anyway."
        [ "${FORCE:-0}" = 1 ] || exit 1
    else
        say "network: www.google.com is issued by Google Trust Services, so TLS is not being re-signed."
    fi
}

hosts_of() { # GROUP
    awk -v g="$1" '$0 !~ /^[ \t]*#/ && NF >= 2 && ($1 == g || $1 == g "-tls12") { print $2 }' "$HOSTS"
}

# --- B-06
do_smoke() {
    say ""
    n_ok=$(awk '$0 !~ /^[ \t]*#/ && NF == 2 && ($1 == "ok" || $1 == "ok-tls12")' "$HOSTS" | wc -l | tr -d ' ')
    n_refuse=$(awk '$0 !~ /^[ \t]*#/ && NF == 2 && ($1 == "refuse" || $1 == "refuse-tls12")' "$HOSTS" | wc -l | tr -d ' ')
    n_no_ems=$(awk '$0 !~ /^[ \t]*#/ && $3 == "no-ems"' "$HOSTS" | wc -l | tr -d ' ')
    n_info=$(awk '$0 !~ /^[ \t]*#/ && NF == 2 && $1 == "info"' "$HOSTS" | wc -l | tr -d ' ')
    n_handshake=$(awk '$0 !~ /^[ \t]*#/ && NF == 2 && $1 == "refuse-handshake"' "$HOSTS" | wc -l | tr -d ' ')
    n_revoked=$(awk '$0 !~ /^[ \t]*#/ && NF == 2 && $1 == "revoked"' "$HOSTS" | wc -l | tr -d ' ')
    say "=== B-06: smoke test against real public sites ($n_ok must connect, $n_refuse must be refused, $n_handshake must be refused at the handshake, $n_revoked must be refused as revoked, $n_no_ems must be refused for want of the extended master secret, $n_info written down)"
    run_logged "$OUT/smoke.txt" "$FC" smoke "$HOSTS" --cacert "$BUNDLE" --tsv "$OUT/smoke.tsv"
    SMOKE_RC=$RC
    # for each failure, and for each server refused for want of the extended master secret, what an independent TLS client says
    # about the same host, to tell a bug of ours from a network or a server
    if [ -f "$OUT/smoke.tsv" ]; then
        mkdir -p "$OUT/failures"
        rm -f "$OUT/failures/.disagree"
        if verify_supports_hostname; then
            hostname_checked=yes
        else
            hostname_checked=no
            say "  (this OpenSSL cannot check host names, so its verdicts below say nothing about a wrong host)"
        fi
        awk -F'\t' '$3 == "FAIL" || $3 == "WEAK" || $1 == "no-ems" { print $1, $2, $3 }' "$OUT/smoke.tsv" | while read -r g h v; do
            case $h in *:*) target=$h; sni=${h%%:*} ;; *) target=$h:443; sni=$h ;; esac
            f="$OUT/failures/$(echo "$h" | tr ':' '_').txt"
            if [ "$hostname_checked" = yes ]; then
                tmo 25 "$OPENSSL" s_client -connect "$target" -servername "$sni" -verify_hostname "$sni" -showcerts -CAfile "$BUNDLE" </dev/null >"$f" 2>&1
            else
                tmo 25 "$OPENSSL" s_client -connect "$target" -servername "$sni" -showcerts -CAfile "$BUNDLE" </dev/null >"$f" 2>&1
            fi
            code=$(verify_code_of "$f")
            proto=$(sed -n 's/^ *Protocol *: *//p' "$f" | head -n 1)
            ems=$(sed -n 's/^ *Extended master secret: *//p' "$f" | head -n 1)
            say "  independent check of $h ($g, $v): OpenSSL says verify code ${code:--} (0 is accepted), ${proto:-no protocol}, extended master secret ${ems:--}; full output in $f"
            if [ "$g" = refuse ] && [ "$code" = 0 ] && [ "$hostname_checked" = yes ]; then
                say "    OpenSSL accepts it too, so this network is probably re-signing TLS (or the bundle trusts too much): not a fault of the library"
            fi
            if [ "$g" = no-ems ] && [ "$v" = PASS ] && [ "$ems" = yes ]; then
                say "    DISAGREE: OpenSSL got the extended master secret from this server and the library says the server did not do it: a bug to look at"
                touch "$OUT/failures/.disagree"
            fi
        done
        if [ -f "$OUT/failures/.disagree" ]; then
            SMOKE_RC=1
        fi
        # B-35: each host the library could not resume with; does OpenSSL resume with it (a ticket from one connection
        # offered on the next)?
        awk -F'\t' '$3 == "FAIL" && $4 ~ /^resumption/ { print $2 }' "$OUT/smoke.tsv" | while read -r h; do
            case $h in *:*) target=$h; sni=${h%%:*} ;; *) target=$h:443; sni=$h ;; esac
            f="$OUT/failures/$(echo "$h" | tr ':' '_')_resumption.txt"
            sess="$OUT/failures/$(echo "$h" | tr ':' '_').sess"
            printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$sni" |
                tmo 25 "$OPENSSL" s_client -connect "$target" -servername "$sni" -sess_out "$sess" -ign_eof >"$f" 2>&1
            tmo 25 "$OPENSSL" s_client -connect "$target" -servername "$sni" -sess_in "$sess" </dev/null >>"$f" 2>&1
            if grep -q '^Reused' "$f"; then reused="resumes the session"; else reused="does not resume the session either"; fi
            say "  independent check of resumption with $h: OpenSSL $reused; full output in $f"
            rm -f "$sess"
        done
        resumed=$(awk -F'\t' 'NR > 1 && $7 == "resumed"' "$OUT/smoke.tsv" | wc -l | tr -d ' ')
        tried=$(awk -F'\t' 'NR > 1 && $7 != "" && $7 != "-"' "$OUT/smoke.tsv" | wc -l | tr -d ' ')
        say "  B-35: TLS sessions resumed with $resumed of the $tried hosts tried again after the GET (the column resumption of smoke.tsv says why not for the others)"
    fi
    say "B-06: exit status $SMOKE_RC"
}

# --- B-08
verify_supports_hostname() {
    "$OPENSSL" s_client -help 2>&1 | grep -q 'verify_hostname'
}

capture_one() { # GROUP HOST
    group=$1
    host=$2
    name=$(echo "$host" | tr ':' '_')
    case $host in *:*) target=$host; sni=${host%%:*} ;; *) target=$host:443; sni=$host ;; esac
    t=$(date -u +%s)
    if verify_supports_hostname; then
        tmo 30 "$OPENSSL" s_client -connect "$target" -servername "$sni" -verify_hostname "$sni" -showcerts -CAfile "$BUNDLE" </dev/null >"$OUT/raw/$name.txt" 2>&1
    else
        tmo 30 "$OPENSSL" s_client -connect "$target" -servername "$sni" -showcerts -CAfile "$BUNDLE" </dev/null >"$OUT/raw/$name.txt" 2>&1
    fi
    # the PEM blocks of the chain as sent (the "Server certificate" section after it repeats the leaf)
    awk '/^Server certificate/ { exit } /-----BEGIN CERTIFICATE-----/ { on = 1 } on { print } /-----END CERTIFICATE-----/ { on = 0 }' \
        "$OUT/raw/$name.txt" >"$OUT/chains/$name.pem"
    if [ ! -s "$OUT/chains/$name.pem" ]; then
        rm -f "$OUT/chains/$name.pem"
        echo "  $host: nothing captured (unreachable?)"
        return
    fi
    code=$(verify_code_of "$OUT/raw/$name.txt")
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$host" "$t" "$group" "${code:--}" >>"$OUT/manifest.tsv"
    echo "  $host: $(grep -c 'BEGIN CERTIFICATE' "$OUT/chains/$name.pem") certificates, OpenSSL verify code ${code:--}"
}

do_capture() {
    say ""
    say "=== B-08: real certificate chains (captured by OpenSSL, verified by the library at the moment of capture)"
    rm -rf "$OUT/chains" "$OUT/raw" "$OUT/real_chains" "$OUT/manifest.tsv" "$OUT/verify.tsv"
    mkdir -p "$OUT/chains" "$OUT/raw"
    printf '# name\thost\ttime\tgroup\topenssl_verify_code (captured with: %s)\n' "$("$OPENSSL" version)" >"$OUT/manifest.tsv"
    # the revoked group's chains are valid ones (only their CA's responder and list say otherwise), taken for B-65
    for group in ok refuse revoked; do
        hosts_of "$group" | while read -r h; do capture_one "$group" "$h"; done
    done
    say "captured $(grep -vc '^#' "$OUT/manifest.tsv") chains"
    run_logged "$OUT/verify.txt" "$FC" verify "$OUT" --cacert "$BUNDLE"
    VERIFY_RC=$RC
    say "B-08: exit status $VERIFY_RC"
    if [ -f "$OUT/real_chains/fixtures.tsv" ]; then
        say "The fixtures are in $OUT/real_chains/. To keep them: copy that directory to tests/data/real_chains/ in the project"
        say "(or send field_results.tgz back); 'cargo test --test real_chains' then replays them on any machine."
    fi
}

# --- B-31: the same hosts, handshakes only, against the roots built into the crate instead of the system bundle
do_roots() {
    say ""
    say "=== B-31: the built-in Mozilla roots (handshakes only; the hosts the system bundle lacks a root for should pass here)"
    run_logged "$OUT/smoke_mozilla.txt" "$FC" smoke "$HOSTS" --cacert mozilla --tls-only --tsv "$OUT/smoke_mozilla.tsv"
    ROOTS_RC=$RC
    say "B-31: exit status $ROOTS_RC"
}

# --- B-101: the same hosts, handshakes only, against the operating system's own store (the Keychain's trust settings), and
# the store itself compared with the CA bundle
do_native() {
    say ""
    say "=== B-101: the Keychain's trust settings (handshakes only; should match the system bundle's results)"
    run_logged "$OUT/native_roots.txt" "$NR" --compare "$BUNDLE"
    grep -E "^native store|^compared with" "$OUT/native_roots.txt" | tee -a "$REPORT"
    NATIVE_RC=$RC
    if [ "$NATIVE_RC" -eq 0 ]; then
        run_logged "$OUT/smoke_native.txt" "$FC" smoke "$HOSTS" --cacert native --tls-only --tsv "$OUT/smoke_native.tsv"
        NATIVE_RC=$RC
    fi
    say "B-101: exit status $NATIVE_RC"
}

# --- B-91: HTTP/3 servers of other implementations follow the client's key updates, and keep-alive PINGs hold a connection
# open through a quiet spell (both checked before against aioquic only). Needs UDP to port 443: a network that blocks it gives
# NOTE lines, not failures. A FAIL may be the server's (RFC 9001 requires following a peer's key update): the log says which.
do_quic() {
    say ""
    say "=== B-91: QUIC key updates and keep-alive against public HTTP/3 servers"
    mkdir -p "$OUT/quic"
    for h in ${FIELD_QUIC_HOSTS:-cloudflare-quic.com www.google.com www.facebook.com quic.nginx.org}; do
        case $h in *:*) target=$h; sni=${h%%:*} ;; *) target=$h:443; sni=$h ;; esac
        name=$(echo "$h" | tr ':/' '__')
        # 300 PINGs, each answered before the next, with the keys updated every 20 packets: about a dozen updates, each of
        # which the server has to follow (and acknowledge) before the client makes the next
        # (at a round trip of 200 ms that takes a minute)
        log="$OUT/quic/$name.keys.txt"
        tmo 240 "$QP" "$target" "$sni" "$BUNDLE" --ping 300 --key-update-after 20 >"$log" 2>&1
        quic_verdict "$h" "key updates" "$log" key_updates 5
        # an idle timeout of 5 s and 20 s of quiet after the handshake, so only the keep-alive PINGs keep it open; then 3 PINGs
        log="$OUT/quic/$name.keepalive.txt"
        tmo 120 "$QP" "$target" "$sni" "$BUNDLE" --idle-ms 5000 --quiet-for 20 --ping 3 >"$log" 2>&1
        quic_keepalive_verdict "$h" "$log"
    done
    say "B-91: exit status $QUIC_RC"
}

# quic_verdict HOST WHAT LOG STAT MIN: PASS if the probe closed the connection itself (so every PING was answered) and the
# statistic STAT reached MIN
quic_verdict() {
    n=$(sed -n "s/.*[ {]$4: \([0-9]*\).*/\1/p" "$3" | tail -n 1)
    closed=$(grep '^closed:' "$3" | tail -n 1)
    if ! grep -q ' Confirmed$' "$3"; then
        say "NOTE  $1 $2: no QUIC handshake (UDP to port 443 blocked, or no HTTP/3 there); see $3"
    elif echo "$closed" | grep -q '^closed: Application' && [ "${n:-0}" -ge "$5" ]; then
        say "PASS  $1 $2: $4 $n, every PING answered"
    else
        say "FAIL  $1 $2: $4 ${n:-?}, ${closed:-not closed (ended from outside)}; see $3"
        QUIC_RC=1
    fi
}

# quic_keepalive_verdict HOST LOG: PASS if the connection was still open when the quiet spell ended (only the keep-alive PINGs
# could keep it: the idle timeout is a quarter of the spell); NOTE if the server ended it during the spell with "no error" (0, or
# HTTP/3's H3_NO_ERROR, 256: its own choice, as a server may close a connection that makes no requests); FAIL otherwise,
# including a close with an error code at any time
quic_keepalive_verdict() {
    k=$(sed -n "s/.*[ {]keep_alives: \([0-9]*\).*/\1/p" "$2" | tail -n 1)
    closed=$(grep '^closed:' "$2" | tail -n 1)
    at=$(grep 'Closed(' "$2" | tail -n 1 | awk '{print $1}')
    if echo "$closed" | grep -qE '^closed: (Application|PeerApplication \{ code: (0|256),|PeerTransport \{ code: 0,)'; then
        benign=1
    else
        benign=0
    fi
    if ! grep -q ' Confirmed$' "$2"; then
        say "NOTE  $1 keep-alive: no QUIC handshake (UDP to port 443 blocked, or no HTTP/3 there); see $2"
    elif grep -q 'kept alive through' "$2" && echo "$closed" | grep -q '^closed: Application'; then
        say "PASS  $1 keep-alive: through the quiet spell on ${k:-?} keep-alive PINGs, every PING answered"
    elif grep -q 'kept alive through' "$2" && [ "$benign" = 1 ]; then
        say "PASS  $1 keep-alive: through the quiet spell on ${k:-?} keep-alive PINGs; then the server closed it at $at ms with no error: ${closed#closed: }"
    elif [ "$benign" = 1 ]; then
        say "NOTE  $1 keep-alive: the server closed it at $at ms, during the quiet spell, after ${k:-?} keep-alive PINGs, with no error: ${closed#closed: }; see $2"
    else
        say "FAIL  $1 keep-alive: ${k:-?} keep-alive PINGs, ${closed:-not closed (ended from outside)}; see $2"
        QUIC_RC=1
    fi
}

# --- B-82: Sigstore's TUF repository: the root rotated from the one built into the crate, timestamp, snapshot, targets, the
# registry.npmjs.org delegation, trusted_root.json and npm's keys, all verified; every file it served is kept for replay
do_tuf() {
    say ""
    say "=== B-82: Sigstore's trust through TUF (https://tuf-repo-cdn.sigstore.dev)"
    rm -rf "$OUT/tuf"
    run_logged "$OUT/tuf.txt" "$ROOT/target/release/examples/tuf_refresh" --save "$OUT/tuf"
    TUF_RC=$RC
    say "B-82: exit status $TUF_RC; the files are in $OUT/tuf/ (tests/data/tuf/sigstore/ in the project replays them)"
}

# --- B-65
do_revocation() {
    say ""
    say "=== B-65: real OCSP responses and CRLs for the chains that were captured"
    if [ ! -f "$OUT/manifest.tsv" ]; then
        say "no captured chains yet: run 'capture' first"
        return
    fi
    rm -rf "$OUT/revocation"
    mkdir -p "$OUT/revocation"
    printf '# name\tfetched_at (unix)\tocsp_url\tocsp_response_file\tcrl_url\tcrl_file\tgroup\n' >"$OUT/revocation/manifest.tsv"
    awk -F'\t' '$1 !~ /^#/ && ($4 == "ok" || $4 == "revoked") { print $1, $4 }' "$OUT/manifest.tsv" | while read -r name group; do
        chain="$OUT/chains/$name.pem"
        [ -s "$chain" ] || continue
        d="$OUT/revocation/$name"
        mkdir -p "$d"
        awk -v dir="$d" 'BEGIN { n = 0 } /-----BEGIN CERTIFICATE-----/ { n++; f = dir "/cert" n ".pem" } n > 0 { print > f } /-----END CERTIFICATE-----/ { close(f) }' "$chain"
        [ -s "$d/cert2.pem" ] || { echo "  $name: the server sent no issuer, so there is nothing to ask about"; rm -rf "$d"; continue; }
        fetched=$(date -u +%s)
        ocsp_url=$("$OPENSSL" x509 -in "$d/cert1.pem" -noout -ocsp_uri 2>/dev/null | head -n 1)
        ocsp_file=-
        if [ -n "$ocsp_url" ]; then
            if tmo 30 "$OPENSSL" ocsp -issuer "$d/cert2.pem" -cert "$d/cert1.pem" -url "$ocsp_url" -noverify -no_nonce -respout "$d/ocsp.der" -text >"$d/ocsp.txt" 2>&1 </dev/null \
                && [ -s "$d/ocsp.der" ]; then
                ocsp_file="revocation/$name/ocsp.der"
            else
                rm -f "$d/ocsp.der"
            fi
        fi
        crl_url=$("$OPENSSL" x509 -in "$d/cert1.pem" -noout -text 2>/dev/null | grep -A6 'CRL Distribution' | grep -o 'URI:[^ ,]*' | sed 's/^URI://' | head -n 1)
        crl_file=-
        if [ -n "$crl_url" ]; then
            if tmo 60 curl -sS --max-time 50 --max-filesize 30000000 -o "$d/crl.der" "$crl_url" 2>"$d/crl.err" </dev/null && [ -s "$d/crl.der" ]; then
                crl_file="revocation/$name/crl.der"
            else
                rm -f "$d/crl.der"
            fi
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$fetched" "${ocsp_url:--}" "$ocsp_file" "${crl_url:--}" "$crl_file" "$group" >>"$OUT/revocation/manifest.tsv"
        echo "  $name: OCSP ${ocsp_url:-none} -> $ocsp_file; CRL ${crl_url:-none} -> $crl_file"
    done
    say "B-65: $(grep -vc '^#' "$OUT/revocation/manifest.tsv") chains looked at; $(awk -F'\t' '$4 != "-" && $1 !~ /^#/' "$OUT/revocation/manifest.tsv" | wc -l | tr -d ' ') OCSP responses and $(awk -F'\t' '$6 != "-" && $1 !~ /^#/' "$OUT/revocation/manifest.tsv" | wc -l | tr -d ' ') CRLs kept"
    # each response and list checked by the library at the moment it was fetched, and the candidates for fixtures written
    run_logged "$OUT/revocation.txt" "$FC" revocation "$OUT"
    REVOCATION_RC=$RC
    say "B-65: exit status $REVOCATION_RC; candidates in $OUT/real_revocation/ (tests/data/real_revocation/ keeps a selection of them)"
}

# --- B-66
do_fuzz() {
    hours=${1:-8}
    secs=$(awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }')
    if [ "$secs" -lt 60 ]; then
        echo "HOURS must be at least 0.02 (a minute): got '$hours'" >&2
        exit 2
    fi
    say ""
    say "=== B-66: fuzz campaign, $hours hours ($secs s) on $(uname -m), $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo '?') cores"
    say "started $(date -u '+%Y-%m-%d %H:%M UTC'); Ctrl-C ends it early and keeps what was found."
    if command -v caffeinate >/dev/null 2>&1; then
        caffeinate -i -s -w $$ &
        CAFF=$!
    else
        CAFF=""
    fi
    # Ctrl-C reaches this shell too; with a trap (not an ignore: the fuzzer must be able to trap it itself) this shell waits
    # for the fuzzer to merge what it found instead of dying with it
    trap 'echo "(interrupted: waiting for the fuzzer to merge what it found)"' INT
    cd fuzz || exit 1
    sh run_all.sh "$secs" 2>&1 | tee -i "$ROOT/$OUT/fuzz-console.txt"
    cd "$ROOT" || exit 1
    trap - INT
    [ -n "$CAFF" ] && kill "$CAFF" 2>/dev/null
    [ -f fuzz/fuzz-results.tgz ] && cp fuzz/fuzz-results.tgz "$OUT/fuzz-results.tgz"
    [ -f fuzz/logs/summary.txt ] && cp fuzz/logs/summary.txt "$OUT/fuzz-summary.txt"
    findings=$(find fuzz/artifacts -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "${findings:-0}" -gt 0 ]; then
        say "B-66: FINDINGS: $findings input(s) in fuzz/artifacts/ crashed, hung or ballooned memory. Send field_results.tgz back."
    elif [ -f "$OUT/fuzz-summary.txt" ]; then
        execs=$(awk -F'|' '/^== summary/ { exit } /^\| [a-z_0-9]+ +\|/ && $2 !~ /target/ { v = $4; gsub(/[ ,]/, "", v); if (v ~ /^[0-9]+$/) last[$2] = v } END { s = 0; for (k in last) s += last[k]; print s }' "$OUT/fuzz-console.txt")
        say "B-66: no findings; at least ${execs:-0} executions (only the first process of each target is counted)"
    else
        say "B-66: no summary was written; see $OUT/fuzz-console.txt"
    fi
    say "(the fuzzer's work files can be deleted now: rm -rf fuzz/work fuzz/logs fuzz/logs.prev)"
}

do_package() {
    tar czf "$OUT.tgz" "$OUT" && say "wrote $OUT.tgz ($(wc -c <"$OUT.tgz" | tr -d ' ') bytes): send this back."
}

# --- go
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found on PATH: install Rust with rustup first (https://rustup.rs)" >&2
    exit 1
fi
find_bundle
find_openssl
environment

say "pratique field check, mode $MODE, $(date -u '+%Y-%m-%d %H:%M UTC')"
say "$(cat "$OUT/environment.txt")"

if [ "$MODE" = fuzz ]; then
    do_fuzz "${2:-8}"
    do_package
    exit 0
fi
if [ "$MODE" = package ]; then
    do_package
    exit 0
fi

if [ -z "$BUNDLE" ]; then
    say "no CA bundle found (looked where the library looks); set SSL_CERT_FILE"
    exit 1
fi
if [ -z "$OPENSSL" ]; then
    say "no openssl found"
    exit 1
fi
[ -f "$HOSTS" ] || { say "no hosts file $HOSTS"; exit 1; }
build
check_network

SMOKE_RC=0
VERIFY_RC=0
REVOCATION_RC=0
ROOTS_RC=0
NATIVE_RC=0
TUF_RC=0
QUIC_RC=0
case "$MODE" in
    smoke) do_smoke ;;
    capture) do_capture ;;
    revocation) do_revocation ;;
    roots) do_roots ;;
    native) do_native ;;
    tuf) do_tuf ;;
    quic) do_quic ;;
    all)
        do_smoke
        do_roots
        do_native
        do_capture
        do_revocation
        do_tuf
        do_quic
        ;;
esac

say ""
if [ "$SMOKE_RC" -ne 0 ] || [ "$VERIFY_RC" -ne 0 ] || [ "$REVOCATION_RC" -ne 0 ] || [ "$ROOTS_RC" -ne 0 ] || [ "$NATIVE_RC" -ne 0 ] || [ "$TUF_RC" -ne 0 ] || [ "$QUIC_RC" -ne 0 ]; then
    say "RESULT: something needs a look (smoke status $SMOKE_RC, built-in roots status $ROOTS_RC, native store status $NATIVE_RC, verify status $VERIFY_RC, revocation status $REVOCATION_RC, TUF status $TUF_RC, QUIC status $QUIC_RC). The lines above that say FAIL or NOTE are the items."
else
    say "RESULT: everything that ran passed."
fi
do_package
