#!/bin/bash
# Four judges of certificate chains, side by side (BACKLOG B-92, part 3): this library, OpenSSL, Go's crypto/x509 and, on a
# Mac, Apple's own verifier (`security verify-cert`: the Security framework that Safari and the Mac's apps use). For every
# chain in a directory laid out as tests/data/chain_cases and tests/data/real_chains are (fixtures.tsv, chains/NAME.pem, the
# anchors' files), each says whether the chain verifies as a TLS server's for the case's host at the case's time, against
# that case's anchors alone. Where they differ is where the review of B-23 should look first.
#
#   tools/chain_judges.sh            the generated cases (tests/data/chain_cases: chains that each differ from a good one in
#                                    one thing; tools/gen_chain_cases.py) and the real chains captured on the Mac
#                                    (tests/data/real_chains)
#   tools/chain_judges.sh DIR...     other directories in that layout (a fresh capture's field_results/real_chains, say)
#
# It writes field_results/chain_judges/ (a table of verdicts for each directory, and report.txt with every disagreement and
# each judge's reason) and field_results/chain_judges.tgz, which is what to send back (CHAIN_OUT=DIR writes DIR and DIR.tgz
# instead). It changes nothing else on the machine and needs no network.
#
# Needs cargo; Go 1.21 or later (`brew install go`); OpenSSL 3 (`brew install openssl@3`: the openssl that comes with macOS
# is LibreSSL, which is not one of the judges here; OPENSSL=/path/to/openssl picks another). A judge that is missing is left
# out, and the report says so. OpenSSL is run with -x509_strict (as Python's ssl module has it since 3.13).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
OUT=${CHAIN_OUT:-field_results/chain_judges}
case "$OUT" in "" | "/" | "." | "..") echo "CHAIN_OUT must be a directory of its own, not '$OUT'" >&2; exit 2 ;; esac
if [ $# -gt 0 ]; then DIRS="$*"; else DIRS="tests/data/chain_cases tests/data/real_chains"; fi
rm -rf "$OUT" "$OUT.tgz"
mkdir -p "$OUT/raw" "$OUT/work"
W=$OUT/work
JUDGES=""
NOTES=""
note() { echo "$*"; NOTES="$NOTES$*
"; }

# --- the judges that are here
echo "building the library's judge..."
if cargo build --release --example chain_judge 2>&1 | tail -1 && [ -x target/release/examples/chain_judge ]; then
    JUDGES="pratique"
else
    echo "the library's judge did not build" >&2
    exit 1
fi
if command -v go > /dev/null 2>&1 && go build -o "$W/chain_judge_go" tools/chain_judge.go 2> "$W/go_build.txt"; then
    JUDGES="$JUDGES go"
    note "go: $(go version)"
else
    note "go: not used ($(command -v go > /dev/null 2>&1 && head -3 "$W/go_build.txt" || echo 'not found: brew install go'))"
fi
if [ -z "${OPENSSL:-}" ]; then
    for p in "$(brew --prefix openssl@3 2> /dev/null)/bin/openssl" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl "$(command -v openssl)"; do
        if [ -x "$p" ] && "$p" version 2> /dev/null | grep -q '^OpenSSL 3'; then OPENSSL=$p; break; fi
    done
fi
if [ -n "${OPENSSL:-}" ] && "$OPENSSL" version 2> /dev/null | grep -q '^OpenSSL 3'; then
    JUDGES="$JUDGES openssl"
    note "openssl: $("$OPENSSL" version) ($OPENSSL), with -x509_strict"
else
    note "openssl: not used (no OpenSSL 3 found: brew install openssl@3, or OPENSSL=/path/to/openssl)"
fi
APPLE_NAME=-n
if [ "$(uname -s)" = Darwin ] && [ -x /usr/bin/security ]; then
    JUDGES="$JUDGES apple"
    note "apple: security verify-cert, macOS $(sw_vers -productVersion 2> /dev/null) ($(uname -m)), policy ssl, local certificates only"
else
    note "apple: not used (not a Mac)"
fi
note "judges: $JUDGES"

TAB=$(printf '\t')
is_ip() { echo "$1" | grep -qE '^[0-9]+(\.[0-9]+){3}$|:'; }

# split_pem FILE DIR: each certificate of a PEM file into DIR/01.pem, DIR/02.pem, ...
split_pem() {
    rm -rf "$2"
    mkdir -p "$2"
    awk -v d="$2" '/-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%02d.pem", d, n) } n && f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$1"
}

cases() { grep -v '^#' "$1/fixtures.tsv" | awk -F'\t' 'NF >= 5'; }

openssl_judge() {
    D=$1
    cases "$D" | while IFS="$TAB" read -r name host time expect anchor rest; do
        split_pem "$D/chains/$name.pem" "$W/c"
        set -- "$W"/c/*.pem
        leaf=$1
        shift
        : > "$W/untrusted.pem"
        for c in "$@"; do cat "$c" >> "$W/untrusted.pem"; done
        if [ "$anchor" = - ]; then : > "$W/anchors.pem"; else cp "$D/$anchor" "$W/anchors.pem"; fi
        hostflag=-verify_hostname
        is_ip "$host" && hostflag=-verify_ip
        if [ -s "$W/untrusted.pem" ]; then
            out=$("$OPENSSL" verify -attime "$time" -purpose sslserver -x509_strict -no-CApath -no-CAstore -CAfile "$W/anchors.pem" \
                -untrusted "$W/untrusted.pem" "$hostflag" "$host" "$leaf" 2>&1)
        else
            out=$("$OPENSSL" verify -attime "$time" -purpose sslserver -x509_strict -no-CApath -no-CAstore -CAfile "$W/anchors.pem" \
                "$hostflag" "$host" "$leaf" 2>&1)
        fi
        if [ $? -eq 0 ]; then
            printf '%s\tok\n' "$name"
        else
            why=$(echo "$out" | grep -m1 -iE '^error|unable|Could not|wrong' | tr '\t\n' '  ')
            printf '%s\tno\t%s\n' "$name" "${why:-$(echo "$out" | tail -1 | tr '\t' ' ')}"
        fi
    done
}

apple_judge() {
    D=$1
    cases "$D" | while IFS="$TAB" read -r name host time expect anchor rest; do
        split_pem "$D/chains/$name.pem" "$W/c"
        args="verify-cert -p ssl -L -d $(perl -MPOSIX -e 'print strftime("%Y-%m-%d-%H:%M:%S", gmtime($ARGV[0]))' "$time")"
        for c in "$W"/c/*.pem; do args="$args -c $c"; done
        if [ "$anchor" != - ]; then
            split_pem "$D/$anchor" "$W/a"
            for a in "$W"/a/*.pem; do args="$args -r $a"; done
        fi
        # (the paths are the script's own and have no spaces; the host goes in as one word)
        out=$(/usr/bin/security $args $APPLE_NAME "$host" 2>&1)
        rc=$?
        if [ $rc -ne 0 ] && [ "$APPLE_NAME" = -n ] && echo "$out" | grep -qiE 'illegal option|unknown option|usage'; then
            APPLE_NAME=-s
            out=$(/usr/bin/security $args $APPLE_NAME "$host" 2>&1)
            rc=$?
        fi
        if [ $rc -eq 0 ]; then
            printf '%s\tok\n' "$name"
        else
            # (the whole message without its colours; the line on Certificate Transparency that every failure ends with goes last,
            # since it is not the reason unless it is the only line)
            clean=$(echo "$out" | perl -pe 's/\e\[[0-9;]*m//g' | grep -v '^[[:space:]]*$')
            why=$( (echo "$clean" | grep -v 'Certificate Transparency'; echo "$clean" | grep 'Certificate Transparency') | tr '\t\n' ' |' | cut -c1-400)
            printf '%s\tno\t%s\n' "$name" "$why"
        fi
    done
}

for D in $DIRS; do
    D=${D%/}
    if [ ! -f "$D/fixtures.tsv" ]; then
        note "skipped $D: it has no fixtures.tsv"
        continue
    fi
    tag=$(echo "$D" | tr '/' '_')
    n=$(cases "$D" | wc -l | tr -d ' ')
    echo "== $D: $n chains"
    for j in $JUDGES; do
        printf '   %-9s' "$j"
        case $j in
            pratique) target/release/examples/chain_judge "$D" > "$OUT/raw/$tag.$j.tsv" ;;
            go) "$W/chain_judge_go" "$D" > "$OUT/raw/$tag.$j.tsv" ;;
            openssl) openssl_judge "$D" > "$OUT/raw/$tag.$j.tsv" ;;
            apple) apple_judge "$D" > "$OUT/raw/$tag.$j.tsv" ;;
        esac
        echo "$(grep -c "${TAB}ok\$" "$OUT/raw/$tag.$j.tsv") accepted, $(grep -c "${TAB}no${TAB}" "$OUT/raw/$tag.$j.tsv") refused"
    done
    echo "$D" >> "$OUT/dirs.txt"
done
[ -f "$OUT/dirs.txt" ] || { echo "nothing was judged"; exit 1; }
printf '%s' "$NOTES" > "$OUT/judges.txt"
rm -rf "$W"

# --- the table and the report
python3 - "$OUT" "$JUDGES" << 'PY'
import os, sys

out, judges = sys.argv[1], sys.argv[2].split()
lines = []
def say(s=""):
    lines.append(s)

say("Chain judges (tools/chain_judges.sh, BACKLOG B-92 part 3)")
say(open(os.path.join(out, "judges.txt")).read().rstrip())
for d in open(os.path.join(out, "dirs.txt")).read().split():
    tag = d.replace("/", "_")
    fixtures = []
    for l in open(os.path.join(d, "fixtures.tsv")):
        if l.startswith("#") or not l.strip():
            continue
        c = l.rstrip("\n").split("\t")
        if len(c) < 5:
            continue
        expect = "refuse" if c[3].startswith("refuse") else c[3]
        fixtures.append((c[0], c[1], expect, c[5] if len(c) > 5 else ""))
    verdict = {}
    for j in judges:
        v = {}
        path = os.path.join(out, "raw", f"{tag}.{j}.tsv")
        if os.path.exists(path):
            for l in open(path):
                c = l.rstrip("\n").split("\t")
                v[c[0]] = (c[1], c[2] if len(c) > 2 else "")
        verdict[j] = v
    with open(os.path.join(out, f"{tag}.tsv"), "w") as t:
        t.write("name\thost\texpect\t" + "\t".join(judges) + "\twhat\n")
        for name, host, expect, what in fixtures:
            t.write(f"{name}\t{host}\t{expect}\t" + "\t".join(verdict[j].get(name, ("-", ""))[0] for j in judges) + f"\t{what}\n")

    def row(name, host, expect, what):
        parts = []
        for j in judges:
            v, why = verdict[j].get(name, ("-", ""))
            parts.append(f"{j} {v}" + (f" ({why[:300]})" if v == "no" else ""))
        return f"  {name} [{host}, expect {expect}]" + (f": {what}" if what else "") + "\n      " + "\n      ".join(parts)

    say()
    say(f"== {d}: {len(fixtures)} chains")
    # (two cases that show whether a judge was asked the question at all: a plain good chain, and one for another host)
    for j in judges:
        names = verdict[j]
        if names.get("ok_ec", ("ok",))[0] == "no":
            say(f"  WARNING: {j} refused the plain good chain (ok_ec): its column says more about how it was called than about it: {names['ok_ec'][1][:200]}")
        if names.get("refuse_host_mismatch", ("no",))[0] == "ok":
            say(f"  WARNING: {j} accepted a chain for another host (refuse_host_mismatch): it was not given the host name to check")
    firm = [f for f in fixtures if f[2] in ("ok", "refuse")]
    for j in judges:
        agree = sum(1 for n, h, e, w in firm if verdict[j].get(n, ("-",))[0] == ("ok" if e == "ok" else "no"))
        say(f"  {j:9} agrees with the expectation on {agree} of {len(firm)} (and judged {len(verdict[j])} chains in all)")
    wrong = [f for f in firm if verdict["pratique"].get(f[0], ("-",))[0] != ("ok" if f[2] == "ok" else "no")]
    say()
    say(f"-- the library against the expectation: {len(wrong)} case(s)" + ("" if wrong else ", none"))
    for f in wrong:
        say(row(*f))
    split = [f for f in fixtures if len({verdict[j].get(f[0], ("-",))[0] for j in judges if f[0] in verdict[j]}) > 1]
    say()
    say(f"-- the judges differ: {len(split)} case(s)" + ("" if split else ", none"))
    for f in split:
        say(row(*f))
    either = [f for f in fixtures if f[2] == "either" and f not in split]
    if either:
        say()
        say(f"-- the cases left to the verifier, where all the judges agree: {len(either)}")
        for name, host, expect, what in either:
            say(f"  {name}: all {verdict['pratique'].get(name, ('-',))[0]}")
report = "\n".join(lines) + "\n"
open(os.path.join(out, "report.txt"), "w").write(report)
print(report)
PY
tar czf "$OUT.tgz" "$OUT" && echo "wrote $OUT.tgz: send it back"
