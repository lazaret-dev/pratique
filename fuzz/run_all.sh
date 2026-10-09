#!/bin/sh
# Builds the fuzzer and runs a campaign over every target in parallel.
#
#   sh run_all.sh [SECONDS] [JOBS]     fuzz for SECONDS in total (default 600) using JOBS processes
#                                       (default: one per core); examples:  sh run_all.sh 3600
#   sh run_all.sh build                 only build
#   sh run_all.sh check                 only build and check that coverage feedback works
#   sh run_all.sh replay TARGET FILE... run saved inputs (for example artifacts/chain/crash-*) once
#   sh run_all.sh regen                 regenerate src/seed_data.rs after adding fixtures to ../tests/data
#
# Every target gets at least one process; spare cores go to the targets that find the most. The
# campaign runs in rounds (FUZZ_ROUND seconds, default 600): after each one the workers' corpora are
# merged into corpus/TARGET, so a find by one worker feeds all the others in the next round.
#
# Ctrl-C stops the workers, merges what they found and prints the summary. (A shell starts background
# jobs with SIGINT ignored, so without this handler Ctrl-C would stop the script and leave every
# worker running.) If an older copy of this script was interrupted, `pkill -f pratique_fuzz`.
#
# Results (all under this directory):
#   corpus/TARGET/      the minimal set of inputs that reach everything found so far (keep it: the next
#                       run starts from it; check it in if you like)
#   artifacts/TARGET/   inputs that crashed, hung or ballooned memory; there should be none (a run moves
#                       an earlier run's findings to artifacts.prev/ first)
#   logs/               what each process printed, and summary.txt
#   fuzz-results.tgz    summary + artifacts + corpus, to send back
#
# Needs a Rust toolchain (stable is enough) and a Unix shell. The coverage counters come from
# LLVM through the RUSTFLAGS below; no nightly compiler, cargo-fuzz or libFuzzer.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE" || exit 1

FLAGS="--cfg pratique_fuzzing -C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-inline-8bit-counters"
BIN="$HERE/target/release/pratique_fuzz"
# the targets that gain most from extra processes, in the order they receive them
HEAVY="tls_flight tls12_flight chain chain_algs purpose_chain revocation_path tls_records ocsp crl certificate tls_post http_response sigstore"

build() {
    RUSTFLAGS="$FLAGS" cargo build --release || {
        echo "the build failed" >&2
        exit 1
    }
}

cpus() {
    nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2
}

regen() {
    out=src/seed_data.rs
    {
        echo "//! Fixture bytes embedded in the fuzzer (generated from ../tests/data by \`sh run_all.sh regen\`)."
        echo
        for set in "OCSP rev_ocsp_ der" "CRL rev_crl_ der" "PEM '' pem"; do
            eval set -- "$set"
            name=$1 prefix=$2 ext=$3
            echo "pub static $name: &[(&str, &[u8])] = &["
            for f in ../tests/data/${prefix}*.$ext; do
                b=$(basename "$f")
                echo "    (\"$b\", include_bytes!(\"../../tests/data/$b\")),"
            done
            echo "];"
            echo
        done
    } >"$out"
    echo "wrote $out"
}

campaign() {
    SECS=${1:-600}
    CPUS=${2:-$(cpus)}
    ROUND=${FUZZ_ROUND:-600}
    build
    "$BIN" check || {
        echo >&2
        echo "The coverage check failed, so a campaign would only be blind random testing." >&2
        echo "Please send the output above back." >&2
        exit 1
    }
    TARGETS=$("$BIN" list)
    N=$(echo "$TARGETS" | wc -l | tr -d ' ')
    stray=$(pgrep -f 'pratique_fuzz (run|child) ' 2>/dev/null | wc -l | tr -d ' ')
    if [ "${stray:-0}" -gt 0 ] && [ -z "${FUZZ_FORCE:-}" ]; then
        echo "$stray fuzzer processes from an earlier run are still running; they would compete for the cores." >&2
        echo "Stop them with:  pkill -f pratique_fuzz   (or set FUZZ_FORCE=1 to start anyway)" >&2
        exit 1
    fi
    # keep the previous run's logs for a look, but do not mix them with this one's
    rm -rf logs.prev
    [ -d logs ] && mv logs logs.prev
    # Findings of an earlier run were reported then (and are in its fuzz-results.tgz): keep them apart,
    # so that this run's summary lists only what this run found.
    if [ -d artifacts ] && [ -n "$(find artifacts -type f 2>/dev/null | head -n 1)" ]; then
        rm -rf artifacts.prev
        mv artifacts artifacts.prev
        echo "findings from an earlier run moved to artifacts.prev/"
    fi
    mkdir -p work corpus artifacts logs
    for t in $TARGETS; do
        mkdir -p "work/$t" "corpus/$t" "artifacts/$t"
        echo 1 >"work/$t/.n"
    done
    extra=$((CPUS - N))
    while [ "$extra" -gt 0 ]; do
        for t in $HEAVY; do
            [ "$extra" -le 0 ] && break
            n=$(cat "work/$t/.n")
            echo $((n + 1)) >"work/$t/.n"
            extra=$((extra - 1))
        done
    done
    echo "campaign: $SECS s on $CPUS cores, $N targets, rounds of $ROUND s (Ctrl-C stops early and keeps the results)"

    START=$(date +%s)
    ROUNDNO=0
    PIDS=""
    : >logs/merge.log
    trap interrupted INT TERM
    while :; do
        NOW=$(date +%s)
        LEFT=$((SECS - (NOW - START)))
        [ "$LEFT" -le 0 ] && break
        R=$ROUND
        [ "$LEFT" -lt "$R" ] && R=$LEFT
        # a last round shorter than half a minute is folded into this one
        [ $((LEFT - R)) -lt 30 ] && R=$LEFT
        ROUNDNO=$((ROUNDNO + 1))
        PIDS=""
        for t in $TARGETS; do
            n=$(cat "work/$t/.n")
            w=1
            while [ "$w" -le "$n" ]; do
                d="work/$t/w$w"
                mkdir -p "$d"
                cp -n "corpus/$t"/* "$d"/ 2>/dev/null
                "$BIN" run "$t" --corpus "$d" --artifacts "artifacts/$t" --seconds "$R" --seed $((ROUNDNO * 1000 + w)) >>"logs/$t-w$w.log" 2>&1 &
                PIDS="$PIDS $!"
                w=$((w + 1))
            done
        done
        echo "round $ROUNDNO: $R s"
        tick=0
        while :; do
            alive=0
            for p in $PIDS; do kill -0 "$p" 2>/dev/null && alive=1; done
            [ "$alive" -eq 0 ] && break
            sleep 5
            tick=$((tick + 1))
            [ $((tick % (${FUZZ_REPORT:-60} / 5))) -eq 0 ] && progress
        done
        wait
        PIDS=""
        merge_all
    done
    finish
}

# One table of where each target stands (the first process of each target reports for it).
# Markdown-style, numbers right-aligned.
progress() {
    echo
    echo "$(date +%H:%M:%S)  round $ROUNDNO, $(($(date +%s) - START)) of $SECS s"
    printf '| %-16s | %5s | %15s | %8s | %8s | %9s | %7s | %5s | %8s |\n' target procs execs edges corpus exec/s crashes bloat "last new"
    echo '| ---------------- | ----: | --------------: | -------: | -------: | --------: | ------: | ----: | -------: |'
    for t in $TARGETS; do
        line=$(grep "^fuzz\[$t\]: #" "logs/$t-w1.log" 2>/dev/null | tail -n 1)
        if [ -z "$line" ]; then
            printf '| %-16s | %5s | %15s | %8s | %8s | %9s | %7s | %5s | %8s |\n' "$t" "$(cat "work/$t/.n")" starting - - - - - -
            continue
        fi
        echo "$line" | awk -v t="$t" -v n="$(cat "work/$t/.n")" '
            function commas(s,   r) { r = ""; while (length(s) > 3) { r = "," substr(s, length(s) - 2) r; s = substr(s, 1, length(s) - 3) } return s r }
            { sub(/^#/, "", $2)
              printf "| %-16s | %5s | %15s | %8s | %8s | %9s | %7s | %5s | %8s |\n", t, n, commas($2), commas($4), commas($6), commas($8), $10, $12, $16 " s" }'
    done
}

merge_all() {
    for t in $TARGETS; do
        "$BIN" merge "$t" --into "corpus/$t" work/"$t"/w* >>logs/merge.log 2>&1
    done
}

finish() {
    rm -f artifacts/*/.current-* artifacts/*/.reason-*
    summary | tee logs/summary.txt
    tar czf fuzz-results.tgz logs/summary.txt artifacts corpus 2>/dev/null && echo "wrote fuzz-results.tgz"
}

interrupted() {
    trap '' INT TERM
    echo
    echo "interrupted: stopping the workers and merging what they found"
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    sleep 1
    wait
    merge_all
    finish
    exit 130
}

summary() {
    echo
    echo "== summary ($(date))"
    printf '| %-16s | %8s | %8s | %8s |\n' target corpus edges findings
    echo '| ---------------- | -------: | -------: | -------: |'
    found=0
    for t in $("$BIN" list); do
        c=$(ls "corpus/$t" 2>/dev/null | wc -l | tr -d ' ')
        a=$(ls "artifacts/$t" 2>/dev/null | wc -l | tr -d ' ')
        e=$(grep "^fuzz\[$t\]: .* kept" logs/merge.log 2>/dev/null | tail -n 1 | sed 's/.*(\([0-9]*\) edges).*/\1/')
        printf '| %-16s | %8s | %8s | %8s |\n' "$t" "$c" "${e:-?}" "$a"
        [ "$a" -gt 0 ] && found=1
    done
    if [ "$found" -eq 1 ]; then
        echo
        echo "findings (each file is the input that triggered it):"
        for f in artifacts/*/*; do
            [ -f "$f" ] && echo "  $f"
        done
        echo
        echo "reproduce one with:  sh run_all.sh replay TARGET FILE"
        echo "what happened is in logs/*.log (search for PANIC, TIMEOUT, BLOAT or CRASH)"
    else
        echo
        echo "no findings."
    fi
}

case "${1:-}" in
build) build ;;
check)
    build
    "$BIN" check
    ;;
replay)
    shift
    build
    "$BIN" replay "$@"
    ;;
regen) regen ;;
-h | --help | help) sed -n '2,/^set -u/p' "$0" | sed '$d' ;;
*) campaign "$@" ;;
esac
