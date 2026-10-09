#!/bin/sh
# Runs the benchmarks (BACKLOG B-54): examples/bench.rs (the primitives) and examples/bench_net.rs (handshakes, requests,
# small messages and bulk transfers on loopback, against the crate's own server), compares every figure with this
# machine's last recorded one, and records the run in bench/results.tsv.
#
#   sh tools/bench.sh [--quick] [--no-record] [--tsv FILE] [--label NAME]
#
# --quick       a tenth of the network samples (a few seconds instead of about half a minute)
# --no-record   compare, but leave bench/results.tsv alone
# --tsv FILE    also write this run's figures to FILE (what tools/native_check.sh keeps, to send back)
# --label NAME  the machine's name in the results (default: the system, the architecture and the CPU's model, never the
#               host name); runs are compared with earlier runs of the same label
#
# A figure that is more than 15 percent worse than the last one is marked SLOWER. On a shared or virtual machine runs
# differ by 10 to 30 percent, so a mark is a reason to run again before calling it a regression. Release builds, with
# the profile in Cargo.toml (see BENCHMARKS.md); POSIX sh, awk and the Rust toolchain are all it needs.

set -u
cd "$(dirname "$0")/.." || exit 1

QUICK=""
RECORD=1
LABEL=""
COPY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) QUICK="--quick" ;;
        --no-record) RECORD=0 ;;
        --tsv) shift; COPY="${1:-}" ;;
        --label) shift; LABEL="${1:-}" ;;
        *) echo "unknown option $1 (see the top of tools/bench.sh)" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$LABEL" ]; then
    CPU=""
    if [ -r /proc/cpuinfo ]; then
        CPU=$(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: *//')
    elif command -v sysctl >/dev/null 2>&1; then
        CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
    fi
    LABEL="$(uname -s) $(uname -m) ${CPU:-unknown CPU}"
fi

RESULTS=bench/results.tsv
mkdir -p bench
[ -f "$RESULTS" ] || printf 'label\tdate\tfigure\tvalue\tunit\n' >"$RESULTS"
# (this run's figures, until they are compared and recorded: inside the project, like everything else this writes)
RUN="bench/.run-$$.tsv"
: >"$RUN" || exit 1
trap 'rm -f "$RUN"' EXIT

echo "building (release)..."
cargo build --release --example bench >/dev/null 2>&1 || { echo "the build of examples/bench.rs failed: cargo build --release --example bench" >&2; exit 1; }
cargo build --release --features server --example bench_net >/dev/null 2>&1 || { echo "the build of examples/bench_net.rs failed: cargo build --release --features server --example bench_net" >&2; exit 1; }
echo "machine: $LABEL"
echo
./target/release/examples/bench --tsv "$RUN" --label "$LABEL" || exit 1
echo
./target/release/examples/bench_net $QUICK --tsv "$RUN" --label "$LABEL" || exit 1

echo
echo "compared with this machine's last recorded run ($RESULTS):"
awk -F '\t' -v label="$LABEL" '
    FNR == NR { if (FNR > 1 && $1 == label) { last[$3] = $4; when[$3] = $2 } next }
    {
        name = $3; v = $4 + 0; unit = $5
        if (!(name in last)) { printf "  %-60s %10.4g %s  (first run)\n", name, v, unit; next }
        old = last[name] + 0
        if (old == 0) { next }
        # higher is better for rates and throughputs, lower for times
        better_high = (unit == "MB/s" || unit == "per s")
        ratio = better_high ? v / old : old / v
        mark = ratio < 0.85 ? "  SLOWER" : (ratio > 1.15 ? "  faster" : "")
        if (mark == "  SLOWER") slower++
        printf "  %-60s %10.4g -> %-10.4g %s %5.2fx%s\n", name, old, v, unit, ratio, mark
    }
    END {
        if (slower) printf "\n%d figure(s) more than 15%% worse: run again before calling it a regression (runs differ by 10 to 30%% on a shared machine)\n", slower
        else print "\nnothing more than 15% worse"
    }
' "$RESULTS" "$RUN"

if [ -n "$COPY" ]; then
    cp "$RUN" "$COPY" && echo "this run's figures are in $COPY"
fi
if [ "$RECORD" = 1 ]; then
    cat "$RUN" >>"$RESULTS"
    echo "recorded in $RESULTS"
fi
