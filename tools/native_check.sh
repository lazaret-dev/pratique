#!/bin/sh
# Runs the whole test suite, the throughput benchmark and the timing-leak tests on THIS machine
# and writes a short report to native_report.txt (full logs in native_check_logs/).
#
#   sh tools/native_check.sh           everything (about 5 minutes the first time, mostly compiling)
#   sh tools/native_check.sh --quick   tests only, no benchmark and no timing runs
#
# Needs only a Rust toolchain (rustup). The OpenSSL interop tests also need an `openssl` whose
# `s_server` speaks TLS 1.3: on macOS the system one is LibreSSL, so the script uses Homebrew's
# `openssl@3` if it is installed and otherwise skips those tests. Nothing is installed or changed
# outside this directory; the only things written are native_report.txt, native_check_logs/ and
# the two build directories (target/ and target-portable/).
#
# Run it from the project root. It uses nothing newer than POSIX sh, so it works with macOS's
# default shell tools.

QUICK=0
[ "$1" = "--quick" ] && QUICK=1

REPORT=native_report.txt
LOGS=native_check_logs
mkdir -p "$LOGS"
: > "$REPORT"
CARGO_TERM_COLOR=never
export CARGO_TERM_COLOR

say() { echo "$*" | tee -a "$REPORT"; }

# run NAME PATTERN COMMAND...  runs COMMAND, keeps the full output in logs/NAME.log and copies the
# lines matching PATTERN into the report, then records the exit status.
run() {
    name=$1
    pattern=$2
    shift 2
    say ""
    say "=== $name"
    if "$@" > "$LOGS/$name.log" 2>&1; then rc=0; else rc=$?; fi
    grep -E "$pattern" "$LOGS/$name.log" | tee -a "$REPORT"
    say "--- $name: exit status $rc"
}

say "pratique native check, $(date -u '+%Y-%m-%d %H:%M UTC')"
say "uname:  $(uname -a)"
if [ -r /proc/cpuinfo ]; then
    say "cpu:    $(grep -m1 -E 'model name|Hardware|CPU part' /proc/cpuinfo)"
elif command -v sysctl >/dev/null 2>&1; then
    say "cpu:    $(sysctl -n machdep.cpu.brand_string 2>/dev/null) ($(sysctl -n hw.ncpu 2>/dev/null) cores)"
fi
if ! command -v cargo >/dev/null 2>&1; then
    say "cargo not found on PATH: install Rust with rustup first (https://rustup.rs)"
    exit 1
fi
say "rustc:  $(rustc --version)"
say "host:   $(rustc -vV | sed -n 's/^host: //p')"

# --- OpenSSL for the interop tests
SKIP_INTEROP=0
if openssl version 2>/dev/null | grep -qi libressl; then
    BREW_OPENSSL=""
    if command -v brew >/dev/null 2>&1; then
        BREW_OPENSSL="$(brew --prefix openssl@3 2>/dev/null)"
    fi
    if [ -n "$BREW_OPENSSL" ] && [ -x "$BREW_OPENSSL/bin/openssl" ]; then
        PATH="$BREW_OPENSSL/bin:$PATH"
        export PATH
    else
        SKIP_INTEROP=1
    fi
fi
if command -v openssl >/dev/null 2>&1; then
    say "openssl: $(openssl version)"
else
    say "openssl: not found"
    SKIP_INTEROP=1
fi

# --- tests
run "unit_tests" "^test result|FAILED|panicked|^error" cargo test --lib
if [ "$SKIP_INTEROP" = 1 ]; then
    say ""
    say "=== interop_openssl: SKIPPED (no OpenSSL with TLS 1.3 s_server; on macOS: brew install openssl@3)"
else
    run "interop_openssl" "^test result|FAILED|panicked|^error" cargo test --test interop_openssl
fi
run "system_roots" "certs,|^test result|FAILED|panicked|^error" cargo test --test system_roots -- --nocapture
# the operating system's own store (B-101): on macOS the Keychain trust settings, compared with the system roots keychain
# (by the test) and with /etc/ssl/cert.pem (by the example); elsewhere the test checks that there is none
run "native_roots" "roots trusted|left out|system roots keychain|^test result|FAILED|panicked|^error" cargo test --test native_roots -- --nocapture
if [ "$(uname)" = Darwin ]; then
    run "native_vs_cert_pem" "native store|compared with|only in|left out|^error" cargo run --example native_roots -- --compare /etc/ssl/cert.pem
fi
run "doc_tests" "^test result|FAILED|^error" cargo test --doc
run "warnings" "warning|^error|Finished" cargo build --release --examples

if [ "$QUICK" = 1 ]; then
    say ""
    say "(--quick: benchmark and timing runs skipped)"
    say "report written to $REPORT"
    exit 0
fi

# --- the benchmarks (B-54): the primitives and, on loopback, handshakes, requests, small messages and bulk transfers, each
# figure compared with this machine's last recorded run in bench/results.tsv (if there is one); the figures are kept in
# native_check_logs/bench.tsv, to send back. bench/results.tsv itself is not changed.
run "bench" "MB/s|ms|per s|backend|SLOWER|faster|more than 15" sh tools/bench.sh --no-record --tsv "$LOGS/bench.tsv"
# the portable path (no vector code) on the primitives, to compare with the default build's
RUSTFLAGS="--cfg pratique_portable"
export RUSTFLAGS
run "bench_portable" "MB/s|ms|backend" cargo run --release --example bench --target-dir target-portable
unset RUSTFLAGS

# --- timing-leak tests (each takes 10 to 60 seconds; they need a quiet machine; "harness" includes the negative control that
# compares identical classes and must report nothing). The library sets ARM's data-independent timing mode around its secret
# arithmetic where the CPU has it (BACKLOG B-99). The last two pass or fail nothing: `dit` measures the comparisons an Apple M5
# flagged with the library's mode held off and then on, and `operand_probe` asks whether the CPU takes longer for some operand
# values than for others; on a CPU without the mode they say so.
for t in harness x25519 ecdh ghash poly1305 aead_and_mac aes dit operand_probe; do
    run "timing_$t" "\\|t\\||panicked|^test result|timing depends|same statistic|did not notice|DIT|largest" \
        cargo test --release --lib "crypto::timing::$t" -- --ignored --nocapture --test-threads=1
done

say ""
say "report written to $REPORT (full logs in $LOGS/)"
