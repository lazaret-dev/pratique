#!/bin/sh
# Checks the line between the pure verification part of the crate and the `net` part.
#
#   sh tools/check_features.sh            static checks, then the pure build (native and wasm32) and its tests
#   sh tools/check_features.sh --quick    the static checks only (no cargo)
#   sh tools/check_features.sh --require-wasm   fail, instead of skipping, if the wasm32 target is not installed
#
# The rule (BACKLOG B-77): everything outside `net` could move unchanged into a crate with an
# unconditional `#![forbid(unsafe_code)]`, no I/O and no dependencies, and everything behind `net`
# into a second crate that depends on the first. So the files listed in PURE below
#   * contain no `unsafe`, no I/O (std::fs, std::net, std::io, std::env, std::process, std::thread, std::os,
#     std::ffi, std::path, SystemTime, Instant, print macros) and no FFI,
#   * name no Cargo feature and no target (`cfg(feature ..)`, `target_*`, `unix`, `windows`) anywhere,
#     tests included, so any `unsafe` they ever gain is compiled into the no-`net` build, where
#     `forbid(unsafe_code)` rejects it,
#   * never mention a module that is behind `net`,
# and the only places that name a feature are the module declarations in src/lib.rs and src/crypto/mod.rs
# (the `net` feature) and in src/tls/mod.rs and src/http/mod.rs (the opt-in `server` feature, which the test TLS server, its
# certificate writer and the test HTTP/2 server sit behind, and which is off by default) (checked below).
#
# What the compiler does not enforce (no I/O, no clock, no environment) is what the grep checks are for.

set -u
cd "$(dirname "$0")/.." || exit 2

QUICK=0
REQUIRE_WASM=0
for a in "$@"; do
    case "$a" in
    --quick) QUICK=1 ;;
    --require-wasm) REQUIRE_WASM=1 ;;
    -h | --help) sed -n '2,/^$/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
    esac
done

# The pure part. Keep in step with the module declarations in src/lib.rs and src/crypto/mod.rs.
PURE="src/asn1.rs src/ber.rs src/cms.rs src/ct.rs src/pem.rs src/util.rs src/verify_error.rs src/x509.rs src/revocation.rs
src/idna.rs src/inflate.rs src/json.rs src/mozilla_roots.rs src/note.rs src/sigstore.rs src/sumdb.rs src/tlog.rs src/trust_root.rs src/tuf.rs
src/crypto/sha1.rs src/crypto/sha2.rs src/crypto/sha2_consts.rs src/crypto/bignum.rs
src/crypto/rsa.rs src/crypto/ecdsa.rs src/crypto/fe25519.rs src/crypto/ed25519.rs"
# Files that declare modules and so must name the feature; checked separately.
SEAMS="src/lib.rs src/crypto/mod.rs src/tls/mod.rs src/http/mod.rs"

NET_MODULES='tls|http|asyncio|sys|zeroize|error|quic'
NET_CRYPTO='aes|aes_ct|aes_hw|gcm|ghash|poly1305|chacha20poly1305|x25519|x25519_base|ecdsa_hw|ecdh|rand|hmac|sha2_wipe|aead_vectors|ecdh_vectors|timing'

fail=0
bad() {
    echo "FAIL: $*"
    fail=1
}

# The code of a file without its comments, and without the test module at the end.
code_of() {
    awk '/^#\[cfg\(test\)\]/ { exit } { print }' "$1" | sed -e 's://.*$::'
}
whole_of() {
    sed -e 's://.*$::' "$1"
}

echo "== pure files"
for f in $PURE; do
    [ -f "$f" ] || { bad "$f is listed as pure but does not exist"; continue; }
    # The scans below look at the code before the test module, so the test module must be the last
    # thing in the file: one `#[cfg(test)]`, on a `mod`, and nothing but its body after it.
    awk -v file="$f" '
        /^#\[cfg\(test\)\]/ { n++; if (n == 1) { intest = 1; want_mod = 1; next } else { printf "FAIL: %s:%d: a second #[cfg(test)] item\n", file, NR; bad = 1 } }
        intest && want_mod { want_mod = 0; if ($0 !~ /^(pub(\(crate\))? )?mod /) { printf "FAIL: %s:%d: #[cfg(test)] is not on a mod\n", file, NR; bad = 1 }; next }
        intest && /^[^ \t}#\/]/ { printf "FAIL: %s:%d: code after the test module: %s\n", file, NR, $0; bad = 1 }
        END { exit bad }' "$f" || fail=1
    if code_of "$f" | grep -n -E '(^|[^A-Za-z0-9_])unsafe([^A-Za-z0-9_]|$)'; then bad "$f: unsafe"; fi
    if code_of "$f" | grep -n -E 'std::(fs|net|io|env|process|thread|os|ffi|path)|SystemTime|Instant|(^|[^A-Za-z0-9_])(println|eprintln|print|eprint|dbg)!|extern +"|libc::|#\[link'; then
        bad "$f: I/O, clock, environment, threads or FFI"
    fi
    if whole_of "$f" | grep -n -E 'cfg(_attr)?\(.*(feature|target_|unix|windows|portable)'; then bad "$f: cfg names a feature or a target"; fi
    if whole_of "$f" | grep -n -E "crate::($NET_MODULES)(::|;|,|\\}| |\$)|crate::crypto::($NET_CRYPTO)([^A-Za-z0-9_]|\$)|super::($NET_CRYPTO)([^A-Za-z0-9_]|\$)"; then
        bad "$f: mentions something behind net"
    fi
done

echo "== the only places that name the net feature"
for f in $SEAMS; do
    # every `cfg(feature = ..)` line must be an attribute directly on a module declaration or a use/fn item
    awk -v file="$f" '
        /cfg\(.*feature/ && !/^#!\[cfg_attr\(not\(feature = "net"\), forbid\(unsafe_code\)\)\]/ {
            rest = $0
            while (match(rest, /^#\[[^]]*\][ \t]*/)) rest = substr(rest, RLENGTH + 1)
            if (rest == "") { pending = NR; text = $0; next }
            if (rest !~ /^(pub(\(crate\))? )?(mod|use|fn) /) { printf "FAIL: %s:%d: a net cfg that is not on a mod/use/fn: %s\n", file, NR, $0; bad = 1 }
            next
        }
        pending && /^#\[/ { next }
        pending {
            if ($0 !~ /^(pub(\(crate\))? )?(mod|use|fn) /) { printf "FAIL: %s:%d: a net cfg that is not on a mod/use/fn: %s\n", file, pending, text; bad = 1 }
            pending = 0
        }
        END { exit bad }' "$f" || fail=1
done
grep -q '^#!\[cfg_attr(not(feature = "net"), forbid(unsafe_code))\]' src/lib.rs || bad 'src/lib.rs lacks #![cfg_attr(not(feature = "net"), forbid(unsafe_code))]'
# nothing else in the crate may name `feature` except net-side code and tests
n=$(grep -rn -E 'cfg(_attr)?\(.*(^|[^_A-Za-z])feature *=' src | grep -v -E '^src/(lib\.rs|crypto/mod\.rs|tls/mod\.rs|http/mod\.rs|fuzz\.rs):' | wc -l | tr -d ' ')
[ "$n" = "0" ] || { grep -rn -E 'cfg(_attr)?\(.*(^|[^_A-Za-z])feature *=' src | grep -v -E '^src/(lib\.rs|crypto/mod\.rs|tls/mod\.rs|http/mod\.rs|fuzz\.rs):'; bad "feature cfgs outside lib.rs, crypto/mod.rs, tls/mod.rs, http/mod.rs and fuzz.rs"; }

echo "== manifest"
awk '/^\[dependencies\]/ { d = 1; next } /^\[/ { d = 0 } d && NF && $0 !~ /^#/ { bad = 1; print "FAIL: dependency: " $0 } END { exit bad }' Cargo.toml || fail=1
grep -q '^default = \["net"\]' Cargo.toml || bad 'Cargo.toml: default features are not ["net"]'
grep -q '^server = \["net"\]' Cargo.toml || bad 'Cargo.toml: the server feature is missing or does not imply net'

if [ "$fail" != 0 ]; then
    echo
    echo "static checks FAILED"
    exit 1
fi
echo "static checks passed ($(echo $PURE | wc -w | tr -d ' ') pure files)"
[ "$QUICK" = 1 ] && exit 0

command -v cargo >/dev/null 2>&1 || { echo "cargo not found: static checks only"; exit 0; }

echo "== pure build, native (forbid(unsafe_code) is in force)"
cargo build --no-default-features 2>&1 | tail -3
cargo build --no-default-features 2>&1 | grep -q '^warning' && bad "warnings in the pure build"
cargo build --no-default-features --features mozilla-roots 2>&1 | grep -q '^warning' && bad "warnings in the pure build with mozilla-roots"
echo "== pure unit tests"
cargo test --lib --no-default-features 2>&1 | grep -E '^test result|FAILED|panicked' || bad "pure tests did not run"
cargo test --lib --no-default-features 2>&1 | grep -q 'test result: ok' || bad "pure tests failed"

echo "== pure build for wasm32-unknown-unknown (no sockets, no OS)"
if rustc --print target-list 2>/dev/null | grep -q '^wasm32-unknown-unknown$' && cargo check --no-default-features --target wasm32-unknown-unknown 2>&1 | tail -2 | grep -q 'Finished'; then
    echo "wasm32 ok"
elif [ "$REQUIRE_WASM" = 1 ]; then
    bad "the pure build does not compile for wasm32-unknown-unknown (is the target installed? rustup target add wasm32-unknown-unknown)"
else
    echo "skipped: the wasm32-unknown-unknown target is not installed (rustup target add wasm32-unknown-unknown)"
fi

echo "== default build and every target, no warnings"
out=$(cargo check --all-targets 2>&1)
echo "$out" | tail -1
echo "$out" | grep -q '^warning' && bad "warnings in the default build"

if [ "$fail" != 0 ]; then
    echo
    echo "FAILED"
    exit 1
fi
echo
echo "all checks passed (run the net test suites separately: cargo test --lib, cargo test --test interop_openssl, ...)"
