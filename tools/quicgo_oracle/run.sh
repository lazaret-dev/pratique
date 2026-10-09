#!/bin/sh
# Makes src/quic/vectors_quicgo_frames.txt and src/quic/vectors_quicgo_params.txt: what quic-go's own frame parser reads from
# payloads that its frame writer made and from the same payloads changed here and there, and what its transport parameter parser
# reads from parameters its writer made (changed too). Nothing from quic-go is
# copied into the repository; its internal/wire package is read from a clone for the run only.
#
#   sh tools/quicgo_oracle/run.sh QUICGO_DIR
#
# QUICGO_DIR is a checkout of github.com/quic-go/quic-go at v0.59.1 (git clone --branch v0.59.1
# --depth 1 https://github.com/quic-go/quic-go).
# The package is built with the Go toolchain in the checkout's own module, so its dependencies must be
# in the module cache (they were for v0.59.1: only golang.org/x/... packages that internal/wire does
# not import, which is why it builds offline). The output is checked in; this is only needed to change it.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
src=$(cd "$1" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R "$src" "$tmp/qg"
# quic-go's own tests need packages (testify) that are not at hand offline; only the oracle runs
rm -f "$tmp/qg/internal/wire/"*_test.go
cp "$repo/tools/quicgo_oracle/frames_oracle_test.go" "$tmp/qg/internal/wire/zz_frames_oracle_test.go"
cp "$repo/tools/quicgo_oracle/params_oracle_test.go" "$tmp/qg/internal/wire/zz_params_oracle_test.go"
(cd "$tmp/qg" && ORACLE_OUT="$tmp/frames.txt" ORACLE_PARAMS_OUT="$tmp/params.txt" go test ./internal/wire -run 'TestZZ' -count=1)
cp "$tmp/frames.txt" "$repo/src/quic/vectors_quicgo_frames.txt"
cp "$tmp/params.txt" "$repo/src/quic/vectors_quicgo_params.txt"
wc -l "$repo/src/quic/vectors_quicgo_frames.txt" "$repo/src/quic/vectors_quicgo_params.txt"
