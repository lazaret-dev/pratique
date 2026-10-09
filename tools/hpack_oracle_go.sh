#!/bin/sh
# Runs tools/hpack_oracle.go against the copy of golang.org/x/net/http2/hpack that ships inside the Go
# distribution (GOROOT/src/vendor/...): it is copied, unchanged, into a scratch module, because a program outside
# the standard library may not import a vendored package directly.
#
#   sh tools/hpack_oracle_go.sh gen tests/data/hpack_go.txt
#   sh tools/hpack_oracle_go.sh check corpus.txt
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/hpack"
cp "$(go env GOROOT)"/src/vendor/golang.org/x/net/http2/hpack/*.go "$work/hpack/"
rm -f "$work"/hpack/*_test.go
cp "$here/hpack_oracle.go" "$work/main.go"
printf 'module hpackoracle\n\ngo 1.21\n' > "$work/go.mod"
case "$2" in /*) file=$2 ;; *) file=$(pwd)/$2 ;; esac
cd "$work" && go run . "$1" "$file"
