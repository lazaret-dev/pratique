#!/bin/sh
# Runs a Go program against the sumdb packages of the local Go toolchain (golang.org/x/mod's
# sumdb/note and sumdb/tlog, vendored under cmd/vendor in GOROOT) as an independent reference
# implementation. Nothing from Go is copied into the repository: the packages are copied into a
# temporary module for the run.
#
#   sh tools/go_oracle.sh PROGRAM.go [args...]     stdin, stdout and stderr pass through; the
#                                                  program finds the repository in $REPO and
#                                                  can import "oracle/note" and "oracle/tlog"
#
# Caution: the tlog package of x/mod before v0.40.0 (Go before 1.25.13) does not authenticate every
# tile (CVE-2026-56865). Use it as an oracle for the note format, record and tree parsing and the
# proof checks, not for tile authentication.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
prog=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
shift
src="$(go env GOROOT)/src/cmd/vendor/golang.org/x/mod/sumdb"
[ -d "$src" ] || { echo "go_oracle.sh: no vendored golang.org/x/mod/sumdb in $(go env GOROOT)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tlog" "$tmp/note"
cp "$src"/tlog/*.go "$tmp/tlog/"
cp "$src"/note/*.go "$tmp/note/"
printf 'module oracle\n\ngo 1.21\n' > "$tmp/go.mod"
cp "$prog" "$tmp/main.go"
cd "$tmp"
REPO="$repo" go run . "$@"
