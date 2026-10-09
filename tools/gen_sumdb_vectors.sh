#!/bin/sh
# Regenerates tests/data/sumdb_vectors.txt: signed notes, tree heads and lookup records, damaged in
# random (but seeded, so reproducible) ways, each with the verdict of Go's golang.org/x/mod/sumdb
# packages. tests/go_vectors.rs replays them against src/note.rs and src/sumdb.rs.
#
#   sh tools/gen_sumdb_vectors.sh
#
# Needs a Go toolchain (see tools/go_oracle.sh). Rerun only to widen the coverage; the verdicts must
# not change for a given seed unless Go's behaviour does.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../tests/data/sumdb_vectors.txt"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
sh "$here/go_oracle.sh" "$here/sumdb_vectors.go" > "$tmp"
mod=$(grep 'golang.org/x/mod ' "$(go env GOROOT)/src/cmd/vendor/modules.txt" | head -1 | sed 's/^# //')
{
  sed -n 1p "$tmp"
  echo "# $(go version | cut -d' ' -f3-); vendored $mod"
  sed 1d "$tmp"
} > "$out"
wc -c "$out"
