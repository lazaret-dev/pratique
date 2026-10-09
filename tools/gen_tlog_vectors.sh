#!/bin/sh
# Regenerates tests/data/tlog_vectors.txt: Merkle inclusion and consistency proofs, valid and
# damaged, made by the Python reference (tools/tlog_vectors.py) and judged by Go's
# golang.org/x/mod/sumdb/tlog (tools/tlog_oracle.go); the script fails if the two disagree.
# tests/go_vectors.rs replays the file against src/tlog.rs.
#
#   sh tools/gen_tlog_vectors.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../tests/data/tlog_vectors.txt"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
python3 "$here/tlog_vectors.py" | timeout 300 sh "$here/go_oracle.sh" "$here/tlog_oracle.go" > "$tmp"
mod=$(grep 'golang.org/x/mod ' "$(go env GOROOT)/src/cmd/vendor/modules.txt" | head -1 | sed 's/^# //')
{
  sed -n 1p "$tmp"
  echo "# $(go version | cut -d' ' -f3-); vendored $mod"
  sed 1d "$tmp"
} > "$out"
wc -c "$out"
