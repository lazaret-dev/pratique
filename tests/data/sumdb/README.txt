Real data from the Go checksum database, https://sum.golang.org, captured by the author on 2026-10-05
with curl (no proxy tricks, nothing edited):

  latest.txt   the response to GET /latest, a signed tree head: size 66746896
               (about 21:46 UTC)
  lookup.txt   the response to GET /lookup/golang.org/x/mod@v0.17.0 (record 24955599 and a signed tree
               head of size 66746981, a little newer than latest.txt because /latest is cached)
  tile/8/...   the seven hash tiles a Go client reads to check the two heads against each other and
               the record against the newer head (fetched about 22:06 UTC). The list comes from running
               the Go code (golang.org/x/mod 0.22.0, sumdb/tlog) with a logging tile reader. The three
               partial tiles were still served at the widths the tree had.

The key that signs both heads is the one pinned in the Go toolchain; see sumdb::KEY. Used by the tests
in src/sumdb.rs and src/tlog.rs. No secrets are involved: this is public data.
