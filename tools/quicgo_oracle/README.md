# quic-go frame oracle

`frames_oracle_test.go` is a Go test that is run inside a copy of quic-go's `internal/wire` package
(`run.sh` does that). It writes frames with quic-go's writer, changes them, and records what quic-go's parser
reads from each payload (the frames, and `ERR` where it stops). The Rust test
`payloads_are_read_as_quic_go_reads_them` in `src/quic/frame.rs` reads the same payloads with the crate's own codec
and has to give the same answer, frame for frame; and writes each frame it reads back byte for byte.

quic-go's parser leaves out one rule of RFC 9000 (a frame type in the fewest bytes, section 12.4); the oracle adds
it, so the two agree on that. Everything else is quic-go as it is.

    git clone --branch v0.59.1 --depth 1 https://github.com/quic-go/quic-go /tmp/quic-go
    sh tools/quicgo_oracle/run.sh /tmp/quic-go

The output (`src/quic/vectors_quicgo_frames.txt`, 1745 payloads) is checked in, so the test needs no Go toolchain.
