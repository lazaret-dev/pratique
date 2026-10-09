//! QUIC (RFC 9000, 9001, 9002), the transport under HTTP/3, written from the RFCs like the rest of
//! this crate and checked against their appendix vectors and against aioquic.
//!
//! This is built bottom-up, each layer tested before the next goes on it:
//!
//! * [`wire`]: variable-length integers, packet-number truncation and recovery.
//! * [`packet`]: long and short headers, coalesced datagrams, Retry and Version Negotiation.
//! * [`frame`]: the frames of a packet, read and written.
//! * [`keys`]: keys from secrets, header protection, the AEAD, key update, Initial keys, the Retry tag.
//! * [`transport_params`]: the transport parameters of RFC 9000 section 18, read, checked and written.
//! * [`tls`]: the TLS 1.3 client as QUIC uses it (CRYPTO frames, no records, ALPN required, transport parameters in an extension).
//! * [`rangeset`], [`sendbuf`], [`reassembly`]: the buffers: sets of numbers as the fewest ranges, what a stream has to send (and
//!   may have to send again), and what it has received out of order.
//! * [`congestion`] and [`recovery`]: RFC 9002, the round-trip estimate, loss detection, the probe timeout, NewReno and the pacer.
//! * [`streams`]: streams and their flow control, both directions, the limits on how many may be open.
//! * [`connection`]: the client connection that puts all of it together.
//!
//! Version 1 only. Nothing here does I/O or reads a clock.
//!
//! The parts that keep state are fuzzed against models of themselves (the `quic_*` targets of the `fuzz` crate); a build with
//! `--cfg pratique_fuzzing` also has `fuzz_hooks`, which runs a whole connection against a test server over a bad network.

pub mod congestion;
pub mod connection;
pub mod frame;
pub mod keys;
pub mod packet;
pub mod rangeset;
pub mod reassembly;
pub mod recovery;
pub mod sendbuf;
pub mod streams;
// the test peer and the test server are used by the fuzzer as well (`fuzz_hooks`; the fuzz crate always has the `server` feature on,
// which the certificates of the test peer need)
#[cfg(any(test, pratique_fuzzing))]
mod test_peer;
#[cfg(any(test, pratique_fuzzing))]
mod test_server;
#[cfg(pratique_fuzzing)]
#[doc(hidden)]
pub mod fuzz_hooks;
pub mod tls;
pub mod transport_params;
#[cfg(test)]
mod vectors;
#[cfg(test)]
mod vectors_aioquic;
pub mod wire;
