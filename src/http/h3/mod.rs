//! HTTP/3 (RFC 9114) for the client, in layers that do no I/O: QPACK header compression ([`qpack`], RFC 9204) and, over the
//! transport in [`crate::quic`], the HTTP/3 frames and connection.
//!
//! The layers are built bottom-up and each is tested before the next goes on it. Until the connection uses them they are only
//! reachable from the tests and the fuzzer.

#![allow(dead_code)]

pub(crate) mod connection;
pub(crate) mod frame;
#[cfg(pratique_fuzzing)]
pub(crate) mod fuzz_hooks;
pub(crate) mod qpack;
mod qpack_static;
