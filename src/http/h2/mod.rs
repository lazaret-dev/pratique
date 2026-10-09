//! HTTP/2 (RFC 9113) for the client, in layers that do no I/O: HPACK header compression ([`hpack`]) and its
//! Huffman code ([`huffman`]), the frames ([`frame`]), and the connection state machine ([`connection`]) that puts them together.

pub(crate) mod connection;
pub(crate) mod frame;
#[cfg(pratique_fuzzing)]
pub(crate) mod fuzz_hooks;
pub(crate) mod hpack;
pub(crate) mod huffman;
