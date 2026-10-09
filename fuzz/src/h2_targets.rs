//! The fuzz targets of the HTTP/2 layers (B-72): `h2_hpack`, `h2_frames`, `h2_client` and `h2_server`. They reach the
//! `pub(crate)` layers through `pratique::http::fuzz_hooks`, which holds the properties (see
//! `src/http/h2/fuzz_hooks.rs`):
//!
//! | target       | what must hold |
//! |--------------|----------------|
//! | `h2_hpack`   | a header block decodes or is refused, never a panic, whatever the table size and the limit; a list that decoded within the limit is written by our encoder (sensitive or not, twice on one table) and read back by a fresh decoder as the same list |
//! | `h2_frames`  | frames cut from the bytes parse or are refused, and the pieces of a frame that parsed lie within its payload |
//! | `h2_client`  | the client's connection fed what a server might send, in pieces of 1 to 200 bytes, with windows from 1000 bytes to 32 MiB, and with bodies read in pieces, collected whole (with a limit as small as 100 bytes) or switched to collecting half way: the flow-control books balance after every step; a collected body is within its limit; what the client writes is the preface and whole frames that parse, and its header blocks decode; when the transport is lost every stream ends or fails, and nothing is left once they are released |
//! | `h2_server`  | the server's connection fed what a client might send: no panic, and what it writes is whole frames that parse |

use pratique::http::fuzz_hooks;

/// The frames that open a connection, a header block, and the other things the frame layer has a form for.
pub const H2_DICT: &[&[u8]] = &[
    // SETTINGS (empty, and acknowledgment), PING, GOAWAY, WINDOW_UPDATE for the connection and stream 1, RST_STREAM
    b"\x00\x00\x00\x04\x00\x00\x00\x00\x00",
    b"\x00\x00\x00\x04\x01\x00\x00\x00\x00",
    b"\x00\x00\x08\x06\x00\x00\x00\x00\x00",
    b"\x00\x00\x08\x07\x00\x00\x00\x00\x00",
    b"\x00\x00\x04\x08\x00\x00\x00\x00\x00",
    b"\x00\x00\x04\x08\x00\x00\x00\x00\x01",
    b"\x00\x00\x04\x03\x00\x00\x00\x00\x01",
    // HEADERS with END_HEADERS (and END_STREAM), CONTINUATION, DATA (and with END_STREAM), PADDED
    b"\x00\x00\x01\x01\x04\x00\x00\x00\x01",
    b"\x00\x00\x01\x01\x05\x00\x00\x00\x01",
    b"\x00\x00\x01\x09\x04\x00\x00\x00\x01",
    b"\x00\x00\x05\x00\x00\x00\x00\x00\x01",
    b"\x00\x00\x05\x00\x01\x00\x00\x00\x01",
    b"\x00\x00\x05\x00\x08\x00\x00\x00\x01",
    // PRIORITY, PUSH_PROMISE
    b"\x00\x00\x05\x02\x00\x00\x00\x00\x01",
    b"\x00\x00\x04\x05\x04\x00\x00\x00\x01",
    // HPACK: :status 200, 404 (indexed), a literal with incremental indexing, a table size update, a Huffman string
    b"\x88",
    b"\x8d",
    b"\x40",
    b"\x3f\xe1\x1f",
    b"\x20",
    b"\x82\x84\x86\x41",
    b"\x80",
];

fn with_control(control: &[u8], flights: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    flights.into_iter().map(|f| control.iter().copied().chain(f).collect()).collect()
}

pub fn seeds_hpack() -> Vec<Vec<u8>> {
    let mut seeds = fuzz_hooks::h2_example_header_blocks();
    // the same blocks with a small table and a small limit
    seeds.extend(fuzz_hooks::h2_example_header_blocks().into_iter().map(|mut b| {
        b[0] = 0b0000_0101;
        b
    }));
    seeds
}

pub fn seeds_frames() -> Vec<Vec<u8>> {
    let mut seeds = fuzz_hooks::h2_example_server_flights();
    seeds.extend(fuzz_hooks::h2_example_client_flights());
    seeds
}

pub fn seeds_client() -> Vec<Vec<u8>> {
    let flights = fuzz_hooks::h2_example_server_flights();
    let mut seeds = with_control(&[0x1f, 0, 199, 255], flights.clone());
    // three requests, small windows, one byte at a time, one byte reads, and the server's SETTINGS not first
    seeds.extend(with_control(&[0x00, 2, 0, 0], flights.clone()));
    seeds.extend(with_control(&[0x25, 1, 40, 17], flights.clone()));
    // bodies collected whole: all three streams with a limit of 200 bytes, two with 5000, and the first switched half way
    seeds.extend(with_control(&[0x00, 0x14, 7, 40], flights.clone()));
    seeds.extend(with_control(&[0x25, 0x28, 100, 255], flights.clone()));
    seeds.extend(with_control(&[0x1f, 0x0c, 30, 3], flights));
    seeds
}

pub fn seeds_server() -> Vec<Vec<u8>> {
    let flights = fuzz_hooks::h2_example_client_flights();
    let mut seeds = with_control(&[0, 100, 0], flights.clone());
    seeds.extend(with_control(&[0x15, 0, 0], flights));
    seeds
}

pub fn hpack(data: &[u8]) {
    fuzz_hooks::h2_hpack(data);
}

pub fn frames(data: &[u8]) {
    fuzz_hooks::h2_frames(data);
}

pub fn client(data: &[u8]) {
    fuzz_hooks::h2_client(data);
}

pub fn server(data: &[u8]) {
    pratique::http::fuzz_hooks_server::h2_server(data);
}
