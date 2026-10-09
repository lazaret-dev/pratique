//! The fuzz targets of HTTP/3 (B-91): of QPACK (`src/http/h3/qpack.rs`) `h3_qpack`, `h3_qpack_exchange` and `h3_qpack_encoder`, and of the
//! frame reader (`src/http/h3/frame.rs`) `h3_frames`, and of the connection (`src/http/h3/connection.rs`) `h3_connection`. They
//! reach the `pub(crate)` layer through `pratique::http::fuzz_hooks`, which holds the properties (see `src/http/h3/fuzz_hooks.rs`
//! and `qpack_harness.rs`):
//!
//! | target              | what must hold |
//! |---------------------|----------------|
//! | `h3_qpack`          | the decoder fed an encoder stream, field sections and cancellations made up from the bytes: no panic, and after each step its table adds up and is within what it announced, what it holds of a cut instruction is bounded, a list it gives is within the limit, a section it holds back is one that waits for entries it has not got, and what it writes on the decoder stream is whole instructions; every list that decoded is written by our encoder (several settings, sensitive or not, three sections on one pair) and read back by a fresh decoder as the same list |
//! | `h3_qpack_exchange` | our encoder and our decoder over links that delay, cut and drop (settings, requests, deliveries and abandoned streams all chosen by the bytes): nothing they say is an error, the decoder reads the fields the encoder was given, no stream waits on more than was allowed, no entry is evicted while a section not acknowledged refers to it, and when everything has arrived the tables agree and nothing is counted as referred to |
//! | `h3_frames`         | the frame reader on a request stream or the control stream, from bytes made up as they come, cut in pieces the bytes choose: it says what a model that has the whole stream before it says (the frames, the code of the error, whether the stream is between frames), a data range is inside the piece it came from, a HEADERS frame over the limit is not kept, and what was read from a request stream is written again and read back the same |
//! | `h3_connection`     | a whole HTTP/3 client connection against a server made up from the bytes (requests, well-made responses with a QPACK table that is filled, delayed and acknowledged, slow writes, resets, GOAWAY, streams of unknown types, and with the low bit of the first byte set, bytes that mean nothing): the books add up, a lost connection was closed with a code of the RFCs, the application sees each stream's events in order, a server that is well made does not lose the connection and what it sent is what is read, and what the client wrote decodes to the requests |
//! | `alt_svc`           | the value of an `Alt-Svc` field (RFC 7838): it parses or is skipped; what it says is within bounds (a port, a host with nothing odd in it, a lifetime of a month at most), an alternative written out again reads back as the same, and an alternative of another protocol in front of it changes nothing |
//! | `h3_qpack_encoder`  | the encoder fed a decoder stream made up from the bytes, between requests: an instruction that makes no sense is an error, anything else leaves its books balanced (what is counted as referred to is what the sections not acknowledged refer to, the table is within its limits, no more streams may be blocked than allowed) |

use pratique::http::fuzz_hooks;

/// What the instructions of the two streams and the field lines begin with (RFC 9204 sections 4.3, 4.4 and 4.5).
pub const QPACK_DICT: &[&[u8]] = &[
    // the prefix of a section: no dynamic entries; required insert count 2 and base 0 (the entries are after the base); 3 with base 2
    b"\x00\x00",
    b"\x03\x81",
    b"\x03\x00",
    b"\x05\x00",
    // encoder stream: Set Dynamic Table Capacity 220 and 4096, Insert With Name Reference (static 0 and 1, dynamic 0 and 1), With
    // Literal Name, Duplicate (0, 2)
    b"\x3f\xbd\x01",
    b"\x3f\xe1\x1f",
    b"\xc0",
    b"\xc1",
    b"\x80",
    b"\x81",
    b"\x4a",
    b"\x02",
    b"\x00",
    // decoder stream: Section Acknowledgment (stream 4), Stream Cancellation (stream 8), Insert Count Increment (1)
    b"\x84",
    b"\x48",
    b"\x01",
    // field lines: Indexed (static 17, dynamic 0 and 1), post-base indexed (0, 1), Literal With Name Reference (static 1; dynamic 0;
    // never indexed), post-base name reference, Literal With Literal Name (and never indexed)
    b"\xd1",
    b"\xc1",
    b"\x10",
    b"\x11",
    b"\x51",
    b"\x40",
    b"\x71",
    b"\x00\x0b",
    b"\x20",
    b"\x30",
    // some of the names and values in the static table and in the generated lists
    b"www.example.com",
    b"/index.html",
    b"user-agent",
    b"accept-encoding",
    b"gzip, deflate",
    b"custom-key",
    b"custom-value",
];

pub fn seeds_qpack() -> Vec<Vec<u8>> {
    fuzz_hooks::h3_qpack_example_decoder_scripts()
}

pub fn seeds_exchange() -> Vec<Vec<u8>> {
    fuzz_hooks::h3_qpack_example_exchange_scripts()
}

pub fn seeds_encoder() -> Vec<Vec<u8>> {
    fuzz_hooks::h3_qpack_example_encoder_scripts()
}

pub fn qpack(data: &[u8]) {
    fuzz_hooks::h3_qpack_decoder(data);
}

pub fn exchange(data: &[u8]) {
    fuzz_hooks::h3_qpack_exchange(data);
}

pub fn encoder(data: &[u8]) {
    fuzz_hooks::h3_qpack_encoder(data);
}

/// What the frames of HTTP/3 are made of: types and lengths, the control frames, the reserved types.
pub const FRAME_DICT: &[&[u8]] = &[
    b"\x00\x05hello",
    b"\x00\x00",
    b"\x01\x03\x00\x00\xd1",
    b"\x01\x00",
    b"\x01\x10",
    b"\x01\x11",
    b"\x04\x00",
    b"\x04\x04\x01\x40\x64\x07",
    b"\x04\x02\x01\x00",
    b"\x07\x01\x00",
    b"\x07\x02\x40\x08",
    b"\x03\x01\x00",
    b"\x05\x02\x00\x00",
    b"\x0d\x01\x00",
    b"\x02\x00",
    b"\x06\x00",
    b"\x08\x00",
    b"\x09\x00",
    b"\x21\x00",
    b"\x40\x21\x00",
    b"\x40\xfa\x01x",
    b"\x80\x00\x00\x01\x00",
    b"\xc0\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x7f\xff",
    b"\xff\xff\xff\xff\xff\xff\xff\xff",
];

pub fn seeds_frames() -> Vec<Vec<u8>> {
    fuzz_hooks::h3_frame_example_streams()
}

pub fn frames(data: &[u8]) {
    fuzz_hooks::h3_frames(data);
}

pub fn seeds_connection() -> Vec<Vec<u8>> {
    fuzz_hooks::h3_connection_example_scripts()
}

pub fn connection(data: &[u8]) {
    fuzz_hooks::h3_connection_exchange(data);
}

/// What an `Alt-Svc` value begins with and is made of.
pub const ALT_SVC_DICT: &[&[u8]] = &[b"h3=\"", b"h3-29=\"", b"\":443\"", b"; ma=", b"; persist=1", b", ", b"clear", b"[::1]:", b"alt.example.com"];

pub fn seeds_alt_svc() -> Vec<Vec<u8>> {
    fuzz_hooks::alt_svc_examples()
}

pub fn alt_svc(data: &[u8]) {
    fuzz_hooks::alt_svc(data);
}
