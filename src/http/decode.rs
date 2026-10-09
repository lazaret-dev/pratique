//! `Content-Encoding` for the clients: deciding what to ask for and what to undo, and a sans-IO decoder of a response body that the
//! blocking and the async stream both drive (see [`Client::decompress`](super::Client::decompress)).
//!
//! The rules, which follow what Go's `net/http` and curl do where they agree and are stricter where a stranger's data is at stake:
//!
//! * decoding is opt-in, and a body is decoded only if the response says it is a single `gzip`, `x-gzip` or `deflate` (a list of
//!   codings, or one that is not known, is left as it came, with its `Content-Encoding` header, for the caller to deal with);
//! * a response that has no body to decode (to `HEAD`, 204, 205, 304) or that is a part of one (206, which is a range of the
//!   *encoded* body) is not touched;
//! * once decoded, `Content-Encoding` and `Content-Length` are gone from the headers (they described the bytes on the wire, not the
//!   ones the caller gets) and the response says so (`uncompressed`);
//! * the output is limited as it is produced (see [`DecodeLimits`]), the stream must end where the body does (nothing follows it),
//!   and a body of no bytes at all is an empty body, which is what servers that put `Content-Encoding: gzip` on every 200 send;
//! * after a failure the body is not read any further, so its connection is closed unless all of the body had arrived already (its
//!   HTTP framing was sound, whatever was wrong with what it held).

use crate::inflate::{Error as InflateError, Format, Inflater, Limits, Status};

/// How much a decoded body may come to: see [`Client::max_decoded_bytes`](super::Client::max_decoded_bytes) and
/// [`Client::max_decode_ratio`](super::Client::max_decode_ratio).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct DecodeLimits {
    /// The most bytes the decoded body may have; `None` means the limit on the body (`max_body_bytes`) of the request.
    pub(crate) max_output: Option<u64>,
    /// If not 0: the most times the compressed size the output may come to, once it is `ratio_floor` bytes long.
    pub(crate) max_ratio: u64,
    pub(crate) ratio_floor: u64,
}

impl DecodeLimits {
    /// The limits of the decoder for a request whose body limit is `max_body`.
    pub(crate) fn for_body(&self, max_body: u64) -> Limits {
        Limits { max_output: self.max_output.unwrap_or(max_body), max_ratio: self.max_ratio, ratio_floor: self.ratio_floor }
    }
}

/// What a request asks for itself, over the client's settings: the decoding, its limits, and its place in a batch.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestOpts {
    /// The limit on the size of the response body (the one on the wire, and the default for the decoded one).
    pub(crate) max_body: Option<u64>,
    /// Decode this response (or not) whatever the client says.
    pub(crate) decompress: Option<bool>,
    /// The limit on the decoded size for this request.
    pub(crate) max_decoded: Option<u64>,
    /// The oldest TLS version this request accepts, over the client's.
    pub(crate) min_tls: Option<crate::tls::TlsVersion>,
    /// The batch it belongs to, over the client's (see `http::schedule`).
    pub(crate) batch: Option<super::schedule::Batch>,
    /// How many bytes it expects to bring, for a scheduler's byte budget.
    pub(crate) expected: Option<u64>,
}

/// The coding of the body of a response that this client undoes, if it is one: a single `gzip`, `x-gzip` or `deflate`, on a response
/// that has a whole body to decode. `identity` counts as no coding at all.
pub(crate) fn coding_of(method: &str, status: u16, headers: &[(String, String)]) -> Option<Format> {
    if method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 205 | 206 | 304) {
        return None;
    }
    let mut found: Option<Format> = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() || token.eq_ignore_ascii_case("identity") {
                continue;
            }
            let format = if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                Format::Gzip
            } else if token.eq_ignore_ascii_case("deflate") {
                // what is meant is zlib, and some servers send the bare form
                Format::ZlibOrDeflate
            } else {
                return None;
            };
            if found.replace(format).is_some() {
                // more than one coding: each layer would be a bomb of its own
                return None;
            }
        }
    }
    found
}

/// Takes the headers that describe the encoded body out of a list of headers whose body has been decoded.
pub(crate) fn strip_encoding_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-encoding") && !n.eq_ignore_ascii_case("content-length"));
}

/// What the decoder wants a stream to do next.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// This many decoded bytes are in the caller's buffer.
    Data(usize),
    /// Read more of the body from the wire into [`BodyDecoder::wire_buf`] and say how much with [`BodyDecoder::wire`].
    Wire,
    /// The end of the decoded body (and of the wire body).
    End,
}

/// Size of the buffer that compressed bytes pass through.
const WIRE_BUF: usize = 16 * 1024;

/// Decodes a body that arrives in pieces: the stream gives it the pieces and takes the decoded bytes. It does no I/O.
pub(crate) struct BodyDecoder {
    inf: Box<Inflater>,
    buf: Box<[u8]>,
    /// `buf[pos..end]` was read from the wire and not decoded yet.
    pos: usize,
    end: usize,
    wire_total: u64,
    wire_eof: bool,
    /// The compressed stream is over; what is left of the wire body must be nothing.
    stream_done: bool,
    finished: bool,
    failed: Option<InflateError>,
}

impl BodyDecoder {
    pub(crate) fn new(format: Format, limits: Limits) -> BodyDecoder {
        BodyDecoder {
            inf: Box::new(Inflater::new(format, limits)),
            buf: vec![0u8; WIRE_BUF].into_boxed_slice(),
            pos: 0,
            end: 0,
            wire_total: 0,
            wire_eof: false,
            stream_done: false,
            finished: false,
            failed: None,
        }
    }

    fn fail<T>(&mut self, e: InflateError) -> Result<T, InflateError> {
        self.failed = Some(e.clone());
        Err(e)
    }

    /// Decodes into `out` (not empty) as far as what has been given allows.
    pub(crate) fn next(&mut self, out: &mut [u8]) -> Result<Next, InflateError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        if out.is_empty() {
            return Ok(Next::Data(0));
        }
        loop {
            if self.finished {
                return Ok(Next::End);
            }
            if self.stream_done {
                // the rest of the wire body is read to its end, to be sure that nothing follows the stream (and so that the
                // connection can be used again)
                if self.wire_eof {
                    self.finished = true;
                    return Ok(Next::End);
                }
                return Ok(Next::Wire);
            }
            if self.wire_eof && self.wire_total == 0 {
                // a body of no bytes is an empty body
                self.finished = true;
                return Ok(Next::End);
            }
            let p = match self.inf.inflate(&self.buf[self.pos..self.end], out) {
                Ok(p) => p,
                Err(e) => return self.fail(e),
            };
            self.pos += p.consumed;
            if p.status == Status::Done {
                // (bytes that the decoder took into its bit buffer count as input it took, and are not the stream's)
                if self.pos < self.end || !self.inf.take_unused().is_empty() {
                    return self.fail(InflateError::Corrupt("data follows the end of the compressed stream"));
                }
                self.stream_done = true;
            }
            if p.produced > 0 {
                return Ok(Next::Data(p.produced));
            }
            match p.status {
                Status::Done => {}
                Status::NeedOutput => return self.fail(InflateError::Corrupt("the decoder made no progress")),
                Status::NeedInput => {
                    if self.wire_eof {
                        // (a gzip stream of members ends here, if it ends between two of them)
                        if let Err(e) = self.inf.finish() {
                            return self.fail(e);
                        }
                        self.finished = true;
                        return Ok(Next::End);
                    }
                    return Ok(Next::Wire);
                }
            }
        }
    }

    /// Where the next piece of the wire body goes; call it only after [`next`](BodyDecoder::next) said `Wire`.
    pub(crate) fn wire_buf(&mut self) -> &mut [u8] {
        self.pos = 0;
        self.end = 0;
        &mut self.buf[..]
    }

    /// `n` bytes of the wire body were read into [`wire_buf`](BodyDecoder::wire_buf); 0 means that the body has ended.
    pub(crate) fn wire(&mut self, n: usize) -> Result<(), InflateError> {
        if n == 0 {
            self.wire_eof = true;
            return Ok(());
        }
        self.wire_total += n as u64;
        if self.stream_done {
            return self.fail(InflateError::Corrupt("data follows the end of the compressed stream"));
        }
        self.pos = 0;
        self.end = n.min(self.buf.len());
        Ok(())
    }
}

impl std::fmt::Debug for BodyDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyDecoder").field("wire_total", &self.wire_total).field("stream_done", &self.stream_done).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    #[test]
    fn only_a_single_known_coding_is_chosen() {
        let get = |hs: &[(&str, &str)]| coding_of("GET", 200, &h(hs));
        assert_eq!(get(&[("Content-Encoding", "gzip")]), Some(Format::Gzip));
        assert_eq!(get(&[("content-encoding", "GZIP")]), Some(Format::Gzip));
        assert_eq!(get(&[("content-encoding", " x-gzip ")]), Some(Format::Gzip));
        assert_eq!(get(&[("content-encoding", "deflate")]), Some(Format::ZlibOrDeflate));
        // identity is no coding, alone or in a list, and an empty header is none either
        assert_eq!(get(&[("content-encoding", "identity")]), None);
        assert_eq!(get(&[("content-encoding", "identity, gzip")]), Some(Format::Gzip));
        assert_eq!(get(&[("content-encoding", "")]), None);
        assert_eq!(get(&[]), None);
        // more than one coding, in one header or in several, and every one that is not known, are left alone
        assert_eq!(get(&[("content-encoding", "gzip, gzip")]), None);
        assert_eq!(get(&[("content-encoding", "deflate, gzip")]), None);
        assert_eq!(get(&[("content-encoding", "gzip"), ("content-encoding", "gzip")]), None);
        assert_eq!(get(&[("content-encoding", "gzip"), ("content-encoding", "br")]), None);
        assert_eq!(get(&[("content-encoding", "br")]), None);
        assert_eq!(get(&[("content-encoding", "zstd")]), None);
        assert_eq!(get(&[("content-encoding", "gzip;q=1")]), None);
        assert_eq!(get(&[("content-encoding", "gzipp")]), None);
        // no body to decode, or a part of the encoded body
        for status in [100, 101, 204, 205, 206, 304] {
            assert_eq!(coding_of("GET", status, &h(&[("content-encoding", "gzip")])), None, "status {status}");
        }
        assert_eq!(coding_of("HEAD", 200, &h(&[("content-encoding", "gzip")])), None);
        assert_eq!(coding_of("head", 200, &h(&[("content-encoding", "gzip")])), None);
        // an error page is decoded like any other body
        assert_eq!(coding_of("GET", 404, &h(&[("content-encoding", "gzip")])), Some(Format::Gzip));
        assert_eq!(coding_of("POST", 201, &h(&[("content-encoding", "deflate")])), Some(Format::ZlibOrDeflate));
    }

    #[test]
    fn the_headers_of_the_encoded_body_are_dropped() {
        let mut hs = h(&[("Content-Type", "text/plain"), ("Content-Encoding", "gzip"), ("content-length", "20"), ("Vary", "Accept-Encoding"), ("ETag", "\"x\"")]);
        strip_encoding_headers(&mut hs);
        assert_eq!(hs, h(&[("Content-Type", "text/plain"), ("Vary", "Accept-Encoding"), ("ETag", "\"x\"")]));
    }

    #[test]
    fn limits_follow_the_body_limit_unless_they_are_set() {
        let d = DecodeLimits::default();
        assert_eq!(d.for_body(100), Limits::new(100));
        let d = DecodeLimits { max_output: Some(7), max_ratio: 50, ratio_floor: 1000 };
        assert_eq!(d.for_body(100), Limits::new(7).with_ratio(50, 1000));
    }

    /// Drives a decoder the way a stream does: the wire body in pieces of `piece` bytes, the output in a buffer of `out` bytes.
    fn drive(d: &mut BodyDecoder, wire: &[u8], piece: usize, out: usize) -> Result<Vec<u8>, InflateError> {
        let mut result = Vec::new();
        let mut buf = vec![0u8; out];
        let mut at = 0;
        loop {
            match d.next(&mut buf)? {
                Next::Data(n) => result.extend_from_slice(&buf[..n]),
                Next::End => return Ok(result),
                Next::Wire => {
                    let n = (wire.len() - at).min(piece).min(d.wire_buf().len());
                    d.wire_buf()[..n].copy_from_slice(&wire[at..at + n]);
                    at += n;
                    d.wire(n)?;
                }
            }
        }
    }

    fn zlib_hello() -> Vec<u8> {
        vec![0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03, 0x08, 0xb1]
    }

    fn gzip_hello() -> Vec<u8> {
        // header, the bare stream of zlib_hello, then the CRC-32 and the length
        let mut g = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        g.extend_from_slice(&zlib_hello()[2..zlib_hello().len() - 4]);
        g.extend_from_slice(&crate::inflate::crc32(0, b"hello hello hello hello").to_le_bytes());
        g.extend_from_slice(&23u32.to_le_bytes());
        g
    }

    #[test]
    fn a_body_is_decoded_however_it_is_cut() {
        for (format, wire) in [(Format::Gzip, gzip_hello()), (Format::Zlib, zlib_hello()), (Format::ZlibOrDeflate, zlib_hello()), (Format::ZlibOrDeflate, zlib_hello()[2..zlib_hello().len() - 4].to_vec())] {
            for piece in [1, 3, 100, 1 << 20] {
                for out in [1, 5, 4096] {
                    let mut d = BodyDecoder::new(format, Limits::new(1000));
                    assert_eq!(drive(&mut d, &wire, piece, out).unwrap(), b"hello hello hello hello", "{format:?} in {piece}s, out {out}s");
                    // and it stays at the end
                    assert_eq!(d.next(&mut [0u8; 8]), Ok(Next::End));
                }
            }
        }
    }

    #[test]
    fn nothing_on_the_wire_is_an_empty_body_but_a_cut_stream_is_not() {
        let mut d = BodyDecoder::new(Format::Gzip, Limits::unlimited());
        assert_eq!(drive(&mut d, &[], 10, 10).unwrap(), b"");
        let wire = gzip_hello();
        for cut in 1..wire.len() {
            let mut d = BodyDecoder::new(Format::Gzip, Limits::unlimited());
            assert_eq!(drive(&mut d, &wire[..cut], 7, 64), Err(InflateError::Truncated), "cut at {cut}");
            // the failure is kept
            assert_eq!(d.next(&mut [0u8; 8]), Err(InflateError::Truncated));
        }
    }

    #[test]
    fn bytes_after_the_stream_are_refused_wherever_they_come_in() {
        for (format, mut wire) in [(Format::Zlib, zlib_hello()), (Format::ZlibOrDeflate, zlib_hello()), (Format::Gzip, gzip_hello())] {
            wire.extend_from_slice(b"\0");
            for piece in [1, 5, 1 << 20] {
                let mut d = BodyDecoder::new(format, Limits::unlimited());
                let r = drive(&mut d, &wire, piece, 4096);
                assert!(matches!(r, Err(InflateError::Corrupt(_))), "{format:?} in {piece}s: {r:?}");
            }
        }
    }

    #[test]
    fn the_output_limit_stops_the_decoding() {
        let mut d = BodyDecoder::new(Format::Gzip, Limits::new(10));
        assert_eq!(drive(&mut d, &gzip_hello(), 100, 4), Err(InflateError::OutputLimit { limit: 10 }));
        let mut d = BodyDecoder::new(Format::Gzip, Limits::new(23));
        assert_eq!(drive(&mut d, &gzip_hello(), 100, 4).unwrap().len(), 23);
    }
}
