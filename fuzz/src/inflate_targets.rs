//! The decompressor (`pratique::inflate`): DEFLATE, zlib and gzip from anywhere.
//!
//! The first byte of an input says how to read the rest: bits 0 to 2 the format, bits 3 and 4 the limits, bits 5 to 7 how the input
//! and the output are cut. What must hold, beyond no panic, no hang and no memory past the limit:
//!
//! * the answer does not depend on how the input and the output are cut (the bytes, or the very same error);
//! * nothing comes out past the limit on the output, and a stream that decoded within no limit decodes the same with a limit of
//!   exactly its size and is refused with `OutputLimit`, and only that, with one byte less;
//! * what decoded under a ratio limit is within the ratio of the input (or under the floor);
//! * what zlib takes, "zlib or bare DEFLATE" takes the same way; what a single gzip member gives, gzip of any members gives too.

use pratique::inflate::{decode_all, Error, Format, Inflater, Limits, Status};

/// The most any run may decode to: keeps a run's memory and time small whatever the input says.
const CAP: u64 = 1 << 20;

pub const INFLATE_DICT: &[&[u8]] = &[
    b"\x1f\x8b\x08\x00",
    b"\x1f\x8b\x08\x1f",
    b"\x78\x9c",
    b"\x78\x01",
    b"\x78\xda",
    b"\x08\x1d",
    b"\x00\x00\xff\xff",
    b"\x01\x00\x00\xff\xff",
    b"\x00\x05\x00\xfa\xff",
    b"\x03\x00",
    b"\x02\x00",
    b"\x05\xc0",
    b"\xed\xbd",
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\xff\xff\xff\xff",
];

const VECTORS: &str = include_str!("../../tests/data/inflate_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn selector(format: &str) -> u8 {
    match format {
        "deflate" => 0,
        "zlib" => 1,
        _ => 3,
    }
}

/// The bases of the damaged streams of tests/data/inflate_vectors.txt and its shorter valid streams, each with every limit setting.
pub fn seeds_inflate() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for line in VECTORS.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (format, hex) = match f[0] {
            "base" => (f[2], f[3]),
            "ok" if f[5].len() <= 2048 => (f[2], f[5]),
            _ => continue,
        };
        let stream = unhex(hex);
        for limits in 0..4u8 {
            let mut input = vec![selector(format) | limits << 3 | (out.len() as u8 % 8) << 5];
            input.extend_from_slice(&stream);
            out.push(input);
        }
    }
    out
}

fn format_of(sel: u8) -> Format {
    match sel & 7 {
        0 | 5 => Format::Deflate,
        1 | 6 => Format::Zlib,
        2 => Format::ZlibOrDeflate,
        3 | 7 => Format::Gzip,
        _ => Format::GzipMember,
    }
}

fn limits_of(sel: u8, len: usize) -> Limits {
    match (sel >> 3) & 3 {
        0 => Limits::new(CAP),
        1 => Limits::new((len as u64 * 4).min(CAP)),
        2 => Limits::new(CAP).with_ratio(10, 64),
        _ => Limits::new(0),
    }
}

/// The whole of `data` as one stream of `format`, with the input given in pieces of `inp` bytes and the output taken in a slice of
/// `out` bytes; the same contract as `decode_all`.
fn chunked(format: Format, data: &[u8], limits: Limits, inp: usize, out: usize) -> Result<Vec<u8>, Error> {
    let mut inf = Inflater::new(format, limits);
    let mut result = Vec::new();
    let mut buf = vec![0u8; out];
    let mut pos = 0usize;
    loop {
        let end = pos.saturating_add(inp).min(data.len());
        let p = inf.inflate(&data[pos..end], &mut buf)?;
        assert!(p.consumed <= end - pos && p.produced <= out, "consumed or produced more than there was");
        pos += p.consumed;
        result.extend_from_slice(&buf[..p.produced]);
        assert!(result.len() as u64 <= limits.max_output, "output past the limit");
        match p.status {
            Status::Done => {
                return if pos == data.len() && inf.take_unused().is_empty() { Ok(result) } else { Err(Error::Corrupt("data follows the end of the compressed stream")) };
            }
            Status::NeedOutput => assert!(p.produced == out, "asked for room with room left"),
            Status::NeedInput => {
                assert_eq!(pos, end, "asked for input without taking what it had");
                if pos == data.len() {
                    inf.finish()?;
                    return Ok(result);
                }
            }
        }
    }
}

/// The same as far as a caller can tell: the same bytes, or an error of the same kind (the texts of `Corrupt` may name different
/// things a stream got wrong, when the cuts make the decoder look at them in another order; they never do in practice, but that
/// is not the contract).
fn same(a: &Result<Vec<u8>, Error>, b: &Result<Vec<u8>, Error>) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(Error::Corrupt(_)), Err(Error::Corrupt(_))) => true,
        (Err(x), Err(y)) => x == y,
        _ => false,
    }
}

pub fn inflate(data: &[u8]) {
    let Some((&sel, stream)) = data.split_first() else { return };
    let format = format_of(sel);
    let limits = limits_of(sel, stream.len());
    let whole = decode_all(format, stream, limits);
    if let Ok(out) = &whole {
        assert!(out.len() as u64 <= limits.max_output);
        if limits.max_ratio > 0 {
            assert!(out.len() as u64 <= limits.ratio_floor.max(limits.max_ratio * stream.len() as u64), "{} bytes out of {}", out.len(), stream.len());
        }
    }

    // the cuts: tiny ones only while the output is small (a byte at a time through a megabyte is slow, not wrong)
    let small = whole.as_ref().map_or(true, |o| o.len() <= 1 << 16);
    let cuts: &[(usize, usize)] = match (sel >> 5, small) {
        (_, false) => &[(509, 4096), (usize::MAX, 1 << 16)],
        (0 | 1, true) => &[(1, 1), (usize::MAX, 7)],
        (2 | 3, true) => &[(3, 5), (64, 33)],
        _ => &[(1, 4096), (7, 1)],
    };
    for &(inp, out) in cuts {
        let r = chunked(format, stream, limits, inp, out);
        assert!(same(&r, &whole), "input in {inp}s and output in {out}s: {:?} against {:?}", r.as_ref().map(Vec::len), whole.as_ref().map(Vec::len));
    }

    // the limit on the output: a stream that fits fits at exactly its size, and not one byte under it
    if let (Ok(out), 0) = (&whole, (sel >> 3) & 3) {
        let n = out.len() as u64;
        assert_eq!(decode_all(format, stream, Limits::new(n)).as_ref(), Ok(out));
        if n > 0 {
            assert_eq!(decode_all(format, stream, Limits::new(n - 1)), Err(Error::OutputLimit { limit: n - 1 }));
        }
    }

    // the formats that take more take this the same way
    if let Ok(out) = &whole {
        if format == Format::Zlib {
            assert_eq!(decode_all(Format::ZlibOrDeflate, stream, limits).as_ref(), Ok(out), "zlib, but not zlib or bare DEFLATE");
        }
        if format == Format::GzipMember {
            assert_eq!(decode_all(Format::Gzip, stream, limits).as_ref(), Ok(out), "one gzip member, but not gzip");
        }
    }
}
