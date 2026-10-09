//! The Huffman code of HPACK (RFC 7541, Appendix B), for header strings.
//!
//! The code is canonical: codes of one length are consecutive numbers, in the order of the symbols, and a longer
//! code starts where the shorter ones end. So the 257 code lengths are all there is to write down; the codes and
//! the decoding tables are worked out from them at compile time. (The test module has the codes themselves, as
//! the RFC lists them, and checks the derived ones against them.)

use std::fmt;

/// The code length of each symbol: the 256 byte values, then EOS (symbol 256).
const LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
     6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
     5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
    13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
     7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
    15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
     6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
];

/// The longest code.
const MAX_LEN: usize = 30;

/// Everything derived from [`LENGTHS`].
struct Tables {
    /// The code of each symbol, right-aligned.
    codes: [u32; 257],
    /// For each code length, the smallest code of that length.
    first_code: [u32; MAX_LEN + 1],
    /// For each code length, how many codes have it.
    count: [u16; MAX_LEN + 1],
    /// For each code length, where its symbols start in `sorted`.
    first_index: [u16; MAX_LEN + 1],
    /// The symbols ordered by code length, then by value: the order in which the codes were handed out.
    sorted: [u16; 257],
}

const TABLES: Tables = build();

const fn build() -> Tables {
    let mut count = [0u16; MAX_LEN + 1];
    let mut s = 0;
    while s < 257 {
        count[LENGTHS[s] as usize] += 1;
        s += 1;
    }
    let mut first_code = [0u32; MAX_LEN + 1];
    let mut first_index = [0u16; MAX_LEN + 1];
    let mut code = 0u32;
    let mut index = 0u16;
    let mut len = 1;
    while len <= MAX_LEN {
        code <<= 1;
        first_code[len] = code;
        first_index[len] = index;
        code += count[len] as u32;
        index += count[len];
        len += 1;
    }
    let mut codes = [0u32; 257];
    let mut sorted = [0u16; 257];
    let mut used = [0u16; MAX_LEN + 1];
    let mut s = 0;
    while s < 257 {
        let len = LENGTHS[s] as usize;
        codes[s] = first_code[len] + used[len] as u32;
        sorted[(first_index[len] + used[len]) as usize] = s as u16;
        used[len] += 1;
        s += 1;
    }
    Tables { codes, first_code, count, first_index, sorted }
}

/// Why a string did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The EOS symbol appeared in the data, which it must not.
    Eos,
    /// The bits left over at the end were longer than 7 or were not all ones.
    Padding,
    /// The decoded string would be longer than the limit.
    TooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Eos => "a Huffman string contains the end-of-string symbol",
            Error::Padding => "a Huffman string ends with bad padding",
            Error::TooLong => "a Huffman string decodes to more than the allowed length",
        })
    }
}

/// How many bytes `src` takes when Huffman coded.
pub(crate) fn encoded_len(src: &[u8]) -> usize {
    let bits: usize = src.iter().map(|&b| LENGTHS[b as usize] as usize).sum();
    bits.div_ceil(8)
}

/// Appends the Huffman coding of `src` to `out`, padded to a whole byte with the most significant bits of EOS (all
/// ones).
pub(crate) fn encode(src: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &b in src {
        let len = LENGTHS[b as usize] as u32;
        acc = (acc << len) | TABLES.codes[b as usize] as u64;
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1u64 << bits) - 1;
    }
    if bits > 0 {
        out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
    }
}

/// Appends the string `src` codes to `out`, which may not grow past `limit` bytes in all by this call. Padding
/// longer than 7 bits, padding that is not all ones and a coded EOS are errors, as RFC 7541 section 5.2 says.
pub(crate) fn decode(src: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let start = out.len();
    let mut code = 0u32;
    let mut len = 0usize;
    for &byte in src {
        for shift in (0..8).rev() {
            code = (code << 1) | ((byte >> shift) & 1) as u32;
            len += 1;
            let n = TABLES.count[len] as u32;
            if n > 0 && code >= TABLES.first_code[len] && code - TABLES.first_code[len] < n {
                let symbol = TABLES.sorted[TABLES.first_index[len] as usize + (code - TABLES.first_code[len]) as usize];
                if symbol == 256 {
                    return Err(Error::Eos);
                }
                if out.len() - start >= limit {
                    return Err(Error::TooLong);
                }
                out.push(symbol as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // what is left is padding: at most 7 bits, all ones
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(Error::Padding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes of RFC 7541, Appendix B (as the Go and the Python implementations have them), for the 256 byte
    /// values and EOS.
    const RFC_CODES: [u32; 257] = [
        0x00001ff8, 0x007fffd8, 0x0fffffe2, 0x0fffffe3, 0x0fffffe4, 0x0fffffe5, 0x0fffffe6, 0x0fffffe7,
        0x0fffffe8, 0x00ffffea, 0x3ffffffc, 0x0fffffe9, 0x0fffffea, 0x3ffffffd, 0x0fffffeb, 0x0fffffec,
        0x0fffffed, 0x0fffffee, 0x0fffffef, 0x0ffffff0, 0x0ffffff1, 0x0ffffff2, 0x3ffffffe, 0x0ffffff3,
        0x0ffffff4, 0x0ffffff5, 0x0ffffff6, 0x0ffffff7, 0x0ffffff8, 0x0ffffff9, 0x0ffffffa, 0x0ffffffb,
        0x00000014, 0x000003f8, 0x000003f9, 0x00000ffa, 0x00001ff9, 0x00000015, 0x000000f8, 0x000007fa,
        0x000003fa, 0x000003fb, 0x000000f9, 0x000007fb, 0x000000fa, 0x00000016, 0x00000017, 0x00000018,
        0x00000000, 0x00000001, 0x00000002, 0x00000019, 0x0000001a, 0x0000001b, 0x0000001c, 0x0000001d,
        0x0000001e, 0x0000001f, 0x0000005c, 0x000000fb, 0x00007ffc, 0x00000020, 0x00000ffb, 0x000003fc,
        0x00001ffa, 0x00000021, 0x0000005d, 0x0000005e, 0x0000005f, 0x00000060, 0x00000061, 0x00000062,
        0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068, 0x00000069, 0x0000006a,
        0x0000006b, 0x0000006c, 0x0000006d, 0x0000006e, 0x0000006f, 0x00000070, 0x00000071, 0x00000072,
        0x000000fc, 0x00000073, 0x000000fd, 0x00001ffb, 0x0007fff0, 0x00001ffc, 0x00003ffc, 0x00000022,
        0x00007ffd, 0x00000003, 0x00000023, 0x00000004, 0x00000024, 0x00000005, 0x00000025, 0x00000026,
        0x00000027, 0x00000006, 0x00000074, 0x00000075, 0x00000028, 0x00000029, 0x0000002a, 0x00000007,
        0x0000002b, 0x00000076, 0x0000002c, 0x00000008, 0x00000009, 0x0000002d, 0x00000077, 0x00000078,
        0x00000079, 0x0000007a, 0x0000007b, 0x00007ffe, 0x000007fc, 0x00003ffd, 0x00001ffd, 0x0ffffffc,
        0x000fffe6, 0x003fffd2, 0x000fffe7, 0x000fffe8, 0x003fffd3, 0x003fffd4, 0x003fffd5, 0x007fffd9,
        0x003fffd6, 0x007fffda, 0x007fffdb, 0x007fffdc, 0x007fffdd, 0x007fffde, 0x00ffffeb, 0x007fffdf,
        0x00ffffec, 0x00ffffed, 0x003fffd7, 0x007fffe0, 0x00ffffee, 0x007fffe1, 0x007fffe2, 0x007fffe3,
        0x007fffe4, 0x001fffdc, 0x003fffd8, 0x007fffe5, 0x003fffd9, 0x007fffe6, 0x007fffe7, 0x00ffffef,
        0x003fffda, 0x001fffdd, 0x000fffe9, 0x003fffdb, 0x003fffdc, 0x007fffe8, 0x007fffe9, 0x001fffde,
        0x007fffea, 0x003fffdd, 0x003fffde, 0x00fffff0, 0x001fffdf, 0x003fffdf, 0x007fffeb, 0x007fffec,
        0x001fffe0, 0x001fffe1, 0x003fffe0, 0x001fffe2, 0x007fffed, 0x003fffe1, 0x007fffee, 0x007fffef,
        0x000fffea, 0x003fffe2, 0x003fffe3, 0x003fffe4, 0x007ffff0, 0x003fffe5, 0x003fffe6, 0x007ffff1,
        0x03ffffe0, 0x03ffffe1, 0x000fffeb, 0x0007fff1, 0x003fffe7, 0x007ffff2, 0x003fffe8, 0x01ffffec,
        0x03ffffe2, 0x03ffffe3, 0x03ffffe4, 0x07ffffde, 0x07ffffdf, 0x03ffffe5, 0x00fffff1, 0x01ffffed,
        0x0007fff2, 0x001fffe3, 0x03ffffe6, 0x07ffffe0, 0x07ffffe1, 0x03ffffe7, 0x07ffffe2, 0x00fffff2,
        0x001fffe4, 0x001fffe5, 0x03ffffe8, 0x03ffffe9, 0x0ffffffd, 0x07ffffe3, 0x07ffffe4, 0x07ffffe5,
        0x000fffec, 0x00fffff3, 0x000fffed, 0x001fffe6, 0x003fffe9, 0x001fffe7, 0x001fffe8, 0x007ffff3,
        0x003fffea, 0x003fffeb, 0x01ffffee, 0x01ffffef, 0x00fffff4, 0x00fffff5, 0x03ffffea, 0x007ffff4,
        0x03ffffeb, 0x07ffffe6, 0x03ffffec, 0x03ffffed, 0x07ffffe7, 0x07ffffe8, 0x07ffffe9, 0x07ffffea,
        0x07ffffeb, 0x0ffffffe, 0x07ffffec, 0x07ffffed, 0x07ffffee, 0x07ffffef, 0x07fffff0, 0x03ffffee,
        0x3fffffff,
    ];

    #[test]
    fn the_derived_codes_are_the_rfcs() {
        for s in 0..257 {
            assert_eq!(TABLES.codes[s], RFC_CODES[s], "symbol {s}");
        }
        // a few that are easy to check by eye: '0' is 00000, 'a' is 00011, '/' is 011000, EOS is thirty ones
        assert_eq!((TABLES.codes[b'0' as usize], LENGTHS[b'0' as usize]), (0x0, 5));
        assert_eq!((TABLES.codes[b'a' as usize], LENGTHS[b'a' as usize]), (0x3, 5));
        assert_eq!((TABLES.codes[b'/' as usize], LENGTHS[b'/' as usize]), (0x18, 6));
        assert_eq!((TABLES.codes[256], LENGTHS[256]), (0x3fff_ffff, 30));
    }

    #[test]
    fn the_code_is_complete_and_has_no_prefixes() {
        // Kraft sum of exactly one: 2^-len over all symbols
        let sum: u64 = LENGTHS.iter().map(|&l| 1u64 << (MAX_LEN as u32 - l as u32)).sum();
        assert_eq!(sum, 1u64 << MAX_LEN);
        // no code is a prefix of another
        for a in 0..257 {
            for b in 0..257 {
                if a != b && LENGTHS[a] <= LENGTHS[b] {
                    assert_ne!(RFC_CODES[b] >> (LENGTHS[b] - LENGTHS[a]), RFC_CODES[a], "{a} is a prefix of {b}");
                }
            }
        }
    }

    fn enc(s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode(s, &mut v);
        v
    }

    fn dec(s: &[u8]) -> Result<Vec<u8>, Error> {
        let mut v = Vec::new();
        decode(s, &mut v, usize::MAX).map(|_| v)
    }

    pub(crate) fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn the_rfc_examples() {
        // RFC 7541 appendices C.4 and C.6; the codings were also made by Python's hpack 4.2.0
        for (text, hex) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("302", "6402"),
            ("private", "aec3771a4b"),
            ("Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"),
            ("https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"),
            ("307", "640eff"),
            ("gzip", "9bd9ab"),
            ("foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"),
        ] {
            let bytes = unhex(hex);
            assert_eq!(enc(text.as_bytes()), bytes, "{text}");
            assert_eq!(dec(&bytes).unwrap(), text.as_bytes(), "{text}");
            assert_eq!(encoded_len(text.as_bytes()), bytes.len());
        }
    }

    #[test]
    fn every_byte_value_and_many_strings_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(dec(&enc(&all)).unwrap(), all);
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for round in 0..300 {
            let len = round % 40;
            let s: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    if round % 3 == 0 {
                        (state % 256) as u8
                    } else {
                        b'a' + (state % 26) as u8
                    }
                })
                .collect();
            let coded = enc(&s);
            assert_eq!(coded.len(), encoded_len(&s));
            assert_eq!(dec(&coded).unwrap(), s, "round {round}");
        }
        assert_eq!(enc(b""), Vec::<u8>::new());
        assert_eq!(dec(b"").unwrap(), b"");
    }

    #[test]
    fn padding_is_checked() {
        // "a" is 00011 and three ones follow: 0001_1111
        assert_eq!(dec(&[0x1f]).unwrap(), b"a");
        // a zero bit in the padding
        assert_eq!(dec(&[0x1e]), Err(Error::Padding));
        // a whole byte of ones is 8 bits of padding, one too many
        assert_eq!(dec(&[0x1f, 0xff]), Err(Error::Padding));
        assert_eq!(dec(&[0xff]), Err(Error::Padding));
        assert_eq!(dec(&[0xfe]), Err(Error::Padding), "a zero at the end is not padding");
    }

    #[test]
    fn eos_is_refused() {
        // thirty ones are EOS (and so are more of them)
        assert_eq!(dec(&[0xff, 0xff, 0xff, 0xff]), Err(Error::Eos));
        // 'a' then EOS
        assert_eq!(dec(&[0b0001_1111, 0xff, 0xff, 0xff, 0xff]), Err(Error::Eos));
    }

    #[test]
    fn the_limit_is_kept() {
        let coded = enc(b"hello world");
        let mut out = Vec::new();
        assert_eq!(decode(&coded, &mut out, 10), Err(Error::TooLong));
        assert!(out.len() <= 10);
        let mut out = b"keep".to_vec();
        assert!(decode(&coded, &mut out, 11).is_ok());
        assert_eq!(out, b"keephello world");
    }

    #[test]
    fn damaged_input_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..3000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 24) as usize;
            let junk: Vec<u8> = (0..len).map(|i| (state >> (i % 8 * 8)) as u8 ^ (i as u8).wrapping_mul(37)).collect();
            let mut out = Vec::new();
            let _ = decode(&junk, &mut out, 64);
            assert!(out.len() <= 64);
        }
    }
}
