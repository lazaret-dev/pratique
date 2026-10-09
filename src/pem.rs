//! PEM and Base64 decoding.

use crate::verify_error::{Error, Result};

/// Decodes standard Base64 (whitespace ignored, padding optional).
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(Error::Certificate("invalid Base64 character".into())),
        };
        if padding > 0 {
            return Err(Error::Certificate("Base64 data after padding".into()));
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Decodes standard Base64 strictly, for data whose exact form matters (signed notes, hashes in
/// text): only the 64-character alphabet, padding to a multiple of four and only at the end (one
/// or two `=`), no whitespace, and the unused bits of the last character zero, so that every byte
/// string has exactly one accepted encoding. The empty string decodes to nothing.
pub fn base64_decode_strict(input: &str) -> Option<Vec<u8>> {
    let b = input.as_bytes();
    if b.len() % 4 != 0 {
        return None;
    }
    let pad = b.iter().rev().take(2).take_while(|c| **c == b'=').count();
    let data = &b[..b.len() - pad];
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in data {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // what is left must be zero: 0, 2 or 4 unused bits
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Encodes bytes as standard padded Base64.
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// One decoded PEM block.
#[derive(Debug, Clone)]
pub struct PemBlock {
    pub label: String,
    pub data: Vec<u8>,
}

/// Extracts every well-formed `-----BEGIN X-----` ... `-----END X-----` block from `text`,
/// ignoring any text in between. Blocks whose Base64 is malformed are skipped.
pub fn parse(text: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else {
            continue;
        };
        let end_marker = format!("-----END {}-----", label);
        let mut body = String::new();
        let mut terminated = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end_marker {
                terminated = true;
                break;
            }
            if l.contains(':') {
                continue; // encapsulated header such as Proc-Type
            }
            body.push_str(l);
        }
        if terminated {
            if let Ok(data) = base64_decode(&body) {
                blocks.push(PemBlock { label: label.to_string(), data });
            }
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert!(base64_decode("Zm9v*").is_err());
    }

    #[test]
    fn base64_encode_roundtrip() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(base64_decode(&base64_encode(&data)).unwrap(), data);
    }

    #[test]
    fn strict_base64_has_exactly_one_encoding_of_every_byte_string() {
        for (text, bytes) in [("", &b""[..]), ("Zg==", b"f"), ("Zm8=", b"fo"), ("Zm9v", b"foo"), ("Zm9vYg==", b"foob"), ("/+8=", b"\xff\xef")] {
            assert_eq!(base64_decode_strict(text).as_deref(), Some(bytes), "{text}");
        }
        for text in [
            "Zg", "Zg=", "Zg===", "Z===", "====", "Zh==", "Zm9=", "Zm9v=", "Zm9vYg=", "Zg==Zg==", "Zg=A", "Zm9v\n", " Zm9v", "Zm 9v", "Zm9v\r\n", "Zm9", "Z", "-_8=", "Zm9\u{e9}", "Zm9v\0",
        ] {
            assert_eq!(base64_decode_strict(text), None, "{text:?}");
        }
        // every string of four from a small alphabet that decodes is the canonical encoding of what it decodes to
        let alphabet = b"AQgw+/0=";
        let mut accepted = 0;
        for n in 0..alphabet.len().pow(4) {
            let text: String = (0..4).map(|i| alphabet[n / alphabet.len().pow(i) % alphabet.len()] as char).collect();
            if let Some(bytes) = base64_decode_strict(&text) {
                assert_eq!(base64_encode(&bytes), text);
                accepted += 1;
            }
        }
        assert!(accepted > 100);
        // and the other way round
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            assert_eq!(base64_decode_strict(&base64_encode(&data)), Some(data));
        }
    }

    #[test]
    fn pem_blocks() {
        let text = "junk\n# comment\n-----BEGIN CERTIFICATE-----\nZm9v\nYmFy\n-----END CERTIFICATE-----\nmore\n-----BEGIN OTHER-----\nAAAA\n-----END OTHER-----\n";
        let blocks = parse(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].data, b"foobar");
        assert_eq!(blocks[1].label, "OTHER");
    }
}
