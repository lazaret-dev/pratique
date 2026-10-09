//! Small shared helpers (hex, constant-time comparison, byte readers).

pub fn hex(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex digit"),
        })
        .collect();
    assert!(digits.len() % 2 == 0, "odd hex length");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// Constant-time equality for byte strings (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// A cursor over a byte slice with checked, big-endian reads.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
    /// Reads a vector with a 1-byte length prefix.
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// Reads a vector with a 2-byte length prefix.
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// Reads a vector with a 3-byte length prefix.
    pub fn vec24(&mut self) -> Option<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small generator of its own: this file is in the part of the crate that has no dependencies, not even on
    /// the crate's fuzzing helpers.
    struct Xorshift(u64);
    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// The obvious definition, checked byte by byte with an early exit: right, and not constant time.
    fn reference(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
    }

    #[test]
    fn ct_eq_agrees_with_a_byte_by_byte_comparison_on_every_single_difference() {
        assert!(ct_eq(b"", b""));
        for len in 1..=48usize {
            let a = Xorshift(0x9e37_79b9_7f4a_7c15 ^ len as u64).bytes(len);
            assert!(ct_eq(&a, &a.clone()), "equal strings of {len} bytes");
            // one bit different, in each position and each bit (so the first, the last and every one between)
            for at in 0..len {
                for bit in 0..8 {
                    let mut b = a.clone();
                    b[at] ^= 1 << bit;
                    assert!(!ct_eq(&a, &b), "{len} bytes, bit {bit} of byte {at}");
                    assert!(!ct_eq(&b, &a));
                }
            }
            // a different length is a different string, even when one is the start of the other
            assert!(!ct_eq(&a, &a[..len - 1]));
            assert!(!ct_eq(&a[..len - 1], &a));
            let mut longer = a.clone();
            longer.push(0);
            assert!(!ct_eq(&a, &longer));
        }
    }

    #[test]
    fn ct_eq_agrees_with_a_byte_by_byte_comparison_on_random_and_special_strings() {
        let mut rng = Xorshift(0x2545_f491_4f6c_dd1d);
        for _ in 0..20_000 {
            let len = (rng.next() % 40) as usize;
            let a = rng.bytes(len);
            // equal, a few bytes changed, wholly random, all zero against all zero, all ones against zeros
            let b = match rng.next() % 5 {
                0 => a.clone(),
                1 => {
                    let mut b = a.clone();
                    for _ in 0..1 + rng.next() % 3 {
                        if !b.is_empty() {
                            let i = rng.next() as usize % b.len();
                            b[i] = rng.next() as u8;
                        }
                    }
                    b
                }
                2 => rng.bytes(len),
                3 => vec![0; len],
                _ => vec![0xff; len],
            };
            assert_eq!(ct_eq(&a, &b), reference(&a, &b), "{a:02x?} against {b:02x?}");
            assert_eq!(ct_eq(&vec![0; len], &b), reference(&vec![0; len], &b));
        }
    }
}
