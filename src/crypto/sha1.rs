//! SHA-1 (FIPS 180-4), for two purposes, neither of which trusts it: OCSP identifies a certificate by
//! the SHA-1 hash of its issuer's name and key (RFC 6960 section 4.1.1), and nearly every responder
//! still does; and the `cms` module can say what a legacy signature over SHA-1 really is.
//!
//! It is `pub(crate)`. Signatures on certificates, CRLs and OCSP responses made with SHA-1 are
//! rejected, like everywhere else in the library. A collision attack on SHA-1 would let someone
//! craft *another issuer* with the same hash, which cannot make a response verify, because the
//! response signature is checked against the real issuer's key.
//!
//! `cms` checks a SHA-1 signature mathematically (so a caller can tell a damaged signature from an
//! old one) but reports it as weak, and a caller that wants to accept it has to say so; nothing
//! here is a verdict that the data is authentic.

pub(crate) const OUTPUT_LEN: usize = 20;

pub(crate) fn digest(data: &[u8]) -> [u8; OUTPUT_LEN] {
    let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut chunks = data.chunks_exact(64);
    for block in &mut chunks {
        compress(&mut h, block.try_into().unwrap());
    }
    // padding: 0x80, zeros, then the 64-bit big-endian length, to a multiple of 64 bytes
    let rest = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let total = if rest.len() < 56 { 64 } else { 128 };
    tail[total - 8..total].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..total].chunks_exact(64) {
        compress(&mut h, block.try_into().unwrap());
    }

    let mut out = [0u8; OUTPUT_LEN];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn fips_180_vectors() {
        assert_eq!(hex(&digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(hex(&digest(&million_a)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    /// Lengths around the padding boundaries (55, 56, 63, 64 bytes) against known hashes of
    /// `n` copies of 'a', computed with an independent implementation.
    #[test]
    fn padding_boundaries() {
        let cases = [
            (55usize, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
        ];
        for (n, want) in cases {
            assert_eq!(hex(&digest(&vec![b'a'; n])), want, "{n} bytes");
        }
    }
}
