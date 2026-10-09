//! The fuzz target `aead`, compiled only with `--cfg pratique_fuzzing`: the AEAD code the build picked (the vector AES, carry-less multiply
//! and ChaCha20 kernels where the CPU has them; those are the only `unsafe` code in the library) against the portable code, on any key, nonce,
//! additional data and message, and against what a message that was changed must do. On an ARM machine it is the aarch64 kernels that are
//! held to the scalar code; on x86-64 it is the SSE and AES-NI ones.
//!
//! Input: one byte of switches, a 16- or 32-byte key (the first switch bit), a 12-byte nonce, one byte for the length of the additional
//! data, the additional data, and the message. A short input is padded with zeros.

use super::aes::Backend;
use super::chacha20poly1305::{seal_with_scalar_code, ChaCha20Poly1305};
use super::gcm::AesGcm;

fn take<'a>(data: &mut &'a [u8], n: usize, pad: &mut Vec<u8>) -> Vec<u8> {
    let n = n.min(data.len());
    let (head, rest) = data.split_at(n);
    *data = rest;
    pad.clear();
    head.to_vec()
}

pub fn aead(input: &[u8]) {
    let Some((&flags, mut data)) = input.split_first() else { return };
    let mut scratch = Vec::new();
    let key_len = if flags & 1 != 0 { 32 } else { 16 };
    let mut key = take(&mut data, key_len, &mut scratch);
    key.resize(key_len, 0);
    let mut nonce_bytes = take(&mut data, 12, &mut scratch);
    nonce_bytes.resize(12, 0);
    let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
    let aad_len = take(&mut data, 1, &mut scratch).first().copied().unwrap_or(0) as usize;
    let aad = take(&mut data, aad_len, &mut scratch);
    let plain = data.to_vec();

    // ---- AES-GCM: the code this CPU gets, and the portable code, make the same message and read each other's
    let (best, portable) = (AesGcm::new(&key), AesGcm::with_backend(&key, Backend::Portable));
    let sealed = best.seal(&nonce, &aad, &plain);
    assert_eq!(sealed, portable.seal(&nonce, &aad, &plain), "AES-GCM: the code this CPU uses ({:?}) and the portable code disagree (key {} bytes, {} of data, {} of additional data)", best.backend(), key_len, plain.len(), aad.len());
    assert_eq!(best.open(&nonce, &aad, &sealed).as_deref(), Some(plain.as_slice()));
    assert_eq!(portable.open(&nonce, &aad, &sealed).as_deref(), Some(plain.as_slice()));
    // the in-place forms (the ones a record layer uses) say what the others do
    let mut buf = plain.clone();
    buf.resize(plain.len() + 16, 0);
    best.seal_in_place(&nonce, &aad, &mut buf);
    assert_eq!(buf, sealed);
    assert_eq!(best.open_in_place(&nonce, &aad, &mut buf), Some(plain.len()));
    assert_eq!(&buf[..plain.len()], plain.as_slice());
    // a message that was changed anywhere (one bit of the ciphertext or the tag, the additional data, the nonce) is read by neither
    let flip = (flags as usize >> 1) * 7 + plain.len();
    let mut bad = sealed.clone();
    let at = flip % bad.len();
    bad[at] ^= 1 << (flip % 8);
    assert!(best.open(&nonce, &aad, &bad).is_none() && portable.open(&nonce, &aad, &bad).is_none(), "AES-GCM read a message with a bit changed at {at}");
    let mut other_aad = aad.clone();
    other_aad.push(flags);
    assert!(best.open(&nonce, &other_aad, &sealed).is_none() && portable.open(&nonce, &other_aad, &sealed).is_none());
    let mut other_nonce = nonce;
    other_nonce[flip % 12] ^= 1;
    assert!(best.open(&other_nonce, &aad, &sealed).is_none() && portable.open(&other_nonce, &aad, &sealed).is_none());

    // ---- ChaCha20-Poly1305: the vector kernel (4 blocks at a time) and the scalar block function make the same message
    let mut chacha_key = key.clone();
    chacha_key.resize(32, flags);
    let chacha = ChaCha20Poly1305::new(&chacha_key);
    let sealed = chacha.seal(&nonce, &aad, &plain);
    assert_eq!(sealed, seal_with_scalar_code(&chacha_key, &nonce, &aad, &plain), "ChaCha20-Poly1305: the vector code and the scalar code disagree ({} of data, {} of additional data)", plain.len(), aad.len());
    assert_eq!(chacha.open(&nonce, &aad, &sealed).as_deref(), Some(plain.as_slice()));
    let mut buf = plain.clone();
    buf.resize(plain.len() + 16, 0);
    chacha.seal_in_place(&nonce, &aad, &mut buf);
    assert_eq!(buf, sealed);
    assert_eq!(chacha.open_in_place(&nonce, &aad, &mut buf), Some(plain.len()));
    let mut bad = sealed.clone();
    let at = flip % bad.len();
    bad[at] ^= 1 << (flip % 8);
    assert!(chacha.open(&nonce, &aad, &bad).is_none(), "ChaCha20-Poly1305 read a message with a bit changed at {at}");
}

/// Inputs to start from: the lengths where the vector code changes how it works (a block, four blocks, eight, the groups around them).
pub fn example_inputs() -> Vec<Vec<u8>> {
    let make = |flags: u8, aad: usize, len: usize| {
        let mut v = vec![flags];
        v.extend((0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(1)));
        v.extend((0..12u8).map(|i| i.wrapping_mul(11).wrapping_add(3)));
        v.push(aad as u8);
        v.extend((0..aad).map(|i| (i * 13 + 5) as u8));
        v.extend((0..len).map(|i| (i * 31 + 7) as u8));
        v
    };
    let mut out = Vec::new();
    for (flags, aad, len) in [(0u8, 0usize, 0usize), (1, 5, 1), (0, 16, 15), (1, 29, 16), (0, 0, 63), (1, 5, 64), (0, 13, 65), (1, 0, 128), (0, 5, 255), (1, 5, 256), (0, 130, 257), (1, 20, 511), (0, 5, 1000)] {
        out.push(make(flags, aad, len));
    }
    out
}
