#![no_std]
#![forbid(unsafe_code)]
mod sbox;

pub fn aes_sbox(q: &[u64; 8]) -> [u64; 8] {
    sbox::sbox(q)
}
