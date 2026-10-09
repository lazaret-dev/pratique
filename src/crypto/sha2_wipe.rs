//! Wiping the state of the hash functions. Behind the `net` feature, with HMAC and HKDF: the hash
//! state of a TLS handshake has absorbed secrets (key blocks, shared secrets), while the pure
//! verification part of the crate hashes only public data and never needs this.

use super::sha2::{Sha256, Sha384, Sha512};
use crate::zeroize::Zeroize;

impl Zeroize for Sha256 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
        self.buf_len.zeroize();
        self.total.zeroize();
    }
}

impl Zeroize for super::sha2::Sha512Core {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
        self.buf_len.zeroize();
        self.total.zeroize();
    }
}

impl Zeroize for Sha512 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for Sha384 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
