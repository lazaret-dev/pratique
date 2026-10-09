//! Cryptographic primitives, written from scratch using only `std`.
//!
//! None of this has been independently audited. See the crate README for caveats.
//!
//! The verification primitives (SHA-1/2, big numbers, RSA and ECDSA verification) are always built and
//! are free of `unsafe`. Everything TLS needs beyond them (HMAC and HKDF, AES and GCM, ChaCha20-
//! Poly1305, X25519, ECDH, the operating system's random numbers, the SIMD kernels, and wiping the
//! hash states) is behind the `net` feature.

// ---- pure (always built)
pub(crate) mod bignum;
pub mod ecdsa;
pub mod ed25519;
pub(crate) mod fe25519;
pub mod rsa;
pub(crate) mod sha1;
pub mod sha2;
mod sha2_consts;
#[cfg(test)]
pub(crate) mod test_vectors;

// ---- behind `net`
#[cfg(all(test, feature = "net"))]
pub(crate) mod aead_vectors;
#[cfg(feature = "net")]
pub mod aes;
#[cfg(feature = "net")]
mod aes_ct;
#[cfg(feature = "net")]
mod aes_hw;
#[cfg(feature = "net")]
pub mod chacha20poly1305;
// ARM's data-independent timing mode around the secret arithmetic (BACKLOG B-99)
#[cfg(feature = "net")]
pub(crate) mod dit;
#[cfg(feature = "net")]
pub mod ecdh;
#[cfg(any(test, feature = "server"))]
pub mod ed25519_sign;
#[cfg(all(test, feature = "net"))]
pub(crate) mod ecdh_vectors;
#[cfg(feature = "net")]
pub mod gcm;
#[cfg(feature = "net")]
pub mod hmac;
#[cfg(feature = "net")]
mod ghash;
#[cfg(feature = "net")]
mod poly1305;
#[cfg(feature = "net")]
pub mod rand;
#[cfg(feature = "net")]
mod sha2_wipe;
#[cfg(feature = "net")]
mod sha2_hw;

/// The SHA-2 block functions this CPU has instructions for, checked against the portable ones (`sha2_hw`); a build
/// without `net` has no code for any (B-103).
#[cfg(feature = "net")]
fn sha2_hardware() -> sha2::Accel {
    sha2_hw::detect()
}
/// See above: none without `net`.
#[cfg(not(feature = "net"))]
fn sha2_hardware() -> sha2::Accel {
    sha2::Accel::NONE
}
// P-256 verification compiled for x86-64's BMI2 and ADX (B-104)
#[cfg(feature = "net")]
mod ecdsa_hw;

/// A P-256 verification compiled for an instruction set extension this CPU has (`ecdsa_hw`), or none; a build without
/// `net` has none (B-104).
#[cfg(feature = "net")]
fn ecdsa_hardware() -> Option<ecdsa::Verify> {
    ecdsa_hw::detect()
}
/// See above: none without `net`.
#[cfg(not(feature = "net"))]
fn ecdsa_hardware() -> Option<ecdsa::Verify> {
    None
}
#[cfg(feature = "net")]
pub mod x25519;
// X25519 key generation by a table of multiples of the base point, constant time (B-103)
#[cfg(feature = "net")]
mod x25519_base;
#[cfg(all(test, feature = "net"))]
mod timing;

/// Entry points for the coverage-guided fuzzer in `fuzz/`; compiled only with `--cfg pratique_fuzzing`. Not part of the API.
#[cfg(all(pratique_fuzzing, feature = "net"))]
#[doc(hidden)]
pub mod fuzz_hooks {
    pub use super::fuzz_aead::{aead, example_inputs as aead_example_inputs};
}
#[cfg(all(pratique_fuzzing, feature = "net"))]
mod fuzz_aead;
