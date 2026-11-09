// Compile and run the clean-room primitive tests before integration touches
// either superseded implementation.  The integration commit will make these
// modules part of `crypto` and can then remove this temporary path harness.
#[path = "../src/crypto/aes_sbox_clean.rs"]
mod aes_sbox_clean;
#[path = "../src/crypto/clmul_clean.rs"]
mod clmul_clean;
