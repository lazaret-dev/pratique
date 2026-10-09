//! The error type of the verification part of the crate (ASN.1, X.509, revocation, signatures).
//!
//! It knows nothing about sockets, TLS or HTTP: the `net` side has its own error type
//! (`error::Error`) that wraps this one.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Certificate parsing or validation failed.
    Certificate(String),
    /// Malformed ASN.1 / DER.
    Asn1(&'static str),
    /// Evidence that was asked for could not be obtained (a CRL could not be downloaded, say). What
    /// that means is the revocation policy's decision: soft-fail goes on, hard-fail refuses.
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Certificate(m) => write!(f, "certificate error: {}", m),
            Error::Asn1(m) => write!(f, "ASN.1 error: {}", m),
            Error::Unavailable(m) => write!(f, "unavailable: {}", m),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn cert<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Certificate(msg.into()))
}
