//! Error type of the `net` side of the library (TLS, HTTP, sockets). Errors from the verification
//! part ([`crate::verify_error`]) are wrapped in [`Error::Verify`]; `?` converts them.

use crate::verify_error;
use std::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying socket or file I/O failure.
    Io(std::io::Error),
    /// TLS protocol violation or handshake failure.
    Tls(String),
    /// The peer sent an alert.
    Alert(u8, u8),
    /// HTTP-level failure (bad URL, malformed response, too many redirects...).
    Http(String),
    /// Certificate, ASN.1 or revocation checking failed (the verification part of the crate).
    Verify(verify_error::Error),
    /// The client refused to send a request, or a redirect it was following, to where it was going, by its own rules and before it connected
    /// to anything: not a network failure, and not a bad server. See [`Refused`].
    Refused(Refused),
    /// A compressed response body (see [`Client::decompress`](crate::http::Client::decompress)) could not be decoded: it is not valid
    /// compressed data, it is cut short, it fails its checksum, or it would come to more than the limits on the decoded size allow.
    /// What had been read of such a body is not to be trusted.
    Decode(crate::inflate::Error),
    /// The request's batch was cancelled ([`Batch::cancel`](crate::http::Batch::cancel)): it was stopped while it waited
    /// to start or while it was under way, or it was made after the cancel.
    Cancelled,
}

/// A request or a redirect that the client's rules did not allow: nothing was sent to the host it named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// 0 if the request itself was refused, 1 for the first redirect it was sent on, and so on.
    pub hop: usize,
    /// Which rule said no.
    pub by: RefusedBy,
    /// Why, in words (it names the host, never a credential, a header value or the path of the URL).
    pub reason: String,
}

/// The rule that refused a request or a redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusedBy {
    /// The rule about hosts of [`Client::allowed_hosts`](crate::http::Client::allowed_hosts).
    HostRule,
    /// A limit on the URL of [`Client::url_limits`](crate::http::Client::url_limits) (its length, its characters, credentials in it, a scheme).
    UrlLimit,
    /// The scheme: plain http without `allow_insecure_http`, or a redirect from https to plain http.
    Scheme,
    /// The hook of [`Client::hop_headers`](crate::http::Client::hop_headers) said no.
    Hook,
}

impl Refused {
    /// Whether this is a redirect that was refused (not the request the caller made).
    pub fn is_redirect(&self) -> bool {
        self.hop > 0
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hop == 0 {
            write!(f, "request refused: {}", self.reason)
        } else {
            write!(f, "redirect {} refused: {}", self.hop, self.reason)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The name of a TLS alert description (RFC 8446 section 6 and the IANA registry), if it has one.
pub fn alert_name(description: u8) -> Option<&'static str> {
    Some(match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => return None,
    })
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Tls(m) => write!(f, "TLS error: {}", m),
            Error::Alert(level, desc) => {
                write!(f, "TLS alert received (level {}, description {}", level, desc)?;
                if let Some(name) = alert_name(*desc) {
                    write!(f, ": {}", name)?;
                }
                f.write_str(")")?;
                match desc {
                    // what servers that cannot do TLS 1.3 answer, which is all this library speaks
                    70 | 40 => f.write_str("; a server that speaks only TLS 1.2 often answers a TLS 1.3 client like this"),
                    _ => Ok(()),
                }
            }
            Error::Http(m) => write!(f, "HTTP error: {}", m),
            Error::Verify(e) => e.fmt(f),
            Error::Refused(r) => r.fmt(f),
            Error::Decode(e) => write!(f, "response body could not be decoded: {}", e),
            Error::Cancelled => f.write_str("cancelled: the request's batch was cancelled"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<verify_error::Error> for Error {
    fn from(e: verify_error::Error) -> Self {
        Error::Verify(e)
    }
}

pub(crate) fn cert<T>(msg: impl Into<String>) -> Result<T> {
    Err(verify_error::Error::Certificate(msg.into()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_are_named_and_a_tls_1_2_only_server_is_hinted_at() {
        assert_eq!(alert_name(70), Some("protocol_version"));
        assert_eq!(alert_name(40), Some("handshake_failure"));
        assert_eq!(alert_name(48), Some("unknown_ca"));
        assert_eq!(alert_name(255), None);
        let m = Error::Alert(2, 70).to_string();
        assert!(m.starts_with("TLS alert received (level 2, description 70: protocol_version)"), "{m}");
        assert!(m.contains("TLS 1.2"), "{m}");
        let m = Error::Alert(2, 40).to_string();
        assert!(m.contains("handshake_failure") && m.contains("TLS 1.2"), "{m}");
        // an alert that has nothing to do with versions says no such thing, and an unknown one still prints
        let m = Error::Alert(2, 48).to_string();
        assert_eq!(m, "TLS alert received (level 2, description 48: unknown_ca)");
        assert_eq!(Error::Alert(1, 200).to_string(), "TLS alert received (level 1, description 200)");
    }
}
