//! Encoding and decoding of TLS 1.3 handshake messages (RFC 8446 section 4).

use super::suite::Suite;
use crate::error::{Error, Result};
use crate::util::Reader;

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
/// The synthetic message that stands for ClientHello1 in the transcript after a HelloRetryRequest.
pub const HS_MESSAGE_HASH: u8 = 254;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_REQUEST: u8 = 13;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_STATUS_REQUEST: u16 = 5;
pub const EXT_SCT: u16 = 18;
pub const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
pub const EXT_OID_FILTERS: u16 = 48;
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;
pub const EXT_COOKIE: u16 = 44;
/// RFC 8446 section 4.2.11: the PSK identities (session tickets) a ClientHello offers, and the one a ServerHello takes.
pub const EXT_PRE_SHARED_KEY: u16 = 41;
/// RFC 8446 section 4.2.9: how a PSK may be used; this client offers `psk_dhe_ke` (1) only, a fresh key exchange with it.
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const PSK_DHE_KE: u8 = 1;
/// RFC 9001 section 8.2.
pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;

pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;
pub const GROUP_X25519: u16 = 0x001d;
/// The key-exchange groups offered in `supported_groups`, in order of preference. A ClientHello
/// carries a key share for the first only; a server that prefers another answers with a
/// HelloRetryRequest.
pub const SUPPORTED_GROUPS: [u16; 3] = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
pub const VERSION_TLS13: u16 = 0x0304;

/// Signature schemes we advertise. Only the first seven may sign a TLS 1.3 handshake; the PKCS#1
/// entries exist so that servers will present RSA-signed certificate chains, and may sign a TLS 1.2
/// ServerKeyExchange. None uses SHA-1, so a server that signs with SHA-1 signs with what was not offered.
pub const SIGNATURE_SCHEMES: [u16; 10] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0807, // ed25519
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256 (certificates, and a TLS 1.2 ServerKeyExchange)
    0x0501, // rsa_pkcs1_sha384 (certificates, and a TLS 1.2 ServerKeyExchange)
    0x0601, // rsa_pkcs1_sha512 (certificates, and a TLS 1.2 ServerKeyExchange)
];

/// RFC 8446 section 4.1.3: a TLS 1.3 server that negotiates TLS 1.2 or 1.1 ends its random with
/// "DOWNGRD" followed by 0x01 or 0x00. A client that sees this knows an attacker (or a broken
/// server) is trying to push the connection to an older version.
pub fn has_downgrade_sentinel(random: &[u8; 32]) -> bool {
    random[24..31] == *b"DOWNGRD" && random[31] <= 1
}

/// The fixed ServerHello.random value that marks a HelloRetryRequest.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16,
    0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put_vec16(v: &mut Vec<u8>, data: &[u8]) {
    put_u16(v, data.len() as u16);
    v.extend_from_slice(data);
}

fn extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    put_u16(out, ext_type);
    put_vec16(out, data);
}

/// Wraps `body` with the 4-byte handshake header.
pub fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(msg_type);
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

pub struct ClientHello<'a> {
    pub random: &'a [u8; 32],
    /// The legacy session id: 32 bytes over TCP (the compatibility mode), empty over QUIC.
    pub session_id: &'a [u8],
    pub server_name: Option<&'a str>,
    /// The one key share sent: its group and public value (32 bytes for X25519, an uncompressed
    /// point for the NIST curves).
    pub key_share_group: u16,
    pub key_share_public: &'a [u8],
    pub alpn: &'a [Vec<u8>],
    /// Ask the server to staple an OCSP response (RFC 6066 section 8).
    pub status_request: bool,
    /// The cookie from a HelloRetryRequest, echoed in the second ClientHello (RFC 8446 section 4.2.2).
    pub cookie: Option<&'a [u8]>,
    /// QUIC's transport parameters (RFC 9001 section 8.2), already encoded.
    pub quic_transport_parameters: Option<&'a [u8]>,
    /// Offer TLS 1.2 as well (after 1.3): its version, its cipher suites (ECDHE with an AEAD only) and the extensions it needs
    /// (the extended master secret, `renegotiation_info`, uncompressed points). Without it the ClientHello is TLS 1.3 only.
    pub tls12: bool,
    /// A session to resume: `psk_key_exchange_modes` (`psk_dhe_ke`) and, last of all, `pre_shared_key` with this one
    /// identity and a binder of zeros that [`set_psk_binder`] fills in.
    pub psk: Option<PskOffer<'a>>,
}

/// The one PSK a ClientHello offers.
pub struct PskOffer<'a> {
    /// The ticket.
    pub identity: &'a [u8],
    /// The ticket's age in milliseconds plus the server's `ticket_age_add`, modulo 2^32.
    pub obfuscated_age: u32,
    /// The length of the binder: the PSK's hash length.
    pub binder_len: usize,
}

/// The part of a ClientHello (with its handshake header) that a PSK binder is computed over: all of it but the binders
/// list at its end (RFC 8446 section 4.2.11.2), for a ClientHello built with one binder of `binder_len` bytes.
pub fn truncated_client_hello(client_hello: &[u8], binder_len: usize) -> &[u8] {
    &client_hello[..client_hello.len() - (2 + 1 + binder_len)]
}

/// Writes `binder` over the zeros [`build_client_hello`] left at the end of a ClientHello offering a PSK.
pub fn set_psk_binder(client_hello: &mut [u8], binder: &[u8]) {
    let n = client_hello.len();
    client_hello[n - binder.len()..].copy_from_slice(binder);
}

pub fn build_client_hello(ch: &ClientHello) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, 0x0303); // legacy_version
    body.extend_from_slice(ch.random);
    body.push(ch.session_id.len() as u8);
    body.extend_from_slice(ch.session_id);

    let mut suites: Vec<u16> = Suite::preference_order().iter().map(|s| s.id()).collect();
    if ch.tls12 {
        suites.extend(super::tls12::Suite12::preference_order().iter().map(|s| s.id()));
    }
    put_u16(&mut body, (suites.len() * 2) as u16);
    for s in suites {
        put_u16(&mut body, s);
    }
    body.extend_from_slice(&[1, 0]); // compression methods: null only

    let mut exts = Vec::new();
    if let Some(name) = ch.server_name {
        let mut e = Vec::new();
        put_u16(&mut e, (name.len() + 3) as u16); // ServerNameList length
        e.push(0); // host_name
        put_vec16(&mut e, name.as_bytes());
        extension(&mut exts, EXT_SERVER_NAME, &e);
    }
    let mut groups = Vec::new();
    let list: Vec<u8> = SUPPORTED_GROUPS.iter().flat_map(|g| g.to_be_bytes()).collect();
    put_vec16(&mut groups, &list);
    extension(&mut exts, EXT_SUPPORTED_GROUPS, &groups);

    let mut sigs = Vec::new();
    let mut list = Vec::new();
    for s in SIGNATURE_SCHEMES {
        put_u16(&mut list, s);
    }
    put_vec16(&mut sigs, &list);
    extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &sigs);

    if ch.tls12 {
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[4, 0x03, 0x04, 0x03, 0x03]);
    } else {
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
    }

    let mut share = Vec::new();
    put_u16(&mut share, ch.key_share_group);
    put_vec16(&mut share, ch.key_share_public);
    let mut shares = Vec::new();
    put_vec16(&mut shares, &share);
    extension(&mut exts, EXT_KEY_SHARE, &shares);

    if !ch.alpn.is_empty() {
        let mut protos = Vec::new();
        for p in ch.alpn {
            protos.push(p.len() as u8);
            protos.extend_from_slice(p);
        }
        let mut e = Vec::new();
        put_vec16(&mut e, &protos);
        extension(&mut exts, EXT_ALPN, &e);
    }

    if ch.status_request {
        // CertificateStatusRequest: status_type ocsp(1), an empty responder_id_list and empty
        // request_extensions: any responder, no nonce
        extension(&mut exts, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]);
    }

    if let Some(cookie) = ch.cookie {
        let mut e = Vec::new();
        put_vec16(&mut e, cookie);
        extension(&mut exts, EXT_COOKIE, &e);
    }

    if let Some(params) = ch.quic_transport_parameters {
        extension(&mut exts, EXT_QUIC_TRANSPORT_PARAMETERS, params);
    }

    if ch.tls12 {
        use super::tls12::{EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO};
        extension(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
        // an empty renegotiated_connection: this is a first handshake (RFC 5746), and none will follow
        extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0]);
        extension(&mut exts, EXT_EC_POINT_FORMATS, &[1, 0]);
    }

    if let Some(psk) = &ch.psk {
        extension(&mut exts, EXT_PSK_KEY_EXCHANGE_MODES, &[1, PSK_DHE_KE]);
        // OfferedPsks: identities<7..2^16-1> (identity<1..2^16-1>, obfuscated_ticket_age u32), binders<33..2^16-1>
        // (binder<32..255>); it must be the last extension (RFC 8446 section 4.2.11)
        let mut identity = Vec::new();
        put_vec16(&mut identity, psk.identity);
        identity.extend_from_slice(&psk.obfuscated_age.to_be_bytes());
        let mut e = Vec::new();
        put_vec16(&mut e, &identity);
        let mut binder = vec![psk.binder_len as u8];
        binder.resize(1 + psk.binder_len, 0);
        put_vec16(&mut e, &binder);
        extension(&mut exts, EXT_PRE_SHARED_KEY, &e);
    }

    put_vec16(&mut body, &exts);
    handshake_message(HS_CLIENT_HELLO, &body)
}

fn bad(msg: &str) -> Error {
    Error::Tls(format!("decode_error: {}", msg))
}

pub struct ServerHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub legacy_version: u16,
    pub selected_version: Option<u16>,
    /// (group, key_exchange). In a HelloRetryRequest the key is empty: only the group is sent.
    pub key_share: Option<(u16, Vec<u8>)>,
    /// The cookie of a HelloRetryRequest, to be echoed.
    pub cookie: Option<Vec<u8>>,
    /// The PSK identity the server took (`pre_shared_key`), if it took one.
    pub selected_identity: Option<u16>,
    /// Extensions of a ServerHello that are not TLS 1.3's, in order: the TLS 1.3 handshake refuses any, the TLS 1.2 one reads them.
    pub other_extensions: Vec<(u16, Vec<u8>)>,
}

/// Iterates over an extensions block, calling `f(type, data)`. Rejects duplicate types.
fn for_each_extension(data: &[u8], mut f: impl FnMut(u16, &[u8]) -> Result<()>) -> Result<()> {
    let mut r = Reader::new(data);
    let mut seen: Vec<u16> = Vec::new();
    while !r.is_empty() {
        let t = r.u16().ok_or_else(|| bad("truncated extension type"))?;
        let d = r.vec16().ok_or_else(|| bad("truncated extension"))?;
        if seen.contains(&t) {
            return Err(Error::Tls("illegal_parameter: duplicate extension".into()));
        }
        seen.push(t);
        f(t, d)?;
    }
    Ok(())
}

pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    let mut r = Reader::new(body);
    let legacy_version = r.u16().ok_or_else(|| bad("ServerHello version"))?;
    let random: [u8; 32] = r
        .take(32)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| bad("ServerHello random"))?;
    let session_id = r.vec8().ok_or_else(|| bad("ServerHello session id"))?.to_vec();
    let cipher_suite = r.u16().ok_or_else(|| bad("ServerHello cipher suite"))?;
    let compression = r.u8().ok_or_else(|| bad("ServerHello compression"))?;
    let exts = r.vec16().unwrap_or(&[]);
    if !r.is_empty() {
        return Err(bad("trailing data in ServerHello"));
    }
    let is_retry = random == HELLO_RETRY_REQUEST_RANDOM;
    let mut sh = ServerHello {
        random,
        session_id,
        cipher_suite,
        compression,
        legacy_version,
        selected_version: None,
        key_share: None,
        cookie: None,
        selected_identity: None,
        other_extensions: Vec::new(),
    };
    for_each_extension(exts, |t, d| {
        match t {
            EXT_SUPPORTED_VERSIONS => {
                if d.len() != 2 {
                    return Err(bad("supported_versions"));
                }
                sh.selected_version = Some(u16::from_be_bytes([d[0], d[1]]));
            }
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(d);
                let group = kr.u16().ok_or_else(|| bad("key_share group"))?;
                // A HelloRetryRequest carries only the group (RFC 8446 section 4.2.8); a
                // ServerHello carries the group and one key.
                let key = if is_retry { Vec::new() } else { kr.vec16().ok_or_else(|| bad("key_share key"))?.to_vec() };
                if !kr.is_empty() {
                    return Err(bad("trailing data in key_share"));
                }
                sh.key_share = Some((group, key));
            }
            EXT_COOKIE if !is_retry => return Err(Error::Tls("unsupported_extension: a cookie in a ServerHello".into())),
            EXT_COOKIE => {
                let mut cr = Reader::new(d);
                let cookie = cr.vec16().ok_or_else(|| bad("cookie"))?;
                if cookie.is_empty() || !cr.is_empty() {
                    return Err(bad("cookie"));
                }
                sh.cookie = Some(cookie.to_vec());
            }
            EXT_PRE_SHARED_KEY if !is_retry => {
                if d.len() != 2 {
                    return Err(bad("pre_shared_key"));
                }
                sh.selected_identity = Some(u16::from_be_bytes([d[0], d[1]]));
            }
            _ if is_retry => return Err(Error::Tls(format!("unsupported_extension: unexpected extension {} in ServerHello", t))),
            _ => sh.other_extensions.push((t, d.to_vec())),
        }
        Ok(())
    })?;
    Ok(sh)
}

/// What EncryptedExtensions told us.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedExtensions {
    /// The ALPN protocol the server selected, if any.
    pub alpn: Option<Vec<u8>>,
    /// The server's QUIC transport parameters, as sent (QUIC only).
    pub quic_transport_parameters: Option<Vec<u8>>,
}

/// Returns the ALPN protocol the server selected, if any.
///
/// Only extensions that RFC 8446 allows in EncryptedExtensions *and* that our ClientHello could
/// have solicited are accepted (section 4.2: an unsolicited extension must abort the handshake):
/// an empty server_name if we sent one, ALPN if we offered it, and supported_groups, which a
/// server may always send. Everything else (key_share and supported_versions belong in the
/// ServerHello, signature_algorithms in CertificateRequest, ...) is `unsupported_extension`.
#[cfg(test)]
pub fn parse_encrypted_extensions(body: &[u8], sent_sni: bool, offered_alpn: bool) -> Result<Option<Vec<u8>>> {
    Ok(parse_encrypted_extensions_for(body, sent_sni, offered_alpn, false)?.alpn)
}

/// [`parse_encrypted_extensions`] for a QUIC client too (`quic`): the server's `quic_transport_parameters`, which a client that
/// sent its own may be answered with, is returned; a client that did not send any refuses them like any other unsolicited
/// extension.
pub fn parse_encrypted_extensions_for(body: &[u8], sent_sni: bool, offered_alpn: bool, quic: bool) -> Result<EncryptedExtensions> {
    let mut r = Reader::new(body);
    let exts = r.vec16().ok_or_else(|| bad("EncryptedExtensions"))?;
    if !r.is_empty() {
        return Err(bad("trailing data in EncryptedExtensions"));
    }
    let mut alpn = None;
    let mut quic_transport_parameters = None;
    for_each_extension(exts, |t, d| {
        match t {
            EXT_SERVER_NAME if sent_sni => {
                if !d.is_empty() {
                    return Err(bad("server_name in EncryptedExtensions must be empty"));
                }
            }
            EXT_SUPPORTED_GROUPS => {
                let mut gr = Reader::new(d);
                let list = gr.vec16().ok_or_else(|| bad("supported_groups"))?;
                if !gr.is_empty() || list.len() % 2 != 0 {
                    return Err(bad("supported_groups"));
                }
            }
            EXT_ALPN if offered_alpn => {
                let mut ar = Reader::new(d);
                let list = ar.vec16().ok_or_else(|| bad("ALPN"))?;
                let mut lr = Reader::new(list);
                let proto = lr.vec8().ok_or_else(|| bad("ALPN protocol"))?;
                if !lr.is_empty() || !ar.is_empty() {
                    return Err(Error::Tls("illegal_parameter: server selected multiple ALPN protocols".into()));
                }
                if proto.is_empty() {
                    return Err(bad("empty ALPN protocol name"));
                }
                alpn = Some(proto.to_vec());
            }
            EXT_QUIC_TRANSPORT_PARAMETERS if quic => quic_transport_parameters = Some(d.to_vec()),
            _ => {
                return Err(Error::Tls(format!(
                    "unsupported_extension: extension {} is not allowed in EncryptedExtensions (or was not offered)",
                    t
                )))
            }
        }
        Ok(())
    })?;
    Ok(EncryptedExtensions { alpn, quic_transport_parameters })
}

/// A server's CertificateRequest (RFC 8446 section 4.3.2): its context and the signatures it takes from the client.
#[derive(Debug)]
pub struct CertificateRequest {
    pub context: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
}

/// Parses a CertificateRequest.
pub fn parse_certificate_request(body: &[u8]) -> Result<CertificateRequest> {
    let mut r = Reader::new(body);
    let context = r.vec8().ok_or_else(|| bad("CertificateRequest context"))?.to_vec();
    let exts = r.vec16().ok_or_else(|| bad("CertificateRequest extensions"))?;
    if !r.is_empty() {
        return Err(bad("trailing data in CertificateRequest"));
    }
    // signature_algorithms is mandatory here; the other allowed extensions are ignored.
    let mut signature_algorithms = None;
    for_each_extension(exts, |t, d| match t {
        EXT_SIGNATURE_ALGORITHMS => {
            let mut sr = Reader::new(d);
            let list = sr.vec16().filter(|l| !l.is_empty() && l.len() % 2 == 0 && sr.is_empty()).ok_or_else(|| bad("CertificateRequest signature_algorithms"))?;
            signature_algorithms = Some(list.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect());
            Ok(())
        }
        EXT_STATUS_REQUEST | EXT_SCT | EXT_CERTIFICATE_AUTHORITIES | EXT_OID_FILTERS | EXT_SIGNATURE_ALGORITHMS_CERT => Ok(()),
        _ => Err(Error::Tls(format!("unsupported_extension: extension {} is not allowed in CertificateRequest", t))),
    })?;
    let signature_algorithms = signature_algorithms.ok_or_else(|| Error::Tls("missing_extension: CertificateRequest has no signature_algorithms".into()))?;
    Ok(CertificateRequest { context, signature_algorithms })
}

/// What a server's Certificate message carries.
pub struct ServerCertificates {
    /// The DER certificates, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The stapled OCSP response of each entry of `chain`, if the server sent one.
    pub staples: Vec<Option<Vec<u8>>>,
}

/// Parses a Certificate message. An entry may carry a stapled OCSP response (RFC 8446 section
/// 4.4.2.1) only if the ClientHello asked for one (`status_request_offered`); any other entry
/// extension is a protocol violation.
pub fn parse_certificate(body: &[u8], status_request_offered: bool) -> Result<ServerCertificates> {
    let mut r = Reader::new(body);
    let ctx = r.vec8().ok_or_else(|| bad("Certificate context"))?;
    if !ctx.is_empty() {
        return Err(Error::Tls("illegal_parameter: non-empty certificate_request_context in server Certificate".into()));
    }
    let list = r.vec24().ok_or_else(|| bad("Certificate list"))?;
    if !r.is_empty() {
        return Err(bad("trailing data in Certificate"));
    }
    let mut lr = Reader::new(list);
    let mut certs = Vec::new();
    let mut staples = Vec::new();
    while !lr.is_empty() {
        let der = lr.vec24().ok_or_else(|| bad("certificate entry"))?;
        let entry_exts = lr.vec16().ok_or_else(|| bad("certificate extensions"))?;
        let mut staple = None;
        for_each_extension(entry_exts, |t, d| match t {
            EXT_STATUS_REQUEST if status_request_offered => {
                // CertificateStatus: status_type, then (for ocsp) opaque OCSPResponse<1..2^24-1>
                let mut sr = Reader::new(d);
                let status_type = sr.u8().ok_or_else(|| bad("CertificateStatus type"))?;
                let response = sr.vec24().ok_or_else(|| bad("CertificateStatus response"))?;
                if !sr.is_empty() {
                    return Err(bad("trailing data in CertificateStatus"));
                }
                if status_type == 1 && !response.is_empty() {
                    staple = Some(response.to_vec());
                }
                Ok(())
            }
            // we asked for nothing else, so a conforming server sends nothing else
            _ => Err(Error::Tls("unsupported_extension: unsolicited extension in a Certificate entry".into())),
        })?;
        if der.is_empty() {
            return Err(bad("empty certificate entry"));
        }
        certs.push(der.to_vec());
        staples.push(staple);
        if certs.len() > 16 {
            return Err(Error::Tls("illegal_parameter: certificate chain too long".into()));
        }
    }
    if certs.is_empty() {
        return Err(Error::Tls("decode_error: server sent an empty certificate list".into()));
    }
    Ok(ServerCertificates { chain: certs, staples })
}

pub fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>)> {
    let mut r = Reader::new(body);
    let scheme = r.u16().ok_or_else(|| bad("CertificateVerify scheme"))?;
    let sig = r.vec16().ok_or_else(|| bad("CertificateVerify signature"))?.to_vec();
    if !r.is_empty() {
        return Err(bad("trailing data in CertificateVerify"));
    }
    Ok((scheme, sig))
}

/// A NewSessionTicket (RFC 8446 section 4.6.1).
pub struct NewSessionTicket {
    /// Seconds the ticket may be used for (at most 604800, seven days).
    pub lifetime: u32,
    /// Added to the ticket's age, in milliseconds, when it is offered.
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
}

/// Parses a NewSessionTicket. Its extensions are skipped (the only one defined, `early_data`, is for 0-RTT, which this
/// client does not do), as the RFC asks of a client that does not know them; a duplicate one is still an error.
pub fn parse_new_session_ticket(body: &[u8]) -> Result<NewSessionTicket> {
    let mut r = Reader::new(body);
    let lifetime = r.u32().ok_or_else(|| bad("NewSessionTicket lifetime"))?;
    let age_add = r.u32().ok_or_else(|| bad("NewSessionTicket age_add"))?;
    let nonce = r.vec8().ok_or_else(|| bad("NewSessionTicket nonce"))?.to_vec();
    let ticket = r.vec16().ok_or_else(|| bad("NewSessionTicket ticket"))?.to_vec();
    let exts = r.vec16().ok_or_else(|| bad("NewSessionTicket extensions"))?;
    if !r.is_empty() {
        return Err(bad("trailing data in NewSessionTicket"));
    }
    if ticket.is_empty() {
        return Err(bad("empty ticket in NewSessionTicket"));
    }
    if lifetime > 604_800 {
        return Err(Error::Tls("illegal_parameter: a ticket lifetime over seven days".into()));
    }
    for_each_extension(exts, |_, _| Ok(()))?;
    Ok(NewSessionTicket { lifetime, age_add, nonce, ticket })
}

/// The data a server signs in CertificateVerify (RFC 8446 section 4.4.3).
pub fn server_certificate_verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    certificate_verify_content(b"TLS 1.3, server CertificateVerify", transcript_hash)
}

/// The data a client signs in its CertificateVerify.
pub fn client_certificate_verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    certificate_verify_content(b"TLS 1.3, client CertificateVerify", transcript_hash)
}

fn certificate_verify_content(context: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let mut c = vec![0x20u8; 64];
    c.extend_from_slice(context);
    c.push(0);
    c.extend_from_slice(transcript_hash);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let ch = build_client_hello(&ClientHello {
            random: &[1; 32],
            session_id: &[2; 32],
            server_name: Some("example.com"),
            key_share_group: GROUP_X25519,
            key_share_public: &[3; 32],
            alpn: &[b"http/1.1".to_vec()],
            status_request: false,
            cookie: None,
            quic_transport_parameters: None,
            psk: None,
            tls12: false,
        });
        assert_eq!(ch[0], HS_CLIENT_HELLO);
        let len = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | ch[3] as usize;
        assert_eq!(len, ch.len() - 4);
        // walk the body with the same reader the parsers use
        let mut r = Reader::new(&ch[4..]);
        assert_eq!(r.u16(), Some(0x0303));
        assert_eq!(r.take(32).unwrap(), &[1; 32]);
        assert_eq!(r.vec8().unwrap(), &[2; 32]);
        assert_eq!(r.vec16().unwrap().len(), 6);
        assert_eq!(r.vec8().unwrap(), &[0]);
        let exts = r.vec16().unwrap();
        assert!(r.is_empty());
        let mut types = Vec::new();
        for_each_extension(exts, |t, _| {
            types.push(t);
            Ok(())
        })
        .unwrap();
        assert_eq!(types, vec![EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_ALPN]);
    }

    #[test]
    fn client_hello_asks_for_a_staple_only_when_told_to() {
        let build = |status_request| {
            build_client_hello(&ClientHello {
                random: &[1; 32],
                session_id: &[2; 32],
                server_name: None,
                key_share_group: GROUP_X25519,
                key_share_public: &[3; 32],
                alpn: &[],
                status_request,
                cookie: None,
                quic_transport_parameters: None,
                psk: None,
            tls12: false,
            })
        };
        let extensions = |ch: &[u8]| {
            let mut r = Reader::new(&ch[4..]);
            r.u16();
            r.take(32);
            r.vec8();
            r.vec16();
            r.vec8();
            let mut found = Vec::new();
            for_each_extension(r.vec16().unwrap(), |t, d| {
                found.push((t, d.to_vec()));
                Ok(())
            })
            .unwrap();
            found
        };
        assert!(!extensions(&build(false)).iter().any(|(t, _)| *t == EXT_STATUS_REQUEST));
        let with = extensions(&build(true));
        // status_type ocsp, empty responder id list, empty request extensions
        assert!(with.contains(&(EXT_STATUS_REQUEST, vec![1, 0, 0, 0, 0])));
    }

    #[test]
    fn server_hello_parsing() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[9; 32]);
        body.push(32);
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        let mut exts = Vec::new();
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]);
        let mut ks = GROUP_X25519.to_be_bytes().to_vec();
        put_vec16(&mut ks, &[5; 32]);
        extension(&mut exts, EXT_KEY_SHARE, &ks);
        put_vec16(&mut body, &exts);
        let sh = parse_server_hello(&body).unwrap();
        assert_eq!(sh.cipher_suite, 0x1301);
        assert_eq!(sh.selected_version, Some(0x0304));
        assert_eq!(sh.key_share, Some((GROUP_X25519, vec![5; 32])));
        // duplicate extension is rejected
        let mut dup = exts.clone();
        extension(&mut dup, EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]);
        let mut b2 = body[..body.len() - exts.len() - 2].to_vec();
        put_vec16(&mut b2, &dup);
        assert!(parse_server_hello(&b2).is_err());
    }

    fn hello_with(random: [u8; 32], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        let mut e = Vec::new();
        for (t, d) in exts {
            extension(&mut e, *t, d);
        }
        put_vec16(&mut body, &e);
        body
    }

    fn rejects(body: &[u8]) -> String {
        parse_server_hello(body).err().expect("must be rejected").to_string()
    }

    #[test]
    fn hello_retry_request_parsing() {
        let versions = (EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04]);
        // group only, plus a cookie
        let retry = hello_with(
            HELLO_RETRY_REQUEST_RANDOM,
            &[versions.clone(), (EXT_KEY_SHARE, GROUP_SECP256R1.to_be_bytes().to_vec()), (EXT_COOKIE, vec![0, 3, 1, 2, 3])],
        );
        let hrr = parse_server_hello(&retry).unwrap();
        assert_eq!(hrr.random, HELLO_RETRY_REQUEST_RANDOM);
        assert_eq!(hrr.key_share, Some((GROUP_SECP256R1, Vec::new())));
        assert_eq!(hrr.cookie, Some(vec![1, 2, 3]));
        // a cookie alone is a valid retry as far as parsing goes
        let cookie_only = parse_server_hello(&hello_with(HELLO_RETRY_REQUEST_RANDOM, &[versions.clone(), (EXT_COOKIE, vec![0, 1, 9])])).unwrap();
        assert!(cookie_only.key_share.is_none() && cookie_only.cookie == Some(vec![9]));

        // the key_share of a retry is the group and nothing else
        assert!(rejects(&hello_with(HELLO_RETRY_REQUEST_RANDOM, &[versions.clone(), (EXT_KEY_SHARE, vec![0, 0x17, 0, 0])])).contains("decode_error"));
        assert!(rejects(&hello_with(HELLO_RETRY_REQUEST_RANDOM, &[versions.clone(), (EXT_KEY_SHARE, vec![0, 0x17, 1])])).contains("decode_error"));
        assert!(rejects(&hello_with(HELLO_RETRY_REQUEST_RANDOM, &[versions.clone(), (EXT_KEY_SHARE, vec![0])])).contains("decode_error"));
        // an empty cookie, a cookie with trailing bytes, a length that overruns
        for cookie in [vec![0, 0], vec![0, 1, 9, 9], vec![0, 5, 1]] {
            assert!(rejects(&hello_with(HELLO_RETRY_REQUEST_RANDOM, &[versions.clone(), (EXT_COOKIE, cookie)])).contains("decode_error"));
        }
    }

    #[test]
    fn a_server_hello_has_no_cookie_and_always_a_key() {
        let versions = (EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04]);
        // the cookie exists only in a HelloRetryRequest
        assert!(rejects(&hello_with([9; 32], &[versions.clone(), (EXT_COOKIE, vec![0, 1, 9])])).contains("unsupported_extension"));
        // a key_share naming only a group is a retry's, not a ServerHello's
        assert!(rejects(&hello_with([9; 32], &[versions.clone(), (EXT_KEY_SHARE, GROUP_X25519.to_be_bytes().to_vec())])).contains("decode_error"));
        // trailing bytes after the key
        let mut ks = GROUP_X25519.to_be_bytes().to_vec();
        put_vec16(&mut ks, &[5; 32]);
        ks.push(0);
        assert!(rejects(&hello_with([9; 32], &[versions, (EXT_KEY_SHARE, ks)])).contains("decode_error"));
    }

    #[test]
    fn client_hello_offers_three_groups_and_can_carry_a_cookie() {
        let hello = |cookie: Option<&[u8]>, group, public: &[u8]| {
            build_client_hello(&ClientHello {
                random: &[1; 32],
                session_id: &[2; 32],
                server_name: None,
                key_share_group: group,
                key_share_public: public,
                alpn: &[],
                status_request: false,
                cookie,
                quic_transport_parameters: None,
                psk: None,
            tls12: false,
            })
        };
        let exts = |ch: &[u8]| {
            let mut r = Reader::new(&ch[4..]);
            r.u16();
            r.take(32);
            r.vec8();
            r.vec16();
            r.vec8();
            let mut found = Vec::new();
            for_each_extension(r.vec16().unwrap(), |t, d| {
                found.push((t, d.to_vec()));
                Ok(())
            })
            .unwrap();
            found
        };
        let first = exts(&hello(None, GROUP_X25519, &[3; 32]));
        assert!(first.contains(&(EXT_SUPPORTED_GROUPS, vec![0, 6, 0, 0x1d, 0, 0x17, 0, 0x18])));
        assert!(!first.iter().any(|(t, _)| *t == EXT_COOKIE));
        let second = exts(&hello(Some(&[7, 8, 9]), GROUP_SECP256R1, &[4; 65]));
        assert!(second.contains(&(EXT_COOKIE, vec![0, 3, 7, 8, 9])));
        let mut share = GROUP_SECP256R1.to_be_bytes().to_vec();
        put_vec16(&mut share, &[4; 65]);
        let mut expected = Vec::new();
        put_vec16(&mut expected, &share);
        assert!(second.contains(&(EXT_KEY_SHARE, expected)));
    }

    #[test]
    fn certificate_parsing() {
        // context(0) | list: one cert "abc" with empty extensions
        let mut entry = vec![0, 0, 3, b'a', b'b', b'c', 0, 0];
        let mut body = vec![0u8];
        let l = entry.len();
        body.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        body.append(&mut entry);
        assert_eq!(parse_certificate(&body, false).unwrap().chain, vec![b"abc".to_vec()]);
        assert!(parse_certificate(&[0, 0, 0, 0], false).is_err()); // empty list
    }
}

#[cfg(test)]
mod strictness_tests {
    use super::*;

    fn ext(t: u16, data: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn block16(inner: &[u8]) -> Vec<u8> {
        let mut v = (inner.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(inner);
        v
    }

    fn alpn_ext(proto: &[u8]) -> Vec<u8> {
        let mut list = vec![proto.len() as u8];
        list.extend_from_slice(proto);
        ext(EXT_ALPN, &block16(&list))
    }

    #[test]
    fn encrypted_extensions_accept_only_solicited_extensions() {
        // an empty body, and the extensions a conforming server may send
        assert_eq!(parse_encrypted_extensions(&block16(&[]), true, true).unwrap(), None);
        let mut ok = ext(EXT_SERVER_NAME, &[]);
        ok.extend(ext(EXT_SUPPORTED_GROUPS, &block16(&[0, 0x1d])));
        ok.extend(alpn_ext(b"h2"));
        assert_eq!(parse_encrypted_extensions(&block16(&ok), true, true).unwrap(), Some(b"h2".to_vec()));

        let reject = |exts: Vec<u8>, sni: bool, alpn: bool| -> String {
            parse_encrypted_extensions(&block16(&exts), sni, alpn).unwrap_err().to_string()
        };
        // belongs in another message
        for t in [EXT_KEY_SHARE, EXT_SUPPORTED_VERSIONS, EXT_SIGNATURE_ALGORITHMS, 41 /* pre_shared_key */, 42 /* early_data */] {
            assert!(reject(ext(t, &[0, 0]), true, true).contains("unsupported_extension"), "type {}", t);
        }
        // not offered by us
        assert!(reject(ext(EXT_SERVER_NAME, &[]), false, true).contains("unsupported_extension"));
        assert!(reject(alpn_ext(b"h2"), true, false).contains("unsupported_extension"));
        // malformed forms of the allowed ones
        assert!(reject(ext(EXT_SERVER_NAME, &[1]), true, true).contains("decode_error"));
        assert!(reject(ext(EXT_SUPPORTED_GROUPS, &block16(&[0])), true, true).contains("decode_error"));
        assert!(reject(alpn_ext(b""), true, true).contains("decode_error"));
        // duplicates
        let mut dup = alpn_ext(b"h2");
        dup.extend(alpn_ext(b"h2"));
        assert!(reject(dup, true, true).contains("duplicate"));
    }

    #[test]
    fn certificate_request_needs_signature_algorithms() {
        let sigalgs = ext(EXT_SIGNATURE_ALGORITHMS, &block16(&[0x04, 0x03]));
        let mut body = vec![2, 0xaa, 0xbb];
        body.extend(block16(&sigalgs));
        let request = parse_certificate_request(&body).unwrap();
        assert_eq!((request.context, request.signature_algorithms), (vec![0xaa, 0xbb], vec![0x0403]));
        // other legitimate extensions are fine alongside it
        let mut more = sigalgs.clone();
        more.extend(ext(EXT_CERTIFICATE_AUTHORITIES, &block16(&[])));
        let mut body = vec![0];
        body.extend(block16(&more));
        assert!(parse_certificate_request(&body).is_ok());
        // missing signature_algorithms
        let mut body = vec![0];
        body.extend(block16(&[]));
        assert!(parse_certificate_request(&body).unwrap_err().to_string().contains("missing_extension"));
        // an extension that has no business here
        let mut bad = sigalgs;
        bad.extend(ext(EXT_KEY_SHARE, &[]));
        let mut body = vec![0];
        body.extend(block16(&bad));
        assert!(parse_certificate_request(&body).unwrap_err().to_string().contains("unsupported_extension"));
    }

    fn certificate_body(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (der, exts) in entries {
            list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
            list.extend_from_slice(der);
            list.extend(block16(exts));
        }
        let mut body = vec![0];
        body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        body.extend(list);
        body
    }

    #[test]
    fn certificate_entries_reject_unsolicited_extensions_and_empty_certs() {
        let parsed = parse_certificate(&certificate_body(&[(b"abc", b"")]), false).unwrap();
        assert_eq!(parsed.chain, vec![b"abc".to_vec()]);
        assert_eq!(parsed.staples, vec![None]);
        // an OCSP response we never asked for
        let status = ext(EXT_STATUS_REQUEST, &[1, 0, 0, 1, 0xaa]);
        let err = parse_certificate(&certificate_body(&[(b"abc", &status)]), false).err().unwrap().to_string();
        assert!(err.contains("unsupported_extension"), "{}", err);
        assert!(parse_certificate(&certificate_body(&[(b"", b"")]), false).err().unwrap().to_string().contains("empty certificate"));
        assert!(parse_certificate(&certificate_body(&[]), false).err().unwrap().to_string().contains("empty certificate list"));
    }

    #[test]
    fn certificate_entries_carry_a_staple_when_one_was_requested() {
        let staple = ext(EXT_STATUS_REQUEST, &[1, 0, 0, 3, 0xde, 0xad, 0xbf]);
        let body = certificate_body(&[(b"leaf", &staple), (b"inter", b"")]);
        let parsed = parse_certificate(&body, true).unwrap();
        assert_eq!(parsed.chain, vec![b"leaf".to_vec(), b"inter".to_vec()]);
        assert_eq!(parsed.staples, vec![Some(vec![0xde, 0xad, 0xbf]), None]);
        // a status type other than ocsp is ignored, an empty response is no response
        for data in [&[2u8, 0, 0, 1, 0xaa][..], &[1, 0, 0, 0][..]] {
            let parsed = parse_certificate(&certificate_body(&[(b"leaf", &ext(EXT_STATUS_REQUEST, data))]), true).unwrap();
            assert_eq!(parsed.staples, vec![None]);
        }
        // malformed: truncated, trailing bytes, a second status_request, another extension type
        for bad_ext in [
            ext(EXT_STATUS_REQUEST, &[1, 0, 0, 5, 1]),
            ext(EXT_STATUS_REQUEST, &[1, 0, 0, 1, 0xaa, 0xbb]),
            ext(EXT_STATUS_REQUEST, &[]),
            [staple.clone(), staple.clone()].concat(),
            ext(EXT_SCT, &[0, 0]),
        ] {
            assert!(parse_certificate(&certificate_body(&[(b"leaf", &bad_ext)]), true).is_err(), "{:02x?}", bad_ext);
        }
    }

    #[test]
    fn downgrade_sentinel_detection() {
        let mut r = [7u8; 32];
        assert!(!has_downgrade_sentinel(&r));
        r[24..32].copy_from_slice(b"DOWNGRD\x01");
        assert!(has_downgrade_sentinel(&r));
        r[31] = 0;
        assert!(has_downgrade_sentinel(&r));
        r[31] = 2;
        assert!(!has_downgrade_sentinel(&r));
    }

    #[test]
    fn parsers_survive_arbitrary_bytes() {
        use crate::fuzz::{random_up_to, run};
        run("tls_message_parsers", 4000, |rng| {
            let data = random_up_to(rng, 200);
            let _ = parse_server_hello(&data);
            let _ = parse_encrypted_extensions(&data, true, true);
            let _ = parse_encrypted_extensions(&data, false, false);
            let _ = parse_certificate_request(&data);
            let _ = parse_certificate(&data, true);
            let _ = parse_certificate(&data, false);
            let _ = parse_certificate_verify(&data);
        });
    }
}
