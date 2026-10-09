//! QUIC transport parameters (RFC 9000 section 18), the `quic_transport_parameters` TLS extension's content.
//!
//! The value is a list of parameters, each a variable-length integer id, a length and a value, in any order. A parameter that is
//! not known is ignored (and kept, for whoever wants to see it); one that is sent twice, or a known one with a value it may not
//! have, or one that only a server may send but a client sent, is a connection error of type TRANSPORT_PARAMETER_ERROR (0x08).
//! Which values mean something for the connection (that `initial_source_connection_id` is the id of the packets that came, that
//! `original_destination_connection_id` is the one the client chose) is for the connection to check; what is checked here is
//! what a parameter says of itself, and that the ones that must be there are.

use super::frame::MAX_STREAMS_LIMIT;
use super::packet::MAX_CID_LEN;
use super::wire::{put_varint, varint_len, Reader, MAX_VARINT};

/// The transport error code of a parameter that is not acceptable.
pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;

/// The smallest `max_udp_payload_size` (a QUIC datagram of 1200 bytes has to be possible).
pub const MIN_UDP_PAYLOAD_SIZE: u64 = 1200;

/// The values of parameters that are not sent.
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;
pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
pub const DEFAULT_MAX_ACK_DELAY: u64 = 25;
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// The largest `ack_delay_exponent`, and the (exclusive) limit of `max_ack_delay` in milliseconds.
pub const MAX_ACK_DELAY_EXPONENT: u64 = 20;
pub const MAX_ACK_DELAY_LIMIT: u64 = 1 << 14;

mod id {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    /// RFC 9221.
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
}

/// Who sent the parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sender {
    Client,
    Server,
}

/// What is wrong with a set of parameters. It is always a TRANSPORT_PARAMETER_ERROR; the text says which.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error(pub &'static str);

impl Error {
    pub fn transport_error(&self) -> u64 {
        TRANSPORT_PARAMETER_ERROR
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport parameters: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// A server's preferred address (RFC 9000 section 18.2). An address family the server does not offer has an address and a port of
/// zero; the fields keep what was sent.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreferredAddress {
    pub ipv4: ([u8; 4], u16),
    pub ipv6: ([u8; 16], u16),
    /// The connection id to use at the new address (1 to 20 bytes).
    pub connection_id: Vec<u8>,
    pub stateless_reset_token: [u8; 16],
}

impl PreferredAddress {
    /// The IPv4 address and port, if there are any (both must be non-zero).
    pub fn ipv4_address(&self) -> Option<([u8; 4], u16)> {
        (self.ipv4.1 != 0 && self.ipv4.0 != [0; 4]).then_some(self.ipv4)
    }

    /// The IPv6 address and port, if there are any.
    pub fn ipv6_address(&self) -> Option<([u8; 16], u16)> {
        (self.ipv6.1 != 0 && self.ipv6.0 != [0; 16]).then_some(self.ipv6)
    }
}

/// The transport parameters of one side. Parameters that are not sent have their default values.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransportParameters {
    /// Server only: the destination connection id of the first Initial packet the client sent.
    pub original_destination_connection_id: Option<Vec<u8>>,
    /// In milliseconds; 0 is no idle timeout.
    pub max_idle_timeout: u64,
    /// Server only.
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u8,
    /// In milliseconds.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    /// Server only.
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: u64,
    /// The source connection id of the first packet the sender sent (RFC 9000 section 7.3): required of both sides.
    pub initial_source_connection_id: Option<Vec<u8>>,
    /// Server only: the source connection id of the Retry packet, if the server sent one.
    pub retry_source_connection_id: Option<Vec<u8>>,
    /// RFC 9221: the largest DATAGRAM frame the sender takes. Read and written; nothing here sends DATAGRAM frames.
    pub max_datagram_frame_size: Option<u64>,
    /// Parameters of ids that are not known, in the order they came (or are to be written: a "grease" parameter, whose id is
    /// 31 * N + 27, goes here).
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl Default for TransportParameters {
    fn default() -> TransportParameters {
        TransportParameters {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay: DEFAULT_MAX_ACK_DELAY,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: None,
            unknown: Vec::new(),
        }
    }
}

fn err<T>(what: &'static str) -> Result<T, Error> {
    Err(Error(what))
}

fn connection_id(value: &[u8]) -> Result<Vec<u8>, Error> {
    if value.len() > MAX_CID_LEN {
        return err("a connection id is longer than 20 bytes");
    }
    Ok(value.to_vec())
}

/// A value that is one variable-length integer and nothing else.
fn number(value: &[u8]) -> Result<u64, Error> {
    let mut r = Reader::new(value);
    let v = r.varint().or(err("a number that is cut short"))?;
    if !r.is_empty() {
        return err("a number with more bytes than its length says");
    }
    Ok(v)
}

fn preferred_address(value: &[u8]) -> Result<PreferredAddress, Error> {
    let mut r = Reader::new(value);
    let short = || Error("preferred_address is cut short");
    let mut v4 = [0u8; 4];
    v4.copy_from_slice(r.bytes(4).map_err(|_| short())?);
    let p4 = u16::from_be_bytes(r.bytes(2).map_err(|_| short())?.try_into().unwrap());
    let mut v6 = [0u8; 16];
    v6.copy_from_slice(r.bytes(16).map_err(|_| short())?);
    let p6 = u16::from_be_bytes(r.bytes(2).map_err(|_| short())?.try_into().unwrap());
    let cid_len = r.u8().map_err(|_| short())? as usize;
    if cid_len == 0 || cid_len > MAX_CID_LEN {
        return err("preferred_address has a connection id that is not 1 to 20 bytes");
    }
    let connection_id = r.bytes(cid_len).map_err(|_| short())?.to_vec();
    let mut token = [0u8; 16];
    token.copy_from_slice(r.bytes(16).map_err(|_| short())?);
    if !r.is_empty() {
        return err("preferred_address is longer than what it holds");
    }
    Ok(PreferredAddress { ipv4: (v4, p4), ipv6: (v6, p6), connection_id, stateless_reset_token: token })
}

impl TransportParameters {
    /// Reads the parameters that `sender` sent. The parameters that must be there (`initial_source_connection_id` from both,
    /// `original_destination_connection_id` from a server) are checked for.
    pub fn decode(data: &[u8], sender: Sender) -> Result<TransportParameters, Error> {
        let mut p = TransportParameters::default();
        let mut r = Reader::new(data);
        let mut ids: Vec<u64> = Vec::new();
        while !r.is_empty() {
            let pid = r.varint().or(err("an id that is cut short"))?;
            let len = r.varint().or(err("a length that is cut short"))?;
            let value = usize::try_from(len).ok().and_then(|len| r.bytes(len).ok());
            let Some(value) = value else { return err("a parameter longer than what is left") };
            ids.push(pid);
            let server_only = |sender: Sender| if sender == Sender::Client { err("a client sent a parameter that only a server sends") } else { Ok(()) };
            match pid {
                id::ORIGINAL_DESTINATION_CONNECTION_ID => {
                    server_only(sender)?;
                    p.original_destination_connection_id = Some(connection_id(value)?);
                }
                id::MAX_IDLE_TIMEOUT => p.max_idle_timeout = number(value)?,
                id::STATELESS_RESET_TOKEN => {
                    server_only(sender)?;
                    let Ok(token) = <[u8; 16]>::try_from(value) else { return err("a stateless_reset_token that is not 16 bytes") };
                    p.stateless_reset_token = Some(token);
                }
                id::MAX_UDP_PAYLOAD_SIZE => {
                    p.max_udp_payload_size = number(value)?;
                    if p.max_udp_payload_size < MIN_UDP_PAYLOAD_SIZE {
                        return err("max_udp_payload_size below 1200");
                    }
                }
                id::INITIAL_MAX_DATA => p.initial_max_data = number(value)?,
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => p.initial_max_stream_data_bidi_local = number(value)?,
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => p.initial_max_stream_data_bidi_remote = number(value)?,
                id::INITIAL_MAX_STREAM_DATA_UNI => p.initial_max_stream_data_uni = number(value)?,
                id::INITIAL_MAX_STREAMS_BIDI => {
                    p.initial_max_streams_bidi = number(value)?;
                    if p.initial_max_streams_bidi > MAX_STREAMS_LIMIT {
                        return err("initial_max_streams_bidi above 2^60");
                    }
                }
                id::INITIAL_MAX_STREAMS_UNI => {
                    p.initial_max_streams_uni = number(value)?;
                    if p.initial_max_streams_uni > MAX_STREAMS_LIMIT {
                        return err("initial_max_streams_uni above 2^60");
                    }
                }
                id::ACK_DELAY_EXPONENT => {
                    let v = number(value)?;
                    if v > MAX_ACK_DELAY_EXPONENT {
                        return err("ack_delay_exponent above 20");
                    }
                    p.ack_delay_exponent = v as u8;
                }
                id::MAX_ACK_DELAY => {
                    p.max_ack_delay = number(value)?;
                    if p.max_ack_delay >= MAX_ACK_DELAY_LIMIT {
                        return err("max_ack_delay of 2^14 or more");
                    }
                }
                id::DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return err("disable_active_migration with a value");
                    }
                    p.disable_active_migration = true;
                }
                id::PREFERRED_ADDRESS => {
                    server_only(sender)?;
                    p.preferred_address = Some(preferred_address(value)?);
                }
                id::ACTIVE_CONNECTION_ID_LIMIT => {
                    p.active_connection_id_limit = number(value)?;
                    if p.active_connection_id_limit < 2 {
                        return err("active_connection_id_limit below 2");
                    }
                }
                id::INITIAL_SOURCE_CONNECTION_ID => p.initial_source_connection_id = Some(connection_id(value)?),
                id::RETRY_SOURCE_CONNECTION_ID => {
                    server_only(sender)?;
                    p.retry_source_connection_id = Some(connection_id(value)?);
                }
                id::MAX_DATAGRAM_FRAME_SIZE => p.max_datagram_frame_size = Some(number(value)?),
                _ => p.unknown.push((pid, value.to_vec())),
            }
        }
        if sender == Sender::Server && p.original_destination_connection_id.is_none() {
            return err("no original_destination_connection_id");
        }
        if p.initial_source_connection_id.is_none() {
            return err("no initial_source_connection_id");
        }
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return err("a parameter that is sent twice");
        }
        Ok(p)
    }

    /// The parameters as `sender` writes them: only those that differ from their defaults, in the order of their ids with the
    /// unknown ones last, and none of the server-only ones from a client.
    pub fn encode(&self, sender: Sender) -> Vec<u8> {
        fn number(out: &mut Vec<u8>, id: u64, v: u64) {
            put_varint(out, id);
            put_varint(out, varint_len(v) as u64);
            put_varint(out, v);
        }
        fn bytes(out: &mut Vec<u8>, id: u64, v: &[u8]) {
            put_varint(out, id);
            put_varint(out, v.len() as u64);
            out.extend_from_slice(v);
        }
        let server = sender == Sender::Server;
        let mut out = Vec::with_capacity(128);
        if let (true, Some(cid)) = (server, &self.original_destination_connection_id) {
            bytes(&mut out, id::ORIGINAL_DESTINATION_CONNECTION_ID, cid);
        }
        if self.max_idle_timeout != 0 {
            number(&mut out, id::MAX_IDLE_TIMEOUT, self.max_idle_timeout);
        }
        if let (true, Some(token)) = (server, &self.stateless_reset_token) {
            bytes(&mut out, id::STATELESS_RESET_TOKEN, token);
        }
        if self.max_udp_payload_size != DEFAULT_MAX_UDP_PAYLOAD_SIZE {
            number(&mut out, id::MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size);
        }
        for (pid, v) in [
            (id::INITIAL_MAX_DATA, self.initial_max_data),
            (id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, self.initial_max_stream_data_bidi_local),
            (id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, self.initial_max_stream_data_bidi_remote),
            (id::INITIAL_MAX_STREAM_DATA_UNI, self.initial_max_stream_data_uni),
            (id::INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (id::INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
        ] {
            if v != 0 {
                number(&mut out, pid, v);
            }
        }
        if self.ack_delay_exponent != DEFAULT_ACK_DELAY_EXPONENT {
            number(&mut out, id::ACK_DELAY_EXPONENT, self.ack_delay_exponent as u64);
        }
        if self.max_ack_delay != DEFAULT_MAX_ACK_DELAY {
            number(&mut out, id::MAX_ACK_DELAY, self.max_ack_delay);
        }
        if self.disable_active_migration {
            bytes(&mut out, id::DISABLE_ACTIVE_MIGRATION, &[]);
        }
        if let (true, Some(pa)) = (server, &self.preferred_address) {
            let mut v = Vec::with_capacity(4 + 2 + 16 + 2 + 1 + pa.connection_id.len() + 16);
            v.extend_from_slice(&pa.ipv4.0);
            v.extend_from_slice(&pa.ipv4.1.to_be_bytes());
            v.extend_from_slice(&pa.ipv6.0);
            v.extend_from_slice(&pa.ipv6.1.to_be_bytes());
            v.push(pa.connection_id.len() as u8);
            v.extend_from_slice(&pa.connection_id);
            v.extend_from_slice(&pa.stateless_reset_token);
            bytes(&mut out, id::PREFERRED_ADDRESS, &v);
        }
        if self.active_connection_id_limit != DEFAULT_ACTIVE_CONNECTION_ID_LIMIT {
            number(&mut out, id::ACTIVE_CONNECTION_ID_LIMIT, self.active_connection_id_limit);
        }
        if let Some(cid) = &self.initial_source_connection_id {
            bytes(&mut out, id::INITIAL_SOURCE_CONNECTION_ID, cid);
        }
        if let (true, Some(cid)) = (server, &self.retry_source_connection_id) {
            bytes(&mut out, id::RETRY_SOURCE_CONNECTION_ID, cid);
        }
        if let Some(size) = self.max_datagram_frame_size {
            number(&mut out, id::MAX_DATAGRAM_FRAME_SIZE, size);
        }
        for (pid, v) in &self.unknown {
            bytes(&mut out, *pid, v);
        }
        out
    }
}

/// True for the ids that are reserved for exercising the rule that unknown parameters are ignored (RFC 9000 section 18.1).
pub fn is_grease(id: u64) -> bool {
    id >= 27 && (id - 27) % 31 == 0 && id <= MAX_VARINT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn client_params() -> TransportParameters {
        TransportParameters {
            max_idle_timeout: 30_000,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 18,
            initial_max_stream_data_bidi_remote: 1 << 18,
            initial_max_stream_data_uni: 1 << 18,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            active_connection_id_limit: 4,
            initial_source_connection_id: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ..TransportParameters::default()
        }
    }

    fn server_params() -> TransportParameters {
        TransportParameters {
            original_destination_connection_id: Some(vec![9; 8]),
            stateless_reset_token: Some([0xab; 16]),
            initial_source_connection_id: Some(vec![7; 4]),
            retry_source_connection_id: Some(vec![6; 5]),
            max_udp_payload_size: 1452,
            max_ack_delay: 20,
            ack_delay_exponent: 5,
            disable_active_migration: true,
            max_datagram_frame_size: Some(1200),
            preferred_address: Some(PreferredAddress {
                ipv4: ([192, 0, 2, 1], 4433),
                ipv6: ([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 4434),
                connection_id: vec![5; 6],
                stateless_reset_token: [0xcd; 16],
            }),
            ..client_params()
        }
    }

    #[test]
    fn a_client_is_written_as_the_rfc_has_it() {
        // hand-computed: id, length, value for each parameter that is not a default. 30000 is a 4-byte varint (0x80007530), so
        // are 2^20 (0x80100000) and 2^18 (0x80040000); 100 is two bytes (0x4064).
        let want = [
            hex("01 04 80 00 75 30"),       // max_idle_timeout
            hex("04 04 80 10 00 00"),       // initial_max_data
            hex("05 04 80 04 00 00"),       // initial_max_stream_data_bidi_local
            hex("06 04 80 04 00 00"),       // initial_max_stream_data_bidi_remote
            hex("07 04 80 04 00 00"),       // initial_max_stream_data_uni
            hex("08 02 40 64"),             // initial_max_streams_bidi
            hex("09 02 40 64"),             // initial_max_streams_uni
            hex("0e 01 04"),                // active_connection_id_limit
            hex("0f 08 01 02 03 04 05 06 07 08"), // initial_source_connection_id
        ]
        .concat();
        assert_eq!(client_params().encode(Sender::Client), want);
        assert_eq!(TransportParameters::decode(&want, Sender::Client).unwrap(), client_params());
    }

    #[test]
    fn what_is_written_is_read_back() {
        for (p, sender) in [(client_params(), Sender::Client), (server_params(), Sender::Server)] {
            let bytes = p.encode(sender);
            assert_eq!(TransportParameters::decode(&bytes, sender).unwrap(), p);
            // and the order of the parameters does not matter: write them backwards
            let mut r = Reader::new(&bytes);
            let mut items = Vec::new();
            while !r.is_empty() {
                let start = r.position();
                r.varint().unwrap();
                let len = r.varint().unwrap() as usize;
                r.bytes(len).unwrap();
                items.push(&bytes[start..r.position()]);
            }
            let backwards: Vec<u8> = items.iter().rev().flat_map(|i| i.iter().copied()).collect();
            assert_eq!(TransportParameters::decode(&backwards, sender).unwrap(), p);
        }
    }

    #[test]
    fn a_client_never_writes_what_only_a_server_sends() {
        let sent = server_params().encode(Sender::Client);
        let read = TransportParameters::decode(&sent, Sender::Client).unwrap();
        assert_eq!(read.original_destination_connection_id, None);
        assert_eq!(read.stateless_reset_token, None);
        assert_eq!(read.preferred_address, None);
        assert_eq!(read.retry_source_connection_id, None);
        // but the rest is there
        assert!(read.disable_active_migration);
        assert_eq!(read.max_udp_payload_size, 1452);
        assert_eq!(read.max_datagram_frame_size, Some(1200));
    }

    #[test]
    fn a_client_that_sends_a_server_parameter_is_refused() {
        let base = client_params().encode(Sender::Client);
        let cases: [(&str, Vec<u8>); 4] = [
            ("original_destination_connection_id", hex("00 01 aa")),
            ("stateless_reset_token", [hex("02 10").as_slice(), &[0; 16]].concat()),
            ("retry_source_connection_id", hex("10 00")),
            ("preferred_address", [hex("0d 2d").as_slice(), &[0; 4], &[0, 0], &[0; 16], &[0, 0], &[4], &[1; 4], &[0; 16]].concat()),
        ];
        for (name, extra) in cases {
            let bytes = [base.clone(), extra.clone()].concat();
            assert!(TransportParameters::decode(&bytes, Sender::Client).is_err(), "{name} from a client");
            // a server may send it (the id it needs is added)
            let server = [bytes.clone(), hex("00 01 aa")].concat();
            if name != "original_destination_connection_id" {
                assert!(TransportParameters::decode(&server, Sender::Server).is_ok(), "{name} from a server");
            }
        }
    }

    #[test]
    fn the_ids_that_must_be_there_are_checked_for() {
        let with = |ps: &[&str]| ps.iter().flat_map(|p| hex(p)).collect::<Vec<u8>>();
        // a client needs initial_source_connection_id (RFC 9000 section 7.3); an empty one is a connection id of no bytes
        assert!(TransportParameters::decode(&[], Sender::Client).is_err());
        assert!(TransportParameters::decode(&with(&["0f 00"]), Sender::Client).is_ok());
        // a server needs it and original_destination_connection_id
        assert!(TransportParameters::decode(&with(&["0f 00"]), Sender::Server).is_err());
        assert!(TransportParameters::decode(&with(&["00 00"]), Sender::Server).is_err());
        let p = TransportParameters::decode(&with(&["0f 00", "00 00"]), Sender::Server).unwrap();
        assert_eq!(p.original_destination_connection_id, Some(vec![]));
        assert_eq!(p.initial_source_connection_id, Some(vec![]));
        assert_eq!(p.retry_source_connection_id, None);
        // a retry_source_connection_id of no bytes is not the same as none
        let p = TransportParameters::decode(&with(&["0f 00", "00 00", "10 00"]), Sender::Server).unwrap();
        assert_eq!(p.retry_source_connection_id, Some(vec![]));
    }

    #[test]
    fn what_is_not_sent_has_its_default() {
        let p = TransportParameters::decode(&hex("0f 00"), Sender::Client).unwrap();
        assert_eq!(p.max_idle_timeout, 0);
        assert_eq!(p.max_udp_payload_size, 65527);
        assert_eq!(p.initial_max_data, 0);
        assert_eq!(p.initial_max_streams_bidi, 0);
        assert_eq!(p.ack_delay_exponent, 3);
        assert_eq!(p.max_ack_delay, 25);
        assert!(!p.disable_active_migration);
        assert_eq!(p.active_connection_id_limit, 2);
        assert_eq!(p.max_datagram_frame_size, None);
        assert!(p.unknown.is_empty());
        assert_eq!(p, TransportParameters { initial_source_connection_id: Some(vec![]), ..TransportParameters::default() });
    }

    #[test]
    fn values_that_a_parameter_may_not_have_are_refused() {
        let ok = hex("0f 00");
        let refused: &[(&str, &str)] = &[
            ("max_udp_payload_size 1199", "03 02 44 af"),
            ("ack_delay_exponent 21", "0a 01 15"),
            ("max_ack_delay 2^14", "0b 04 80 00 40 00"),
            ("active_connection_id_limit 1", "0e 01 01"),
            ("active_connection_id_limit 0", "0e 01 00"),
            ("initial_max_streams_bidi 2^60 + 1", "08 08 d0 00 00 00 00 00 00 01"),
            ("initial_max_streams_uni 2^62 - 1", "09 08 ff ff ff ff ff ff ff ff"),
            ("retry_source_connection_id of 21 bytes", "10 15 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14"),
            ("disable_active_migration with a byte", "0c 01 00"),
            ("a number cut short inside its length", "04 01 40"),
            ("a number with a length of two for a one-byte number", "04 02 05 00"),
            ("an empty number", "04 00"),
            ("a length past the end", "04 05 01"),
            ("a cut-off length", "04"),
            ("a cut-off id", "c0"),
        ];
        for (what, bytes) in refused {
            let bytes = [ok.clone(), hex(bytes)].concat();
            assert!(TransportParameters::decode(&bytes, Sender::Server).is_err(), "{what}");
            assert!(TransportParameters::decode(&[bytes, hex("00 00")].concat(), Sender::Server).is_err(), "{what}");
        }
        // the limits themselves are fine
        let accepted: &[(&str, &str)] = &[
            ("max_udp_payload_size 1200", "03 02 44 b0"),
            ("ack_delay_exponent 20", "0a 01 14"),
            ("max_ack_delay 2^14 - 1", "0b 02 7f ff"),
            ("active_connection_id_limit 2", "0e 01 02"),
            ("initial_max_streams_uni 2^60", "09 08 d0 00 00 00 00 00 00 00"),
        ];
        for (what, bytes) in accepted {
            let bytes = [ok.clone(), hex(bytes)].concat();
            assert!(TransportParameters::decode(&bytes, Sender::Client).is_ok(), "{what}");
        }
        // a connection id of 20 bytes is carried, one of 21 is not (in each of the three parameters that carry one)
        let ids = [("initial_source_connection_id", "0f", "00 00"), ("original_destination_connection_id", "00", "0f 00"), ("retry_source_connection_id", "10", "0f 00 00 00")];
        for (name, pid, rest) in ids {
            let with = |n: usize| [hex(rest), hex(pid), vec![n as u8], vec![7; n]].concat();
            assert!(TransportParameters::decode(&with(20), Sender::Server).is_ok(), "{name}: 20 bytes");
            assert!(TransportParameters::decode(&with(21), Sender::Server).is_err(), "{name}: 21 bytes");
        }
    }

    #[test]
    fn numbers_may_be_written_in_more_bytes_than_they_need() {
        // RFC 9000 section 16: only the frame type has to be in the fewest bytes
        let p = TransportParameters::decode(&hex("0f 00 04 04 80 00 00 07 01 02 40 05"), Sender::Client).unwrap();
        assert_eq!(p.initial_max_data, 7);
        assert_eq!(p.max_idle_timeout, 5);
        // and so may the id and the length
        let p = TransportParameters::decode(&hex("0f 00 40 04 40 01 07"), Sender::Client).unwrap();
        assert_eq!(p.initial_max_data, 7);
    }

    #[test]
    fn a_parameter_sent_twice_is_refused_even_if_the_values_agree() {
        for dup in ["0f 00 04 01 07 04 01 07", "0f 00 0c 00 0c 00", "0f 00 0f 00", "0f 00 21 00 21 00", "0f 00 04 01 07 04 01 08"] {
            assert!(TransportParameters::decode(&hex(dup), Sender::Client).is_err(), "{dup}");
        }
        // an id in two spellings is still one id
        assert!(TransportParameters::decode(&hex("0f 00 04 01 07 40 04 01 07"), Sender::Client).is_err());
    }

    #[test]
    fn unknown_parameters_are_ignored_and_kept() {
        let grease = 27 + 31 * 200;
        assert!(is_grease(grease) && is_grease(27) && !is_grease(28) && !is_grease(0));
        let mut p = client_params();
        p.unknown = vec![(grease, vec![1, 2, 3]), (0x4000_0000, vec![]), (0x21, vec![9; 40])];
        let bytes = p.encode(Sender::Client);
        let read = TransportParameters::decode(&bytes, Sender::Client).unwrap();
        assert_eq!(read, p);
        assert_eq!(read.unknown.len(), 3);
        // the ones the draft documents that are not known here are unknown too
        let read = TransportParameters::decode(&[hex("0f 00 c0 00 00 00 ff 04 de 1b 01 05")].concat(), Sender::Client).unwrap();
        assert_eq!(read.unknown, vec![(0xff04de1b, vec![5])]);
    }

    #[test]
    fn the_preferred_address_is_read_field_by_field() {
        let p = TransportParameters::decode(&server_params().encode(Sender::Server), Sender::Server).unwrap();
        let pa = p.preferred_address.unwrap();
        assert_eq!(pa.ipv4_address(), Some(([192, 0, 2, 1], 4433)));
        assert_eq!(pa.ipv6_address().unwrap().1, 4434);
        assert_eq!(pa.connection_id, vec![5; 6]);
        assert_eq!(pa.stateless_reset_token, [0xcd; 16]);
        // a family that is not offered has zeros, and one with a port and no address (or the other way) is not an address
        let none = PreferredAddress { ipv4: ([0; 4], 0), ipv6: ([1; 16], 0), connection_id: vec![1], stateless_reset_token: [0; 16] };
        assert_eq!((none.ipv4_address(), none.ipv6_address()), (None, None));
        let only_port = PreferredAddress { ipv4: ([0; 4], 80), ..none.clone() };
        assert_eq!(only_port.ipv4_address(), None);
        // too short, too long, a connection id of no bytes or of 21
        let pa_value = |len: usize| {
            let mut v = vec![0u8; 4 + 2 + 16 + 2];
            v.push(len as u8);
            v.extend(vec![3u8; len]);
            v.extend([0u8; 16]);
            v
        };
        let with = |value: &[u8]| {
            let mut b = hex("0f 00 00 00");
            b.push(0x0d);
            b.push(value.len() as u8);
            b.extend_from_slice(value);
            b
        };
        assert!(TransportParameters::decode(&with(&pa_value(1)), Sender::Server).is_ok());
        assert!(TransportParameters::decode(&with(&pa_value(20)), Sender::Server).is_ok());
        assert!(TransportParameters::decode(&with(&pa_value(0)), Sender::Server).is_err());
        assert!(TransportParameters::decode(&with(&pa_value(21)), Sender::Server).is_err());
        let v = pa_value(4);
        assert!(TransportParameters::decode(&with(&v[..v.len() - 1]), Sender::Server).is_err());
        assert!(TransportParameters::decode(&with(&[v.clone(), vec![0]].concat()), Sender::Server).is_err());
        assert!(TransportParameters::decode(&with(&v[..10]), Sender::Server).is_err());
        assert!(TransportParameters::decode(&with(&[]), Sender::Server).is_err());
    }

    #[test]
    fn a_stateless_reset_token_is_16_bytes() {
        let with = |n: usize| [hex("0f 00 00 00 02"), vec![n as u8], vec![1; n]].concat();
        assert!(TransportParameters::decode(&with(16), Sender::Server).is_ok());
        for n in [0, 15, 17] {
            assert!(TransportParameters::decode(&with(n), Sender::Server).is_err(), "{n} bytes");
        }
    }

    #[test]
    fn the_largest_values_are_carried() {
        let mut p = client_params();
        p.initial_max_data = MAX_VARINT;
        p.initial_max_stream_data_uni = MAX_VARINT;
        p.max_idle_timeout = MAX_VARINT;
        p.initial_max_streams_bidi = MAX_STREAMS_LIMIT;
        p.max_udp_payload_size = MAX_VARINT;
        let bytes = p.encode(Sender::Client);
        assert_eq!(TransportParameters::decode(&bytes, Sender::Client).unwrap(), p);
    }

    /// The line that quic-go's tests oracle (`tools/quicgo_oracle`) gives for a set of parameters, field by field.
    fn describe(p: &TransportParameters) -> Vec<(&'static str, String)> {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let opt = |b: &Option<Vec<u8>>| b.as_ref().map(|b| hex(b)).unwrap_or_default();
        let pa = match &p.preferred_address {
            None => "none".to_string(),
            Some(pa) => {
                let v4 = pa.ipv4_address().map(|(a, port)| std::net::SocketAddr::from((a, port)).to_string()).unwrap_or("-".into());
                let v6 = pa.ipv6_address().map(|(a, port)| std::net::SocketAddr::from((a, port)).to_string()).unwrap_or("-".into());
                format!("{v4},{v6},{},{}", hex(&pa.connection_id), hex(&pa.stateless_reset_token))
            }
        };
        vec![
            ("odcid", opt(&p.original_destination_connection_id)),
            ("iscid", opt(&p.initial_source_connection_id)),
            ("rscid", p.retry_source_connection_id.as_ref().map(|c| hex(c)).unwrap_or("none".into())),
            ("idle", p.max_idle_timeout.to_string()),
            ("udp", p.max_udp_payload_size.to_string()),
            ("data", p.initial_max_data.to_string()),
            ("bl", p.initial_max_stream_data_bidi_local.to_string()),
            ("br", p.initial_max_stream_data_bidi_remote.to_string()),
            ("u", p.initial_max_stream_data_uni.to_string()),
            ("sb", p.initial_max_streams_bidi.to_string()),
            ("su", p.initial_max_streams_uni.to_string()),
            ("ade", p.ack_delay_exponent.to_string()),
            ("mad", p.max_ack_delay.to_string()),
            ("dam", p.disable_active_migration.to_string()),
            ("pa", pa),
            ("ctl", p.active_connection_id_limit.to_string()),
            ("srt", p.stateless_reset_token.as_ref().map(|t| hex(t)).unwrap_or("none".into())),
            ("dgram", p.max_datagram_frame_size.map(|v| v.to_string()).unwrap_or("none".into())),
        ]
    }

    #[test]
    fn parameters_are_read_as_quic_go_reads_them() {
        // Each line: who sent the parameters (C or S) and whether the list is as quic-go wrote it (V) or changed (M), the list, and
        // what quic-go (v0.59.1, its own parser) makes of it: ERR, or the values. The lists are what quic-go's writer made for
        // random parameters of both sides, and the same changed here and there: a byte, a cut, one more parameter, a value, the
        // order, one parameter left out. Each list is read as sent by a client and as sent by a server. Made by `tools/quicgo_oracle/`.
        // quic-go keeps three things in another form, which are undone here: an idle timeout is at least 5 seconds when it is sent
        // (and 0 when it is not, which is what we have for both), and is kept as a number of nanoseconds that overflows;
        // `max_udp_payload_size` is the largest number when it is not sent (the RFC's default is 65527).
        let mut checked = 0;
        let (mut accepted, mut refused) = (0, 0);
        for line in include_str!("vectors_quicgo_params.txt").lines() {
            let mut parts = line.splitn(3, ' ');
            let head = parts.next().unwrap();
            let bytes = parts.next().unwrap();
            let result = parts.next().unwrap();
            let data: Vec<u8> = (0..bytes.len() / 2).map(|i| u8::from_str_radix(&bytes[2 * i..2 * i + 2], 16).unwrap()).collect();
            let sender = if head.starts_with('C') { Sender::Client } else { Sender::Server };
            let ours = TransportParameters::decode(&data, sender);
            if result == "ERR" {
                assert!(ours.is_err(), "{line}\nquic-go refuses it, we read {ours:?}");
                refused += 1;
                continue;
            }
            let p = ours.unwrap_or_else(|e| panic!("{line}\nquic-go reads it, we refuse it: {e}"));
            let theirs: Vec<(&str, &str)> = result.strip_prefix("OK ").unwrap().split(' ').map(|kv| kv.split_once('=').unwrap()).collect();
            let mine = describe(&p);
            assert_eq!(theirs.len(), mine.len(), "{line}");
            for ((tk, tv), (mk, mv)) in theirs.iter().zip(&mine) {
                assert_eq!(tk, mk, "{line}");
                match *mk {
                    "idle" => {
                        let go_ms: i64 = tv.parse().unwrap();
                        let ns = (p.max_idle_timeout as i64).wrapping_mul(1_000_000).max(5_000_000_000);
                        assert!(go_ms == ns / 1_000_000 || (p.max_idle_timeout == 0 && go_ms == 0), "{line}\nidle: quic-go {go_ms} ms, we read {}", p.max_idle_timeout);
                    }
                    "udp" => assert!(*tv == mv || (*tv == &MAX_VARINT.to_string() && p.max_udp_payload_size == DEFAULT_MAX_UDP_PAYLOAD_SIZE), "{line}\nudp: quic-go {tv}, we read {mv}"),
                    _ => assert_eq!(tv, mv, "{line}\n{mk}"),
                }
            }
            // what we write for it is read again as the same parameters
            let again = TransportParameters::decode(&p.encode(sender), sender).unwrap();
            assert_eq!(again, p, "{line}");
            checked += 1;
            accepted += 1;
        }
        // all of it was used, and a good part of what is read is read by both
        assert_eq!(checked + refused, 2800);
        assert!(accepted > 800 && refused > 1500, "{accepted} accepted, {refused} refused");
    }

    #[test]
    fn every_cut_of_the_parameters_is_read_or_refused_without_a_panic() {
        let bytes = server_params().encode(Sender::Server);
        let whole = TransportParameters::decode(&bytes, Sender::Server).unwrap();
        for n in 0..bytes.len() {
            // a prefix is a list of whole parameters, or it is cut inside one; it never reads as something else
            if let Ok(p) = TransportParameters::decode(&bytes[..n], Sender::Server) {
                assert_ne!(p, whole);
            }
        }
    }
}
