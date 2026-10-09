//! A QUIC client connection (RFC 9000, 9001, 9002): the state machine that the layers below it are for.
//!
//! The connection does no I/O and reads no clock. The owner gives it datagrams that arrived ([`Connection::recv`]) and asks it for
//! datagrams to send ([`Connection::poll_transmit`], until there are none), each with the time it is at; it says when it next needs
//! to be woken ([`Connection::timeout`]) and is woken with [`Connection::on_timeout`]. What happens to the connection that the owner
//! should know of comes out of [`Connection::poll_event`].
//!
//! What is here: the handshake (the TLS client of [`tls`] in CRYPTO frames, the packet protection of every level, Retry
//! and Version Negotiation, the transport parameters and the connection ids that authenticate them), acknowledgments (what to
//! acknowledge and when, and what the peer's acknowledgments say, with [`recovery`](super::recovery)), the probe timeout, the idle
//! timeout, key updates, closing and draining, stateless resets. Streams are in [`streams`](super::streams).
//!
//! A packet that cannot be opened is dropped without a word, since that is what forged and damaged packets look like; one that
//! opens and is wrong closes the connection with the transport error that RFC 9000 names for it.

use super::congestion::NewReno;
use super::frame::{self, Frame};
use super::keys::{self, Keys, OpenError, TAG_LEN};
use super::packet::{self, PacketType, MAX_CID_LEN, VERSION_1};
use super::rangeset::RangeSet;
use super::reassembly::{self, Reassembler};
use super::recovery::{Probe, Recovery, Sent, Space};
use super::sendbuf::SendBuf;
use super::streams::{StreamError, StreamEvent, StreamFrame, Streams, StreamsConfig};
use super::tls::{self, Level, TlsClient};
use super::transport_params::{Sender, TransportParameters, MIN_UDP_PAYLOAD_SIZE};
use super::wire::{decode_packet_number, packet_number_len, varint_len};
use crate::crypto::dit::Dit;
use crate::error::{Error, Result};
use crate::tls::{ClientConfig, Suite};
use crate::zeroize::Zeroizing;
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

/// The transport error codes (RFC 9000 section 20.1).
pub mod code {
    pub const NO_ERROR: u64 = 0x00;
    pub const INTERNAL_ERROR: u64 = 0x01;
    pub const CONNECTION_REFUSED: u64 = 0x02;
    pub const FLOW_CONTROL_ERROR: u64 = 0x03;
    pub const STREAM_LIMIT_ERROR: u64 = 0x04;
    pub const STREAM_STATE_ERROR: u64 = 0x05;
    pub const FINAL_SIZE_ERROR: u64 = 0x06;
    pub const FRAME_ENCODING_ERROR: u64 = 0x07;
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
    pub const CONNECTION_ID_LIMIT_ERROR: u64 = 0x09;
    pub const PROTOCOL_VIOLATION: u64 = 0x0a;
    pub const INVALID_TOKEN: u64 = 0x0b;
    pub const APPLICATION_ERROR: u64 = 0x0c;
    pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0x0d;
    pub const KEY_UPDATE_ERROR: u64 = 0x0e;
    pub const AEAD_LIMIT_REACHED: u64 = 0x0f;
    pub const NO_VIABLE_PATH: u64 = 0x10;
}

/// A reason to close the connection with a transport error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransportError {
    pub code: u64,
    /// The type of the frame that was wrong (0 if none was).
    pub frame_type: u64,
    pub reason: String,
}

impl TransportError {
    pub fn new(code: u64, reason: impl Into<String>) -> TransportError {
        TransportError { code, frame_type: 0, reason: reason.into() }
    }

    pub fn in_frame(mut self, frame_type: u64) -> TransportError {
        self.frame_type = frame_type;
        self
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QUIC transport error {:#x}: {}", self.code, self.reason)
    }
}

impl std::error::Error for TransportError {}

/// How a connection is set up.
#[derive(Clone, Debug)]
pub struct Config {
    /// The idle timeout to offer (0: none). The connection closes when nothing has been heard for the smaller of ours and the
    /// peer's, but no sooner than three probe timeouts.
    pub max_idle_timeout: Duration,
    /// The flow control limit on all streams together that the peer may send, and on those of each kind (RFC 9000 section 18.2).
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    /// How many streams the peer may open.
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    /// The largest UDP payload we take. The datagrams that we send are no larger than 1200 bytes and `max_datagram_size`.
    pub max_udp_payload_size: u64,
    /// How many connection ids of ours the peer may hold at once (at least 2).
    pub active_connection_id_limit: u64,
    /// The size of the datagrams we send, at most (not less than 1200; also limited by the peer's `max_udp_payload_size`).
    pub max_datagram_size: usize,
    /// How long our connection ids are (1 to 20; a server demultiplexes on them, a client on a socket needs little).
    pub cid_len: usize,
    /// The ACK delay exponent we send, and the longest we hold back an acknowledgment, in milliseconds.
    pub ack_delay_exponent: u8,
    pub max_ack_delay: Duration,
    /// How much a stream holds that was written and is not yet acknowledged: a write that would pass it is cut short, and the
    /// application writes the rest when it is told that there is room. At least the bandwidth-delay product of the path, to
    /// keep it full.
    pub stream_send_buffer: usize,
    /// How many packets the 1-RTT keys seal before the connection updates them (RFC 9001 section 6): at most three quarters of
    /// what the AEAD allows (2^23 packets under AES-GCM), whatever this says. A key update needs the handshake confirmed and a
    /// packet of the keys in use acknowledged; a connection that cannot update its keys before they are near their limit
    /// closes with AEAD_LIMIT_REACHED.
    pub key_update_after: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_idle_timeout: Duration::from_secs(30),
            initial_max_data: 16 << 20,
            initial_max_stream_data_bidi_local: 8 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 16,
            max_udp_payload_size: 1472,
            active_connection_id_limit: 4,
            max_datagram_size: 1200,
            cid_len: 8,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            stream_send_buffer: 1 << 20,
            key_update_after: 1 << 22,
        }
    }
}

/// Why a connection is over.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CloseReason {
    /// We found the peer at fault (or the handshake failed) and closed with this transport error.
    Local(TransportError),
    /// The application closed it, with this error code and reason.
    Application { code: u64, reason: Vec<u8> },
    /// The peer closed it with a transport error.
    PeerTransport { code: u64, frame_type: u64, reason: Vec<u8> },
    /// The peer closed it (the application's error code).
    PeerApplication { code: u64, reason: Vec<u8> },
    /// Nothing was heard for the idle timeout.
    IdleTimeout,
    /// The peer sent a stateless reset: it has no state for the connection.
    StatelessReset,
    /// The server does not speak version 1: it listed these versions (RFC 9000 section 6).
    VersionNegotiation(Vec<u32>),
}

/// What the owner of the connection is told.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// The handshake is complete: the server is authenticated, the 1-RTT keys are in, streams can be used.
    Established,
    /// The server has said that the handshake is confirmed (HANDSHAKE_DONE).
    Confirmed,
    /// The connection is over: for the reason; nothing more is sent (but see [`Connection::timeout`]: it ends after a closing or
    /// draining period).
    Closed(CloseReason),
}

/// The state of a connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Before the TLS handshake is complete.
    Handshaking,
    Established,
    /// We sent CONNECTION_CLOSE and wait to see whether the peer needs it again.
    Closing,
    /// The peer closed (or reset): nothing is sent.
    Draining,
    /// Over: nothing is sent or received.
    Closed,
}

/// What a packet that was sent held that has to be dealt with when it is acknowledged or lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentFrame {
    Crypto { offset: u64, len: usize },
    /// An ACK frame, with the largest packet number it acknowledged: once it is acknowledged, those acknowledgments need not be
    /// repeated (RFC 9000 section 13.2.4).
    Ack { largest: u64 },
    Ping,
    RetireConnectionId(u64),
    Stream(StreamFrame),
}

type Payload = Vec<SentFrame>;

/// What is known of the packets received in one space, to say what to acknowledge and when (RFC 9000 section 13.2).
#[derive(Default)]
struct AckState {
    received: RangeSet,
    largest: Option<u64>,
    largest_time: Option<Instant>,
    /// The largest packet number of an ack-eliciting packet received.
    largest_eliciting: Option<u64>,
    /// Ack-eliciting packets received since the last acknowledgment was sent.
    unacked: u32,
    /// An acknowledgment is to go out at the next chance.
    immediate: bool,
    /// When an acknowledgment is due if no other reason makes it sooner.
    deadline: Option<Instant>,
}

/// How many ranges at most an ACK frame has.
const MAX_ACK_RANGES: usize = 32;

impl AckState {
    fn on_received(&mut self, now: Instant, pn: u64, eliciting: bool, delay_allowed: bool, max_ack_delay: Duration) {
        // an ack-eliciting packet that is out of order is acknowledged at once: it is below an earlier one, or it is above the
        // highest with a gap (a packet missing) between (RFC 9000 section 13.2.1)
        let out_of_order = eliciting
            && self.largest_eliciting.is_some_and(|le| pn < le || (pn > le + 1 && !self.received.covers(le + 1..pn)));
        self.received.insert_one(pn);
        if self.largest.is_none_or(|l| pn > l) {
            self.largest = Some(pn);
            self.largest_time = Some(now);
        }
        if !eliciting {
            return;
        }
        if self.largest_eliciting.is_none_or(|l| pn > l) {
            self.largest_eliciting = Some(pn);
        }
        self.unacked += 1;
        if !delay_allowed || out_of_order || self.unacked >= 2 {
            self.immediate = true;
        } else if self.deadline.is_none() {
            self.deadline = Some(now + max_ack_delay);
        }
    }

    /// There is something to acknowledge: it goes in any packet that is sent.
    fn pending(&self) -> bool {
        self.unacked > 0
    }

    /// An acknowledgment is to be sent now, packet or no packet.
    fn due(&self, now: Instant) -> bool {
        self.pending() && (self.immediate || self.deadline.is_some_and(|d| d <= now))
    }

    /// Writes an ACK frame into `out` if there is something to acknowledge and the frame fits in `room`; returns the largest packet
    /// number it acknowledges.
    fn write(&mut self, out: &mut Vec<u8>, now: Instant, exponent: u8, room: usize) -> Option<u64> {
        if !self.pending() {
            return None;
        }
        let mut ranges: Vec<RangeInclusive<u64>> = self.received.iter().rev().take(MAX_ACK_RANGES).map(|r| r.start..=r.end - 1).collect();
        let largest = *ranges.first()?.end();
        let delay = self.largest_time.map_or(0, |t| now.saturating_duration_since(t).as_micros() as u64 >> exponent);
        let mut tmp = Vec::new();
        loop {
            tmp.clear();
            frame::write_ack(&mut tmp, delay, &ranges, None);
            if tmp.len() <= room {
                break;
            }
            if ranges.len() == 1 {
                return None;
            }
            ranges.pop();
        }
        out.extend_from_slice(&tmp);
        self.unacked = 0;
        self.immediate = false;
        self.deadline = None;
        Some(largest)
    }
}

/// The state of one packet number space.
struct PacketSpace {
    /// What our packets are sealed with, and what the peer's are opened with.
    tx: Option<Keys>,
    rx: Option<Keys>,
    next_pn: u64,
    ack: AckState,
    crypto_tx: SendBuf,
    crypto_rx: Reassembler,
    /// How many probe packets to send, whatever the congestion window says.
    probes: u8,
}

impl PacketSpace {
    fn new() -> PacketSpace {
        PacketSpace { tx: None, rx: None, next_pn: 0, ack: AckState::default(), crypto_tx: SendBuf::new(), crypto_rx: Reassembler::new(), probes: 0 }
    }
}

/// The 1-RTT key phases (RFC 9001 section 6).
struct KeyPhases {
    /// The phase bit of the keys we send with, and of the keys we receive with.
    tx_phase: bool,
    rx_phase: bool,
    /// The keys of the phase before, to open packets that were reordered across the update; dropped after a while.
    rx_prev: Option<Keys>,
    rx_prev_until: Option<Instant>,
    /// The lowest packet number received in the phase now (what is lower is of the phase before).
    rx_first_pn: u64,
    /// The first packet number that we sent in the phase now.
    tx_first_pn: u64,
    /// A packet that we sent in the phase now has been acknowledged: the keys may be updated (RFC 9001 section 6.5).
    tx_acked: bool,
}

/// Connection ids that the peer gave us.
struct PeerCid {
    sequence: u64,
    cid: Vec<u8>,
    reset_token: [u8; 16],
}

/// A packet that is built and not yet sealed.
struct Building {
    space: Space,
    buf: Vec<u8>,
    pn: u64,
    pn_len: usize,
    pn_offset: usize,
    long: Option<packet::LongHeader>,
    frames: Payload,
    ack_eliciting: bool,
    in_flight: bool,
    /// Whether the packet may go without a probe's content, etc.: only so far as `build` needed.
    is_initial: bool,
}

/// How a connection that is closing is doing.
struct Closing {
    /// What to tell the peer: the code, the frame type (None: an application's error), the reason.
    code: u64,
    frame_type: Option<u64>,
    reason: Vec<u8>,
    deadline: Instant,
    /// A CONNECTION_CLOSE is to be sent (again).
    pending: bool,
    /// How many datagrams came while closing: one in each power of two is answered.
    received: u64,
}

/// How many packets that cannot be opened yet (keys not in) are kept per level, and how large.
const MAX_BUFFERED: usize = 8;
/// How many bytes of out-of-order handshake data are kept.
const CRYPTO_WINDOW: u64 = 256 * 1024;
/// How many PATH_RESPONSE frames are held.
const MAX_PATH_RESPONSES: usize = 8;

pub struct Connection {
    config: Config,
    state: State,
    scid: Vec<u8>,
    /// The connection id we send to: the one the server chose, after its first packet.
    dcid: Vec<u8>,
    dcid_sequence: u64,
    /// The destination connection id of the first Initial packet, which the server repeats in its transport parameters.
    original_dcid: Vec<u8>,
    /// The id that the Initial keys come from (the original one, or after a Retry the one the Retry gave).
    initial_dcid: Vec<u8>,
    /// The source connection id of the server's first packet.
    server_scid: Option<Vec<u8>>,
    retry_scid: Option<Vec<u8>>,
    token: Vec<u8>,
    first_initial_sent: Option<Instant>,
    spaces: [PacketSpace; 3],
    phases: Option<KeyPhases>,
    tls: TlsClient,
    peer: Option<TransportParameters>,
    peer_ack_delay_exponent: u8,
    recovery: Recovery<Payload>,
    streams: Streams,
    handshake_complete: bool,
    handshake_confirmed: bool,
    /// A packet of the server's has been processed (so Retry and Version Negotiation are no more).
    received_any: bool,
    retire_cids: Vec<u64>,
    peer_cids: Vec<PeerCid>,
    reset_tokens: Vec<[u8; 16]>,
    path_responses: Vec<[u8; 8]>,
    new_tokens: Vec<Vec<u8>>,
    /// When something was last heard (for the idle timeout), and whether an ack-eliciting packet went out since.
    last_activity: Instant,
    eliciting_sent_since_rx: bool,
    ping_pending: bool,
    /// The application waits for the peer (see [`Connection::set_keep_alive`]), and when the last PING to keep it so was asked for.
    keep_alive: bool,
    last_keep_alive: Option<Instant>,
    max_datagram_size: usize,
    closing: Option<Closing>,
    events: VecDeque<Event>,
    undecryptable: [Vec<Vec<u8>>; 3],
    /// A time that the pacer asks to be woken at.
    pacing_wake: Option<Instant>,
    stats: Stats,
}

/// Counts, for tests and for whoever is curious.
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_lost: u64,
    pub probes: u64,
    /// Key updates this end started (not those it followed).
    pub key_updates: u64,
    /// PINGs sent to keep the connection alive (see [`Connection::set_keep_alive`]).
    pub keep_alives: u64,
}

/// What the 1-RTT keys that send need before the next packet (see [`Connection::keys_due`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyAction {
    Keep,
    Updated,
    /// They are near their limit and could not be updated: the connection is to close.
    Close,
}

/// Keys that have sealed `sealed` packets of the `limit` they may are updated past `update_after` (or three quarters of the limit),
/// by `update`, which says whether it could; ones that are within a sixteenth of the limit and could not be are done with.
fn key_action(sealed: u64, update_after: u64, limit: u64, update: impl FnOnce() -> bool) -> KeyAction {
    if sealed < update_after.min(limit / 4 * 3) {
        return KeyAction::Keep;
    }
    if update() {
        return KeyAction::Updated;
    }
    if sealed >= limit - limit / 16 {
        KeyAction::Close
    } else {
        KeyAction::Keep
    }
}

fn level_of(space: Space) -> Level {
    match space {
        Space::Initial => Level::Initial,
        Space::Handshake => Level::Handshake,
        Space::Application => Level::Application,
    }
}

fn io_error(e: std::io::Error) -> Error {
    Error::Io(e)
}

impl Connection {
    /// Starts a connection to `server_name`, which is the name the server's certificate is checked against, with a ClientHello that
    /// offers the ALPN protocols of `tls`. The first datagram is ready to be taken with [`poll_transmit`](Connection::poll_transmit).
    pub fn connect(config: &Config, tls: &ClientConfig, server_name: &str, now: Instant) -> Result<Connection> {
        let dcid_len = 8usize.max(config.cid_len);
        let mut dcid = vec![0u8; dcid_len];
        crate::crypto::rand::fill(&mut dcid).map_err(io_error)?;
        let mut scid = vec![0u8; config.cid_len];
        crate::crypto::rand::fill(&mut scid).map_err(io_error)?;
        Connection::connect_with_ids(config, tls, server_name, now, scid, dcid)
    }

    /// `connect` with the connection ids given (the destination id is at least 8 bytes, RFC 9000 section 7.2).
    pub fn connect_with_ids(config: &Config, tls: &ClientConfig, server_name: &str, now: Instant, scid: Vec<u8>, dcid: Vec<u8>) -> Result<Connection> {
        if scid.len() > MAX_CID_LEN || dcid.len() > MAX_CID_LEN || dcid.len() < 8 || config.max_datagram_size < MIN_UDP_PAYLOAD_SIZE as usize {
            return Err(Error::Tls("QUIC: invalid connection ids or datagram size".into()));
        }
        let params = local_params(config, &scid);
        let (tls, events) = TlsClient::new(server_name, tls, &params.encode(Sender::Client))?;
        let mut c = Connection::new(config, tls, scid, dcid, now);
        c.apply_tls_events(now, events).map_err(|e| Error::Tls(e.reason))?;
        Ok(c)
    }

    fn new(config: &Config, tls: TlsClient, scid: Vec<u8>, dcid: Vec<u8>, now: Instant) -> Connection {
        let mds = config.max_datagram_size;
        let mut c = Connection {
            config: config.clone(),
            state: State::Handshaking,
            scid,
            dcid: dcid.clone(),
            dcid_sequence: 0,
            original_dcid: dcid.clone(),
            initial_dcid: dcid.clone(),
            server_scid: None,
            retry_scid: None,
            token: Vec::new(),
            first_initial_sent: None,
            spaces: [PacketSpace::new(), PacketSpace::new(), PacketSpace::new()],
            phases: None,
            tls,
            peer: None,
            peer_ack_delay_exponent: 3,
            recovery: Recovery::new(mds),
            streams: Streams::new(StreamsConfig {
                client: true,
                max_data: config.initial_max_data,
                bidi_local: config.initial_max_stream_data_bidi_local,
                bidi_remote: config.initial_max_stream_data_bidi_remote,
                uni: config.initial_max_stream_data_uni,
                max_streams_bidi: config.initial_max_streams_bidi,
                max_streams_uni: config.initial_max_streams_uni,
                send_buffer: config.stream_send_buffer,
            }),
            handshake_complete: false,
            handshake_confirmed: false,
            received_any: false,
            retire_cids: Vec::new(),
            peer_cids: Vec::new(),
            reset_tokens: Vec::new(),
            path_responses: Vec::new(),
            new_tokens: Vec::new(),
            last_activity: now,
            eliciting_sent_since_rx: false,
            ping_pending: false,
            keep_alive: false,
            last_keep_alive: None,
            max_datagram_size: mds,
            closing: None,
            events: VecDeque::new(),
            undecryptable: [Vec::new(), Vec::new(), Vec::new()],
            pacing_wake: None,
            stats: Stats::default(),
        };
        c.install_initial_keys(&dcid);
        c
    }

    fn install_initial_keys(&mut self, dcid: &[u8]) {
        let (client, server) = keys::initial_keys(dcid);
        self.spaces[0].tx = Some(client);
        self.spaces[0].rx = Some(server);
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // what the owner asks

    pub fn state(&self) -> State {
        self.state
    }

    pub fn is_established(&self) -> bool {
        self.handshake_complete && matches!(self.state, State::Established)
    }

    pub fn is_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Whether the connection is over as far as the application is concerned (closing, draining or closed).
    pub fn is_closing(&self) -> bool {
        matches!(self.state, State::Closing | State::Draining | State::Closed)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The ALPN protocol the server selected.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }

    /// The server's certificate chain, leaf first.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.tls.peer_certificates()
    }

    /// The server's transport parameters, once they are known.
    pub fn peer_parameters(&self) -> Option<&TransportParameters> {
        self.peer.as_ref()
    }

    pub fn smoothed_rtt(&self) -> Duration {
        self.recovery.smoothed_rtt()
    }

    pub fn congestion(&self) -> &NewReno {
        self.recovery.congestion()
    }

    pub fn bytes_in_flight(&self) -> usize {
        self.recovery.bytes_in_flight()
    }

    /// Tokens that NEW_TOKEN frames brought (for a later connection to the same server).
    pub fn take_new_tokens(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.new_tokens)
    }

    /// Asks for a PING to be sent (to keep the connection from going idle).
    pub fn ping(&mut self) {
        self.ping_pending = true;
    }

    /// Whether the application is waiting for the peer (a request in flight): while it is, the connection sends a PING when it
    /// has heard nothing for a third of the idle timeout, so that a server that takes long to answer (longer than the idle
    /// timeout) does not see the connection go idle, and nor does this end. Off, a connection with nothing to do is let go idle,
    /// as RFC 9000 section 10.1 has it.
    pub fn set_keep_alive(&mut self, on: bool) {
        if on && !self.keep_alive {
            self.last_keep_alive = None;
        }
        self.keep_alive = on;
    }

    /// When the next PING to keep the connection alive is due, if one is.
    fn keep_alive_at(&self) -> Option<Instant> {
        if !self.keep_alive || !self.handshake_complete || self.state != State::Established {
            return None;
        }
        let every = self.idle_timeout()? / 3;
        let since = self.last_keep_alive.map_or(self.last_activity, |t| t.max(self.last_activity));
        Some(since + every)
    }

    /// Updates the 1-RTT keys that this end sends with (RFC 9001 section 6), if it may: the handshake is confirmed, and a packet
    /// sent with the keys in use has been acknowledged (which also means that the peer followed the last update). Whether it
    /// did. The connection does this by itself before the keys reach their limit (see [`Config::key_update_after`]).
    pub fn update_keys(&mut self) -> bool {
        if !self.handshake_confirmed || self.is_closing() || self.is_closed() {
            return false;
        }
        let si = Space::Application.index();
        let (Some(p), Some(tx)) = (self.phases.as_mut(), self.spaces[si].tx.as_mut()) else { return false };
        if !p.tx_acked || p.rx_phase != p.tx_phase {
            return false;
        }
        *tx = tx.next();
        p.tx_phase = !p.tx_phase;
        p.tx_first_pn = self.spaces[si].next_pn;
        p.tx_acked = false;
        self.stats.key_updates += 1;
        true
    }

    /// Before a packet is sealed: the keys are updated once they have sealed `key_update_after` packets (or three quarters of their
    /// limit), and a connection whose keys are near their limit and cannot be updated is closed while it can still say so.
    fn keys_due(&mut self, now: Instant) {
        let si = Space::Application.index();
        let Some(tx) = self.spaces[si].tx.as_ref() else { return };
        if self.phases.is_none() {
            return;
        }
        let (sealed, limit) = (tx.packet.sealed(), tx.packet.confidentiality_limit());
        match key_action(sealed, self.config.key_update_after, limit, || self.update_keys()) {
            KeyAction::Keep | KeyAction::Updated => {}
            KeyAction::Close => {
                self.close_with_error(now, TransportError::new(code::AEAD_LIMIT_REACHED, "the packet keys are near their limit and could not be updated"));
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // streams (see the module [`streams`](super::streams) for what they do and for the events)

    /// Whether [`open_stream`](Connection::open_stream) would give a stream now.
    pub fn can_open_stream(&self, bidirectional: bool) -> bool {
        !self.is_closing() && !self.is_closed() && self.streams.can_open(bidirectional)
    }

    /// Opens a stream and gives its id. [`StreamError::Blocked`] until the handshake has given the peer's limits, and when the
    /// peer's limit on the streams we open is reached ([`StreamEvent::Available`] says when it is raised).
    pub fn open_stream(&mut self, bidirectional: bool) -> std::result::Result<u64, StreamError> {
        self.check_streams_usable()?;
        self.streams.open(bidirectional)
    }

    /// Writes data on a stream, and ends it after the data if `fin`. Returns how many bytes were taken (see
    /// [`Streams::write`](super::streams::Streams::write)).
    pub fn stream_write(&mut self, id: u64, data: &[u8], fin: bool) -> std::result::Result<usize, StreamError> {
        self.check_streams_usable()?;
        self.streams.write(id, data, fin)
    }

    /// Reads from a stream: how many bytes, and whether the stream ends with them.
    pub fn stream_read(&mut self, id: u64, buf: &mut [u8]) -> std::result::Result<(usize, bool), StreamError> {
        if self.is_closing() || self.is_closed() {
            return Err(StreamError::Closed);
        }
        self.streams.read(id, buf)
    }

    /// Gives up sending on a stream: RESET_STREAM goes out with this application error code.
    pub fn stream_reset(&mut self, id: u64, error: u64) -> std::result::Result<(), StreamError> {
        self.check_streams_usable()?;
        self.streams.reset(id, error)
    }

    /// Asks the peer to stop sending on a stream (STOP_SENDING with this application error code).
    pub fn stream_stop_sending(&mut self, id: u64, error: u64) -> std::result::Result<(), StreamError> {
        self.check_streams_usable()?;
        self.streams.stop_sending(id, error)
    }

    /// What the receiving side of a stream holds, in words: for the tests and the fuzzer when something is wrong.
    pub fn describe_stream(&self, id: u64) -> String {
        self.streams.describe_recv(id)
    }

    /// Whether the streams have anything to send (for the tests and the fuzzer).
    pub fn streams_have_pending(&self) -> bool {
        self.streams.has_pending()
    }

    /// The ids of the streams that are still kept: a stream is forgotten once both its directions are finished, acknowledged and
    /// read (for the tests and the fuzzer).
    pub fn stream_ids(&self) -> Vec<u64> {
        self.streams.stream_ids()
    }

    /// What has happened to the streams that the application should look at: the next event, if there is one.
    pub fn poll_stream_event(&mut self) -> Option<StreamEvent> {
        self.streams.poll_event()
    }

    /// How many more bytes a write on the stream takes now, or `None` if it cannot be written to.
    pub fn stream_send_room(&self, id: u64) -> Option<usize> {
        self.streams.send_room(id)
    }

    fn check_streams_usable(&self) -> std::result::Result<(), StreamError> {
        if self.is_closing() || self.is_closed() {
            Err(StreamError::Closed)
        } else {
            Ok(())
        }
    }

    /// Closes the connection with an application's error code (RFC 9000 section 10.2): the CONNECTION_CLOSE frame goes out at the
    /// next [`poll_transmit`](Connection::poll_transmit) and the connection ends after the closing period.
    pub fn close(&mut self, now: Instant, code: u64, reason: &[u8]) {
        if self.is_closing() {
            return;
        }
        let r = CloseReason::Application { code, reason: reason.to_vec() };
        self.start_closing(now, code, None, reason.to_vec(), r);
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // closing

    fn closing_period(&self) -> Duration {
        3 * self.recovery.pto_period(Space::Application)
    }

    /// Closes because the peer did something that a transport error is for.
    fn close_with_error(&mut self, now: Instant, e: TransportError) {
        if self.is_closing() {
            return;
        }
        let reason = e.reason.clone().into_bytes();
        let ft = Some(e.frame_type);
        self.start_closing(now, e.code, ft, reason, CloseReason::Local(e));
    }

    fn start_closing(&mut self, now: Instant, code: u64, frame_type: Option<u64>, reason: Vec<u8>, why: CloseReason) {
        self.state = State::Closing;
        self.closing = Some(Closing { code, frame_type, reason, deadline: now + self.closing_period(), pending: true, received: 0 });
        self.events.push_back(Event::Closed(why));
    }

    /// The peer closed the connection (or it reset it).
    fn start_draining(&mut self, now: Instant, why: CloseReason) {
        if matches!(self.state, State::Draining | State::Closed) {
            return;
        }
        let was_closing = self.state == State::Closing;
        self.state = State::Draining;
        let deadline = now + self.closing_period();
        self.closing = Some(Closing { code: 0, frame_type: None, reason: Vec::new(), deadline, pending: false, received: 0 });
        if !was_closing {
            self.events.push_back(Event::Closed(why));
        }
    }

    fn abandon(&mut self, why: CloseReason) {
        self.state = State::Closed;
        self.closing = None;
        self.events.push_back(Event::Closed(why));
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // timers

    fn idle_timeout(&self) -> Option<Duration> {
        let local = self.config.max_idle_timeout;
        let peer = self.peer.as_ref().map_or(0, |p| p.max_idle_timeout);
        let peer = Duration::from_millis(peer);
        let t = match (local.is_zero(), peer.is_zero()) {
            (true, true) => return None,
            (true, false) => peer,
            (false, true) => local,
            (false, false) => local.min(peer),
        };
        // never less than three probe timeouts (RFC 9000 section 10.1)
        Some(t.max(3 * self.recovery.pto_period(Space::Application)))
    }

    /// When the connection next needs the owner to call [`on_timeout`](Connection::on_timeout) (or poll_transmit): `None` if never.
    pub fn timeout(&self) -> Option<Instant> {
        let mut t: Option<Instant> = None;
        let mut add = |x: Option<Instant>| {
            if let Some(x) = x {
                t = Some(t.map_or(x, |c| c.min(x)));
            }
        };
        match self.state {
            State::Closed => return None,
            State::Closing | State::Draining => {
                return self.closing.as_ref().map(|c| c.deadline);
            }
            _ => {}
        }
        add(self.recovery.timer());
        for s in &self.spaces {
            add(s.ack.deadline.filter(|_| s.ack.pending()));
        }
        add(self.idle_timeout().map(|d| self.last_activity + d));
        add(self.keep_alive_at());
        add(self.pacing_wake);
        if let Some(p) = &self.phases {
            add(p.rx_prev_until);
        }
        t
    }

    /// The time `timeout` gave has come.
    pub fn on_timeout(&mut self, now: Instant) {
        match self.state {
            State::Closed => return,
            State::Closing | State::Draining => {
                if self.closing.as_ref().is_some_and(|c| now >= c.deadline) {
                    self.state = State::Closed;
                    self.closing = None;
                }
                return;
            }
            _ => {}
        }
        if let Some(d) = self.idle_timeout() {
            if now >= self.last_activity + d {
                self.abandon(CloseReason::IdleTimeout);
                return;
            }
        }
        if let Some(p) = &mut self.phases {
            if p.rx_prev_until.is_some_and(|t| now >= t) {
                p.rx_prev = None;
                p.rx_prev_until = None;
            }
        }
        if self.pacing_wake.is_some_and(|t| now >= t) {
            self.pacing_wake = None;
        }
        if self.keep_alive_at().is_some_and(|t| now >= t) {
            self.ping_pending = true;
            self.last_keep_alive = Some(now);
            self.stats.keep_alives += 1;
        }
        if self.recovery.timer().is_some_and(|t| now >= t) {
            let out = self.recovery.on_timeout(now);
            self.stats.packets_lost += out.lost.len() as u64;
            for p in out.lost {
                self.requeue(out.lost_space, &p.payload);
            }
            if let Some(Probe { space, anti_deadlock }) = out.probe {
                self.stats.probes += 1;
                self.queue_probe(space, anti_deadlock);
            }
        }
    }

    /// What a probe timeout puts in the packets it sends: the data of the oldest packet that is still out (it is not declared lost, it
    /// is sent again to find out), or a PING if there is nothing.
    fn queue_probe(&mut self, space: Space, anti_deadlock: bool) {
        let si = space.index();
        if self.spaces[si].tx.is_none() {
            return;
        }
        let oldest = self.recovery.outstanding(space).find(|p| p.ack_eliciting).map(|p| p.payload.clone());
        if let Some(frames) = oldest {
            self.requeue(space, &frames);
        }
        self.spaces[si].probes = if anti_deadlock { 1 } else { 2 };
    }

    /// Puts what the frames carried back to be sent: they were lost, or a probe wants them out again.
    fn requeue(&mut self, space: Space, frames: &[SentFrame]) {
        let si = space.index();
        for f in frames {
            match f {
                SentFrame::Crypto { offset, len } => self.spaces[si].crypto_tx.on_lost(*offset, *len, false),
                SentFrame::Stream(sf) => self.streams.on_lost(sf),
                SentFrame::RetireConnectionId(seq) => {
                    if !self.retire_cids.contains(seq) {
                        self.retire_cids.push(*seq);
                    }
                }
                SentFrame::Ack { .. } | SentFrame::Ping => {}
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // receiving

    /// A datagram arrived. It may hold several packets (RFC 9000 section 12.2). It is changed: packets are opened in place.
    pub fn recv(&mut self, now: Instant, datagram: &mut [u8]) {
        // one switch to data-independent timing for the packets of the datagram and the TLS work on them (B-104)
        let _dit = Dit::on();
        match self.state {
            State::Closed | State::Draining => return,
            State::Closing => {
                if let Some(c) = &mut self.closing {
                    c.received += 1;
                    if c.received.is_power_of_two() {
                        c.pending = true;
                    }
                }
                return;
            }
            _ => {}
        }
        self.stats.datagrams_received += 1;
        let mut off = 0;
        while off < datagram.len() && !self.is_closing() {
            let consumed = self.recv_packet(now, &mut datagram[off..]);
            match consumed {
                Some(n) if n > 0 => off += n,
                _ => break,
            }
        }
        self.replay_buffered(now);
    }

    /// Handles the packet that begins `data`; how many bytes it took (None: the rest of the datagram is not to be read).
    fn recv_packet(&mut self, now: Instant, data: &mut [u8]) -> Option<usize> {
        let (ty, pn_offset, len, scid, token_empty) = {
            let pkt = match packet::parse(data, self.scid.len()) {
                Ok(p) => p,
                Err(_) => {
                    self.stats.packets_dropped += 1;
                    return None;
                }
            };
            // everything that the server sends us is to the connection id we gave it (we gave it one)
            if pkt.dcid != &self.scid[..] {
                self.stats.packets_dropped += 1;
                return Some(pkt.len);
            }
            match pkt.ty {
                PacketType::VersionNegotiation => {
                    let versions: Vec<u32> = packet::versions(pkt.versions).collect();
                    let scid = pkt.scid.to_vec();
                    self.on_version_negotiation(now, &scid, versions);
                    return None;
                }
                PacketType::Retry => {
                    let (scid, token) = (pkt.scid.to_vec(), pkt.token.to_vec());
                    let genuine = keys::retry_is_genuine(&self.original_dcid, data);
                    self.on_retry(now, genuine, scid, token);
                    return None;
                }
                PacketType::ZeroRtt => return Some(pkt.len),
                ty => (ty, pkt.pn_offset, pkt.len, pkt.scid.to_vec(), pkt.token.is_empty()),
            }
        };
        if ty == PacketType::Initial && !token_empty {
            // RFC 9000 section 17.2.2: discard the packet or close the connection. The token is read from a header that has not
            // been authenticated yet, and a packet damaged on the way (a bit of its token length) must not end a connection
            // that did nothing wrong (found by the fuzz target `quic_connection`, whose network flips bits); so the connection is
            // closed for a packet that is genuine (its header is authenticated with its payload), and one that is not is dropped.
            if self.initial_is_genuine(&data[..len], pn_offset) {
                self.close_with_error(now, TransportError::new(code::PROTOCOL_VIOLATION, "a server's Initial packet has a token"));
            } else {
                self.stats.packets_dropped += 1;
            }
            return None;
        }
        self.process_packet(now, &mut data[..len], ty, pn_offset, &scid);
        Some(len)
    }

    /// Whether an Initial packet opens with the Initial keys (on a copy: nothing in it is acted on).
    fn initial_is_genuine(&mut self, packet: &[u8], pn_offset: usize) -> bool {
        let largest = self.spaces[0].ack.largest;
        let Some(rx) = self.spaces[0].rx.as_mut() else { return false };
        let mut copy = packet.to_vec();
        matches!(rx.open(&mut copy, pn_offset, largest), Ok(_) | Err(OpenError::ReservedBits))
    }

    fn on_version_negotiation(&mut self, now: Instant, scid: &[u8], versions: Vec<u32>) {
        // only before anything else has come, from our destination id, and not one that lists the version we speak
        if self.received_any || scid != &self.original_dcid[..] || versions.contains(&VERSION_1) {
            self.stats.packets_dropped += 1;
            return;
        }
        let _ = now;
        self.abandon(CloseReason::VersionNegotiation(versions));
    }

    fn on_retry(&mut self, now: Instant, genuine: bool, scid: Vec<u8>, token: Vec<u8>) {
        // at most one, before anything else from the server, with a token and an integrity tag that checks
        if self.received_any || self.retry_scid.is_some() || token.is_empty() || !genuine || scid.len() > MAX_CID_LEN {
            self.stats.packets_dropped += 1;
            return;
        }
        let rtt = self.first_initial_sent.map(|t| now.saturating_duration_since(t));
        self.retry_scid = Some(scid.clone());
        self.dcid = scid.clone();
        self.initial_dcid = scid.clone();
        self.token = token;
        self.install_initial_keys(&scid);
        // what was sent is not acknowledged and is sent again (the same handshake message, with new packet numbers, which continue)
        self.recovery.reset(rtt);
        self.spaces[0].crypto_tx.mark_all_lost();
        self.spaces[0].probes = 0;
    }

    /// A packet of a level whose keys we do not have yet is kept for when we do.
    fn buffer_packet(&mut self, space: Space, packet: &[u8]) {
        let q = &mut self.undecryptable[space.index()];
        if q.len() < MAX_BUFFERED {
            q.push(packet.to_vec());
        } else {
            self.stats.packets_dropped += 1;
        }
    }

    /// Tries again the packets that were kept, at the levels that have keys now.
    fn replay_buffered(&mut self, now: Instant) {
        for space in Space::ALL {
            let si = space.index();
            while self.spaces[si].rx.is_some() && !self.undecryptable[si].is_empty() && !self.is_closing() {
                let mut packets = std::mem::take(&mut self.undecryptable[si]);
                for p in packets.iter_mut() {
                    if self.is_closing() {
                        break;
                    }
                    let parsed = packet::parse(p, self.scid.len()).ok().map(|k| (k.ty, k.pn_offset, k.len, k.scid.to_vec()));
                    if let Some((ty, pn_offset, len, scid)) = parsed {
                        if len <= p.len() {
                            self.process_packet(now, &mut p[..len], ty, pn_offset, &scid);
                        }
                    }
                }
            }
        }
    }

    fn process_packet(&mut self, now: Instant, buf: &mut [u8], ty: PacketType, pn_offset: usize, scid: &[u8]) {
        let space = match ty {
            PacketType::Initial => Space::Initial,
            PacketType::Handshake => Space::Handshake,
            PacketType::OneRtt => Space::Application,
            _ => return,
        };
        let si = space.index();
        if ty != PacketType::OneRtt {
            // once a packet has come from the server, its source connection id is the one it uses (RFC 9000 section 7.2)
            if self.server_scid.as_deref().is_some_and(|s| s != scid) {
                self.stats.packets_dropped += 1;
                return;
            }
        }
        if self.spaces[si].rx.is_none() {
            // keys of this level are not in yet, or are gone
            if self.spaces[si].tx.is_some() || space != Space::Initial {
                self.buffer_packet(space, buf);
            } else {
                self.stats.packets_dropped += 1;
            }
            return;
        }
        let largest = self.spaces[si].ack.largest;
        let opened = if ty == PacketType::OneRtt {
            self.open_one_rtt(now, buf, pn_offset, largest)
        } else {
            let rx = self.spaces[si].rx.as_mut().expect("checked");
            rx.open(buf, pn_offset, largest).map(|o| (o.pn, o.payload))
        };
        let (pn, payload) = match opened {
            Ok(x) => x,
            Err(OpenError::ReservedBits) => {
                self.close_with_error(now, TransportError::new(code::PROTOCOL_VIOLATION, "reserved bits are not zero"));
                return;
            }
            Err(e) => {
                self.stats.packets_dropped += 1;
                if ty == PacketType::OneRtt {
                    self.after_failed_one_rtt(now, buf, e);
                }
                return;
            }
        };
        if self.spaces[si].ack.received.contains(pn) {
            self.stats.packets_dropped += 1;
            return;
        }
        // the first packet of the server: its source connection id is the one to send to from now on
        if ty != PacketType::OneRtt && self.server_scid.is_none() {
            self.server_scid = Some(scid.to_vec());
            self.dcid = scid.to_vec();
            self.dcid_sequence = 0;
        }
        self.received_any = true;
        self.stats.packets_received += 1;
        let eliciting = match self.process_frames(now, space, ty, &buf[payload]) {
            Ok(e) => e,
            Err(e) => {
                self.close_with_error(now, e);
                return;
            }
        };
        if self.is_closing() {
            return;
        }
        self.last_activity = now;
        self.eliciting_sent_since_rx = false;
        let delay_allowed = space == Space::Application && self.handshake_complete;
        let max_ack_delay = self.config.max_ack_delay;
        self.spaces[si].ack.on_received(now, pn, eliciting, delay_allowed, max_ack_delay);
    }

    /// Opens a 1-RTT packet: which keys it takes depends on the key phase bit it has (RFC 9001 section 6.3). Returns the packet number
    /// and where the frames are.
    fn open_one_rtt(&mut self, now: Instant, buf: &mut [u8], pn_offset: usize, largest: Option<u64>) -> std::result::Result<(u64, std::ops::Range<usize>), OpenError> {
        let si = Space::Application.index();
        let Some(phases) = &mut self.phases else { return Err(OpenError::TooShort) };
        let rx = self.spaces[si].rx.as_mut().expect("1-RTT keys");
        let hdr = rx.header.unprotect(buf, pn_offset).ok_or(OpenError::TooShort)?;
        let pn = decode_packet_number(largest, hdr.truncated_pn, hdr.pn_len);
        let phase = hdr.first & 0x04 != 0;
        if phase == phases.rx_phase {
            let range = keys::open_payload(&mut rx.packet, buf, pn_offset, &hdr, pn)?;
            phases.rx_first_pn = phases.rx_first_pn.min(pn);
            return Ok((pn, range));
        }
        // the other phase: an old packet (below the first of this phase) or a key update
        if pn < phases.rx_first_pn {
            let prev = phases.rx_prev.as_mut().ok_or(OpenError::Authentication)?;
            let range = keys::open_payload(&mut prev.packet, buf, pn_offset, &hdr, pn)?;
            return Ok((pn, range));
        }
        let mut next = rx.next();
        let range = keys::open_payload(&mut next.packet, buf, pn_offset, &hdr, pn)?;
        // it opened: the peer has updated its keys (or answers ours). Ours follow if they have not yet.
        let old = std::mem::replace(rx, next);
        phases.rx_prev = Some(old);
        phases.rx_phase = phase;
        phases.rx_first_pn = pn;
        let pto = 3 * self.recovery.pto_period(Space::Application);
        phases.rx_prev_until = Some(now + pto);
        if phases.tx_phase != phase {
            let tx = self.spaces[si].tx.as_mut().expect("1-RTT keys");
            let next_tx = tx.next();
            *tx = next_tx;
            phases.tx_phase = phase;
            phases.tx_first_pn = self.spaces[si].next_pn;
            phases.tx_acked = false;
        }
        Ok((pn, range))
    }

    /// A 1-RTT packet that did not open might be a stateless reset (RFC 9000 section 10.3), or one too many that did not.
    fn after_failed_one_rtt(&mut self, now: Instant, buf: &[u8], e: OpenError) {
        if e == OpenError::Authentication {
            let si = Space::Application.index();
            if self.spaces[si].rx.as_ref().is_some_and(|k| k.packet.integrity_limit_reached()) {
                self.close_with_error(now, TransportError::new(code::AEAD_LIMIT_REACHED, "too many packets failed to open"));
                return;
            }
        }
        // a stateless reset is at least 21 bytes and ends in a token that the server gave us
        if buf.len() >= 21 {
            let tail = &buf[buf.len() - 16..];
            if self.reset_tokens.iter().any(|t| crate::util::ct_eq(t, tail)) {
                self.start_draining(now, CloseReason::StatelessReset);
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // frames

    /// Reads the frames of a packet and acts on each. Returns whether the packet has an ack-eliciting frame.
    fn process_frames(&mut self, now: Instant, space: Space, ty: PacketType, payload: &[u8]) -> std::result::Result<bool, TransportError> {
        let mut eliciting = false;
        for f in frame::frames(payload, ty) {
            let f = f.map_err(|e| TransportError::new(e.transport_error(), e.to_string()).in_frame(e.frame_type))?;
            eliciting |= f.ack_eliciting();
            let ft = f.frame_type();
            self.process_frame(now, space, f).map_err(|e| if e.frame_type == 0 { e.in_frame(ft) } else { e })?;
            if self.is_closing() {
                break;
            }
        }
        Ok(eliciting)
    }

    fn process_frame(&mut self, now: Instant, space: Space, f: Frame<'_>) -> std::result::Result<(), TransportError> {
        match f {
            Frame::Padding(_) | Frame::Ping => Ok(()),
            Frame::Ack(a) => self.on_ack_frame(now, space, &a),
            Frame::Crypto { offset, data } => self.on_crypto(now, space, offset, data),
            Frame::NewToken { token } => {
                if token.is_empty() {
                    return Err(TransportError::new(code::PROTOCOL_VIOLATION, "an empty NEW_TOKEN"));
                }
                self.new_tokens.push(token.to_vec());
                Ok(())
            }
            Frame::ResetStream { .. }
            | Frame::StopSending { .. }
            | Frame::Stream { .. }
            | Frame::MaxData(_)
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreams { .. }
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => self.streams.on_frame(&f),
            Frame::NewConnectionId { sequence, retire_prior_to, cid, reset_token } => self.on_new_connection_id(sequence, retire_prior_to, cid, *reset_token),
            Frame::RetireConnectionId(sequence) => {
                // we gave out one connection id, with sequence number 0
                if sequence >= 1 {
                    return Err(TransportError::new(code::PROTOCOL_VIOLATION, "RETIRE_CONNECTION_ID for a connection id that was not issued"));
                }
                Ok(())
            }
            Frame::PathChallenge(data) => {
                if self.path_responses.len() < MAX_PATH_RESPONSES {
                    self.path_responses.push(data);
                }
                Ok(())
            }
            Frame::PathResponse(_) => Ok(()), // (we send no challenge)
            Frame::ConnectionClose { code, frame_type, reason } => {
                let why = match frame_type {
                    Some(ft) => CloseReason::PeerTransport { code, frame_type: ft, reason: reason.to_vec() },
                    None => CloseReason::PeerApplication { code, reason: reason.to_vec() },
                };
                self.start_draining(now, why);
                Ok(())
            }
            Frame::HandshakeDone => {
                if !self.handshake_confirmed {
                    self.handshake_confirmed = true;
                    self.discard_space(now, Space::Handshake);
                    self.recovery.on_handshake_confirmed(now);
                    self.events.push_back(Event::Confirmed);
                }
                Ok(())
            }
        }
    }

    fn on_ack_frame(&mut self, now: Instant, space: Space, a: &frame::Ack<'_>) -> std::result::Result<(), TransportError> {
        let si = space.index();
        if a.largest >= self.spaces[si].next_pn {
            return Err(TransportError::new(code::PROTOCOL_VIOLATION, "an acknowledgment of a packet that was not sent"));
        }
        let exponent = if space == Space::Application || self.handshake_complete { self.peer_ack_delay_exponent } else { 3 };
        let delay = Duration::from_micros(a.delay_micros(exponent as u32));
        let out = self.recovery.on_ack_received(now, space, a.largest, delay, a.ranges());
        if space == Space::Application {
            if let Some(p) = self.phases.as_mut().filter(|p| a.largest >= p.tx_first_pn) {
                p.tx_acked = true;
            }
        }
        for p in &out.acked {
            for f in &p.payload {
                match f {
                    SentFrame::Crypto { offset, len } => self.spaces[si].crypto_tx.on_acked(*offset, *len, false),
                    SentFrame::Stream(sf) => self.streams.on_acked(sf),
                    // the peer has our acknowledgment of these: they need not be acknowledged again
                    SentFrame::Ack { largest } => self.spaces[si].ack.received.remove_below(largest + 1),
                    SentFrame::Ping | SentFrame::RetireConnectionId(_) => {}
                }
            }
        }
        self.stats.packets_lost += out.lost.len() as u64;
        for p in &out.lost {
            self.requeue(space, &p.payload);
        }
        Ok(())
    }

    fn on_crypto(&mut self, now: Instant, space: Space, offset: u64, data: &[u8]) -> std::result::Result<(), TransportError> {
        let si = space.index();
        match self.spaces[si].crypto_rx.insert(offset, data, CRYPTO_WINDOW) {
            Ok(()) => {}
            Err(reassembly::Error::Exceeded) => return Err(TransportError::new(code::CRYPTO_BUFFER_EXCEEDED, "too much handshake data out of order")),
            Err(reassembly::Error::Inconsistent) => return Err(TransportError::new(code::PROTOCOL_VIOLATION, "handshake data that differs from what was sent before")),
        }
        let bytes = self.spaces[si].crypto_rx.take();
        if bytes.is_empty() {
            return Ok(());
        }
        let events = self.tls.read_crypto(level_of(space), &bytes).map_err(|e| TransportError::new(tls::close_code(&e), e.to_string()))?;
        self.apply_tls_events(now, events)
    }

    fn apply_tls_events(&mut self, now: Instant, events: Vec<tls::Event>) -> std::result::Result<(), TransportError> {
        for event in events {
            match event {
                tls::Event::Crypto(level, data) => self.spaces[level.index()].crypto_tx.write(&data),
                tls::Event::Keys { level, suite, write, read } => self.install_keys(level, suite, &write, &read),
                tls::Event::PeerTransportParameters(bytes) => self.on_peer_parameters(&bytes)?,
                tls::Event::ServerAuthenticated => {}
                tls::Event::Complete => {
                    self.handshake_complete = true;
                    if self.state == State::Handshaking {
                        self.state = State::Established;
                    }
                    self.events.push_back(Event::Established);
                }
            }
        }
        let _ = now;
        Ok(())
    }

    fn install_keys(&mut self, level: Level, suite: Suite, write: &Zeroizing<Vec<u8>>, read: &Zeroizing<Vec<u8>>) {
        let si = level.index();
        self.spaces[si].tx = Some(Keys::new(suite, write));
        self.spaces[si].rx = Some(Keys::new(suite, read));
        match level {
            Level::Handshake => self.recovery.set_handshake_keys(true),
            Level::Application => {
                self.phases = Some(KeyPhases { tx_phase: false, rx_phase: false, rx_prev: None, rx_prev_until: None, rx_first_pn: 0, tx_first_pn: 0, tx_acked: false });
            }
            Level::Initial => {}
        }
    }

    /// The server's transport parameters: what they say of connection ids is checked against what we know (RFC 9000 section 7.3).
    fn on_peer_parameters(&mut self, bytes: &[u8]) -> std::result::Result<(), TransportError> {
        let err = |m: &str| TransportError::new(code::TRANSPORT_PARAMETER_ERROR, m);
        let p = TransportParameters::decode(bytes, Sender::Server).map_err(|e| err(&e.to_string()))?;
        if p.original_destination_connection_id.as_deref() != Some(&self.original_dcid[..]) {
            return Err(err("original_destination_connection_id is not the one we first sent to"));
        }
        if p.initial_source_connection_id.is_none() || p.initial_source_connection_id != self.server_scid {
            return Err(err("initial_source_connection_id is not the source connection id of the server's first packet"));
        }
        if p.retry_source_connection_id != self.retry_scid {
            return Err(err("retry_source_connection_id does not match the Retry (or lack of one)"));
        }
        self.max_datagram_size = self.config.max_datagram_size.min(p.max_udp_payload_size as usize).max(MIN_UDP_PAYLOAD_SIZE as usize);
        self.recovery.set_max_datagram_size(self.max_datagram_size);
        self.recovery.set_max_ack_delay(Duration::from_millis(p.max_ack_delay));
        self.peer_ack_delay_exponent = p.ack_delay_exponent;
        if let Some(t) = p.stateless_reset_token {
            self.reset_tokens.push(t);
        }
        self.streams.set_peer_params(&p);
        self.peer = Some(p);
        Ok(())
    }

    fn on_new_connection_id(&mut self, sequence: u64, retire_prior_to: u64, cid: &[u8], reset_token: [u8; 16]) -> std::result::Result<(), TransportError> {
        if let Some(known) = self.peer_cids.iter().find(|c| c.sequence == sequence) {
            if known.cid != cid || known.reset_token != reset_token {
                return Err(TransportError::new(code::PROTOCOL_VIOLATION, "a connection id with a sequence number that was used before, and is not the same"));
            }
        } else if sequence >= retire_prior_to {
            self.peer_cids.push(PeerCid { sequence, cid: cid.to_vec(), reset_token });
            self.reset_tokens.push(reset_token);
        } else {
            // it is retired at once: the peer told us so with the same frame
            self.retire_cids.push(sequence);
        }
        // the ones below `retire_prior_to` are to be retired
        let (retired, kept): (Vec<PeerCid>, Vec<PeerCid>) = std::mem::take(&mut self.peer_cids).into_iter().partition(|c| c.sequence < retire_prior_to);
        self.peer_cids = kept;
        for c in retired {
            if !self.retire_cids.contains(&c.sequence) {
                self.retire_cids.push(c.sequence);
            }
        }
        if self.dcid_sequence < retire_prior_to {
            // the one in use is retired: use the lowest that is left
            if let Some(next) = self.peer_cids.iter().min_by_key(|c| c.sequence) {
                self.dcid = next.cid.clone();
                self.dcid_sequence = next.sequence;
            }
            if !self.retire_cids.contains(&self.dcid_sequence) && self.dcid_sequence < retire_prior_to {
                self.retire_cids.push(self.dcid_sequence);
            }
        }
        // we are to hold no more than the limit we gave (the one in use is not counted among those that were kept)
        if self.peer_cids.len() as u64 + 1 > self.config.active_connection_id_limit {
            return Err(TransportError::new(code::CONNECTION_ID_LIMIT_ERROR, "more connection ids than the limit"));
        }
        Ok(())
    }

    /// Drops the keys of `space` and what goes with them. The client does this with the Initial keys when it first sends a Handshake
    /// packet (RFC 9001 section 4.9.1), and with the Handshake keys when the handshake is confirmed.
    fn discard_space(&mut self, now: Instant, space: Space) {
        let si = space.index();
        if self.spaces[si].tx.is_none() && self.spaces[si].rx.is_none() {
            return;
        }
        self.spaces[si].tx = None;
        self.spaces[si].rx = None;
        self.spaces[si].crypto_tx = SendBuf::new();
        self.spaces[si].probes = 0;
        self.spaces[si].ack = AckState::default();
        self.undecryptable[si].clear();
        let _ = self.recovery.discard_space(now, space);
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // sending

    fn header_len(&self, space: Space, pn_len: usize) -> usize {
        match space {
            Space::Application => 1 + self.dcid.len() + pn_len,
            Space::Initial => 1 + 4 + 1 + self.dcid.len() + 1 + self.scid.len() + varint_len(self.token.len() as u64) + self.token.len() + 2 + pn_len,
            Space::Handshake => 1 + 4 + 1 + self.dcid.len() + 1 + self.scid.len() + 2 + pn_len,
        }
    }

    /// Whether `space` has a reason to send an ack-eliciting packet that is not in the way of the congestion window: it is something
    /// that is to be sent, not a reason that is sent on its own.
    fn has_data(&self, space: Space) -> bool {
        let s = &self.spaces[space.index()];
        if s.crypto_tx.has_pending() {
            return true;
        }
        space == Space::Application
            && (self.ping_pending || !self.path_responses.is_empty() || !self.retire_cids.is_empty() || self.streams.has_pending())
    }

    /// Makes the next datagram to send, if there is one: `out` is cleared and holds it. A datagram holds one packet or several, of
    /// different levels, one after the other.
    pub fn poll_transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> bool {
        let _dit = Dit::on(); // one switch for the packets of the datagram (B-104)
        out.clear();
        match self.state {
            State::Closed | State::Draining => return false,
            State::Closing => return self.transmit_close(now, out),
            _ => {}
        }
        self.keys_due(now);
        if self.state == State::Closing {
            return self.transmit_close(now, out);
        }
        self.pacing_wake = None;
        let max = self.max_datagram_size;
        let blocked = self.recovery.congestion().blocked();
        let paced = if blocked { None } else { self.recovery.next_send_time(now) };
        let allow_eliciting = !blocked && paced.is_none();
        let mut packets: Vec<Building> = Vec::new();
        let mut total = 0;
        let mut padded_to = 0;
        for space in Space::ALL {
            let si = space.index();
            if self.spaces[si].tx.is_none() {
                continue;
            }
            let room = max - total;
            if room < 64 {
                break;
            }
            let probe = self.spaces[si].probes > 0;
            // an acknowledgment that is due is a reason to send, one that is not due goes along if a packet is sent anyway
            let ack_due = self.spaces[si].ack.due(now);
            if !(ack_due || probe || (allow_eliciting && self.has_data(space))) {
                continue;
            }
            if let Some(b) = self.build_packet(now, space, room, allow_eliciting) {
                total += b.buf.len() + TAG_LEN;
                packets.push(b);
            }
        }
        if packets.is_empty() {
            if !blocked && paced.is_some() && (0..3).any(|i| self.spaces[i].tx.is_some() && self.has_data(Space::ALL[i])) {
                self.pacing_wake = paced;
            }
            return false;
        }
        // every datagram a client sends with an Initial packet in it is at least 1200 bytes (RFC 9000 section 14.1)
        if packets.iter().any(|p| p.is_initial) {
            padded_to = 1200;
        }
        self.finish_datagram(now, packets, padded_to, out);
        if !allow_eliciting {
            // (an acknowledgment went out and nothing else could)
        }
        self.stats.datagrams_sent += 1;
        true
    }

    /// Builds the packet of `space` for the datagram, with at most `room` bytes: an acknowledgment if there is one to send, what is
    /// due, and a probe's content if one is asked for.
    fn build_packet(&mut self, now: Instant, space: Space, room: usize, allow_eliciting: bool) -> Option<Building> {
        let si = space.index();
        let pn = self.spaces[si].next_pn;
        let pn_len = packet_number_len(pn, self.recovery.largest_acked(space)).unwrap_or(4);
        let overhead = self.header_len(space, pn_len) + TAG_LEN;
        if room < overhead + 4 {
            return None;
        }
        let budget = room - overhead;
        let mut payload: Vec<u8> = Vec::with_capacity(budget);
        let mut frames: Payload = Vec::new();
        let mut eliciting = false;
        let probe = self.spaces[si].probes > 0;

        let exponent = self.config.ack_delay_exponent;
        if let Some(largest) = self.spaces[si].ack.write(&mut payload, now, exponent, budget) {
            frames.push(SentFrame::Ack { largest });
        }
        if allow_eliciting || probe {
            // handshake data
            loop {
                let used = payload.len();
                let Some(offset) = self.spaces[si].crypto_tx.next_offset() else { break };
                let header = 1 + varint_len(offset) + 2;
                if budget < used + header + 1 {
                    break;
                }
                let Some(chunk) = self.spaces[si].crypto_tx.next_chunk(budget - used - header, u64::MAX) else { break };
                let mut data = Vec::with_capacity(chunk.len);
                self.spaces[si].crypto_tx.copy(chunk.offset, chunk.len, &mut data);
                Frame::Crypto { offset: chunk.offset, data: &data }.write(&mut payload);
                frames.push(SentFrame::Crypto { offset: chunk.offset, len: chunk.len });
                eliciting = true;
            }
            if space == Space::Application {
                // answers to path challenges
                while let Some(d) = self.path_responses.last().copied() {
                    if payload.len() + 9 > budget {
                        break;
                    }
                    self.path_responses.pop();
                    Frame::PathResponse(d).write(&mut payload);
                    eliciting = true;
                }
                while let Some(&seq) = self.retire_cids.last() {
                    if payload.len() + 1 + varint_len(seq) > budget {
                        break;
                    }
                    self.retire_cids.pop();
                    Frame::RetireConnectionId(seq).write(&mut payload);
                    frames.push(SentFrame::RetireConnectionId(seq));
                    eliciting = true;
                }
                let before = payload.len();
                let mut sent = Vec::new();
                self.streams.write_frames(&mut payload, budget.saturating_sub(before), &mut sent);
                if !sent.is_empty() {
                    eliciting = true;
                    frames.extend(sent);
                }
                if self.ping_pending && payload.len() < budget {
                    Frame::Ping.write(&mut payload);
                    frames.push(SentFrame::Ping);
                    self.ping_pending = false;
                    eliciting = true;
                }
            }
            if probe {
                if !eliciting && payload.len() < budget {
                    Frame::Ping.write(&mut payload);
                    frames.push(SentFrame::Ping);
                    eliciting = true;
                }
                if eliciting {
                    self.spaces[si].probes -= 1;
                }
            }
        }
        if payload.is_empty() {
            return None;
        }
        // (header protection needs a sample: a payload of at least four bytes does for every length of packet number)
        if payload.len() < 4 {
            payload.resize(4, 0);
        }
        let mut buf = Vec::with_capacity(overhead + payload.len());
        let (long, pn_offset) = match space {
            Space::Application => {
                let key_phase = self.phases.as_ref().is_some_and(|p| p.tx_phase);
                let o = packet::write_short_header(&mut buf, &self.dcid, false, key_phase, pn, pn_len);
                (None, o)
            }
            _ => {
                let ty = if space == Space::Initial { PacketType::Initial } else { PacketType::Handshake };
                let token: &[u8] = if space == Space::Initial { &self.token } else { &[] };
                let h = packet::write_long_header(&mut buf, ty, &self.dcid, &self.scid, token, pn, pn_len);
                (Some(h), h.pn_offset)
            }
        };
        buf.extend_from_slice(&payload);
        self.spaces[si].next_pn += 1;
        Some(Building { space, buf, pn, pn_len, pn_offset, long, frames, ack_eliciting: eliciting, in_flight: eliciting, is_initial: space == Space::Initial })
    }

    /// Seals the packets and puts them in `out`, after padding the last to make the datagram `pad_to` bytes if it is shorter.
    fn finish_datagram(&mut self, now: Instant, mut packets: Vec<Building>, pad_to: usize, out: &mut Vec<u8>) {
        let total: usize = packets.iter().map(|b| b.buf.len() + TAG_LEN).sum();
        if total < pad_to {
            let last = packets.last_mut().expect("a packet");
            last.buf.resize(last.buf.len() + (pad_to - total), 0);
            last.in_flight = true;
        }
        let mut sent_handshake = false;
        for mut b in packets {
            let si = b.space.index();
            if let Some(h) = b.long {
                packet::finish_long(&mut b.buf, h, TAG_LEN);
            }
            let keys = self.spaces[si].tx.as_mut().expect("keys of a space that a packet was built for");
            keys.seal(&mut b.buf, b.pn_offset, b.pn_len, b.pn).expect("the payload is long enough for a sample");
            out.extend_from_slice(&b.buf);
            self.stats.packets_sent += 1;
            if b.space == Space::Handshake {
                sent_handshake = true;
            }
            if b.space == Space::Initial && self.first_initial_sent.is_none() {
                self.first_initial_sent = Some(now);
            }
            if b.ack_eliciting && !self.eliciting_sent_since_rx {
                // the first ack-eliciting packet after one was received restarts the idle timer (RFC 9000 section 10.1)
                self.eliciting_sent_since_rx = true;
                self.last_activity = now;
            }
            let sent = Sent { pn: b.pn, time: now, size: b.buf.len(), ack_eliciting: b.ack_eliciting, in_flight: b.in_flight, payload: b.frames };
            self.recovery.on_packet_sent(now, b.space, sent);
        }
        if sent_handshake {
            // the client's first Handshake packet is the end of the Initial space (RFC 9001 section 4.9.1)
            self.discard_space(now, Space::Initial);
        }
    }

    /// The datagram for a connection that is closing: a CONNECTION_CLOSE at the highest level that has keys (or, before the handshake
    /// is done, at both of the handshake's levels, where the frame has to be a transport error).
    fn transmit_close(&mut self, now: Instant, out: &mut Vec<u8>) -> bool {
        let Some(c) = &mut self.closing else { return false };
        if !c.pending {
            return false;
        }
        c.pending = false;
        let (code, frame_type, reason) = (c.code, c.frame_type, c.reason.clone());
        let mut packets = Vec::new();
        let have_app = self.spaces[2].tx.is_some();
        let spaces: &[Space] = if have_app { &[Space::Application] } else { &[Space::Initial, Space::Handshake] };
        for &space in spaces {
            let si = space.index();
            if self.spaces[si].tx.is_none() {
                continue;
            }
            // (an application's error cannot be said in the packets of the handshake: it becomes APPLICATION_ERROR with no reason)
            let (code, frame_type, reason) = match (space, frame_type) {
                (Space::Application, ft) => (code, ft, reason.clone()),
                (_, Some(ft)) => (code, Some(ft), reason.clone()),
                (_, None) => (self::code::APPLICATION_ERROR, Some(0), Vec::new()),
            };
            let pn = self.spaces[si].next_pn;
            let pn_len = packet_number_len(pn, self.recovery.largest_acked(space)).unwrap_or(4);
            let overhead = self.header_len(space, pn_len) + TAG_LEN;
            let room = self.max_datagram_size - overhead - packets.iter().map(|b: &Building| b.buf.len() + TAG_LEN).sum::<usize>();
            let mut payload = Vec::new();
            let mut r = reason.as_slice();
            // the reason is cut to what fits
            let fixed = 1 + varint_len(code) + frame_type.map_or(0, varint_len) + 2;
            if r.len() + fixed > room {
                r = &r[..room.saturating_sub(fixed)];
            }
            Frame::ConnectionClose { code, frame_type, reason: r }.write(&mut payload);
            if payload.len() < 4 {
                payload.resize(4, 0);
            }
            let mut buf = Vec::new();
            let (long, pn_offset) = if space == Space::Application {
                let key_phase = self.phases.as_ref().is_some_and(|p| p.tx_phase);
                (None, packet::write_short_header(&mut buf, &self.dcid, false, key_phase, pn, pn_len))
            } else {
                let ty = if space == Space::Initial { PacketType::Initial } else { PacketType::Handshake };
                let token: &[u8] = if space == Space::Initial { &self.token } else { &[] };
                let h = packet::write_long_header(&mut buf, ty, &self.dcid, &self.scid, token, pn, pn_len);
                (Some(h), h.pn_offset)
            };
            buf.extend_from_slice(&payload);
            self.spaces[si].next_pn += 1;
            packets.push(Building { space, buf, pn, pn_len, pn_offset, long, frames: Vec::new(), ack_eliciting: false, in_flight: false, is_initial: space == Space::Initial });
        }
        if packets.is_empty() {
            return false;
        }
        let pad = if packets.iter().any(|p| p.is_initial) { 1200 } else { 0 };
        self.finish_datagram(now, packets, pad, out);
        self.stats.datagrams_sent += 1;
        true
    }
}

fn local_params(config: &Config, scid: &[u8]) -> TransportParameters {
    TransportParameters {
        max_idle_timeout: config.max_idle_timeout.as_millis() as u64,
        max_udp_payload_size: config.max_udp_payload_size,
        initial_max_data: config.initial_max_data,
        initial_max_stream_data_bidi_local: config.initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote: config.initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni: config.initial_max_stream_data_uni,
        initial_max_streams_bidi: config.initial_max_streams_bidi,
        initial_max_streams_uni: config.initial_max_streams_uni,
        ack_delay_exponent: config.ack_delay_exponent,
        max_ack_delay: config.max_ack_delay.as_millis() as u64,
        disable_active_migration: true,
        active_connection_id_limit: config.active_connection_id_limit,
        initial_source_connection_id: Some(scid.to_vec()),
        ..TransportParameters::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_server::{Link, ServerOptions, TestQuicServer};
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn link(opts: ServerOptions) -> Link {
        Link::new(TestQuicServer::new("example.test", opts), &Config::default())
    }

    fn established(l: &mut Link) {
        assert!(l.run_until(Duration::from_secs(20), |l| l.client.is_established()), "the handshake did not complete: {:?}", l.client_events);
    }

    fn confirmed(l: &mut Link) {
        assert!(l.run_until(Duration::from_secs(20), |l| l.client.is_confirmed()), "the handshake was not confirmed: {:?}", l.client_events);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // the handshake

    #[test]
    fn a_handshake_completes_and_is_confirmed() {
        let mut l = link(ServerOptions::default());
        established(&mut l);
        confirmed(&mut l);
        assert_eq!(l.client_events, vec![Event::Established, Event::Confirmed]);
        assert_eq!(l.client.alpn(), Some(&b"h3"[..]));
        assert!(l.server.handshake_done, "the server got the client's Finished");
        assert_eq!(l.client.peer_certificates().len(), l.server.tls.pki.chain.len());
        // the client's first datagram is 1200 bytes (RFC 9000 section 14.1)
        assert!(l.client_datagram_sizes[0] >= 1200, "{:?}", l.client_datagram_sizes);
        // the Initial keys are gone, and the Handshake keys too, once the handshake is confirmed
        assert!(l.client.spaces[0].tx.is_none() && l.client.spaces[0].rx.is_none());
        assert!(l.client.spaces[1].tx.is_none() && l.client.spaces[1].rx.is_none());
        assert!(l.client.spaces[2].tx.is_some());
        let p = l.client.peer_parameters().expect("peer parameters");
        assert_eq!(p.initial_max_streams_bidi, 100);
        // an RTT sample was taken: 40 ms (20 each way) of virtual time
        assert!(l.client.smoothed_rtt() >= ms(35) && l.client.smoothed_rtt() <= ms(60), "{:?}", l.client.smoothed_rtt());
    }

    #[test]
    fn a_handshake_after_a_retry() {
        let mut l = link(ServerOptions { retry: true, ..ServerOptions::default() });
        established(&mut l);
        confirmed(&mut l);
        // the Initial packet that carries the token: more than one datagram of Initial packets was sent
        assert!(l.client_datagram_sizes.len() >= 2 && l.client_datagram_sizes[1] >= 1200);
        assert_eq!(l.client.retry_scid.as_deref(), Some(&[0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7][..]));
        // a Retry is not an acknowledgment, and the packet numbers go on (RFC 9000 section 17.2.5.3)
        assert!(l.server.log.iter().any(|s| s.contains("Initial pn=1 ")), "{:?}", l.server.log);
    }

    #[test]
    fn a_lost_first_flight_is_sent_again_after_the_probe_timeout() {
        let mut l = link(ServerOptions::default());
        l.drop_rule = Box::new(|from_client, n, _| from_client && n == 0);
        established(&mut l);
        // the probe timeout from the initial round trip estimate: 333 + 4 * 166.5 = 999 ms
        assert!(l.elapsed() >= ms(999) && l.elapsed() < ms(1400), "{:?}", l.elapsed());
        assert!(l.client.stats().probes >= 1);
        // the Initial that was sent again is 1200 bytes too
        assert!(l.client_datagram_sizes[1] >= 1200);
    }

    #[test]
    fn a_lost_server_flight_is_sent_again() {
        for lost in [vec![0u64], vec![1], vec![0, 1], vec![1, 2], vec![0, 1, 2]] {
            let mut l = link(ServerOptions { crypto_chunk: 400, ..ServerOptions::default() });
            let lost2 = lost.clone();
            l.drop_rule = Box::new(move |from_client, n, _| !from_client && lost2.contains(&n));
            assert!(l.run_until(Duration::from_secs(30), |l| l.client.is_confirmed()), "lost {lost:?}: {:?}", l.client_events);
        }
    }

    #[test]
    fn handshake_data_in_small_frames_and_many_packets() {
        let mut l = link(ServerOptions { crypto_chunk: 50, ..ServerOptions::default() });
        established(&mut l);
        confirmed(&mut l);
    }

    #[test]
    fn lossy_handshakes_in_both_directions_complete() {
        // every third datagram is lost, in a rotation that differs from run to run
        for offset in 0..3u64 {
            let mut l = link(ServerOptions { crypto_chunk: 600, ..ServerOptions::default() });
            l.drop_rule = Box::new(move |_, n, _| (n + offset) % 3 == 0 && n < 12);
            assert!(l.run_until(Duration::from_secs(60), |l| l.client.is_confirmed()), "offset {offset}: {:?}", l.client_events);
        }
    }

    #[test]
    fn the_server_is_checked_for_the_connection_ids_in_its_parameters() {
        type Mutate = Box<dyn Fn(&mut TransportParameters)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("no original_destination_connection_id", Box::new(|p| p.original_destination_connection_id = None)),
            ("a wrong original_destination_connection_id", Box::new(|p| p.original_destination_connection_id = Some(vec![1; 8]))),
            ("no initial_source_connection_id", Box::new(|p| p.initial_source_connection_id = None)),
            ("a wrong initial_source_connection_id", Box::new(|p| p.initial_source_connection_id = Some(vec![2; 8]))),
            ("a retry_source_connection_id without a Retry", Box::new(|p| p.retry_source_connection_id = Some(vec![0xb0; 8]))),
        ];
        for (what, mutate) in cases {
            let mut l = link(ServerOptions { params: mutate, ..ServerOptions::default() });
            l.run_until(Duration::from_secs(5), |l| l.client.is_closing());
            let reason = l.client_events.iter().find_map(|e| if let Event::Closed(r) = e { Some(r.clone()) } else { None });
            let Some(CloseReason::Local(e)) = reason else { panic!("{what}: {:?}", l.client_events) };
            assert_eq!(e.code, code::TRANSPORT_PARAMETER_ERROR, "{what}");
            // the server is told, in the Initial or the Handshake packet
            l.run_until(Duration::from_secs(1), |l| l.server.close_received.is_some());
            assert_eq!(l.server.close_received.as_ref().map(|c| c.0), Some(code::TRANSPORT_PARAMETER_ERROR), "{what}: {:?}", l.server.log);
        }
    }

    #[test]
    fn a_server_initial_with_a_token_closes_the_connection_only_if_it_is_genuine() {
        let ids = ([0xa0u8; 8], [0xd0u8; 8], [0xe0u8; 8]);
        let start = |now| {
            let server = TestQuicServer::new("example.test", ServerOptions::default());
            Connection::connect_with_ids(&Config::default(), &server.client_config(), "example.test", now, ids.0.to_vec(), ids.1.to_vec()).unwrap()
        };
        // a server's Initial: a PING and some padding, sealed with the server's Initial keys
        let initial = |token: &[u8]| {
            let (_, mut server_keys) = keys::initial_keys(&ids.1);
            let mut p = Vec::new();
            let h = packet::write_long_header(&mut p, PacketType::Initial, &ids.0, &ids.2, token, 0, 2);
            p.push(0x01);
            p.extend([0u8; 30]);
            packet::finish_long(&mut p, h, TAG_LEN);
            server_keys.seal(&mut p, h.pn_offset, 2, 0).unwrap();
            p
        };
        let now = Instant::now();
        let mut c = start(now);
        c.recv(now, &mut initial(b"t"));
        assert!(c.is_closing(), "a genuine Initial with a token");
        assert!(matches!(c.poll_event(), Some(Event::Closed(CloseReason::Local(e))) if e.code == code::PROTOCOL_VIOLATION));
        // one without, whose token length was damaged on the way (1 + 4 + 1 + 8 + 1 + 8 bytes in): dropped
        for bit in 0..8 {
            let mut c = start(now);
            let mut damaged = initial(b"");
            damaged[23] ^= 1 << bit;
            let dropped = c.stats().packets_dropped;
            c.recv(now, &mut damaged);
            assert!(!c.is_closing(), "bit {bit}: a damaged Initial closed the connection");
            assert!(c.stats().packets_dropped > dropped, "bit {bit}");
        }
    }

    #[test]
    fn a_retry_that_the_server_does_not_repeat_in_its_parameters_fails() {
        let mut l = link(ServerOptions { retry: true, params: Box::new(|p| p.retry_source_connection_id = None), ..ServerOptions::default() });
        l.run_until(Duration::from_secs(5), |l| l.client.is_closing());
        assert!(matches!(l.client_events.last(), Some(Event::Closed(CloseReason::Local(e))) if e.code == code::TRANSPORT_PARAMETER_ERROR), "{:?}", l.client_events);
    }

    #[test]
    fn a_server_without_transport_parameters_is_refused_by_tls() {
        let mut l = link(ServerOptions { raw_params: Some(None), ..ServerOptions::default() });
        l.run_until(Duration::from_secs(5), |l| l.client.is_closing());
        // missing_extension (109): CRYPTO_ERROR 0x100 + 109
        assert!(matches!(l.client_events.last(), Some(Event::Closed(CloseReason::Local(e))) if e.code == 0x100 + 109), "{:?}", l.client_events);
    }

    #[test]
    fn transport_parameters_that_are_malformed_close_the_connection() {
        let mut l = link(ServerOptions { raw_params: Some(Some(vec![0x03, 0x01, 0x20])), ..ServerOptions::default() }); // max_udp_payload_size 32
        l.run_until(Duration::from_secs(5), |l| l.client.is_closing());
        assert!(matches!(l.client_events.last(), Some(Event::Closed(CloseReason::Local(e))) if e.code == code::TRANSPORT_PARAMETER_ERROR), "{:?}", l.client_events);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // version negotiation

    #[test]
    fn version_negotiation_that_lists_no_version_we_speak_ends_the_connection() {
        let mut l = link(ServerOptions::default());
        l.flush();
        // (the client's first datagram is in flight; the server answers it with a Version Negotiation packet instead)
        let mut vn = vec![0x80u8, 0, 0, 0, 0];
        vn.push(8);
        vn.extend_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]); // the client's connection id
        vn.push(8);
        vn.extend_from_slice(&[0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]); // the one it sent to
        vn.extend_from_slice(&0x6b3343cfu32.to_be_bytes());
        vn.extend_from_slice(&0xff00001du32.to_be_bytes());
        l.client.recv(l.now, &mut vn);
        assert!(l.client.is_closed());
        assert_eq!(l.client.poll_event(), Some(Event::Closed(CloseReason::VersionNegotiation(vec![0x6b3343cf, 0xff00001d]))));
        let mut out = Vec::new();
        assert!(!l.client.poll_transmit(l.now, &mut out), "nothing is sent for it");
    }

    #[test]
    fn version_negotiation_that_lists_version_1_or_has_other_ids_is_ignored() {
        let mut l = link(ServerOptions::default());
        l.flush();
        let make = |dcid: [u8; 8], scid: [u8; 8], versions: &[u32]| {
            let mut vn = vec![0x80u8, 0, 0, 0, 0, 8];
            vn.extend_from_slice(&dcid);
            vn.push(8);
            vn.extend_from_slice(&scid);
            for v in versions {
                vn.extend_from_slice(&v.to_be_bytes());
            }
            vn
        };
        let mine = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
        let sent_to = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7];
        for mut vn in [make(mine, sent_to, &[1, 2]), make([9; 8], sent_to, &[2]), make(mine, [9; 8], &[2])] {
            l.client.recv(l.now, &mut vn);
            assert!(!l.client.is_closing());
        }
        established(&mut l);
    }

    #[test]
    fn a_version_negotiation_packet_after_the_server_has_answered_is_ignored() {
        let mut l = link(ServerOptions::default());
        established(&mut l);
        let mut vn = vec![0x80u8, 0, 0, 0, 0, 8, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 8, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0, 0, 0, 2];
        l.client.recv(l.now, &mut vn);
        assert!(!l.client.is_closing());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // closing

    #[test]
    fn the_application_closes_the_connection() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        l.client.close(l.now, 0x101, b"going away");
        assert_eq!(l.client.state(), State::Closing);
        l.flush();
        assert!(l.run_until(Duration::from_secs(1), |l| l.server.close_received.is_some()));
        assert_eq!(l.server.close_received, Some((0x101, b"going away".to_vec())));
        assert_eq!(l.client_events.last(), Some(&Event::Closed(CloseReason::Application { code: 0x101, reason: b"going away".to_vec() })));
        // after the closing period it is closed (three probe timeouts)
        let t = l.client.timeout().expect("the end of the closing period");
        assert!(t > l.now);
        l.client.on_timeout(t);
        assert!(l.client.is_closed());
        assert_eq!(l.client.timeout(), None);
    }

    #[test]
    fn an_application_close_before_the_handshake_is_a_transport_error_in_the_handshake_packets() {
        let mut l = link(ServerOptions::default());
        l.flush();
        l.client.close(l.now, 0x101, b"nope");
        l.flush();
        l.run_until(Duration::from_secs(1), |l| l.server.close_received.is_some());
        assert_eq!(l.server.close_received, Some((code::APPLICATION_ERROR, Vec::new())), "{:?}", l.server.log);
    }

    #[test]
    fn a_closing_connection_answers_what_it_receives_now_and_then() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        l.client.close(l.now, 0, b"");
        let mut out = Vec::new();
        assert!(l.client.poll_transmit(l.now, &mut out), "the first CONNECTION_CLOSE");
        assert!(!l.client.poll_transmit(l.now, &mut out));
        let mut sent = 0;
        for _ in 0..16 {
            let mut junk = vec![0x40u8; 40];
            junk[1..9].copy_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
            l.client.recv(l.now, &mut junk);
            if l.client.poll_transmit(l.now, &mut out) {
                sent += 1;
            }
        }
        // one answer in each power of two of datagrams received: 1, 2, 4, 8, 16
        assert_eq!(sent, 5);
    }

    #[test]
    fn the_peer_closes_the_connection() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        l.server.close_with = Some((0x33, b"bye".to_vec()));
        assert!(l.run_until(Duration::from_secs(1), |l| l.client.is_closing()));
        assert_eq!(l.client.state(), State::Draining);
        assert_eq!(l.client_events.last(), Some(&Event::Closed(CloseReason::PeerApplication { code: 0x33, reason: b"bye".to_vec() })));
        let mut out = Vec::new();
        l.flush();
        assert!(!l.client.poll_transmit(l.now, &mut out), "a draining connection sends nothing");
        let t = l.client.timeout().unwrap();
        l.client.on_timeout(t);
        assert!(l.client.is_closed());
    }

    #[test]
    fn an_idle_connection_closes_at_the_smaller_idle_timeout() {
        let mut l = link(ServerOptions { params: Box::new(|p| p.max_idle_timeout = 5_000), ..ServerOptions::default() });
        confirmed(&mut l);
        let idle_from = l.client.last_activity;
        assert_eq!(l.client.idle_timeout(), Some(ms(5000)));
        // nothing happens (no one sends): the next time the client needs is the idle timeout
        let mut ended = false;
        for _ in 0..50 {
            if !l.step() {
                break;
            }
            if l.client.is_closed() {
                ended = true;
                break;
            }
        }
        assert!(ended, "{:?}", l.client_events);
        assert_eq!(l.client_events.last(), Some(&Event::Closed(CloseReason::IdleTimeout)));
        assert!(l.now >= idle_from + ms(5000));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // acknowledgments

    #[test]
    fn the_client_acknowledges_one_ping_after_the_delay_and_two_at_once() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        l.advance(ms(500)); // let everything settle
        let before = l.client.stats().packets_sent;
        let mut ping = Vec::new();
        Frame::Ping.write(&mut ping);
        l.server.queued = ping.clone();
        l.flush();
        // delivered 20 ms later: the client holds the acknowledgment, 25 ms at most
        l.step();
        let mut out = Vec::new();
        assert!(!l.client.poll_transmit(l.now, &mut out), "an acknowledgment of one ping is held back");
        let due = l.client.timeout().expect("the acknowledgment's time");
        assert_eq!(due, l.now + ms(25));
        l.now = due;
        l.client.on_timeout(l.now);
        assert!(l.client.poll_transmit(l.now, &mut out));
        assert!(l.client.stats().packets_sent > before);
        // two pings in two packets: acknowledged at once
        l.advance(ms(500));
        l.server.queued = ping.clone();
        l.flush();
        l.server.queued = ping.clone();
        l.flush();
        // (both are delivered in one step, which also lets the client send what it has to: count its datagrams)
        let sent = l.client_datagram_sizes.len();
        let now = l.now;
        l.step();
        assert_eq!(l.now, now + ms(20));
        assert_eq!(l.client_datagram_sizes.len(), sent + 1, "two pings are acknowledged at once, in one datagram");
        assert_eq!(l.client.timeout().map(|t| t > l.now), Some(true));
    }

    #[test]
    fn the_largest_acknowledged_and_the_ranges_are_what_was_received() {
        let mut a = AckState::default();
        let t = Instant::now();
        for pn in [0, 1, 2, 5, 6, 9] {
            a.on_received(t, pn, true, true, ms(25));
        }
        let mut out = Vec::new();
        let largest = a.write(&mut out, t + ms(8), 3, 100).unwrap();
        assert_eq!(largest, 9);
        // 9; delay 8000 us >> 3 = 1000; 2 more ranges; first range 0; gap 1 (7, 8), length 1 (5, 6); gap 1 (3, 4), length 2 (0..2)
        let mut r = crate::quic::wire::Reader::new(&out);
        assert_eq!(r.u8().unwrap(), 0x02);
        assert_eq!([r.varint().unwrap(), r.varint().unwrap(), r.varint().unwrap(), r.varint().unwrap()], [9, 1000, 2, 0]);
        assert_eq!([r.varint().unwrap(), r.varint().unwrap(), r.varint().unwrap(), r.varint().unwrap()], [1, 1, 1, 2]);
        assert!(r.is_empty());
        // the acknowledgment was sent: nothing is pending
        assert!(!a.pending() && a.write(&mut Vec::new(), t, 3, 100).is_none());
    }

    #[test]
    fn what_comes_out_of_order_is_acknowledged_at_once() {
        let t = Instant::now();
        let mut a = AckState::default();
        a.on_received(t, 0, true, true, ms(25));
        assert!(!a.due(t), "the first is held back");
        a.write(&mut Vec::new(), t, 3, 100);
        // a gap: 0 then 2
        a.on_received(t, 2, true, true, ms(25));
        assert!(a.due(t));
        a.write(&mut Vec::new(), t, 3, 100);
        // a packet that fills the gap
        a.on_received(t, 1, true, true, ms(25));
        assert!(a.due(t));
        a.write(&mut Vec::new(), t, 3, 100);
        // in order again: held back; and a packet that is not ack-eliciting never makes one due
        a.on_received(t, 3, true, true, ms(25));
        assert!(!a.due(t) && a.due(t + ms(25)));
        a.write(&mut Vec::new(), t, 3, 100);
        a.on_received(t, 5, false, true, ms(25));
        assert!(!a.pending());
        // the handshake levels do not wait
        let mut h = AckState::default();
        h.on_received(t, 0, true, false, ms(25));
        assert!(h.due(t));
    }

    #[test]
    fn an_acknowledgment_that_is_too_big_for_the_room_is_cut_to_the_highest_ranges() {
        let mut a = AckState::default();
        let t = Instant::now();
        for pn in (0..60).step_by(2) {
            a.on_received(t, pn, true, true, ms(25));
        }
        let mut out = Vec::new();
        let largest = a.write(&mut out, t, 3, 20).unwrap();
        assert_eq!(largest, 58);
        assert!(out.len() <= 20);
        let mut r = crate::quic::wire::Reader::new(&out);
        r.u8().unwrap();
        r.varint().unwrap();
        r.varint().unwrap();
        let count = r.varint().unwrap();
        assert!(count >= 1 && count < 29);
        // room for nothing
        let mut b = AckState::default();
        b.on_received(t, 0, true, true, ms(25));
        assert!(b.write(&mut Vec::new(), t, 3, 3).is_none());
        assert!(b.pending());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // key update

    #[test]
    fn a_key_update_by_the_server_is_followed() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        l.advance(ms(500));
        let mut ping = Vec::new();
        Frame::Ping.write(&mut ping);
        l.server.key_update();
        l.server.queued = ping.clone();
        l.flush();
        assert!(l.run_until(ms(500), |l| l.client.phases.as_ref().is_some_and(|p| p.rx_phase)));
        // the client has opened the packet with the next keys, and has updated its own
        assert_eq!(l.client.phases.as_ref().map(|p| (p.rx_phase, p.tx_phase)), Some((true, true)));
        // what it sends now is in the new phase: the server can open it, with its keys updated
        l.client.ping();
        l.advance(ms(200));
        assert_eq!(l.server.rx_updates, 1, "{:?}", l.server.log);
        assert!(l.client.stats().packets_dropped == 0, "{:?}", l.client.stats());
        // and everything goes on
        l.client.ping();
        l.advance(ms(200));
        assert_eq!(l.server.rx_updates, 1);
        assert!(l.server.log.iter().filter(|s| s.starts_with("OneRtt") && s.contains("Ping")).count() >= 2, "{:?}", l.server.log);
    }

    #[test]
    fn the_client_updates_its_keys_before_they_wear_out_and_the_server_follows() {
        let config = Config { key_update_after: 40, ..Config::default() };
        let mut l = Link::new(TestQuicServer::new("example.test", ServerOptions::default()), &config);
        confirmed(&mut l);
        transfer(&mut l, &pattern(300_000, 2), &pattern(100_000, 3));
        l.advance(ms(300));
        let stats = l.client.stats();
        assert!(stats.key_updates >= 3, "{stats:?}");
        // the server saw each, and followed (its packets are in the client's phase, and open)
        assert_eq!(l.server.rx_updates, stats.key_updates);
        // (the server's keys followed the client's last update; the client hears them when the server next has something to say)
        assert_eq!(l.client.phases.as_ref().unwrap().tx_phase, l.server.tx_phase);
        assert_eq!(stats.packets_dropped, 0, "{stats:?}");
        // no key sealed many more than it was to: an update waits only for an acknowledgment
        assert!(l.client.spaces[2].tx.as_ref().unwrap().packet.sealed() < 40 + 40, "{}", l.client.spaces[2].tx.as_ref().unwrap().packet.sealed());
        assert!(!l.client.is_closing());
    }

    #[test]
    fn keys_are_not_updated_again_before_a_packet_sent_with_them_is_acknowledged() {
        let config = Config { key_update_after: 10, ..Config::default() };
        let mut l = Link::new(TestQuicServer::new("example.test", ServerOptions::default()), &config);
        assert!(!l.client.update_keys(), "an update before the handshake is confirmed");
        confirmed(&mut l);
        l.client.ping();
        l.advance(ms(200));
        // from now on the server's datagrams are lost: nothing more is acknowledged
        let from = l.sent_by_server;
        l.drop_rule = Box::new(move |from_client, n, _| !from_client && n >= from);
        let id = l.client.open_stream(true).unwrap();
        for _ in 0..30 {
            let _ = l.client.stream_write(id, &[7u8; 1000], false);
            l.advance(ms(20));
        }
        assert_eq!(l.client.stats().key_updates, 1, "{:?}", l.client.stats());
        assert!(!l.client.update_keys());
        // the server is heard again: its acknowledgments let the next update happen
        l.drop_rule = Box::new(|_, _, _| false);
        assert!(l.run_until(Duration::from_secs(5), |l| l.client.stats().key_updates >= 2), "{:?}", l.client.stats());
        assert!(!l.client.is_closing());
    }

    #[test]
    fn after_following_the_servers_update_the_client_waits_for_an_acknowledgment_of_its_own_new_keys() {
        let config = Config { key_update_after: u64::MAX, ..Config::default() };
        let mut l = Link::new(TestQuicServer::new("example.test", ServerOptions::default()), &config);
        confirmed(&mut l);
        l.client.ping();
        l.advance(ms(200));
        // the server updates its keys, and the client follows when it opens a packet of the new ones
        let mut ping = Vec::new();
        Frame::Ping.write(&mut ping);
        l.server.key_update();
        l.server.queued = ping;
        l.flush();
        assert!(l.run_until(ms(500), |l| l.client.phases.as_ref().is_some_and(|p| p.rx_phase)));
        l.advance(ms(100));
        let first = l.client.phases.as_ref().map(|p| p.tx_first_pn).unwrap();
        assert!(l.client.phases.as_ref().is_some_and(|p| p.tx_phase && !p.tx_acked));
        assert!(l.client.spaces[2].next_pn > first, "nothing was sent with the new keys");
        let ack = |l: &mut Link, largest: u64| {
            let mut b = vec![0x02];
            crate::quic::wire::put_varint(&mut b, largest);
            b.extend([0, 0, 0]);
            let f = frame::frames(&b, PacketType::OneRtt).next().unwrap().unwrap();
            let Frame::Ack(a) = f else { panic!("{f:?}") };
            let now = l.now;
            l.client.on_ack_frame(now, Space::Application, &a).unwrap();
        };
        // an acknowledgment of a packet sent with the keys before does not let the client update again
        ack(&mut l, first - 1);
        assert!(!l.client.update_keys());
        // one of a packet sent with the keys now does
        ack(&mut l, first);
        assert!(l.client.update_keys());
    }

    #[test]
    fn keys_near_their_limit_that_cannot_be_updated_close_the_connection() {
        let limit = 1u64 << 23;
        let never = || -> bool { panic!("not asked to update") };
        assert_eq!(key_action(1000, 1 << 22, limit, never), KeyAction::Keep);
        // past what was asked for, or three quarters of the limit, whichever is first
        assert_eq!(key_action(1 << 22, 1 << 22, limit, || true), KeyAction::Updated);
        assert_eq!(key_action(limit / 4 * 3, u64::MAX, limit, || true), KeyAction::Updated);
        assert_eq!(key_action(limit / 4 * 3 - 1, u64::MAX, limit, never), KeyAction::Keep);
        // one that cannot be updated goes on until it is a sixteenth from its limit, and then the connection closes
        assert_eq!(key_action(limit / 4 * 3, 0, limit, || false), KeyAction::Keep);
        assert_eq!(key_action(limit - limit / 16 - 1, 0, limit, || false), KeyAction::Keep);
        assert_eq!(key_action(limit - limit / 16, 0, limit, || false), KeyAction::Close);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // keeping alive

    #[test]
    fn a_connection_that_waits_for_its_peer_is_kept_alive_and_one_that_does_not_goes_idle() {
        let config = Config { max_idle_timeout: Duration::from_secs(3), ..Config::default() };
        let mut l = Link::new(TestQuicServer::new("example.test", ServerOptions::default()), &config);
        confirmed(&mut l);
        l.client.set_keep_alive(true);
        // a minute in which neither side has anything to say: the client pings every second (a third of the idle timeout)
        assert!(!l.run_until(Duration::from_secs(60), |l| l.client.is_closing() || l.client.is_closed()), "{:?}", l.client_events);
        let pings = l.client.stats().keep_alives;
        assert!((55..=62).contains(&pings), "{pings} keep-alive PINGs in a minute");
        // the server hears them (all but the last, which may be on its way): it does not go idle either, as they ask for an answer
        let heard = l.server.log.iter().filter(|s| s.starts_with("OneRtt") && s.contains("Ping")).count() as u64;
        assert!(heard + 1 >= pings, "the server heard {heard} of {pings}");
        // nothing waits any more: the connection goes idle as it should
        l.client.set_keep_alive(false);
        assert!(l.run_until(Duration::from_secs(10), |l| l.client.is_closed()));
        assert!(l.client_events.iter().any(|e| matches!(e, Event::Closed(CloseReason::IdleTimeout))), "{:?}", l.client_events);
        assert_eq!(l.client.stats().keep_alives, pings);
    }

    #[test]
    fn a_peer_that_does_not_answer_keep_alives_still_times_out() {
        let config = Config { max_idle_timeout: Duration::from_secs(3), ..Config::default() };
        let mut l = Link::new(TestQuicServer::new("example.test", ServerOptions::default()), &config);
        confirmed(&mut l);
        l.client.set_keep_alive(true);
        let from = l.sent_by_server;
        l.drop_rule = Box::new(move |from_client, n, _| !from_client && n >= from);
        let started = l.now;
        assert!(l.run_until(Duration::from_secs(20), |l| l.client.is_closed()));
        // (the idle timer starts again with the first ack-eliciting packet sent after the last one received, not with each)
        assert!(l.now - started <= Duration::from_secs(5), "{:?}", l.now - started);
        assert!(l.client_events.iter().any(|e| matches!(e, Event::Closed(CloseReason::IdleTimeout))), "{:?}", l.client_events);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // what is dropped

    #[test]
    fn packets_that_do_not_open_are_dropped_without_harm() {
        let mut l = link(ServerOptions::default());
        l.flush();
        // noise to the connection id: a short header and a long header of version 1
        let mut a = vec![0x40u8; 60];
        a[1..9].copy_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
        l.client.recv(l.now, &mut a);
        let mut b = vec![0xc0u8, 0, 0, 0, 1, 8, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 4, 1, 2, 3, 4, 0, 0x40, 0x30];
        b.extend_from_slice(&[0x77; 0x30]);
        l.client.recv(l.now, &mut b);
        // a packet for another connection
        let mut c = vec![0x40u8; 60];
        l.client.recv(l.now, &mut c);
        // a datagram that is not a packet
        l.client.recv(l.now, &mut [0xff, 0x00]);
        l.client.recv(l.now, &mut []);
        assert!(!l.client.is_closing());
        assert!(l.client.stats().packets_dropped >= 3);
        established(&mut l);
    }

    #[test]
    fn handshake_packets_that_come_before_the_initial_are_kept_and_used() {
        // the server's datagram has the Initial and the Handshake packets one after the other: take them apart and give the client the
        // Handshake packets first
        let mut l = link(ServerOptions { crypto_chunk: 300, ..ServerOptions::default() });
        // run the server on the client's first datagram
        let mut first = Vec::new();
        assert!(l.client.poll_transmit(l.now, &mut first));
        l.server.recv(l.now, &mut first);
        let mut datagram = Vec::new();
        assert!(l.server.poll_transmit(l.now, &mut datagram));
        // the packets of the datagram, one by one
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut off = 0;
        while off < datagram.len() {
            let len = packet::parse(&datagram[off..], 8).unwrap().len;
            packets.push(datagram[off..off + len].to_vec());
            off += len;
        }
        assert!(packets.len() >= 2, "{}", packets.len());
        // the Handshake packets first, then the Initial
        let initial = packets.remove(0);
        for mut p in packets {
            l.client.recv(l.now, &mut p);
        }
        assert_eq!(l.client.undecryptable[1].len().min(1), 1, "handshake packets are kept until the keys come");
        let mut f = initial;
        l.client.recv(l.now, &mut f);
        // the kept ones were used: the handshake is complete
        l.flush();
        established(&mut l);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // streams

    fn client_stream_events(l: &mut Link) -> Vec<StreamEvent> {
        std::iter::from_fn(|| l.client.poll_stream_event()).collect()
    }

    fn pattern(len: usize, seed: u32) -> Vec<u8> {
        (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 13) as u8).collect()
    }

    #[test]
    fn streams_wait_for_the_handshake_and_are_closed_with_the_connection() {
        let mut l = link(ServerOptions::default());
        assert_eq!(l.client.open_stream(true), Err(StreamError::Blocked), "the server's limits are not known yet");
        confirmed(&mut l);
        let id = l.client.open_stream(true).unwrap();
        l.client.close(l.now, 0, b"");
        assert_eq!(l.client.open_stream(true), Err(StreamError::Closed));
        assert_eq!(l.client.stream_write(id, b"x", false), Err(StreamError::Closed));
        assert_eq!(l.client.stream_read(id, &mut [0u8; 1]), Err(StreamError::Closed));
        assert_eq!(l.client.stream_reset(id, 1), Err(StreamError::Closed));
    }

    #[test]
    fn a_request_goes_out_and_the_response_comes_back_on_the_same_stream() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        let id = l.client.open_stream(true).unwrap();
        assert_eq!(id, 0);
        assert_eq!(l.client.stream_write(id, b"GET /", true), Ok(5));
        l.advance(ms(100));
        let mut buf = [0u8; 100];
        assert_eq!(l.server.streams.read(id, &mut buf), Ok((5, true)));
        assert_eq!(&buf[..5], b"GET /");
        let body = pattern(3000, 1);
        assert_eq!(l.server.streams.write(id, &body, true), Ok(3000));
        l.advance(ms(200));
        assert_eq!(client_stream_events(&mut l), vec![StreamEvent::Readable(id)]);
        let mut got = Vec::new();
        loop {
            match l.client.stream_read(id, &mut buf) {
                Ok((n, fin)) => {
                    got.extend_from_slice(&buf[..n]);
                    if fin {
                        break;
                    }
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(got, body);
        // all acknowledged: the stream is over on both sides
        l.advance(ms(300));
        assert!(!l.client.streams.contains(id) && !l.server.streams.contains(id));
        assert!(l.server.stream_error.is_none());
        assert!(!l.client.is_closing());
    }

    /// Sends `up` on a stream to the server and has the server send `down` back on it, until both have arrived whole, with the end.
    fn transfer(l: &mut Link, up: &[u8], down: &[u8]) {
        let id = l.client.open_stream(true).unwrap();
        let (mut up_at, mut down_at) = (0, 0);
        let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
        let (mut up_end, mut down_end) = (false, false);
        let mut buf = vec![0u8; 5000];
        for _ in 0..40_000 {
            if up_at < up.len() || (up.is_empty() && up_at == 0) {
                match l.client.stream_write(id, &up[up_at..], true) {
                    Ok(n) => up_at += n,
                    Err(StreamError::Blocked) => {}
                    Err(e) => panic!("{e}"),
                }
            }
            if l.server.streams.contains(id) && down_at <= down.len() {
                match l.server.streams.write(id, &down[down_at..], true) {
                    Ok(n) => {
                        down_at += n;
                        if down_at == down.len() {
                            down_at += 1; // (done: the end was written with the last of it)
                        }
                    }
                    Err(StreamError::Blocked) => {}
                    Err(e) => panic!("{e}"),
                }
            }
            while l.server.streams.contains(id) && !up_end {
                match l.server.streams.read(id, &mut buf) {
                    Ok((n, fin)) => {
                        got_up.extend_from_slice(&buf[..n]);
                        up_end |= fin;
                        if n == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            while !down_end {
                match l.client.stream_read(id, &mut buf) {
                    Ok((n, fin)) => {
                        got_down.extend_from_slice(&buf[..n]);
                        down_end |= fin;
                        if n == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            while l.client.poll_stream_event().is_some() {}
            if up_end && down_end {
                break;
            }
            assert!(!l.client.is_closing(), "{:?} {:?}", l.client_events, l.server.stream_error);
            l.advance(ms(5));
        }
        assert!(up_end && down_end, "up {}/{} down {}/{} after {:?}", got_up.len(), up.len(), got_down.len(), down.len(), l.elapsed());
        assert!(got_up == up, "what the server got differs");
        assert!(got_down == down, "what the client got differs");
        assert!(l.server.stream_error.is_none(), "{:?}", l.server.stream_error);
    }

    #[test]
    fn a_lot_of_data_both_ways() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        transfer(&mut l, &pattern(400_000, 1), &pattern(300_000, 2));
        assert_eq!(l.client.stats().packets_lost, 0);
    }

    #[test]
    fn a_lot_of_data_over_a_link_that_loses_packets() {
        for (seed, loss) in [(1u64, 3u64), (2, 8), (3, 15)] {
            let mut l = link(ServerOptions::default());
            confirmed(&mut l);
            let mut state = seed * 7919 + 13;
            l.drop_rule = Box::new(move |_, _, _| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % 100 < loss
            });
            transfer(&mut l, &pattern(250_000, seed as u32), &pattern(200_000, seed as u32 + 9));
            assert!(l.client.stats().packets_lost > 0, "loss {loss}%");
        }
    }

    #[test]
    fn the_servers_flow_control_limits_are_kept_to_and_moved_up_as_it_reads() {
        // 20 000 bytes in all, 8 000 on a stream, to begin with
        let mut l = link(ServerOptions {
            params: Box::new(|p| {
                p.initial_max_data = 20_000;
                p.initial_max_stream_data_bidi_remote = 8_000;
            }),
            ..ServerOptions::default()
        });
        confirmed(&mut l);
        transfer(&mut l, &pattern(150_000, 5), &pattern(1000, 6));
        // the client was held to the limit at the start: it said so
        assert!(l.server.log.iter().any(|s| s.contains("StreamDataBlocked") || s.contains("DataBlocked")), "no blocked frame came");
    }

    #[test]
    fn the_client_stays_within_the_servers_stream_limit_and_opens_more_when_it_is_raised() {
        let mut l = link(ServerOptions { params: Box::new(|p| p.initial_max_streams_bidi = 2), ..ServerOptions::default() });
        confirmed(&mut l);
        let a = l.client.open_stream(true).unwrap();
        let b = l.client.open_stream(true).unwrap();
        assert_eq!(l.client.open_stream(true), Err(StreamError::Blocked));
        l.advance(ms(100));
        assert!(l.server.log.iter().any(|s| s.contains("StreamsBlocked")), "{:?}", l.server.log);
        // both streams are used and finished, on both sides: the server lets the client open another
        for id in [a, b] {
            l.client.stream_write(id, b"request", true).unwrap();
        }
        l.advance(ms(100));
        for id in [a, b] {
            let mut buf = [0u8; 20];
            assert_eq!(l.server.streams.read(id, &mut buf), Ok((7, true)));
            l.server.streams.write(id, b"ok", true).unwrap();
        }
        l.advance(ms(200));
        for id in [a, b] {
            assert_eq!(l.client.stream_read(id, &mut [0u8; 20]), Ok((2, true)));
        }
        l.advance(ms(300));
        assert!(client_stream_events(&mut l).contains(&StreamEvent::Available { bidirectional: true }));
        assert!(l.client.open_stream(true).is_ok());
    }

    #[test]
    fn a_stream_that_the_server_opens_is_read_by_the_client() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        let id = l.server.streams.open(false).unwrap();
        assert_eq!(id, 3);
        l.server.streams.write(id, b"control stream", false).unwrap();
        l.advance(ms(100));
        assert_eq!(client_stream_events(&mut l), vec![StreamEvent::Readable(3)]);
        let mut buf = [0u8; 50];
        assert_eq!(l.client.stream_read(3, &mut buf), Ok((14, false)));
        assert_eq!(l.client.stream_read(3, &mut buf), Err(StreamError::Blocked));
        // the client has no stream to write to on it
        assert_eq!(l.client.stream_write(3, b"x", false), Err(StreamError::Unknown));
    }

    #[test]
    fn a_reset_and_a_stop_sending_cross_the_connection() {
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        let a = l.client.open_stream(true).unwrap();
        l.client.stream_write(a, &pattern(5000, 1), false).unwrap();
        l.advance(ms(100));
        l.client.stream_reset(a, 42).unwrap();
        l.advance(ms(100));
        assert_eq!(l.server.streams.read(a, &mut [0u8; 10]), Err(StreamError::Reset(42)));
        // the server asks the client to stop sending on another
        let b = l.client.open_stream(true).unwrap();
        l.client.stream_write(b, &pattern(5000, 2), false).unwrap();
        l.advance(ms(100));
        l.server.streams.stop_sending(b, 7).unwrap();
        l.advance(ms(200));
        assert!(client_stream_events(&mut l).contains(&StreamEvent::Stopped(b, 7)));
        assert_eq!(l.client.stream_write(b, b"x", false), Err(StreamError::Stopped(7)));
        assert!(!l.client.is_closing() && l.server.stream_error.is_none());
    }

    #[test]
    fn the_server_that_breaks_the_flow_control_rules_ends_the_connection() {
        // data beyond the limit of the stream (1 MiB for the client's unidirectional streams of the server)
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        let mut frame = Vec::new();
        Frame::Stream { id: 3, offset: (1 << 20) + 10, data: &[0; 10], fin: false }.write(&mut frame);
        l.server.queued = frame;
        l.flush();
        assert!(l.run_until(ms(500), |l| l.server.close_received.is_some()));
        assert_eq!(l.server.close_received.as_ref().map(|c| c.0), Some(code::FLOW_CONTROL_ERROR));
        assert!(l.client.is_closing());
        // a frame for a stream that the client only sends on
        let mut l = link(ServerOptions::default());
        confirmed(&mut l);
        let mut frame = Vec::new();
        Frame::Stream { id: 2, offset: 0, data: &[0; 10], fin: false }.write(&mut frame);
        l.server.queued = frame;
        l.flush();
        assert!(l.run_until(ms(500), |l| l.server.close_received.is_some()));
        assert_eq!(l.server.close_received.as_ref().map(|c| c.0), Some(code::STREAM_STATE_ERROR));
    }
}
