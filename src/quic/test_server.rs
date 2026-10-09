//! A QUIC server for the tests of the client connection: it speaks packets (it reads and writes them with the same code as the
//! client, so it is no check of the formats: aioquic is), runs the handshake with the message-level TLS server of
//! [`test_peer`](super::test_peer), and can be told to do what a server should not, or to take a different way (a Retry, wrong
//! transport parameters, handshake data cut in pieces), so that a test sees what the client does.
//!
//! It has no loss recovery of its own but a timer that sends again whatever of its handshake data is not acknowledged. A
//! [`Link`] connects it to a client in a test, with a virtual clock, delay and loss that the test chooses.
#![allow(dead_code)]

use super::connection::{Connection, Event, SentFrame, TransportError};
use super::frame::{self, Frame};
use super::keys::{self, Keys, TAG_LEN};
use super::packet::{self, PacketType};
use super::rangeset::RangeSet;
use super::reassembly::Reassembler;
use super::sendbuf::SendBuf;
use super::streams::{StreamFrame, Streams, StreamsConfig};
use super::test_peer::{Flight, Hello, Options, TestServer};
use super::transport_params::{Sender, TransportParameters};
use super::wire::{decode_packet_number, varint_len};
use crate::tls::ClientConfig;
use std::time::{Duration, Instant};

/// What the server does that is not the usual.
pub struct ServerOptions {
    /// Answer the first Initial with a Retry.
    pub retry: bool,
    /// What to say in TLS (the ALPN protocol, the suite, ...).
    pub tls: Options,
    /// Change the transport parameters that the server would send (the connection ids are filled in before).
    pub params: Box<dyn Fn(&mut TransportParameters)>,
    /// Send these bytes as the transport parameters extension instead (Some(None): no extension at all).
    pub raw_params: Option<Option<Vec<u8>>>,
    /// Send the handshake flight in pieces of at most this many bytes per CRYPTO frame.
    pub crypto_chunk: usize,
    /// How long before unacknowledged handshake data is sent again.
    pub retransmit_after: Duration,
}

impl Default for ServerOptions {
    fn default() -> ServerOptions {
        ServerOptions {
            retry: false,
            tls: Options::default(),
            params: Box::new(|_| {}),
            raw_params: None,
            crypto_chunk: 1000,
            retransmit_after: Duration::from_millis(300),
        }
    }
}

struct Sent {
    level: usize,
    pn: u64,
    crypto: Vec<(u64, usize)>,
    /// The packet has HANDSHAKE_DONE in it.
    handshake_done: bool,
    /// The stream frames in it, which are lost when the timer runs out (and nothing is known of them).
    streams: Vec<StreamFrame>,
}

pub struct TestQuicServer {
    pub tls: TestServer,
    pub opts: ServerOptions,
    pub scid: Vec<u8>,
    pub odcid: Option<Vec<u8>>,
    pub client_scid: Vec<u8>,
    retry: Option<(Vec<u8>, Vec<u8>)>, // (the id it gave, the token)
    retry_sent: bool,
    /// (what we open with, what we seal with)
    keys: [Option<(Keys, Keys)>; 3],
    crypto_tx: [SendBuf; 3],
    crypto_rx: [Reassembler; 3],
    received: [RangeSet; 3],
    largest_rx: [Option<u64>; 3],
    ack_due: [bool; 3],
    next_pn: [u64; 3],
    sent: Vec<Sent>,
    flight: Option<Flight>,
    pub handshake_done: bool,
    handshake_done_sent: bool,
    handshake_done_acked: bool,
    /// Frames, as bytes, that the test wants sent in the next 1-RTT packet.
    pub queued: Vec<u8>,
    /// What came, one line a frame.
    pub log: Vec<String>,
    pub close_received: Option<(u64, Vec<u8>)>,
    retransmit_at: Option<Instant>,
    /// Datagrams that were to be sent at once, made already (a Retry).
    outbox: Vec<Vec<u8>>,
    pub tx_phase: bool,
    rx_phase: bool,
    /// The first 1-RTT packet number the server sent in its key phase now, and whether the client has acknowledged one sent
    /// in it (only then may the server update its keys again: RFC 9001 section 6.5).
    tx_phase_first_pn: u64,
    tx_phase_acked: bool,
    /// How many times the client's keys changed under us.
    pub rx_updates: u64,
    pub datagrams_received: u64,
    pub packets_received: u64,
    /// Close the connection with this code in the next 1-RTT packet.
    pub close_with: Option<(u64, Vec<u8>)>,
    /// The server's streams: the client's frames go in, and what the test writes goes out. Made again from the transport
    /// parameters that the server sends, when the ClientHello comes.
    pub streams: Streams,
    /// The error that the streams found in a frame of the client (the test server does not close the connection for it).
    pub stream_error: Option<TransportError>,
}

fn default_streams() -> Streams {
    Streams::new(StreamsConfig {
        client: false,
        max_data: 1 << 20,
        bidi_local: 1 << 18,
        bidi_remote: 1 << 18,
        uni: 1 << 18,
        max_streams_bidi: 100,
        max_streams_uni: 100,
        send_buffer: 4 << 20,
    })
}

impl TestQuicServer {
    pub fn new(name: &str, opts: ServerOptions) -> TestQuicServer {
        TestQuicServer {
            tls: TestServer::new(name),
            opts,
            scid: vec![0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7],
            odcid: None,
            client_scid: Vec::new(),
            retry: None,
            retry_sent: false,
            keys: [None, None, None],
            crypto_tx: [SendBuf::new(), SendBuf::new(), SendBuf::new()],
            crypto_rx: [Reassembler::new(), Reassembler::new(), Reassembler::new()],
            received: [RangeSet::new(), RangeSet::new(), RangeSet::new()],
            largest_rx: [None; 3],
            ack_due: [false; 3],
            next_pn: [0; 3],
            sent: Vec::new(),
            flight: None,
            handshake_done: false,
            handshake_done_sent: false,
            handshake_done_acked: false,
            queued: Vec::new(),
            log: Vec::new(),
            close_received: None,
            retransmit_at: None,
            outbox: Vec::new(),
            tx_phase: false,
            rx_phase: false,
            tx_phase_first_pn: 0,
            tx_phase_acked: false,
            rx_updates: 0,
            datagrams_received: 0,
            packets_received: 0,
            close_with: None,
            streams: default_streams(),
            stream_error: None,
        }
    }

    pub fn client_config(&self) -> ClientConfig {
        let mut config = ClientConfig::new(self.tls.pki.trust_store());
        config.alpn_protocols = vec![b"h3".to_vec()];
        config
    }

    pub fn timeout(&self) -> Option<Instant> {
        self.retransmit_at
    }

    pub fn on_timeout(&mut self, now: Instant) {
        if self.retransmit_at.is_some_and(|t| now >= t) {
            for l in 0..3 {
                self.crypto_tx[l].mark_all_lost();
            }
            if !self.handshake_done_acked {
                self.handshake_done_sent = false;
            }
            for packet in &mut self.sent {
                for f in std::mem::take(&mut packet.streams) {
                    self.streams.on_lost(&f);
                }
            }
            self.retransmit_at = None;
        }
    }

    pub fn recv(&mut self, now: Instant, datagram: &mut [u8]) {
        self.datagrams_received += 1;
        let mut off = 0;
        while off < datagram.len() {
            let Ok(p) = packet::parse(&datagram[off..], self.scid.len()) else { return };
            let (ty, pn_offset, len, dcid, scid, token) = (p.ty, p.pn_offset, p.len, p.dcid.to_vec(), p.scid.to_vec(), p.token.to_vec());
            self.recv_packet(now, &mut datagram[off..off + len], ty, pn_offset, &dcid, &scid, &token);
            off += len;
        }
    }

    fn recv_packet(&mut self, now: Instant, buf: &mut [u8], ty: PacketType, pn_offset: usize, dcid: &[u8], scid: &[u8], token: &[u8]) {
        let level = match ty {
            PacketType::Initial => 0,
            PacketType::Handshake => 1,
            PacketType::OneRtt => 2,
            _ => return,
        };
        if ty == PacketType::Initial {
            if self.keys[0].is_none() {
                if self.opts.retry && !self.retry_sent {
                    // a Retry: our own id for the client to use, and a token
                    self.retry_sent = true;
                    self.odcid = Some(dcid.to_vec());
                    self.client_scid = scid.to_vec();
                    let new_scid = vec![0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
                    let token = b"a retry token".to_vec();
                    self.retry = Some((new_scid.clone(), token.clone()));
                    let mut r = vec![0xf0u8];
                    r.extend_from_slice(&1u32.to_be_bytes());
                    r.push(scid.len() as u8);
                    r.extend_from_slice(scid);
                    r.push(new_scid.len() as u8);
                    r.extend_from_slice(&new_scid);
                    r.extend_from_slice(&token);
                    let tag = keys::retry_tag(dcid, &r);
                    r.extend_from_slice(&tag);
                    self.outbox.push(r);
                    return;
                }
                if let Some((new_scid, expected)) = &self.retry {
                    if token != expected.as_slice() || dcid != new_scid.as_slice() {
                        return;
                    }
                    self.scid = new_scid.clone();
                } else {
                    self.odcid = Some(dcid.to_vec());
                }
                self.client_scid = scid.to_vec();
                let (client, server) = keys::initial_keys(dcid);
                self.keys[0] = Some((client, server));
            }
        }
        let Some((rx, tx)) = self.keys[level].as_mut() else { return };
        let opened = if level == 2 {
            // 1-RTT: the key phase says which keys
            let Some(hdr) = rx.header.unprotect(buf, pn_offset) else { return };
            let pn = decode_packet_number(self.largest_rx[level], hdr.truncated_pn, hdr.pn_len);
            let phase = hdr.first & 0x04 != 0;
            let range = if phase == self.rx_phase {
                keys::open_payload(&mut rx.packet, buf, pn_offset, &hdr, pn)
            } else {
                let mut next = rx.next();
                let r = keys::open_payload(&mut next.packet, buf, pn_offset, &hdr, pn);
                if r.is_ok() {
                    *rx = next;
                    self.rx_phase = phase;
                    self.rx_updates += 1;
                    // the client updated its keys: the server's follow, before it acknowledges anything (RFC 9001 section 6.2)
                    if self.tx_phase != phase {
                        *tx = tx.next();
                        self.tx_phase = phase;
                        self.tx_phase_first_pn = self.next_pn[2];
                        self.tx_phase_acked = false;
                    }
                }
                r
            };
            range.map(|payload| keys::Opened { pn, first: hdr.first, payload })
        } else {
            rx.open(buf, pn_offset, self.largest_rx[level])
        };
        let Ok(o) = opened else { return };
        self.packets_received += 1;
        let payload = buf[o.payload.clone()].to_vec();
        let mut eliciting = false;
        for f in frame::frames(&payload, ty) {
            let f = match f {
                Ok(f) => f,
                Err(e) => {
                    self.log.push(format!("bad frame: {e}"));
                    break;
                }
            };
            eliciting |= f.ack_eliciting();
            self.log.push(format!("{:?} pn={} {:?}", ty, o.pn, f));
            match f {
                Frame::Crypto { offset, data } => {
                    let _ = self.crypto_rx[level].insert(offset, data, 1 << 20);
                    let bytes = self.crypto_rx[level].take();
                    self.on_crypto(now, level, &bytes);
                }
                Frame::Ack(a) => {
                    if level == 2 && a.largest >= self.tx_phase_first_pn {
                        self.tx_phase_acked = true;
                    }
                    let mut acked = Vec::new();
                    let mut done_acked = false;
                    let mut stream_frames = Vec::new();
                    self.sent.retain(|s| {
                        if s.level == level && a.acknowledges(s.pn) {
                            acked.push((s.level, s.crypto.clone()));
                            done_acked |= s.handshake_done;
                            stream_frames.extend(s.streams.iter().cloned());
                            false
                        } else {
                            true
                        }
                    });
                    for f in &stream_frames {
                        self.streams.on_acked(f);
                    }
                    if done_acked {
                        self.handshake_done_acked = true;
                        // (the handshake is confirmed: the Initial and Handshake keys are given up, and with them the handshake data
                        // that nobody can acknowledge any more, which a server that kept sending it would send for ever)
                        self.keys[0] = None;
                        self.keys[1] = None;
                        self.crypto_tx[0].clear();
                        self.crypto_tx[1].clear();
                        self.sent.retain(|s| s.level == 2);
                    }
                    for (l, ranges) in acked {
                        for (off, len) in ranges {
                            self.crypto_tx[l].on_acked(off, len, false);
                        }
                    }
                }
                Frame::ConnectionClose { code, reason, .. } => self.close_received = Some((code, reason.to_vec())),
                Frame::Stream { .. }
                | Frame::ResetStream { .. }
                | Frame::StopSending { .. }
                | Frame::MaxData(_)
                | Frame::MaxStreamData { .. }
                | Frame::MaxStreams { .. }
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. } => {
                    if let Err(e) = self.streams.on_frame(&f) {
                        self.stream_error.get_or_insert(e);
                    }
                }
                _ => {}
            }
        }
        self.received[level].insert_one(o.pn);
        if self.largest_rx[level].is_none_or(|l| o.pn > l) {
            self.largest_rx[level] = Some(o.pn);
        }
        if eliciting {
            self.ack_due[level] = true;
        }
    }

    fn on_crypto(&mut self, now: Instant, level: usize, bytes: &[u8]) {
        if level == 0 && self.flight.is_none() {
            // a whole ClientHello, or wait for more
            if bytes.len() < 4 {
                return;
            }
            let hello = Hello::parse(bytes);
            let mut o = self.opts.tls.clone();
            // transport parameters: the ids as the connection knows them
            let mut params = TransportParameters {
                original_destination_connection_id: self.odcid.clone(),
                initial_source_connection_id: Some(self.scid.clone()),
                retry_source_connection_id: self.retry.as_ref().map(|(s, _)| s.clone()),
                max_idle_timeout: 30_000,
                initial_max_data: 1 << 20,
                initial_max_stream_data_bidi_local: 1 << 18,
                initial_max_stream_data_bidi_remote: 1 << 18,
                initial_max_stream_data_uni: 1 << 18,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                ..TransportParameters::default()
            };
            (self.opts.params)(&mut params);
            o.params = match &self.opts.raw_params {
                Some(raw) => raw.clone(),
                None => Some(params.encode(Sender::Server)),
            };
            self.streams = Streams::new(StreamsConfig {
                client: false,
                max_data: params.initial_max_data,
                bidi_local: params.initial_max_stream_data_bidi_local,
                bidi_remote: params.initial_max_stream_data_bidi_remote,
                uni: params.initial_max_stream_data_uni,
                max_streams_bidi: params.initial_max_streams_bidi,
                max_streams_uni: params.initial_max_streams_uni,
                send_buffer: 4 << 20,
            });
            if let Some((_, bytes)) = hello.extensions.iter().find(|(t, _)| *t == 0x39) {
                if let Ok(client_params) = TransportParameters::decode(bytes, Sender::Client) {
                    self.streams.set_peer_params(&client_params);
                }
            }
            let flight = self.tls.flight(&hello, &o);
            self.crypto_tx[0].write(&flight.server_hello);
            for m in &flight.handshake {
                self.crypto_tx[1].write(m);
            }
            self.keys[1] = Some((Keys::new(flight.suite, &flight.client_handshake_secret), Keys::new(flight.suite, &flight.server_handshake_secret)));
            self.keys[2] = Some((Keys::new(flight.suite, &flight.client_application_secret), Keys::new(flight.suite, &flight.server_application_secret)));
            self.flight = Some(flight);
            self.retransmit_at = Some(now + self.opts.retransmit_after);
        } else if level == 1 {
            if let Some(f) = &self.flight {
                // the client's Finished
                if bytes.len() >= f.client_finished.len() && bytes[..f.client_finished.len()] == f.client_finished[..] {
                    self.handshake_done = true;
                }
            }
        }
    }

    /// The next datagram to send, if there is one.
    pub fn poll_transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> bool {
        out.clear();
        if let Some(d) = self.outbox.pop() {
            *out = d;
            return true;
        }
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut has_initial_crypto = false;
        for level in 0..3 {
            if self.keys[level].is_none() {
                continue;
            }
            let ty = [PacketType::Initial, PacketType::Handshake, PacketType::OneRtt][level];
            let used: usize = packets.iter().map(|p| p.len()).sum();
            if used + 100 > 1200 {
                break;
            }
            let room = 1200 - used - 50;
            let mut payload = Vec::new();
            let mut crypto = Vec::new();
            // (an acknowledgment goes when one is due, and also with every 1-RTT packet that is sent anyway, as most servers do: one
            // that went once and was lost leaves a client that hears the server but not of its own packets, backing its probes
            // off until the idle timeout ends a connection on which nothing was wrong; found by the field run's fuzzing)
            let piggyback = level == 2 && (!self.queued.is_empty() || self.streams.has_pending() || (self.handshake_done && !self.handshake_done_sent));
            if (self.ack_due[level] || piggyback) && !self.received[level].is_empty() {
                let ranges: Vec<_> = self.received[level].iter().rev().take(10).map(|r| r.start..=r.end - 1).collect();
                frame::write_ack(&mut payload, 0, &ranges, None);
                self.ack_due[level] = false;
            }
            let mut eliciting = false;
            let mut carries_done = false;
            while let Some(off) = self.crypto_tx[level].next_offset() {
                let header = 1 + varint_len(off) + 2;
                if payload.len() + header + 10 > room {
                    break;
                }
                let max = (room - payload.len() - header).min(self.opts.crypto_chunk);
                let Some(c) = self.crypto_tx[level].next_chunk(max, u64::MAX) else { break };
                let mut data = Vec::new();
                self.crypto_tx[level].copy(c.offset, c.len, &mut data);
                Frame::Crypto { offset: c.offset, data: &data }.write(&mut payload);
                crypto.push((c.offset, c.len));
                eliciting = true;
                if level == 0 {
                    has_initial_crypto = true;
                }
            }
            let mut stream_frames: Vec<StreamFrame> = Vec::new();
            if level == 2 {
                if self.handshake_done && !self.handshake_done_sent {
                    Frame::HandshakeDone.write(&mut payload);
                    self.handshake_done_sent = true;
                    carries_done = true;
                    eliciting = true;
                }
                if !self.queued.is_empty() {
                    payload.extend_from_slice(&std::mem::take(&mut self.queued));
                    eliciting = true;
                }
                let mut written = Vec::new();
                let budget = room.saturating_sub(payload.len());
                self.streams.write_frames(&mut payload, budget, &mut written);
                for f in written {
                    if let SentFrame::Stream(f) = f {
                        stream_frames.push(f);
                    }
                }
                if !stream_frames.is_empty() {
                    eliciting = true;
                }
                if let Some((code, reason)) = self.close_with.take() {
                    Frame::ConnectionClose { code, frame_type: None, reason: &reason }.write(&mut payload);
                }
            }
            if payload.is_empty() {
                continue;
            }
            let pn = self.next_pn[level];
            self.next_pn[level] += 1;
            let mut buf = Vec::new();
            let (long, pn_offset) = if ty == PacketType::OneRtt {
                (None, packet::write_short_header(&mut buf, &self.client_scid, false, self.tx_phase, pn, 4))
            } else {
                let h = packet::write_long_header(&mut buf, ty, &self.client_scid, &self.scid, &[], pn, 4);
                (Some(h), h.pn_offset)
            };
            if payload.len() < 4 {
                payload.resize(4, 0);
            }
            buf.extend_from_slice(&payload);
            if let Some(h) = long {
                packet::finish_long(&mut buf, h, TAG_LEN);
            }
            let (_, tx) = self.keys[level].as_mut().expect("keys");
            tx.seal(&mut buf, pn_offset, 4, pn).unwrap();
            if eliciting {
                self.sent.push(Sent { level, pn, crypto, handshake_done: carries_done, streams: stream_frames });
            }
            packets.push(buf);
        }
        if packets.is_empty() {
            return false;
        }
        let _ = has_initial_crypto; // (a real server pads its Initial datagrams to 1200 bytes; the client does not check)
        for p in packets {
            out.extend_from_slice(&p);
        }
        if self.crypto_tx.iter().any(|c| c.has_pending()) || !self.sent.is_empty() || (self.handshake_done_sent && !self.handshake_done_acked) {
            self.retransmit_at.get_or_insert(now + self.opts.retransmit_after);
        }
        true
    }

    /// Whether the server may start a key update: the client has acknowledged a packet that the server sent with the keys it
    /// has now (RFC 9001 section 6.5), so it has those keys.
    pub fn keys_agreed(&self) -> bool {
        self.tx_phase_acked && self.rx_phase == self.tx_phase
    }

    /// Updates the keys the server sends with (and expects): a key update that the server starts.
    pub fn key_update(&mut self) {
        self.tx_phase_first_pn = self.next_pn[2];
        self.tx_phase_acked = false;
        if let Some((rx, tx)) = self.keys[2].as_mut() {
            *tx = tx.next();
            let _ = rx;
        }
        self.tx_phase = !self.tx_phase;
    }
}

/// A client and a server joined by a link with a virtual clock: a test says how long the link takes, and which datagrams it loses.
pub struct Link {
    pub now: Instant,
    pub start: Instant,
    pub client: Connection,
    pub server: TestQuicServer,
    pub delay: Duration,
    /// Datagrams in transit: (when they arrive, to the server?, the bytes).
    transit: Vec<(Instant, bool, Vec<u8>)>,
    /// Decides whether a datagram is lost: (from the client?, its number among those from that side, the bytes).
    pub drop_rule: Box<dyn FnMut(bool, u64, &[u8]) -> bool>,
    pub sent_by_client: u64,
    pub sent_by_server: u64,
    pub client_events: Vec<Event>,
    /// The sizes of the datagrams the client sent, as it sent them (lost ones too).
    pub client_datagram_sizes: Vec<usize>,
}

impl Link {
    pub fn new(server: TestQuicServer, config: &super::connection::Config) -> Link {
        let now = Instant::now();
        let client = Connection::connect_with_ids(
            config,
            &server.client_config(),
            "example.test",
            now,
            vec![0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7],
            vec![0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7],
        )
        .expect("a connection");
        Link {
            now,
            start: now,
            client,
            server,
            delay: Duration::from_millis(20),
            transit: Vec::new(),
            drop_rule: Box::new(|_, _, _| false),
            sent_by_client: 0,
            sent_by_server: 0,
            client_events: Vec::new(),
            client_datagram_sizes: Vec::new(),
        }
    }

    /// How much virtual time has passed.
    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Sends all that either side has to send now.
    pub fn flush(&mut self) {
        let mut buf = Vec::new();
        while self.client.poll_transmit(self.now, &mut buf) {
            let n = self.sent_by_client;
            self.sent_by_client += 1;
            self.client_datagram_sizes.push(buf.len());
            if !(self.drop_rule)(true, n, &buf) {
                self.transit.push((self.now + self.delay, true, buf.clone()));
            }
        }
        while self.server.poll_transmit(self.now, &mut buf) {
            let n = self.sent_by_server;
            self.sent_by_server += 1;
            if !(self.drop_rule)(false, n, &buf) {
                self.transit.push((self.now + self.delay, false, buf.clone()));
            }
        }
        while let Some(e) = self.client.poll_event() {
            self.client_events.push(e);
        }
    }

    /// When the next thing happens (a datagram arrives, a timer expires), if anything will.
    pub fn next_event(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        };
        for (t, _, _) in &self.transit {
            consider(Some(*t));
        }
        consider(self.client.timeout());
        consider(self.server.timeout());
        next
    }

    /// Does what happens at `t` (not before now): delivers the datagrams that are due and wakes whoever's timer is due.
    fn process_at(&mut self, t: Instant) {
        self.now = self.now.max(t);
        let now = self.now;
        // deliver what has arrived, in the order sent
        let mut due: Vec<(Instant, bool, Vec<u8>)> = Vec::new();
        let mut rest = Vec::new();
        for item in std::mem::take(&mut self.transit) {
            if item.0 <= now {
                due.push(item);
            } else {
                rest.push(item);
            }
        }
        self.transit = rest;
        due.sort_by_key(|d| d.0);
        for (_, to_server, mut bytes) in due {
            if to_server {
                self.server.recv(now, &mut bytes);
            } else {
                self.client.recv(now, &mut bytes);
            }
        }
        if self.client.timeout().is_some_and(|t| t <= now) {
            self.client.on_timeout(now);
        }
        if self.server.timeout().is_some_and(|t| t <= now) {
            self.server.on_timeout(now);
        }
        self.flush();
    }

    /// Advances to the next thing that happens, and does it. False if nothing ever will.
    pub fn step(&mut self) -> bool {
        self.flush();
        let Some(t) = self.next_event() else { return false };
        self.process_at(t);
        true
    }

    /// Lets `d` of virtual time pass, with everything that happens in it.
    pub fn advance(&mut self, d: Duration) {
        self.flush();
        let target = self.now + d;
        while let Some(t) = self.next_event() {
            if t > target {
                break;
            }
            self.process_at(t);
        }
        self.now = target;
        self.flush();
    }

    /// Steps until `done` says so or `limit` of virtual time has passed (from now). Returns whether `done` became true.
    pub fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Link) -> bool) -> bool {
        let deadline = self.now + limit;
        if done(self) {
            return true;
        }
        while self.now <= deadline {
            if !self.step() {
                return done(self);
            }
            if done(self) {
                return true;
            }
        }
        false
    }
}

#[allow(unused_imports)]
use decode_packet_number as _;
