//! The client connection of QUIC, for the coverage-guided fuzzer in `fuzz/`; compiled only with `--cfg pratique_fuzzing`. Not part
//! of the API.
//!
//! [`connection`] makes a client and the test server of `test_server.rs` talk over a network of its own (virtual clock; it loses,
//! duplicates, delays and corrupts datagrams), completes the handshake, and then does what the input says to the client's streams and,
//! through the server, to the server's. The input chooses the settings (the flow control limits of both sides, the size of the
//! datagrams, whether there is a Retry, how bad the network is) and then the steps, so what is reached is every path of the
//! connection that a peer and an application can make: the loss recovery under real loss, the flow control with windows from a
//! few hundred bytes up, the streams, key updates, closing.
//!
//! There are two kinds of run, by the first byte:
//!
//! * **honest** (even): the server does what a server does, and the network may lose, duplicate, delay and corrupt (but not three
//!   datagrams in a row in one direction, so that something always gets through). Then the bytes of every stream have to come out as
//!   they went in, whole, in order, with their ends, in both directions, whatever the windows and the loss, all the streams that
//!   were not reset or stopped; the client must not have closed the connection; the server's streams, which see what the client
//!   sends, must find no violation of flow control in it; a stream that both sides have finished with must be forgotten once all is
//!   acknowledged; a server that keeps pinging keeps the connection from idling out, however long the client says nothing; and a
//!   connection that has nothing more to do must end by the idle timeout.
//! * **hostile** (odd): the server also sends the frames that the input holds, in packets that are sealed right, whatever they say:
//!   reset what was not opened, flow control limits that go down, streams beyond the limit, ids out of the connection ids' range,
//!   cuts in the middle of a frame. Nothing is promised of the data; what must hold is that nothing panics, that the client's
//!   datagrams are of a size that a datagram may be, that it ends when it has closed, and that it never goes on forever.

use super::connection::{CloseReason, Config, Connection, Event};
use super::streams::{StreamError, StreamEvent};
use super::test_server::{ServerOptions, TestQuicServer};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// A fast generator that the same input always gives the same numbers of.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A byte at a time from the input, zeros when it has run out.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, self.0), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The byte at offset `at` of the stream `id` that `from_client` writes.
fn pat(from_client: bool, id: u64, at: u64) -> u8 {
    (at.wrapping_mul(131).wrapping_add(id.wrapping_mul(17)).wrapping_add(u64::from(from_client) * 7) % 251) as u8
}

fn is_bidirectional(id: u64) -> bool {
    id & 2 == 0
}

/// What the application of each side wrote and read, by (written by the client?, stream id).
#[derive(Default)]
struct Book {
    written: BTreeMap<(bool, u64), u64>,
    read: BTreeMap<(bool, u64), u64>,
    fin_written: BTreeSet<(bool, u64)>,
    fin_read: BTreeSet<(bool, u64)>,
    /// Reset or stopped, one way or the other: what came is checked to be the beginning of what was written, no more.
    broken: BTreeSet<(bool, u64)>,
}

struct Sim {
    now: Instant,
    start: Instant,
    client: Connection,
    server: TestQuicServer,
    /// Datagrams in transit: (arrival, a number for the order they were sent in, to the server?, the bytes).
    transit: Vec<(Instant, u64, bool, Vec<u8>)>,
    seq: u64,
    rng: Rng,
    delay: Duration,
    loss: u64,
    duplicate: u64,
    reorder: u64,
    corrupt: u64,
    /// How many datagrams were lost in a row, toward the server and toward the client.
    dropped_in_a_row: [u32; 2],
    /// When a datagram last got through, toward the server and toward the client.
    last_through: [Instant; 2],
    /// In an honest run, a direction that has had nothing through for this long lets the next datagram through.
    starved: Duration,
    /// Nothing the server sends reaches the client (the end of a hostile run: the server goes quiet).
    server_muted: bool,
    honest: bool,
    max_datagram: usize,
    first_datagram: bool,
    /// How many datagrams the server has sent, and whether it answers the first with a Retry (which the test server does not send
    /// again if it is lost: a real one does not need to remember).
    server_datagrams: u64,
    retry: bool,
    book: Book,
    /// The streams each side opened, and those that each has been told of by the other.
    own_client: Vec<u64>,
    own_server: Vec<u64>,
    known_client: BTreeSet<u64>,
    known_server: BTreeSet<u64>,
    /// How many key updates the server began.
    updates_begun: u64,
    steps: u64,
    /// Why the client's connection ended, if it has.
    closed: Option<CloseReason>,
    /// Say what happens on stderr (`PRATIQUE_FUZZ_TRACE` is set).
    trace: bool,
}

impl Sim {
    /// Takes everything the two ends have to send and puts it on the network.
    fn flush(&mut self) {
        let mut buf = Vec::new();
        let mut n = 0;
        while self.client.poll_transmit(self.now, &mut buf) {
            n += 1;
            assert!(n < 50_000, "the client sends datagrams without end");
            assert!(buf.len() <= self.max_datagram.max(1200), "a datagram of {} bytes, the limit is {}", buf.len(), self.max_datagram.max(1200));
            if self.first_datagram {
                self.first_datagram = false;
                assert!(buf.len() >= 1200, "the first datagram of the client is {} bytes, under 1200", buf.len());
            }
            self.route(true, buf.clone());
        }
        let mut n = 0;
        while self.server.poll_transmit(self.now, &mut buf) {
            n += 1;
            assert!(n < 50_000, "the server sends datagrams without end");
            self.route(false, buf.clone());
        }
    }

    /// What the network does to a datagram.
    fn route(&mut self, to_server: bool, mut bytes: Vec<u8>) {
        if !to_server && self.server_muted {
            return;
        }
        let dir = usize::from(to_server);
        let protected = !to_server && self.retry && self.server_datagrams == 0;
        if !to_server {
            self.server_datagrams += 1;
        }
        let mut lose = self.rng.chance(self.loss) && !protected;
        // (what is corrupted is not read, which is a loss as far as the others are concerned; the version and the first byte stay: a
        // changed version makes a Version Negotiation packet, which a client believes. Nor is anything corrupted on its way to the
        // server before the handshake is done, for the test server takes the connection ids and keys of the first Initial it sees.)
        let mut corrupted = bytes.len() > 6 && !protected && self.rng.chance(self.corrupt) && (!to_server || self.server.handshake_done || !self.honest);
        if (lose || corrupted) && self.honest {
            // (three in a row is not enough on its own: the probes of a client that has heard nothing back off, one round trip
            // after another can fail with a loss in either direction, and an honest network that lost every round trip for
            // the idle timeout ended a connection that did nothing wrong (found by the field run's fuzzing, at 25% loss). So
            // a direction that has had nothing through for a quarter of the idle timeout lets the next datagram through: of the
            // idle timeout that applies, the smaller of the two sides'. A quarter of the client's alone, 30 s of a 120 s setting,
            // was all of the server's 30 s, and the network could be silent until the client gave up: found by fuzzing after the
            // field run.)
            if self.dropped_in_a_row[dir] >= 3 || self.now.saturating_duration_since(self.last_through[dir]) >= self.starved {
                lose = false;
                corrupted = false;
            }
        }
        if lose || corrupted {
            self.dropped_in_a_row[dir] += 1;
        } else {
            self.dropped_in_a_row[dir] = 0;
            self.last_through[dir] = self.now;
        }
        if self.trace {
            eprintln!("{:>8.1} ms  {}  {:>5} bytes  {}", (self.now - self.start).as_secs_f64() * 1000.0, if to_server { "client->server" } else { "server->client" }, bytes.len(), if lose { "lost" } else if corrupted { "corrupted" } else { "" });
        }
        if lose {
            return;
        }
        if corrupted {
            let at = 6 + self.rng.below(bytes.len() as u64 - 6) as usize;
            bytes[at] ^= 1 << self.rng.below(8);
        }
        let mut when = self.now + self.delay;
        if self.rng.chance(self.reorder) {
            when += self.delay * (1 + self.rng.below(3) as u32);
        }
        self.seq += 1;
        if self.rng.chance(self.duplicate) {
            self.seq += 1;
            let again = when + Duration::from_millis(self.rng.below(30));
            self.transit.push((again, self.seq, to_server, bytes.clone()));
        }
        self.transit.push((when, self.seq, to_server, bytes));
    }

    fn next_event(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        };
        for (t, _, _, _) in &self.transit {
            consider(Some(*t));
        }
        consider(self.client.timeout());
        consider(self.server.timeout());
        next
    }

    /// Does what happens at `t`: delivers the datagrams that are due and runs the timers that are due.
    fn process_at(&mut self, t: Instant) {
        self.steps += 1;
        assert!(self.steps < 400_000, "it does not end: {} steps, {:?} of virtual time", self.steps, self.now - self.start);
        self.now = self.now.max(t);
        let now = self.now;
        let (mut due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.transit).into_iter().partition(|d| d.0 <= now);
        self.transit = rest;
        due.sort_by_key(|d| (d.0, d.1));
        for (_, _, to_server, mut bytes) in due {
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
        self.service();
    }

    /// Lets `d` of virtual time pass, with everything that happens in it.
    fn advance(&mut self, d: Duration) {
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
        self.service();
    }

    fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Sim) -> bool) -> bool {
        let deadline = self.now + limit;
        self.flush();
        while !done(self) {
            let Some(t) = self.next_event() else { return done(self) };
            if t > deadline {
                return false;
            }
            self.process_at(t);
        }
        true
    }

    /// The application's part that is not for the input to choose: what the streams tell, and what the server reads (at once, all of
    /// it, so that the client is not held back by the server's flow control for long: that is what the windows in the settings are for).
    fn service(&mut self) {
        while let Some(e) = self.client.poll_event() {
            if let Event::Closed(reason) = e {
                if self.trace {
                    eprintln!("{:>8.1} ms  the client's connection is closed: {reason:?}", (self.now - self.start).as_secs_f64() * 1000.0);
                }
                self.closed.get_or_insert(reason);
            }
        }
        while let Some(e) = self.client.poll_stream_event() {
            match e {
                StreamEvent::Readable(id) => {
                    self.known_client.insert(id);
                }
                StreamEvent::Stopped(id, _) => {
                    self.book.broken.insert((true, id));
                }
                _ => {}
            }
        }
        while let Some(e) = self.server.streams.poll_event() {
            match e {
                StreamEvent::Readable(id) => {
                    self.known_server.insert(id);
                }
                StreamEvent::Stopped(id, _) => {
                    self.book.broken.insert((false, id));
                }
                _ => {}
            }
        }
        let ids: Vec<u64> = self.known_server.iter().copied().collect();
        for id in ids {
            self.read_on(false, id, 4000);
        }
    }

    fn write_on(&mut self, from_client: bool, id: u64, len: usize, fin: bool) {
        let key = (from_client, id);
        let at = self.book.written.get(&key).copied().unwrap_or(0);
        let data: Vec<u8> = (0..len as u64).map(|i| pat(from_client, id, at + i)).collect();
        let r = if from_client { self.client.stream_write(id, &data, fin) } else { self.server.streams.write(id, &data, fin) };
        match r {
            Ok(n) => {
                assert!(n <= len, "a write took {n} of {len} bytes");
                *self.book.written.entry(key).or_insert(0) += n as u64;
                if fin && n == len {
                    self.book.fin_written.insert(key);
                }
            }
            Err(StreamError::Reset(_)) => panic!("a write that says the peer reset the stream"),
            Err(_) => {}
        }
    }

    /// Reads from the stream everything there is (at most `max` bytes at a time) and checks that it is what the other side wrote.
    fn read_on(&mut self, by_client: bool, id: u64, max: usize) {
        let key = (!by_client, id);
        let mut buf = vec![0u8; max.max(1)];
        for _ in 0..10_000 {
            let r = if by_client { self.client.stream_read(id, &mut buf) } else { self.server.streams.read(id, &mut buf) };
            match r {
                Ok((n, fin)) => {
                    assert!(n <= buf.len());
                    let at = self.book.read.entry(key).or_insert(0);
                    if self.honest {
                        for (i, b) in buf[..n].iter().enumerate() {
                            assert_eq!(*b, pat(key.0, id, *at + i as u64), "stream {id} (written by the {}): byte {} is not what was written", if key.0 { "client" } else { "server" }, *at + i as u64);
                        }
                    }
                    *at += n as u64;
                    if fin {
                        self.book.fin_read.insert(key);
                        return;
                    }
                    if n == 0 {
                        return;
                    }
                }
                Err(StreamError::Reset(_)) => {
                    self.book.broken.insert(key);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    /// Every stream that the books know of is read, by whoever is its reader.
    fn read_everything(&mut self) {
        let keys: BTreeSet<(bool, u64)> = self.book.written.keys().chain(self.book.fin_written.iter()).copied().collect();
        for (from_client, id) in keys {
            self.read_on(!from_client, id, 5000);
        }
    }

    /// Whether every stream that was not broken has been read whole, with its end.
    fn complete(&self) -> bool {
        self.book.written.keys().chain(self.book.fin_written.iter()).all(|key| {
            self.book.broken.contains(key)
                || (self.book.read.get(key).copied().unwrap_or(0) == self.book.written.get(key).copied().unwrap_or(0)
                    && (!self.book.fin_written.contains(key) || self.book.fin_read.contains(key)))
        })
    }

    fn describe_incomplete(&self) -> String {
        let mut s = String::new();
        if self.trace {
            eprintln!("the server's streams: pending {} ; client {:?} stats {:?} timeout {:?}", self.server.streams.has_pending(), self.client.state(), self.client.stats(), self.client.timeout().map(|t| t.saturating_duration_since(self.now)));
            for id in self.server.streams.stream_ids() {
                eprintln!("server stream {id}: {}", self.server.streams.describe_send(id));
            }
            for id in self.known_client.iter().chain(self.own_client.iter()) {
                eprintln!("client stream {id}: {}", self.client.describe_stream(*id));
            }
            eprintln!("client: window {} in flight {} ssthresh {} srtt {:?} streams pending {} confirmed {}", self.client.congestion().window(), self.client.bytes_in_flight(), self.client.congestion().ssthresh(), self.client.smoothed_rtt(), self.client.streams_have_pending(), self.client.is_confirmed());
            eprintln!("server timer {:?}", self.server.timeout().map(|t| t.saturating_duration_since(self.now)));
            eprintln!("what the server was told:");
            for line in self.server.log.iter().rev().take(80).rev() {
                eprintln!("   {line}");
            }
        }
        for key in self.book.written.keys().chain(self.book.fin_written.iter()) {
            if self.book.broken.contains(key) {
                continue;
            }
            let (w, r) = (self.book.written.get(key).copied().unwrap_or(0), self.book.read.get(key).copied().unwrap_or(0));
            if r != w || (self.book.fin_written.contains(key) && !self.book.fin_read.contains(key)) {
                s += &format!("\n stream {} by the {}: wrote {w}, read {r}, end written {} read {}", key.1, if key.0 { "client" } else { "server" }, self.book.fin_written.contains(key), self.book.fin_read.contains(key));
            }
        }
        if self.trace {
            eprintln!("incomplete:{s}");
        }
        s
    }
}

fn pick(ids: &[u64], by: u8) -> Option<u64> {
    if ids.is_empty() {
        None
    } else {
        Some(ids[by as usize % ids.len()])
    }
}

/// The idle timeout the test server asks for (its transport parameter, in milliseconds); the connection's is the smaller of
/// this and the client's.
const SERVER_IDLE_MS: u64 = 30_000;

/// See the top of this file.
pub fn connection(data: &[u8]) {
    let mut c = Cursor(data);
    let b0 = c.u8();
    let honest = b0 & 1 == 0;
    let retry = b0 & 2 != 0;
    let crypto_chunk = [1000, 300, 150, 1100][(b0 >> 2) as usize & 3];
    let delay = Duration::from_millis([5, 20, 40, 100][(b0 >> 4) as usize & 3]);
    let loss = [0, 3, 10, 25][(b0 >> 6) as usize & 3];
    let b1 = c.u8();
    let b2 = c.u8();
    let b3 = c.u8();
    let seed = u64::from(c.u16()) << 16 | u64::from(c.u16()) | 1 << 40;

    let windows = [2500u64, 9000, 65_536, 1 << 20];
    let mut config = Config::default();
    // (an honest run is not to end by the idle timeout because the loss was unlucky: backing off after the loss of a few probes in a
    // row takes seconds. A hostile one may, and ends so.)
    config.max_idle_timeout = Duration::from_secs(if honest { [30, 60, 120][(b1 % 3) as usize] } else { [5, 15, 30][(b1 % 3) as usize] });
    config.initial_max_data = windows[(b1 >> 2) as usize & 3];
    config.initial_max_stream_data_bidi_local = windows[(b1 >> 4) as usize & 3];
    config.initial_max_stream_data_uni = windows[(b1 >> 6) as usize & 3];
    config.initial_max_stream_data_bidi_remote = windows[(b2 >> 6) as usize & 3];
    config.initial_max_streams_bidi = [0, 2, 8][(b2 % 3) as usize];
    config.initial_max_streams_uni = [0, 4, 16][((b2 >> 2) % 3) as usize];
    config.stream_send_buffer = [3000, 20_000, 1 << 20][((b2 >> 4) % 3) as usize];
    config.max_datagram_size = [1200, 1350, 1472][(b3 % 3) as usize];
    // (keys updated every 64 packets, so that a run goes through updates the client starts, under loss and reordering: B-91)
    config.key_update_after = 64;
    config.cid_len = [4, 8, 20][((b3 >> 2) % 3) as usize];

    let server_data = [3000u64, 12_000, 1 << 20][(b3 >> 4) as usize % 3];
    let server_stream = [1500u64, 4000, 1 << 18][(b3 >> 6) as usize % 3];
    let server_streams = [1u64, 3, 20][(b2 >> 1) as usize % 3];
    let mut opts = ServerOptions::default();
    opts.retry = retry;
    opts.crypto_chunk = crypto_chunk;
    opts.params = Box::new(move |p| {
        p.max_idle_timeout = SERVER_IDLE_MS;
        p.initial_max_data = server_data;
        p.initial_max_stream_data_bidi_local = server_stream;
        p.initial_max_stream_data_bidi_remote = server_stream;
        p.initial_max_stream_data_uni = server_stream;
        p.initial_max_streams_bidi = server_streams;
        p.initial_max_streams_uni = server_streams + 1;
    });
    let server = TestQuicServer::new("example.test", opts);
    let now = Instant::now();
    let tls = server.client_config();
    let scid: Vec<u8> = (0..config.cid_len).map(|i| 0xa0 + i as u8).collect();
    let client = Connection::connect_with_ids(&config, &tls, "example.test", now, scid, vec![0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]).expect("a connection");
    let mut sim = Sim {
        now,
        start: now,
        client,
        server,
        transit: Vec::new(),
        seq: 0,
        rng: Rng(seed),
        delay,
        loss,
        duplicate: if honest { 3 } else { 10 },
        reorder: if honest { 10 } else { 20 },
        corrupt: if honest { 3 } else { 10 },
        dropped_in_a_row: [0; 2],
        last_through: [now; 2],
        starved: config.max_idle_timeout.min(Duration::from_millis(SERVER_IDLE_MS)) / 4,
        server_muted: false,
        honest,
        max_datagram: config.max_datagram_size,
        first_datagram: true,
        server_datagrams: 0,
        retry,
        book: Book::default(),
        own_client: Vec::new(),
        own_server: Vec::new(),
        known_client: BTreeSet::new(),
        known_server: BTreeSet::new(),
        updates_begun: 0,
        steps: 0,
        closed: None,
        trace: std::env::var_os("PRATIQUE_FUZZ_TRACE").is_some(),
    };
    if sim.trace {
        eprintln!("settings: honest {honest} retry {retry} loss {loss}% delay {delay:?} client {config:?} server data {server_data} stream {server_stream} streams {server_streams}");
    }

    // the handshake, over the same network
    let confirmed = sim.run_until(Duration::from_secs(120), |s| s.client.is_confirmed());
    if !confirmed {
        assert!(!honest, "the handshake did not finish in two minutes: {:?}", sim.client.state());
        return;
    }
    sim.service();

    let mut closed_by_us = false;
    for _ in 0..150 {
        if c.is_empty() || sim.client.is_closing() {
            break;
        }
        let op = c.u8() % 16;
        let a = c.u8();
        let n = c.u16() as usize;
        if sim.trace {
            eprintln!("{:>8.1} ms  op {op} a {a} n {n}", (sim.now - sim.start).as_secs_f64() * 1000.0);
        }
        match op {
            0..=2 => {
                if honest {
                    // (traffic, so that the idle timeout is not what ends a run that waits)
                    sim.client.ping();
                }
                sim.advance(Duration::from_millis([1, 7, 40][op as usize] * (1 + u64::from(a) % 8)))
            }
            3 => {
                if let Ok(id) = sim.client.open_stream(a & 1 == 0) {
                    sim.own_client.push(id);
                }
            }
            4 | 5 => {
                let mut ids = sim.own_client.clone();
                ids.extend(sim.known_client.iter().copied().filter(|&id| is_bidirectional(id) && id & 1 == 1));
                if let Some(id) = pick(&ids, a) {
                    sim.write_on(true, id, n % 2500, a % 9 == 0);
                }
            }
            6 => {
                let mut ids: Vec<u64> = sim.known_client.iter().copied().collect();
                ids.extend(sim.own_client.iter().copied().filter(|&id| is_bidirectional(id)));
                if let Some(id) = pick(&ids, a) {
                    sim.read_on(true, id, 1 + n % 3000);
                }
            }
            7 => {
                // the client stops a stream it reads (what came is the beginning of what the server wrote), or resets one it writes
                let code = u64::from(c.u8());
                if a & 1 == 0 {
                    let mut ids: Vec<u64> = sim.known_client.iter().copied().collect();
                    ids.extend(sim.own_client.iter().copied().filter(|&id| is_bidirectional(id)));
                    if let Some(id) = pick(&ids, a >> 1) {
                        if sim.client.stream_stop_sending(id, code).is_ok() {
                            sim.book.broken.insert((false, id));
                        }
                    }
                } else {
                    let mut ids = sim.own_client.clone();
                    ids.extend(sim.known_client.iter().copied().filter(|&id| is_bidirectional(id)));
                    if let Some(id) = pick(&ids, a >> 1) {
                        if sim.client.stream_reset(id, code).is_ok() {
                            sim.book.broken.insert((true, id));
                        }
                    }
                }
            }
            8 => {
                if let Ok(id) = sim.server.streams.open(a & 1 == 0) {
                    sim.own_server.push(id);
                }
            }
            9 | 10 => {
                let mut ids = sim.own_server.clone();
                ids.extend(sim.known_server.iter().copied().filter(|&id| is_bidirectional(id)));
                if let Some(id) = pick(&ids, a) {
                    sim.write_on(false, id, n % 2500, a % 9 == 0);
                }
            }
            11 => {
                let ids: Vec<u64> = sim.known_server.iter().copied().collect();
                if let Some(id) = pick(&ids, a) {
                    let code = u64::from(c.u8());
                    if a & 1 == 0 {
                        if sim.server.streams.stop_sending(id, code).is_ok() {
                            sim.book.broken.insert((true, id));
                        }
                    } else if is_bidirectional(id) && sim.server.streams.reset(id, code).is_ok() {
                        sim.book.broken.insert((false, id));
                    }
                }
            }
            12 => {
                if !honest {
                    let len = (n % 90).min(c.0.len());
                    let (frames, rest) = c.0.split_at(len);
                    sim.server.queued.extend_from_slice(frames);
                    c.0 = rest;
                } else {
                    // the client says nothing for longer than the idle timeout (30 seconds, which the server asked for) while the server
                    // only pings now and then: hearing from the peer keeps a connection alive, and our own acknowledgments do not count
                    let step = Duration::from_secs(2 + u64::from(a) % 5);
                    for _ in 0..40 / step.as_secs() + 1 {
                        sim.server.queued.push(0x01);
                        sim.advance(step);
                        assert!(!sim.client.is_closing(), "the client ended the connection while the server kept talking: {:?}, {:?}", sim.client.state(), sim.closed);
                    }
                }
            }
            13 => sim.client.ping(),
            14 => {
                // (one update at a time: a second before the client has answered the first is not what a server does; nor is one
                // before the server has seen packets of the client's own last update, which `rx_updates` counted too: found when the
                // client began to update its keys itself, B-91)
                if sim.server.keys_agreed() {
                    sim.server.key_update();
                    sim.updates_begun += 1;
                }
            }
            _ => {
                if a % 16 == 0 {
                    sim.client.close(sim.now, u64::from(a), b"fuzz");
                    closed_by_us = true;
                } else if a % 16 == 1 {
                    // (refused unless the last update was answered and acknowledged)
                    sim.client.update_keys();
                } else {
                    sim.client.ping();
                }
            }
        }
        sim.flush();
        sim.service();
        // what must hold of the client whatever happened
        assert!(sim.client.congestion().window() >= 2 * 1200, "a congestion window of {} bytes", sim.client.congestion().window());
        assert_eq!(sim.client.bytes_in_flight(), sim.client.congestion().bytes_in_flight());
    }

    if honest && !closed_by_us {
        // every byte that was written, and every end, comes out
        let mut ok = false;
        for _ in 0..1200 {
            sim.read_everything();
            if sim.complete() {
                ok = true;
                break;
            }
            sim.advance(Duration::from_millis(100));
            assert!(!sim.client.is_closing(), "the client ended the connection: {:?}, {:?} (the server's streams said {:?}; at {:?}){}", sim.client.state(), sim.closed, sim.server.stream_error, sim.now - sim.start, sim.describe_incomplete());
        }
        assert!(ok, "after two minutes the data has not all come:{} (client {:?}, {} lost of {} sent)", sim.describe_incomplete(), sim.client.state(), sim.client.stats().packets_lost, sim.client.stats().packets_sent);
        assert!(sim.server.stream_error.is_none(), "the client broke a rule of streams: {:?}", sim.server.stream_error);
        assert!(sim.server.close_received.is_none(), "the client closed: {:?}", sim.server.close_received);

        // everything arrived, so the acknowledgments of it do (the loss that is left is bounded), and a stream that both sides have
        // finished with, written to its end, acknowledged and read to its end, is then forgotten (or the books of a connection that
        // lasts for days would grow with every request)
        let mut settled = false;
        for _ in 0..1200 {
            sim.read_everything();
            if sim.client.bytes_in_flight() == 0 && !sim.client.streams_have_pending() {
                settled = true;
                break;
            }
            sim.advance(Duration::from_millis(100));
            assert!(!sim.client.is_closing(), "the client ended the connection while it waited for the last acknowledgments: {:?}, {:?}", sim.client.state(), sim.closed);
        }
        assert!(settled, "everything arrived, but after two minutes the client still has {} bytes in flight (pending: {})", sim.client.bytes_in_flight(), sim.client.streams_have_pending());
        let live: BTreeSet<u64> = sim.client.stream_ids().into_iter().collect();
        let ids: BTreeSet<u64> = sim.book.written.keys().chain(sim.book.fin_written.iter()).map(|k| k.1).collect();
        for id in ids {
            let (sent, got) = ((true, id), (false, id));
            if sim.book.broken.contains(&sent) || sim.book.broken.contains(&got) {
                continue;
            }
            let client_opened = id & 1 == 0;
            let sending_done = (!client_opened && !is_bidirectional(id)) || sim.book.fin_written.contains(&sent);
            let receiving_done = (client_opened && !is_bidirectional(id)) || sim.book.fin_read.contains(&got);
            assert!(!(sending_done && receiving_done && live.contains(&id)), "stream {id} is finished both ways, and everything is acknowledged, but the client still keeps it ({})", sim.client.describe_stream(id));
        }
    }

    // and a connection with nothing to do ends: by the idle timeout (or at once if it was closed) and then it is quiet. (A hostile
    // server may have left itself unable to hear the client, with frames that move the client to connection ids it does not
    // know, and retransmit to it for ever, which keeps a connection alive as the RFC says it should: so it goes quiet here. Found
    // by the field run's fuzzing.)
    sim.server_muted = !honest;
    let mut ended = false;
    for _ in 0..2000 {
        if sim.client.is_closed() {
            ended = true;
            break;
        }
        if sim.client.is_closing() && sim.client.timeout().is_none() {
            break;
        }
        sim.advance(Duration::from_millis(500));
    }
    assert!(ended, "after the script the connection did not end in 1000 seconds: {:?}, timer {:?}", sim.client.state(), sim.client.timeout());
    assert!(sim.client.timeout().is_none(), "a closed connection with a timer");
    let mut buf = Vec::new();
    assert!(!sim.client.poll_transmit(sim.now, &mut buf), "a closed connection sends");
}
