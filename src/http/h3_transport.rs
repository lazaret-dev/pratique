//! The blocking client's HTTP/3 transport: one QUIC connection to an origin, shared by every request to it.
//!
//! The pieces below it do no I/O and read no clock: [`crate::quic::connection::Connection`] (packets, loss recovery, streams) and the
//! HTTP/3 connection of [`super::h3::connection`] (frames, QPACK, requests). This module is what gives them a UDP socket, a clock and
//! callers. A [`Shared`] connection is the socket, both state machines under one lock, and two threads: a *reader* that waits for
//! datagrams and feeds them in, and a *timer* that sleeps until the QUIC connection says it has to be woken (an acknowledgment that
//! is due, a probe timeout, the pacer, the idle timeout) and until the connection has been idle long enough to close. A caller that
//! has something to say (a request, some body, credit for what it has read) says it itself under the lock and sends the datagrams that
//! come of it from its own thread, so that a request does not wait for another thread to wake up to be sent; what the reader or the
//! timer does is the same ([`Shared::pump`]), and wakes the callers whose streams have news.
//!
//! A caller opens a stream ([`Shared::start`]), sends the request body as the connection takes it, waits for the head
//! ([`H3Stream::head`]) and reads the body ([`H3Stream::read`], or [`H3Stream::collect`] for all of it at once); dropping the
//! [`H3Stream`] gives the stream up (a response that was not read to its end is cancelled, which costs the connection nothing). Each
//! stream has a condition variable of its own, and a connection wakes the streams that have something to do (and only those), so that
//! a connection with a hundred streams does not wake a hundred threads for the news of one.
//!
//! The [`Registry`] holds a client's connections by origin, and what the client knows of how to reach an origin over QUIC: nothing is
//! tried unless the origin said, in an `Alt-Svc` field of a response, that it is there (or the client was told to assume it is), the
//! first request after that dials (a request that comes while the dial is going on goes the TCP way, unless the client assumes), and an
//! origin that could not be reached is left to TCP for five minutes, and for twice as long after each failure that follows, up to a
//! day, so that a network that drops UDP costs one handshake timeout and not one for every request.
//!
//! What a failed request tells the caller is what HTTP/2's does ([`Failure`]): whether it can be sent again whatever the method (the
//! server refused the stream, or said in GOAWAY that it had not got that far), and whether the connection was lost under it before any
//! answer (so that a request that may be repeated can be, once, if the connection was an old one).

use super::altsvc::{self, Alternative, Parsed};
use super::h2::connection::{Head, Request};
use super::h2_transport::{Failure, StartError, Waits};
use super::h3::connection::{Config as H3Config, Connection as H3Connection, OpenError, QuicTransport, StreamError, StreamEvent};
use super::h3::frame::code as h3_code;
use super::idle::Key;
use crate::error::Error;
use crate::quic::connection::{CloseReason, Config as QuicConfig, Connection as QuicConnection, Event};
use crate::tls::ClientConfig;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// The longest the reader thread waits for a datagram before it looks at whether the connection is over.
const READ_WAIT: Duration = Duration::from_millis(100);

/// The longest the timer thread sleeps without being told that something changed.
const TIMER_WAIT: Duration = Duration::from_secs(1);

/// How many times [`Shared::pump`] goes round when the HTTP/3 layer still has something to do (it always has an end; this is a bound on
/// the damage of a bug).
const PUMP_ROUNDS: usize = 16;

/// How long an origin that could not be reached over QUIC is left to TCP after the first failure; twice as long after each one that follows.
const BACKOFF_BASE: Duration = Duration::from_secs(300);
const BACKOFF_MAX: Duration = Duration::from_secs(24 * 3600);

/// The most connections a client has to one origin (more are not dialed: the requests go the TCP way).
const MAX_CONNECTIONS: usize = 8;

/// The most origins whose alternatives or failures are remembered.
const MAX_ORIGINS: usize = 1024;

/// How long the handshake of an alternative that an origin advertised is given at most (when the client was not told to assume it is
/// there): a path that drops UDP should cost a request this much and no more.
pub(super) const ALT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------------------------------- the connection

/// Why the connection ended, when it did not end because this endpoint closed it.
#[derive(Clone, Debug)]
struct Lost {
    /// The server closed it, or it timed out, or it was reset (as opposed to our finding it at fault).
    peer_closed: bool,
    why: String,
}

/// What a stream's waiter is waiting for.
const WANT_NOTHING: u8 = 0;
const WANT_NEWS: u8 = 1;
const WANT_ROOM: u8 = 2;

/// A stream's condition variable, and what its waiter (there is one at most) waits for.
struct Slot {
    cv: Condvar,
    want: AtomicU8,
}

struct State {
    quic: QuicConnection,
    h3: H3Connection,
    /// Datagrams are made here.
    out: Vec<u8>,
    lost: Option<Lost>,
    /// We closed it (the client was dropped, it had been idle, or the server said to go away and nothing was left).
    retired: bool,
    /// No more requests are started on it (the origin took back what it had said about QUIC): it is closed when the ones in flight are done.
    draining: bool,
    /// How many [`H3Stream`]s there are, and when the last one went.
    open: usize,
    last_used: Instant,
    slots: HashMap<u64, Arc<Slot>>,
    /// The moment the timer thread is waiting for: something that makes the connection need to be woken earlier wakes it.
    timer_at: Option<Instant>,
}

/// One QUIC connection and the threads that run it (see the top of the file).
pub(super) struct Shared {
    state: Mutex<State>,
    timer: Condvar,
    socket: UdpSocket,
    idle_timeout: Duration,
    /// Set when the connection is over: the threads end when they see it.
    done: AtomicBool,
}

/// What a registry sees of a connection.
pub(super) enum Probe {
    /// Lost or closed: forget it.
    Dead,
    /// Cannot take another stream now (the server's limit, or it said to go away).
    Full,
    /// Can; this many streams are in flight.
    Open(usize),
}

/// What dialing needs to know.
pub(super) struct DialOptions {
    /// How long the handshake may take (in all, over every address tried).
    pub(super) handshake_timeout: Duration,
    /// Closes the connection when no request has used it for this long.
    pub(super) idle_timeout: Duration,
    /// When the whole request must be finished.
    pub(super) deadline: Option<Instant>,
    /// The client's resolver (see `http::connect`).
    pub(super) resolver: Arc<super::connect::Resolver>,
}

/// Makes a QUIC connection to `host:port` that is authenticated as `server_name` (the origin: an alternative service has to be
/// authoritative for it), and starts its threads.
pub(super) fn dial(host: &str, port: u16, server_name: &str, tls: &ClientConfig, opts: DialOptions) -> Result<Arc<Shared>, Error> {
    let now = Instant::now();
    let mut limit = now.checked_add(opts.handshake_timeout).unwrap_or(now + Duration::from_secs(3600));
    if let Some(d) = opts.deadline {
        limit = limit.min(d);
    }
    // the client's resolver (its cache, and its order: the address that last connected over TCP first, the families
    // interleaved), within the time of the handshake
    let addrs: Vec<SocketAddr> = opts.resolver.resolve(host, limit)?.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
    if addrs.is_empty() {
        return Err(Error::Http(format!("no address for {host}")));
    }
    let mut last: Option<Error> = None;
    for (i, addr) in addrs.iter().enumerate() {
        let left = limit.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        // (an address that does not answer is not given all the time there is when another may)
        let until = Instant::now() + if i + 1 < addrs.len() { left / 2 } else { left };
        match handshake(*addr, server_name, tls, until) {
            Ok((socket, quic)) => return Shared::start_threads(socket, quic, opts.idle_timeout),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::Io(io::Error::new(io::ErrorKind::TimedOut, "timed out making a QUIC connection"))))
}

/// The handshake with one address, on a socket of its own, up to the moment the 1-RTT keys are in (the requests can go from then on).
fn handshake(addr: SocketAddr, server_name: &str, tls: &ClientConfig, until: Instant) -> Result<(UdpSocket, QuicConnection), Error> {
    let socket = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
    socket.connect(addr)?;
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut quic = QuicConnection::connect(&QuicConfig::default(), &tls, server_name, Instant::now())?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let now = Instant::now();
        while quic.poll_transmit(now, &mut out) {
            // (a send that fails at this stage is a network that has no route to the server: there is no use in waiting)
            socket.send(&out)?;
        }
        while let Some(ev) = quic.poll_event() {
            match ev {
                Event::Established => {
                    if quic.alpn() != Some(b"h3") {
                        return Err(Error::Http("the server did not choose HTTP/3 in the QUIC handshake".into()));
                    }
                    return Ok((socket, quic));
                }
                Event::Closed(reason) => return Err(Error::Http(format!("the QUIC handshake failed: {}", describe_close(&reason)))),
                Event::Confirmed => {}
            }
        }
        if now >= until {
            return Err(Error::Io(io::Error::new(io::ErrorKind::TimedOut, "timed out in the QUIC handshake")));
        }
        let wake = quic.timeout().map_or(until, |t| t.min(until));
        socket.set_read_timeout(Some(wake.saturating_duration_since(now).max(Duration::from_millis(1))))?;
        match socket.recv(&mut buf) {
            Ok(n) => quic.recv(Instant::now(), &mut buf[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            // an ICMP "port unreachable" comes back as this: nothing listens
            Err(e) => return Err(Error::Io(e)),
        }
        if quic.timeout().is_some_and(|t| t <= Instant::now()) {
            quic.on_timeout(Instant::now());
        }
    }
}

fn describe_close(reason: &CloseReason) -> String {
    match reason {
        CloseReason::Local(e) => e.to_string(),
        CloseReason::Application { code, .. } => format!("closed by us with application error {code:#x}"),
        CloseReason::PeerTransport { code, reason, .. } => format!("the server closed the connection with transport error {code:#x} ({})", String::from_utf8_lossy(reason)),
        CloseReason::PeerApplication { code, reason } => format!("the server closed the connection with application error {code:#x} ({})", String::from_utf8_lossy(reason)),
        CloseReason::IdleTimeout => "the connection timed out".into(),
        CloseReason::StatelessReset => "the server has no state for the connection (a stateless reset)".into(),
        CloseReason::VersionNegotiation(v) => format!("the server does not speak QUIC version 1 (it listed {v:x?})"),
    }
}

impl Shared {
    fn start_threads(socket: UdpSocket, quic: QuicConnection, idle_timeout: Duration) -> Result<Arc<Shared>, Error> {
        let state = State {
            quic,
            h3: H3Connection::new(H3Config::default()),
            out: Vec::new(),
            lost: None,
            retired: false,
            draining: false,
            open: 0,
            last_used: Instant::now(),
            slots: HashMap::new(),
            timer_at: None,
        };
        let shared = Arc::new(Shared { state: Mutex::new(state), timer: Condvar::new(), socket, idle_timeout, done: AtomicBool::new(false) });
        shared.socket.set_read_timeout(Some(READ_WAIT))?;
        {
            // (the HTTP/3 layer opens its three streams and says its SETTINGS)
            let mut g = shared.lock();
            shared.pump(&mut g);
        }
        let reader = shared.clone();
        thread::Builder::new().name("pratique-h3-read".into()).spawn(move || reader.read_loop())?;
        let timer = shared.clone();
        if let Err(e) = thread::Builder::new().name("pratique-h3-timer".into()).spawn(move || timer.timer_loop()) {
            shared.retire();
            return Err(e.into());
        }
        Ok(shared)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -------------------------------------------------------------------------------------------- running it

    /// Runs the connection as far as it goes: the HTTP/3 layer takes in what the transport has and writes what is due, the datagrams that
    /// are due are sent, what the QUIC connection reports is taken in, and the streams that have news (and the timer, if its moment is
    /// now earlier) are woken. Every thread that has changed something calls it before it lets go of the lock.
    fn pump(&self, g: &mut State) {
        for _ in 0..PUMP_ROUNDS {
            let now = Instant::now();
            if g.lost.is_none() {
                let State { h3, quic, .. } = &mut *g;
                // (the error of a lost connection is in `h3.error()`, and in what the streams say)
                let _ = h3.process(&mut QuicTransport { conn: quic, now });
            }
            self.transmit(g, now);
            self.take_events(g);
            if g.lost.is_some() || !g.h3.needs_processing() {
                break;
            }
        }
        self.wake(g);
        if g.lost.is_none() {
            if let Some(t) = g.quic.timeout() {
                if g.timer_at.is_none_or(|at| t < at) {
                    g.timer_at = Some(t);
                    self.timer.notify_one();
                }
            }
        }
    }

    /// Sends the datagrams that are due.
    fn transmit(&self, g: &mut State, now: Instant) {
        let State { quic, out, lost, .. } = &mut *g;
        // one switch to data-independent timing for the whole flight (B-104); the sends in between do not mind it
        let _dit = crate::crypto::dit::Dit::on();
        while quic.poll_transmit(now, out) {
            if let Err(e) = self.socket.send(out) {
                // A send that fails once the connection is up is a datagram that is lost, which the connection deals with as it does
                // any other; but one that says there is no route is a connection that is not going to come back.
                if lost.is_none() && matches!(e.kind(), io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkDown | io::ErrorKind::PermissionDenied) {
                    *lost = Some(Lost { peer_closed: true, why: format!("sending failed: {e}") });
                    break;
                }
            }
        }
    }

    /// What the QUIC connection says happened to it.
    fn take_events(&self, g: &mut State) {
        while let Some(ev) = g.quic.poll_event() {
            if let Event::Closed(reason) = ev {
                let peer_closed = matches!(reason, CloseReason::PeerApplication { .. } | CloseReason::PeerTransport { .. } | CloseReason::StatelessReset | CloseReason::IdleTimeout);
                if g.lost.is_none() {
                    g.lost = Some(Lost { peer_closed, why: describe_close(&reason) });
                }
            }
        }
        if let Some(lost) = &g.lost {
            // (every stream that is not complete fails, and what is waiting hears of it)
            let code = if lost.peer_closed { h3_code::H3_NO_ERROR } else { h3_code::H3_INTERNAL_ERROR };
            let why = lost.why.clone();
            g.h3.transport_closed(code, &why);
            self.done.store(true, Ordering::Release);
            self.timer.notify_all();
        }
    }

    /// Wakes the streams whose waiters have something to do, and all of them if the connection is lost.
    fn wake(&self, g: &State) {
        for (id, slot) in &g.slots {
            let want = slot.want.load(Ordering::Relaxed);
            if want == WANT_NOTHING {
                continue;
            }
            let go = g.lost.is_some() || (want == WANT_NEWS && g.h3.ready(*id)) || (want == WANT_ROOM && g.h3.writable(*id));
            if go {
                slot.cv.notify_one();
            }
        }
    }

    /// Waits on a stream's condition variable until `until` (or until it is woken): the lock comes back, or `Err` if the time is up.
    fn wait<'a>(&'a self, g: MutexGuard<'a, State>, slot: &Slot, want: u8, until: Instant) -> Result<MutexGuard<'a, State>, ()> {
        let now = Instant::now();
        if now >= until {
            return Err(());
        }
        slot.want.store(want, Ordering::Relaxed);
        let (g, _) = slot.cv.wait_timeout(g, until - now).unwrap_or_else(|e| e.into_inner());
        slot.want.store(WANT_NOTHING, Ordering::Relaxed);
        Ok(g)
    }

    // -------------------------------------------------------------------------------------------- the threads

    /// Reads datagrams and feeds them in.
    fn read_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        let mut errors = 0u32;
        while !self.done.load(Ordering::Acquire) {
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    errors = 0;
                    let mut g = self.lock();
                    if g.lost.is_some() {
                        return;
                    }
                    g.quic.recv(Instant::now(), &mut buf[..n]);
                    self.pump(&mut g);
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(e) => {
                    // an ICMP error for a datagram that was sent comes back on a connected socket: before the handshake is over it is the
                    // end of the connection (the dial hears of it itself), after it it is ignored (RFC 9000 section 14.5 says to)
                    errors += 1;
                    if errors > 100 {
                        let mut g = self.lock();
                        if g.lost.is_none() {
                            g.lost = Some(Lost { peer_closed: true, why: format!("the socket failed: {e}") });
                        }
                        self.take_events(&mut g);
                        self.wake(&g);
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    /// Sleeps until the QUIC connection has to be woken, or the connection has been idle for long enough.
    fn timer_loop(self: Arc<Self>) {
        let mut g = self.lock();
        loop {
            if self.done.load(Ordering::Acquire) || g.lost.is_some() {
                return;
            }
            let now = Instant::now();
            let idle_at = (g.open == 0 && !g.retired).then(|| g.last_used + self.idle_timeout);
            if idle_at.is_some_and(|t| now >= t) {
                self.close_locked(&mut g);
                return;
            }
            let quic_at = g.quic.timeout();
            if quic_at.is_some_and(|t| t <= now) {
                g.quic.on_timeout(now);
                self.pump(&mut g);
                continue;
            }
            let next = match (quic_at, idle_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            g.timer_at = next;
            let wait = next.map_or(TIMER_WAIT, |t| t.saturating_duration_since(now)).min(TIMER_WAIT);
            g = self.timer.wait_timeout(g, wait).unwrap_or_else(|e| e.into_inner()).0;
            g.timer_at = None;
        }
    }

    // -------------------------------------------------------------------------------------------- the registry's questions

    pub(super) fn probe(&self) -> Probe {
        let mut g = self.lock();
        if g.lost.is_some() || g.retired {
            return Probe::Dead;
        }
        if g.draining || !g.h3.usable() {
            // the server said to go away (or the origin took its alternative back): what is in flight finishes, and the connection goes when it has
            if g.open == 0 {
                self.close_locked(&mut g);
                return Probe::Dead;
            }
            return Probe::Full;
        }
        if !g.quic.can_open_stream(true) {
            return Probe::Full;
        }
        Probe::Open(g.open)
    }

    pub(super) fn is_alive(&self) -> bool {
        let g = self.lock();
        g.lost.is_none() && !g.retired
    }

    pub(super) fn is_idle(&self) -> bool {
        let g = self.lock();
        g.lost.is_none() && !g.retired && g.open == 0
    }

    /// Starts no more requests on the connection, and closes it when the ones in flight are done.
    fn drain(&self) {
        let mut g = self.lock();
        g.draining = true;
        if g.open == 0 {
            self.close_locked(&mut g);
        }
    }

    /// Closes the connection if no request is using it.
    pub(super) fn close_if_idle(&self) {
        let mut g = self.lock();
        if g.open == 0 {
            self.close_locked(&mut g);
        }
    }

    /// The client that owned the connection is gone: it closes when its streams are done (a response that is being read goes on being read).
    pub(super) fn retire(&self) {
        self.drain();
    }

    fn close_locked(&self, g: &mut State) {
        if g.retired || g.lost.is_some() {
            return;
        }
        g.retired = true;
        let now = Instant::now();
        let State { h3, quic, .. } = &mut *g;
        h3.close(&mut QuicTransport { conn: quic, now });
        self.transmit(g, now);
        if g.lost.is_none() {
            g.lost = Some(Lost { peer_closed: false, why: "the connection was closed by the client".into() });
        }
        self.take_events(g);
        self.wake(g);
    }

    // -------------------------------------------------------------------------------------------- requests

    /// Opens a stream for a request and sends its body (as the connection takes it). The head of the response is asked of the stream.
    pub(super) fn start(self: &Arc<Self>, request: &Request<'_>, body: &[u8], waits: Waits) -> Result<H3Stream, StartError> {
        let (id, slot) = {
            let mut g = self.lock();
            if g.lost.is_some() || g.retired {
                return Err(StartError::Unavailable);
            }
            let now = Instant::now();
            let id = {
                let State { h3, quic, .. } = &mut *g;
                match h3.open_stream(&mut QuicTransport { conn: quic, now }, request, body.is_empty()) {
                    Ok(id) => id,
                    Err(OpenError::Full) => return Err(StartError::Full),
                    Err(OpenError::Unavailable) => return Err(StartError::Unavailable),
                    Err(OpenError::Invalid(why)) => return Err(StartError::Failed(Failure { error: Error::Http(why), retry_safe: false, peer_closed: false })),
                }
            };
            let slot = Arc::new(Slot { cv: Condvar::new(), want: AtomicU8::new(WANT_NOTHING) });
            g.slots.insert(id, slot.clone());
            g.open += 1;
            // (while a request is in flight the connection does not go idle, however long the server takes: B-91)
            g.quic.set_keep_alive(true);
            self.pump(&mut g);
            (id, slot)
        };
        // (from here on the stream gives itself up when it is dropped)
        let mut stream = H3Stream { shared: self.clone(), id, slot, got_head: false, finished: false };
        if let Err(f) = stream.send_body(body, waits) {
            return Err(StartError::Failed(f));
        }
        Ok(stream)
    }

    /// What a stream's failure is, for the caller: if the server did not act on the request, that; if the connection was lost before an
    /// answer, that too.
    fn failure(g: &State, e: &StreamError, got_head: bool) -> Failure {
        let peer_closed = g.lost.as_ref().is_some_and(|l| l.peer_closed) && !got_head;
        let error = if peer_closed { Error::Io(io::Error::new(io::ErrorKind::ConnectionReset, e.reason.clone())) } else { Error::Http(e.to_string()) };
        Failure { error, retry_safe: e.retry_safe, peer_closed }
    }
}

// ---------------------------------------------------------------------------------------------------- a stream

/// One request's stream on a shared connection.
pub(super) struct H3Stream {
    shared: Arc<Shared>,
    id: u64,
    slot: Arc<Slot>,
    got_head: bool,
    /// The response has been read to its end.
    finished: bool,
}

impl H3Stream {
    /// Sends what is left of the request: the body, as the connection takes it, and the end of the request.
    fn send_body(&mut self, body: &[u8], waits: Waits) -> Result<(), Failure> {
        let shared = self.shared.clone();
        let mut sent = 0;
        let mut until = waits.until();
        let mut g = shared.lock();
        while sent < body.len() {
            let now = Instant::now();
            let taken = {
                let State { h3, quic, .. } = &mut *g;
                h3.send_data(&mut QuicTransport { conn: quic, now }, self.id, &body[sent..], true)
            };
            match taken {
                Ok(n) => {
                    sent += n;
                    shared.pump(&mut g);
                    if n > 0 {
                        until = waits.until();
                    } else {
                        g = match shared.wait(g, &self.slot, WANT_ROOM, until) {
                            Ok(g) => g,
                            Err(()) => return Err(Failure { error: waits.expired_in("HTTP/3"), retry_safe: false, peer_closed: false }),
                        };
                    }
                }
                Err(e) => return Err(Shared::failure(&g, &e, false)),
            }
        }
        Ok(())
    }

    /// Waits for the head of the response (the interim ones are dropped).
    pub(super) fn head(&mut self, waits: Waits) -> Result<Head, Failure> {
        let shared = self.shared.clone();
        let until = waits.until();
        let mut g = shared.lock();
        loop {
            match g.h3.poll_stream(self.id, &mut []) {
                StreamEvent::Head(h) => {
                    self.got_head = true;
                    return Ok(h);
                }
                StreamEvent::Failed(e) => return Err(Shared::failure(&g, &e, false)),
                _ => {}
            }
            g = match shared.wait(g, &self.slot, WANT_NEWS, until) {
                Ok(g) => g,
                Err(()) => return Err(Failure { error: waits.expired_in("HTTP/3"), retry_safe: false, peer_closed: false }),
            };
        }
    }

    /// Reads body into `out`: how many bytes, and 0 at the end of the response.
    pub(super) fn read(&mut self, out: &mut [u8], waits: Waits) -> Result<usize, Failure> {
        if self.finished || out.is_empty() {
            return Ok(0);
        }
        let shared = self.shared.clone();
        let until = waits.until();
        let mut g = shared.lock();
        loop {
            match g.h3.poll_stream(self.id, out) {
                StreamEvent::Data(n) => {
                    // (what was taken makes room: the HTTP/3 layer reads on, and the transport tells the server it may send more)
                    shared.pump(&mut g);
                    return Ok(n);
                }
                StreamEvent::End => {
                    self.finished = true;
                    return Ok(0);
                }
                StreamEvent::Failed(e) => return Err(Shared::failure(&g, &e, self.got_head)),
                // (trailers are dropped, as over HTTP/2)
                StreamEvent::Trailers(_) | StreamEvent::Head(_) => continue,
                StreamEvent::Pending => {}
            }
            g = match shared.wait(g, &self.slot, WANT_NEWS, until) {
                Ok(g) => g,
                Err(()) => return Err(Failure { error: waits.expired_in("HTTP/3"), retry_safe: false, peer_closed: false }),
            };
        }
    }

    /// The rest of the body as one buffer, up to `limit` bytes.
    pub(super) fn collect(&mut self, limit: u64, waits: Waits) -> Result<Vec<u8>, Failure> {
        let mut body: Vec<u8> = Vec::new();
        if self.finished {
            return Ok(body);
        }
        let shared = self.shared.clone();
        let mut piece: Vec<u8> = Vec::new();
        let mut until = waits.until();
        let mut g = shared.lock();
        loop {
            match g.h3.take_stream_data(self.id, &mut piece) {
                StreamEvent::Data(_) => {
                    if body.is_empty() {
                        std::mem::swap(&mut body, &mut piece);
                    } else {
                        body.extend_from_slice(&piece);
                    }
                    if body.len() as u64 > limit {
                        return Err(Failure { error: Error::Http("response body exceeds the configured size limit".into()), retry_safe: false, peer_closed: false });
                    }
                    shared.pump(&mut g);
                    until = waits.until();
                    continue;
                }
                StreamEvent::End => {
                    self.finished = true;
                    return Ok(body);
                }
                StreamEvent::Failed(e) => return Err(Shared::failure(&g, &e, self.got_head)),
                StreamEvent::Trailers(_) | StreamEvent::Head(_) => continue,
                StreamEvent::Pending => {}
            }
            g = match shared.wait(g, &self.slot, WANT_NEWS, until) {
                Ok(g) => g,
                Err(()) => return Err(Failure { error: waits.expired_in("HTTP/3"), retry_safe: false, peer_closed: false }),
            };
        }
    }
}

impl Drop for H3Stream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        let now = Instant::now();
        {
            let State { h3, quic, .. } = &mut *g;
            h3.release_stream(&mut QuicTransport { conn: quic, now }, self.id);
        }
        g.slots.remove(&self.id);
        g.open = g.open.saturating_sub(1);
        if g.open == 0 {
            g.quic.set_keep_alive(false);
        }
        g.last_used = now;
        self.shared.pump(&mut g);
        if g.open == 0 {
            if g.draining {
                self.shared.close_locked(&mut g);
            } else {
                // (the idle time starts now)
                self.shared.timer.notify_one();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------- registry

/// What a request finds when it asks for a connection to an origin.
pub(super) enum Acquired {
    /// A live connection with room for another stream.
    Conn(Arc<Shared>),
    /// There is none: the caller dials the host and port, and tells the registry how it went through the ticket.
    Dial(Ticket, String, u16),
    /// Not over QUIC: use TCP.
    Skip,
}

/// What is known of an origin's alternative.
struct Known {
    alt: Alternative,
    expires: Instant,
}

/// An origin that could not be reached.
struct Backoff {
    until: Instant,
    failures: u32,
}

#[derive(Default)]
struct Origin {
    conns: Vec<Arc<Shared>>,
    dialing: bool,
    alt: Option<Known>,
    backoff: Option<Backoff>,
}

/// A client's HTTP/3 connections and what it knows of how to reach origins over QUIC.
pub(super) struct Registry {
    origins: Mutex<HashMap<Key, Origin>>,
    changed: Condvar,
}

impl Registry {
    pub(super) fn new() -> Registry {
        Registry { origins: Mutex::new(HashMap::new()), changed: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Key, Origin>> {
        self.origins.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Notes what a response from `key` said in its `Alt-Svc` fields (only the first alternative for HTTP/3 counts). A response over a
    /// connection that was not authenticated must not be believed: the caller says only what came over TLS or QUIC.
    pub(super) fn learn<'a>(&self, key: &Key, values: impl Iterator<Item = &'a str>, host_allowed: &dyn Fn(&str, u16) -> bool) {
        let (mut found, mut clear) = (None, false);
        for v in values {
            match altsvc::parse(v) {
                Parsed::Clear => clear = true,
                // (an alternative at another host is a place to send requests to: the client's rule has a say)
                Parsed::H3(Some(a)) if found.is_none() && host_allowed(a.host.as_deref().unwrap_or(&key.host), a.port) => found = Some(a),
                Parsed::H3(_) => {}
            }
        }
        if found.is_none() && !clear {
            return;
        }
        let mut map = self.lock();
        if map.len() >= MAX_ORIGINS && !map.contains_key(key) {
            let now = Instant::now();
            map.retain(|_, o| !o.conns.is_empty() || o.dialing || o.backoff.as_ref().is_some_and(|b| b.until > now));
            if map.len() >= MAX_ORIGINS {
                return;
            }
        }
        let origin = map.entry(key.clone()).or_default();
        match found {
            Some(alt) if !alt.max_age.is_zero() => {
                let expires = Instant::now().checked_add(alt.max_age).unwrap_or_else(|| Instant::now() + Duration::from_secs(30 * 24 * 3600));
                origin.alt = Some(Known { alt, expires });
                // (a newer word from the origin ends the time that its own `clear` set; a failure's time it does not)
                if origin.backoff.as_ref().is_some_and(|b| b.failures == 0) {
                    origin.backoff = None;
                }
            }
            // (`ma=0` takes the alternative back, as `clear` does: nothing new goes over QUIC, not even to a client that assumes it
            // is there, until the time of a failure has gone by)
            _ => {
                origin.alt = None;
                for c in &origin.conns {
                    c.drain();
                }
                if origin.backoff.is_none() {
                    origin.backoff = Some(Backoff { until: Instant::now() + BACKOFF_BASE, failures: 0 });
                }
            }
        }
    }

    /// A connection to `key` that can take a request, or the duty to dial one, or the news that this origin is not to be reached over QUIC
    /// now. `assume`: the client tries QUIC for an origin it has heard nothing about, and a request that comes while another dials waits for
    /// it (up to `wait`, or the request's deadline); without it only an origin that said it is there is tried, and a request that comes
    /// while another dials goes the TCP way at once.
    pub(super) fn acquire(self: &Arc<Self>, key: &Key, host: &str, port: u16, assume: bool, waits: Waits, wait: Duration) -> Acquired {
        let give_up = {
            let now = Instant::now();
            let by_wait = now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(3600));
            waits.deadline.map_or(by_wait, |d| by_wait.min(d))
        };
        let mut map = self.lock();
        loop {
            let now = Instant::now();
            let Some(origin) = map.get_mut(key).or(None) else {
                if !assume {
                    return Acquired::Skip;
                }
                map.insert(key.clone(), Origin::default());
                continue;
            };
            if origin.alt.as_ref().is_some_and(|k| now >= k.expires) {
                origin.alt = None;
            }
            // the least loaded of those that can take a stream
            let mut best: Option<(usize, Arc<Shared>)> = None;
            let mut dead = false;
            for c in &origin.conns {
                match c.probe() {
                    Probe::Dead => dead = true,
                    Probe::Full => {}
                    Probe::Open(load) => {
                        if best.as_ref().is_none_or(|(l, _)| load < *l) {
                            best = Some((load, c.clone()));
                        }
                    }
                }
            }
            if dead {
                origin.conns.retain(|c| c.is_alive());
            }
            if let Some((_, c)) = best {
                return Acquired::Conn(c);
            }
            let target = match (&origin.alt, assume) {
                (Some(k), _) => (k.alt.host.clone().unwrap_or_else(|| host.to_string()), k.alt.port),
                (None, true) => (host.to_string(), port),
                (None, false) => return Acquired::Skip,
            };
            if origin.backoff.as_ref().is_some_and(|b| now < b.until) || origin.conns.len() >= MAX_CONNECTIONS {
                return Acquired::Skip;
            }
            if !origin.dialing {
                origin.dialing = true;
                return Acquired::Dial(Ticket { registry: self.clone(), key: key.clone(), settled: false }, target.0, target.1);
            }
            if !assume || now >= give_up {
                return Acquired::Skip;
            }
            map = self.changed.wait_timeout(map, give_up - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// A connection that was made turned out not to work (it was lost before it carried an answer): the origin is left to TCP for a while,
    /// as if the dial had failed.
    pub(super) fn broken(&self, key: &Key) {
        let mut map = self.lock();
        let origin = map.entry(key.clone()).or_default();
        let failures = origin.backoff.as_ref().map_or(0, |b| b.failures).saturating_add(1);
        origin.backoff = Some(Backoff { until: Instant::now() + backoff_for(failures), failures });
    }

    /// Closes the connections that have no stream in flight.
    pub(super) fn close_idle(&self) {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        for c in conns {
            c.close_if_idle();
        }
    }

    /// How many connections have no stream in flight.
    pub(super) fn idle(&self) -> usize {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        conns.iter().filter(|c| c.is_idle()).count()
    }

    /// Whether the origin is left to TCP for now, and the alternative it has (tests).
    #[cfg(test)]
    pub(super) fn standing(&self, key: &Key) -> (bool, Option<Alternative>) {
        let map = self.lock();
        match map.get(key) {
            Some(o) => (o.backoff.as_ref().is_some_and(|b| Instant::now() < b.until), o.alt.as_ref().map(|k| k.alt.clone())),
            None => (false, None),
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let origins = std::mem::take(&mut *self.origins.lock().unwrap_or_else(|e| e.into_inner()));
        for origin in origins.into_values() {
            for c in origin.conns {
                c.retire();
            }
        }
    }
}

/// How long an origin is left to TCP after this many failures in a row.
fn backoff_for(failures: u32) -> Duration {
    BACKOFF_BASE.checked_mul(1u32 << failures.saturating_sub(1).min(20)).unwrap_or(BACKOFF_MAX).min(BACKOFF_MAX)
}

/// The duty to dial a connection to an origin, held by the request that has been told to. Requests to the origin that assume QUIC
/// wait for it to be settled.
pub(super) struct Ticket {
    registry: Arc<Registry>,
    key: Key,
    settled: bool,
}

impl Ticket {
    /// The dial gave a connection: it is shared from now on.
    pub(super) fn connected(mut self, conn: Arc<Shared>) {
        self.settled = true;
        {
            let mut map = self.registry.lock();
            let origin = map.entry(self.key.clone()).or_default();
            origin.conns.push(conn);
            origin.dialing = false;
            origin.backoff = None;
        }
        self.registry.changed.notify_all();
    }

    /// The origin could not be reached: it is left to TCP for a while (longer each time that it happens again).
    pub(super) fn failed(mut self) {
        self.settled = true;
        {
            let mut map = self.registry.lock();
            let origin = map.entry(self.key.clone()).or_default();
            origin.dialing = false;
            let failures = origin.backoff.as_ref().map_or(0, |b| b.failures).saturating_add(1);
            origin.backoff = Some(Backoff { until: Instant::now() + backoff_for(failures), failures });
        }
        self.registry.changed.notify_all();
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.settled {
            // the dial was given up on (an error that is not the origin's): whoever waits may try for themselves
            {
                let mut map = self.registry.lock();
                if let Some(origin) = map.get_mut(&self.key) {
                    origin.dialing = false;
                }
            }
            self.registry.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    //! The registry's rules, with no connection (the transport against servers is in `tests/h3_client_interop.rs`).
    use super::*;

    fn key() -> Key {
        Key { tls: true, host: "example.com".into(), port: 443, proxy: None, min_tls: crate::tls::TlsVersion::Tls12 }
    }

    fn waits() -> Waits {
        Waits { timeout: Duration::from_secs(5), deadline: None }
    }

    fn alt(port: u16, secs: u64) -> Alternative {
        Alternative { host: None, port, max_age: Duration::from_secs(secs) }
    }

    #[test]
    fn an_origin_nobody_has_spoken_of_is_left_to_tcp() {
        let r = Arc::new(Registry::new());
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
    }

    #[test]
    fn an_alternative_that_was_advertised_is_dialed_once_at_a_time() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":8443"; ma=60"#].into_iter(), &|_, _| true);
        let first = r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1));
        match &first {
            Acquired::Dial(_, host, port) => assert_eq!((host.as_str(), *port), ("example.com", 8443)),
            _ => panic!("the first request has to dial"),
        }
        // the second does not wait for it: TCP now
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
        // and when the dial is dropped without a word another may try
        drop(first);
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Dial(..)));
    }

    #[test]
    fn an_alternative_on_another_host_is_dialed_there() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3="alt.example.net:4433""#].into_iter(), &|_, _| true);
        match r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)) {
            Acquired::Dial(_, host, port) => assert_eq!((host.as_str(), port), ("alt.example.net", 4433)),
            _ => panic!("dial"),
        }
    }

    #[test]
    fn what_was_advertised_can_be_taken_back_or_run_out() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":443"; ma=60"#].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, Some(alt(443, 60)));
        r.learn(&key(), ["clear"].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, None);
        r.learn(&key(), [r#"h3=":443"; ma=60"#].into_iter(), &|_, _| true);
        r.learn(&key(), [r#"h3=":443"; ma=0"#].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, None);
        // a field that says nothing about HTTP/3 changes nothing
        r.learn(&key(), [r#"h3=":443"; ma=60"#].into_iter(), &|_, _| true);
        r.learn(&key(), [r#"h2=":443""#, "nonsense"].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, Some(alt(443, 60)));
        // the first alternative of the fields is the one; `clear` in a field of its own clears what the others did not replace
        r.learn(&key(), [r#"h3=":1""#, r#"h3=":2""#].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, Some(alt(1, altsvc::DEFAULT_MAX_AGE)));
        r.learn(&key(), ["clear"].into_iter(), &|_, _| true);
        assert_eq!(r.standing(&key()).1, None);
        // (a lifetime that has run out is not believed)
        r.learn(&key(), [r#"h3=":443"; ma=1"#].into_iter(), &|_, _| true);
        r.lock().get_mut(&key()).unwrap().alt.as_mut().unwrap().expires = Instant::now() - Duration::from_millis(1);
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
        assert_eq!(r.standing(&key()).1, None);
    }

    #[test]
    fn an_origin_that_could_not_be_reached_is_left_to_tcp_for_longer_each_time() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":443""#].into_iter(), &|_, _| true);
        let mut waited = vec![];
        for _ in 0..4 {
            // (let the last backoff run out)
            r.lock().get_mut(&key()).unwrap().backoff.as_mut().map(|b| b.until = Instant::now() - Duration::from_millis(1));
            let Acquired::Dial(ticket, ..) = r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)) else { panic!("dial") };
            ticket.failed();
            assert!(r.standing(&key()).0);
            assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
            let b = r.lock();
            let o = b.get(&key()).unwrap().backoff.as_ref().unwrap();
            waited.push((o.failures, o.until.saturating_duration_since(Instant::now()).as_secs()));
        }
        assert_eq!(waited.iter().map(|w| w.0).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        // 5 minutes, 10, 20, 40 (a second less each, for the time that has gone)
        for (w, want) in waited.iter().zip([300u64, 600, 1200, 2400]) {
            assert!(w.1 <= want && w.1 + 3 >= want, "{w:?} for {want}");
        }
    }

    #[test]
    fn an_alternative_at_a_host_the_clients_rule_does_not_allow_is_not_learned() {
        let r = Arc::new(Registry::new());
        let only_example = |host: &str, _port: u16| host == "alt.example.net" || host == "example.com";
        // another host that the rule does not name: not used (the origin's own host, which the rule let the request go to, is)
        r.learn(&key(), [r#"h3="evil.example.org:443""#].into_iter(), &only_example);
        assert_eq!(r.standing(&key()).1, None);
        // (the next field's alternative is looked at: the first one that is allowed is the one)
        r.learn(&key(), [r#"h3="evil.example.org:443""#, r#"h3=":8443""#].into_iter(), &only_example);
        assert_eq!(r.standing(&key()).1, Some(alt(8443, altsvc::DEFAULT_MAX_AGE)));
        r.learn(&key(), [r#"h3="alt.example.net:4433""#].into_iter(), &only_example);
        assert_eq!(r.standing(&key()).1.unwrap().host.as_deref(), Some("alt.example.net"));
    }

    #[test]
    fn an_alternative_at_a_port_the_clients_rule_does_not_allow_is_not_learned() {
        let r = Arc::new(Registry::new());
        // a rule that lets the origin's own host through on the default port only: an alternative at the same host on another port is
        // another place to send requests to, and is not used (with no host of its own it is the origin's host, and the port counts)
        let default_port_only = |host: &str, port: u16| host == "example.com" && port == 443;
        r.learn(&key(), [r#"h3=":8443""#].into_iter(), &default_port_only);
        assert_eq!(r.standing(&key()).1, None);
        r.learn(&key(), [r#"h3="example.com:8443""#, r#"h3=":443""#].into_iter(), &default_port_only);
        assert_eq!(r.standing(&key()).1, Some(alt(443, altsvc::DEFAULT_MAX_AGE)));
    }

    #[test]
    fn a_connection_that_did_not_work_leaves_the_origin_to_tcp() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":443"; ma=3600"#].into_iter(), &|_, _| true);
        r.broken(&key());
        assert!(r.standing(&key()).0);
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
        // (not even for a client that assumes: the failure counts as a failed dial)
        assert!(matches!(r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(1)), Acquired::Skip));
        r.broken(&key());
        assert_eq!(r.lock().get(&key()).unwrap().backoff.as_ref().unwrap().failures, 2);
        // the alternative is still known: it is the time that is waited out
        assert_eq!(r.standing(&key()).1, Some(alt(443, 3600)));
    }

    #[test]
    fn what_the_origin_clears_is_left_alone_until_it_says_otherwise() {
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":443"; ma=3600"#].into_iter(), &|_, _| true);
        r.learn(&key(), ["clear"].into_iter(), &|_, _| true);
        // nothing is tried, by a client that is told or by one that assumes
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
        assert!(matches!(r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(1)), Acquired::Skip));
        // until it advertises again
        r.learn(&key(), [r#"h3=":8443"; ma=3600"#].into_iter(), &|_, _| true);
        match r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)) {
            Acquired::Dial(_, host, port) => assert_eq!((host.as_str(), port), ("example.com", 8443)),
            _ => panic!("dial"),
        }
        // (but a word from the origin does not undo the time of a failure)
        let r = Arc::new(Registry::new());
        r.learn(&key(), [r#"h3=":443""#].into_iter(), &|_, _| true);
        let Acquired::Dial(ticket, ..) = r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)) else { panic!("dial") };
        ticket.failed();
        r.learn(&key(), [r#"h3=":443""#].into_iter(), &|_, _| true);
        assert!(matches!(r.acquire(&key(), "example.com", 443, false, waits(), Duration::from_secs(1)), Acquired::Skip));
    }

    #[test]
    fn a_client_that_assumes_http3_tries_an_origin_nobody_has_spoken_of() {
        let r = Arc::new(Registry::new());
        match r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(1)) {
            Acquired::Dial(_, host, port) => assert_eq!((host.as_str(), port), ("example.com", 443)),
            _ => panic!("dial"),
        }
    }

    #[test]
    fn a_client_that_assumes_waits_for_a_dial_that_is_going_on_and_then_goes_the_tcp_way_if_it_failed() {
        let r = Arc::new(Registry::new());
        let Acquired::Dial(ticket, ..) = r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(1)) else { panic!("dial") };
        let r2 = r.clone();
        let waiter = thread::spawn(move || {
            let started = Instant::now();
            let got = r2.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(10));
            (matches!(got, Acquired::Skip), started.elapsed())
        });
        thread::sleep(Duration::from_millis(100));
        ticket.failed();
        let (skipped, took) = waiter.join().unwrap();
        assert!(skipped, "an origin that could not be reached is left to TCP");
        assert!(took >= Duration::from_millis(80) && took < Duration::from_secs(5), "{took:?}");
    }

    #[test]
    fn a_request_that_waits_for_a_dial_gives_up_when_its_time_is_up() {
        let r = Arc::new(Registry::new());
        let Acquired::Dial(_ticket, ..) = r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_secs(1)) else { panic!("dial") };
        let started = Instant::now();
        assert!(matches!(r.acquire(&key(), "example.com", 443, true, waits(), Duration::from_millis(150)), Acquired::Skip));
        assert!(started.elapsed() >= Duration::from_millis(100) && started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn only_so_many_origins_are_remembered() {
        let r = Arc::new(Registry::new());
        for i in 0..MAX_ORIGINS + 50 {
            let k = Key { tls: true, host: format!("h{i}.example"), port: 443, proxy: None, min_tls: crate::tls::TlsVersion::Tls12 };
            r.learn(&k, [r#"h3=":443""#].into_iter(), &|_, _| true);
        }
        assert!(r.lock().len() <= MAX_ORIGINS);
    }
}
