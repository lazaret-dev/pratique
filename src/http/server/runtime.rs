//! The server runtime (B-112): listeners, limits on connections, timeouts, graceful shutdown, an access log, and
//! certificates and OCSP staples kept fresh while the server runs.
//!
//! ```no_run
//! use pratique::http::server::{redirect_to_https, AcmeHttp01, Request, Response, ServerBuilder};
//! use pratique::tls::server::ServerConfig;
//! use std::sync::Arc;
//!
//! let tls = Arc::new(ServerConfig::from_pem(&std::fs::read_to_string("fullchain.pem")?, &std::fs::read_to_string("key.pem")?)?
//!     .with_alpn(&["h2", "http/1.1"]));
//! let acme = AcmeHttp01::new();
//! let server = ServerBuilder::new(|req: Request| Response::text(200, format!("hello, {}\n", req.path())))
//!     .tls("[::]:443", tls)
//!     .plain_with("[::]:80", acme.wrap(redirect_to_https(None)))
//!     .access_log(|e| println!("{} {} {} {} {}", e.peer.map(|p| p.ip().to_string()).unwrap_or_default(), e.method, e.target, e.status, e.bytes))
//!     .start()?;
//! server.wait();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Each connection has a thread of its own (and each HTTP/2 stream's handler another, under a limit for the whole
//! server), so the limits are what bound the threads: [`Limits::max_connections`] in all and
//! [`Limits::max_connections_per_ip`] from one address, past which a new connection is closed at once.
//!
//! **Timeouts.** A socket's own read timeout bounds one wait, and a client that sends a byte just before each one runs out
//! is never timed out by it; so the server keeps deadlines for whole phases and sets the socket's timeout to what is left
//! of the phase before each read:
//!
//! * the TLS handshake, in all ([`Limits::handshake_timeout`]);
//! * an idle connection, until the first byte of the next request or, in HTTP/2, while no stream is open (frames
//!   that are not requests, PING for one, do not keep it alive) ([`Limits::idle_timeout`]);
//! * a request head, in all, from its first byte (slowloris) ([`Limits::head_timeout`]);
//! * a request body, as a rate: after [`Limits::body_grace`], at least [`Limits::body_min_rate`] bytes a second on average,
//!   counted from when the handler first reads it (in HTTP/2, a handler waits at most [`Limits::body_wait`] for more of
//!   its body);
//! * each write, and in HTTP/2 a handler's wait for the client's window ([`Limits::write_timeout`]);
//! * a connection handed over by an upgrade, per read ([`Limits::upgraded_idle_timeout`]).
//!
//! **Shutdown.** [`Server::shutdown`] stops accepting, closes the idle connections, lets those under way finish (HTTP/1.1:
//! the response says `Connection: close`; HTTP/2: GOAWAY with no error) and, at the deadline, cuts what is left.

use super::{Handler, HttpConfig, Socket, Version};
use crate::tls::certs::{CertStore, CertifiedKey};
use crate::tls::server::{ServerConfig, ServerStream};
use crate::tls::Duplex;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

// ------------------------------------------------------------------------------------------------ limits

/// The limits of a [`Server`]. The defaults suit a server on the internet.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Connections open at once; past it a new one is closed at once.
    pub max_connections: usize,
    /// Connections open at once from one client address (IPv6: from one /64).
    pub max_connections_per_ip: usize,
    /// HTTP/2 handlers running at once, over all connections (each has a thread); past it a new stream is refused
    /// (REFUSED_STREAM, which a client may send again).
    pub max_h2_handlers: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub head_timeout: Duration,
    pub body_grace: Duration,
    pub body_min_rate: u64,
    pub body_wait: Duration,
    pub write_timeout: Duration,
    pub upgraded_idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_connections: 4096,
            max_connections_per_ip: 128,
            max_h2_handlers: 2048,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            head_timeout: Duration::from_secs(10),
            body_grace: Duration::from_secs(10),
            body_min_rate: 1024,
            body_wait: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            upgraded_idle_timeout: Duration::from_secs(300),
        }
    }
}

// ------------------------------------------------------------------------------------------------ the timer

/// What bounds the next read of a connection.
#[derive(Clone, Copy, Debug)]
enum ReadLimit {
    None,
    Until(Instant),
    Each(Duration),
    /// At least `rate` bytes a second after `grace`, counted from `start`.
    Rate { start: Instant, grace: Duration, rate: u64, read: u64 },
}

/// The deadlines of one connection, which the protocol layer moves from phase to phase and its socket keeps to.
#[derive(Debug)]
pub(crate) struct Timer {
    limit: Mutex<ReadLimit>,
}

impl Timer {
    pub(crate) fn new() -> Arc<Timer> {
        Arc::new(Timer { limit: Mutex::new(ReadLimit::None) })
    }

    fn lock(&self) -> MutexGuard<'_, ReadLimit> {
        self.limit.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reads end at `deadline`.
    pub(crate) fn until(&self, deadline: Instant) {
        *self.lock() = ReadLimit::Until(deadline);
    }

    /// Each read waits at most `each`.
    pub(crate) fn each(&self, each: Duration) {
        *self.lock() = ReadLimit::Each(each);
    }

    /// Reads keep to a minimum rate from now.
    pub(crate) fn rate(&self, grace: Duration, rate: u64) {
        *self.lock() = ReadLimit::Rate { start: Instant::now(), grace, rate: rate.max(1), read: 0 };
    }

    /// No deadline.
    pub(crate) fn none(&self) {
        *self.lock() = ReadLimit::None;
    }

    /// How long the next read may wait (`None`: as long as it likes); an error if the time is up.
    fn wait(&self) -> io::Result<Option<Duration>> {
        let deadline = match *self.lock() {
            ReadLimit::None => return Ok(None),
            ReadLimit::Each(d) => return Ok(Some(d.max(Duration::from_millis(1)))),
            ReadLimit::Until(t) => t,
            ReadLimit::Rate { start, grace, rate, read } => start + grace + Duration::from_secs_f64(read as f64 / rate as f64),
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the client took too long"));
        }
        Ok(Some(left.max(Duration::from_millis(1))))
    }

    fn count(&self, n: usize) {
        if let ReadLimit::Rate { read, .. } = &mut *self.lock() {
            *read += n as u64;
        }
    }
}

/// A socket that keeps to its connection's [`Timer`].
pub(crate) struct Timed<S: Socket> {
    inner: S,
    timer: Arc<Timer>,
    /// The read timeout last set on the socket.
    set: Option<Option<Duration>>,
}

impl<S: Socket> Timed<S> {
    pub(crate) fn new(inner: S, timer: Arc<Timer>, write_timeout: Duration) -> io::Result<Timed<S>> {
        inner.set_write_timeout(Some(write_timeout.max(Duration::from_millis(1))))?;
        Ok(Timed { inner, timer, set: None })
    }
}

/// How long a read with no deadline waits before it lets its caller look again (an HTTP/2 connection whose deadline
/// may change while it waits: a stream that begins to wait for a window).
const POLL: Duration = Duration::from_millis(500);

impl<S: Socket> Read for Timed<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let limited = self.timer.wait()?;
            let wait = Some(limited.unwrap_or(POLL));
            if self.set != Some(wait) {
                self.inner.set_read_timeout(wait)?;
                self.set = Some(wait);
            }
            match self.inner.read(buf) {
                Ok(n) => {
                    self.timer.count(n);
                    return Ok(n);
                }
                // the socket's timeout ran out: the phase's deadline decides (a rate may have moved on)
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    if limited.is_none() {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "no deadline: look again"));
                    }
                    self.timer.wait()?;
                    if matches!(*self.timer.lock(), ReadLimit::Each(_)) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "the connection was idle too long"));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Socket> Write for Timed<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).map_err(|e| {
            if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
                io::Error::new(io::ErrorKind::TimedOut, "the client did not read in time")
            } else {
                e
            }
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Socket> Duplex for Timed<S> {
    fn duplicate(&self) -> io::Result<Self> {
        Ok(Timed { inner: self.inner.duplicate()?, timer: self.timer.clone(), set: None })
    }
}

impl<S: Socket> Socket for Timed<S> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
    fn shutdown(&self) {
        self.inner.shutdown()
    }
    fn shutdown_write(&self) {
        self.inner.shutdown_write()
    }
}

// ------------------------------------------------------------------------------------------------ the control of a connection

/// What the protocol layer gets from the runtime for one connection: its timer and timeouts, whether the server is
/// closing, the limit on HTTP/2 handlers, the access log. A connection served without the runtime gets one that does
/// nothing ([`Ctl::detached`]).
pub(crate) struct Ctl {
    pub(crate) timer: Option<Arc<Timer>>,
    pub(crate) limits: Limits,
    /// The server is shutting down: answer what is under way, take nothing new.
    pub(crate) closing: AtomicBool,
    /// HTTP/1.1: waiting for the first byte of a request (the shutdown closes such a connection at once).
    pub(crate) idle: AtomicBool,
    /// HTTP/2: how to say GOAWAY on this connection.
    pub(crate) h2: Mutex<Option<Weak<dyn GoAway>>>,
    pub(crate) log: Option<AccessLog>,
    pub(crate) handlers: Option<Arc<AtomicUsize>>,
    /// To close the reading side of an idle connection.
    pub(crate) stop_reading: Option<Box<dyn Fn() + Send + Sync>>,
}

/// An HTTP/2 connection that can be asked to go away.
pub(crate) trait GoAway: Send + Sync {
    /// Says GOAWAY; true if nothing is left under way (the connection can be closed now).
    fn go_away(&self) -> bool;
}

impl Ctl {
    pub(crate) fn detached() -> Arc<Ctl> {
        Arc::new(Ctl { timer: None, limits: Limits::default(), closing: AtomicBool::new(false), idle: AtomicBool::new(false), h2: Mutex::new(None), log: None, handlers: None, stop_reading: None })
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// A place for one more HTTP/2 handler, if the server has one.
    pub(crate) fn take_handler(&self) -> bool {
        let Some(n) = &self.handlers else { return true };
        let max = self.limits.max_h2_handlers;
        // (a loop rather than fetch_update, which Rust 1.99 renamed try_update: this builds without a warning on both)
        let mut c = n.load(Ordering::SeqCst);
        loop {
            if c >= max {
                return false;
            }
            match n.compare_exchange_weak(c, c + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(now) => c = now,
            }
        }
    }

    pub(crate) fn give_handler(&self) {
        if let Some(n) = &self.handlers {
            n.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// The HTTP/2 driver says how to reach it; if the server is closing already, it is told at once.
    pub(crate) fn set_h2(&self, h: Weak<dyn GoAway>) {
        *self.h2.lock().unwrap_or_else(|e| e.into_inner()) = Some(h.clone());
        if self.is_closing() {
            if let Some(h) = h.upgrade() {
                if h.go_away() {
                    self.stop();
                }
            }
        }
    }

    /// Asks the connection to finish: say GOAWAY, or close at the end of the response, or close now if it is idle.
    fn begin_close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        let h2 = self.h2.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(Weak::upgrade);
        if let Some(h) = h2 {
            if h.go_away() {
                self.stop();
            }
        }
        if self.idle.load(Ordering::SeqCst) {
            self.stop();
        }
    }

    /// Closes the reading side, which ends the connection's loop (nothing more will be read).
    pub(crate) fn stop(&self) {
        if let Some(stop) = &self.stop_reading {
            stop();
        }
    }
}

/// One line of the access log: a request and what became of it.
#[derive(Debug)]
pub struct AccessEntry<'a> {
    pub peer: Option<SocketAddr>,
    pub method: &'a str,
    pub target: &'a str,
    pub authority: &'a str,
    pub version: Version,
    pub user_agent: Option<&'a str>,
    /// The status sent (0 if the handler's response could not be sent at all).
    pub status: u16,
    /// Body bytes sent.
    pub bytes: u64,
    /// From the end of the request head to the end of the response.
    pub duration: Duration,
}

/// Called after each response.
pub type AccessLog = Arc<dyn Fn(&AccessEntry<'_>) + Send + Sync>;

/// What the access log needs of a request, kept before the handler takes the request.
pub(crate) struct Pending {
    peer: Option<SocketAddr>,
    method: String,
    target: String,
    authority: String,
    version: Version,
    user_agent: Option<String>,
    started: Instant,
}

impl Pending {
    pub(crate) fn of(ctl: &Ctl, req: &super::Request) -> Option<Pending> {
        ctl.log.as_ref()?;
        Some(Pending {
            peer: req.info.peer,
            method: req.method.clone(),
            target: req.target.clone(),
            authority: req.authority.clone(),
            version: req.version,
            user_agent: req.header("user-agent").map(str::to_string),
            started: Instant::now(),
        })
    }

    pub(crate) fn done(self, ctl: &Ctl, status: u16, bytes: u64) {
        if let Some(log) = &ctl.log {
            log(&AccessEntry {
                peer: self.peer,
                method: &self.method,
                target: &self.target,
                authority: &self.authority,
                version: self.version,
                user_agent: self.user_agent.as_deref(),
                status,
                bytes,
                duration: self.started.elapsed(),
            });
        }
    }
}

// ------------------------------------------------------------------------------------------------ the server

enum Listen {
    Tls { addr: String, config: Arc<ServerConfig> },
    Plain { addr: String, handler: Option<Arc<dyn Handler>> },
    H2c { addr: String },
}

/// Called with what ended a connection badly: a handshake that failed, a client that broke the protocol, a timeout.
pub type ErrorLog = Arc<dyn Fn(Option<SocketAddr>, &io::Error) + Send + Sync>;

/// Builds a [`Server`]: its listeners, its handler, its limits.
pub struct ServerBuilder {
    handler: Arc<dyn Handler>,
    listen: Vec<Listen>,
    http: HttpConfig,
    limits: Limits,
    log: Option<AccessLog>,
    errors: Option<ErrorLog>,
}

impl ServerBuilder {
    /// A server whose listeners answer with `handler` (unless a plain listener has a handler of its own).
    pub fn new(handler: impl Handler) -> ServerBuilder {
        ServerBuilder { handler: Arc::new(handler), listen: Vec::new(), http: HttpConfig::default(), limits: Limits::default(), log: None, errors: None }
    }

    /// Listens for TLS on `addr` (HTTP/2 or HTTP/1.1, as the configuration's ALPN protocols and the client agree).
    pub fn tls(mut self, addr: &str, config: Arc<ServerConfig>) -> ServerBuilder {
        self.listen.push(Listen::Tls { addr: addr.to_string(), config });
        self
    }

    /// Listens for plain HTTP on `addr` (HTTP/1.1, or HTTP/2 with prior knowledge), with the server's handler.
    pub fn plain(mut self, addr: &str) -> ServerBuilder {
        self.listen.push(Listen::Plain { addr: addr.to_string(), handler: None });
        self
    }

    /// Listens for plain HTTP on `addr` with a handler of its own: [`redirect_to_https`](super::redirect_to_https), say,
    /// wrapped by [`AcmeHttp01`](super::AcmeHttp01).
    pub fn plain_with(mut self, addr: &str, handler: impl Handler) -> ServerBuilder {
        self.listen.push(Listen::Plain { addr: addr.to_string(), handler: Some(Arc::new(handler)) });
        self
    }

    /// Listens for plain HTTP/2 with prior knowledge on `addr`, and nothing else (behind a proxy that speaks it).
    pub fn h2c(mut self, addr: &str) -> ServerBuilder {
        self.listen.push(Listen::H2c { addr: addr.to_string() });
        self
    }

    pub fn http_config(mut self, config: HttpConfig) -> ServerBuilder {
        self.http = config;
        self
    }

    pub fn limits(mut self, limits: Limits) -> ServerBuilder {
        self.limits = limits;
        self
    }

    /// Calls `log` after each response.
    pub fn access_log(mut self, log: impl Fn(&AccessEntry<'_>) + Send + Sync + 'static) -> ServerBuilder {
        self.log = Some(Arc::new(log));
        self
    }

    /// Calls `log` with what ended a connection badly (a failed handshake, a protocol error, a timeout).
    pub fn error_log(mut self, log: impl Fn(Option<SocketAddr>, &io::Error) + Send + Sync + 'static) -> ServerBuilder {
        self.errors = Some(Arc::new(log));
        self
    }

    /// Binds the listeners and starts accepting.
    pub fn start(self) -> io::Result<Server> {
        if self.listen.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a server with no listeners"));
        }
        let inner = Arc::new(Inner {
            http: self.http,
            limits: self.limits,
            log: self.log,
            errors: self.errors,
            stopping: AtomicBool::new(false),
            conns: Mutex::new(Conns::default()),
            all_closed: Condvar::new(),
            handlers: Arc::new(AtomicUsize::new(0)),
            stats: Counters::default(),
            next_id: AtomicU64::new(0),
        });
        let mut addrs = Vec::new();
        let mut listeners = Vec::new();
        for l in self.listen {
            let (addr, kind) = match l {
                Listen::Tls { addr, config } => (addr, Kind::Tls(config)),
                Listen::Plain { addr, handler } => (addr, Kind::Plain(handler.unwrap_or_else(|| self.handler.clone()))),
                Listen::H2c { addr } => (addr, Kind::H2c),
            };
            let sockaddr = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("no address in {addr}")))?;
            let listener = TcpListener::bind(sockaddr)?;
            addrs.push(listener.local_addr()?);
            listeners.push((listener, kind));
        }
        let mut threads = Vec::new();
        for (listener, kind) in listeners {
            let inner = inner.clone();
            let handler = self.handler.clone();
            threads.push(thread::Builder::new().name("pratique-accept".into()).spawn(move || accept_loop(inner, listener, kind, handler))?);
        }
        Ok(Server { inner, threads: Mutex::new(threads), addrs })
    }
}

#[derive(Clone)]
enum Kind {
    Tls(Arc<ServerConfig>),
    Plain(Arc<dyn Handler>),
    H2c,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    refused: AtomicU64,
    timed_out: AtomicU64,
}

#[derive(Default)]
struct Conns {
    open: HashMap<u64, Arc<ConnEntry>>,
    per_ip: HashMap<IpAddr, usize>,
}

struct ConnEntry {
    ctl: Arc<Ctl>,
    socket: TcpStream,
}

struct Inner {
    http: HttpConfig,
    limits: Limits,
    log: Option<AccessLog>,
    errors: Option<ErrorLog>,
    stopping: AtomicBool,
    conns: Mutex<Conns>,
    all_closed: Condvar,
    handlers: Arc<AtomicUsize>,
    stats: Counters,
    next_id: AtomicU64,
}

impl Inner {
    fn conns(&self) -> MutexGuard<'_, Conns> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The address a per-address limit counts by: the address itself, or for IPv6 its /64 (one network's machines).
fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    }
}

fn accept_loop(inner: Arc<Inner>, listener: TcpListener, kind: Kind, handler: Arc<dyn Handler>) {
    loop {
        let (socket, peer) = match listener.accept() {
            Ok(s) => s,
            Err(_) if inner.stopping.load(Ordering::SeqCst) => return,
            Err(e) => {
                // out of file descriptors, say: wait a little rather than spin
                if !matches!(e.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted) {
                    thread::sleep(Duration::from_millis(50));
                }
                continue;
            }
        };
        if inner.stopping.load(Ordering::SeqCst) {
            return;
        }
        let key = limit_key(peer.ip());
        let id = inner.next_id.fetch_add(1, Ordering::SeqCst);
        let ctl = {
            let mut conns = inner.conns();
            let from_ip = conns.per_ip.get(&key).copied().unwrap_or(0);
            if conns.open.len() >= inner.limits.max_connections || from_ip >= inner.limits.max_connections_per_ip {
                inner.stats.refused.fetch_add(1, Ordering::SeqCst);
                drop(conns);
                let _ = socket.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let Ok(control) = socket.try_clone() else { continue };
            let stopper = socket.try_clone().ok();
            let ctl = Arc::new(Ctl {
                timer: Some(Timer::new()),
                limits: inner.limits.clone(),
                closing: AtomicBool::new(false),
                idle: AtomicBool::new(false),
                h2: Mutex::new(None),
                log: inner.log.clone(),
                handlers: Some(inner.handlers.clone()),
                stop_reading: stopper.map(|s| Box::new(move || {
                    let _ = s.shutdown(std::net::Shutdown::Read);
                }) as Box<dyn Fn() + Send + Sync>),
            });
            conns.open.insert(id, Arc::new(ConnEntry { ctl: ctl.clone(), socket: control }));
            *conns.per_ip.entry(key).or_insert(0) += 1;
            ctl
        };
        inner.stats.accepted.fetch_add(1, Ordering::SeqCst);
        let (inner2, kind, handler) = (inner.clone(), kind.clone(), handler.clone());
        let spawned = thread::Builder::new().name("pratique-conn".into()).spawn(move || {
            let inner = inner2;
            let _ = socket.set_nodelay(true);
            serve_one(&inner, socket, peer, kind, handler, &ctl);
            let mut conns = inner.conns();
            conns.open.remove(&id);
            if let Some(n) = conns.per_ip.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    conns.per_ip.remove(&key);
                }
            }
            if conns.open.is_empty() {
                inner.all_closed.notify_all();
            }
        });
        if spawned.is_err() {
            let mut conns = inner.conns();
            if let Some(entry) = conns.open.remove(&id) {
                let _ = entry.socket.shutdown(std::net::Shutdown::Both);
            }
            if let Some(n) = conns.per_ip.get_mut(&key) {
                *n -= 1;
            }
        }
    }
}

fn serve_one(inner: &Inner, socket: TcpStream, peer: SocketAddr, kind: Kind, handler: Arc<dyn Handler>, ctl: &Arc<Ctl>) {
    let timer = ctl.timer.clone().expect("the runtime's connections have a timer");
    let local = socket.local_addr().ok();
    let Ok(timed) = Timed::new(socket, timer.clone(), inner.limits.write_timeout) else { return };
    let info = super::ConnInfo { peer: Some(peer), local, tls: None };
    let result = match kind {
        Kind::Plain(h) => super::serve_plain_ctl(timed, info, h, &inner.http, ctl.clone()),
        Kind::H2c => {
            timer.until(Instant::now() + inner.limits.idle_timeout);
            match timed.duplicate() {
                Ok(writer) => super::h2::serve(Box::new(timed), Box::new(writer), Arc::new(info), handler, &inner.http, ctl.clone()),
                Err(e) => Err(e),
            }
        }
        Kind::Tls(config) => {
            timer.until(Instant::now() + inner.limits.handshake_timeout);
            match ServerStream::accept(timed, &config) {
                Ok(stream) => super::serve_tls_ctl(stream, info, handler, &inner.http, ctl.clone()),
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        }
    };
    if let Err(e) = result {
        if e.kind() == io::ErrorKind::TimedOut || e.to_string().contains("took too long") || e.to_string().contains("did not read in time") {
            inner.stats.timed_out.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(log) = &inner.errors {
            log(Some(peer), &e);
        }
    }
}

/// A running server. Dropping it does not stop it: call [`shutdown`](Server::shutdown).
pub struct Server {
    inner: Arc<Inner>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    addrs: Vec<SocketAddr>,
}

/// What a server has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections open now.
    pub open: usize,
    pub accepted: u64,
    /// Connections closed at once for the limits on connections.
    pub refused: u64,
    /// Connections that ended because a timeout ran out.
    pub timed_out: u64,
}

impl Server {
    /// The addresses the listeners are bound to, in the order they were added (with the ports the system picked for
    /// `:0`).
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    pub fn stats(&self) -> Stats {
        let s = &self.inner.stats;
        Stats { open: self.inner.conns().open.len(), accepted: s.accepted.load(Ordering::SeqCst), refused: s.refused.load(Ordering::SeqCst), timed_out: s.timed_out.load(Ordering::SeqCst) }
    }

    /// A handle that can shut the server down from another thread.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle { inner: Arc::downgrade(&self.inner), addrs: self.addrs.clone() }
    }

    /// Stops accepting, asks every connection to finish (idle ones close at once), waits up to `grace` for them, and
    /// then cuts the rest. Returns once the listeners have stopped.
    pub fn shutdown(&self, grace: Duration) {
        stop(&self.inner, &self.addrs, grace);
        for t in self.threads.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let _ = t.join();
        }
    }

    /// Blocks until the server is shut down through a [`ServerHandle`].
    pub fn wait(&self) {
        for t in self.threads.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let _ = t.join();
        }
    }
}

/// Shuts a [`Server`] down from elsewhere (a signal handler's thread, a handler that serves `/admin/stop`).
#[derive(Clone)]
pub struct ServerHandle {
    inner: Weak<Inner>,
    addrs: Vec<SocketAddr>,
}

impl ServerHandle {
    /// As [`Server::shutdown`], without waiting for the listener threads.
    pub fn shutdown(&self, grace: Duration) {
        if let Some(inner) = self.inner.upgrade() {
            stop(&inner, &self.addrs, grace);
        }
    }
}

fn stop(inner: &Inner, addrs: &[SocketAddr], grace: Duration) {
    if inner.stopping.swap(true, Ordering::SeqCst) {
        return;
    }
    // a connection to each listener wakes its accept, which then sees that the server is stopping
    for addr in addrs {
        let mut a = *addr;
        if a.ip().is_unspecified() {
            a.set_ip(if a.is_ipv4() { IpAddr::from([127, 0, 0, 1]) } else { IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]) });
        }
        let _ = TcpStream::connect_timeout(&a, Duration::from_secs(1));
    }
    let entries: Vec<Arc<ConnEntry>> = inner.conns().open.values().cloned().collect();
    for e in &entries {
        e.ctl.begin_close();
    }
    let deadline = Instant::now() + grace;
    let mut conns = inner.conns();
    while !conns.open.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        conns = inner.all_closed.wait_timeout(conns, left).unwrap_or_else(|e| e.into_inner()).0;
    }
    for e in conns.open.values() {
        let _ = e.socket.shutdown(std::net::Shutdown::Both);
    }
}

// ------------------------------------------------------------------------------------------------ certificates from files

/// Keeps a [`CertStore`] in step with certificate and key files: every `every`, the files whose modification time
/// changed are read again, and if every pair reads and each key is its certificate's, the store's certificates are
/// replaced (keeping the order: the first pair is the default). What went wrong is given to `report`, and the store is
/// left as it was. Stops when the returned handle is dropped.
pub fn reload_certificates(store: Arc<CertStore>, files: Vec<(PathBuf, PathBuf)>, every: Duration, report: impl Fn(&str) + Send + 'static) -> Reloader {
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let stop2 = stop.clone();
    let thread = thread::spawn(move || {
        let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let mut seen: Vec<(Option<SystemTime>, Option<SystemTime>)> = files.iter().map(|(c, k)| (mtime(c), mtime(k))).collect();
        loop {
            {
                let (lock, cond) = &*stop2;
                let stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
                let (stopped, _) = cond.wait_timeout_while(stopped, every, |s| !*s).unwrap_or_else(|e| e.into_inner());
                if *stopped {
                    return;
                }
            }
            let now: Vec<_> = files.iter().map(|(c, k)| (mtime(c), mtime(k))).collect();
            if now == seen {
                continue;
            }
            match load_pairs(&files) {
                Ok(certs) => {
                    store.replace(certs);
                    seen = now;
                    report("certificates reloaded");
                }
                Err(e) => report(&format!("certificates not reloaded: {e}")),
            }
        }
    });
    Reloader { stop, thread: Some(thread) }
}

fn load_pairs(files: &[(PathBuf, PathBuf)]) -> Result<Vec<CertifiedKey>, String> {
    files
        .iter()
        .map(|(c, k)| {
            let chain = std::fs::read_to_string(c).map_err(|e| format!("{}: {e}", c.display()))?;
            let key = std::fs::read_to_string(k).map_err(|e| format!("{}: {e}", k.display()))?;
            CertifiedKey::from_pem(&chain, &key).map_err(|e| format!("{}: {e}", c.display()))
        })
        .collect()
}

/// Stops the thread of [`reload_certificates`] (or [`refresh_ocsp_staples`], or [`acme::manage`](super::acme::manage))
/// when dropped.
pub struct Reloader {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Reloader {
    /// The handle of `thread`, which waits on `stop` and ends when it becomes true.
    pub(super) fn new(stop: Arc<(Mutex<bool>, Condvar)>, thread: JoinHandle<()>) -> Reloader {
        Reloader { stop, thread: Some(thread) }
    }
}

impl Drop for Reloader {
    fn drop(&mut self) {
        let (lock, cond) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cond.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ------------------------------------------------------------------------------------------------ OCSP staples

/// Keeps the OCSP staples of a [`CertStore`] fresh: for each certificate that names an OCSP responder (and has its
/// issuer next in its chain), a response is fetched (over plain HTTP, as OCSP is served), checked (signed for this
/// certificate by its issuer or a responder it authorized, "good", in its window), and stapled; it is fetched again
/// halfway through its window (but at least an hour and at most a day after the last), and a staple whose window has
/// passed is taken off rather than sent. A certificate with no responder (Let's Encrypt's, since 2025) is left alone.
/// What went wrong is given to `report`. Stops when the returned handle is dropped.
pub fn refresh_ocsp_staples(store: Arc<CertStore>, report: impl Fn(&str) + Send + 'static) -> Reloader {
    use crate::revocation::OcspSource;
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let stop2 = stop.clone();
    let thread = thread::spawn(move || {
        let source = crate::http::HttpOcspSource::new();
        // per certificate (by its DER): when to fetch next, and when its staple stops being good
        let mut next: HashMap<Vec<u8>, (i64, Option<i64>)> = HashMap::new();
        loop {
            let now = crate::sys::now_unix();
            let mut wait = 3600i64;
            for (index, ck) in store.certificates().iter().enumerate() {
                let chain = ck.chain();
                let (Some(leaf_der), Some(issuer_der)) = (chain.first(), chain.get(1)) else { continue };
                let (Ok(leaf), Ok(issuer)) = (crate::x509::Certificate::parse(leaf_der), crate::x509::Certificate::parse(issuer_der)) else { continue };
                let Some(url) = leaf.ocsp_uris().iter().find(|u| u.starts_with("http://")).cloned() else { continue };
                let (due, good_until) = next.get(leaf_der).copied().unwrap_or((0, None));
                if good_until.is_some_and(|t| t <= now) {
                    store.set_ocsp_staple(index, None);
                }
                if due > now {
                    wait = wait.min(due - now);
                    continue;
                }
                let request = crate::revocation::ocsp_request(&leaf, &issuer);
                let fetched = source.fetch(&url, &request).map_err(|e| e.to_string()).and_then(|resp| {
                    if !crate::revocation::ocsp_response_is_good(&resp, &leaf, &issuer, now) {
                        return Err("the responder's answer is not a good, current response for the certificate".into());
                    }
                    let until = crate::revocation::ocsp_response_valid_until(&resp).ok_or("a response with no window")?;
                    Ok((resp, until))
                });
                match fetched {
                    Ok((resp, until)) => {
                        store.set_ocsp_staple(index, Some(resp));
                        let again = now + ((until - now) / 2).clamp(3600, 86_400);
                        next.insert(leaf_der.clone(), (again, Some(until)));
                        wait = wait.min(again - now);
                    }
                    Err(e) => {
                        report(&format!("OCSP for certificate {index} from {url}: {e}"));
                        next.insert(leaf_der.clone(), (now + 300, good_until));
                        wait = wait.min(300);
                    }
                }
            }
            let (lock, cond) = &*stop2;
            let stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
            let (stopped, _) = cond.wait_timeout_while(stopped, Duration::from_secs(wait.max(1) as u64), |s| !*s).unwrap_or_else(|e| e.into_inner());
            if *stopped {
                return;
            }
        }
    });
    Reloader { stop, thread: Some(thread) }
}

// ------------------------------------------------------------------------------------------------ lingering

/// After an HTTP/1.1 refusal: says that nothing more will be written and reads what the client is still sending, for at
/// most a second or 64 KiB, so that the refusal reaches the client before the connection is closed (closing with unread
/// data makes the system reset the connection, which can destroy the answer before the client reads it).
pub(crate) fn linger<S: Socket>(socket: &mut S) {
    socket.shutdown_write();
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut buf = [0u8; 8192];
    let mut total = 0;
    while Instant::now() < deadline && total < 64 * 1024 {
        match socket.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => total += n,
        }
    }
}
