//! Making TCP connections (BACKLOG B-48): host names resolved through a short-lived cache, within the connect timeout,
//! and the addresses raced as RFC 8305 ("Happy Eyeballs Version 2") describes, so that an address family that does not
//! work (IPv6 that is routed nowhere, the usual case) costs a quarter of a second instead of the whole connect timeout.
//!
//! * **Resolution** goes through the system's resolver (`getaddrinfo`, through the standard library), on a thread of its
//!   own, so that the caller waits no longer than its connect timeout (the standard library has no timeout for it; the
//!   lookup goes on in the background and its answer still fills the cache). Callers that ask for the same name while it
//!   is being looked up wait for that one lookup. An answer is kept for [`DEFAULT_DNS_TTL`] (or what
//!   [`Client::dns_cache`](super::Client::dns_cache) says; the system's resolver does not give the record's own time to
//!   live), for at most 512 names; a failure is not kept. An IP address is not looked up.
//! * **Order** (RFC 8305 section 4): the resolver's order (RFC 6724's, from `getaddrinfo`), the address that last
//!   connected for that name moved to the front, then the families interleaved, starting with the first one's.
//! * **Racing** (section 5): the first address is tried; if it has not connected after the connection attempt delay
//!   ([`DEFAULT_ATTEMPT_DELAY`], 250 ms, from 10 ms to 2 s with
//!   [`Client::connection_attempt_delay`](super::Client::connection_attempt_delay)), or as soon as it fails, the next one
//!   is tried as well, and so on; the first connection made wins and the attempts still running are dropped (a late
//!   success is closed). Each attempt has the time left before the connect timeout. One address is simply tried, with no
//!   thread. The standard library cannot cancel a connect that is under way, so an attempt that lost keeps its thread
//!   until it ends, at the latest at the connect timeout.
//! * **Not done:** the separate AAAA and A queries of section 3 (the system's resolver answers both at once), and
//!   attempt delays learned from round-trip times.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// How long a name's addresses are kept.
pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(30);
/// How long an attempt to connect has before the next address is tried as well (RFC 8305 section 5).
pub const DEFAULT_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// The range RFC 8305 section 5 allows the connection attempt delay.
pub(crate) const MIN_ATTEMPT_DELAY: Duration = Duration::from_millis(10);
pub(crate) const MAX_ATTEMPT_DELAY: Duration = Duration::from_secs(2);
/// Names kept.
const NAMES: usize = 512;
/// Addresses tried for one connection.
const MAX_ATTEMPTS: usize = 32;

/// How a client makes its connections: its resolver and the delay between attempts. Clones share the resolver.
#[derive(Clone)]
pub(crate) struct Establish {
    pub(crate) resolver: Arc<Resolver>,
    pub(crate) attempt_delay: Duration,
}

impl std::fmt::Debug for Establish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Establish").field("dns_ttl", &self.resolver.ttl).field("attempt_delay", &self.attempt_delay).finish()
    }
}

impl Default for Establish {
    fn default() -> Establish {
        Establish { resolver: Arc::new(Resolver::new(DEFAULT_DNS_TTL)), attempt_delay: DEFAULT_ATTEMPT_DELAY }
    }
}

type Lookup = dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync;

/// A name's addresses as the system's resolver gave them, kept for a while.
pub(crate) struct Resolver {
    ttl: Duration,
    lookup: Arc<Lookup>,
    names: Arc<Mutex<HashMap<String, Name>>>,
}

#[derive(Default)]
struct Name {
    /// The answer and until when it is used.
    addrs: Option<(Vec<IpAddr>, Instant)>,
    /// The lookup under way, which other callers wait for.
    pending: Option<Arc<Pending>>,
    /// The address that last connected.
    last_good: Option<IpAddr>,
    /// When the name was last asked for (the least recent goes when the table is full).
    used: Option<Instant>,
}

/// What a lookup came to: an error as its kind and text, since `io::Error` cannot be cloned.
type Answer = Result<Vec<IpAddr>, (io::ErrorKind, String)>;

/// A lookup under way, and its answer when it is in.
#[derive(Default)]
struct Pending {
    answer: Mutex<Option<Answer>>,
    done: Condvar,
}

fn system_lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    Ok((host, 0u16).to_socket_addrs()?.map(|a| a.ip()).collect())
}

fn lock(names: &Mutex<HashMap<String, Name>>) -> MutexGuard<'_, HashMap<String, Name>> {
    // every change is one assignment, so a panic elsewhere leaves the table usable
    names.lock().unwrap_or_else(|e| e.into_inner())
}

impl Resolver {
    /// A resolver that keeps answers for `ttl` (zero keeps none; lookups of one name at the same time are still made
    /// once).
    pub(crate) fn new(ttl: Duration) -> Resolver {
        Resolver::with_lookup(ttl, Arc::new(system_lookup))
    }

    /// The same with another way to look names up (for tests).
    pub(crate) fn with_lookup(ttl: Duration, lookup: Arc<Lookup>) -> Resolver {
        Resolver { ttl, lookup, names: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// The addresses of `host` in the order to try them, waiting for the lookup until `until` at the latest.
    pub(crate) fn resolve(&self, host: &str, until: Instant) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let key = host.to_ascii_lowercase();
        let now = Instant::now();
        let (pending, mine) = {
            let mut names = lock(&self.names);
            let name = names.entry(key.clone()).or_default();
            name.used = Some(now);
            match (&name.addrs, &name.pending) {
                (Some((addrs, expires)), _) if now < *expires => return Ok(order(addrs, name.last_good)),
                (_, Some(p)) => (p.clone(), false),
                _ => {
                    let p = Arc::new(Pending::default());
                    name.pending = Some(p.clone());
                    if names.len() > NAMES {
                        evict(&mut names, &key);
                    }
                    (p, true)
                }
            }
        };
        if mine {
            self.start(&key, pending.clone());
        }
        let mut answer = pending.answer.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(a) = answer.as_ref() {
                return match a {
                    Ok(addrs) => {
                        let last_good = lock(&self.names).get(&key).and_then(|n| n.last_good);
                        Ok(order(addrs, last_good))
                    }
                    Err((kind, text)) => Err(io::Error::new(*kind, text.clone())),
                };
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("resolving {host} took longer than the time there was to connect")));
            }
            answer = pending.done.wait_timeout(answer, left).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// Looks `key` up on a thread of its own (on this one if no thread can be had), and gives the answer to the table and
    /// to whoever waits for it.
    fn start(&self, key: &str, pending: Arc<Pending>) {
        let (lookup, names, ttl, key) = (self.lookup.clone(), self.names.clone(), self.ttl, key.to_string());
        let job = move || {
            let answer = lookup(&key);
            {
                let mut table = lock(&names);
                let name = table.entry(key).or_default();
                name.pending = None;
                match &answer {
                    // an empty answer is not kept: it says nothing for long
                    Ok(addrs) if !addrs.is_empty() && !ttl.is_zero() => name.addrs = Some((addrs.clone(), Instant::now() + ttl)),
                    _ => name.addrs = None,
                }
            }
            *pending.answer.lock().unwrap_or_else(|e| e.into_inner()) = Some(answer.map_err(|e| (e.kind(), e.to_string())));
            pending.done.notify_all();
        };
        let job = Arc::new(Mutex::new(Some(job)));
        let on_thread = job.clone();
        let spawned = thread::Builder::new().name("pratique resolve".into()).spawn(move || {
            if let Some(job) = on_thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
                job()
            }
        });
        if spawned.is_err() {
            // no thread to be had: the lookup is made here, without the limit on its time
            if let Some(job) = job.lock().unwrap_or_else(|e| e.into_inner()).take() {
                job()
            }
        }
    }

    /// Notes that `ip` connected for `host`: it is tried first next time.
    pub(crate) fn connected(&self, host: &str, ip: IpAddr) {
        if host.parse::<IpAddr>().is_ok() {
            return;
        }
        if let Some(name) = lock(&self.names).get_mut(&host.to_ascii_lowercase()) {
            name.last_good = Some(ip);
        }
    }

    /// How many names are in the table (for tests).
    #[cfg(test)]
    pub(crate) fn names(&self) -> usize {
        lock(&self.names).len()
    }
}

/// Drops the least recently asked-for name other than `keep`, preferring expired answers with no lookup under way.
fn evict(names: &mut HashMap<String, Name>, keep: &str) {
    let now = Instant::now();
    let victim = names
        .iter()
        .filter(|(k, n)| k.as_str() != keep && n.pending.is_none())
        .min_by_key(|(_, n)| (n.addrs.as_ref().is_some_and(|(_, e)| *e > now), n.used))
        .map(|(k, _)| k.clone());
    if let Some(k) = victim {
        names.remove(&k);
    }
}

/// RFC 8305 section 4: `addrs` without repeats, `preferred` first, then the two families interleaved, starting with the
/// family of the first.
pub(crate) fn order(addrs: &[IpAddr], preferred: Option<IpAddr>) -> Vec<IpAddr> {
    let mut list: Vec<IpAddr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !list.contains(a) {
            list.push(*a);
        }
    }
    if let Some(i) = preferred.and_then(|p| list.iter().position(|a| *a == p)) {
        let p = list.remove(i);
        list.insert(0, p);
    }
    let Some(first) = list.first() else { return list };
    let first_v6 = first.is_ipv6();
    let (mut same, mut other): (Vec<IpAddr>, Vec<IpAddr>) = list.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(same.len() + other.len());
    same.reverse();
    other.reverse();
    loop {
        match (same.pop(), other.pop()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

/// Connects to one of `addrs` (in that order), racing them as RFC 8305 section 5 says, by `until` at the latest: the
/// stream and the address it went to. `connect` makes one attempt with the time it is given.
pub(crate) fn race<T, F>(addrs: &[SocketAddr], delay: Duration, until: Instant, connect: F) -> io::Result<(T, SocketAddr)>
where
    T: Send + 'static,
    F: Fn(SocketAddr, Duration) -> io::Result<T> + Send + Sync + 'static,
{
    let addrs = &addrs[..addrs.len().min(MAX_ATTEMPTS)];
    let left = |now: Instant| until.saturating_duration_since(now);
    match addrs {
        [] => return Err(io::Error::new(io::ErrorKind::NotFound, "no address to connect to")),
        [only] => {
            let t = left(Instant::now());
            if t.is_zero() {
                return Err(timed_out(addrs, &[]));
            }
            return connect(*only, t).map(|s| (s, *only)).map_err(|e| failed(addrs, &[(*only, e)]));
        }
        _ => {}
    }
    let connect = Arc::new(connect);
    let (tx, rx) = mpsc::channel::<(usize, io::Result<T>)>();
    let mut errors: Vec<(SocketAddr, io::Error)> = Vec::new();
    let (mut next, mut running) = (0usize, 0usize);
    let mut next_at = Instant::now();
    loop {
        let now = Instant::now();
        // the next attempt, when its time has come (or the one before it has failed)
        if next < addrs.len() && (now >= next_at || running == 0) {
            let t = left(now);
            if t.is_zero() {
                return Err(timed_out(addrs, &errors));
            }
            let (i, addr, tx, attempt_connect) = (next, addrs[next], tx.clone(), connect.clone());
            let attempt = move || {
                // (a send after the race is over fails, and drops a connection that came too late)
                let _ = tx.send((i, attempt_connect(addr, t)));
            };
            let spawned = thread::Builder::new().name("pratique connect".into()).stack_size(128 * 1024).spawn(attempt);
            if spawned.is_err() {
                // no thread to be had: this attempt alone, on this thread, with what time is left
                match connect(addr, t) {
                    Ok(s) => return Ok((s, addr)),
                    Err(e) => errors.push((addr, e)),
                }
            } else {
                running += 1;
            }
            next += 1;
            next_at = now + delay;
            continue;
        }
        if running == 0 {
            return Err(failed(addrs, &errors));
        }
        let wake = if next < addrs.len() { next_at.min(until) } else { until };
        match rx.recv_timeout(wake.saturating_duration_since(now)) {
            Ok((i, Ok(stream))) => return Ok((stream, addrs[i])),
            Ok((i, Err(e))) => {
                running -= 1;
                errors.push((addrs[i], e));
                // the next one goes at once (RFC 8305 section 5: a failure starts the next attempt)
                next_at = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= until => return Err(timed_out(addrs, &errors)),
            Err(_) => {}
        }
    }
}

fn tried(errors: &[(SocketAddr, io::Error)]) -> String {
    errors.iter().map(|(a, e)| format!("{a}: {e}")).collect::<Vec<_>>().join("; ")
}

/// Every attempt failed: the last failure's kind, and what each address said.
fn failed(addrs: &[SocketAddr], errors: &[(SocketAddr, io::Error)]) -> io::Error {
    let kind = errors.last().map_or(io::ErrorKind::Other, |(_, e)| e.kind());
    if let [(_, e)] = errors {
        if addrs.len() == 1 {
            return io::Error::new(kind, e.to_string());
        }
    }
    io::Error::new(kind, format!("no address answered ({})", tried(errors)))
}

fn timed_out(addrs: &[SocketAddr], errors: &[(SocketAddr, io::Error)]) -> io::Error {
    let n = addrs.len();
    let what = if errors.is_empty() { String::new() } else { format!("; {}", tried(errors)) };
    io::Error::new(io::ErrorKind::TimedOut, format!("connecting timed out ({n} address{} tried{what})", if n == 1 { "" } else { "es" }))
}

/// Resolves `host` and connects to `port` on one of its addresses, by `until` at the latest.
pub(crate) fn connect(est: &Establish, host: &str, port: u16, until: Instant) -> io::Result<TcpStream> {
    let ips = est.resolver.resolve(host, until)?;
    if ips.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host} did not resolve to any address")));
    }
    let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    let (tcp, addr) = race(&addrs, est.attempt_delay, until, |a, t| TcpStream::connect_timeout(&a, t))?;
    est.resolver.connected(host, addr.ip());
    Ok(tcp)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn v6(n: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n))
    }

    #[test]
    fn addresses_are_interleaved_by_family_after_the_one_that_last_connected() {
        assert_eq!(order(&[v6(1), v6(2), v6(3), v4(1), v4(2)], None), [v6(1), v4(1), v6(2), v4(2), v6(3)]);
        assert_eq!(order(&[v4(1), v4(2), v6(1)], None), [v4(1), v6(1), v4(2)]);
        // the one that connected last goes first, and its family leads
        assert_eq!(order(&[v6(1), v6(2), v4(1), v4(2)], Some(v4(2))), [v4(2), v6(1), v4(1), v6(2)]);
        // one that is no longer in the answer changes nothing; repeats are dropped
        assert_eq!(order(&[v6(1), v4(1), v6(1)], Some(v4(9))), [v6(1), v4(1)]);
        assert!(order(&[], Some(v4(1))).is_empty());
    }

    /// A fake attempt: the address's last byte says what it does: `1x` connects after x * 10 ms, `2x` fails after x * 10
    /// ms, `3x` hangs until its time is up. Each attempt that starts is counted.
    fn fake(started: Arc<AtomicUsize>) -> impl Fn(SocketAddr, Duration) -> io::Result<u8> + Send + Sync + 'static {
        move |addr, t| {
            started.fetch_add(1, Ordering::SeqCst);
            let IpAddr::V4(ip) = addr.ip() else { unreachable!() };
            let n = ip.octets()[3];
            let ms = Duration::from_millis(u64::from(n % 10) * 10);
            match n / 10 {
                1 if ms <= t => {
                    thread::sleep(ms);
                    Ok(n)
                }
                2 if ms <= t => {
                    thread::sleep(ms);
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                }
                _ => {
                    thread::sleep(t);
                    Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
                }
            }
        }
    }

    fn addrs(codes: &[u8]) -> Vec<SocketAddr> {
        codes.iter().map(|c| SocketAddr::new(v4(*c), 443)).collect()
    }

    fn run(codes: &[u8], delay_ms: u64, limit_ms: u64) -> (io::Result<u8>, Duration, usize) {
        let started = Arc::new(AtomicUsize::new(0));
        let t = Instant::now();
        let r = race(&addrs(codes), Duration::from_millis(delay_ms), t + Duration::from_millis(limit_ms), fake(started.clone()));
        (r.map(|(s, a)| {
            assert_eq!(a, SocketAddr::new(v4(s), 443));
            s
        }), t.elapsed(), started.load(Ordering::SeqCst))
    }

    #[test]
    fn an_address_that_does_not_answer_costs_the_attempt_delay_not_the_timeout() {
        // the first hangs: the second is tried after 100 ms and connects at once
        let (r, took, started) = run(&[30, 10], 100, 5000);
        assert_eq!(r.unwrap(), 10);
        assert!(took >= Duration::from_millis(100) && took < Duration::from_millis(1000), "{took:?}");
        assert_eq!(started, 2);
        // the first is slow but quicker than the delay: nothing else is tried
        let (r, _, started) = run(&[13, 10], 250, 5000);
        assert_eq!((r.unwrap(), started), (13, 1));
        // the first is slower than the delay, but still connects before the second: the first wins
        let (r, _, started) = run(&[15, 18], 20, 5000);
        assert_eq!((r.unwrap(), started), (15, 2));
    }

    #[test]
    fn a_failure_starts_the_next_attempt_at_once() {
        let (r, took, started) = run(&[20, 21, 10], 2000, 5000);
        assert_eq!(r.unwrap(), 10);
        assert!(took < Duration::from_millis(1000), "{took:?}");
        assert_eq!(started, 3);
    }

    #[test]
    fn when_all_fail_every_address_is_named_and_the_last_kind_is_kept() {
        let (r, _, started) = run(&[20, 21], 50, 5000);
        let e = r.unwrap_err();
        assert_eq!((e.kind(), started), (io::ErrorKind::ConnectionRefused, 2));
        assert!(e.to_string().contains("192.0.2.20:443: refused") && e.to_string().contains("192.0.2.21:443: refused"), "{e}");
        // one address: its own error, as it was
        let (r, _, _) = run(&[20], 50, 5000);
        assert_eq!(r.unwrap_err().to_string(), "refused");
    }

    #[test]
    fn the_limit_ends_the_race() {
        let (r, took, started) = run(&[30, 31, 32], 50, 300);
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(took >= Duration::from_millis(300) && took < Duration::from_millis(1500), "{took:?}");
        assert_eq!(started, 3);
        // no time at all: nothing is tried
        let (r, _, started) = run(&[10, 11], 50, 0);
        assert_eq!((r.unwrap_err().kind(), started), (io::ErrorKind::TimedOut, 0));
    }

    #[test]
    fn a_connection_made_after_the_race_was_won_is_closed() {
        struct Counted(Arc<AtomicUsize>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let d = dropped.clone();
        let connect = move |addr: SocketAddr, _t: Duration| -> io::Result<Counted> {
            // the first takes 300 ms, the second 10
            thread::sleep(Duration::from_millis(if addr.port() == 1 { 300 } else { 10 }));
            Ok(Counted(d.clone()))
        };
        let a: Vec<SocketAddr> = vec![SocketAddr::new(v4(1), 1), SocketAddr::new(v4(1), 2)];
        let (won, addr) = race(&a, Duration::from_millis(50), Instant::now() + Duration::from_secs(5), connect).unwrap();
        assert_eq!(addr.port(), 2);
        thread::sleep(Duration::from_millis(400));
        assert_eq!(dropped.load(Ordering::SeqCst), 1, "the first one's late connection was dropped");
        drop(won);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn real_sockets_a_refused_address_then_a_listening_one() {
        let open = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        let a = [closed_addr, open.local_addr().unwrap()];
        let t = Instant::now();
        let (_s, addr) = race(&a, Duration::from_secs(2), t + Duration::from_secs(5), |a, t| TcpStream::connect_timeout(&a, t)).unwrap();
        assert_eq!(addr, open.local_addr().unwrap());
        assert!(t.elapsed() < Duration::from_secs(1));
        // through the resolver, by name, and the address that answered is remembered
        let est = Establish::default();
        let port = open.local_addr().unwrap().port();
        connect(&est, "localhost", port, Instant::now() + Duration::from_secs(5)).unwrap();
        connect(&est, "127.0.0.1", port, Instant::now() + Duration::from_secs(5)).unwrap();
        let e = connect(&est, "127.0.0.1", closed_addr.port(), Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }

    /// An address that takes no connection: a listener on `ip:port` whose queue of connections waiting to be accepted is
    /// full, so that the system drops what comes next without an answer, as a network that routes nowhere does. `None`
    /// if the queue never fills (the test that wanted it then says so and does nothing).
    pub(crate) fn black_hole(ip: IpAddr, port: u16) -> Option<(TcpListener, Vec<TcpStream>)> {
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).ok()?;
        let addr = listener.local_addr().ok()?;
        let mut queued = Vec::new();
        for _ in 0..5000 {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Ok(s) => queued.push(s),
                Err(e) if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => return Some((listener, queued)),
                Err(_) => return None,
            }
        }
        None
    }

    #[test]
    fn real_sockets_an_address_that_does_not_answer_costs_the_attempt_delay() {
        let good = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = good.local_addr().unwrap().port();
        let Some((_hole, _queued)) = black_hole(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port) else {
            eprintln!("no black hole can be made on this system: skipped");
            return;
        };
        let lookup: Arc<Lookup> = Arc::new(|_: &str| Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), IpAddr::V4(Ipv4Addr::LOCALHOST)]));
        let est = Establish { resolver: Arc::new(Resolver::with_lookup(Duration::from_secs(30), lookup)), attempt_delay: DEFAULT_ATTEMPT_DELAY };
        let t = Instant::now();
        let s = connect(&est, "dual.test", port, t + Duration::from_secs(10)).unwrap();
        let took = t.elapsed();
        assert_eq!(s.peer_addr().unwrap(), good.local_addr().unwrap());
        assert!(took >= DEFAULT_ATTEMPT_DELAY && took < Duration::from_secs(2), "{took:?}");
        // the address that answered goes first next time
        let t = Instant::now();
        connect(&est, "dual.test", port, t + Duration::from_secs(10)).unwrap();
        assert!(t.elapsed() < DEFAULT_ATTEMPT_DELAY, "{:?}", t.elapsed());
        // the black hole alone: the connect timeout, and a TimedOut
        let t = Instant::now();
        let e = race(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port)], DEFAULT_ATTEMPT_DELAY, t + Duration::from_millis(400), |a, t| TcpStream::connect_timeout(&a, t)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        assert!(t.elapsed() >= Duration::from_millis(400), "{:?}", t.elapsed());
    }

    /// A lookup that counts its calls, waits `wait`, and answers what `answer` says.
    fn counting(calls: Arc<AtomicUsize>, wait: Duration, answer: fn(usize) -> io::Result<Vec<IpAddr>>) -> Arc<Lookup> {
        Arc::new(move |_host: &str| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(wait);
            answer(n)
        })
    }

    fn soon(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    #[test]
    fn answers_are_kept_for_their_time_and_failures_are_not() {
        let calls = Arc::new(AtomicUsize::new(0));
        let r = Resolver::with_lookup(Duration::from_millis(100), counting(calls.clone(), Duration::ZERO, |n| {
            if n == 0 {
                Err(io::Error::new(io::ErrorKind::Other, "no such host"))
            } else {
                Ok(vec![v4(1), v6(1)])
            }
        }));
        assert_eq!(r.resolve("Example.test", soon(1000)).unwrap_err().to_string(), "no such host");
        assert_eq!(r.resolve("example.test", soon(1000)).unwrap(), [v4(1), v6(1)], "the failure was not kept");
        assert_eq!(r.resolve("EXAMPLE.test", soon(1000)).unwrap(), [v4(1), v6(1)]);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the answer was kept, under any spelling");
        r.connected("example.test", v6(1));
        assert_eq!(r.resolve("example.test", soon(1000)).unwrap(), [v6(1), v4(1)], "the address that connected goes first");
        thread::sleep(Duration::from_millis(120));
        r.resolve("example.test", soon(1000)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3, "looked up again once its time was over");
        // an address is not looked up
        assert_eq!(r.resolve("192.0.2.7", soon(0)).unwrap(), [v4(7)]);
        assert_eq!(r.resolve("2001:db8::5", soon(0)).unwrap(), [v6(5)]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // a time to live of zero keeps nothing
        let calls = Arc::new(AtomicUsize::new(0));
        let r = Resolver::with_lookup(Duration::ZERO, counting(calls.clone(), Duration::ZERO, |_| Ok(vec![v4(1)])));
        r.resolve("a.test", soon(1000)).unwrap();
        r.resolve("a.test", soon(1000)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn callers_that_ask_at_once_share_one_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let r = Arc::new(Resolver::with_lookup(Duration::from_secs(30), counting(calls.clone(), Duration::from_millis(100), |_| Ok(vec![v4(1)]))));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let r = r.clone();
                thread::spawn(move || r.resolve("a.test", soon(5000)).unwrap())
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap(), [v4(1)]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_slow_lookup_is_waited_for_no_longer_than_the_limit_and_its_answer_is_still_kept() {
        let calls = Arc::new(AtomicUsize::new(0));
        let r = Resolver::with_lookup(Duration::from_secs(30), counting(calls.clone(), Duration::from_millis(300), |_| Ok(vec![v4(1)])));
        let t = Instant::now();
        let e = r.resolve("slow.test", soon(50)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_millis(250), "{:?}", t.elapsed());
        // a second caller waits for the same lookup
        assert_eq!(r.resolve("slow.test", soon(2000)).unwrap(), [v4(1)]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // and later the answer is there at once
        assert_eq!(r.resolve("slow.test", soon(0)).unwrap(), [v4(1)]);
    }

    #[test]
    fn the_table_is_bounded() {
        let r = Resolver::with_lookup(Duration::from_secs(30), Arc::new(|_: &str| Ok(vec![v4(1)])));
        for i in 0..(NAMES + 100) {
            r.resolve(&format!("h{i}.test"), soon(1000)).unwrap();
        }
        assert!(r.names() <= NAMES + 1, "{}", r.names());
    }
}
