//! Scheduling requests (BACKLOG B-74): limits on the requests in flight, in all and per host, a budget on the bytes they
//! bring in, turns taken fairly between hosts, and batches of requests with a deadline and a way to cancel them. One
//! [`Scheduler`] can serve several clients ([`Client::scheduler`](super::Client::scheduler)), blocking and async alike,
//! and the `*_async` methods that run the blocking client on the pool.
//!
//! * **In flight** means from the moment a request is let go until its response is over: read to its end, or dropped (a
//!   [`Response`](super::Response) is over when the call returns; a [`ResponseStream`](super::ResponseStream) when its
//!   body has been read or it is dropped), or failed. Redirects are part of the request.
//! * **Per host**: a request counts against the host it is talking to (`host:port`); a redirect to another host gives
//!   that host's place back and waits for one at the other (ahead of the requests that have not started).
//! * **Bytes**: a request reserves what it says it will bring ([`RequestBuilder::expected_bytes`](super::RequestBuilder::expected_bytes)),
//!   then, once the head of its response is in, the length the server gives (more or less than the estimate), and, for a
//!   body without a length, what has come so far if that is more. A request is let go when its estimate fits in what is
//!   left of the budget, or when nothing is reserved at all (so that one that is larger than the budget still goes, alone).
//!   A size learnt later can take the total over the budget: no request is held up for that once it is under way (that
//!   could leave every request waiting for another), but no new one starts until the total is back under the budget.
//! * **Turns**: requests that wait are let go host by host in turn, and in the order they came within a host, so that a
//!   host with a long queue does not hold up the others. A host whose limit is reached is passed over until it has room.
//! * **Batches** ([`Batch`]): a deadline for all the requests of the batch (it shortens a request's
//!   [`total_timeout`](super::Client::total_timeout) and bounds the wait to be let go), and [`Batch::cancel`], which fails
//!   at once the requests that wait, and stops those under way: an HTTP/1.1 connection is shut down, an HTTP/2 stream is
//!   reset (and the server pinged, so that a thread reading the connection for the others notices within a round trip),
//!   and an async request is woken and fails. A request made after the cancel fails at once. HTTP/3 requests do not
//!   notice a cancel until their next deadline.
//!
//! ```no_run
//! use std::time::Duration;
//! use pratique::http::{Batch, Scheduler};
//! let sched = Scheduler::new().max_in_flight(16).max_in_flight_per_host(4).byte_budget(512 << 20);
//! let client = pratique::Client::new()?.scheduler(&sched);
//! let batch = Batch::with_timeout(Duration::from_secs(120));
//! let scan = client.in_batch(&batch);
//! let zip = scan.request("GET", "https://proxy.golang.org/golang.org/x/mod/@v/v0.20.0.zip").expected_bytes(4 << 20).send()?;
//! println!("{} bytes; {} requests in flight", zip.body.len(), sched.in_flight());
//! batch.cancel();
//! # Ok::<(), pratique::error::Error>(())
//! ```

use crate::error::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

/// Limits on requests in flight, shared by the clients it is given to. Cloning it shares it.
#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

struct Inner {
    /// 0: no limit.
    max_in_flight: usize,
    max_per_host: usize,
    byte_budget: u64,
    state: Mutex<State>,
    /// Threads waiting to be let go sleep here; each looks at its own entry when woken.
    changed: Condvar,
}

#[derive(Default)]
struct State {
    in_flight: usize,
    hosts: HashMap<String, usize>,
    bytes: u64,
    /// Waiting requests by host, in the order they came (those that moved to the host on a redirect first).
    queues: HashMap<String, VecDeque<u64>>,
    /// Hosts with requests waiting, in the order of their turns.
    turns: VecDeque<String>,
    waiters: HashMap<u64, Waiter>,
    next_id: u64,
}

struct Waiter {
    host: String,
    /// It also needs a place among all requests in flight (a new request; a redirect already has one).
    global: bool,
    cost: u64,
    granted: bool,
    waker: Option<Waker>,
}

impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheduler")
            .field("max_in_flight", &self.inner.max_in_flight)
            .field("max_in_flight_per_host", &self.inner.max_per_host)
            .field("byte_budget", &self.inner.byte_budget)
            .field("in_flight", &self.in_flight())
            .field("waiting", &self.waiting())
            .finish()
    }
}

impl Default for Scheduler {
    fn default() -> Scheduler {
        Scheduler::new()
    }
}

impl Scheduler {
    /// A scheduler with no limits (each of the setters below adds one). The limits are set before it is given to a client:
    /// each setter makes a new scheduler, which shares nothing with the one it was called on.
    pub fn new() -> Scheduler {
        Scheduler::with(0, 0, 0)
    }

    fn with(max_in_flight: usize, max_per_host: usize, byte_budget: u64) -> Scheduler {
        Scheduler { inner: Arc::new(Inner { max_in_flight, max_per_host, byte_budget, state: Mutex::new(State::default()), changed: Condvar::new() }) }
    }

    /// At most `n` requests in flight in all (0: no limit).
    pub fn max_in_flight(self, n: usize) -> Scheduler {
        Scheduler::with(n, self.inner.max_per_host, self.inner.byte_budget)
    }

    /// At most `n` requests in flight to one host and port (0: no limit).
    pub fn max_in_flight_per_host(self, n: usize) -> Scheduler {
        Scheduler::with(self.inner.max_in_flight, n, self.inner.byte_budget)
    }

    /// No new request starts while the bytes reserved by those in flight, and its own estimate, come to more than `bytes`
    /// (0: no budget). See the module documentation for what a request reserves.
    pub fn byte_budget(self, bytes: u64) -> Scheduler {
        Scheduler::with(self.inner.max_in_flight, self.inner.max_per_host, bytes)
    }

    /// Requests in flight now.
    pub fn in_flight(&self) -> usize {
        self.lock().in_flight
    }

    /// Requests waiting to be let go (or to move to another host on a redirect).
    pub fn waiting(&self) -> usize {
        self.lock().waiters.values().filter(|w| !w.granted).count()
    }

    /// Bytes reserved by the requests in flight.
    pub fn bytes_in_flight(&self) -> u64 {
        self.lock().bytes
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.lock()
    }

    /// Lets a new request to `host` go, waiting for its turn until `until` at most (forever with `None`), or until
    /// `running` is cancelled.
    pub(crate) fn admit(&self, host: &str, cost: u64, until: Option<Instant>, running: Option<&Running>) -> Result<Ticket> {
        let id = self.inner.enqueue(host, true, cost, false);
        self.inner.wait_for(id, until, running)?;
        Ok(Ticket { sched: self.inner.clone(), host: Some(host.to_string()), bytes: cost })
    }

    /// The same for a task.
    pub(crate) async fn admit_async(&self, host: &str, cost: u64, until: Option<Instant>, running: Option<&Running>) -> Result<Ticket> {
        let id = self.inner.enqueue(host, true, cost, false);
        self.inner.wait_for_async(id, until, running).await?;
        Ok(Ticket { sched: self.inner.clone(), host: Some(host.to_string()), bytes: cost })
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // every change is a count or a queue entry made under the lock, so a panic elsewhere leaves it usable
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fits(&self, s: &State, w: &Waiter) -> bool {
        let global = !w.global || self.max_in_flight == 0 || s.in_flight < self.max_in_flight;
        let host = self.max_per_host == 0 || s.hosts.get(&w.host).copied().unwrap_or(0) < self.max_per_host;
        let bytes = !w.global || self.byte_budget == 0 || s.bytes == 0 || s.bytes.saturating_add(w.cost) <= self.byte_budget;
        global && host && bytes
    }

    /// Lets go whoever can go, host by host in turn, and wakes them.
    fn dispatch(&self, s: &mut State) {
        let mut wake: Vec<Waker> = Vec::new();
        let mut granted_any = false;
        loop {
            let mut granted = None;
            for (i, host) in s.turns.iter().enumerate() {
                let Some(&id) = s.queues.get(host).and_then(|q| q.front()) else { continue };
                if self.fits(s, &s.waiters[&id]) {
                    granted = Some((i, id));
                    break;
                }
            }
            let Some((i, id)) = granted else { break };
            let host = s.turns.remove(i).expect("a turn");
            let queue = s.queues.get_mut(&host).expect("a queue");
            queue.pop_front();
            if queue.is_empty() {
                s.queues.remove(&host);
            } else {
                // its next request waits for the host's next turn, after the others
                s.turns.push_back(host.clone());
            }
            let w = s.waiters.get_mut(&id).expect("a waiter");
            w.granted = true;
            let (global, cost) = (w.global, w.cost);
            if let Some(waker) = w.waker.take() {
                wake.push(waker);
            }
            if global {
                s.in_flight += 1;
                s.bytes += cost;
            }
            *s.hosts.entry(host).or_insert(0) += 1;
            granted_any = true;
        }
        if granted_any {
            self.changed.notify_all();
        }
        for w in wake {
            w.wake();
        }
    }

    /// Puts a request in the queue of `host` (at its front with `first`), lets go whoever can go, and gives its id.
    fn enqueue(&self, host: &str, global: bool, cost: u64, first: bool) -> u64 {
        let mut s = self.lock();
        let id = s.next_id;
        s.next_id += 1;
        s.waiters.insert(id, Waiter { host: host.to_string(), global, cost, granted: false, waker: None });
        let queue = s.queues.entry(host.to_string()).or_default();
        if first {
            queue.push_front(id);
        } else {
            queue.push_back(id);
        }
        if !s.turns.iter().any(|h| h == host) {
            s.turns.push_back(host.to_string());
        }
        self.dispatch(&mut s);
        id
    }

    /// Whether `id` has been let go (and then forgets it), or `None` if it still waits.
    fn take_grant(s: &mut State, id: u64) -> Option<()> {
        if s.waiters.get(&id)?.granted {
            s.waiters.remove(&id);
            return Some(());
        }
        None
    }

    /// Takes `id` out of the queue (it gave up); a grant that came in the meantime is given back.
    fn abandon(&self, id: u64) {
        let mut s = self.lock();
        let Some(w) = s.waiters.remove(&id) else { return };
        if w.granted {
            Inner::release(&mut s, &w.host, w.global, w.cost);
        } else if let Some(q) = s.queues.get_mut(&w.host) {
            q.retain(|x| *x != id);
            if q.is_empty() {
                s.queues.remove(&w.host);
                s.turns.retain(|h| *h != w.host);
            }
        }
        self.dispatch(&mut s);
    }

    fn release(s: &mut State, host: &str, global: bool, bytes: u64) {
        if let Some(n) = s.hosts.get_mut(host) {
            *n -= 1;
            if *n == 0 {
                s.hosts.remove(host);
            }
        }
        if global {
            s.in_flight -= 1;
            s.bytes = s.bytes.saturating_sub(bytes);
        }
    }

    fn wait_for(self: &Arc<Self>, id: u64, until: Option<Instant>, running: Option<&Running>) -> Result<()> {
        // a cancel wakes this thread through the condition variable
        let _waiting = running.map(|r| Waiting::new(r, self));
        let mut s = self.lock();
        loop {
            if Inner::take_grant(&mut s, id).is_some() {
                return Ok(());
            }
            if running.is_some_and(Running::is_cancelled) {
                drop(s);
                self.abandon(id);
                return Err(Error::Cancelled);
            }
            s = match until {
                None => self.changed.wait(s).unwrap_or_else(|e| e.into_inner()),
                Some(t) => {
                    let left = t.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        drop(s);
                        self.abandon(id);
                        return Err(waited_too_long());
                    }
                    self.changed.wait_timeout(s, left).unwrap_or_else(|e| e.into_inner()).0
                }
            };
        }
    }

    async fn wait_for_async(&self, id: u64, until: Option<Instant>, running: Option<&Running>) -> Result<()> {
        // gives the place back if the task gives up (its future is dropped) before it is let go
        struct Leave<'a> {
            inner: &'a Inner,
            id: u64,
            done: bool,
        }
        impl Drop for Leave<'_> {
            fn drop(&mut self) {
                if !self.done {
                    self.inner.abandon(self.id);
                }
            }
        }
        let mut leave = Leave { inner: self, id, done: false };
        let mut sleep = until.map(crate::asyncio::sleep_until);
        std::future::poll_fn(|cx| {
            if running.is_some_and(Running::is_cancelled) {
                return Poll::Ready(Err(Error::Cancelled));
            }
            {
                let mut s = self.lock();
                if Inner::take_grant(&mut s, id).is_some() {
                    leave.done = true;
                    return Poll::Ready(Ok(()));
                }
                if let Some(w) = s.waiters.get_mut(&id) {
                    w.waker = Some(cx.waker().clone());
                }
            }
            if let Some(r) = running {
                r.set_waker(cx.waker());
            }
            if let Some(sl) = sleep.as_mut() {
                if Pin::new(sl).poll(cx).is_ready() {
                    return Poll::Ready(Err(waited_too_long()));
                }
            }
            Poll::Pending
        })
        .await
    }
}

fn waited_too_long() -> Error {
    Error::Io(crate::asyncio::net::deadline_error())
}

/// A request's place among those in flight, given back when it is dropped (by the response, when it is over).
pub(crate) struct Ticket {
    sched: Arc<Inner>,
    /// The host it counts against (none while it moves to another).
    host: Option<String>,
    /// What it reserves now.
    bytes: u64,
}

impl Ticket {
    /// Moves to `host` (a redirect): gives the place at the old host back and waits for one at the new, ahead of the
    /// requests that have not started.
    pub(crate) fn move_to(&mut self, host: &str, until: Option<Instant>, running: Option<&Running>) -> Result<()> {
        if self.host.as_deref() == Some(host) {
            return Ok(());
        }
        self.leave_host();
        let id = self.sched.enqueue(host, false, 0, true);
        self.sched.wait_for(id, until, running)?;
        self.host = Some(host.to_string());
        Ok(())
    }

    /// The same for a task.
    pub(crate) async fn move_to_async(&mut self, host: &str, until: Option<Instant>, running: Option<&Running>) -> Result<()> {
        if self.host.as_deref() == Some(host) {
            return Ok(());
        }
        self.leave_host();
        let id = self.sched.enqueue(host, false, 0, true);
        self.sched.wait_for_async(id, until, running).await?;
        self.host = Some(host.to_string());
        Ok(())
    }

    fn leave_host(&mut self) {
        if let Some(old) = self.host.take() {
            let mut s = self.sched.lock();
            if let Some(n) = s.hosts.get_mut(&old) {
                *n -= 1;
                if *n == 0 {
                    s.hosts.remove(&old);
                }
            }
            self.sched.dispatch(&mut s);
        }
    }

    /// What the response says it will bring: its length, when the head gives one (it replaces the estimate).
    pub(crate) fn length_known(&mut self, length: u64) {
        self.set_bytes(length);
    }

    /// What has come of a body so far: the reservation grows to it if it is more.
    pub(crate) fn received(&mut self, total: u64) {
        if total > self.bytes {
            self.set_bytes(total);
        }
    }

    fn set_bytes(&mut self, bytes: u64) {
        if bytes == self.bytes {
            return;
        }
        let mut s = self.sched.lock();
        s.bytes = s.bytes.saturating_sub(self.bytes).saturating_add(bytes);
        let less = bytes < self.bytes;
        self.bytes = bytes;
        if less {
            self.sched.dispatch(&mut s);
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut s = self.sched.lock();
        match self.host.take() {
            Some(host) => Inner::release(&mut s, &host, true, self.bytes),
            None => {
                // (between two hosts: only the place among all)
                s.in_flight -= 1;
                s.bytes = s.bytes.saturating_sub(self.bytes);
            }
        }
        self.sched.dispatch(&mut s);
    }
}

// ------------------------------------------------------------------------------------------------ batches

/// Requests that share a deadline and can be cancelled together: give it to a request with
/// [`RequestBuilder::batch`](super::RequestBuilder::batch) (or [`AsyncRequestBuilder::batch`](super::AsyncRequestBuilder::batch)), or
/// to every request of a client with [`Client::in_batch`](super::Client::in_batch). Cloning it shares it. See the module
/// documentation for what a cancel does.
#[derive(Clone)]
pub struct Batch {
    inner: Arc<BatchInner>,
}

struct BatchInner {
    deadline: Option<Instant>,
    cancelled: AtomicBool,
    /// The requests under way or waiting, to stop if the batch is cancelled.
    members: Mutex<(u64, HashMap<u64, Running>)>,
}

impl fmt::Debug for Batch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batch").field("deadline", &self.inner.deadline).field("cancelled", &self.is_cancelled()).finish()
    }
}

impl Default for Batch {
    fn default() -> Batch {
        Batch::new()
    }
}

impl Batch {
    /// A batch with no deadline.
    pub fn new() -> Batch {
        Batch::make(None)
    }

    /// A batch whose requests must all be over by `deadline`.
    pub fn with_deadline(deadline: Instant) -> Batch {
        Batch::make(Some(deadline))
    }

    /// A batch whose requests must all be over within `timeout` from now.
    pub fn with_timeout(timeout: Duration) -> Batch {
        Batch::make(Instant::now().checked_add(timeout))
    }

    fn make(deadline: Option<Instant>) -> Batch {
        Batch { inner: Arc::new(BatchInner { deadline, cancelled: AtomicBool::new(false), members: Mutex::new((0, HashMap::new())) }) }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.inner.deadline
    }

    /// Fails the requests of the batch that wait, stops those under way, and fails any made from now on.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        let members: Vec<Running> = self.inner.members.lock().unwrap_or_else(|e| e.into_inner()).1.values().cloned().collect();
        for m in members {
            m.cancel();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// A new request of the batch: its control, which the batch stops if it is cancelled (at once if it already is).
    pub(crate) fn join(&self) -> Membership {
        let running = Running::new();
        let id = {
            let mut m = self.inner.members.lock().unwrap_or_else(|e| e.into_inner());
            m.0 += 1;
            let id = m.0;
            m.1.insert(id, running.clone());
            id
        };
        if self.is_cancelled() {
            running.cancel();
        }
        Membership { batch: self.clone(), id, running }
    }
}

/// A request's place in a batch, left when it is dropped.
pub(crate) struct Membership {
    batch: Batch,
    id: u64,
    pub(crate) running: Running,
}

impl Membership {
    pub(crate) fn batch(&self) -> &Batch {
        &self.batch
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        self.batch.inner.members.lock().unwrap_or_else(|e| e.into_inner()).1.remove(&self.id);
    }
}

/// How a request that is under way is stopped.
pub(crate) enum Interrupt {
    /// The socket of an HTTP/1.1 connection: shut it down.
    Socket(std::net::TcpStream),
    /// Anything else (an HTTP/2 stream): call this.
    Call(Box<dyn Fn() + Send + Sync>),
}

/// The control of one request: cancelled or not, and how to stop what it is doing now. Cloning it shares it.
#[derive(Clone)]
pub(crate) struct Running {
    inner: Arc<RunningInner>,
}

struct RunningInner {
    cancelled: AtomicBool,
    now: Mutex<RunningNow>,
}

#[derive(Default)]
struct RunningNow {
    interrupt: Option<Interrupt>,
    /// The scheduler a thread of this request waits in, to wake it.
    waits_in: Option<Arc<Inner>>,
    /// The task to wake.
    waker: Option<Waker>,
}

impl Running {
    pub(crate) fn new() -> Running {
        Running { inner: Arc::new(RunningInner { cancelled: AtomicBool::new(false), now: Mutex::new(RunningNow::default()) }) }
    }

    fn lock(&self) -> MutexGuard<'_, RunningNow> {
        self.inner.now.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Fails with [`Error::Cancelled`] if the request has been cancelled.
    pub(crate) fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        let (interrupt, waits_in, waker) = {
            let mut now = self.lock();
            (now.interrupt.take(), now.waits_in.clone(), now.waker.take())
        };
        match interrupt {
            Some(Interrupt::Socket(s)) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Some(Interrupt::Call(f)) => f(),
            None => {}
        }
        if let Some(inner) = waits_in {
            // (the waiter looks at the flag with the lock held and then sleeps: taking the lock here puts this wake-up
            // after its look, or the look after the flag)
            drop(inner.lock());
            inner.changed.notify_all();
        }
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// What stops the request now (replacing what stopped it before); if it is already cancelled, it is used at once.
    pub(crate) fn set(&self, interrupt: Interrupt) {
        self.lock().interrupt = Some(interrupt);
        if self.is_cancelled() {
            self.cancel();
        }
    }

    /// The task to wake if the request is cancelled.
    pub(crate) fn set_waker(&self, waker: &Waker) {
        let mut now = self.lock();
        if !now.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
            now.waker = Some(waker.clone());
        }
    }
}

/// While a thread of a request waits in a scheduler, a cancel wakes it; dropping this ends that.
struct Waiting<'a> {
    running: &'a Running,
}

impl<'a> Waiting<'a> {
    fn new(running: &'a Running, inner: &Arc<Inner>) -> Waiting<'a> {
        running.lock().waits_in = Some(inner.clone());
        Waiting { running }
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.running.lock().waits_in = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// The ids let go so far among `ids`.
    fn granted(s: &Scheduler, ids: &[u64]) -> Vec<u64> {
        let st = s.lock();
        ids.iter().copied().filter(|id| st.waiters.get(id).is_some_and(|w| w.granted)).collect()
    }

    /// A ticket for a waiter that has been let go.
    fn ticket(s: &Scheduler, id: u64, host: &str, cost: u64) -> Ticket {
        assert!(Inner::take_grant(&mut s.lock(), id).is_some(), "{id} was let go");
        Ticket { sched: s.inner.clone(), host: Some(host.to_string()), bytes: cost }
    }

    #[test]
    fn at_most_the_limit_in_flight_and_a_drop_lets_the_next_go() {
        let s = Scheduler::new().max_in_flight(2);
        let a = s.admit("a:443", 0, None, None).unwrap();
        let _b = s.admit("b:443", 0, None, None).unwrap();
        assert_eq!(s.in_flight(), 2);
        let s2 = s.clone();
        let waiter = thread::spawn(move || s2.admit("c:443", 0, Some(Instant::now() + Duration::from_secs(5)), None));
        while s.waiting() == 0 {
            thread::sleep(Duration::from_millis(2));
        }
        drop(a);
        let _c = waiter.join().unwrap().unwrap();
        // and one that waits too long gives up, and its place is not kept
        let t = Instant::now();
        let e = s.admit("d:443", 0, Some(t + Duration::from_millis(50)), None).err().unwrap();
        assert!(e.to_string().contains("total time limit"), "{e}");
        assert!(t.elapsed() >= Duration::from_millis(50));
        assert_eq!((s.waiting(), s.in_flight()), (0, 2));
    }

    #[test]
    fn hosts_take_turns_and_requests_keep_their_order_within_a_host() {
        let s = Scheduler::new().max_in_flight(1);
        let first = s.admit("a:443", 0, None, None).unwrap();
        let ids: Vec<u64> = ["a:443", "a:443", "a:443", "b:443", "c:443"].iter().map(|h| s.inner.enqueue(h, true, 0, false)).collect();
        assert!(granted(&s, &ids).is_empty());
        // one at a time: a, b, c, then a's next two (a's turn came first, the others' after)
        let mut order = Vec::new();
        drop(first);
        for _ in 0..5 {
            let g = granted(&s, &ids);
            assert_eq!(g.len(), 1, "one at a time");
            let id = g[0];
            order.push(ids.iter().position(|x| *x == id).unwrap());
            let host = s.lock().waiters[&id].host.clone();
            drop(ticket(&s, id, &host, 0));
        }
        assert_eq!(order, [0, 3, 4, 1, 2]);
        assert_eq!(s.in_flight(), 0);
    }

    #[test]
    fn a_host_at_its_limit_holds_up_no_other_host() {
        let s = Scheduler::new().max_in_flight(10).max_in_flight_per_host(1);
        let a1 = s.admit("a:443", 0, None, None).unwrap();
        let a2 = s.inner.enqueue("a:443", true, 0, false);
        let b1 = s.inner.enqueue("b:443", true, 0, false);
        assert_eq!(granted(&s, &[a2, b1]), [b1]);
        drop(a1);
        assert_eq!(granted(&s, &[a2, b1]), [a2, b1]);
    }

    #[test]
    fn the_byte_budget_holds_new_requests_until_what_is_reserved_comes_down() {
        let s = Scheduler::new().byte_budget(100);
        let mut big = s.admit("a:443", 60, None, None).unwrap();
        let fifty = s.inner.enqueue("a:443", true, 50, false);
        // another host's smaller request fits and goes past it
        let thirty = s.inner.enqueue("b:443", true, 30, false);
        assert_eq!(granted(&s, &[fifty, thirty]), [thirty]);
        assert_eq!(s.bytes_in_flight(), 90);
        // the head of the big one says 10 bytes: room for the fifty
        big.length_known(10);
        assert_eq!(granted(&s, &[fifty, thirty]), [fifty, thirty]);
        assert_eq!(s.bytes_in_flight(), 90);
        // a body without a length grows its reservation as it comes; a length can also be more than the estimate
        big.received(25);
        assert_eq!(s.bytes_in_flight(), 105);
        let late = s.inner.enqueue("c:443", true, 1, false);
        assert!(granted(&s, &[late]).is_empty(), "over the budget: nothing new starts");
        let t50 = ticket(&s, fifty, "a:443", 50);
        let t30 = ticket(&s, thirty, "b:443", 30);
        drop(t50);
        assert_eq!(granted(&s, &[late]), [late]);
        drop((big, t30, ticket(&s, late, "c:443", 1)));
        assert_eq!(s.bytes_in_flight(), 0);
        // with nothing reserved, a request larger than the budget still goes, alone
        let huge = s.admit("a:443", 1000, None, None).unwrap();
        let small = s.inner.enqueue("b:443", true, 1, false);
        assert!(granted(&s, &[small]).is_empty());
        drop(huge);
        assert_eq!(granted(&s, &[small]), [small]);
    }

    #[test]
    fn a_redirect_moves_to_the_other_host_ahead_of_its_queue() {
        let s = Scheduler::new().max_in_flight(10).max_in_flight_per_host(1);
        let mut t = s.admit("a:443", 0, None, None).unwrap();
        let b1 = s.admit("b:443", 0, None, None).unwrap();
        let b_new = s.inner.enqueue("b:443", true, 0, false);
        let s2 = s.clone();
        let mover = thread::spawn(move || {
            t.move_to("b:443", Some(Instant::now() + Duration::from_secs(5)), None).unwrap();
            t
        });
        while s.waiting() < 2 {
            thread::sleep(Duration::from_millis(2));
        }
        // a's place was given back at once
        assert_eq!(s.lock().hosts.get("a:443"), None);
        drop(b1);
        let t = mover.join().unwrap();
        assert!(granted(&s2, &[b_new]).is_empty(), "the redirect went first");
        assert_eq!(s.in_flight(), 1 + 0, "the redirect kept its place among all; the new one waits");
        drop(t);
        assert_eq!(granted(&s, &[b_new]), [b_new]);
    }

    #[test]
    fn a_cancelled_batch_fails_its_waiting_requests_at_once_and_new_ones_too() {
        let s = Scheduler::new().max_in_flight(1);
        let _held = s.admit("a:443", 0, None, None).unwrap();
        let batch = Batch::new();
        let m = batch.join();
        let s2 = s.clone();
        let running = m.running.clone();
        let waiter = thread::spawn(move || s2.admit("a:443", 0, None, Some(&running)).err().map(|e| e.to_string()));
        while s.waiting() == 0 {
            thread::sleep(Duration::from_millis(2));
        }
        let t = Instant::now();
        batch.cancel();
        assert_eq!(waiter.join().unwrap().as_deref(), Some("cancelled: the request's batch was cancelled"));
        assert!(t.elapsed() < Duration::from_secs(1));
        assert_eq!(s.waiting(), 0, "its place in the queue is gone");
        assert!(batch.join().running.check().is_err(), "a request made after the cancel fails");
        // an interrupt set after the cancel is used at once
        let (a, b) = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let a = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
            (a, l.accept().unwrap().0)
        };
        m.running.set(Interrupt::Socket(a.try_clone().unwrap()));
        let mut buf = [0u8; 1];
        use std::io::Read;
        assert_eq!((&a).read(&mut buf).unwrap_or(0), 0, "the socket was shut down");
        drop(b);
    }

    #[test]
    fn a_task_waits_for_its_turn_and_a_dropped_one_gives_its_place_back() {
        let s = Scheduler::new().max_in_flight(1);
        let held = s.admit("a:443", 0, None, None).unwrap();
        let s2 = s.clone();
        let task = thread::spawn(move || crate::asyncio::block_on(s2.admit_async("b:443", 0, None, None)).map(|_| ()));
        while s.waiting() == 0 {
            thread::sleep(Duration::from_millis(2));
        }
        drop(held);
        task.join().unwrap().unwrap();
        assert_eq!(s.in_flight(), 0);
        // a future polled once and dropped
        let held = s.admit("a:443", 0, None, None).unwrap();
        {
            let mut fut = Box::pin(s.admit_async("b:443", 0, None, None));
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            assert!(fut.as_mut().poll(&mut cx).is_pending());
            assert_eq!(s.waiting(), 1);
        }
        assert_eq!(s.waiting(), 0);
        drop(held);
        assert_eq!(s.in_flight(), 0);
        // a cancel wakes a task that waits
        let held = s.admit("a:443", 0, None, None).unwrap();
        let batch = Batch::new();
        let m = batch.join();
        let (s2, r) = (s.clone(), m.running.clone());
        let task = thread::spawn(move || crate::asyncio::block_on(s2.admit_async("b:443", 0, None, Some(&r))).err().map(|e| e.to_string()));
        while s.waiting() == 0 {
            thread::sleep(Duration::from_millis(2));
        }
        batch.cancel();
        assert!(task.join().unwrap().unwrap().contains("cancelled"));
        assert_eq!(s.waiting(), 0);
        drop(held);
    }
}
