//! Timers for async code, without a runtime: [`sleep`], [`timeout`] and [`Timed`], an adapter that puts read and write
//! timeouts and an overall deadline on any [`AsyncRead`] + [`AsyncWrite`] stream.
//!
//! One thread (started the first time a timer waits, and named `pratique timer`) keeps a heap of deadlines and wakes each
//! timer's task when its time comes. The futures use only `std::task::Waker`, so they work with any executor. A timer is
//! never early (it checks the clock itself when polled) and is late by however long the thread takes to be scheduled. A timer
//! that is dropped before its time is forgotten. If the thread cannot be started, timers are due at once rather than never.

use super::io::{AsyncRead, AsyncWrite};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------------------------------ the timer thread

struct Timers {
    state: Mutex<State>,
    changed: Condvar,
}

struct State {
    /// (deadline, id) of every timer that is waiting, and of some that were dropped since (they are skipped, and cleared out
    /// when they are more than half of the heap).
    heap: BinaryHeap<Reverse<(Instant, u64)>>,
    /// The timers that are waiting: their deadline and whom to wake.
    waiting: HashMap<u64, (Instant, Waker)>,
    next_id: u64,
    /// Whether the thread is running; `None` until the first timer, `Some(false)` if it could not be started.
    thread: Option<bool>,
}

fn timers() -> &'static Timers {
    static TIMERS: OnceLock<Timers> = OnceLock::new();
    TIMERS.get_or_init(|| Timers {
        state: Mutex::new(State { heap: BinaryHeap::new(), waiting: HashMap::new(), next_id: 0, thread: None }),
        changed: Condvar::new(),
    })
}

impl Timers {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a timer; `None` if there is no thread to fire it (the caller then treats the timer as due).
    fn register(&'static self, deadline: Instant, waker: &Waker) -> Option<u64> {
        let mut s = self.lock();
        if s.thread.is_none() {
            let started = thread::Builder::new().name("pratique timer".into()).spawn(move || self.run()).is_ok();
            s.thread = Some(started);
        }
        if s.thread != Some(true) {
            return None;
        }
        let id = s.next_id;
        s.next_id += 1;
        let earliest = s.heap.peek().map(|Reverse((t, _))| *t);
        s.heap.push(Reverse((deadline, id)));
        s.waiting.insert(id, (deadline, waker.clone()));
        if s.heap.len() > 64 && s.heap.len() > 2 * s.waiting.len() {
            // mostly dropped timers: build the heap again from the ones that wait
            s.heap = s.waiting.iter().map(|(&id, &(t, _))| Reverse((t, id))).collect();
        }
        drop(s);
        if earliest.is_none_or(|t| deadline < t) {
            self.changed.notify_one();
        }
        Some(id)
    }

    /// Who to wake for a timer that is waiting; false if it has fired (or was never there).
    fn update(&self, id: u64, waker: &Waker) -> bool {
        match self.lock().waiting.get_mut(&id) {
            Some((_, w)) => {
                if !w.will_wake(waker) {
                    *w = waker.clone();
                }
                true
            }
            None => false,
        }
    }

    fn cancel(&self, id: u64) {
        self.lock().waiting.remove(&id);
    }

    fn run(&self) {
        let mut due: Vec<Waker> = Vec::new();
        let mut s = self.lock();
        loop {
            let now = Instant::now();
            let mut next: Option<Instant> = None;
            while let Some(&Reverse((t, id))) = s.heap.peek() {
                if !s.waiting.contains_key(&id) {
                    s.heap.pop();
                } else if t <= now {
                    s.heap.pop();
                    if let Some((_, w)) = s.waiting.remove(&id) {
                        due.push(w);
                    }
                } else {
                    next = Some(t);
                    break;
                }
            }
            if !due.is_empty() {
                // woken without the lock held, so that the woken tasks can poll (and register again) at once
                drop(s);
                for w in due.drain(..) {
                    w.wake();
                }
                s = self.lock();
                continue;
            }
            s = match next {
                Some(t) => self.changed.wait_timeout(s, t.saturating_duration_since(now)).unwrap_or_else(|e| e.into_inner()).0,
                None => self.changed.wait(s).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }
}

// ------------------------------------------------------------------------------------------------ sleep

/// A future that is ready at a point in time; see [`sleep`] and [`sleep_until`].
#[must_use = "a timer does nothing unless it is awaited or polled"]
pub struct Sleep {
    deadline: Instant,
    id: Option<u64>,
}

/// A future that is ready `duration` from now.
pub fn sleep(duration: Duration) -> Sleep {
    sleep_until(Instant::now().checked_add(duration).unwrap_or_else(far_future))
}

/// A future that is ready at `deadline` (at once if that has passed).
pub fn sleep_until(deadline: Instant) -> Sleep {
    Sleep { deadline, id: None }
}

/// About thirty years from now: what a duration too long for `Instant` stands for.
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400 * 365 * 30)
}

impl Sleep {
    /// When it is ready.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Whether its time has come.
    pub fn is_elapsed(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Moves it to another point in time (before or after the one it had).
    pub fn reset(&mut self, deadline: Instant) {
        if let Some(id) = self.id.take() {
            timers().cancel(id);
        }
        self.deadline = deadline;
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            if let Some(id) = self.id.take() {
                timers().cancel(id);
            }
            return Poll::Ready(());
        }
        match self.id {
            Some(id) if timers().update(id, cx.waker()) => Poll::Pending,
            _ => match timers().register(self.deadline, cx.waker()) {
                Some(id) => {
                    self.id = Some(id);
                    Poll::Pending
                }
                // no thread to fire it: due now, rather than never
                None => Poll::Ready(()),
            },
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            timers().cancel(id);
        }
    }
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sleep").field("deadline", &self.deadline).finish()
    }
}

// ------------------------------------------------------------------------------------------------ timeout

/// What [`timeout`] gives when the time ran out first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed(pub(crate) ());

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the time limit was reached")
    }
}

impl std::error::Error for Elapsed {}

impl From<Elapsed> for io::Error {
    fn from(e: Elapsed) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, e)
    }
}

/// A future with a time limit; see [`timeout`].
#[must_use = "a timeout does nothing unless it is awaited or polled"]
pub struct Timeout<F> {
    future: Pin<Box<F>>,
    sleep: Sleep,
}

/// Runs `future` for at most `duration`: its output, or [`Elapsed`] if the time ran out first (the future is then dropped
/// when the `Timeout` is).
pub fn timeout<F: Future>(duration: Duration, future: F) -> Timeout<F> {
    Timeout { future: Box::pin(future), sleep: sleep(duration) }
}

/// [`timeout`] with a point in time instead of a duration.
pub fn timeout_at<F: Future>(deadline: Instant, future: F) -> Timeout<F> {
    Timeout { future: Box::pin(future), sleep: sleep_until(deadline) }
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // the future first: one that is ready when the time is up still counts
        if let Poll::Ready(v) = self.future.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        match Pin::new(&mut self.sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed(()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ------------------------------------------------------------------------------------------------ Timed

/// An [`AsyncRead`] + [`AsyncWrite`] stream with time limits: a read that waits longer than the read timeout for its first
/// byte, a write (or flush, or close) that waits longer than the write timeout, or anything after the deadline, fails with
/// `io::ErrorKind::TimedOut`. A limit counts the time one call waits, as a socket's timeouts do, so a stream that keeps moving
/// never times out however long it runs (the deadline is what bounds that). Without limits it is the stream as it is.
pub struct Timed<S> {
    inner: S,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    deadline: Option<Instant>,
    reading: Option<Waiting>,
    writing: Option<Waiting>,
    /// The slot of a per-host connection limit that the stream holds while it is open (the async client's; see
    /// `Client::max_connections_per_host`).
    permit: Option<super::slots::Permit>,
}

/// The timer of a call that is waiting, and whether it stands for the deadline (or for the call's own limit).
struct Waiting {
    sleep: Sleep,
    at_deadline: bool,
}

impl<S> Timed<S> {
    /// `inner` with no limits yet.
    pub fn new(inner: S) -> Timed<S> {
        Timed { inner, read_timeout: None, write_timeout: None, deadline: None, reading: None, writing: None, permit: None }
    }

    /// The longest one read may wait.
    pub fn with_read_timeout(mut self, t: Duration) -> Timed<S> {
        self.read_timeout = Some(t);
        self
    }

    /// The longest one write, flush or close may wait.
    pub fn with_write_timeout(mut self, t: Duration) -> Timed<S> {
        self.write_timeout = Some(t);
        self
    }

    /// When everything has to be over.
    pub fn with_deadline(mut self, deadline: Instant) -> Timed<S> {
        self.deadline = Some(deadline);
        self
    }

    /// Replaces all three limits (`None`: no limit): for a stream that is used again for something else.
    pub fn set_limits(&mut self, read_timeout: Option<Duration>, write_timeout: Option<Duration>, deadline: Option<Instant>) {
        self.read_timeout = read_timeout;
        self.write_timeout = write_timeout;
        self.deadline = deadline;
        self.reading = None;
        self.writing = None;
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The stream without its limits (and without the connection slot it held, if any, which is given back).
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Holds `permit` for as long as the stream lives.
    pub(crate) fn hold(&mut self, permit: Option<super::slots::Permit>) {
        self.permit = permit;
    }
}

/// The error of a call that waited too long.
fn timed_out(at_deadline: bool, what: &str, limit: Option<Duration>) -> io::Error {
    if at_deadline {
        super::net::deadline_error()
    } else {
        io::Error::new(io::ErrorKind::TimedOut, format!("no progress on a {what} within {:?}", limit.unwrap_or_default()))
    }
}

/// Polls `op`. When it starts to wait, a timer starts for the nearer of its own limit and the deadline; a call that is still
/// waiting when the timer is due fails. Past the deadline nothing more starts.
fn poll_limited<T>(
    slot: &mut Option<Waiting>,
    per_call: Option<Duration>,
    deadline: Option<Instant>,
    cx: &mut Context<'_>,
    what: &str,
    op: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
) -> Poll<io::Result<T>> {
    if slot.is_none() && deadline.is_some_and(|d| Instant::now() >= d) {
        return Poll::Ready(Err(timed_out(true, what, per_call)));
    }
    match op(cx) {
        Poll::Ready(r) => {
            *slot = None;
            Poll::Ready(r)
        }
        Poll::Pending => {
            if slot.is_none() {
                let call = per_call.and_then(|t| Instant::now().checked_add(t));
                let chosen = match (call, deadline) {
                    (Some(c), Some(d)) if d <= c => Some((d, true)),
                    (Some(c), _) => Some((c, false)),
                    (None, Some(d)) => Some((d, true)),
                    (None, None) => None,
                };
                let Some((t, at_deadline)) = chosen else { return Poll::Pending };
                *slot = Some(Waiting { sleep: sleep_until(t), at_deadline });
            }
            let waiting = slot.as_mut().expect("a timer");
            match Pin::new(&mut waiting.sleep).poll(cx) {
                Poll::Ready(()) => {
                    let at_deadline = waiting.at_deadline;
                    *slot = None;
                    Poll::Ready(Err(timed_out(at_deadline, what, per_call)))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Timed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let inner = &mut this.inner;
        poll_limited(&mut this.reading, this.read_timeout, this.deadline, cx, "read", |cx| Pin::new(inner).poll_read(cx, buf))
    }
}

impl<S: AsyncWrite + Unpin> Timed<S> {
    fn poll_write_side<T>(&mut self, cx: &mut Context<'_>, what: &str, op: impl FnOnce(&mut S, &mut Context<'_>) -> Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        let inner = &mut self.inner;
        poll_limited(&mut self.writing, self.write_timeout, self.deadline, cx, what, |cx| op(inner, cx))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Timed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_side(cx, "write", |s, cx| Pin::new(s).poll_write(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_side(cx, "flush", |s, cx| Pin::new(s).poll_flush(cx))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_side(cx, "close", |s, cx| Pin::new(s).poll_close(cx))
    }
}

impl<S: fmt::Debug> fmt::Debug for Timed<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timed")
            .field("inner", &self.inner)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("deadline", &self.deadline)
            .finish()
    }
}
