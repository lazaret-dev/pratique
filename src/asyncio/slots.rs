//! Counted slots per key, for threads and for tasks (BACKLOG B-48: the per-host connection limit of the clients).
//!
//! At most `max` slots of one key are held at a time; each is a [`Permit`], given back when it is dropped. A thread that
//! finds none free waits on a condition variable ([`Slots::wait`]), a task on its waker ([`Slots::changed`]); both are
//! woken by every release and by every [`poke`](Slots::poke), which a client calls when something else a waiter may use
//! has turned up (a connection parked in its pool). A waiter is told only that something changed, and looks again: the
//! slot it hoped for may have gone to another, so there is no promise of order between waiters.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

pub(crate) struct Slots {
    max: usize,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    held: HashMap<String, usize>,
    /// Moves on with every release and every poke: a waiter that saw one value and sees another knows that something changed.
    generation: u64,
    /// The tasks waiting for the next change.
    wakers: Vec<Waker>,
}

/// One slot of one key, held until it is dropped.
pub(crate) struct Permit {
    slots: Arc<Slots>,
    key: String,
}

impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit").field("key", &self.key).finish()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut s = self.slots.lock();
        if let Some(n) = s.held.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                s.held.remove(&self.key);
            }
        }
        self.slots.wake(s);
    }
}

impl Slots {
    /// Slots for at most `max` holders per key (at least one).
    pub(crate) fn new(max: usize) -> Arc<Slots> {
        Arc::new(Slots { max: max.max(1), state: Mutex::new(State::default()), changed: Condvar::new() })
    }

    pub(crate) fn max(&self) -> usize {
        self.max
    }

    /// How many of `key`'s slots are held now.
    #[cfg(test)]
    pub(crate) fn held(&self, key: &str) -> usize {
        self.lock().held.get(key).copied().unwrap_or(0)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // every change is one count or one push, so a panic elsewhere leaves the state consistent
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Moves the generation on and wakes every waiter, thread or task.
    fn wake(&self, mut s: MutexGuard<'_, State>) {
        s.generation = s.generation.wrapping_add(1);
        let wakers = std::mem::take(&mut s.wakers);
        drop(s);
        self.changed.notify_all();
        for w in wakers {
            w.wake();
        }
    }

    /// A slot of `key` if one is free; if not, the generation to wait on.
    pub(crate) fn try_take(self: &Arc<Self>, key: &str) -> Result<Permit, u64> {
        let mut s = self.lock();
        let n = s.held.entry(key.to_string()).or_insert(0);
        if *n < self.max {
            *n += 1;
            return Ok(Permit { slots: self.clone(), key: key.to_string() });
        }
        Err(s.generation)
    }

    /// Something a waiter may use turned up: every waiter looks again.
    pub(crate) fn poke(&self) {
        let s = self.lock();
        self.wake(s);
    }

    /// Waits on this thread until something changes after generation `seen`, or until `until`: false if that came first.
    pub(crate) fn wait(&self, seen: u64, until: Option<Instant>) -> bool {
        let mut s = self.lock();
        while s.generation == seen {
            match until {
                None => s = self.changed.wait(s).unwrap_or_else(|e| e.into_inner()),
                Some(t) => {
                    let left = t.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    s = self.changed.wait_timeout(s, left).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
        }
        true
    }

    /// Waits in a task until something changes after generation `seen` (with no limit of its own: the caller puts one
    /// around it).
    pub(crate) fn changed(self: &Arc<Self>, seen: u64) -> Changed {
        Changed { slots: self.clone(), seen }
    }
}

/// The future of [`Slots::changed`].
pub(crate) struct Changed {
    slots: Arc<Slots>,
    seen: u64,
}

impl Future for Changed {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut s = self.slots.lock();
        if s.generation != self.seen {
            return Poll::Ready(());
        }
        if !s.wakers.iter().any(|w| w.will_wake(cx.waker())) {
            s.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn at_most_max_per_key_and_a_drop_gives_one_back() {
        let s = Slots::new(2);
        let a = s.try_take("a:443").unwrap();
        let _b = s.try_take("a:443").unwrap();
        let seen = s.try_take("a:443").unwrap_err();
        // another key is counted apart
        let _c = s.try_take("b:443").unwrap();
        assert_eq!((s.held("a:443"), s.held("b:443"), s.held("c:443")), (2, 1, 0));
        drop(a);
        assert_eq!(s.held("a:443"), 1);
        assert!(s.wait(seen, Some(Instant::now())), "the release moved the generation on");
        assert!(s.try_take("a:443").is_ok());
        assert_eq!(Slots::new(0).max(), 1);
    }

    #[test]
    fn a_waiting_thread_is_woken_by_a_release_or_a_poke_and_gives_up_at_its_limit() {
        let s = Slots::new(1);
        let held = s.try_take("h").unwrap();
        let seen = s.try_take("h").unwrap_err();
        let t = Instant::now();
        assert!(!s.wait(seen, Some(t + Duration::from_millis(50))));
        assert!(t.elapsed() >= Duration::from_millis(50));
        let s2 = s.clone();
        let waiter = std::thread::spawn(move || {
            let r = s2.wait(seen, Some(Instant::now() + Duration::from_secs(10)));
            (r, s2.try_take("h").is_ok())
        });
        std::thread::sleep(Duration::from_millis(30));
        drop(held);
        assert_eq!(waiter.join().unwrap(), (true, true));
        // a poke wakes without a slot coming free
        let _held = s.try_take("h").unwrap();
        let seen = s.try_take("h").unwrap_err();
        let s2 = s.clone();
        let waiter = std::thread::spawn(move || s2.wait(seen, None));
        std::thread::sleep(Duration::from_millis(30));
        s.poke();
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn a_waiting_task_is_woken_by_a_release() {
        let s = Slots::new(1);
        let held = s.try_take("h").unwrap();
        let seen = s.try_take("h").unwrap_err();
        let s2 = s.clone();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(held);
        });
        crate::asyncio::block_on(s2.changed(seen));
        release.join().unwrap();
        let _held = s.try_take("h").unwrap();
        // a change that came before the wait is not missed
        let seen = s.try_take("h").unwrap_err();
        s.poke();
        crate::asyncio::block_on(s.changed(seen));
    }
}
