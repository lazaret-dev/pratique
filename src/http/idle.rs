//! Idle connections kept for the next request (HTTP/1.1 keep-alive).
//!
//! A [`Key`] names what two requests must share to share a connection: scheme, host, port and the
//! proxy it is tunnelled through. A finished exchange whose connection is fit for another request
//! parks it with [`IdlePool::put`]; the next request to the same place asks for it with
//! [`IdlePool::take`], which hands out the most recently parked one first (the newest connection is
//! the least likely to have been closed by the server) and drops the ones that have been idle for
//! too long. There is no timer thread: expired connections are dropped when the pool is next used.
//!
//! The pool is generic over the connection type, so the blocking client and the async client share
//! it. A connection is never dropped while the lock is held: closing one writes to the network.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What two requests must have in common to use the same connection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The proxy a TLS tunnel goes through: host, port and credentials.
    pub(crate) proxy: Option<(String, u16, Option<String>)>,
    /// The oldest TLS version the requests that may use the connection accept: a connection made for a request that allows
    /// TLS 1.2 is never given to one that requires 1.3 (it may have become a TLS 1.2 one).
    pub(crate) min_tls: crate::tls::TlsVersion,
}

/// How much is kept and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// Keep connections at all. When false, requests say `Connection: close` and nothing is parked.
    pub(crate) keep_alive: bool,
    /// How long a connection may wait for another request.
    pub(crate) idle_timeout: Duration,
    /// Most idle connections kept for one [`Key`]; 0 turns reuse off.
    pub(crate) max_idle_per_host: usize,
    /// Most idle connections kept in all.
    pub(crate) max_idle_total: usize,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy { keep_alive: true, idle_timeout: Duration::from_secs(90), max_idle_per_host: 8, max_idle_total: 64 }
    }
}

impl Policy {
    /// True if finished connections should be parked.
    pub(crate) fn parks(&self) -> bool {
        self.keep_alive && self.max_idle_per_host > 0 && self.max_idle_total > 0 && !self.idle_timeout.is_zero()
    }
}

struct Idle<T> {
    conn: T,
    parked: Instant,
    expires: Instant,
}

struct Inner<T> {
    hosts: HashMap<Key, VecDeque<Idle<T>>>,
    total: usize,
}

/// The idle connections of a client, shared by its clones and by the threads that use them.
pub(crate) struct IdlePool<T> {
    inner: Mutex<Inner<T>>,
}

impl<T> IdlePool<T> {
    pub(crate) fn new() -> IdlePool<T> {
        IdlePool { inner: Mutex::new(Inner { hosts: HashMap::new(), total: 0 }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        // a panic elsewhere must not take the whole client down with it: the data is a list of
        // connections, and every one is checked before it is used
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The most recently parked connection for `key` that has not expired at `now`. Expired ones
    /// for the key are dropped.
    pub(crate) fn take(&self, key: &Key, now: Instant) -> Option<T> {
        let (found, expired) = {
            let mut inner = self.lock();
            let Some(list) = inner.hosts.get_mut(key) else { return None };
            let mut expired = Vec::new();
            let mut i = 0;
            while i < list.len() {
                if list[i].expires <= now {
                    expired.extend(list.remove(i).map(|e| e.conn));
                } else {
                    i += 1;
                }
            }
            let found = list.pop_back().map(|e| e.conn);
            let removed = expired.len() + usize::from(found.is_some());
            if list.is_empty() {
                inner.hosts.remove(key);
            }
            inner.total -= removed;
            (found, expired)
        };
        drop(expired);
        found
    }

    /// Parks `conn` for `key` for `idle_for` (but never longer than the policy's idle timeout), then
    /// drops whatever the limits no longer allow: the oldest of the key's connections beyond the
    /// per-host limit, and the oldest of all beyond the total limit.
    pub(crate) fn put(&self, key: Key, conn: T, idle_for: Duration, policy: &Policy, now: Instant) {
        let idle_for = idle_for.min(policy.idle_timeout);
        let Some(expires) = now.checked_add(idle_for) else { return };
        let mut dropped = Vec::new();
        {
            let mut inner = self.lock();
            let list = inner.hosts.entry(key).or_default();
            list.push_back(Idle { conn, parked: now, expires });
            while list.len() > policy.max_idle_per_host {
                dropped.extend(list.pop_front().map(|e| e.conn));
            }
            inner.total += 1;
            inner.total -= dropped.len();
            while inner.total > policy.max_idle_total {
                // the oldest parked connection of any key
                let oldest = inner.hosts.iter().filter_map(|(k, l)| l.front().map(|e| (e.parked, k.clone()))).min_by_key(|(p, _)| *p);
                let Some((_, k)) = oldest else { break };
                if let Some(list) = inner.hosts.get_mut(&k) {
                    dropped.extend(list.pop_front().map(|e| e.conn));
                    if list.is_empty() {
                        inner.hosts.remove(&k);
                    }
                }
                inner.total -= 1;
            }
        }
        drop(dropped);
    }

    /// The connection to `host:port` (of any key but `keep`) that has been parked the longest: the one to close when a
    /// per-host connection limit needs room. A connection of `keep`, the key of the request that wants the room, is never
    /// taken: one that has just been parked is for that request to use, not to close (BACKLOG B-105).
    pub(crate) fn take_oldest_to(&self, host: &str, port: u16, keep: Option<&Key>) -> Option<T> {
        let mut inner = self.lock();
        let key = inner
            .hosts
            .iter()
            .filter(|(k, _)| k.host == host && k.port == port && Some(*k) != keep)
            .filter_map(|(k, l)| l.front().map(|e| (e.parked, k.clone())))
            .min_by_key(|(p, _)| *p)
            .map(|(_, k)| k)?;
        let list = inner.hosts.get_mut(&key)?;
        let found = list.pop_front().map(|e| e.conn);
        if list.is_empty() {
            inner.hosts.remove(&key);
        }
        inner.total -= usize::from(found.is_some());
        found
    }

    /// Drops every idle connection.
    pub(crate) fn clear(&self) {
        let all: Vec<VecDeque<Idle<T>>> = {
            let mut inner = self.lock();
            inner.total = 0;
            inner.hosts.drain().map(|(_, l)| l).collect()
        };
        drop(all);
    }

    /// How many connections are parked.
    pub(crate) fn len(&self) -> usize {
        self.lock().total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A connection that counts how many have been dropped.
    struct Conn {
        id: usize,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn key(host: &str) -> Key {
        Key { tls: true, host: host.to_string(), port: 443, proxy: None, min_tls: crate::tls::TlsVersion::Tls12 }
    }

    fn policy() -> Policy {
        Policy::default()
    }

    const SECOND: Duration = Duration::from_secs(1);

    fn fixture() -> (IdlePool<Conn>, Arc<AtomicUsize>, Instant) {
        (IdlePool::new(), Arc::new(AtomicUsize::new(0)), Instant::now())
    }

    fn conn(id: usize, dropped: &Arc<AtomicUsize>) -> Conn {
        Conn { id, dropped: dropped.clone() }
    }

    #[test]
    fn the_newest_parked_connection_comes_out_first() {
        let (pool, dropped, t0) = fixture();
        for id in 1..=3 {
            pool.put(key("a"), conn(id, &dropped), 60 * SECOND, &policy(), t0 + SECOND * id as u32);
        }
        assert_eq!(pool.len(), 3);
        let now = t0 + 10 * SECOND;
        assert_eq!(pool.take(&key("a"), now).map(|c| c.id), Some(3));
        assert_eq!(pool.take(&key("a"), now).map(|c| c.id), Some(2));
        assert_eq!(pool.take(&key("a"), now).map(|c| c.id), Some(1));
        assert!(pool.take(&key("a"), now).is_none());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn a_connection_is_only_for_the_key_it_was_parked_under() {
        let (pool, dropped, t0) = fixture();
        pool.put(key("a"), conn(1, &dropped), 60 * SECOND, &policy(), t0);
        for other in [key("b"), Key { tls: false, ..key("a") }, Key { port: 8443, ..key("a") }, Key { proxy: Some(("p".into(), 3128, None)), ..key("a") }] {
            assert!(pool.take(&other, t0).is_none(), "{other:?}");
        }
        // a proxy with other credentials is another place
        pool.put(Key { proxy: Some(("p".into(), 3128, Some("u:1".into()))), ..key("a") }, conn(2, &dropped), 60 * SECOND, &policy(), t0);
        assert!(pool.take(&Key { proxy: Some(("p".into(), 3128, Some("u:2".into()))), ..key("a") }, t0).is_none());
        assert_eq!(pool.take(&key("a"), t0).map(|c| c.id), Some(1));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_oldest_connection_to_a_host_of_any_key_can_be_taken_to_make_room() {
        let (pool, dropped, t0) = fixture();
        pool.put(key("a"), conn(1, &dropped), 60 * SECOND, &policy(), t0 + SECOND);
        pool.put(Key { min_tls: crate::tls::TlsVersion::Tls13, ..key("a") }, conn(2, &dropped), 60 * SECOND, &policy(), t0);
        pool.put(key("b"), conn(3, &dropped), 60 * SECOND, &policy(), t0);
        pool.put(Key { port: 8443, ..key("a") }, conn(4, &dropped), 60 * SECOND, &policy(), t0);
        // not the key of the request that wants the room: that one it would use
        assert!(pool.take_oldest_to("a", 443, Some(&Key { min_tls: crate::tls::TlsVersion::Tls13, ..key("a") })).is_some_and(|c| c.id == 1));
        pool.put(key("a"), conn(1, &dropped), 60 * SECOND, &policy(), t0 + SECOND);
        assert_eq!(pool.take_oldest_to("a", 443, None).map(|c| c.id), Some(2));
        assert!(pool.take_oldest_to("a", 443, Some(&key("a"))).is_none());
        assert_eq!(pool.take_oldest_to("a", 443, None).map(|c| c.id), Some(1));
        assert!(pool.take_oldest_to("a", 443, None).is_none());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn an_expired_connection_is_dropped_not_handed_out() {
        let (pool, dropped, t0) = fixture();
        pool.put(key("a"), conn(1, &dropped), 10 * SECOND, &policy(), t0);
        pool.put(key("a"), conn(2, &dropped), 100 * SECOND, &policy(), t0 + SECOND);
        // at exactly the expiry the connection is no longer good
        let taken = pool.take(&key("a"), t0 + 10 * SECOND).expect("the second connection is still good");
        assert_eq!(taken.id, 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 1, "the expired one was dropped");
        assert_eq!(pool.len(), 0);
        // an expiry in the middle of the list is found too, whichever end the newer one is on
        pool.put(key("b"), conn(3, &dropped), 100 * SECOND, &policy(), t0);
        pool.put(key("b"), conn(4, &dropped), 5 * SECOND, &policy(), t0 + SECOND);
        let taken = pool.take(&key("b"), t0 + 20 * SECOND).expect("the first of b's connections is still good");
        assert_eq!(taken.id, 3);
        assert_eq!(dropped.load(Ordering::SeqCst), 2, "the expired one of b was dropped");
    }

    #[test]
    fn the_policy_caps_how_long_a_server_may_ask_for() {
        let (pool, dropped, t0) = fixture();
        let p = Policy { idle_timeout: 30 * SECOND, ..policy() };
        pool.put(key("a"), conn(1, &dropped), 3600 * SECOND, &p, t0);
        assert!(pool.take(&key("a"), t0 + 31 * SECOND).is_none());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        // a connection parked "for ever" must not overflow the clock either
        pool.put(key("a"), conn(2, &dropped), Duration::MAX, &Policy { idle_timeout: Duration::MAX, ..p }, t0);
        assert!(pool.len() <= 1);
    }

    #[test]
    fn the_per_host_limit_drops_the_oldest() {
        let (pool, dropped, t0) = fixture();
        let p = Policy { max_idle_per_host: 2, ..policy() };
        for id in 1..=4 {
            pool.put(key("a"), conn(id, &dropped), 60 * SECOND, &p, t0 + SECOND * id as u32);
        }
        assert_eq!(pool.len(), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(pool.take(&key("a"), t0 + 9 * SECOND).map(|c| c.id), Some(4));
        assert_eq!(pool.take(&key("a"), t0 + 9 * SECOND).map(|c| c.id), Some(3));
    }

    #[test]
    fn the_total_limit_drops_the_oldest_of_all_hosts() {
        let (pool, dropped, t0) = fixture();
        let p = Policy { max_idle_total: 3, ..policy() };
        pool.put(key("a"), conn(1, &dropped), 60 * SECOND, &p, t0);
        pool.put(key("b"), conn(2, &dropped), 60 * SECOND, &p, t0 + SECOND);
        pool.put(key("a"), conn(3, &dropped), 60 * SECOND, &p, t0 + 2 * SECOND);
        pool.put(key("c"), conn(4, &dropped), 60 * SECOND, &p, t0 + 3 * SECOND);
        assert_eq!(pool.len(), 3);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let now = t0 + 4 * SECOND;
        assert_eq!(pool.take(&key("a"), now).map(|c| c.id), Some(3), "the older of a's two was the one dropped");
        assert!(pool.take(&key("a"), now).is_none());
        assert_eq!(pool.take(&key("b"), now).map(|c| c.id), Some(2));
        assert_eq!(pool.take(&key("c"), now).map(|c| c.id), Some(4));
    }

    #[test]
    fn clear_drops_everything() {
        let (pool, dropped, t0) = fixture();
        for (i, h) in ["a", "b", "c"].iter().enumerate() {
            pool.put(key(h), conn(i, &dropped), 60 * SECOND, &policy(), t0);
        }
        pool.clear();
        assert_eq!(pool.len(), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 3);
        assert!(pool.take(&key("a"), t0).is_none());
    }

    #[test]
    fn nothing_is_parked_when_the_policy_says_no() {
        assert!(policy().parks());
        for off in [
            Policy { keep_alive: false, ..policy() },
            Policy { max_idle_per_host: 0, ..policy() },
            Policy { max_idle_total: 0, ..policy() },
            Policy { idle_timeout: Duration::ZERO, ..policy() },
        ] {
            assert!(!off.parks(), "{off:?}");
        }
    }

    #[test]
    fn a_connection_is_never_closed_while_the_lock_is_held() {
        // closing a connection writes to the network, which must not happen under the lock: a Drop
        // that uses the pool would otherwise deadlock
        struct Reentrant {
            pool: Arc<IdlePool<Reentrant>>,
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                let _ = self.pool.len();
            }
        }
        let pool = Arc::new(IdlePool::new());
        let t0 = Instant::now();
        let p = Policy { max_idle_per_host: 1, max_idle_total: 1, ..policy() };
        for _ in 0..3 {
            pool.put(key("a"), Reentrant { pool: pool.clone() }, 60 * SECOND, &p, t0);
        }
        pool.put(key("b"), Reentrant { pool: pool.clone() }, 1 * SECOND, &p, t0);
        assert!(pool.take(&key("b"), t0 + 5 * SECOND).is_none());
        pool.clear();
    }

    #[test]
    fn threads_share_one_pool() {
        let pool = Arc::new(IdlePool::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let t0 = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let (pool, dropped) = (pool.clone(), dropped.clone());
                std::thread::spawn(move || {
                    for i in 0..500 {
                        pool.put(key("a"), conn(t * 1000 + i, &dropped), 60 * SECOND, &policy(), t0);
                        let _ = pool.take(&key("a"), t0);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        pool.clear();
        assert_eq!(pool.len(), 0);
        // every connection that was put in was either taken out (and dropped here) or dropped by the pool
        assert!(dropped.load(Ordering::SeqCst) <= 4000);
    }
}
