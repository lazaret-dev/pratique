//! TLS 1.3 session resumption (RFC 8446 sections 2.2, 4.2.11 and 4.6.1; BACKLOG B-35 and B-47): the tickets a server
//! sends after a handshake are kept, per server name, and the next connection to that server offers one, which spares
//! the server's certificate chain, its check and the server's signature, and a round of public-key work.
//!
//! What is kept and how it is used:
//!
//! * **Tickets come from full TLS 1.3 handshakes** (and from connections resumed from those); TLS 1.2 and QUIC
//!   connections neither keep nor offer any.
//! * **A ticket is used once** (RFC 8446 appendix C.4): it is taken out of the store when it is offered. At most four
//!   are kept per server and 256 servers in all; the oldest go first.
//! * **A session lives as long as the server says (at most seven days), and no longer than [`Resumption::max_age`]
//!   after the certificate check it rests on** (one hour by default). A ticket that arrives on a resumed connection
//!   inherits the time of the original check, so a chain of resumptions never extends it: after `max_age` the next
//!   connection makes a full handshake and checks the chain (and its revocation) again.
//! * **A session is offered only to a connection whose configuration would have accepted it**: the same trust store
//!   (the same `Arc`), the same certificate verification switch and the same revocation mode. Clones of a
//!   [`ClientConfig`](super::ClientConfig) share one store, which is how the connections of one HTTP client share it.
//! * The key exchange is always fresh (`psk_dhe_ke` only): resumption without a new X25519 or ECDHE share would lose
//!   forward secrecy. No 0-RTT data is sent (it can be replayed).
//! * The server must take the offered identity, with a cipher suite of the same hash; a resumed handshake has no
//!   Certificate or CertificateVerify, and a server that sends one is refused. A server that does not take the ticket
//!   makes a full handshake, which is checked in full.

use super::suite::Suite;
use crate::revocation::RevocationMode;
use crate::x509::TrustStore;
use crate::zeroize::Zeroizing;
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The longest a ticket may live (RFC 8446 section 4.6.1).
pub const MAX_TICKET_LIFETIME: u64 = 604_800;
/// Tickets kept per server.
const TICKETS_PER_SERVER: usize = 4;
/// Servers kept.
const SERVERS: usize = 256;

/// Whether and how TLS 1.3 sessions are resumed; part of [`ClientConfig`](super::ClientConfig). Cloning it shares the
/// store of sessions.
#[derive(Clone)]
pub struct Resumption {
    enabled: bool,
    max_age: u64,
    store: Arc<Mutex<Store>>,
}

impl Default for Resumption {
    fn default() -> Resumption {
        Resumption::new()
    }
}

impl fmt::Debug for Resumption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resumption").field("enabled", &self.enabled).field("max_age", &self.max_age).field("sessions", &self.sessions()).finish()
    }
}

impl Resumption {
    /// Resumption on, with a new store of its own, and sessions used for at most an hour after the certificate check they
    /// rest on.
    pub fn new() -> Resumption {
        Resumption { enabled: true, max_age: 3600, store: Arc::new(Mutex::new(Store::default())) }
    }

    /// No resumption: every connection makes a full handshake, and tickets are not kept.
    pub fn off() -> Resumption {
        Resumption { enabled: false, ..Resumption::new() }
    }

    /// The longest a session is used after the certificate check it rests on, in seconds (at most seven days, the most a
    /// ticket may live).
    pub fn max_age(mut self, seconds: u64) -> Resumption {
        self.max_age = seconds.min(MAX_TICKET_LIFETIME);
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// How many tickets are kept now, for all servers.
    pub fn sessions(&self) -> usize {
        self.lock().servers.iter().map(|(_, q)| q.len()).sum()
    }

    /// Forgets every session.
    pub fn clear(&self) {
        *self.lock() = Store::default();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        // a panic while the lock was held leaves a store that is still consistent (every change is one push or pop)
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Takes a session for `server_name` that `scope` may use at `now` (Unix seconds), if there is one; expired ones are
    /// dropped on the way.
    pub(crate) fn take(&self, server_name: &str, scope: &Scope, now: i64) -> Option<Session> {
        if !self.enabled {
            return None;
        }
        let mut store = self.lock();
        let i = store.servers.iter().position(|(n, _)| n == server_name)?;
        let queue = &mut store.servers[i].1;
        queue.retain(|s| s.expires > now);
        // the newest first: it is the furthest from expiring
        let found = queue.iter().rposition(|s| s.scope.same(scope)).and_then(|j| queue.remove(j));
        if queue.is_empty() {
            store.servers.remove(i);
        }
        found
    }

    /// Keeps a session for `server_name`.
    pub(crate) fn insert(&self, server_name: &str, session: Session) {
        if !self.enabled {
            return;
        }
        let mut store = self.lock();
        let i = match store.servers.iter().position(|(n, _)| n == server_name) {
            Some(i) => i,
            None => {
                if store.servers.len() == SERVERS {
                    store.servers.pop_front();
                }
                store.servers.push_back((server_name.to_string(), VecDeque::new()));
                store.servers.len() - 1
            }
        };
        let queue = &mut store.servers[i].1;
        if queue.len() == TICKETS_PER_SERVER {
            queue.pop_front();
        }
        queue.push_back(session);
    }

    /// When a session made at `received` (Unix seconds) from a ticket of `lifetime` seconds, on a chain checked at
    /// `verified_at`, stops being used.
    pub(crate) fn expiry(&self, received: i64, lifetime: u32, verified_at: i64) -> i64 {
        (received + i64::from(lifetime)).min(verified_at + self.max_age as i64)
    }
}

#[derive(Default)]
struct Store {
    /// Server name and its tickets, oldest first; the servers in the order they were first seen.
    servers: VecDeque<(String, VecDeque<Session>)>,
}

/// What a session was made under, and must be used under: the trust it was checked against.
#[derive(Clone)]
pub(crate) struct Scope {
    pub(crate) trust: Arc<TrustStore>,
    pub(crate) verify: bool,
    pub(crate) revocation: RevocationMode,
}

impl Scope {
    fn same(&self, other: &Scope) -> bool {
        Arc::ptr_eq(&self.trust, &other.trust) && self.verify == other.verify && self.revocation == other.revocation
    }
}

/// A session to resume: the ticket, the key it stands for, and what the full handshake established.
pub(crate) struct Session {
    pub(crate) ticket: Vec<u8>,
    /// The PSK: HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce).
    pub(crate) psk: Zeroizing<Vec<u8>>,
    /// The suite of the connection it came from: the server must resume with one of the same hash.
    pub(crate) suite: Suite,
    pub(crate) age_add: u32,
    /// When the ticket arrived, for its age.
    pub(crate) received: Instant,
    /// Unix seconds from which it is not used.
    pub(crate) expires: i64,
    /// When the server's chain was checked (Unix seconds), in the full handshake this session descends from.
    pub(crate) verified_at: i64,
    /// The server's chain, as it was sent then.
    pub(crate) peer_chain: Vec<Vec<u8>>,
    pub(crate) scope: Scope,
}

impl Session {
    /// The age to send: milliseconds since the ticket arrived, plus `age_add` (RFC 8446 section 4.2.11.1).
    pub(crate) fn obfuscated_age(&self) -> u32 {
        let ms = self.received.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        ms.wrapping_add(self.age_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(trust: &Arc<TrustStore>) -> Scope {
        Scope { trust: trust.clone(), verify: true, revocation: RevocationMode::SoftFail }
    }

    fn session(trust: &Arc<TrustStore>, ticket: u8, expires: i64) -> Session {
        Session {
            ticket: vec![ticket],
            psk: Zeroizing::new(vec![0; 32]),
            suite: Suite::Aes128GcmSha256,
            age_add: 7,
            received: Instant::now(),
            expires,
            verified_at: 0,
            peer_chain: vec![],
            scope: scope(trust),
        }
    }

    #[test]
    fn a_ticket_is_used_once_newest_first_and_only_before_it_expires() {
        let r = Resumption::new();
        let t = Arc::new(TrustStore::empty());
        for (i, exp) in [(1u8, 100), (2, 200), (3, 50)] {
            r.insert("a.test", session(&t, i, exp));
        }
        assert_eq!(r.sessions(), 3);
        // at 60 the third has expired: it is dropped, and the newest of the others is taken
        assert_eq!(r.take("a.test", &scope(&t), 60).unwrap().ticket, [2]);
        assert_eq!(r.sessions(), 1);
        assert_eq!(r.take("a.test", &scope(&t), 60).unwrap().ticket, [1]);
        assert!(r.take("a.test", &scope(&t), 60).is_none());
        assert!(r.take("b.test", &scope(&t), 60).is_none());
        assert_eq!(r.sessions(), 0);
    }

    #[test]
    fn a_session_is_offered_only_under_the_trust_it_was_made_under() {
        let r = Resumption::new();
        let t = Arc::new(TrustStore::empty());
        r.insert("a.test", session(&t, 1, 100));
        // another trust store (even an equal one), verification off, another revocation mode: not offered
        let other = Arc::new(TrustStore::empty());
        assert!(r.take("a.test", &scope(&other), 0).is_none());
        assert!(r.take("a.test", &Scope { verify: false, ..scope(&t) }, 0).is_none());
        assert!(r.take("a.test", &Scope { revocation: RevocationMode::HardFail, ..scope(&t) }, 0).is_none());
        assert_eq!(r.take("a.test", &scope(&t), 0).unwrap().ticket, [1]);
    }

    #[test]
    fn the_store_is_bounded_and_shared_by_clones() {
        let r = Resumption::new();
        let shared = r.clone();
        let t = Arc::new(TrustStore::empty());
        for i in 0..10u8 {
            r.insert("a.test", session(&t, i, 100));
        }
        assert_eq!(shared.sessions(), TICKETS_PER_SERVER);
        assert_eq!(shared.take("a.test", &scope(&t), 0).unwrap().ticket, [9]);
        for i in 0..300 {
            r.insert(&format!("h{i}.test"), session(&t, 0, 100));
        }
        assert_eq!(r.lock().servers.len(), SERVERS);
        assert!(r.take("h0.test", &scope(&t), 0).is_none(), "the oldest servers went first");
        assert!(r.take("h299.test", &scope(&t), 0).is_some());
        r.clear();
        assert_eq!(shared.sessions(), 0);
    }

    #[test]
    fn off_keeps_and_offers_nothing() {
        let r = Resumption::off();
        let t = Arc::new(TrustStore::empty());
        r.insert("a.test", session(&t, 1, 100));
        assert_eq!(r.sessions(), 0);
        assert!(r.take("a.test", &scope(&t), 0).is_none());
        assert!(!r.is_enabled());
    }

    #[test]
    fn a_session_ends_with_its_ticket_or_max_age_after_the_check() {
        let r = Resumption::new();
        assert_eq!(r.expiry(1000, 7200, 1000), 4600, "an hour after the check, before the ticket's two hours");
        assert_eq!(r.expiry(1000, 600, 1000), 1600, "the ticket's ten minutes");
        // a ticket received on a resumed connection keeps the original check's time
        assert_eq!(r.expiry(4000, 7200, 1000), 4600);
        assert_eq!(Resumption::new().max_age(1_000_000).max_age, MAX_TICKET_LIFETIME);
    }

    #[test]
    fn the_age_is_obfuscated_with_age_add() {
        let t = Arc::new(TrustStore::empty());
        let mut s = session(&t, 1, 100);
        s.age_add = u32::MAX;
        // a few milliseconds at most, wrapping around 2^32
        assert!(s.obfuscated_age().wrapping_add(1) < 1000);
    }
}
