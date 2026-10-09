//! Session tickets the server can read back without keeping anything per session (B-110).
//!
//! A ticket is the session's state (its suite, the resumption PSK, when it was issued and for how long, the name the
//! client asked for, the ALPN protocol and the client's certificate chain if it sent one) sealed with AES-256-GCM
//! under a ticket key of the server's: `key name (16) || nonce (12) || ciphertext || tag`, the key name being the
//! additional data. Nothing about the session is kept on the server, so any number of tickets can be outstanding and a
//! server restarted with the same [`TicketKeys`] (or a pool of servers sharing them) resumes them all.
//!
//! The keys rotate: a new one is made every `rotate_every` (12 hours by default), tickets are sealed under the newest,
//! and the old ones are kept as long as a ticket sealed under them can still be valid (`rotate_every` plus the ticket
//! lifetime), then wiped. A ticket under a key that is gone, a ticket that does not open (changed, or not ours), or a
//! ticket past its lifetime is not an error: the handshake is simply a full one.
//!
//! Without early data (this server never accepts it) a ticket used twice is harmless: resumption is `psk_dhe_ke`, a
//! fresh key exchange every time, and only the client that holds the PSK can complete it.

use crate::crypto::gcm::AesGcm;
use crate::crypto::rand;
use crate::error::Result;
use crate::sys;
use crate::util::Reader;
use crate::zeroize::{Zeroize, Zeroizing};
use std::sync::Mutex;

const NAME_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const STATE_VERSION: u8 = 1;

struct TicketKey {
    name: [u8; NAME_LEN],
    cipher: AesGcm,
    created: i64,
}

/// The keys tickets are sealed under, rotated as the module documentation says. Share one between configurations (and
/// servers) that should resume each other's sessions.
pub struct TicketKeys {
    keys: Mutex<Vec<TicketKey>>,
    rotate_every: i64,
    /// how long a key is kept after it stops being the newest: the longest ticket lifetime
    keep_for: i64,
}

impl TicketKeys {
    /// New keys, rotated every 12 hours, for tickets that live at most `max_lifetime` seconds.
    pub fn new(max_lifetime: u32) -> Result<TicketKeys> {
        TicketKeys::with_rotation(12 * 3600, max_lifetime)
    }

    /// New keys, rotated every `rotate_every` seconds.
    pub fn with_rotation(rotate_every: i64, max_lifetime: u32) -> Result<TicketKeys> {
        let keys = TicketKeys { keys: Mutex::new(Vec::new()), rotate_every: rotate_every.max(1), keep_for: max_lifetime as i64 };
        keys.keys.lock().unwrap_or_else(|e| e.into_inner()).push(TicketKey::fresh(sys::now_unix())?);
        Ok(keys)
    }

    /// Makes a new key the one tickets are sealed under now, as a rotation would.
    pub fn rotate(&self) -> Result<()> {
        self.rotate_at(sys::now_unix(), true)
    }

    fn rotate_at(&self, now: i64, force: bool) -> Result<()> {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let newest = keys.last().map_or(i64::MIN, |k| k.created);
        if force || now - newest >= self.rotate_every {
            keys.push(TicketKey::fresh(now)?);
        }
        // a key stops being the newest when the next one is made; keep it while its tickets may be valid
        let mut i = 0;
        while i + 1 < keys.len() {
            let retired = keys[i + 1].created;
            if now - retired > self.keep_for + self.rotate_every {
                keys.remove(i);
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// `state` sealed under the newest key (rotating first if it is due).
    pub(crate) fn seal(&self, state: &[u8]) -> Result<Vec<u8>> {
        self.seal_at(state, sys::now_unix())
    }

    fn seal_at(&self, state: &[u8], now: i64) -> Result<Vec<u8>> {
        self.rotate_at(now, false)?;
        let nonce: [u8; NONCE_LEN] = rand::bytes()?;
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let key = keys.last().expect("there is always a key");
        let mut out = Vec::with_capacity(NAME_LEN + NONCE_LEN + state.len() + 16);
        out.extend_from_slice(&key.name);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&key.cipher.seal(&nonce, &key.name, state));
        Ok(out)
    }

    /// The state in `ticket`, if it is one of ours under a key still kept and it has not been changed.
    pub(crate) fn open(&self, ticket: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if ticket.len() < NAME_LEN + NONCE_LEN + 16 {
            return None;
        }
        let (name, rest) = ticket.split_at(NAME_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let key = keys.iter().find(|k| k.name[..] == *name)?;
        key.cipher.open(nonce.try_into().ok()?, name, sealed).map(Zeroizing::new)
    }

    #[cfg(test)]
    fn key_count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

impl TicketKey {
    fn fresh(now: i64) -> Result<TicketKey> {
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::fill(&mut secret[..])?;
        Ok(TicketKey { name: rand::bytes()?, cipher: AesGcm::new(&secret[..]), created: now })
    }
}

/// What a ticket carries.
#[derive(Debug)]
pub(crate) struct TicketState {
    pub suite: u16,
    /// Unix seconds
    pub issued: i64,
    /// seconds
    pub lifetime: u32,
    pub age_add: u32,
    pub psk: Zeroizing<Vec<u8>>,
    pub server_name: Option<String>,
    pub alpn: Option<Vec<u8>>,
    /// the client's certificate chain (DER, leaf first), if it authenticated with one
    pub client_chain: Vec<Vec<u8>>,
}

impl PartialEq for TicketState {
    fn eq(&self, o: &Self) -> bool {
        self.suite == o.suite
            && self.issued == o.issued
            && self.lifetime == o.lifetime
            && self.age_add == o.age_add
            && crate::util::ct_eq(&self.psk, &o.psk)
            && self.server_name == o.server_name
            && self.alpn == o.alpn
            && self.client_chain == o.client_chain
    }
}

impl TicketState {
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(128 + self.client_chain.iter().map(|c| c.len() + 3).sum::<usize>()));
        v.push(STATE_VERSION);
        v.extend_from_slice(&self.suite.to_be_bytes());
        v.extend_from_slice(&(self.issued as u64).to_be_bytes());
        v.extend_from_slice(&self.lifetime.to_be_bytes());
        v.extend_from_slice(&self.age_add.to_be_bytes());
        v.push(self.psk.len() as u8);
        v.extend_from_slice(&self.psk);
        let name = self.server_name.as_deref().unwrap_or("").as_bytes();
        v.push(self.server_name.is_some() as u8);
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        let alpn = self.alpn.as_deref().unwrap_or(&[]);
        v.push(self.alpn.is_some() as u8);
        v.push(alpn.len() as u8);
        v.extend_from_slice(alpn);
        v.extend_from_slice(&(self.client_chain.len() as u16).to_be_bytes());
        for c in &self.client_chain {
            v.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
            v.extend_from_slice(c);
        }
        v
    }

    pub(crate) fn decode(data: &[u8]) -> Option<TicketState> {
        let mut r = Reader::new(data);
        if r.u8()? != STATE_VERSION {
            return None;
        }
        let suite = r.u16()?;
        let issued = u64::from_be_bytes(r.take(8)?.try_into().ok()?) as i64;
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let psk = Zeroizing::new(r.vec8()?.to_vec());
        let has_name = r.u8()? == 1;
        let name = r.vec16()?;
        let server_name = if has_name { Some(String::from_utf8(name.to_vec()).ok()?) } else { None };
        let has_alpn = r.u8()? == 1;
        let alpn = r.vec8()?;
        let alpn = has_alpn.then(|| alpn.to_vec());
        let count = r.u16()?;
        let mut client_chain = Vec::with_capacity(count as usize);
        for _ in 0..count {
            client_chain.push(r.vec24()?.to_vec());
        }
        r.is_empty().then_some(TicketState { suite, issued, lifetime, age_add, psk, server_name, alpn, client_chain })
    }

    /// Still within its lifetime at `now` (and not issued in the future, beyond a minute of clock difference).
    pub(crate) fn is_current(&self, now: i64) -> bool {
        self.issued <= now + 60 && now < self.issued + self.lifetime as i64
    }
}

impl Drop for TicketState {
    fn drop(&mut self) {
        for c in self.client_chain.iter_mut() {
            c.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> TicketState {
        TicketState {
            suite: 0x1301,
            issued: 1_800_000_000,
            lifetime: 86_400,
            age_add: 0xdead_beef,
            psk: Zeroizing::new(vec![7u8; 32]),
            server_name: Some("example.test".into()),
            alpn: Some(b"h2".to_vec()),
            client_chain: vec![vec![1, 2, 3], vec![4; 300]],
        }
    }

    #[test]
    fn the_state_round_trips_and_nothing_else_decodes() {
        let s = state();
        let enc = s.encode();
        assert_eq!(TicketState::decode(&enc).unwrap(), s);
        let mut bare = state();
        bare.server_name = None;
        bare.alpn = None;
        bare.client_chain = vec![];
        assert_eq!(TicketState::decode(&bare.encode()).unwrap(), bare);
        for cut in 0..enc.len() {
            assert!(TicketState::decode(&enc[..cut]).is_none(), "cut at {cut}");
        }
        let mut longer = enc.to_vec();
        longer.push(0);
        assert!(TicketState::decode(&longer).is_none());
        let mut v2 = enc.to_vec();
        v2[0] = 2;
        assert!(TicketState::decode(&v2).is_none());
        assert!(s.is_current(1_800_000_000) && s.is_current(1_800_086_399) && s.is_current(1_799_999_950));
        assert!(!s.is_current(1_800_086_400) && !s.is_current(1_799_999_900));
    }

    #[test]
    fn tickets_open_only_unchanged_and_only_with_the_keys_that_sealed_them() {
        let keys = TicketKeys::new(86_400).unwrap();
        let t = keys.seal(b"the session").unwrap();
        assert_eq!(&keys.open(&t).unwrap()[..], b"the session");
        for i in 0..t.len() {
            let mut bad = t.clone();
            bad[i] ^= 1;
            assert!(keys.open(&bad).is_none(), "byte {i} changed");
        }
        assert!(keys.open(&t[..t.len() - 1]).is_none());
        assert!(keys.open(&[]).is_none());
        let other = TicketKeys::new(86_400).unwrap();
        assert!(other.open(&t).is_none(), "another server's keys");
        // two tickets of the same state differ (a fresh nonce each)
        assert_ne!(keys.seal(b"the session").unwrap(), t);
    }

    #[test]
    fn keys_rotate_and_old_ones_are_kept_as_long_as_their_tickets_live() {
        let keys = TicketKeys::with_rotation(100, 1000).unwrap();
        let t0 = keys.keys.lock().unwrap()[0].created;
        let early = keys.seal_at(b"early", t0).unwrap();
        // a rotation is due after 100 s: the next ticket is under a new key, the old one still opens
        let later = keys.seal_at(b"later", t0 + 150).unwrap();
        assert_eq!(keys.key_count(), 2);
        assert_ne!(early[..NAME_LEN], later[..NAME_LEN]);
        assert_eq!(&keys.open(&early).unwrap()[..], b"early");
        // the first key retired at t0 + 150; it goes once its tickets cannot be valid (lifetime + rotation after that)
        keys.rotate_at(t0 + 150 + 1101, false).unwrap();
        assert!(keys.open(&early).is_none());
        assert!(keys.key_count() >= 1);
        keys.rotate().unwrap();
        assert!(keys.key_count() >= 2);
    }
}
