//! ARM's data-independent timing mode (FEAT_DIT, Armv8.4). While the `DIT` bit of a thread's PSTATE is set, the instructions
//! that ARM lists as data-independent take a time that does not depend on the values they work on. Without it a core may
//! take shortcuts on some values (a multiply by zero, say), which constant-time code cannot see or prevent.
//!
//! An Apple M5 Max showed why it matters (BACKLOG B-99): without the bit, ECDH on P-256 and P-384, SHA-256, AES key setup
//! and GCM sealing took measurably less time on zero-heavy inputs (|t| up to 174 on P-256 for a scalar of 3 against random
//! ones, although the code has no branch or table index on secrets); with it, every one of those comparisons was clean.
//! So every entry point of the `net` crypto that works on secrets sets it for as long as it runs, the way AWS-LC's
//! `SET_DIT_AUTO_RESET` and Go's `crypto/subtle.WithDataIndependentTiming` do: ECDH and X25519 (key generation and the
//! shared secret), AES and AES-GCM (key setup, sealing, opening, the block and CTR functions QUIC's header protection uses),
//! ChaCha20-Poly1305 and the ChaCha20 mask, and HMAC (so HKDF and the TLS key schedules and PRF). It costs a few percent
//! where it is set (about 4% on ECDH and 15% on SHA-256 on the M5) and nothing elsewhere.
//!
//! Not covered: plain `sha2` and the rest of the pure part (no `unsafe` there, and it hashes and verifies public data: a
//! caller that hashes a secret with `Sha256` directly on such a CPU sets the mode itself); RSA and ECDSA verification
//! (public data). On other targets, on a CPU without the feature and in a `pratique_portable` build, [`Dit::on`] does
//! nothing.

use std::marker::PhantomData;

/// Keeps `DIT` set on this thread until it is dropped, then puts back what was there before. It is not `Send`: the bit
/// belongs to the thread that set it (and a thread started while it is set starts with it set).
pub(crate) struct Dit {
    restore: bool,
    _thread: PhantomData<*const ()>,
}

impl Dit {
    /// Whether this CPU has the mode.
    #[cfg(test)]
    pub(crate) fn available() -> bool {
        imp::available()
    }

    /// Whether the bit is set on this thread now.
    #[cfg(test)]
    pub(crate) fn is_set() -> bool {
        imp::available() && imp::get()
    }

    /// Sets the bit for this thread, if the CPU has the mode and it is not set already.
    #[inline]
    pub(crate) fn on() -> Dit {
        #[cfg(test)]
        if HELD_OFF.with(std::cell::Cell::get) {
            return Dit { restore: false, _thread: PhantomData };
        }
        #[cfg(test)]
        GUARDS.with(|g| g.set(g.get() + 1));
        let restore = imp::available() && !imp::get();
        if restore {
            imp::set(true);
        }
        Dit { restore, _thread: PhantomData }
    }
}

impl Drop for Dit {
    #[inline]
    fn drop(&mut self) {
        if self.restore {
            imp::set(false);
        }
    }
}

#[cfg(test)]
thread_local! {
    static HELD_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// How many guards this thread has made (not held off), on every CPU: what shows that an entry point has one.
    static GUARDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many guards `f` makes on this thread. Test builds only.
#[cfg(test)]
pub(crate) fn guards_in(f: impl FnOnce()) -> usize {
    let before = GUARDS.with(std::cell::Cell::get);
    f();
    GUARDS.with(std::cell::Cell::get) - before
}

/// Runs `f` with the library's own guards doing nothing on this thread, so that the timing tests can measure what the mode
/// changes (`crypto::timing::dit_on_and_off`). Test builds only.
#[cfg(test)]
pub(crate) fn held_off<R>(f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HELD_OFF.with(|h| h.set(false));
        }
    }
    assert!(!Dit::is_set(), "held_off inside a guard measures nothing");
    HELD_OFF.with(|h| h.set(true));
    let _reset = Reset;
    f()
}

#[cfg(all(target_arch = "aarch64", not(pratique_portable)))]
mod imp {
    use core::arch::asm;

    /// The bit's place in the register view of `DIT` (S3_3_C4_C2_5, written by number so that no assembler feature is needed).
    const DIT_BIT: u64 = 1 << 24;

    pub(super) fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("dit")
    }

    pub(super) fn get() -> bool {
        let v: u64;
        // SAFETY: only called after `available()` said the CPU has FEAT_DIT, so the register exists; reading it has no effect.
        unsafe { asm!("mrs {}, s3_3_c4_c2_5", out(reg) v, options(nostack, preserves_flags)) };
        v & DIT_BIT != 0
    }

    pub(super) fn set(on: bool) {
        let v: u64 = if on { DIT_BIT } else { 0 };
        // SAFETY: only called after `available()` said the CPU has FEAT_DIT. Writing the bit changes how long some
        // instructions may take on this thread and nothing else. Without `nomem` the compiler treats this as touching
        // memory, so loads and stores of the work it guards are not moved across it.
        unsafe { asm!("msr s3_3_c4_c2_5, {}", in(reg) v, options(nostack, preserves_flags)) };
    }
}

#[cfg(not(all(target_arch = "aarch64", not(pratique_portable))))]
mod imp {
    pub(super) fn available() -> bool {
        false
    }

    pub(super) fn get() -> bool {
        false
    }

    pub(super) fn set(_on: bool) {}
}

#[cfg(test)]
mod tests {
    use super::Dit;

    #[test]
    fn the_guard_sets_the_bit_and_puts_back_what_was_there() {
        if !Dit::available() {
            assert!(!Dit::is_set());
            let _g = Dit::on();
            assert!(!Dit::is_set(), "a CPU without the mode never reports the bit set");
            return;
        }
        assert!(!Dit::is_set(), "the bit is clear on a fresh test thread");
        {
            let _outer = Dit::on();
            assert!(Dit::is_set());
            {
                // a guard inside another leaves the bit to the outer one
                let _inner = Dit::on();
                assert!(Dit::is_set());
            }
            assert!(Dit::is_set());
        }
        assert!(!Dit::is_set());
        // and a thread that is already running does not see this one's bit (one started while it is set starts with it set:
        // Linux copies the thread's state to the new one)
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || {
            wait.recv().unwrap();
            Dit::is_set()
        });
        let _g = Dit::on();
        go.send(()).unwrap();
        assert!(!other.join().unwrap());
        assert!(Dit::is_set());
    }

    /// Every entry point of the crypto that works on secrets makes a guard (counted on every CPU, so this holds on x86 too)
    /// and leaves the bit as it found it.
    #[test]
    fn the_library_sets_it_around_secret_work_and_puts_it_back() {
        use super::{guards_in, held_off};
        use crate::crypto::chacha20poly1305::{ChaCha20Mask, ChaCha20Poly1305};
        use crate::crypto::ecdsa::Curve;
        use crate::crypto::sha2::{Sha256, Sha384};
        use crate::crypto::{aes::Aes, ecdh, gcm::AesGcm, hmac, x25519};
        let k = [7u8; 32];
        let (g, c, a, m) = (AesGcm::new(&k[..16]), ChaCha20Poly1305::new(&k), Aes::new(&k), ChaCha20Mask::new(&k));
        let (s, p) = ecdh::generate(Curve::P384).unwrap();
        let mut buf = vec![0u8; 18];
        let entry_points: Vec<(&str, Box<dyn Fn()>)> = vec![
            ("AesGcm::new", Box::new(|| drop(AesGcm::new(&k[..16])))),
            ("AesGcm::seal", Box::new(|| drop(g.seal(&[1; 12], b"", b"hi")))),
            ("AesGcm::open", Box::new(|| drop(g.open(&[1; 12], b"", &[0; 18])))),
            ("ChaCha20Poly1305::new", Box::new(|| drop(ChaCha20Poly1305::new(&k)))),
            ("ChaCha20Poly1305::seal", Box::new(|| drop(c.seal(&[1; 12], b"", b"hi")))),
            ("ChaCha20Poly1305::open", Box::new(|| drop(c.open(&[1; 12], b"", &[0; 18])))),
            ("ChaCha20Mask::new", Box::new(|| drop(ChaCha20Mask::new(&k)))),
            ("ChaCha20Mask::mask", Box::new(|| { let _ = m.mask(&[0; 16]); })),
            ("Aes::new", Box::new(|| drop(Aes::new(&k)))),
            ("Aes::encrypt_block", Box::new(|| { let _ = a.encrypt_block(&[0; 16]); })),
            ("Aes::ctr_xor", Box::new(|| a.ctr_xor(&[0; 12], 1, &mut [0; 40]))),
            ("x25519", Box::new(|| { let _ = x25519::x25519(&k, &x25519::BASE_POINT); })),
            ("x25519::public_key", Box::new(|| { let _ = x25519::public_key(&k); })),
            ("ecdh::public_key", Box::new(|| drop(ecdh::public_key(Curve::P256, &k)))),
            ("ecdh::generate", Box::new(|| drop(ecdh::generate(Curve::P256)))),
            ("ecdh::shared_secret", Box::new(|| drop(ecdh::shared_secret(Curve::P384, &s, &p)))),
            ("Hmac::mac", Box::new(|| drop(hmac::Hmac::<Sha256>::mac(&k, b"m")))),
            ("hkdf_extract", Box::new(|| drop(hmac::hkdf_extract::<Sha384>(b"salt", &k)))),
            ("hkdf_expand_label", Box::new(|| drop(hmac::hkdf_expand_label::<Sha256>(&k, "key", b"", 16)))),
        ];
        assert!(!Dit::is_set());
        for (name, f) in &entry_points {
            assert!(guards_in(|| f()) >= 1, "{name} works without data-independent timing");
            assert!(!Dit::is_set(), "{name} left the bit set");
            assert_eq!(guards_in(|| held_off(|| f())), 0, "{name}: held off, no guard counts");
        }
        // in place, too
        assert!(guards_in(|| g.seal_in_place(&[1; 12], b"", &mut buf)) >= 1);
        assert!(guards_in(|| { let _ = g.open_in_place(&[1; 12], b"", &mut buf); }) >= 1);
        // inside a caller's own guard the bit stays set throughout
        let _g = Dit::on();
        for (_, f) in &entry_points {
            f();
            assert_eq!(Dit::is_set(), Dit::available());
        }
    }
}
