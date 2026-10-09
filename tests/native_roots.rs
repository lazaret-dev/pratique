//! The operating system's own store of roots (BACKLOG B-101) on the machine the tests run on: on a Mac and on Windows it
//! must be read and hold roots; elsewhere it must say there is none.
//!
//! On a Mac the trusted roots are compared with what Apple's own `security` tool says the system roots are. On Windows (or
//! under Wine) with `PRATIQUE_TOUCH_WINDOWS_STORES=1` the test adds a root made for the tests to the current user's `ROOT`
//! store and sees that it is trusted, that it is left out while it is in the `Disallowed` store or has an enhanced key usage
//! property that leaves out TLS server authentication, and takes it out again. Existing roots are not touched, but set
//! that only in a Wine prefix or on a throwaway machine (Windows asks for confirmation before it adds a root).

use pratique::native_roots::native_roots;

#[test]
fn the_native_store_is_read_where_there_is_one() {
    const HAS_ONE: bool = cfg!(any(target_os = "macos", windows));
    match (native_roots(), HAS_ONE) {
        (Ok(mut r), true) => {
            let store = r.trust_store();
            eprintln!("{} roots trusted, {} left out", store.len(), r.excluded.len());
            for (_, why) in &r.excluded {
                eprintln!("  left out: {why}");
            }
            assert!(store.len() >= 20, "only {} roots", store.len());
        }
        (Ok(_), false) => panic!("a native store on a system that has none"),
        (Err(e), true) => panic!("{e}"),
        (Err(_), false) => {}
    }
}

#[cfg(target_os = "macos")]
#[test]
fn on_a_mac_the_trusted_roots_are_the_system_roots_less_what_the_settings_deny() {
    use std::collections::BTreeSet;
    let out = std::process::Command::new("security")
        .args(["find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"])
        .output()
        .expect("the security tool runs");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let system: BTreeSet<Vec<u8>> = pratique::pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect();
    let r = native_roots().unwrap();
    let trusted: BTreeSet<Vec<u8>> = r.trusted.iter().cloned().collect();
    let excluded: BTreeSet<Vec<u8>> = r.excluded.iter().map(|(d, _)| d.clone()).collect();
    eprintln!("system roots keychain: {}; trusted: {}, of them system roots: {}; left out: {}", system.len(), trusted.len(), trusted.intersection(&system).count(), excluded.len());
    // every system root is either trusted or left out for a reason the settings gave (none is simply missed)
    let missed: Vec<_> = system.iter().filter(|d| !trusted.contains(*d) && !excluded.contains(*d)).collect();
    assert!(missed.len() * 20 <= system.len(), "{} of {} system roots were neither trusted nor left out", missed.len(), system.len());
    // and most of them are trusted
    assert!(trusted.intersection(&system).count() * 10 >= system.len() * 8, "{} of {}", trusted.intersection(&system).count(), system.len());
}

#[cfg(windows)]
mod windows_stores {
    use core::ffi::c_void;
    use pratique::native_roots::native_roots;

    #[repr(C)]
    struct CertContext {
        encoding_type: u32,
        encoded: *const u8,
        encoded_len: u32,
        info: *const c_void,
        store: *mut c_void,
    }

    #[repr(C)]
    struct EnhKeyUsage {
        count: u32,
        ids: *const *const u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(prov: usize, name: *const u16) -> *mut c_void;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
        fn CertControlStore(store: *mut c_void, flags: u32, ctrl: u32, para: *const c_void) -> i32;
        fn CertEnumCertificatesInStore(store: *mut c_void, prev: *const CertContext) -> *const CertContext;
        fn CertCreateCertificateContext(encoding: u32, der: *const u8, len: u32) -> *const CertContext;
        fn CertFreeCertificateContext(ctx: *const CertContext) -> i32;
        fn CertAddCertificateContextToStore(store: *mut c_void, ctx: *const CertContext, disposition: u32, out: *mut *const CertContext) -> i32;
        fn CertDeleteCertificateFromStore(ctx: *const CertContext) -> i32;
        fn CertSetEnhancedKeyUsage(ctx: *const CertContext, usage: *const EnhKeyUsage) -> i32;
    }

    const X509_ASN: u32 = 1;
    const ADD_NEW: u32 = 1; // CERT_STORE_ADD_NEW
    const CTRL_COMMIT: u32 = 3; // CERT_STORE_CTRL_COMMIT

    /// A root made for the tests, in no real store.
    fn test_root() -> Vec<u8> {
        pratique::pem::parse(include_str!("data/as_root.pem")).remove(0).data
    }

    /// Opens a system store of the current user, runs `f` on it, commits and closes it. Windows writes a change to the
    /// registry at once; Wine writes a delete only when the store is committed or freed (and does not free it on close
    /// after a delete), and never writes a property set on a certificate already in the store, which is why the test sets
    /// properties on a context of its own and adds that.
    fn with_store<T>(name: &str, f: impl FnOnce(*mut c_void) -> T) -> T {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = unsafe { CertOpenSystemStoreW(0, wide.as_ptr()) };
        assert!(!h.is_null(), "open {name}: {}", std::io::Error::last_os_error());
        let out = f(h);
        let committed = unsafe { CertControlStore(h, 0, CTRL_COMMIT, core::ptr::null()) };
        let err = std::io::Error::last_os_error();
        unsafe { CertCloseStore(h, 0) };
        assert_ne!(committed, 0, "commit {name}: {err}");
        out
    }

    /// The context of `der` in a store, if it is there (the enumeration's reference, which the caller frees or deletes).
    fn find(store: *mut c_void, der: &[u8]) -> Option<*const CertContext> {
        let mut ctx: *const CertContext = core::ptr::null();
        loop {
            ctx = unsafe { CertEnumCertificatesInStore(store, ctx) };
            if ctx.is_null() {
                return None;
            }
            if unsafe { std::slice::from_raw_parts((*ctx).encoded, (*ctx).encoded_len as usize) } == der {
                return Some(ctx);
            }
        }
    }

    /// Puts `der` into a store, with an enhanced key usage property (`Some`) or none, in place of any copy there (taken out
    /// first: Wine replaces a certificate in memory but writes only a new one to its registry).
    fn put(name: &str, der: &[u8], usage: Option<&[&str]>) {
        take_out(name, der);
        let strings: Vec<std::ffi::CString> = usage.unwrap_or(&[]).iter().map(|o| std::ffi::CString::new(*o).unwrap()).collect();
        let ptrs: Vec<*const u8> = strings.iter().map(|s| s.as_ptr().cast()).collect();
        let eku = EnhKeyUsage { count: ptrs.len() as u32, ids: ptrs.as_ptr() };
        with_store(name, |store| {
            let ctx = unsafe { CertCreateCertificateContext(X509_ASN, der.as_ptr(), der.len() as u32) };
            assert!(!ctx.is_null(), "CertCreateCertificateContext: {}", std::io::Error::last_os_error());
            if usage.is_some() {
                let ok = unsafe { CertSetEnhancedKeyUsage(ctx, &eku) };
                assert_ne!(ok, 0, "CertSetEnhancedKeyUsage: {}", std::io::Error::last_os_error());
            }
            let ok = unsafe { CertAddCertificateContextToStore(store, ctx, ADD_NEW, core::ptr::null_mut()) };
            let err = std::io::Error::last_os_error();
            unsafe { CertFreeCertificateContext(ctx) };
            assert_ne!(ok, 0, "add to {name}: {err}");
        });
    }

    /// Takes `der` out of a store if it is there.
    fn take_out(name: &str, der: &[u8]) {
        with_store(name, |store| {
            if let Some(ctx) = find(store, der) {
                let ok = unsafe { CertDeleteCertificateFromStore(ctx) };
                assert_ne!(ok, 0, "delete from {name}: {}", std::io::Error::last_os_error());
            }
        });
    }

    /// Takes the test root out of both stores when the test ends, failed or not.
    struct Restore(Vec<u8>);

    impl Drop for Restore {
        fn drop(&mut self) {
            take_out("Disallowed", &self.0);
            take_out("ROOT", &self.0);
        }
    }

    /// What the native store makes of `der`: absent (`None`), trusted (`Ok`) or left out, and why.
    fn seen(der: &[u8]) -> Option<Result<(), String>> {
        let r = native_roots().unwrap();
        let trusted = r.trusted.iter().any(|d| d == der);
        let excluded = r.excluded.into_iter().find(|(d, _)| d == der).map(|(_, w)| w);
        assert!(!(trusted && excluded.is_some()), "both trusted and left out");
        if trusted {
            Some(Ok(()))
        } else {
            excluded.map(Err)
        }
    }

    fn left_out_for(der: &[u8], words: &str) -> bool {
        matches!(seen(der), Some(Err(w)) if w.contains(words))
    }

    #[test]
    fn a_disallowed_root_and_one_for_other_uses_are_left_out() {
        if std::env::var("PRATIQUE_TOUCH_WINDOWS_STORES").as_deref() != Ok("1") {
            eprintln!("skipped: set PRATIQUE_TOUCH_WINDOWS_STORES=1 (in a Wine prefix or on a throwaway Windows machine, where adding a root to the user's store asks for confirmation) to run it");
            return;
        }
        let root = test_root();
        let _restore = Restore(root.clone());
        take_out("Disallowed", &root);
        take_out("ROOT", &root);
        assert_eq!(seen(&root), None, "the test root is in no store to begin with");
        // a root the user adds is trusted
        put("ROOT", &root, None);
        assert_eq!(seen(&root), Some(Ok(())), "added to ROOT");
        // into the Disallowed store, and out again
        put("Disallowed", &root, None);
        assert!(left_out_for(&root, "Disallowed"), "{:?}", seen(&root));
        take_out("Disallowed", &root);
        assert_eq!(seen(&root), Some(Ok(())), "out of Disallowed");
        // an enhanced key usage property: code signing only, then with server authentication, then no use, then none
        put("ROOT", &root, Some(&["1.3.6.1.5.5.7.3.3"]));
        assert!(left_out_for(&root, "does not include"), "code signing only: {:?}", seen(&root));
        put("ROOT", &root, Some(&["1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.1"]));
        assert_eq!(seen(&root), Some(Ok(())), "with server authentication");
        put("ROOT", &root, Some(&[]));
        assert!(left_out_for(&root, "no use"), "an empty property: {:?}", seen(&root));
        put("ROOT", &root, None);
        assert_eq!(seen(&root), Some(Ok(())), "no property");
        take_out("ROOT", &root);
        assert_eq!(seen(&root), None, "taken out");
    }
}
