//! The operating system's own store of trusted roots (BACKLOG B-101): the trust settings of the macOS Keychain and the
//! Windows certificate store, read through their APIs (FFI to Security.framework and CoreFoundation, or to `crypt32`; no
//! dependencies), as the roots trusted for TLS servers. [`crate::sys::native_trust_store`] makes a [`TrustStore`] of them.
//!
//! What counts as trusted errs toward refusing: a store that is read wrong must leave a root out rather than let one in.
//!
//! * **macOS**: the three trust-settings domains, the user's first, then the administrator's, then the system's (a
//!   decision in one hides the same certificate in those after it, as the system's own evaluation has it). In a domain a
//!   certificate's settings are read in order; an entry counts for TLS if it names no policy or the SSL policy
//!   (`kSecPolicyAppleSSL`), and no application, host name (`kSecTrustSettingsPolicyString`) or key usage
//!   (`kSecTrustSettingsKeyUsage`, unless it is "any"), which this store could not keep; its result (`kSecTrustSettingsResult`, "trust as root"
//!   when it is absent) decides: trust as root or trust root, the certificate is trusted; deny, it is left out; unspecified,
//!   the next entry. An empty list of settings means "trust as root" (Apple's documentation). A certificate whose settings
//!   say nothing for TLS is trusted if it is one of the system's roots, and left out if it is only the user's or the
//!   administrator's (where `rustls-native-certs` would take it). A certificate with no settings in a domain
//!   (`errSecItemNotFound` or `errSecNoTrustSettings`) leaves the decision to the next; any other error fails the whole
//!   read: a store that could not be read is not a smaller store.
//! * **Windows**: the current user's `ROOT` store (which includes the machine's roots and those of group policy), less
//!   every certificate in the `Disallowed` store, less those whose enhanced key usage property, where one is set, does not
//!   include TLS server authentication (`1.3.6.1.5.5.7.3.1`) or allows no use at all.
//! * **Elsewhere** there is no such store: [`native_roots`] fails, and the CA bundle file is the system's store
//!   ([`crate::sys::system_trust_store`]).
//!
//! A certificate that does not parse is left out and counted. What the systems can say and this store cannot keep (a root
//! trusted for one host only, a date after which a root is distrusted, the Windows "not before" properties) is left out
//! rather than widened.
//!
//! Tested: the logic of each system on recorded settings (unit tests, everywhere); the Windows calls against Wine's
//! `crypt32` (this repository's CI machine has no Windows); the macOS calls only on a Mac (`tools/native_check.sh` compares
//! them with what the `security` tool says).

use crate::x509::TrustStore;

/// What reading the system's store came to.
#[derive(Debug, Default)]
pub struct NativeRoots {
    /// The certificates trusted as roots for TLS servers (DER), each once.
    pub trusted: Vec<Vec<u8>>,
    /// Certificates the store has that are not trusted for TLS servers, and why (DER, reason).
    pub excluded: Vec<(Vec<u8>, String)>,
}

impl NativeRoots {
    /// A trust store of the trusted certificates; any that does not parse moves to `excluded`.
    pub fn trust_store(&mut self) -> TrustStore {
        let mut store = TrustStore::empty();
        let mut kept = Vec::with_capacity(self.trusted.len());
        for der in std::mem::take(&mut self.trusted) {
            match store.add_der(&der) {
                Ok(()) => kept.push(der),
                Err(e) => self.excluded.push((der, format!("does not parse: {e}"))),
            }
        }
        self.trusted = kept;
        store
    }
}

/// Reads the system's store: the roots trusted for TLS servers, and those it has and does not trust for that.
pub fn native_roots() -> Result<NativeRoots, String> {
    imp::read()
}

// (the macOS logic, apart from its FFI: used there, and by the tests everywhere)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// What a certificate's settings in one macOS domain come to for TLS, from its list of settings (each entry as the keys
/// this module reads). Separate from the FFI so that it is tested everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Trusted,
    Denied,
    /// Nothing for TLS in this domain: the next one decides.
    NoWord,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// One entry of a certificate's trust settings, as far as it matters here.
#[derive(Clone, Debug, Default)]
pub(crate) struct Setting {
    /// The entry names a policy, and whether it is the SSL one.
    pub(crate) policy: Option<bool>,
    /// The entry is limited to an application, a host name or some key usages (not "any", [`KEY_USE_ANY`]).
    pub(crate) limited: bool,
    /// `kSecTrustSettingsResult` (absent: trust as root).
    pub(crate) result: Option<i32>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const RESULT_TRUST_ROOT: i32 = 1;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const RESULT_TRUST_AS_ROOT: i32 = 2;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const RESULT_DENY: i32 = 3;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const RESULT_UNSPECIFIED: i32 = 4;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// `kSecTrustSettingsKeyUseAny` (0xffffffff as a signed 32-bit number): a key usage that limits nothing.
pub(crate) const KEY_USE_ANY: i32 = -1;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The verdict of a list of settings (an empty list is "trust as root").
pub(crate) fn verdict(settings: &[Setting]) -> Verdict {
    if settings.is_empty() {
        return Verdict::Trusted;
    }
    for s in settings {
        if s.policy == Some(false) || s.limited {
            continue;
        }
        match s.result.unwrap_or(RESULT_TRUST_ROOT) {
            RESULT_TRUST_ROOT | RESULT_TRUST_AS_ROOT => return Verdict::Trusted,
            RESULT_DENY => return Verdict::Denied,
            // unspecified, invalid, or a value this module does not know: the next entry
            _ => continue,
        }
    }
    Verdict::NoWord
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The macOS domains in the order they decide.
pub(crate) const DOMAINS: [(u32, &str); 3] = [(0, "user"), (1, "admin"), (2, "system")];

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// Puts together the verdicts of the domains (in the order of [`DOMAINS`]) for each certificate: `per_domain[i]` lists
/// the certificates of domain `i` with their verdicts.
pub(crate) fn decide(per_domain: &[Vec<(Vec<u8>, Verdict)>]) -> NativeRoots {
    use std::collections::BTreeMap;
    // (the certificate, and whether a decision has been made: trusted or not, and why)
    let mut decided: BTreeMap<Vec<u8>, Option<(bool, String)>> = BTreeMap::new();
    let mut order: Vec<Vec<u8>> = Vec::new();
    for (i, certs) in per_domain.iter().enumerate() {
        let (_, name) = DOMAINS[i];
        let system = i == 2;
        for (der, v) in certs {
            let entry = decided.entry(der.clone()).or_insert_with(|| {
                order.push(der.clone());
                None
            });
            if entry.is_some() {
                continue;
            }
            *entry = match v {
                Verdict::Trusted => Some((true, String::new())),
                Verdict::Denied => Some((false, format!("denied by the {name} trust settings"))),
                // the system's roots are trusted unless their settings say otherwise
                Verdict::NoWord if system => Some((true, String::new())),
                Verdict::NoWord => None,
            };
        }
    }
    let mut out = NativeRoots::default();
    for der in order {
        match decided.remove(&der).flatten() {
            Some((true, _)) => out.trusted.push(der),
            Some((false, why)) => out.excluded.push((der, why)),
            None => out.excluded.push((der, "trust settings for other purposes only (user or administrator)".into())),
        }
    }
    out
}

#[cfg_attr(not(windows), allow(dead_code))]
/// The Windows rule for one certificate of the `ROOT` store: (in `Disallowed`, its enhanced key usage property: `None`
/// for none set, `Some(list)` otherwise, an empty list meaning no use at all).
pub(crate) fn windows_verdict(disallowed: bool, usage: &Option<Vec<String>>) -> Result<(), String> {
    if disallowed {
        return Err("in the Disallowed store".into());
    }
    match usage {
        None => Ok(()),
        Some(list) if list.iter().any(|o| o == "1.3.6.1.5.5.7.3.1") => Ok(()),
        Some(list) if list.is_empty() => Err("its enhanced key usage property allows no use".into()),
        Some(list) => Err(format!("its enhanced key usage property does not include TLS server authentication ({})", list.join(", "))),
    }
}

// ------------------------------------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod imp {
    use super::{decide, verdict, NativeRoots, Setting, Verdict, DOMAINS};
    use core::ffi::c_void;

    type CFTypeRef = *const c_void;
    type CFIndex = isize;
    type OSStatus = i32;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFArrayGetCount(array: CFTypeRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(array: CFTypeRef, index: CFIndex) -> CFTypeRef;
        fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
        fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFNumberGetValue(number: CFTypeRef, the_type: CFIndex, out: *mut c_void) -> u8;
        fn CFStringCreateWithBytes(alloc: CFTypeRef, bytes: *const u8, len: CFIndex, encoding: u32, external: u8) -> CFTypeRef;
        fn CFEqual(a: CFTypeRef, b: CFTypeRef) -> u8;
        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFNumberGetTypeID() -> usize;
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecTrustSettingsCopyCertificates(domain: u32, certs: *mut CFTypeRef) -> OSStatus;
        fn SecTrustSettingsCopyTrustSettings(cert: CFTypeRef, domain: u32, settings: *mut CFTypeRef) -> OSStatus;
        fn SecCertificateCopyData(cert: CFTypeRef) -> CFTypeRef;
        fn SecPolicyCopyProperties(policy: CFTypeRef) -> CFTypeRef;
        static kSecPolicyOid: CFTypeRef;
        static kSecPolicyAppleSSL: CFTypeRef;
    }

    const NO_TRUST_SETTINGS: OSStatus = -25263; // errSecNoTrustSettings
    const ITEM_NOT_FOUND: OSStatus = -25300; // errSecItemNotFound: what SecTrustSettingsCopyTrustSettings says of a certificate without settings
    const NUMBER_SINT64: CFIndex = 4; // kCFNumberSInt64Type
    const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

    /// A Core Foundation object this code owns (from a Copy or Create call), released when dropped.
    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Copy or Create function, which gives a reference this code owns, and
                // it is released once.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    /// A CFString of `s`.
    fn cfstr(s: &str) -> Owned {
        // SAFETY: the bytes are valid for `s.len()` and are copied; a null allocator is the default one.
        Owned(unsafe { CFStringCreateWithBytes(core::ptr::null(), s.as_ptr(), s.len() as CFIndex, UTF8, 0) })
    }

    /// The bytes of a CFData.
    ///
    /// SAFETY: `data` must be a live CFData.
    unsafe fn bytes(data: CFTypeRef) -> Vec<u8> {
        let len = CFDataGetLength(data);
        let ptr = CFDataGetBytePtr(data);
        if ptr.is_null() || len <= 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(ptr, len as usize).to_vec()
    }

    /// The items of a CFArray (borrowed from it).
    ///
    /// SAFETY: `array` must be a live CFArray, and outlive what is returned.
    unsafe fn items(array: CFTypeRef) -> Vec<CFTypeRef> {
        (0..CFArrayGetCount(array)).map(|i| CFArrayGetValueAtIndex(array, i)).collect()
    }

    struct Keys {
        policy: Owned,
        policy_string: Owned,
        application: Owned,
        key_usage: Owned,
        result: Owned,
    }

    /// Whether `policy` (a SecPolicyRef) is the SSL policy.
    ///
    /// SAFETY: `policy` must be a live SecPolicyRef.
    unsafe fn is_ssl(policy: CFTypeRef) -> bool {
        let props = Owned(SecPolicyCopyProperties(policy));
        if props.0.is_null() {
            return false;
        }
        let oid = CFDictionaryGetValue(props.0, kSecPolicyOid);
        !oid.is_null() && CFEqual(oid, kSecPolicyAppleSSL) != 0
    }

    /// A CFNumber's value as a signed 32-bit number (the low 32 bits of a larger one, as Apple's own code reads these
    /// keys), or `None` if `value` is not a number.
    ///
    /// SAFETY: `value` must be a live Core Foundation object.
    unsafe fn number(value: CFTypeRef) -> Option<i32> {
        if CFGetTypeID(value) != CFNumberGetTypeID() {
            return None;
        }
        let mut v: i64 = 0;
        (CFNumberGetValue(value, NUMBER_SINT64, (&mut v as *mut i64).cast()) != 0).then_some(v as i32)
    }

    /// One entry of a certificate's trust settings.
    ///
    /// SAFETY: `dict` must be a live CFDictionary.
    unsafe fn setting(dict: CFTypeRef, k: &Keys) -> Setting {
        let policy = CFDictionaryGetValue(dict, k.policy.0);
        let key_usage = CFDictionaryGetValue(dict, k.key_usage.0);
        // a key usage limits the entry unless it is "any" (one that cannot be read limits it)
        let limited = [&k.policy_string, &k.application].iter().any(|key| !CFDictionaryGetValue(dict, key.0).is_null())
            || (!key_usage.is_null() && number(key_usage) != Some(super::KEY_USE_ANY));
        let result = CFDictionaryGetValue(dict, k.result.0);
        // a result that is not a number is no result this code can read: "unspecified", so the entry is passed over
        let result = (!result.is_null()).then(|| number(result).unwrap_or(super::RESULT_UNSPECIFIED));
        Setting { policy: (!policy.is_null()).then(|| is_ssl(policy)), limited, result }
    }

    pub(super) fn read() -> Result<NativeRoots, String> {
        let keys = Keys {
            policy: cfstr("kSecTrustSettingsPolicy"),
            policy_string: cfstr("kSecTrustSettingsPolicyString"),
            application: cfstr("kSecTrustSettingsApplication"),
            key_usage: cfstr("kSecTrustSettingsKeyUsage"),
            result: cfstr("kSecTrustSettingsResult"),
        };
        if [&keys.policy, &keys.policy_string, &keys.application, &keys.key_usage, &keys.result].iter().any(|k| k.0.is_null()) {
            return Err("CoreFoundation could not make a string".into());
        }
        let mut per_domain = Vec::new();
        for (domain, name) in DOMAINS {
            let mut certs: CFTypeRef = core::ptr::null();
            // SAFETY: the out pointer is valid; on success it holds an array this code owns.
            let status = unsafe { SecTrustSettingsCopyCertificates(domain, &mut certs) };
            let certs = Owned(certs);
            let mut found = Vec::new();
            match status {
                0 => {}
                NO_TRUST_SETTINGS => {
                    per_domain.push(found);
                    continue;
                }
                e => return Err(format!("SecTrustSettingsCopyCertificates for the {name} domain: OSStatus {e}")),
            }
            // SAFETY: `certs` is a live CFArray of SecCertificateRefs, kept alive by `certs` until the end of this block.
            for cert in unsafe { items(certs.0) } {
                // SAFETY: `cert` is a live SecCertificateRef; the data is owned and released.
                let der = unsafe {
                    let data = Owned(SecCertificateCopyData(cert));
                    if data.0.is_null() {
                        continue;
                    }
                    bytes(data.0)
                };
                let mut settings: CFTypeRef = core::ptr::null();
                // SAFETY: `cert` is live and the out pointer valid; on success the array is owned.
                let status = unsafe { SecTrustSettingsCopyTrustSettings(cert, domain, &mut settings) };
                let settings = Owned(settings);
                let v = match status {
                    // SAFETY: a live CFArray of CFDictionaries, owned by `settings` until the end of this arm.
                    0 if !settings.0.is_null() => verdict(&unsafe { items(settings.0) }.into_iter().map(|d| unsafe { setting(d, &keys) }).collect::<Vec<_>>()),
                    0 => Verdict::Trusted,
                    NO_TRUST_SETTINGS | ITEM_NOT_FOUND => Verdict::NoWord,
                    e => return Err(format!("SecTrustSettingsCopyTrustSettings in the {name} domain: OSStatus {e}")),
                };
                found.push((der, v));
            }
            per_domain.push(found);
        }
        Ok(decide(&per_domain))
    }
}

// ------------------------------------------------------------------------------------------------ Windows

#[cfg(windows)]
mod imp {
    use super::{windows_verdict, NativeRoots};
    use core::ffi::c_void;

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

    #[link(name = "kernel32")]
    extern "system" {
        fn SetLastError(code: u32);
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(prov: usize, name: *const u16) -> *mut c_void;
        fn CertEnumCertificatesInStore(store: *mut c_void, prev: *const CertContext) -> *const CertContext;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
        fn CertGetEnhancedKeyUsage(cert: *const CertContext, flags: u32, usage: *mut EnhKeyUsage, len: *mut u32) -> i32;
    }

    const PROP_ONLY: u32 = 0x4; // CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG
    const NOT_FOUND: i32 = 0x8009_2004_u32 as i32; // CRYPT_E_NOT_FOUND

    /// An open system store, closed when dropped.
    struct Store(*mut c_void);

    impl Store {
        fn open(name: &str) -> Result<Store, String> {
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that lives through the call; 0 is "no provider".
            let h = unsafe { CertOpenSystemStoreW(0, wide.as_ptr()) };
            if h.is_null() {
                return Err(format!("CertOpenSystemStoreW({name}): {}", std::io::Error::last_os_error()));
            }
            Ok(Store(h))
        }

        /// Every certificate in the store: its DER, and its enhanced key usage property (see `windows_verdict`).
        fn certificates(&self) -> Result<Vec<(Vec<u8>, Usage)>, String> {
            let mut out = Vec::new();
            let mut ctx: *const CertContext = core::ptr::null();
            loop {
                // SAFETY: the store is open; `ctx` is null or the context the previous call returned, which this call frees.
                ctx = unsafe { CertEnumCertificatesInStore(self.0, ctx) };
                if ctx.is_null() {
                    break;
                }
                // SAFETY: `ctx` is a live context; its encoded bytes are valid for `encoded_len`.
                let der = unsafe { std::slice::from_raw_parts((*ctx).encoded, (*ctx).encoded_len as usize).to_vec() };
                out.push((der, usage(ctx)?));
            }
            Ok(out)
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            // SAFETY: the handle came from CertOpenSystemStoreW and is closed once.
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    /// The enhanced key usage property of `ctx`: `None` if it has none (good for every use), the OIDs otherwise.
    /// An enhanced key usage property: `None` when the certificate has none, else the usages it names.
    type Usage = Option<Vec<String>>;

    fn usage(ctx: *const CertContext) -> Result<Usage, String> {
        let mut len: u32 = 0;
        // SAFETY: a size query (null buffer) on a live context.
        let ok = unsafe { CertGetEnhancedKeyUsage(ctx, PROP_ONLY, core::ptr::null_mut(), &mut len) };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(NOT_FOUND) => Ok(None),
                _ => Err(format!("CertGetEnhancedKeyUsage: {e}")),
            };
        }
        // (a buffer of u64 words, for the alignment of the structure and its pointers)
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(2)];
        let mut len = (buf.len() * 8) as u32;
        let usage = buf.as_mut_ptr().cast::<EnhKeyUsage>();
        // (the last error tells "every use" from "no use" when the list comes back empty: it must be this call's)
        // SAFETY: setting the thread's last error has no preconditions; `buf` holds `len` bytes, aligned for the structure.
        let ok = unsafe {
            SetLastError(0);
            CertGetEnhancedKeyUsage(ctx, PROP_ONLY, usage, &mut len)
        };
        if ok == 0 {
            return Err(format!("CertGetEnhancedKeyUsage: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: the call filled the structure; its pointers point into `buf`, at NUL-terminated ASCII strings.
        unsafe {
            let count = (*usage).count as usize;
            if count == 0 {
                // "no uses" when the property is there (the error says which, and it was not "not found" above)
                return match std::io::Error::last_os_error().raw_os_error() {
                    Some(NOT_FOUND) => Ok(None),
                    _ => Ok(Some(Vec::new())),
                };
            }
            let ids = std::slice::from_raw_parts((*usage).ids, count);
            Ok(Some(ids.iter().map(|&p| std::ffi::CStr::from_ptr(p.cast()).to_string_lossy().into_owned()).collect()))
        }
    }

    pub(super) fn read() -> Result<NativeRoots, String> {
        let disallowed: Vec<Vec<u8>> = Store::open("Disallowed")?.certificates()?.into_iter().map(|(der, _)| der).collect();
        let mut out = NativeRoots::default();
        for (der, usage) in Store::open("ROOT")?.certificates()? {
            if out.trusted.contains(&der) {
                continue;
            }
            match windows_verdict(disallowed.contains(&der), &usage) {
                Ok(()) => out.trusted.push(der),
                Err(why) => out.excluded.push((der, why)),
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------------------------------------------ elsewhere

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use super::NativeRoots;

    pub(super) fn read() -> Result<NativeRoots, String> {
        Err("this operating system has no native store of trusted roots: use the CA bundle file (sys::system_trust_store)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(policy: Option<bool>, limited: bool, result: Option<i32>) -> Setting {
        Setting { policy, limited, result }
    }

    #[test]
    fn the_settings_of_a_domain_come_to_a_verdict_for_tls() {
        assert_eq!(verdict(&[]), Verdict::Trusted, "an empty list is trust as root");
        assert_eq!(verdict(&[s(None, false, None)]), Verdict::Trusted, "no result is trust as root");
        assert_eq!(verdict(&[s(Some(true), false, Some(RESULT_DENY))]), Verdict::Denied);
        assert_eq!(verdict(&[s(Some(true), false, Some(RESULT_TRUST_AS_ROOT))]), Verdict::Trusted);
        // another policy's entry says nothing for TLS; the next one decides
        assert_eq!(verdict(&[s(Some(false), false, Some(RESULT_TRUST_ROOT))]), Verdict::NoWord);
        assert_eq!(verdict(&[s(Some(false), false, Some(RESULT_TRUST_ROOT)), s(Some(true), false, Some(RESULT_DENY))]), Verdict::Denied);
        // unspecified passes to the next; the first that decides wins
        assert_eq!(verdict(&[s(None, false, Some(RESULT_UNSPECIFIED)), s(None, false, Some(RESULT_DENY)), s(None, false, None)]), Verdict::Denied);
        assert_eq!(verdict(&[s(None, false, Some(RESULT_UNSPECIFIED))]), Verdict::NoWord);
        // limited to a host, an application or a key usage: not a trust this store can keep
        assert_eq!(verdict(&[s(Some(true), true, Some(RESULT_TRUST_ROOT))]), Verdict::NoWord);
        // (a deny so limited is not taken either: the next entry, or the domain after, decides)
        assert_eq!(verdict(&[s(Some(true), true, Some(RESULT_DENY)), s(None, false, None)]), Verdict::Trusted);
        // a value nobody knows
        assert_eq!(verdict(&[s(None, false, Some(99))]), Verdict::NoWord);
    }

    #[test]
    fn the_users_word_comes_before_the_administrators_and_the_systems() {
        let (a, b, c, d, e) = (vec![1u8], vec![2u8], vec![3u8], vec![4u8], vec![5u8]);
        let user = vec![(a.clone(), Verdict::Denied), (b.clone(), Verdict::NoWord), (d.clone(), Verdict::Trusted)];
        let admin = vec![(b.clone(), Verdict::Denied), (c.clone(), Verdict::NoWord), (e.clone(), Verdict::NoWord)];
        let system = vec![(a.clone(), Verdict::Trusted), (c.clone(), Verdict::NoWord), (d.clone(), Verdict::Denied)];
        let r = decide(&[user, admin, system]);
        // a: denied by the user, though the system trusts it; b: the user says nothing, the administrator denies;
        // c: nobody says anything, and it is a system root: trusted; d: trusted by the user, whatever the system says;
        // e: the administrator's, with settings for other purposes only: left out
        assert_eq!(r.trusted, [d.clone(), c.clone()]);
        let why: Vec<(&[u8], &str)> = r.excluded.iter().map(|(d, w)| (d.as_slice(), w.as_str())).collect();
        assert_eq!(why, [(&a[..], "denied by the user trust settings"), (&b[..], "denied by the admin trust settings"), (&e[..], "trust settings for other purposes only (user or administrator)")]);
    }

    #[test]
    fn windows_leaves_out_the_disallowed_and_roots_for_other_uses() {
        assert!(windows_verdict(false, &None).is_ok());
        assert!(windows_verdict(false, &Some(vec!["1.3.6.1.5.5.7.3.3".into(), "1.3.6.1.5.5.7.3.1".into()])).is_ok());
        assert!(windows_verdict(true, &None).unwrap_err().contains("Disallowed"));
        assert!(windows_verdict(false, &Some(vec!["1.3.6.1.5.5.7.3.4".into()])).unwrap_err().contains("does not include"));
        assert!(windows_verdict(false, &Some(vec![])).unwrap_err().contains("no use"));
    }

    #[test]
    fn a_certificate_that_does_not_parse_moves_to_the_excluded() {
        let root = crate::pem::parse(include_str!("../tests/data/as_root.pem")).remove(0).data;
        let mut n = NativeRoots { trusted: vec![root.clone(), vec![0x30, 0x00]], excluded: vec![] };
        let store = n.trust_store();
        assert_eq!(store.len(), 1);
        assert_eq!(n.trusted, [root]);
        assert!(n.excluded[0].1.starts_with("does not parse"));
    }

    #[test]
    fn what_this_system_says() {
        // on Linux there is no native store; on a Mac or Windows (or Wine) the store is read and has roots
        const HAS_ONE: bool = cfg!(any(target_os = "macos", windows));
        match native_roots() {
            Err(e) if HAS_ONE => panic!("{e}"),
            Err(_) => {}
            Ok(mut r) => {
                let store = r.trust_store();
                eprintln!("native store: {} trusted, {} left out", store.len(), r.excluded.len());
                for (der, why) in r.excluded.iter().take(20) {
                    let name = crate::x509::Certificate::from_der(der).map(|c| c.subject_summary()).unwrap_or_else(|_| "?".into());
                    eprintln!("  left out [{name}]: {why}");
                }
                assert!(store.len() > 10, "{} roots", store.len());
            }
        }
    }
}
