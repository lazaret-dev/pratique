//! The proxy the operating system is set to use (BACKLOG B-117): see [`SystemProxy`].

// (what reads the settings of macOS and of Windows is compiled everywhere, and tested everywhere; elsewhere nothing calls it)
#![cfg_attr(not(any(test, target_os = "macos", windows)), allow(dead_code))]

use super::{Proxy, Url};
use std::net::Ipv4Addr;

/// Whose settings a [`SystemProxy`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettingsSource {
    /// macOS, from the system configuration (`SCDynamicStoreCopyProxies`).
    MacOs,
    /// Windows, from the current user's `Internet Settings` in the registry.
    Windows,
}

impl std::fmt::Display for SettingsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SettingsSource::MacOs => "the macOS network settings",
            SettingsSource::Windows => "the Windows Internet Settings",
        })
    }
}

/// The operating system's proxy settings, as far as an https client goes (BACKLOG B-117): the static settings of macOS (System Settings, Network, Details,
/// Proxies; read with `SCDynamicStoreCopyProxies`) and of Windows (Internet Options, LAN settings; the current user's `Internet Settings`
/// in the registry), for a client that is to go where the machine's other programs go. A Mac or a Windows machine in a company is often
/// told its proxy that way and not in `HTTPS_PROXY`; Python's `urllib` (so pip and requests) reads the same settings, and this reads them
/// as it does.
///
/// What is read, and what is done with it:
///
/// * **The proxy for https.** macOS: the "Secure web proxy (HTTPS)", when it is on. Windows: `ProxyServer` when `ProxyEnable` is set, one
///   `host:port` for every scheme or the `https=` entry of a list (`http=…;https=…`). A proxy for plain http only is not used for https (Python
///   does not use it either), and a proxy without a port is on port 80, as Python has it.
/// * **The hosts that go direct.** macOS: "Bypass proxy settings for these hosts & domains" (globs such as `*.local`, and address prefixes
///   such as `169.254/16`) and "Exclude simple hostnames" (a name without a dot). Windows: `ProxyOverride` (globs separated by `;`, and
///   `<local>` for a name without a dot). Matched as Python matches them, without a DNS lookup, except that a Windows entry has to match the
///   whole host (Python's match is anchored at the start only, so that `example.com` there also bypasses `example.com.evil.net`; here such
///   a host goes through the proxy). `localhost` and loopback addresses always go direct, as the systems' own programs have them.
/// * **A proxy auto-config file (PAC) and auto-discovery (WPAD)** are reported ([`SystemProxy::pac`], [`SystemProxy::auto_detect`],
///   [`SystemProxy::notes`]) and **not followed**: a PAC file is a script, which this library does not run. Where one is set, name the
///   proxy it gives in `HTTPS_PROXY` (or set it as the static proxy).
/// * **What this client does not speak** (a SOCKS proxy, a proxy reached over TLS, an entry it cannot read) is reported in
///   [`SystemProxy::ignored`]; NTLM and Kerberos are not spoken either (a system proxy is used without credentials).
///
/// Linux and the other systems have no such settings (GNOME's and KDE's belong to the desktop): there the environment is all there is, and
/// [`SystemProxy::read`] gives nothing. The client reads the settings once, when it is told to ([`Client::proxy_from_system`](super::Client::proxy_from_system)),
/// and puts the environment first: see there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemProxy {
    /// Whose settings these are; `None` if none were read (another system, or nothing set).
    pub source: Option<SettingsSource>,
    /// The proxy for https URLs, if one is set and on.
    pub https: Option<Proxy>,
    /// The entries of the list of hosts that go direct, as the system has them (Windows' `<local>` is [`bypass_simple`](Self::bypass_simple)).
    pub bypass: Vec<String>,
    /// Whether a host name without a dot goes direct (macOS "Exclude simple hostnames", Windows `<local>`).
    pub bypass_simple: bool,
    /// The URL of a proxy auto-config file, if one is set: reported, not followed.
    pub pac: Option<String>,
    /// Whether the system is set to discover its proxy (WPAD): reported, not followed.
    pub auto_detect: bool,
    /// What the settings say that this client does not use, in words (a SOCKS proxy, a proxy over TLS, an entry it cannot read).
    pub ignored: Vec<String>,
}

/// What macOS says, as `SCDynamicStoreCopyProxies` has it (the keys of `kSCPropNetProxies…`).
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub(crate) struct MacSettings {
    pub(crate) https_enable: bool,
    pub(crate) https_proxy: Option<String>,
    pub(crate) https_port: Option<i64>,
    pub(crate) http_enable: bool,
    pub(crate) socks_enable: bool,
    pub(crate) exceptions: Vec<String>,
    pub(crate) exclude_simple: bool,
    pub(crate) pac_enable: bool,
    pub(crate) pac_url: Option<String>,
    pub(crate) auto_discovery: bool,
}

/// What Windows says, as the values of `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` have it.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub(crate) struct WindowsSettings {
    pub(crate) proxy_enable: bool,
    pub(crate) proxy_server: Option<String>,
    pub(crate) proxy_override: Option<String>,
    pub(crate) auto_config_url: Option<String>,
    /// The flags of `Connections\DefaultConnectionSettings` (its bytes 8 to 11), if it was there.
    pub(crate) connection_flags: Option<u32>,
}

/// `DefaultConnectionSettings`: "automatically detect settings".
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
const AUTO_DETECT: u32 = 0x08;

/// The port of a system proxy that names none: 80, as an `http://host` URL has it (and as Python then uses it).
const SYSTEM_PROXY_PORT: u16 = 80;

/// `s` if it is not empty once trimmed.
fn present(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// A proxy from `host` and `port` as a system names them, or why it cannot be used.
fn proxy_at(host: &str, port: u16) -> Result<Proxy, String> {
    let host = host.trim();
    let bracketed = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    match Proxy::parse(&format!("http://{bracketed}:{port}")) {
        Ok(p) if p.auth.is_none() && p.port == port => Ok(p),
        _ => Err(format!("the proxy {host:?} is not a host this client can reach")),
    }
}

/// A proxy from an address as Windows has it in `ProxyServer` (`host`, `host:port`, `http://host:port`), or why it cannot be used.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
fn proxy_from_address(address: &str) -> Result<Proxy, String> {
    let address = address.trim();
    let rest = match address.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
        Some((scheme, _)) => return Err(format!("the proxy {address:?} is a {scheme} proxy, which this client does not speak")),
        None => address,
    };
    let rest = rest.trim_end_matches('/');
    // host, host:port, [v6], [v6]:port
    let (host, port) = match rest.strip_prefix('[') {
        Some(r) => match r.split_once(']') {
            Some((h, "")) => (format!("[{h}]"), None),
            Some((h, p)) => (format!("[{h}]"), Some(p.strip_prefix(':').unwrap_or("x"))),
            None => return Err(format!("the proxy {address:?} is not a host and port")),
        },
        None => match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (rest.to_string(), None),
        },
    };
    let port = match port {
        None => SYSTEM_PROXY_PORT,
        Some(p) => match p.parse::<u16>() {
            Ok(p) if p != 0 => p,
            _ => return Err(format!("the proxy {address:?} has no port this client can use")),
        },
    };
    proxy_at(&host, port)
}

impl SystemProxy {
    /// The settings of the system this runs on: macOS's and Windows'; nothing elsewhere (and nothing when they cannot be read).
    pub fn read() -> SystemProxy {
        #[cfg(target_os = "macos")]
        {
            SystemProxy::from_mac(&imp::read())
        }
        #[cfg(windows)]
        {
            SystemProxy::from_windows(&imp::read())
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            SystemProxy::default()
        }
    }

    /// The settings that `m` amounts to.
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    pub(crate) fn from_mac(m: &MacSettings) -> SystemProxy {
        let mut s = SystemProxy {
            source: Some(SettingsSource::MacOs),
            bypass: m.exceptions.iter().map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect(),
            bypass_simple: m.exclude_simple,
            pac: if m.pac_enable { present(m.pac_url.as_deref()).or(Some(String::new())) } else { None },
            auto_detect: m.auto_discovery,
            ..SystemProxy::default()
        };
        match (m.https_enable, present(m.https_proxy.as_deref())) {
            (true, Some(host)) => {
                let port = match m.https_port {
                    None | Some(0) => Ok(SYSTEM_PROXY_PORT),
                    Some(p) => u16::try_from(p).map_err(|_| format!("the secure web proxy's port {p} is not a port")),
                };
                match port.and_then(|port| proxy_at(&host, port)) {
                    Ok(p) => s.https = Some(p),
                    Err(e) => s.ignored.push(e),
                }
            }
            (true, None) => s.ignored.push("the secure web proxy (HTTPS) is on and names no server".into()),
            (false, _) if m.http_enable => s.ignored.push("a web proxy (HTTP) is set, and is not used for https (the secure web proxy is off)".into()),
            _ => {}
        }
        if m.socks_enable {
            s.ignored.push("a SOCKS proxy is set, and this client does not speak SOCKS".into());
        }
        s
    }

    /// The settings that `w` amounts to.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    pub(crate) fn from_windows(w: &WindowsSettings) -> SystemProxy {
        let mut s = SystemProxy {
            source: Some(SettingsSource::Windows),
            pac: present(w.auto_config_url.as_deref()),
            auto_detect: w.connection_flags.is_some_and(|f| f & AUTO_DETECT != 0),
            ..SystemProxy::default()
        };
        for entry in w.proxy_override.as_deref().unwrap_or("").split(';').map(str::trim).filter(|e| !e.is_empty()) {
            if entry.eq_ignore_ascii_case("<local>") {
                s.bypass_simple = true;
            } else {
                s.bypass.push(entry.to_string());
            }
        }
        let server = present(w.proxy_server.as_deref());
        let Some(server) = server.filter(|_| w.proxy_enable) else { return s };
        // one address for every scheme, or `scheme=address` entries
        let https = if !server.contains('=') && !server.contains(';') {
            Some(server.as_str())
        } else {
            let mut https = None;
            let mut socks = false;
            for entry in server.split(';').map(str::trim).filter(|e| !e.is_empty()) {
                match entry.split_once('=') {
                    Some((scheme, address)) if scheme.trim().eq_ignore_ascii_case("https") => https = Some(address),
                    Some((scheme, _)) if scheme.trim().eq_ignore_ascii_case("socks") => socks = true,
                    Some(_) => {}
                    None => s.ignored.push(format!("the ProxyServer entry {entry:?} is not scheme=address")),
                }
            }
            if https.is_none() && socks {
                s.ignored.push("the proxy for https is a SOCKS proxy, and this client does not speak SOCKS".into());
            }
            https
        };
        match https.map(proxy_from_address) {
            Some(Ok(p)) => s.https = Some(p),
            Some(Err(e)) => s.ignored.push(e),
            None => {}
        }
        s
    }

    /// The proxy a request to `url` goes through under these settings: none for plain http, for a host that goes direct, and when no proxy
    /// for https is set.
    pub fn proxy_for(&self, url: &Url) -> Option<&Proxy> {
        if !url.is_https() || self.bypasses(&url.host) {
            return None;
        }
        self.https.as_ref()
    }

    /// Whether a request to `host` goes direct (the host as a URL has it: lower case, an IPv6 address without brackets).
    pub fn bypasses(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if is_loopback(host) || (self.bypass_simple && !host.contains('.')) {
            return true;
        }
        let ip = host.parse::<Ipv4Addr>().ok().map(u32::from);
        self.bypass.iter().any(|entry| {
            if self.source == Some(SettingsSource::MacOs) {
                // (Python's `_proxy_bypass_macosx_sysconf`: an entry that begins with an address is a prefix of addresses, for an address)
                if let (Some((base, mask)), Some(ip)) = (address_prefix(entry), ip) {
                    return mask <= 32 && (u128::from(ip) >> (32 - mask)) == (base >> (32 - mask));
                }
            }
            glob(&entry.to_ascii_lowercase(), host)
        })
    }

    /// What a log should say about these settings: the proxy that is used, and what is set and not followed (a PAC file, discovery, what
    /// this client does not speak). Empty when nothing is set.
    pub fn notes(&self) -> Vec<String> {
        let Some(source) = self.source else { return Vec::new() };
        let mut out = Vec::new();
        if let Some(p) = &self.https {
            let host = if p.host.contains(':') { format!("[{}]", p.host) } else { p.host.clone() };
            out.push(format!("{source} name {host}:{} as the proxy for https", p.port));
        }
        if let Some(pac) = &self.pac {
            // (the URL without its query, which some services use for an account's key)
            let shown = pac.split(['?', '#']).next().unwrap_or("");
            let shown = if shown.is_empty() { String::from("with no URL") } else { format!("at {shown}") };
            out.push(format!("{source} set a proxy auto-config file ({shown}), which is not followed (it is a script): name the proxy it gives in HTTPS_PROXY"));
        }
        if self.auto_detect {
            out.push(format!("{source} are set to discover a proxy (WPAD), which is not done: name the proxy in HTTPS_PROXY if there is one"));
        }
        out.extend(self.ignored.iter().map(|i| format!("{source}: {i}")));
        out
    }
}

/// `localhost`, a name under it, or a loopback address.
fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
}

/// The address prefix an entry of macOS's list begins with, as Python reads it (`(\d+(?:\.\d+)*)(/\d+)?` at the start of the entry): the
/// address as a number (missing parts are 0, parts after the fourth are dropped) and the length of the prefix (8 for each part written,
/// unless a `/n` says).
fn address_prefix(entry: &str) -> Option<(u128, u32)> {
    let b = entry.as_bytes();
    let digits = |from: usize| b[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut parts: Vec<u128> = Vec::new();
    let mut i = 0;
    loop {
        let n = digits(i);
        if n == 0 {
            break;
        }
        parts.push(entry[i..i + n].parse::<u128>().unwrap_or(u128::MAX >> 64));
        i += n;
        if b.get(i) == Some(&b'.') && digits(i + 1) > 0 {
            i += 1;
        } else {
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    let mask = match b.get(i) {
        Some(b'/') if digits(i + 1) > 0 => entry[i + 1..i + 1 + digits(i + 1)].parse::<u32>().unwrap_or(u32::MAX),
        _ => 8 * parts.len() as u32,
    };
    parts.resize(4, 0);
    let base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    Some((base, mask))
}

/// Whether `host` is matched, whole, by `pattern` (lower case both): `*` is any run of characters, `?` one, and the rest is itself.
fn glob(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.as_bytes(), host.as_bytes());
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < h.len() {
        match p.get(i) {
            Some(b'*') => {
                star = Some((i, j));
                i += 1;
            }
            Some(&c) if c == b'?' || c == h[j] => {
                i += 1;
                j += 1;
            }
            _ => match star {
                Some((si, sj)) => {
                    i = si + 1;
                    j = sj + 1;
                    star = Some((si, sj + 1));
                }
                None => return false,
            },
        }
    }
    p[i..].iter().all(|&c| c == b'*')
}

// ------------------------------------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod imp {
    use super::MacSettings;
    use core::ffi::{c_char, c_void};

    type CFTypeRef = *const c_void;
    type CFIndex = isize;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFArrayGetCount(array: CFTypeRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(array: CFTypeRef, index: CFIndex) -> CFTypeRef;
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFNumberGetValue(number: CFTypeRef, the_type: CFIndex, out: *mut c_void) -> u8;
        fn CFStringCreateWithBytes(alloc: CFTypeRef, bytes: *const u8, len: CFIndex, encoding: u32, external: u8) -> CFTypeRef;
        fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
        fn CFStringGetMaximumSizeForEncoding(len: CFIndex, encoding: u32) -> CFIndex;
        fn CFStringGetCString(s: CFTypeRef, buffer: *mut c_char, size: CFIndex, encoding: u32) -> u8;
        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFNumberGetTypeID() -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFDictionaryGetTypeID() -> usize;
    }

    #[link(name = "SystemConfiguration", kind = "framework")]
    extern "C" {
        fn SCDynamicStoreCopyProxies(store: CFTypeRef) -> CFTypeRef;
    }

    const NUMBER_SINT64: CFIndex = 4; // kCFNumberSInt64Type
    const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

    /// A Core Foundation object this code owns (from a Copy or Create call), released when dropped.
    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Copy or Create function, which gives a reference this code owns, and it is released once.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    /// A CFString of `s`.
    fn cfstr(s: &str) -> Owned {
        // SAFETY: the bytes are valid for `s.len()` and are copied; a null allocator is the default one.
        Owned(unsafe { CFStringCreateWithBytes(core::ptr::null(), s.as_ptr(), s.len() as CFIndex, UTF8, 0) })
    }

    /// The text of a CFString.
    ///
    /// SAFETY: `s` must be a live CFString.
    unsafe fn text(s: CFTypeRef) -> Option<String> {
        let max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), UTF8);
        if max < 0 {
            return None;
        }
        let mut buf = vec![0u8; max as usize + 1];
        if CFStringGetCString(s, buf.as_mut_ptr().cast(), buf.len() as CFIndex, UTF8) == 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).ok()
    }

    /// The proxy settings of the system configuration: what the user (or device management) set for the network in use.
    pub(super) fn read() -> MacSettings {
        // SAFETY: a null store asks for the current settings; the dictionary is a copy this code owns (or null).
        let dict = Owned(unsafe { SCDynamicStoreCopyProxies(core::ptr::null()) });
        // SAFETY: a non-null result is a live CF object, which is asked its type before it is used as a dictionary.
        if dict.0.is_null() || unsafe { CFGetTypeID(dict.0) != CFDictionaryGetTypeID() } {
            return MacSettings::default();
        }
        // (each value is borrowed from the dictionary, which lives to the end of this function, and is asked its type before it is read)
        let value = |key: &str| -> CFTypeRef {
            let k = cfstr(key);
            if k.0.is_null() {
                return core::ptr::null();
            }
            // SAFETY: both are live CF objects; the value is borrowed from `dict`.
            unsafe { CFDictionaryGetValue(dict.0, k.0) }
        };
        let number = |key: &str| -> Option<i64> {
            let v = value(key);
            // SAFETY: `v` is a live CFNumber (checked), and the output is an i64 for kCFNumberSInt64Type.
            unsafe {
                if v.is_null() || CFGetTypeID(v) != CFNumberGetTypeID() {
                    return None;
                }
                let mut n: i64 = 0;
                (CFNumberGetValue(v, NUMBER_SINT64, (&mut n as *mut i64).cast()) != 0).then_some(n)
            }
        };
        let string = |key: &str| -> Option<String> {
            let v = value(key);
            // SAFETY: `v` is a live CFString (checked).
            unsafe { (!v.is_null() && CFGetTypeID(v) == CFStringGetTypeID()).then(|| text(v)).flatten() }
        };
        let strings = |key: &str| -> Vec<String> {
            let v = value(key);
            // SAFETY: `v` is a live CFArray (checked), and each item is asked its type before it is read as a string.
            unsafe {
                if v.is_null() || CFGetTypeID(v) != CFArrayGetTypeID() {
                    return Vec::new();
                }
                (0..CFArrayGetCount(v))
                    .map(|i| CFArrayGetValueAtIndex(v, i))
                    .filter(|s| !s.is_null() && CFGetTypeID(*s) == CFStringGetTypeID())
                    .filter_map(|s| text(s))
                    .collect()
            }
        };
        let on = |key: &str| number(key).is_some_and(|n| n != 0);
        MacSettings {
            https_enable: on("HTTPSEnable"),
            https_proxy: string("HTTPSProxy"),
            https_port: number("HTTPSPort"),
            http_enable: on("HTTPEnable"),
            socks_enable: on("SOCKSEnable"),
            exceptions: strings("ExceptionsList"),
            exclude_simple: on("ExcludeSimpleHostnames"),
            pac_enable: on("ProxyAutoConfigEnable"),
            pac_url: string("ProxyAutoConfigURLString"),
            auto_discovery: on("ProxyAutoDiscoveryEnable"),
        }
    }
}

// ------------------------------------------------------------------------------------------------ Windows

#[cfg(windows)]
mod imp {
    use super::WindowsSettings;
    use core::ffi::c_void;

    type Hkey = *mut c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: Hkey, subkey: *const u16, options: u32, sam: u32, result: *mut Hkey) -> i32;
        fn RegQueryValueExW(key: Hkey, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, len: *mut u32) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }

    /// `HKEY_CURRENT_USER`: `(HKEY)(ULONG_PTR)(LONG)0x80000001`, sign-extended on a 64-bit system.
    pub(super) fn current_user() -> Hkey {
        0x8000_0001_u32 as i32 as isize as Hkey
    }

    pub(super) const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const KEY_READ: u32 = 0x2_0019;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    /// The most a value is read of (a proxy list or a bypass list longer than this is not a setting anyone made).
    const MAX_VALUE: u32 = 64 * 1024;

    pub(super) fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// An open registry key, closed when dropped.
    struct Key(Hkey);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key was opened by RegOpenKeyExW and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    impl Key {
        fn open(root: Hkey, path: &str) -> Option<Key> {
            let path = wide(path);
            let mut key: Hkey = core::ptr::null_mut();
            // SAFETY: `path` is NUL-terminated and lives through the call; `key` is written on success only.
            let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, &mut key) };
            (status == 0).then_some(Key(key))
        }

        /// A value's type and bytes.
        fn raw(&self, name: &str) -> Option<(u32, Vec<u8>)> {
            let name = wide(name);
            let (mut kind, mut len) = (0u32, 0u32);
            // SAFETY: a null buffer asks for the size; `name` is NUL-terminated.
            let status = unsafe { RegQueryValueExW(self.0, name.as_ptr(), core::ptr::null_mut(), &mut kind, core::ptr::null_mut(), &mut len) };
            if status != 0 || len > MAX_VALUE {
                return None;
            }
            let mut data = vec![0u8; len as usize];
            // SAFETY: `data` has `len` bytes, which the call writes at most.
            let status = unsafe { RegQueryValueExW(self.0, name.as_ptr(), core::ptr::null_mut(), &mut kind, data.as_mut_ptr(), &mut len) };
            if status != 0 {
                return None;
            }
            data.truncate(len as usize);
            Some((kind, data))
        }

        fn string(&self, name: &str) -> Option<String> {
            let (kind, data) = self.raw(name)?;
            if kind != REG_SZ && kind != REG_EXPAND_SZ {
                return None;
            }
            let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
            String::from_utf16(&units).ok()
        }

        fn dword(&self, name: &str) -> Option<u32> {
            match self.raw(name)? {
                (REG_DWORD, d) if d.len() >= 4 => Some(u32::from_le_bytes([d[0], d[1], d[2], d[3]])),
                _ => None,
            }
        }

        fn binary(&self, name: &str) -> Option<Vec<u8>> {
            match self.raw(name)? {
                (REG_BINARY, d) => Some(d),
                _ => None,
            }
        }
    }

    pub(super) fn read() -> WindowsSettings {
        read_key(current_user(), INTERNET_SETTINGS)
    }

    /// The settings under `path` (and its `Connections` key) of `root`.
    pub(super) fn read_key(root: Hkey, path: &str) -> WindowsSettings {
        let Some(key) = Key::open(root, path) else { return WindowsSettings::default() };
        let flags = Key::open(root, &format!(r"{path}\Connections"))
            .and_then(|c| c.binary("DefaultConnectionSettings"))
            .filter(|d| d.len() >= 12)
            .map(|d| u32::from_le_bytes([d[8], d[9], d[10], d[11]]));
        WindowsSettings {
            proxy_enable: key.dword("ProxyEnable").is_some_and(|v| v != 0),
            proxy_server: key.string("ProxyServer"),
            proxy_override: key.string("ProxyOverride"),
            auto_config_url: key.string("AutoConfigURL"),
            connection_flags: flags,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[link(name = "advapi32")]
        extern "system" {
            fn RegCreateKeyExW(key: Hkey, subkey: *const u16, reserved: u32, class: *const u16, options: u32, sam: u32, attrs: *const c_void, result: *mut Hkey, disposition: *mut u32) -> i32;
            fn RegSetValueExW(key: Hkey, name: *const u16, reserved: u32, kind: u32, data: *const u8, len: u32) -> i32;
            fn RegDeleteTreeW(key: Hkey, subkey: *const u16) -> i32;
        }

        const KEY_ALL_ACCESS: u32 = 0xF_003F;

        /// A key of the test's own under HKCU (`root`, and the settings at `path` under it), which is removed with what is under it when
        /// dropped: the user's own settings are never touched.
        struct Scratch {
            root: String,
            path: String,
        }

        impl Scratch {
            fn new() -> Scratch {
                let root = format!(r"Software\pratique-test-{}", std::process::id());
                Scratch { path: format!(r"{root}\Internet Settings"), root }
            }

            fn set(&self, sub: &str, name: &str, kind: u32, data: &[u8]) {
                let path = wide(&if sub.is_empty() { self.path.clone() } else { format!(r"{}\{sub}", self.path) });
                let mut key: Hkey = core::ptr::null_mut();
                // SAFETY: the strings are NUL-terminated and live through the calls; the key is closed by `Key`.
                unsafe {
                    let mut disposition = 0;
                    assert_eq!(RegCreateKeyExW(current_user(), path.as_ptr(), 0, core::ptr::null(), 0, KEY_ALL_ACCESS, core::ptr::null(), &mut key, &mut disposition), 0);
                    let key = Key(key);
                    assert_eq!(RegSetValueExW(key.0, wide(name).as_ptr(), 0, kind, data.as_ptr(), data.len() as u32), 0);
                }
            }

            fn string(&self, sub: &str, name: &str, value: &str) {
                let bytes: Vec<u8> = wide(value).iter().flat_map(|u| u.to_le_bytes()).collect();
                self.set(sub, name, REG_SZ, &bytes);
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                // SAFETY: the path is NUL-terminated; the tree is the test's own.
                unsafe { RegDeleteTreeW(current_user(), wide(&self.root).as_ptr()) };
            }
        }

        #[test]
        fn the_settings_are_read_from_the_registry() {
            let scratch = Scratch::new();
            // nothing there yet: nothing read
            assert!(read_key(current_user(), &scratch.path).proxy_server.is_none());
            scratch.set("", "ProxyEnable", REG_DWORD, &1u32.to_le_bytes());
            scratch.string("", "ProxyServer", "http=web.example:80;https=secure.example:8443;socks=s.example:1080");
            scratch.string("", "ProxyOverride", "*.corp.example;<local>;10.*");
            scratch.string("", "AutoConfigURL", "http://wpad.corp.example/proxy.pac");
            let mut connection = vec![0x46, 0, 0, 0, 5, 0, 0, 0];
            connection.extend_from_slice(&(0x01u32 | 0x08).to_le_bytes());
            connection.extend_from_slice(&[0; 20]);
            scratch.set("Connections", "DefaultConnectionSettings", REG_BINARY, &connection);
            let w = read_key(current_user(), &scratch.path);
            assert!(w.proxy_enable);
            assert_eq!(w.proxy_server.as_deref(), Some("http=web.example:80;https=secure.example:8443;socks=s.example:1080"));
            assert_eq!(w.proxy_override.as_deref(), Some("*.corp.example;<local>;10.*"));
            assert_eq!(w.auto_config_url.as_deref(), Some("http://wpad.corp.example/proxy.pac"));
            assert_eq!(w.connection_flags, Some(0x09));
            let s = super::super::SystemProxy::from_windows(&w);
            let p = s.https.as_ref().unwrap();
            assert_eq!((p.host.as_str(), p.port), ("secure.example", 8443));
            assert!(s.bypass_simple && s.auto_detect && s.bypasses("a.corp.example") && s.bypasses("10.1.2.3") && !s.bypasses("pypi.org"));
            // off: the server is there and is not used
            scratch.set("", "ProxyEnable", REG_DWORD, &0u32.to_le_bytes());
            assert!(super::super::SystemProxy::from_windows(&read_key(current_user(), &scratch.path)).https.is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn mac(https: Option<(&str, i64)>) -> MacSettings {
        MacSettings {
            https_enable: https.is_some(),
            https_proxy: https.map(|h| h.0.to_string()),
            https_port: https.map(|h| h.1),
            exceptions: vec!["*.local".into(), "169.254/16".into()],
            ..MacSettings::default()
        }
    }

    fn at(s: &SystemProxy) -> Option<(String, u16)> {
        s.https.as_ref().map(|p| (p.host.clone(), p.port))
    }

    #[test]
    fn the_secure_web_proxy_of_macos_is_the_one_for_https() {
        let s = SystemProxy::from_mac(&mac(Some(("proxy.corp.example", 3128))));
        assert_eq!(at(&s), Some(("proxy.corp.example".into(), 3128)));
        assert_eq!(s.proxy_for(&url("https://pypi.org/simple/")).map(|p| p.port), Some(3128));
        // not for plain http, and not for what the list sends direct (macOS's default list: `*.local` and the link-local addresses)
        assert!(s.proxy_for(&url("http://pypi.org/")).is_none());
        for direct in ["https://printer.local/", "https://169.254.10.20/", "https://localhost/", "https://127.0.0.1/", "https://[::1]/"] {
            assert!(s.proxy_for(&url(direct)).is_none(), "{direct}");
        }
        assert!(s.proxy_for(&url("https://169.255.0.1/")).is_some() && s.proxy_for(&url("https://local/")).is_some());
        // off, or with no server: none (and the second is said)
        let mut m = mac(Some(("proxy.corp.example", 3128)));
        m.https_enable = false;
        assert!(SystemProxy::from_mac(&m).https.is_none());
        let mut m = mac(Some(("", 3128)));
        m.https_proxy = None;
        let s = SystemProxy::from_mac(&m);
        assert!(s.https.is_none() && s.ignored[0].contains("names no server"), "{s:?}");
        // a port of 0 or none is 80 (as Python makes `http://host` of it); an IPv6 address is one
        assert_eq!(at(&SystemProxy::from_mac(&mac(Some(("proxy.corp.example", 0))))), Some(("proxy.corp.example".into(), 80)));
        assert_eq!(at(&SystemProxy::from_mac(&mac(Some(("fd00::1", 8080))))), Some(("fd00::1".into(), 8080)));
        // what cannot be a proxy is said, not used
        for (host, port) in [("proxy.corp.example", 70000), ("bad host", 3128), ("user@proxy", 3128), ("proxy/x", 3128)] {
            let s = SystemProxy::from_mac(&mac(Some((host, port))));
            assert!(s.https.is_none() && s.ignored.len() == 1, "{host}:{port}: {s:?}");
        }
    }

    #[test]
    fn a_web_proxy_for_http_alone_and_socks_are_reported_and_not_used() {
        let m = MacSettings { http_enable: true, socks_enable: true, ..mac(None) };
        let s = SystemProxy::from_mac(&m);
        assert!(s.https.is_none());
        assert_eq!(s.ignored.len(), 2, "{s:?}");
        assert!(s.notes().iter().any(|n| n.contains("SOCKS")) && s.notes().iter().any(|n| n.contains("not used for https")));
    }

    #[test]
    fn a_pac_file_and_discovery_are_reported_and_not_followed() {
        let m = MacSettings { pac_enable: true, pac_url: Some("https://pac.example/corp/proxy.pac?key=secret".into()), auto_discovery: true, ..mac(None) };
        let s = SystemProxy::from_mac(&m);
        assert_eq!(s.pac.as_deref(), Some("https://pac.example/corp/proxy.pac?key=secret"));
        assert!(s.auto_detect && s.https.is_none() && s.proxy_for(&url("https://pypi.org/")).is_none());
        let notes = s.notes().join("\n");
        assert!(notes.contains("https://pac.example/corp/proxy.pac") && !notes.contains("secret"), "{notes}");
        assert!(notes.contains("not followed") && notes.contains("WPAD"), "{notes}");
        // set and off: nothing
        let m = MacSettings { pac_enable: false, pac_url: Some("https://pac.example/proxy.pac".into()), ..mac(None) };
        assert!(SystemProxy::from_mac(&m).pac.is_none() && SystemProxy::from_mac(&m).notes().is_empty());
        // with a static proxy as well: the static one is used, and the PAC file is still said
        let m = MacSettings { pac_enable: true, pac_url: Some("https://pac.example/proxy.pac".into()), ..mac(Some(("proxy.corp.example", 3128))) };
        let s = SystemProxy::from_mac(&m);
        assert!(s.proxy_for(&url("https://pypi.org/")).is_some() && s.notes().len() == 2, "{:?}", s.notes());
    }

    #[test]
    fn the_bypass_list_of_macos_is_read_as_python_reads_it() {
        let m = MacSettings { exceptions: vec!["*.corp.example".into(), "Build.Example".into(), "10/8".into(), "192.168.1.*".into(), "172.16/12".into(), "1.2.3.4/40".into(), "".into()], ..mac(Some(("p.example", 3128))) };
        let s = SystemProxy::from_mac(&m);
        for direct in ["a.corp.example", "a.b.corp.example", "build.example", "10.200.3.4", "192.168.1.77", "172.31.255.1", "172.16.0.1"] {
            assert!(s.bypasses(direct), "{direct}");
        }
        for proxied in ["corp.example", "a.corp.example.evil.net", "build.example.org", "11.0.0.1", "192.168.2.1", "172.32.0.1", "1.2.3.4", "pypi.org", "simple"] {
            assert!(!s.bypasses(proxied), "{proxied}");
        }
        // an address prefix is about addresses: a name is matched by the glob, which `10/8` is not
        assert!(!s.bypasses("10.example"));
        // "exclude simple hostnames": a name without a dot
        let s = SystemProxy::from_mac(&MacSettings { exclude_simple: true, ..m });
        assert!(s.bypasses("simple") && s.bypasses("intranet") && !s.bypasses("pypi.org"));
    }

    #[test]
    fn windows_has_one_proxy_for_every_scheme_or_one_for_each() {
        let w = |server: &str| WindowsSettings { proxy_enable: true, proxy_server: Some(server.into()), ..WindowsSettings::default() };
        for (server, want) in [
            ("proxy.corp.example:8080", Some(("proxy.corp.example", 8080))),
            ("http://proxy.corp.example:8080", Some(("proxy.corp.example", 8080))),
            ("proxy.corp.example", Some(("proxy.corp.example", 80))),
            ("[fd00::1]:3128", Some(("fd00::1", 3128))),
            ("http=web.example:80;https=secure.example:443", Some(("secure.example", 443))),
            ("HTTPS = secure.example:443 ; http=web.example:80", Some(("secure.example", 443))),
            ("http=web.example:80", None),
            ("http=web.example:80;ftp=f.example:21", None),
        ] {
            let s = SystemProxy::from_windows(&w(server));
            assert_eq!(at(&s), want.map(|(h, p)| (h.to_string(), p)), "{server}");
        }
        // what this client does not speak, and what cannot be read, is said and not used
        for server in ["socks=s.example:1080", "https://secure.example:443", "https=socks5://s.example:1080", "proxy.corp.example:0", "proxy.corp.example:x", "http=a;nonsense"] {
            let s = SystemProxy::from_windows(&w(server));
            assert!(s.https.is_none() && !s.ignored.is_empty(), "{server}: {s:?}");
        }
        // off: not used
        let s = SystemProxy::from_windows(&WindowsSettings { proxy_enable: false, ..w("proxy.corp.example:8080") });
        assert!(s.https.is_none() && s.ignored.is_empty());
    }

    #[test]
    fn the_bypass_list_of_windows_matches_whole_hosts() {
        let w = WindowsSettings { proxy_enable: true, proxy_server: Some("p.example:8080".into()), proxy_override: Some(" *.corp.example ; <local>;Build.Example;10.*;192.168.?.1;;".into()), ..WindowsSettings::default() };
        let s = SystemProxy::from_windows(&w);
        assert!(s.bypass_simple);
        assert_eq!(s.bypass, ["*.corp.example", "Build.Example", "10.*", "192.168.?.1"]);
        for direct in ["a.corp.example", "build.example", "10.1.2.3", "192.168.5.1", "intranet"] {
            assert!(s.bypasses(direct), "{direct}");
        }
        // (Python's match is anchored at the start only; this one is not, so that these go through the proxy)
        for proxied in ["build.example.evil.net", "corp.example", "192.168.15.1", "pypi.org", "a.corp.example.org"] {
            assert!(!s.bypasses(proxied), "{proxied}");
        }
    }

    #[test]
    fn windows_reports_its_setup_script_and_discovery() {
        let w = WindowsSettings { auto_config_url: Some("http://wpad.corp.example/proxy.pac".into()), connection_flags: Some(0x0d), ..WindowsSettings::default() };
        let s = SystemProxy::from_windows(&w);
        assert!(s.pac.is_some() && s.auto_detect && s.https.is_none());
        assert_eq!(s.notes().len(), 2);
        assert!(!SystemProxy::from_windows(&WindowsSettings { connection_flags: Some(0x01), ..w }).auto_detect);
    }

    #[test]
    fn the_glob_is_whole_and_without_case() {
        for (p, h, want) in [
            ("*.example.com", "a.example.com", true),
            ("*.example.com", "example.com", false),
            ("*", "anything", true),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "aXXbYY", false),
            ("?.example", "a.example", true),
            ("?.example", "ab.example", false),
            ("example", "example.org", false),
            ("**x", "ax", true),
            ("", "", true),
            ("", "a", false),
        ] {
            assert_eq!(glob(p, h), want, "{p} {h}");
        }
    }

    #[test]
    fn an_address_prefix_is_read_as_python_reads_it() {
        assert_eq!(address_prefix("169.254/16"), Some(((169 << 24) | (254 << 16), 16)));
        assert_eq!(address_prefix("10"), Some((10 << 24, 8)));
        assert_eq!(address_prefix("192.168.1.*"), Some(((192 << 24) | (168 << 16) | (1 << 8), 24)));
        assert_eq!(address_prefix("1.2.3.4.5"), Some(((1 << 24) | (2 << 16) | (3 << 8) | 4, 40)));
        assert_eq!(address_prefix("*.local"), None);
        assert_eq!(address_prefix("local"), None);
    }

    #[test]
    fn nothing_set_is_nothing_to_say() {
        assert!(SystemProxy::default().notes().is_empty() && SystemProxy::default().proxy_for(&url("https://pypi.org/")).is_none());
        // (on this system, whatever it is, reading gives something that can be asked)
        let _ = SystemProxy::read().proxy_for(&url("https://pypi.org/"));
    }
}
