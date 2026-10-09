//! A cookie jar for the clients ([`Client::cookie_jar`](super::Client::cookie_jar)): RFC 6265 with the stricter rules of its revision
//! (RFC 6265bis), and stricter still where a browser has a public-suffix list to lean on and this client has none.
//!
//! What it does:
//!
//! * every cookie is *host-only*: it goes back to the host that set it and to no other. A `Domain` attribute is honoured only as far as
//!   it names that host or a domain the host is in (otherwise the cookie is refused), and the cookie is then kept for the host that set
//!   it, not for the domain. Without a list of public suffixes there is no telling `example.com` from `co.uk`, and a cookie that a host
//!   sets for every host of a domain is how one host plants a session on another (cookie tossing);
//! * `Path`, `Secure`, `Expires` and `Max-Age` as the RFC says (`Max-Age` wins; zero or less deletes), and the `__Secure-` and
//!   `__Host-` prefixes as RFC 6265bis says; a `Secure` cookie only from https, and plain http cannot overwrite one;
//! * limits: 50 cookies a host, 3,000 in all, 4,096 bytes for a name and its value; the oldest goes first when one is reached;
//! * `HttpOnly` and `SameSite` mean nothing to a client that runs no scripts and has no sites, and are ignored.
//!
//! The jar is shared by the clones of a handle, and so by every client it is given to.

use super::url::Url;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PER_HOST: usize = 50;
const MAX_TOTAL: usize = 3000;
const MAX_PAIR: usize = 4096;
/// The latest expiry kept (the year 9999); later ones are cut to it.
const MAX_EXPIRY: i64 = 253_402_300_799;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cookie {
    name: String,
    value: String,
    host: String,
    path: String,
    secure: bool,
    /// Seconds since 1970; `None` for a cookie that lasts as long as the jar.
    expires: Option<i64>,
    /// The order the cookies were first set in.
    created: u64,
}

#[derive(Debug, Default)]
struct Store {
    cookies: Vec<Cookie>,
    next: u64,
}

/// A store of cookies, for [`Client::cookie_jar`](super::Client::cookie_jar). Cheap to clone; the clones share the cookies.
///
/// ```
/// use pratique::http::{CookieJar, Url};
/// let jar = CookieJar::new();
/// let url = Url::parse("https://api.example.com/v1/login").unwrap();
/// assert!(jar.set_cookie(&url, "session=abc123; Path=/; Secure; HttpOnly"));
/// assert_eq!(jar.header_for(&Url::parse("https://api.example.com/v1/items").unwrap()).as_deref(), Some("session=abc123"));
/// // host-only: not for another host, not even one of the same domain
/// assert_eq!(jar.header_for(&Url::parse("https://www.example.com/").unwrap()), None);
/// ```
#[derive(Clone, Debug, Default)]
pub struct CookieJar {
    store: Arc<Mutex<Store>>,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl CookieJar {
    pub fn new() -> CookieJar {
        CookieJar::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        // (a panic elsewhere while it was held leaves a store that is still a list of cookies)
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Takes in one `Set-Cookie` header as if it had come with a response from `url`; false if it was refused (or only deleted a
    /// cookie). For cookies that the caller got some other way.
    pub fn set_cookie(&self, url: &Url, header: &str) -> bool {
        self.set_cookie_at(url, header, now())
    }

    /// The `Cookie` header that a request to `url` would carry now, if any cookie is for it.
    pub fn header_for(&self, url: &Url) -> Option<String> {
        self.header_for_at(url, now())
    }

    /// The names and values of the cookies a request to `url` would carry now, in the order they would be sent.
    pub fn cookies_for(&self, url: &Url) -> Vec<(String, String)> {
        self.matching(url, now()).into_iter().map(|c| (c.name, c.value)).collect()
    }

    /// How many cookies the jar holds (some may have expired and not been dropped yet).
    pub fn len(&self) -> usize {
        self.lock().cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every cookie.
    pub fn clear(&self) {
        self.lock().cookies.clear();
    }

    /// Drops the cookies of one host.
    pub fn clear_host(&self, host: &str) {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.lock().cookies.retain(|c| c.host != host);
    }

    /// Takes in the `Set-Cookie` headers of a response from `url`.
    pub(crate) fn store_from<'a>(&self, url: &Url, headers: impl Iterator<Item = &'a str>) {
        let t = now();
        for h in headers {
            self.set_cookie_at(url, h, t);
        }
    }

    pub(crate) fn header_for_at(&self, url: &Url, t: i64) -> Option<String> {
        let cookies = self.matching(url, t);
        if cookies.is_empty() {
            return None;
        }
        Some(cookies.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; "))
    }

    fn matching(&self, url: &Url, t: i64) -> Vec<Cookie> {
        let path = request_path(url);
        let mut store = self.lock();
        store.cookies.retain(|c| c.expires.map_or(true, |e| e > t));
        let mut out: Vec<Cookie> = store.cookies.iter().filter(|c| c.host == url.host && path_matches(&path, &c.path) && (!c.secure || url.is_https())).cloned().collect();
        // longer paths first, then the older cookie (RFC 6265, 5.4)
        out.sort_by(|a, b| b.path.len().cmp(&a.path.len()).then(a.created.cmp(&b.created)));
        out
    }

    pub(crate) fn set_cookie_at(&self, url: &Url, header: &str, t: i64) -> bool {
        let Some(mut cookie) = parse(url, header, t) else { return false };
        let mut store = self.lock();
        let s = &mut *store;
        s.cookies.retain(|c| c.expires.map_or(true, |e| e > t));
        // plain http does not get to replace (or shadow) a Secure cookie (RFC 6265bis, 5.7, step 14)
        if !url.is_https() && s.cookies.iter().any(|c| c.secure && c.name == cookie.name && c.host == cookie.host && (path_matches(&cookie.path, &c.path) || path_matches(&c.path, &cookie.path))) {
            return false;
        }
        let old = s.cookies.iter().position(|c| c.name == cookie.name && c.host == cookie.host && c.path == cookie.path);
        if let Some(i) = old {
            cookie.created = s.cookies[i].created;
            s.cookies.remove(i);
        } else {
            cookie.created = s.next;
            s.next += 1;
        }
        if cookie.expires.is_some_and(|e| e <= t) {
            // an expiry in the past is how a cookie is deleted
            return false;
        }
        s.cookies.push(cookie);
        // the limits: the oldest of the host, then the oldest of all
        let host = s.cookies.last().map(|c| c.host.clone()).unwrap_or_default();
        while s.cookies.iter().filter(|c| c.host == host).count() > MAX_PER_HOST {
            let i = s.cookies.iter().enumerate().filter(|(_, c)| c.host == host).min_by_key(|(_, c)| c.created).map(|(i, _)| i).unwrap();
            s.cookies.remove(i);
        }
        while s.cookies.len() > MAX_TOTAL {
            let i = s.cookies.iter().enumerate().min_by_key(|(_, c)| c.created).map(|(i, _)| i).unwrap();
            s.cookies.remove(i);
        }
        true
    }
}

/// The path of a URL, without its query.
fn request_path(url: &Url) -> String {
    let p = url.path_and_query.split('?').next().unwrap_or("/");
    if p.starts_with('/') {
        p.to_string()
    } else {
        "/".to_string()
    }
}

/// The path a cookie gets when it names none (RFC 6265, 5.1.4): the request's path up to its last `/`.
fn default_path(url: &Url) -> String {
    let p = request_path(url);
    match p.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => p[..i].to_string(),
    }
}

/// RFC 6265, 5.1.4.
fn path_matches(request: &str, cookie: &str) -> bool {
    request == cookie || (request.starts_with(cookie) && (cookie.ends_with('/') || request.as_bytes().get(cookie.len()) == Some(&b'/')))
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// One `Set-Cookie` header from `url`, as RFC 6265 section 5.2 reads it and with the checks of 5.3 and of RFC 6265bis; `None` if it is
/// to be ignored.
fn parse(url: &Url, header: &str, t: i64) -> Option<Cookie> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let (name, value) = (name.trim(), value.trim());
    if name.is_empty() || name.len() + value.len() > MAX_PAIR {
        return None;
    }
    let bad = |s: &str| s.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f);
    if bad(name) || bad(value) || name.contains(|c: char| c == '=' || c.is_whitespace()) {
        return None;
    }
    let mut expires: Option<i64> = None;
    let mut max_age: Option<i64> = None;
    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut secure = false;
    for attr in parts {
        let (key, val) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (attr.trim(), ""),
        };
        if key.eq_ignore_ascii_case("expires") {
            if let Some(e) = parse_cookie_date(val) {
                expires = Some(e);
            }
        } else if key.eq_ignore_ascii_case("max-age") {
            let digits = val.strip_prefix('-').unwrap_or(val);
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                // a number too long to read is a very long time, or a very long time ago
                let n: i64 = digits.parse().unwrap_or(i64::MAX);
                max_age = Some(if val.starts_with('-') { -1 } else { n });
            }
        } else if key.eq_ignore_ascii_case("domain") {
            let d = val.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
            domain = (!d.is_empty()).then_some(d);
        } else if key.eq_ignore_ascii_case("path") {
            path = val.starts_with('/').then(|| val.to_string());
        } else if key.eq_ignore_ascii_case("secure") {
            secure = true;
        }
    }
    // the Domain: only the host itself or a domain it is in, and the cookie stays the host's
    if let Some(d) = &domain {
        let inside = url.host == *d || (!is_ip(&url.host) && url.host.ends_with(&format!(".{d}")));
        if !inside {
            return None;
        }
    }
    if secure && !url.is_https() {
        return None;
    }
    let path_said = path.is_some();
    let path = path.unwrap_or_else(|| default_path(url));
    // the prefixes (RFC 6265bis, 4.1.3)
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("__secure-") && !secure {
        return None;
    }
    if lower.starts_with("__host-") && (!secure || domain.is_some() || !path_said || path != "/") {
        return None;
    }
    let expires = match max_age {
        Some(n) if n <= 0 => Some(i64::MIN),
        Some(n) => Some(t.saturating_add(n).min(MAX_EXPIRY)),
        None => expires.map(|e| e.min(MAX_EXPIRY)),
    };
    Some(Cookie { name: name.to_string(), value: value.to_string(), host: url.host.clone(), path, secure, expires, created: 0 })
}

/// A date in a cookie (RFC 6265, 5.1.1), as seconds since 1970: the forgiving reading that browsers share, which takes the formats of
/// RFC 1123, RFC 850 and asctime alike.
pub(crate) fn parse_cookie_date(text: &str) -> Option<i64> {
    let delimiter = |c: char| c == '\t' || (' '..='/').contains(&c) || (';'..='@').contains(&c) || ('['..='`').contains(&c) || ('{'..='~').contains(&c);
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    // a token's leading digits (1 to `max` of them) and whether anything follows them
    fn digits(token: &str, min: usize, max: usize) -> Option<(u32, &str)> {
        let n = token.bytes().take_while(|b| b.is_ascii_digit()).count();
        if n < min || n > max {
            return None;
        }
        Some((token[..n].parse().ok()?, &token[n..]))
    }
    for token in text.split(delimiter).filter(|t| !t.is_empty()) {
        if time.is_none() {
            let parsed = (|| {
                let (h, rest) = digits(token, 1, 2)?;
                let (m, rest) = digits(rest.strip_prefix(':')?, 1, 2)?;
                let (s, rest) = digits(rest.strip_prefix(':')?, 1, 2)?;
                rest.bytes().all(|b| !b.is_ascii_digit()).then_some((h, m, s))
            })();
            if parsed.is_some() {
                time = parsed;
                continue;
            }
        }
        if day.is_none() {
            if let Some((d, rest)) = digits(token, 1, 2) {
                if rest.bytes().all(|b| !b.is_ascii_digit()) {
                    day = Some(d);
                    continue;
                }
            }
        }
        if month.is_none() && token.len() >= 3 {
            const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
            if let Some(m) = MONTHS.iter().position(|m| token[..3].eq_ignore_ascii_case(m)) {
                month = Some(m as u32 + 1);
                continue;
            }
        }
        if year.is_none() {
            if let Some((y, rest)) = digits(token, 2, 4) {
                if rest.bytes().all(|b| !b.is_ascii_digit()) {
                    year = Some(y);
                    continue;
                }
            }
        }
    }
    let (h, mi, s) = time?;
    let (d, mo, mut y) = (day?, month?, year?);
    if (70..=99).contains(&y) {
        y += 1900;
    } else if y <= 69 {
        y += 2000;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo as usize - 1];
    if y < 1601 || d < 1 || d > days_in_month || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(days_from_civil(y as i64, mo as i64, d as i64) * 86_400 + (h * 3600 + mi * 60 + s) as i64)
}

/// Days since 1970-01-01 of a date of the proleptic Gregorian calendar (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_790_000_000; // 2026-09-21

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn jar_with(url: &str, headers: &[&str]) -> CookieJar {
        let jar = CookieJar::new();
        for h in headers {
            jar.set_cookie_at(&u(url), h, T);
        }
        jar
    }

    fn sent(jar: &CookieJar, url: &str) -> Option<String> {
        jar.header_for_at(&u(url), T + 1)
    }

    #[test]
    fn dates_in_every_format_that_is_out_there() {
        // 1994-11-06 08:49:37 UTC
        let want = Some(784_111_777);
        for d in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994", "06 nov 1994 8:49:37", "Sun, 06-Nov-1994 08:49:37 UTC", "1994 Nov 6 08:49:37"] {
            assert_eq!(parse_cookie_date(d), want, "{d}");
        }
        assert_eq!(parse_cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_cookie_date("Wed, 21 Oct 2015 07:28:00 GMT"), Some(1_445_412_480));
        assert_eq!(parse_cookie_date("Fri, 31 Dec 9999 23:59:59 GMT"), Some(MAX_EXPIRY));
        assert_eq!(parse_cookie_date("Tue, 29 Feb 2028 12:00:00 GMT"), Some(1_835_438_400));
        // two-digit years: 70 to 99 are the 1900s, the rest the 2000s
        assert_eq!(parse_cookie_date("01 Jan 69 00:00:00"), parse_cookie_date("01 Jan 2069 00:00:00"));
        assert_eq!(parse_cookie_date("01 Jan 70 00:00:00"), Some(0));
        for bad in ["", "yesterday", "Sun, 06 Nov 1994", "06 Nov 1994 25:00:00", "31 Feb 2026 00:00:00", "29 Feb 2027 00:00:00", "06 Xyz 1994 08:49:37", "06 Nov 1600 08:49:37", "0 Nov 1994 08:49:37", "06 Nov 12345 08:49:37"] {
            assert_eq!(parse_cookie_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_cookie_goes_back_to_its_host_and_its_path_only() {
        let jar = jar_with("https://api.example.com/v1/login", &["a=1", "b=2; Path=/", "c=3; Path=/v1/items"]);
        // a (default path /v1), b (/), c (/v1/items): longer paths first
        assert_eq!(sent(&jar, "https://api.example.com/v1/items/7").as_deref(), Some("c=3; a=1; b=2"));
        assert_eq!(sent(&jar, "https://api.example.com/v1").as_deref(), Some("a=1; b=2"));
        assert_eq!(sent(&jar, "https://api.example.com/v10").as_deref(), Some("b=2"));
        assert_eq!(sent(&jar, "https://api.example.com/").as_deref(), Some("b=2"));
        // any port and scheme of the host (a cookie is a host's), and no other host
        assert_eq!(sent(&jar, "http://api.example.com:8080/").as_deref(), Some("b=2"));
        for other in ["https://example.com/", "https://www.example.com/", "https://x.api.example.com/", "https://api.example.com.evil.test/"] {
            assert_eq!(sent(&jar, other), None, "{other}");
        }
    }

    #[test]
    fn a_domain_attribute_does_not_widen_a_cookie() {
        let jar = jar_with("https://login.example.com/", &["sso=1; Domain=example.com; Path=/", "own=2; Domain=.login.example.com; Path=/"]);
        assert_eq!(sent(&jar, "https://login.example.com/").as_deref(), Some("sso=1; own=2"));
        assert_eq!(sent(&jar, "https://www.example.com/"), None);
        assert_eq!(sent(&jar, "https://example.com/"), None);
        // a domain the host is not in is refused outright
        for h in ["x=1; Domain=other.com", "x=1; Domain=ample.com", "x=1; Domain=www.login.example.com"] {
            assert!(!jar.set_cookie_at(&u("https://login.example.com/"), h, T), "{h}");
        }
        // an address is its own domain and no other
        assert!(jar.set_cookie_at(&u("https://10.0.0.1/"), "ip=1; Domain=10.0.0.1", T));
        assert!(!jar.set_cookie_at(&u("https://10.0.0.1/"), "ip=1; Domain=0.0.1", T));
    }

    #[test]
    fn secure_cookies_and_the_prefixes() {
        let jar = CookieJar::new();
        assert!(jar.set_cookie_at(&u("https://a.test/"), "s=1; Secure; Path=/", T));
        assert_eq!(sent(&jar, "https://a.test/").as_deref(), Some("s=1"));
        assert_eq!(sent(&jar, "http://a.test/"), None);
        // not from plain http, which cannot overwrite one either
        assert!(!jar.set_cookie_at(&u("http://a.test/"), "t=1; Secure", T));
        assert!(!jar.set_cookie_at(&u("http://a.test/"), "s=evil; Path=/", T));
        assert!(!jar.set_cookie_at(&u("http://a.test/x"), "s=evil; Path=/x", T));
        assert_eq!(sent(&jar, "https://a.test/x").as_deref(), Some("s=1"));
        // __Secure- needs Secure; __Host- needs Secure, Path=/ and no Domain
        assert!(!jar.set_cookie_at(&u("https://a.test/"), "__Secure-x=1", T));
        assert!(jar.set_cookie_at(&u("https://a.test/"), "__Secure-x=1; Secure", T));
        assert!(!jar.set_cookie_at(&u("https://a.test/"), "__Host-y=1; Secure", T)); // the default path is /, but Path must be said
        assert!(!jar.set_cookie_at(&u("https://a.test/"), "__Host-y=1; Secure; Path=/; Domain=a.test", T));
        assert!(jar.set_cookie_at(&u("https://a.test/"), "__Host-y=1; Secure; Path=/", T));
        assert!(!jar.set_cookie_at(&u("https://a.test/"), "__HOST-z=1; Path=/", T));
    }

    #[test]
    fn expiry_replacement_and_deletion() {
        let jar = CookieJar::new();
        let url = u("https://a.test/");
        assert!(jar.set_cookie_at(&url, "k=1; Max-Age=60; Path=/", T));
        assert!(jar.set_cookie_at(&url, "old=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/", T) == false);
        assert!(jar.set_cookie_at(&url, "session=1; Path=/", T));
        assert_eq!(jar.header_for_at(&url, T + 59).as_deref(), Some("k=1; session=1"));
        assert_eq!(jar.header_for_at(&url, T + 60).as_deref(), Some("session=1"));
        // Max-Age wins over Expires
        assert!(jar.set_cookie_at(&url, "m=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=100; Path=/", T));
        assert_eq!(jar.header_for_at(&url, T + 99).as_deref(), Some("session=1; m=1"));
        // the same name, host and path replaces (and keeps its place), Max-Age=0 deletes
        assert!(jar.set_cookie_at(&url, "session=2; Path=/", T));
        assert_eq!(jar.header_for_at(&url, T).as_deref(), Some("session=2; m=1"));
        assert!(!jar.set_cookie_at(&url, "session=x; Max-Age=0; Path=/", T));
        assert!(!jar.set_cookie_at(&url, "m=x; Max-Age=-5; Path=/", T));
        assert_eq!(jar.header_for_at(&url, T), None);
        // a Max-Age that is not a number is no Max-Age; one that is too long to read is a long time
        assert!(jar.set_cookie_at(&url, "n=1; Max-Age=soon; Path=/", T));
        assert!(jar.set_cookie_at(&url, "f=1; Max-Age=99999999999999999999999; Path=/", T));
        assert_eq!(jar.header_for_at(&url, MAX_EXPIRY - 1).as_deref(), Some("n=1; f=1"));
    }

    #[test]
    fn what_is_not_a_cookie_is_ignored() {
        let jar = CookieJar::new();
        let url = u("https://a.test/");
        for h in ["", "novalue", "=nameless", " =x", "a b=1", "x=\u{1}", "x=a\u{7f}b", &format!("big={}", "v".repeat(MAX_PAIR))] {
            assert!(!jar.set_cookie_at(&url, h, T), "{h:?}");
        }
        assert!(jar.is_empty());
        // quotes, spaces around, an empty value and odd attributes are all fine
        assert!(jar.set_cookie_at(&url, " q = \"a b\" ; Path = / ; HttpOnly; SameSite=Strict; Unknown", T));
        assert!(jar.set_cookie_at(&url, "e=; Path=/", T));
        assert_eq!(jar.header_for_at(&url, T).as_deref(), Some("q=\"a b\"; e="));
        // a path that does not start with / is the default path
        assert!(jar.set_cookie_at(&u("https://a.test/dir/page"), "p=1; Path=relative", T));
        assert_eq!(jar.header_for_at(&u("https://a.test/dir/x"), T).as_deref(), Some("p=1; q=\"a b\"; e="));
        assert_eq!(jar.header_for_at(&u("https://a.test/other"), T).as_deref(), Some("q=\"a b\"; e="));
    }

    #[test]
    fn the_limits_drop_the_oldest() {
        let jar = CookieJar::new();
        for i in 0..MAX_PER_HOST + 5 {
            assert!(jar.set_cookie_at(&u("https://many.test/"), &format!("c{i}=1; Path=/"), T));
        }
        assert_eq!(jar.len(), MAX_PER_HOST);
        let sent = jar.header_for_at(&u("https://many.test/"), T).unwrap();
        assert!(!sent.contains("c0=") && !sent.contains("c4=") && sent.contains("c5=") && sent.contains(&format!("c{}=", MAX_PER_HOST + 4)));
        for h in 0..(MAX_TOTAL / MAX_PER_HOST + 2) {
            for i in 0..MAX_PER_HOST {
                jar.set_cookie_at(&u(&format!("https://h{h}.test/")), &format!("c{i}=1"), T);
            }
        }
        assert_eq!(jar.len(), MAX_TOTAL);
        // the newest hosts are whole, the oldest are gone
        assert_eq!(jar.header_for_at(&u("https://many.test/"), T), None);
        assert!(jar.header_for_at(&u(&format!("https://h{}.test/", MAX_TOTAL / MAX_PER_HOST + 1)), T).is_some());
        jar.clear_host("H61.test.");
        jar.clear();
        assert!(jar.is_empty());
    }
}
