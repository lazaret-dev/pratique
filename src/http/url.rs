//! A small URL type for http(s) requests.

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// "http" or "https"
    pub scheme: String,
    /// Lower-cased host; IPv6 literals are stored WITHOUT brackets.
    pub host: String,
    pub port: u16,
    /// Path plus optional "?query", always starting with '/'.
    pub path_and_query: String,
    /// "user:password" if present in the URL.
    pub userinfo: Option<String>,
}

fn err<T>(msg: &str) -> Result<T> {
    Err(Error::Http(format!("invalid URL: {}", msg)))
}

impl Url {
    pub fn parse(input: &str) -> Result<Url> {
        let input = input.trim();
        if input.chars().any(|c| c.is_control() || c == ' ') {
            return err("contains whitespace or control characters");
        }
        if !input.is_ascii() {
            return err("contains non-ASCII characters (use punycode for hosts, which pratique::idna::to_ascii makes, and percent-encoding elsewhere)");
        }
        let Some((scheme, rest)) = input.split_once("://") else {
            return err("missing scheme (expected http:// or https://)");
        };
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return err("unsupported scheme"),
        };
        let rest = rest.split('#').next().unwrap();
        let (authority, tail) = match rest.find(|c| c == '/' || c == '?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let path_and_query = if tail.is_empty() {
            "/".to_string()
        } else if tail.starts_with('?') {
            format!("/{}", tail)
        } else {
            tail.to_string()
        };
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
            None => (None, authority),
        };
        let bracketed = hostport.starts_with('[');
        let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
            let Some(end) = r.find(']') else { return err("unterminated IPv6 literal") };
            let host = &r[..end];
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return err("bad IPv6 literal");
            }
            let after = &r[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return err("garbage after IPv6 literal"),
            };
            (host.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (hostport.to_string(), None),
            }
        };
        if host.is_empty() {
            return err("empty host");
        }
        // only a bracketed IPv6 literal may contain a colon; "a:b:80" is not a host with a colon in it
        if !bracketed && !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
            return err("illegal character in host");
        }
        let port = match port {
            None => default_port,
            Some("") => default_port,
            Some(p) => match p.parse::<u16>() {
                Ok(0) | Err(_) => return err("bad port"),
                Ok(n) => n,
            },
        };
        Ok(Url { scheme, host: host.to_ascii_lowercase(), port, path_and_query, userinfo })
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    /// The port the scheme has when a URL says none: 443 for https, 80 for http.
    pub(crate) fn default_port(&self) -> u16 {
        if self.is_https() {
            443
        } else {
            80
        }
    }

    fn host_for_display(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// Value for the Host header.
    pub fn host_header(&self) -> String {
        if self.port == self.default_port() {
            self.host_for_display()
        } else {
            format!("{}:{}", self.host_for_display(), self.port)
        }
    }

    /// Scheme + host + port, used to decide whether credentials may follow a redirect.
    pub fn origin(&self) -> (&str, &str, u16) {
        (&self.scheme, &self.host, self.port)
    }

    /// Resolves a Location header value against this URL.
    pub fn join(&self, location: &str) -> Result<Url> {
        let location = location.trim();
        if location.contains("://") {
            return Url::parse(location);
        }
        let base = format!("{}://{}", self.scheme, self.host_header());
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{}", self.scheme, rest));
        }
        let location = location.split('#').next().unwrap();
        if location.starts_with('/') {
            return Url::parse(&format!("{}{}", base, location));
        }
        if location.starts_with('?') {
            let path = self.path_and_query.split('?').next().unwrap();
            return Url::parse(&format!("{}{}{}", base, path, location));
        }
        // relative path: replace the last segment of the base path
        let path = self.path_and_query.split('?').next().unwrap();
        let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
        let joined = normalize_dots(&format!("{}{}", dir, location));
        Url::parse(&format!("{}{}", base, joined))
    }
}

/// What a client refuses in the URL of a request, and in the URL of every redirect it follows, before it connects: the structural part of
/// a rule for a caller that may reach some servers and no others (the host part is [`HostRules`](super::HostRules)). Nothing is refused
/// by default; [`strict`](UrlLimits::strict) is the tightest set.
///
/// The text of the URL is checked as it came (what the caller passed, and for a redirect the `Location` value as well as the URL it
/// resolves to), so that what is refused is what was given and not what was made of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UrlLimits {
    max_length: Option<usize>,
    printable_ascii: bool,
    no_credentials: bool,
    https_only: bool,
}

impl UrlLimits {
    /// Nothing refused.
    pub fn new() -> UrlLimits {
        UrlLimits::default()
    }

    /// The tightest set: https only, no credentials in the URL, printable ASCII only (no space, control character or byte over 0x7e), and at
    /// most 2,048 bytes.
    pub fn strict() -> UrlLimits {
        UrlLimits { max_length: Some(2048), printable_ascii: true, no_credentials: true, https_only: true }
    }

    /// Refuses a URL (as text) longer than `bytes`.
    pub fn max_length(mut self, bytes: usize) -> UrlLimits {
        self.max_length = Some(bytes);
        self
    }

    /// Refuses a URL (as text) that has a byte other than `!` to `~` (so no space, control character or non-ASCII byte, which the URL parser
    /// refuses in the middle of a URL anyway, but which it would take at the ends of the text).
    pub fn printable_ascii_only(mut self, on: bool) -> UrlLimits {
        self.printable_ascii = on;
        self
    }

    /// Refuses a URL that has a `user:password@` part.
    pub fn refuse_credentials(mut self, on: bool) -> UrlLimits {
        self.no_credentials = on;
        self
    }

    /// Refuses a URL whose scheme is not https (on every hop: `allow_insecure_http` does not lift it).
    pub fn https_only(mut self, on: bool) -> UrlLimits {
        self.https_only = on;
        self
    }

    fn refuse<T>(why: String) -> std::result::Result<T, String> {
        Err(format!("URL not allowed: {why}"))
    }

    /// Checks the text of a URL (before it is parsed); the reason, if it is refused.
    pub(crate) fn check_text(&self, text: &str) -> std::result::Result<(), String> {
        if let Some(max) = self.max_length {
            if text.len() > max {
                return Self::refuse(format!("{} bytes is longer than {max}", text.len()));
            }
        }
        if self.printable_ascii && !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Self::refuse("a byte that is not printable ASCII".into());
        }
        Ok(())
    }

    /// Checks a parsed URL; the reason, if it is refused.
    pub(crate) fn check(&self, url: &Url) -> std::result::Result<(), String> {
        if self.https_only && !url.is_https() {
            return Self::refuse(format!("{} is not https", url.scheme));
        }
        if self.no_credentials && url.userinfo.is_some() {
            return Self::refuse("credentials in the URL".into());
        }
        Ok(())
    }
}

/// Removes "." and ".." segments from a path (query string preserved).
fn normalize_dots(path_and_query: &str) -> String {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let mut out: Vec<&str> = Vec::new();
    let trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = format!("/{}", out.join("/"));
    if trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    if let Some(q) = query {
        result.push('?');
        result.push_str(q);
    }
    result
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.host_header(), self.path_and_query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_urls() {
        let u = Url::parse("https://Example.COM/a/b?x=1#frag").unwrap();
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port), ("https", "example.com", 443));
        assert_eq!(u.path_and_query, "/a/b?x=1");
        assert_eq!(Url::parse("http://h").unwrap().path_and_query, "/");
        assert_eq!(Url::parse("http://h?q=1").unwrap().path_and_query, "/?q=1");
        assert_eq!(Url::parse("http://h:8080/x").unwrap().port, 8080);
        assert_eq!(Url::parse("http://h:8080/x").unwrap().host_header(), "h:8080");
        assert_eq!(Url::parse("https://h:443/").unwrap().host_header(), "h");
    }

    #[test]
    fn parses_ipv6_and_userinfo() {
        let u = Url::parse("https://[::1]:8443/p").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 8443));
        assert_eq!(u.host_header(), "[::1]:8443");
        assert_eq!(u.to_string(), "https://[::1]:8443/p");
        let u = Url::parse("https://user:pw@host/").unwrap();
        assert_eq!(u.userinfo.as_deref(), Some("user:pw"));
        assert_eq!(u.host, "host");
    }

    #[test]
    fn rejects_bad_urls() {
        for bad in [
            "example.com", "ftp://x/", "https://", "https://:80/", "https://h:0/", "https://h:99999/", "https://h /x",
            "https://h/\r\nHost: evil", "https://[::1/", "https://h/é", "https://ho$t/",
            // found by the fuzzer: a colon in a host that is not a bracketed IPv6 literal
            "http://a:b:80/", "https://user:pw:x/", "http://y[::1]/", "http://[::1]x/", "http://a::1/",
        ] {
            assert!(Url::parse(bad).is_err(), "{:?} should be rejected", bad);
        }
    }

    #[test]
    fn joins_locations() {
        let base = Url::parse("https://a.example/dir/page?x=1").unwrap();
        assert_eq!(base.join("https://b.example/z").unwrap().to_string(), "https://b.example/z");
        assert_eq!(base.join("//c.example/q").unwrap().to_string(), "https://c.example/q");
        assert_eq!(base.join("/abs").unwrap().to_string(), "https://a.example/abs");
        assert_eq!(base.join("other").unwrap().to_string(), "https://a.example/dir/other");
        assert_eq!(base.join("../up").unwrap().to_string(), "https://a.example/up");
        assert_eq!(base.join("?y=2").unwrap().to_string(), "https://a.example/dir/page?y=2");
        assert_eq!(base.join("sub/").unwrap().to_string(), "https://a.example/dir/sub/");
        assert_eq!(base.join("../../../../x").unwrap().to_string(), "https://a.example/x");
    }

    fn refused<T: std::fmt::Debug>(r: std::result::Result<T, String>) -> bool {
        matches!(&r, Err(m) if m.starts_with("URL not allowed"))
    }

    #[test]
    fn limits_refuse_nothing_until_they_are_asked_to() {
        let none = UrlLimits::new();
        let long = format!("https://u:p@h/{}\u{e9} x", "a".repeat(5000));
        assert!(none.check_text(&long).is_ok());
        assert!(none.check(&Url::parse("http://u:p@h/").unwrap()).is_ok());
        assert_eq!(UrlLimits::new(), UrlLimits::default());
    }

    #[test]
    fn a_length_limit_counts_bytes_and_is_inclusive() {
        let l = UrlLimits::new().max_length(20);
        assert!(l.check_text(&"a".repeat(20)).is_ok());
        assert!(refused(l.check_text(&"a".repeat(21))));
        // (bytes, not characters)
        assert!(refused(l.check_text(&"\u{e9}".repeat(11))));
        assert!(UrlLimits::new().max_length(0).check_text("").is_ok());
    }

    #[test]
    fn printable_ascii_is_the_bytes_bang_to_tilde() {
        let l = UrlLimits::new().printable_ascii_only(true);
        assert!(l.check_text("https://h/!~").is_ok());
        for bad in ["a b", " a", "a ", "a\n", "a\r", "a\t", "a\0", "a\u{1f}", "a\u{7f}", "a\u{80}", "caf\u{e9}", "a\u{2028}", "\u{feff}a"] {
            assert!(refused(l.check_text(bad)), "{bad:?}");
        }
    }

    #[test]
    fn credentials_and_a_scheme_other_than_https_are_refused_when_asked() {
        let url = |s: &str| Url::parse(s).unwrap();
        let creds = UrlLimits::new().refuse_credentials(true);
        assert!(creds.check(&url("https://h/")).is_ok() && creds.check(&url("http://h/")).is_ok());
        for bad in ["https://u@h/", "https://u:p@h/", "https://:@h/", "https://@h/", "http://u@h:8080/"] {
            assert!(refused(creds.check(&url(bad))), "{bad}");
        }
        let https = UrlLimits::new().https_only(true);
        assert!(https.check(&url("https://u:p@h/")).is_ok());
        assert!(refused(https.check(&url("http://h/"))) && refused(https.check(&url("HTTP://h:443/"))));
    }

    #[test]
    fn strict_is_all_of_them() {
        let s = UrlLimits::strict();
        assert_eq!(s, UrlLimits::new().max_length(2048).printable_ascii_only(true).refuse_credentials(true).https_only(true));
        assert!(s.check_text(&format!("https://h/{}", "a".repeat(2048 - 10))).is_ok());
        assert!(refused(s.check_text(&format!("https://h/{}", "a".repeat(2049 - 10)))));
        assert!(refused(s.check(&Url::parse("http://h/").unwrap())) && refused(s.check(&Url::parse("https://u@h/").unwrap())));
        assert!(refused(s.check_text("https://h/ ")));
        assert!(s.check(&Url::parse("https://h:8443/x?y=1").unwrap()).is_ok());
    }
}
