//! Which hosts a client may reach: the rule of a module (or a caller) that is allowed to talk to some servers and no others.
//!
//! A rule is a list of entries, each a host (`api.example.com`, an IPv4 address, an IPv6 address with or without brackets), a host with a
//! port (`api.example.com:8443`, `[::1]:8443`) or a wildcard (`*.example.com`). What the entries let through depends on two switches, which
//! are off by default and which a caller that wants a tight rule turns on:
//!
//! * **Wildcards.** By default `*.example.com` matches a host that has one label or more before the suffix, at any depth (`a.example.com`,
//!   `a.b.example.com`), and **never the suffix itself** (the bare domain needs an entry of its own, so that a rule says what it lets through).
//!   With [`one_label_wildcards`](HostRules::one_label_wildcards) it matches exactly one label (`a.example.com`, not `a.b.example.com`), and
//!   the label has to be a valid one: `a` to `z`, digits and inner hyphens, at most 63 bytes (no underscore).
//! * **Ports.** By default an entry without a port matches the host on any port, and an entry with one matches that port only. With
//!   [`default_port_only`](HostRules::default_port_only) an entry without a port, a wildcard included, matches the default port of the scheme only
//!   (so 443 for https, written or not), and a host on another port is let through only by an entry that has that port, `host:port`; never by a wildcard.
//!
//! Comparison is of the host the client will connect to, as the URL gave it: ASCII, lower case (a trailing dot is ignored), so an
//! internationalized name is matched in its `xn--` form, and an address written another way (`2130706433`, `0x7f.1`) does not match the entry
//! for the address it means.
//!
//! The client applies a rule to the URL of the request and to the URL of every redirect it follows, before it connects: a redirect to a
//! host the rule does not name is an error, and nothing is sent to that host. With a rule set, an `Alt-Svc` alternative is used only if the rule
//! allows its host and port (the origin's own host, if the alternative names none).

use super::url::Url;
use crate::error::{Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A list of hosts a client may reach. Empty allows nothing (use no rule at all to allow everything).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostRules {
    /// Hosts, normalized (lower case, no trailing dot, IPv6 without brackets in its shortest form), with the port if the entry had one.
    exact: Vec<(String, Option<u16>)>,
    /// Suffixes of wildcards, with the dot: `.example.com` for `*.example.com`.
    suffixes: Vec<String>,
    one_label: bool,
    default_port_only: bool,
}

fn bad(entry: &str, why: &str) -> Error {
    Error::Http(format!("invalid host rule {entry:?}: {why}"))
}

/// A DNS name in the form a URL has it: labels of letters, digits, hyphens and underscores, none empty, none longer than 63 bytes, no
/// hyphen at either end, 253 bytes in all.
fn is_name(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// One label as a wildcard of one label allows it: lower-case letters, digits and hyphens that are not at either end, 1 to 63 bytes.
fn is_strict_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && !s.starts_with('-') && !s.ends_with('-') && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether the last label of a host is a number (`1`, `0x7f`): such a host is an address, whatever its other labels look like.
fn ends_in_a_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    !last.is_empty() && (last.bytes().all(|b| b.is_ascii_digit()) || last.strip_prefix("0x").is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// A port as an entry writes it: digits, 1 to 65535.
fn parse_port(entry: &str, text: &str) -> Result<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(entry, "the port is not a number"));
    }
    match text.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(bad(entry, "the port is not in 1 to 65535")),
    }
}

/// A host as an entry writes it, without the port: a name, an IPv4 address, an IPv6 address with or without brackets.
fn parse_host(entry: &str, text: &str) -> Result<String> {
    let text = text.strip_suffix('.').unwrap_or(text);
    let inner = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')).unwrap_or(text);
    if inner.contains(':') {
        return inner.parse::<Ipv6Addr>().map(|a| a.to_string()).map_err(|_| bad(entry, "not an IPv6 address"));
    }
    if text.starts_with('[') || text.ends_with(']') {
        return Err(bad(entry, "brackets are for an IPv6 address"));
    }
    if is_name(inner) {
        Ok(inner.to_string())
    } else {
        Err(bad(entry, "not a host name or an address"))
    }
}

impl HostRules {
    /// A rule from its entries: hosts, hosts with a port, and wildcards that begin `*.` and have a domain of at least two labels after it
    /// (`*.example.com`; not `*.com`, which would be most of the internet; not a `*` anywhere else, and no port on a wildcard). An entry that is not
    /// one of those is an error, so that a rule that was meant to refuse something does not quietly allow it, or the other way round.
    ///
    /// The rule it makes has the looser meaning of each switch (wildcards at any depth, ports as the entries say); see
    /// [`one_label_wildcards`](HostRules::one_label_wildcards) and [`default_port_only`](HostRules::default_port_only).
    pub fn new<I>(entries: I) -> Result<HostRules>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut rules = HostRules::default();
        for entry in entries {
            let entry = entry.as_ref();
            let lower = entry.trim().to_ascii_lowercase();
            if lower.is_empty() {
                return Err(bad(entry, "empty"));
            }
            if !lower.is_ascii() {
                return Err(bad(entry, "not ASCII (write an internationalized name in its xn-- form)"));
            }
            if let Some(rest) = lower.strip_prefix("*.") {
                let domain = rest.strip_suffix('.').unwrap_or(rest);
                if domain.contains(':') {
                    return Err(bad(entry, "a wildcard has no port (with default_port_only it matches the default port, and a host on another port needs an entry of its own)"));
                }
                if domain.contains('*') || !is_name(domain) {
                    return Err(bad(entry, "a wildcard is `*.` and a domain name, like `*.example.com`"));
                }
                if !domain.contains('.') {
                    return Err(bad(entry, "a wildcard needs a domain of at least two labels after `*.`, like `*.example.com`"));
                }
                if domain.parse::<Ipv4Addr>().is_ok() {
                    return Err(bad(entry, "a wildcard cannot be an address"));
                }
                let suffix = format!(".{domain}");
                if !rules.suffixes.contains(&suffix) {
                    rules.suffixes.push(suffix);
                }
                continue;
            }
            if lower.contains('*') {
                return Err(bad(entry, "`*` is only allowed as the first label of a wildcard, `*.example.com`"));
            }
            // host, or host:port; an IPv6 address has colons of its own, and carries a port only in brackets
            let (host, port) = if lower.starts_with('[') {
                let Some(end) = lower.find(']') else { return Err(bad(entry, "brackets are for an IPv6 address")) };
                let after = &lower[end + 1..];
                match after {
                    "" => (&lower[..=end], None),
                    _ => match after.strip_prefix(':') {
                        Some(p) => (&lower[..=end], Some(parse_port(entry, p)?)),
                        None => return Err(bad(entry, "nothing may follow the brackets but a port")),
                    },
                }
            } else if lower.matches(':').count() == 1 {
                let (h, p) = lower.split_once(':').unwrap();
                (h, Some(parse_port(entry, p)?))
            } else {
                (lower.as_str(), None)
            };
            let host = (parse_host(entry, host)?, port);
            if !rules.exact.contains(&host) {
                rules.exact.push(host);
            }
        }
        Ok(rules)
    }

    /// Whether a wildcard matches exactly one label, a valid one, before its domain (`*.example.com` allows `a.example.com` and neither
    /// `a.b.example.com` nor `example.com`), or any number of labels (the default).
    pub fn one_label_wildcards(mut self, on: bool) -> HostRules {
        self.one_label = on;
        self
    }

    /// Whether an entry without a port, a wildcard included, matches the default port only (the default is not to look at the port). A host
    /// that is written with a port is then allowed on that port by an entry that has it, and by nothing else.
    pub fn default_port_only(mut self, on: bool) -> HostRules {
        self.default_port_only = on;
        self
    }

    /// Whether a request may go to `host` on `port`, where `default_port` is the port the scheme has when the URL says none (`host` as
    /// a URL has it: lower case, an IPv6 address without brackets).
    pub fn allows(&self, host: &str, port: u16, default_port: u16) -> bool {
        let lower = host.to_ascii_lowercase();
        let host = lower.strip_suffix('.').unwrap_or(&lower);
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        let v6;
        let host = match host.parse::<Ipv6Addr>() {
            Ok(a) => {
                v6 = a.to_string();
                v6.as_str()
            }
            Err(_) => host,
        };
        let default_only = self.default_port_only;
        if self.exact.iter().any(|(e, p)| e == host && p.map_or(!default_only || port == default_port, |p| port == p)) {
            return true;
        }
        if default_only && port != default_port {
            return false;
        }
        // (an address is never under a wildcard, however it is written: a host whose last label is a number is one to a URL parser and to the
        // resolver, `10.1.1` is 10.1.0.1, and `*.0.0.1` would otherwise let 127.0.0.1 through)
        if ends_in_a_number(host) {
            return false;
        }
        self.suffixes.iter().any(|s| match host.strip_suffix(s.as_str()) {
            Some(before) => {
                if self.one_label {
                    is_strict_label(before)
                } else {
                    is_name(before)
                }
            }
            None => false,
        })
    }

    /// Whether a request to this URL may be made: its host, on its port (the scheme's default when it has none).
    pub fn allows_url(&self, url: &Url) -> bool {
        self.allows(&url.host, url.port, url.default_port())
    }

    /// Whether the rule names no host at all (so it allows none).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(entries: &[&str]) -> HostRules {
        HostRules::new(entries.iter().copied()).unwrap()
    }

    /// On the default port of https.
    fn ok(r: &HostRules, host: &str) -> bool {
        r.allows(host, 443, 443)
    }

    #[test]
    fn a_host_entry_allows_that_host_and_no_other() {
        let r = rules(&["api.example.com", "Other.Example.ORG."]);
        assert!(ok(&r, "api.example.com") && ok(&r, "API.example.com") && ok(&r, "api.example.com."));
        assert!(ok(&r, "other.example.org"));
        for no in ["example.com", "x.api.example.com", "api.example.com.evil.net", "evilapi.example.com", "api-example.com", "api.example.co", ""] {
            assert!(!ok(&r, no), "{no}");
        }
    }

    #[test]
    fn a_wildcard_allows_what_is_under_it_at_any_depth_and_not_the_domain_itself() {
        let r = rules(&["*.example.com"]);
        for yes in ["a.example.com", "a.b.example.com", "A.B.C.example.com", "x-1.example.com", "_dmarc.example.com", "a.example.com."] {
            assert!(ok(&r, yes), "{yes}");
        }
        for no in ["example.com", ".example.com", "..example.com", "a..example.com", "-a.example.com", "evilexample.com", "a.example.com.evil.net", "a.example.org", "xexample.com", "com", "127.0.0.1", "::1"] {
            assert!(!ok(&r, no), "{no}");
        }
        // the domain on its own is named on its own
        let r = rules(&["*.example.com", "example.com"]);
        assert!(ok(&r, "example.com") && ok(&r, "www.example.com"));
    }

    #[test]
    fn a_wildcard_of_one_label_allows_one_valid_label_and_not_the_domain() {
        // (the Marketplace's hosts are `<publisher>.gallerycdn.vsassets.io`: one label under the domain)
        let r = rules(&["*.gallerycdn.vsassets.io"]).one_label_wildcards(true);
        for yes in ["x.gallerycdn.vsassets.io", "X.GalleryCDN.vsassets.io", "publisher-1.gallerycdn.vsassets.io", "1.gallerycdn.vsassets.io", "xn--abc.gallerycdn.vsassets.io", "x.gallerycdn.vsassets.io."] {
            assert!(ok(&r, yes), "{yes}");
        }
        let long_ok = format!("{}.gallerycdn.vsassets.io", "a".repeat(63));
        let too_long = format!("{}.gallerycdn.vsassets.io", "a".repeat(64));
        assert!(ok(&r, &long_ok) && !ok(&r, &too_long));
        for no in [
            "gallerycdn.vsassets.io",
            "a.b.gallerycdn.vsassets.io",
            "evilgallerycdn.vsassets.io",
            ".gallerycdn.vsassets.io",
            "-x.gallerycdn.vsassets.io",
            "x-.gallerycdn.vsassets.io",
            "x_y.gallerycdn.vsassets.io",
            "x..gallerycdn.vsassets.io",
            "x.gallerycdn.vsassets.io.evil.net",
            "x.vsassets.io",
            "127.0.0.1",
        ] {
            assert!(!ok(&r, no), "{no}");
        }
        // off, it is the any-depth wildcard again (and an underscore is a character of a name)
        let r = r.one_label_wildcards(false);
        assert!(ok(&r, "a.b.gallerycdn.vsassets.io") && ok(&r, "x_y.gallerycdn.vsassets.io") && !ok(&r, "gallerycdn.vsassets.io"));
    }

    #[test]
    fn ports_are_not_looked_at_unless_the_rule_asks() {
        let r = rules(&["a.example.com", "*.example.org", "b.example.com:8443"]);
        // an entry with no port: any port; one with a port: that port
        for port in [443u16, 80, 8443, 1] {
            assert!(r.allows("a.example.com", port, 443) && r.allows("x.example.org", port, 443), "{port}");
        }
        assert!(r.allows("b.example.com", 8443, 443));
        assert!(!r.allows("b.example.com", 443, 443) && !r.allows("b.example.com", 9443, 443));
    }

    #[test]
    fn with_default_port_only_a_wildcard_and_a_plain_entry_match_the_default_port_and_a_port_needs_its_own_entry() {
        let r = rules(&["a.example.com", "*.example.org", "b.example.com:8443", "c.example.com:443", "[::1]", "[::2]:9000"]).default_port_only(true);
        // the default port, written in the URL or not (the caller says what the URL's port is)
        assert!(r.allows("a.example.com", 443, 443) && r.allows("x.example.org", 443, 443) && r.allows("c.example.com", 443, 443) && r.allows("::1", 443, 443));
        // another port: only the entry that has it
        assert!(!r.allows("a.example.com", 8443, 443));
        assert!(!r.allows("x.example.org", 8443, 443), "a wildcard never matches an explicit port");
        assert!(!r.allows("a.example.com", 80, 443) && !r.allows("::1", 8443, 443));
        assert!(r.allows("b.example.com", 8443, 443) && r.allows("::2", 9000, 443));
        // ... and that entry is for that port only
        assert!(!r.allows("b.example.com", 443, 443) && !r.allows("b.example.com", 9443, 443) && !r.allows("::2", 443, 443) && !r.allows("c.example.com", 8443, 443));
        // the default is the scheme's: 80 for http, so that is the port an entry without one means there
        assert!(r.allows("a.example.com", 80, 80) && !r.allows("a.example.com", 443, 80));
        // off again, the ports are not looked at
        assert!(r.default_port_only(false).allows("a.example.com", 8443, 443));
    }

    #[test]
    fn an_address_is_never_under_a_wildcard() {
        // found by the fuzz target `egress`: `*.0.0.1` ends as an address does, and let 127.0.0.1 through
        for r in [rules(&["*.0.0.1", "*.168.1.1", "*.1.1"]), rules(&["*.0.0.1", "*.168.1.1", "*.1.1"]).one_label_wildcards(true)] {
            for host in ["127.0.0.1", "192.168.1.1", "10.1.1", "1.1.1.1", "0.0.0.1"] {
                assert!(!ok(&r, host), "{host}");
            }
        }
        // (a host that ends in a number is an address to a URL parser, so no wildcard has it; one that does not is a name)
        for host in ["a.0.0.1", "x.0.0x7f", "x.1.0x", "x.1.127", "10.0.0x1"] {
            assert!(!ok(&rules(&["*.0.0.1", "*.0.0x7f", "*.1.0x", "*.1.127", "*.0.0x1"]), host), "{host}");
        }
        assert!(ok(&rules(&["*.0.0.1", "*.example.com"]), "a.1.example.com") && ok(&rules(&["*.example.com"]), "0x7f.example.com"));
        // (and an entry for the host itself is a host's own)
        assert!(ok(&rules(&["10.1.1", "a.0.0.1"]), "10.1.1") && ok(&rules(&["a.0.0.1"]), "a.0.0.1"));
    }

    #[test]
    fn addresses_are_matched_as_written_in_their_shortest_form() {
        let r = rules(&["127.0.0.1", "[::1]", "2001:DB8:0:0:0:0:0:1"]);
        assert!(ok(&r, "127.0.0.1") && ok(&r, "::1") && ok(&r, "[::1]") && ok(&r, "2001:db8::1"));
        // an address written another way is a different host name as far as the rule goes (it would still resolve to the address)
        for no in ["2130706433", "0x7f.1", "127.1", "127.0.0.2", "0:0:0:0:0:0:0:2", "::ffff:127.0.0.1"] {
            assert!(!ok(&r, no), "{no}");
        }
        // (the long form of an address is read as the address it is: the same host)
        assert!(ok(&r, "0:0:0:0:0:0:0:1"));
    }

    #[test]
    fn entries_that_are_not_what_they_look_like_are_refused_when_the_rule_is_made() {
        for entry in [
            "", " ", ".", "*", "*.", "*.com", "*.*.example.com", "a.*.example.com", "*example.com", "ex*.example.com", "example.com/", "http://example.com", "example.com/path", "a b.example.com", "-a.example.com",
            "a..example.com", ".example.com", "*.127.0.0.1", "*.[::1]", "[::1", "::g", "exämple.com", "a@example.com", "*.example.com:443", "*.example.com:8443", "example.com:", "example.com:0", "example.com:65536",
            "example.com:44a", "example.com:-1", "example.com:+443", "example.com:443:443", "[::1]x", "[::1]:", "[::1]:0", "[example.com]", "[::1]]", "[127.0.0.1]",
        ] {
            assert!(HostRules::new([entry]).is_err(), "{entry:?} was accepted");
        }
        // the error says which entry
        assert!(HostRules::new(["ok.example.com", "*.com"]).unwrap_err().to_string().contains("*.com"));
        // and what is allowed is allowed
        for entry in ["example.com:443", "example.com:1", "example.com:65535", "[::1]:443", "::1", "1.2.3.4:8080", "EXAMPLE.com.:443"] {
            assert!(HostRules::new([entry]).is_ok(), "{entry:?} was refused");
        }
    }

    #[test]
    fn an_empty_rule_allows_nothing() {
        let r = HostRules::new(Vec::<String>::new()).unwrap();
        assert!(r.is_empty() && !ok(&r, "example.com") && !ok(&r, "127.0.0.1"));
    }

    #[test]
    fn repeated_entries_make_one() {
        let r = rules(&["a.example.com", "A.example.com.", "*.example.org", "*.EXAMPLE.org", "a.example.com:443", "a.example.com:443"]);
        assert_eq!((r.exact.len(), r.suffixes.len()), (2, 1));
    }

    #[test]
    fn a_url_is_judged_by_its_host_and_its_port() {
        let r = rules(&["a.example.com", "*.example.org", "b.example.com:8443"]).default_port_only(true).one_label_wildcards(true);
        let url = |s: &str| Url::parse(s).unwrap();
        assert!(r.allows_url(&url("https://a.example.com/x")) && r.allows_url(&url("https://a.example.com:443/x")) && r.allows_url(&url("https://x.example.org/")));
        assert!(!r.allows_url(&url("https://a.example.com:8443/x")) && !r.allows_url(&url("https://x.example.org:8443/")) && !r.allows_url(&url("https://a.b.example.org/")));
        assert!(r.allows_url(&url("https://b.example.com:8443/")) && !r.allows_url(&url("https://b.example.com/")));
        // an http URL's default is 80
        assert!(r.allows_url(&url("http://a.example.com/")) && !r.allows_url(&url("http://a.example.com:443/")) && r.allows_url(&url("http://a.example.com:80/")));
    }
}
