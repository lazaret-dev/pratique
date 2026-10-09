//! The `Alt-Svc` header field (RFC 7838): an origin says that it can be reached in another way too. Of what it may list only the
//! HTTP/3 alternative matters here: `h3=":443"; ma=86400` says that the same origin is served over QUIC at port 443 of the same host
//! (or at another host, `h3="alt.example:8443"`), and that the client may believe it for `ma` seconds (a day if it is not said).
//! `Alt-Svc: clear` takes back everything that was said before.
//!
//! What is read is what a client needs and no more: the first `h3` alternative of the value (the drafts of HTTP/3, `h3-29` and the like,
//! are other protocols and are not ours), its authority and its lifetime. A value that does not parse is skipped from the bad
//! alternative to the next comma, as RFC 7838 section 3 has it ("ignore ... that it cannot parse"); nothing in it can make the
//! client do more than try a UDP connection to a port, which it does anyway.

use std::time::Duration;

/// The longest an alternative is believed, whatever it says: a month.
pub(crate) const MAX_AGE_LIMIT: u64 = 30 * 24 * 3600;

/// The lifetime of an alternative that does not give one (RFC 7838 section 3.1).
pub(crate) const DEFAULT_MAX_AGE: u64 = 24 * 3600;

/// An HTTP/3 alternative of an origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Alternative {
    /// The host to connect to, if it is not the origin's.
    pub(crate) host: Option<String>,
    pub(crate) port: u16,
    pub(crate) max_age: Duration,
}

/// What a value of `Alt-Svc` comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// `clear`: nothing is known of alternatives any more.
    Clear,
    /// The first HTTP/3 alternative that the value lists, if it lists one.
    H3(Option<Alternative>),
}

/// Reads the value of an `Alt-Svc` field (the values of several fields are one value joined by commas, so they may be given one at a time).
pub(crate) fn parse(value: &str) -> Parsed {
    let v = value.trim_matches(|c| c == ' ' || c == '\t');
    if v.eq_ignore_ascii_case("clear") {
        return Parsed::Clear;
    }
    for item in split_outside_quotes(v, b',') {
        if let Some(alt) = parse_item(item) {
            return Parsed::H3(Some(alt));
        }
    }
    Parsed::H3(None)
}

/// The pieces of `s` between the `sep` bytes that are not inside a quoted string (a backslash in a quoted string takes the next
/// character as it is).
fn split_outside_quotes(s: &str, sep: u8) -> Vec<&str> {
    let b = s.as_bytes();
    let (mut out, mut start, mut quoted, mut i) = (Vec::new(), 0, false, 0);
    while i < b.len() {
        match b[i] {
            b'\\' if quoted => i += 1,
            b'"' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start.min(s.len())..]);
    out
}

/// One `alt-value`: `protocol-id="authority"` and the parameters after it, which are `;`-separated. `None` if it is not an `h3` one or is
/// not well formed.
fn parse_item(item: &str) -> Option<Alternative> {
    let mut parts = split_outside_quotes(item, b';').into_iter();
    let first = parts.next()?.trim_matches(|c| c == ' ' || c == '\t');
    let (id, authority) = first.split_once('=')?;
    if percent_decode(id.trim_matches(|c| c == ' ' || c == '\t'))? != b"h3" {
        return None;
    }
    // (the authority is a quoted string: `:443` is not a token)
    let authority = authority.trim_matches(|c| c == ' ' || c == '\t');
    if !authority.starts_with('"') {
        return None;
    }
    let (host, port) = split_authority(&unquote(authority)?)?;
    let mut max_age = DEFAULT_MAX_AGE;
    for p in parts {
        let Some((name, val)) = p.trim_matches(|c| c == ' ' || c == '\t').split_once('=') else { continue };
        if name.trim_matches(|c| c == ' ' || c == '\t').eq_ignore_ascii_case("ma") {
            let val = unquote(val.trim_matches(|c| c == ' ' || c == '\t'))?;
            // (a number of seconds and nothing else: a value that is not is a value that is wrong)
            if val.is_empty() || !val.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            max_age = val.parse::<u64>().unwrap_or(u64::MAX).min(MAX_AGE_LIMIT);
        }
    }
    Some(Alternative { host, port, max_age: Duration::from_secs(max_age) })
}

/// The text of a quoted string without its quotes, or of a token as it is.
fn unquote(s: &str) -> Option<String> {
    let Some(inner) = s.strip_prefix('"') else {
        return (!s.is_empty() && !s.contains('"')).then(|| s.to_string());
    };
    let inner = inner.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// `[ uri-host ] ":" port`: the host as it is (an IPv6 address keeps its brackets off), None if there is none, and the port.
fn split_authority(a: &str) -> Option<(Option<String>, u16)> {
    let (host, port) = a.rsplit_once(':')?;
    if !port_text_is_plain(port) {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    if host.is_empty() {
        return Some((None, port));
    }
    let name = match host.strip_prefix('[') {
        Some(rest) => {
            // an IPv6 address in brackets, in the one way it is written (the lower-case form of the address)
            let addr: std::net::Ipv6Addr = rest.strip_suffix(']')?.parse().ok()?;
            addr.to_string()
        }
        None => {
            // a name or an IPv4 address: letters, digits, hyphens and dots
            if host.len() > 253 || !host.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') || host.starts_with('.') || host.ends_with("..") {
                return None;
            }
            host.to_ascii_lowercase()
        }
    };
    Some((Some(name), port))
}

/// A port is digits only (`parse` of a number also takes a leading plus).
fn port_text_is_plain(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// `%XX` escapes undone (a protocol-id is percent-encoded); None if one is not two hexadecimal digits.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// What holds of any value, for the tests and the fuzzer (`alt_svc`): it parses or is skipped, never more; what it says is within bounds;
/// an alternative written out again reads back the same; and what is in front of it, if that is another protocol's, changes nothing.
#[cfg(any(test, pratique_fuzzing))]
pub(crate) fn check(value: &str) {
    let p = parse(value);
    match &p {
        Parsed::Clear => assert!(value.trim_matches(|c| c == ' ' || c == '\t').eq_ignore_ascii_case("clear")),
        Parsed::H3(None) => {}
        Parsed::H3(Some(a)) => {
            assert!(a.port != 0);
            assert!(a.max_age <= Duration::from_secs(MAX_AGE_LIMIT));
            let host = match &a.host {
                Some(h) => {
                    assert!(!h.is_empty() && h.len() <= 253, "{h:?}");
                    assert!(h.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c)) && *h == h.to_ascii_lowercase(), "{h:?}");
                    if h.contains(':') { format!("[{h}]") } else { h.clone() }
                }
                None => String::new(),
            };
            let again = format!("h3=\"{host}:{}\"; ma={}", a.port, a.max_age.as_secs());
            assert_eq!(parse(&again), p, "{again}");
        }
    }
    if p != Parsed::Clear {
        assert_eq!(parse(&format!("x=\"y\", {value}")), p, "something of another protocol in front changed the reading of {value:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h3(host: Option<&str>, port: u16, secs: u64) -> Parsed {
        Parsed::H3(Some(Alternative { host: host.map(str::to_string), port, max_age: Duration::from_secs(secs) }))
    }

    #[test]
    fn the_usual_forms() {
        assert_eq!(parse(r#"h3=":443"; ma=2592000"#), h3(None, 443, 2592000));
        assert_eq!(parse(r#"h3=":443""#), h3(None, 443, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h3-29=":443"; ma=86400, h3=":8443"; ma=60; persist=1"#), h3(None, 8443, 60));
        assert_eq!(parse(r#"h3="alt.Example.com:8443";ma=10"#), h3(Some("alt.example.com"), 8443, 10));
        assert_eq!(parse(r#"h3="[2001:db8::1]:443""#), h3(Some("2001:db8::1"), 443, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"  h3=":443"  ;  MA=5 "#), h3(None, 443, 5));
        // (a protocol id is case-sensitive, like the ALPN id it is)
        assert_eq!(parse(r#"H3=":443""#), Parsed::H3(None));
        // (what the big sites say)
        assert_eq!(parse(r#"h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000"#), h3(None, 443, 2592000));
    }

    #[test]
    fn clear_and_what_is_not_http3() {
        assert_eq!(parse("clear"), Parsed::Clear);
        assert_eq!(parse(" Clear "), Parsed::Clear);
        assert_eq!(parse(r#"h2=":443"; ma=3600"#), Parsed::H3(None));
        assert_eq!(parse(r#"h3-29=":443""#), Parsed::H3(None));
        assert_eq!(parse(""), Parsed::H3(None));
        assert_eq!(parse(","), Parsed::H3(None));
        // (the protocol id is percent-encoded)
        assert_eq!(parse(r#"h%33=":443""#), h3(None, 443, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h%3=":443""#), Parsed::H3(None));
    }

    #[test]
    fn a_lifetime_is_a_number_and_is_bounded() {
        assert_eq!(parse(r#"h3=":443"; ma=0"#), h3(None, 443, 0));
        assert_eq!(parse(r#"h3=":443"; ma="120""#), h3(None, 443, 120));
        assert_eq!(parse(r#"h3=":443"; ma=99999999999999999999999"#), h3(None, 443, MAX_AGE_LIMIT));
        assert_eq!(parse(r#"h3=":443"; ma=31536000"#), h3(None, 443, MAX_AGE_LIMIT));
        // a lifetime that is not a number spoils the alternative, and the next one is looked at
        assert_eq!(parse(r#"h3=":443"; ma=-1, h3=":444""#), h3(None, 444, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h3=":443"; ma=1.5"#), Parsed::H3(None));
        assert_eq!(parse(r#"h3=":443"; ma="#), Parsed::H3(None));
        // other parameters are no business of ours
        assert_eq!(parse(r#"h3=":443"; foo; bar=baz; ma=7; persist=1"#), h3(None, 443, 7));
    }

    #[test]
    fn a_bad_authority_is_skipped() {
        for bad in [
            r#"h3=:443"#,
            r#"h3="443""#,
            r#"h3=":0""#,
            r#"h3=":65536""#,
            r#"h3=":+443""#,
            r#"h3=":4 43""#,
            r#"h3="exa mple:443""#,
            r#"h3="a/b:443""#,
            r#"h3="[::1:443""#,
            r#"h3="[]:443""#,
            r#"h3="[xyz]:443""#,
            r#"h3="[1.2.3.4]:443""#,
            r#"h3=":443"#,
            r#"h3=":443"""#,
            r#"h3"#,
            r#"=":443""#,
            r#"h3=""#,
        ] {
            assert_eq!(parse(bad), Parsed::H3(None), "{bad}");
        }
        // (and the next one that is good is the one)
        assert_eq!(parse(r#"h3="a/b:443", h3=":444""#), h3(None, 444, DEFAULT_MAX_AGE));
    }

    #[test]
    fn an_address_in_brackets_is_one_and_is_written_in_lower_case() {
        // (found by the fuzzer: the case was kept, and anything of hexadecimal digits and colons was taken for an address)
        assert_eq!(parse(r#"h3="[2001:DB8::1]:443""#), h3(Some("2001:db8::1"), 443, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h3="[2001:0db8:0:0:0:0:0:1]:443""#), h3(Some("2001:db8::1"), 443, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h3="[::ffff:1.2.3.4]:443""#), h3(Some("::ffff:1.2.3.4"), 443, DEFAULT_MAX_AGE));
        for bad in [r#"h3="[B0:12d18:3b]:443""#, r#"h3="[2001:db8:::1]:443""#, r#"h3="[1:2:3:4:5:6:7:8:9]:443""#, r#"h3="[fe80::1%eth0]:443""#, r#"h3="[::1]]:443""#] {
            assert_eq!(parse(bad), Parsed::H3(None), "{bad}");
        }
    }

    #[test]
    fn commas_and_semicolons_in_a_quoted_string_are_part_of_it() {
        assert_eq!(parse(r#"h3="a,b:443", h3=":9""#), h3(None, 9, DEFAULT_MAX_AGE));
        assert_eq!(parse(r#"h3="a;b:443"; ma=3"#), Parsed::H3(None));
        assert_eq!(parse(r#"h3=":1\5"; ma=3"#), h3(None, 15, 3));
        assert_eq!(parse(r#"h3="\:443"; ma=3"#), h3(None, 443, 3));
    }

    #[test]
    fn what_holds_of_any_value_holds_of_these() {
        for v in [
            r#"h3=":443"; ma=2592000,h3-29=":443"; ma=2592000"#,
            r#"h3="[2001:db8::1]:443""#,
            r#"h3="a.example:1";ma=1,h3=":2""#,
            r#"clear"#,
            r#"h3="a;b:443"; ma=3"#,
            r#""h3=":443""#,
            r#"h3=":443"; x="unterminated"#,
            "",
        ] {
            check(v);
        }
    }

    #[test]
    fn hostile_input_is_only_skipped() {
        let long = format!("h3=\"{}:443\"", "a".repeat(300));
        assert_eq!(parse(&long), Parsed::H3(None));
        assert_eq!(parse(&"\"".repeat(1000)), Parsed::H3(None));
        assert_eq!(parse(&",".repeat(1000)), Parsed::H3(None));
        assert_eq!(parse("h3=\":443\"\u{0}"), Parsed::H3(None));
        assert_eq!(parse("h3=\":443\"; ma=\u{7f}"), Parsed::H3(None));
    }
}
