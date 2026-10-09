//! The fuzz target `egress`, compiled only with `--cfg pratique_fuzzing`: what a client with a rule about hosts, limits on a URL and a
//! hook that gives each hop its headers decides about a request and about every redirect it follows.
//!
//! The input is a byte of switches, then lines of text: the entries of the rule (separated by spaces), the URL of the request, the headers the hook
//! gives (`name: value` pairs separated by `;`), and then the `Location` of one redirect after another. Whatever it says, nothing may panic, and
//! what the client decides must be what a second, simple account of the rules decides (written below on purpose without sharing code with
//! `hostrules.rs`, `url.rs` or `mod.rs`): the rule about hosts, the limits on a URL, the order that a redirect is judged in, what the hook gave
//! for the hop and the headers that are sent with it.

use super::{Client, Hop, HopInfo, HostRules, Url, UrlLimits};
use crate::error::Error;
use crate::tls::ClientConfig;
use crate::x509::TrustStore;
use std::net::Ipv6Addr;

/// The rule about hosts, as a simple program: an entry is a host (maybe with a port) or a wildcard.
enum Entry {
    Host(String, Option<u16>),
    Wild(String),
}

fn canonical(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    match host.parse::<Ipv6Addr>() {
        Ok(a) => a.to_string(),
        Err(_) => host.to_string(),
    }
}

/// An entry that `HostRules::new` took, read again. (Only called for a list that it took whole.)
fn entry_of(text: &str) -> Entry {
    let lower = text.trim().to_ascii_lowercase();
    if let Some(domain) = lower.strip_prefix("*.") {
        return Entry::Wild(domain.strip_suffix('.').unwrap_or(domain).to_string());
    }
    if let Some(inner) = lower.strip_prefix('[') {
        let end = inner.find(']').expect("brackets were checked");
        let port = inner[end + 1..].strip_prefix(':').map(|p| p.parse::<u16>().expect("a port was checked"));
        return Entry::Host(canonical(&inner[..end]), port);
    }
    if lower.matches(':').count() == 1 {
        let (host, port) = lower.split_once(':').unwrap();
        return Entry::Host(canonical(host), Some(port.parse::<u16>().expect("a port was checked")));
    }
    Entry::Host(canonical(&lower), None)
}

struct Model {
    entries: Vec<Entry>,
    one_label: bool,
    default_port_only: bool,
    max_length: Option<usize>,
    printable: bool,
    no_credentials: bool,
    https_only: bool,
}

impl Model {
    fn label_ok(&self, before: &str) -> bool {
        let edge = |l: &str| l.starts_with('-') || l.ends_with('-');
        if self.one_label {
            !before.is_empty() && before.len() <= 63 && !edge(before) && before.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        } else {
            before.len() <= 253
                && before.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !edge(l) && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'))
        }
    }

    fn host_allowed(&self, host: &str, port: u16, default_port: u16) -> bool {
        let host = canonical(host);
        for e in &self.entries {
            if let Entry::Host(h, p) = e {
                let port_ok = match p {
                    Some(p) => port == *p,
                    None => !self.default_port_only || port == default_port,
                };
                if *h == host && port_ok {
                    return true;
                }
            }
        }
        if self.default_port_only && port != default_port {
            return false;
        }
        // (a host whose last label is a number (`1`, `0x7f`) is an address to a URL parser, and is never under a wildcard)
        let last = host.rsplit('.').next().unwrap_or("");
        let hex = last.strip_prefix("0x");
        if !last.is_empty() && (last.chars().all(|c| c.is_ascii_digit()) || hex.is_some_and(|h| h.chars().all(|c| c.is_ascii_hexdigit()))) {
            return false;
        }
        self.entries.iter().any(|e| match e {
            Entry::Wild(d) => host.strip_suffix(&format!(".{d}")).is_some_and(|before| self.label_ok(before)),
            Entry::Host(..) => false,
        })
    }

    /// Whether the limits on a URL let this text through.
    fn text_ok(&self, text: &str) -> bool {
        self.max_length.map_or(true, |m| text.len() <= m) && (!self.printable || text.bytes().all(|b| (b'!'..=b'~').contains(&b)))
    }

    fn url_ok(&self, url: &Url) -> bool {
        (!self.https_only || url.scheme == "https") && (!self.no_credentials || url.userinfo.is_none())
    }

    fn target_ok(&self, url: &Url) -> bool {
        let default_port = if url.scheme == "https" { 443 } else { 80 };
        self.url_ok(url) && self.host_allowed(&url.host, url.port, default_port)
    }
}

const OWN: [&str; 3] = ["host", "connection", "content-length"];

fn token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// What the hook gives for a hop: the headers of the input, and one of its own that says where the hop goes.
fn given(spec: &[(String, String)], url: &Url) -> Vec<(String, String)> {
    let mut v = spec.to_vec();
    v.push(("X-Hop-Host".to_string(), url.host.clone()));
    v
}

fn spec_ok(spec: &[(String, String)]) -> bool {
    spec.iter().all(|(n, v)| token(n) && !v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) && !OWN.iter().any(|o| n.eq_ignore_ascii_case(o)))
}

fn same(a: &Hop, b: &Hop) -> bool {
    (&a.method, &a.url, &a.headers, &a.body, &a.granted, a.index) == (&b.method, &b.url, &b.headers, &b.body, &b.granted, b.index)
}

fn copy(h: &Hop) -> Hop {
    Hop { method: h.method.clone(), url: h.url.clone(), headers: h.headers.clone(), body: h.body.clone(), granted: h.granted.clone(), index: h.index, decode: h.decode, min_tls: h.min_tls, running: None }
}

/// The header list that goes with `hop` is well made, and is what the caller, the hook and the client each give.
fn check_sent(client: &Client, hop: &Hop, insecure_ok: bool) {
    let sent = client.request_headers(hop);
    if !hop.url.is_https() && !insecure_ok {
        assert!(matches!(&sent, Err(Error::Refused(r)) if r.hop == hop.index), "plain http without leave: {sent:?}");
        return;
    }
    let sent = sent.unwrap_or_else(|e| panic!("headers for {} were refused: {e}", hop.url));
    for (n, v) in &sent {
        assert!(token(n), "a header name {n:?} that is not a token");
        assert!(!v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0), "a header value with a line break or NUL ({n})");
    }
    let count = |name: &str| sent.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count();
    let hosts: Vec<_> = sent.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).collect();
    assert_eq!(hosts.len(), 1, "Host is set once");
    assert_eq!(hosts[0].1, hop.url.host_header());
    assert!(count("connection") <= 1 && count("content-length") <= usize::from(!hop.body.is_empty() || matches!(hop.method.as_str(), "POST" | "PUT" | "PATCH")));
    // what the hook gave is there, as it gave it; and the caller's of the same name is not
    let mut names: Vec<String> = hop.granted.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
    names.sort();
    names.dedup();
    for name in &names {
        let want: Vec<&String> = hop.granted.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v).collect();
        let got: Vec<&String> = sent.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v).collect();
        assert_eq!(got, want, "what the hook gave under {name} and what was sent");
    }
    // a hop's header is the hook's for this hop and no other
    let hosts: Vec<&String> = sent.iter().filter(|(n, _)| n.eq_ignore_ascii_case("x-hop-host")).map(|(_, v)| v).collect();
    assert!(hosts.len() <= 1 && hosts.iter().all(|h| **h == hop.url.host), "a header of another hop: {hosts:?} at {}", hop.url);
}

pub fn egress(data: &[u8]) {
    let Some((&flags, rest)) = data.split_first() else { return };
    let text = String::from_utf8_lossy(rest);
    let mut lines = text.split('\n');
    let entries: Vec<&str> = lines.next().unwrap_or("").split(' ').filter(|e| !e.is_empty()).collect();
    let first = lines.next().unwrap_or("");
    let spec: Vec<(String, String)> = lines
        .next()
        .unwrap_or("")
        .split(';')
        .filter_map(|p| p.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        // (the harness's own marker, which the hook adds for each hop: an input that gave one too would make the check below
        // see two, one of them not the hop's, without the client having done anything wrong; found by the field run's fuzzing)
        .filter(|(n, _)| !n.eq_ignore_ascii_case("x-hop-host"))
        .collect();
    let locations: Vec<&str> = lines.collect();
    let spec_is_ok = spec_ok(&spec);

    let rules = match HostRules::new(entries.iter().copied()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let (one_label, default_port_only) = (flags & 1 != 0, flags & 2 != 0);
    let rules = rules.one_label_wildcards(one_label).default_port_only(default_port_only);
    let mut limits = UrlLimits::new();
    let mut model = Model {
        entries: entries.iter().map(|e| entry_of(e)).collect(),
        one_label,
        default_port_only,
        max_length: None,
        printable: flags & 4 != 0,
        no_credentials: flags & 8 != 0,
        https_only: flags & 16 != 0,
    };
    limits = limits.printable_ascii_only(model.printable).refuse_credentials(model.no_credentials).https_only(model.https_only);
    if flags & 64 != 0 {
        model.max_length = Some(60);
        limits = limits.max_length(60);
    }
    let insecure_ok = flags & 32 != 0;
    let method = if flags & 128 != 0 { "POST" } else { "GET" };
    let hook_spec = spec.clone();
    let client = Client::with_tls_config(ClientConfig::new(TrustStore::empty()))
        .allow_insecure_http(insecure_ok)
        .allowed_hosts(rules)
        .url_limits(limits)
        .hop_headers(move |info: &HopInfo<'_>| Ok(given(&hook_spec, info.url)));
    let caller: Vec<(String, String)> = [("Authorization", "Bearer caller"), ("Cookie", "k=v"), ("X-Caller", "1"), ("Private-Token", "caller-token")]
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();

    // the rule about hosts, asked of every host this input names, is what the simple account says
    let judged = |u: &Url| {
        let default_port = if u.scheme == "https" { 443 } else { 80 };
        let got = client.check_target(u, 0).is_ok();
        let want = model.target_ok(u);
        assert_eq!(got, want, "{u:?}: the client says {got}, the simple account {want} (flags {flags:#x}, entries {entries:?}, default port {default_port})");
    };

    // ---- the request itself
    let expected = model.text_ok(first) && Url::parse(first).map_or(false, |u| model.target_ok(&u)) && spec_is_ok;
    let started = client.start(method.to_string(), first, caller.clone(), b"{}".to_vec());
    assert_eq!(started.is_ok(), expected, "the request {first:?}: the client says {:?}, the simple account {expected} (flags {flags:#x}, entries {entries:?}, spec {spec:?})", started.as_ref().map(|_| ()));
    if let Err(e) = &started {
        // a refusal by a rule is a refusal, of hop 0 (a URL that does not parse, or a hook that gives a bad header, is not)
        if let Error::Refused(r) = e {
            assert_eq!(r.hop, 0);
        }
    }
    let Ok(mut hop) = started else { return };
    judged(&hop.url);
    assert_eq!((hop.index, hop.granted.clone()), (0, given(&spec, &hop.url)));
    check_sent(&client, &hop, insecure_ok);

    // ---- every redirect
    let mut hops = 0usize;
    for (i, location) in locations.iter().take(12).enumerate() {
        let status = [302u16, 303, 307, 308, 301][i % 5];
        let before = copy(&hop);
        let was = hops;
        let result = client.follow(&mut hop, status, &[("Location".to_string(), location.to_string())], &mut hops);
        if was >= 10 {
            // the limit on redirects (the client's default) is checked before anything else, and before the count goes up
            assert!(matches!(&result, Err(Error::Http(m)) if m.contains("too many redirects")), "{result:?}");
            assert!(same(&before, &hop) && hops == was);
            return;
        }
        assert_eq!(hops, was + 1);
        // what the simple account says about this one
        let next = if model.text_ok(location) { before.url.join(location).ok() } else { None };
        let next_ok = next.as_ref().is_some_and(|n| model.text_ok(&n.to_string()) && !(before.url.is_https() && !n.is_https()) && model.target_ok(n));
        match (&result, next_ok) {
            (Ok(true), true) => {}
            (Err(Error::Refused(r)), false) => assert_eq!(r.hop, hops, "the hop a refusal names"),
            (Err(_), false) => {}
            other => panic!("the redirect {location:?} from {}: the client says {:?}, the simple account says it is {} (flags {flags:#x}, entries {entries:?})", before.url, other.0.as_ref().map(|_| ()), next_ok),
        }
        match result {
            Err(_) => {
                assert!(same(&before, &hop), "a refused hop leaves the request as it was");
                return;
            }
            Ok(followed) => {
                assert!(followed);
                let n = next.unwrap();
                assert_eq!((&hop.url, hop.index), (&n, hops));
                judged(&hop.url);
                // the method and the body: as a redirect of this status makes them
                let drop_body = status == 303 && before.method != "HEAD" || (status == 301 || status == 302) && before.method == "POST";
                assert_eq!(hop.method, if drop_body { "GET" } else { before.method.as_str() });
                assert_eq!(hop.body.is_empty(), drop_body || before.body.is_empty());
                // the credentials of the caller go no further than their origin; what the hook gave is this hop's own
                let carried = |name: &str| hop.headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(name));
                if before.url.origin() != hop.url.origin() {
                    assert!(!carried("authorization") && !carried("cookie"), "a credential followed a redirect to another origin");
                }
                assert_eq!(hop.granted, given(&spec, &hop.url), "what the hook gave is for this hop only");
                check_sent(&client, &hop, insecure_ok);
            }
        }
    }
}

/// Inputs to start from: the rule of a module that reaches the Marketplace (one label, the default port, strict limits) and the loose one.
pub fn example_inputs() -> Vec<Vec<u8>> {
    let strict = 1 | 2 | 4 | 8 | 16;
    let make = |flags: u8, text: &str| {
        let mut v = vec![flags];
        v.extend_from_slice(text.as_bytes());
        v
    };
    vec![
        make(strict, "marketplace.visualstudio.com *.gallerycdn.vsassets.io *.gallery.vsassets.io\nhttps://marketplace.visualstudio.com/_apis/public/gallery/extensionquery\nAuthorization: Bearer t\nhttps://x.gallerycdn.vsassets.io/a\n/b\nhttps://a.b.gallerycdn.vsassets.io/c"),
        make(strict | 128, "marketplace.visualstudio.com *.gallerycdn.vsassets.io\nhttps://marketplace.visualstudio.com/q\nPrivate-Token: p;X-Other: 1\nhttps://u:p@x.gallerycdn.vsassets.io/a"),
        make(0, "api.example.com *.cdn.example.net example.org:8443\nhttps://api.example.com/start\n\nhttps://a.b.cdn.example.net:8443/x\nhttp://a.cdn.example.net/y"),
        make(32 | 128, "127.0.0.1 [::1]:8443 localhost\nhttp://127.0.0.1:8080/a?b=c\nX-Token: t\nhttp://localhost:9/z\n//[::1]:8443/w\n?q=1"),
        make(strict | 64, "a.example.com\nhttps://a.example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nHost: evil\n"),
        make(0, "*.example.com\nhttps://x.example.com/\nX-A: b\r\nX-B: c\nhttps://example.com/"),
    ]
}
