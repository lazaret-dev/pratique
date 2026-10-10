//! What a client with a rule about hosts ([`Client::allowed_hosts`]) does, and what a POST that carries JSON and says what it accepts sends.
//! The rule is about the host a request is going to: the first URL and every redirect, before anything is sent there. These settle, that
//! the rule's own tests cannot, that it is applied where a request is made (blocking, async, streamed, whole) and at every hop, that a
//! refused host is not so much as connected to, and that what a redirect keeps and drops is what a caller who sends JSON needs. The
//! tighter rule that a caller can ask for (one-label wildcards, the default port only, and the limits of [`UrlLimits`]) is settled here
//! too, for the rule of a module that reaches the Marketplace's hosts: on the first URL and on every hop.

use super::testserver::*;
use super::{Hop, HopInfo, HostRules};
use crate::error::{Refused, RefusedBy};
use crate::asyncio::block_on;
use crate::error::Error;
use crate::http::{Url, UrlLimits};
use std::sync::{Arc, Mutex};

/// A rule as `HostRules::new` makes it: the tight one (one label under a wildcard, the default port for an entry without a port).
fn rules(entries: &[&str]) -> HostRules {
    HostRules::new(entries.iter().copied()).unwrap()
}

/// A rule for the test servers, which listen on ports that are not the default: an entry without a port is any port.
fn local(entries: &[&str]) -> HostRules {
    rules(entries).default_port_only(false)
}

/// The URL of `server` with its host written as `host` (`localhost` reaches the same server as `127.0.0.1` does).
fn as_host(server: &TestServer, host: &str, path: &str) -> String {
    server.url(path).replace("127.0.0.1", host)
}

fn refused(e: &Error) -> bool {
    matches!(e, Error::Refused(r) if r.by == RefusedBy::HostRule && r.reason.starts_with("host not allowed"))
}

/// Refused by a limit of the URL (not by the rule about hosts).
fn limited(e: &Error) -> bool {
    matches!(e, Error::Refused(r) if r.by == RefusedBy::UrlLimit && r.reason.starts_with("URL not allowed"))
}

fn port_of(server: &TestServer) -> u16 {
    Url::parse(&server.url("/")).unwrap().port
}

/// A client with the rule that a module reaching the Marketplace has: the hosts of its CDNs (one label under each domain, on the default
/// port: the rule as it is made, with no switch to set), and the strictest limits on a URL. It has no connection to make: the tests ask it
/// what it decides.
fn marketplace() -> crate::Client {
    crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io", "*.gallery.vsassets.io"]))
        .url_limits(UrlLimits::strict())
}

/// What `client` decides about a request to `url`: the host it is to go to, or why not.
fn first(client: &crate::Client, url: &str) -> Result<String, Error> {
    client.start("GET".into(), url, vec![], vec![]).map(|hop| hop.url.host)
}

/// What `client` decides about a redirect from `from` to `location`: the host it goes to, or why not.
fn hop_to(client: &crate::Client, from: &str, location: &str) -> Result<String, Error> {
    let mut hop = Hop { method: "GET".into(), url: Url::parse(from).unwrap(), headers: vec![], body: vec![], granted: vec![], index: 0, decode: None, min_tls: None, running: None };
    client.follow(&mut hop, 302, &[("Location".to_string(), location.to_string())], &mut 0)?;
    Ok(hop.url.host)
}

#[derive(Debug)]
enum Verdict {
    /// Goes to this host.
    Goes(&'static str),
    /// The rule about hosts refuses it.
    Host,
    /// A limit of the URL refuses it.
    Url,
    /// A redirect from https to plain http is refused (as it is of every client).
    Plain,
}

fn check(what: &str, got: Result<String, Error>, want: &Verdict) {
    let ok = match (&got, want) {
        (Ok(h), Verdict::Goes(w)) => h == w,
        (Err(e), Verdict::Host) => refused(e),
        (Err(e), Verdict::Url) => limited(e),
        (Err(Error::Refused(r)), Verdict::Plain) => r.by == RefusedBy::Scheme && r.reason.contains("plain http"),
        _ => false,
    };
    assert!(ok, "{what}: wanted {want:?}, got {got:?}");
}

#[test]
fn a_request_to_a_host_the_rule_does_not_name_is_refused_and_nothing_connects() {
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().allowed_hosts(rules(&["api.example.com", "*.example.org"]));
    for url in [server.url("/"), as_host(&server, "localhost", "/"), as_host(&server, "example.org", "/")] {
        let e = client.get(&url).unwrap_err();
        assert!(refused(&e), "{url}: {e}");
    }
    assert_eq!(server.connections(), 0, "a host that is refused is not connected to");
    // the rule names the host: it goes through
    let client = server.client().allowed_hosts(local(&["api.example.com", "127.0.0.1"]));
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello");
    // (the same for a request that is streamed, and for the other methods)
    let none = server.client().allowed_hosts(rules(&["api.example.com"]));
    assert!(refused(&none.get_stream(&server.url("/")).err().unwrap()));
    assert!(refused(&none.post(&server.url("/"), "x").unwrap_err()));
    assert!(refused(&none.head(&server.url("/")).unwrap_err()));
    assert!(refused(&none.request("PUT", &server.url("/")).body("x").send().unwrap_err()));
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_redirect_to_a_host_the_rule_does_not_name_is_refused_before_anything_is_sent_there() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"moved")));
    let client = origin.client().allowed_hosts(local(&["127.0.0.1"]));
    let e = client.get(&origin.url("/")).unwrap_err();
    assert!(refused(&e) && e.to_string().contains("localhost"), "{e}");
    assert_eq!((origin.connections(), target.connections()), (1, 0), "the redirect was seen, and the host it names was not connected to");
    // streamed, the same
    assert!(refused(&client.get_stream(&origin.url("/")).err().unwrap()));
    assert_eq!(target.connections(), 0);
    // with the host in the rule, the same redirect is followed
    let client = origin.client().allowed_hosts(local(&["127.0.0.1", "localhost"]));
    assert_eq!(client.get(&origin.url("/")).unwrap().text(), "target");
    assert_eq!(target.connections(), 1);
    // and with no rule at all
    assert_eq!(origin.client().get(&origin.url("/")).unwrap().text(), "target");
}

#[test]
fn every_hop_is_checked_not_only_the_first_and_the_last() {
    // a (127.0.0.1) -> b (127.0.0.1) -> c (written as localhost) -> last (127.0.0.1): with a rule that names only 127.0.0.1 the hop in the
    // middle of the chain is the one that is refused, though the host at the end of it is allowed
    let last = TestServer::start(|_| ok("end"));
    let last_url = last.url("/end");
    let c = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {last_url}")], b"")));
    let c_url = as_host(&c, "localhost", "/c");
    let b = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {c_url}")], b"")));
    let b_url = b.url("/b");
    let a = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {b_url}")], b"")));
    let client = a.client().allowed_hosts(local(&["127.0.0.1"]));
    let e = client.get(&a.url("/a")).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!((a.connections(), b.connections(), c.connections(), last.connections()), (1, 1, 0, 0));
    // a rule that names all of them follows the chain to the end
    let client = a.client().allowed_hosts(local(&["127.0.0.1", "localhost"]));
    assert_eq!(client.get(&a.url("/a")).unwrap().text(), "end");
}

#[test]
fn a_user_name_in_the_url_does_not_make_a_host_allowed() {
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().allowed_hosts(local(&["127.0.0.1"]));
    // the host is what follows the last `@`, whatever comes before it
    let evil = server.url("/").replace("://127.0.0.1", "://127.0.0.1@localhost");
    assert!(refused(&client.get(&evil).unwrap_err()), "{evil}");
    let fine = server.url("/").replace("://127.0.0.1", "://localhost@127.0.0.1");
    assert_eq!(client.get(&fine).unwrap().text(), "hello");
    // nor does a redirect that has one
    let target = TestServer::start(|_| ok("target"));
    let landed = target.url("/").replace("://127.0.0.1", "://127.0.0.1@localhost");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"")));
    assert!(refused(&origin.client().allowed_hosts(local(&["127.0.0.1"])).get(&origin.url("/")).unwrap_err()));
    assert_eq!(target.connections(), 0);
}

#[test]
fn a_clone_has_the_rule_that_was_set_on_it() {
    let server = TestServer::start(|_| ok("hello"));
    let shared = server.client();
    let module_a = shared.clone().allowed_hosts(local(&["127.0.0.1"]));
    let module_b = shared.clone().allowed_hosts(rules(&["api.example.com"]));
    assert_eq!(module_a.get(&server.url("/")).unwrap().text(), "hello");
    assert!(refused(&module_b.get(&server.url("/")).unwrap_err()));
    // the client they came from has none
    assert_eq!(shared.get(&server.url("/")).unwrap().text(), "hello");
    // and a rule can be taken away from a clone
    assert_eq!(module_b.clone().any_host().get(&server.url("/")).unwrap().text(), "hello");
    // they share their connections: one was made, and it served all three that got through
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_wildcard_is_applied_to_the_hop_that_a_redirect_makes() {
    // (no network: the decision of `follow` for the redirect's `Location`)
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty())).allowed_hosts(rules(&["api.example.com", "*.cdn.example.net"]));
    let hop = |url: &str| Hop { method: "GET".into(), url: Url::parse(url).unwrap(), headers: vec![], body: vec![], granted: vec![], index: 0, decode: None, min_tls: None, running: None };
    let location = |value: &str| vec![("Location".to_string(), value.to_string())];
    // (where the redirect goes, the host it ends up at if it is followed)
    for (to, goes_to) in [
        ("https://a.cdn.example.net/x", Some("a.cdn.example.net")),
        // (the rule as it is made: one label under the wildcard)
        ("https://a.b.cdn.example.net/x", None),
        ("https://API.example.com/x", Some("api.example.com")),
        ("/relative", Some("api.example.com")),
        ("https://cdn.example.net/x", None),
        ("https://evilcdn.example.net/x", None),
        ("https://a.cdn.example.net.evil.org/x", None),
        ("https://example.com/x", None),
        ("//evil.example.org/x", None),
        ("https://api.example.com@evil.example.org/x", None),
        ("https://a.cdn.example.net:8443@evil.example.org/x", None),
    ] {
        let mut h = hop("https://api.example.com/start");
        let r = client.follow(&mut h, 302, &location(to), &mut 0);
        match (r, goes_to) {
            (Ok(true), Some(host)) => assert_eq!(h.url.host, host, "{to}"),
            (Err(e), None) => assert!(refused(&e), "{to}: {e}"),
            (r, _) => panic!("{to}: {r:?}"),
        }
    }
    // a refused hop leaves the request as it was
    let mut h = hop("https://api.example.com/start");
    assert!(client.follow(&mut h, 302, &location("https://evil.example.org/"), &mut 0).is_err());
    assert_eq!(h.url.host, "api.example.com");
}

#[test]
fn the_async_client_applies_the_rule_too() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |s| if s.path() == "/ok" { ok("fine") } else { Reply::Send(response(302, &[&format!("Location: {landed}")], b"")) });
    let client = origin.client().allowed_hosts(local(&["127.0.0.1"])).into_async();
    assert_eq!(block_on(client.get(&origin.url("/ok"))).unwrap().text(), "fine");
    let e = block_on(client.get(&origin.url("/redirect"))).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(target.connections(), 0);
    let e = block_on(client.get(&as_host(&origin, "localhost", "/ok"))).unwrap_err();
    assert!(refused(&e), "{e}");
    // (and the blocking client's `*_async` methods)
    let e = block_on(origin.client().allowed_hosts(local(&["127.0.0.1"])).get_async(&origin.url("/redirect"))).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(target.connections(), 0);
}

#[test]
fn the_limits_hold_at_every_hop_of_a_followed_redirect() {
    // the redirect limit, the size limit of the body of the last response and the time limit are the ones of the client the request was made with
    let server = TestServer::start(|s| match s.path() {
        "/loop" => Reply::Send(response(302, &["Location: /loop"], b"")),
        "/big" => Reply::Send(response(200, &[], &[b'x'; 5000])),
        "/slow" => Reply::Send(response(302, &["Location: /big"], b"")),
        _ => ok("hello"),
    });
    let client = server.client().allowed_hosts(local(&["127.0.0.1"]));
    let e = client.clone().max_redirects(3).get(&server.url("/loop")).unwrap_err();
    assert!(e.to_string().contains("too many redirects"), "{e}");
    assert_eq!(server.requests().iter().filter(|s| s.path() == "/loop").count(), 4, "the first request and three redirects");
    let e = client.clone().max_body_bytes(1000).get(&server.url("/slow")).unwrap_err();
    assert!(e.to_string().contains("size limit"), "{e}");
    assert_eq!(client.request("GET", &server.url("/slow")).max_body_bytes(10_000).send().unwrap().body.len(), 5000);
}

// ------------------------------------------------------------------------------------------------ a POST of JSON

#[test]
fn a_post_of_json_that_says_what_it_accepts() {
    let server = TestServer::start(|s| {
        let body = String::from_utf8_lossy(&s.body).to_string();
        Reply::Send(response(200, &["Content-Type: application/json"], format!("{{\"got\":{}}}", body.len()).as_bytes()))
    });
    let client = server.client().allowed_hosts(local(&["127.0.0.1"]));
    let json = r#"{"module":"market","query":"café \"quoted\"","n":[1,2,3]}"#;
    let r = client
        .request("POST", &server.url("/api/v1/search"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json; charset=utf-8")
        .body(json)
        .send()
        .unwrap();
    assert_eq!((r.status, r.text()), (200, format!("{{\"got\":{}}}", json.len())));
    let seen = server.requests().remove(0);
    assert_eq!(seen.method(), "POST");
    assert_eq!(seen.path(), "/api/v1/search");
    assert_eq!(seen.body, json.as_bytes());
    assert_eq!(seen.header("content-length"), Some(json.len().to_string().as_str()));
    assert_eq!(seen.header("content-type"), Some("application/json; charset=utf-8"));
    // the caller's Accept is the one sent, and the default (`*/*`) is not sent besides it
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert_eq!(seen.head.to_ascii_lowercase().matches("\naccept:").count(), 1, "{}", seen.head);
    // without one, the default is
    client.post(&server.url("/x"), "{}").unwrap();
    assert_eq!(server.requests().last().unwrap().header("accept"), Some("*/*"));
}

#[test]
fn a_redirect_that_keeps_the_method_keeps_the_json_and_what_is_accepted() {
    let target = TestServer::start(|s| Reply::Send(response(200, &[], format!("{} {}", s.method(), String::from_utf8_lossy(&s.body)).as_bytes())));
    let landed = target.url("/landed");
    let origin = TestServer::start(move |s| {
        let status = match s.path() {
            "/temporary" => 307,
            "/permanent" => 308,
            "/see-other" => 303,
            _ => 302,
        };
        Reply::Send(response(status, &[&format!("Location: {landed}")], b""))
    });
    let client = origin.client().allowed_hosts(local(&["127.0.0.1"]));
    let post = |path: &str| {
        client
            .request("POST", &origin.url(path))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer secret")
            .body(r#"{"a":1}"#)
            .send()
            .unwrap()
    };
    // 307 and 308: the same method and the same body, to the same host
    for path in ["/temporary", "/permanent"] {
        assert_eq!(post(path).text(), r#"POST {"a":1}"#, "{path}");
        let landed = target.requests().pop().unwrap();
        assert_eq!(landed.header("accept"), Some("application/json"), "{path}");
        assert_eq!(landed.header("content-type"), Some("application/json"), "{path}");
    }
    // 303 (and 302 for a POST): a GET without the body or what described it; what is accepted stays
    for path in ["/see-other", "/found"] {
        assert_eq!(post(path).text(), "GET ", "{path}");
        let landed = target.requests().pop().unwrap();
        assert_eq!(landed.header("accept"), Some("application/json"), "{path}");
        assert_eq!(landed.header("content-type"), None, "{path}");
    }
    // (the credential is not sent to another origin by any of them)
    assert!(target.requests().iter().all(|s| s.header("authorization").is_none()));
}

// ------------------------------------------------------------------------------------------------ the tighter rule

const CDN: &str = "x.gallerycdn.vsassets.io";

#[test]
fn the_rule_of_a_module_that_reaches_the_marketplace_holds_on_the_first_url() {
    let client = marketplace();
    let long = |n: usize| format!("https://{CDN}/{}", "a".repeat(n - format!("https://{CDN}/").len()));
    for (url, want) in [
        ("https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://X.GalleryCDN.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Goes(CDN)),
        ("https://p-1.gallery.vsassets.io/a".to_string(), Verdict::Goes("p-1.gallery.vsassets.io")),
        ("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery".to_string(), Verdict::Goes("marketplace.visualstudio.com")),
        // one label, and no other: not the domain, not two labels, not a name that only ends like the domain
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://x_y.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        (format!("https://{}.gallerycdn.vsassets.io/a", "a".repeat(64)), Verdict::Host),
        // the default port only: a wildcard never matches another port, and nor does a plain entry
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Host),
        ("https://marketplace.visualstudio.com:8443/a".to_string(), Verdict::Host),
        // https only, no credentials, printable ASCII only, at most 2,048 bytes
        ("http://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://u@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://u:p@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/a b".to_string(), Verdict::Url),
        (" https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/a\n".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/caf\u{e9}".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/\u{7f}".to_string(), Verdict::Url),
        (long(2048), Verdict::Goes(CDN)),
        (long(2049), Verdict::Url),
    ] {
        check(&url, first(&client, &url), &want);
    }
}

#[test]
fn the_rule_of_a_module_that_reaches_the_marketplace_holds_on_every_redirect() {
    let client = marketplace();
    let from = "https://marketplace.visualstudio.com/start";
    let long = |n: usize| format!("https://{CDN}/{}", "a".repeat(n - format!("https://{CDN}/").len()));
    for (location, want) in [
        ("https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Goes(CDN)),
        ("//x.gallery.vsassets.io/a".to_string(), Verdict::Goes("x.gallery.vsassets.io")),
        ("/relative".to_string(), Verdict::Goes("marketplace.visualstudio.com")),
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io:80/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io.evil.org/a".to_string(), Verdict::Host),
        ("https://u@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        // (refused twice over: it has a user name, and its host is evil.org; the limit speaks first)
        ("https://x.gallerycdn.vsassets.io@evil.org/a".to_string(), Verdict::Url),
        ("https://u:p@x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Url),
        ("http://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Plain),
        ("https://x.gallerycdn.vsassets.io/a b".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/caf\u{e9}".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/\u{7f}".to_string(), Verdict::Url),
        (long(2048), Verdict::Goes(CDN)),
        (long(2049), Verdict::Url),
        (format!("/{}", "a".repeat(3000)), Verdict::Url),
    ] {
        check(&location, hop_to(&client, from, &location), &want);
    }
    // a short Location can make a long URL: it is the URL that is sent to that is judged, as well as what the server said
    let base = format!("https://marketplace.visualstudio.com/{}", "p".repeat(1980));
    assert!(base.len() < 2048);
    assert!(hop_to(&client, &base, "?q=1").is_ok());
    assert!(limited(&hop_to(&client, &base, &format!("?q={}", "a".repeat(100))).unwrap_err()));
    // (a hop that follows a hop: it is the one the redirect has made that the next is judged from, and every one is judged)
    let mut hop = Hop { method: "GET".into(), url: Url::parse(from).unwrap(), headers: vec![], body: vec![], granted: vec![], index: 0, decode: None, min_tls: None, running: None };
    let at = |v: &str| vec![("Location".to_string(), v.to_string())];
    let mut hops = 0;
    assert!(client.follow(&mut hop, 302, &at("https://x.gallerycdn.vsassets.io/one"), &mut hops).unwrap());
    assert!(client.follow(&mut hop, 302, &at("https://y.gallery.vsassets.io/two"), &mut hops).unwrap());
    assert!(limited(&client.follow(&mut hop, 302, &at("https://u:p@z.gallery.vsassets.io/three"), &mut hops).unwrap_err()));
    assert_eq!(hop.url.host, "y.gallery.vsassets.io", "a refused hop leaves the request where it was");
}

#[test]
fn with_the_switches_off_the_rule_is_the_loose_one() {
    // the same locations through a client that has the hosts with both switches off and no limit: any depth, any port, credentials and
    // a long URL are what the rule lets through (a caller that wants that says so)
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io"]).one_label_wildcards(false).default_port_only(false));
    let from = "https://marketplace.visualstudio.com/start";
    let long = format!("https://{CDN}/{}", "a".repeat(3000));
    for (location, want) in [
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes("a.b.gallerycdn.vsassets.io")),
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Goes(CDN)),
        ("https://u:p@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x_y.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes("x_y.gallerycdn.vsassets.io")),
        (long, Verdict::Goes(CDN)),
        // what no switch lets through: the domain itself, a name that only ends like it, a host that is not named
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evil.org/a".to_string(), Verdict::Host),
    ] {
        check(&location, hop_to(&client, from, &location), &want);
    }
    assert_eq!(first(&client, " https://u:p@a.b.gallerycdn.vsassets.io:8443/a").unwrap(), "a.b.gallerycdn.vsassets.io");
    // one switch at a time
    let one_label = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["*.gallerycdn.vsassets.io"]).default_port_only(false));
    assert!(refused(&first(&one_label, "https://a.b.gallerycdn.vsassets.io/").unwrap_err()));
    assert!(first(&one_label, "https://a.gallerycdn.vsassets.io:8443/").is_ok(), "a port is not looked at when the rule is told not to");
    let default_port = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["*.gallerycdn.vsassets.io"]).one_label_wildcards(false));
    assert!(refused(&first(&default_port, "https://a.gallerycdn.vsassets.io:8443/").unwrap_err()));
    assert!(first(&default_port, "https://a.b.gallerycdn.vsassets.io/").is_ok(), "the depth is not looked at when the rule is told not to");
}

#[test]
fn a_port_is_judged_at_every_hop_and_nothing_is_connected_to_that_is_refused() {
    // origin and target are on the same host and on different ports: with the default port only (the rule as it is made) and an entry for
    // the origin's port, the
    // redirect to the target's port is refused (the host is the one the rule names), and with an entry for each it is followed
    let target = TestServer::start(|_| ok("target"));
    let landed = target.url("/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"moved")));
    let (po, pt) = (port_of(&origin), port_of(&target));
    let tight = |entries: &[String]| origin.client().allowed_hosts(HostRules::new(entries.iter().map(|e| e.as_str())).unwrap());
    let e = tight(&[format!("127.0.0.1:{po}")]).get(&origin.url("/")).unwrap_err();
    assert!(refused(&e) && e.to_string().contains(&pt.to_string()), "{e}");
    assert_eq!((origin.connections(), target.connections()), (1, 0));
    // (a plain entry is the default port only: the origin is not reached either)
    let e = tight(&["127.0.0.1".to_string()]).get(&origin.url("/")).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(origin.connections(), 1, "nothing was connected to for that");
    assert_eq!(tight(&[format!("127.0.0.1:{po}"), format!("127.0.0.1:{pt}")]).get(&origin.url("/")).unwrap().text(), "target");
    // the loose rule: a host is every port, and an entry with a port is that port
    assert_eq!(origin.client().allowed_hosts(local(&["127.0.0.1"])).get(&origin.url("/")).unwrap().text(), "target");
    let by_port = origin.client().allowed_hosts(rules(&[&format!("127.0.0.1:{po}")]));
    assert!(refused(&by_port.get(&origin.url("/")).unwrap_err()));
}

#[test]
fn a_redirect_that_a_limit_refuses_is_refused_before_anything_is_sent_there() {
    let target = TestServer::start(|_| ok("target"));
    let creds = target.url("/").replace("://", "://user:pw@");
    let long = format!("{}{}", target.url("/"), "a".repeat(2100));
    let spaced = format!("{}a b", target.url("/"));
    for (location, limits, without) in [
        (creds, UrlLimits::new().refuse_credentials(true), "target"),
        (long, UrlLimits::new().max_length(2048), "target"),
        // (what the URL parser refuses anyway, in the middle of a URL: the limit says so first and in its own words)
        (spaced, UrlLimits::new().printable_ascii_only(true), "invalid URL"),
    ] {
        let at = location.clone();
        let reached = target.connections();
        let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {at}")], b"moved")));
        let client = origin.client().allowed_hosts(local(&["127.0.0.1"])).url_limits(limits);
        let e = client.get(&origin.url("/")).unwrap_err();
        assert!(limited(&e), "{limits:?}: {e}");
        assert!(limited(&client.get_stream(&origin.url("/")).err().unwrap()));
        assert!(limited(&block_on(client.clone().into_async().get(&origin.url("/"))).unwrap_err()));
        assert_eq!(target.connections(), reached, "{limits:?}: the target was connected to");
        // the same redirect, with no limit, is what it would have been
        let unlimited = origin.client().get(&origin.url("/"));
        let got = match &unlimited {
            Ok(r) => r.text(),
            Err(e) => e.to_string(),
        };
        assert!(got.contains(without), "{limits:?}: {got}");
    }
    // https only: a request to a plain http URL is refused before a connection, though the client may use plain http
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().url_limits(UrlLimits::new().https_only(true));
    let e = client.get(&server.url("/")).unwrap_err();
    assert!(limited(&e) && e.to_string().contains("not https"), "{e}");
    assert_eq!(server.connections(), 0);
    assert_eq!(server.client().get(&server.url("/")).unwrap().text(), "hello");
}

#[test]
fn a_clone_has_the_limits_that_were_set_on_it() {
    let server = TestServer::start(|_| ok("hello"));
    let shared = server.client();
    let strict = shared.clone().url_limits(UrlLimits::strict());
    assert!(limited(&strict.get(&server.url("/")).unwrap_err()));
    assert_eq!(shared.get(&server.url("/")).unwrap().text(), "hello");
    assert_eq!(strict.clone().url_limits(UrlLimits::new()).get(&server.url("/")).unwrap().text(), "hello");
}

// ------------------------------------------------------------------------------------------------ headers for each hop

type Log = Arc<Mutex<Vec<String>>>;

/// A hook that notes what it is asked (`hop method port from-port`) and gives what `give` says for the port the hop goes to.
fn noting(log: &Log, give: impl Fn(&HopInfo<'_>) -> Result<Vec<(String, String)>, Error> + Send + Sync + 'static) -> impl Fn(&HopInfo<'_>) -> Result<Vec<(String, String)>, Error> + Send + Sync + 'static {
    let log = log.clone();
    move |info| {
        let from = info.from.map_or("-".to_string(), |u| u.port.to_string());
        log.lock().unwrap().push(format!("{} {} {} {} {}", info.hop, info.method, info.url.port, from, info.crosses_origin()));
        give(info)
    }
}

fn h(name: &str, value: &str) -> (String, String) {
    (name.to_string(), value.to_string())
}

#[test]
fn each_hop_gets_the_headers_the_hook_gives_for_it_and_no_other_hop_does() {
    // a (127.0.0.1) -> b (localhost) -> c (127.0.0.1): three hosts, three tokens, and a header the hook gives is not one that a redirect carries on
    let c = TestServer::start(|_| ok("end"));
    let c_url = c.url("/c");
    let b = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {c_url}")], b"")));
    let b_url = as_host(&b, "localhost", "/b");
    let a = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {b_url}")], b"")));
    let (pa, pb, pc) = (port_of(&a), port_of(&b), port_of(&c));
    let log: Log = Default::default();
    let client = a.client().hop_headers(noting(&log, move |info| {
        Ok(match info.url.port {
            p if p == pa => vec![h("Authorization", "Bearer token-a"), h("PRIVATE-TOKEN", "private-a")],
            p if p == pb => vec![h("Authorization", "Bearer token-b")],
            _ => vec![],
        })
    }));
    assert_eq!(client.get(&a.url("/a")).unwrap().text(), "end");
    let seen = |s: &TestServer| s.requests().remove(0);
    assert_eq!((seen(&a).header("authorization"), seen(&a).header("private-token")), (Some("Bearer token-a"), Some("private-a")));
    assert_eq!((seen(&b).header("authorization"), seen(&b).header("private-token")), (Some("Bearer token-b"), None), "b gets its own, and not what a was given");
    assert_eq!((seen(&c).header("authorization"), seen(&c).header("private-token")), (None, None), "c is given nothing, and not what a or b was given");
    // asked once for each hop, in order, with what each hop is
    assert_eq!(*log.lock().unwrap(), vec![format!("0 GET {pa} - false"), format!("1 GET {pb} {pa} true"), format!("2 GET {pc} {pb} true")]);
}

#[test]
fn a_redirect_to_the_same_origin_is_not_a_crossing_and_is_asked_about_all_the_same() {
    let server = TestServer::start(|s| if s.path() == "/start" { Reply::Send(response(302, &["Location: /next"], b"")) } else { ok("there") });
    let log: Log = Default::default();
    let client = server.client().hop_headers(noting(&log, |info| Ok(vec![h("X-Hop", &info.hop.to_string())])));
    assert_eq!(client.get(&server.url("/start")).unwrap().text(), "there");
    let port = port_of(&server);
    assert_eq!(*log.lock().unwrap(), vec![format!("0 GET {port} - false"), format!("1 GET {port} {port} false")]);
    let reqs = server.requests();
    assert_eq!((reqs[0].header("x-hop"), reqs[1].header("x-hop")), (Some("0"), Some("1")), "each request has the header of its own hop, not of the one before");
}

#[test]
fn what_the_hook_gives_replaces_what_the_caller_set_and_what_a_url_says() {
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().hop_headers(|_| Ok(vec![h("authorization", "Bearer from-hook")]));
    // (the caller's own Authorization, a user name in the URL: the hook's is the one that is sent, and there is one)
    let r = client.request("GET", &server.url("/")).header("Authorization", "Bearer from-caller").header("X-Other", "kept").send().unwrap();
    assert_eq!(r.text(), "hello");
    let url = server.url("/").replace("://", "://user:pw@");
    client.get(&url).unwrap();
    for seen in server.requests() {
        assert_eq!(seen.header("authorization"), Some("Bearer from-hook"));
        assert_eq!(seen.head.to_ascii_lowercase().matches("\nauthorization:").count(), 1, "{}", seen.head);
    }
    assert_eq!(server.requests()[0].header("x-other"), Some("kept"));
    // without a hook, they are what they were
    let plain = server.client();
    plain.request("GET", &server.url("/")).header("Authorization", "Bearer from-caller").send().unwrap();
    assert_eq!(server.requests().last().unwrap().header("authorization"), Some("Bearer from-caller"));
}

#[test]
fn a_caller_header_is_carried_by_a_redirect_as_before_and_the_credential_ones_are_dropped_at_another_origin() {
    // what the hook gives is for the hop it is given for; what the caller set is what it was (Authorization, Cookie and Proxy-Authorization
    // are dropped at another origin, and the others stay), and the hook's answer for the new hop is added to that
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"")));
    let pt = port_of(&target);
    let client = origin.client().hop_headers(move |info| Ok(if info.url.port == pt { vec![h("Authorization", "Bearer for-target")] } else { vec![] }));
    client
        .request("GET", &origin.url("/"))
        .header("Authorization", "Bearer from-caller")
        .header("Cookie", "k=v")
        .header("X-Kept", "yes")
        .send()
        .unwrap();
    let seen = target.requests().remove(0);
    assert_eq!(seen.header("authorization"), Some("Bearer for-target"));
    assert_eq!((seen.header("cookie"), seen.header("x-kept")), (None, Some("yes")));
}

#[test]
fn a_hop_the_hook_refuses_is_not_connected_to_and_the_request_fails_with_what_it_said() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"moved")));
    let refuse_localhost = |info: &HopInfo<'_>| {
        if info.url.host == "localhost" {
            Err(Error::Http(format!("no credentials for {}", info.url.host)))
        } else {
            Ok(vec![h("Authorization", "Bearer secret-value")])
        }
    };
    let client = origin.client().hop_headers(refuse_localhost);
    let e = client.get(&origin.url("/")).unwrap_err();
    assert!(e.to_string().contains("no credentials for localhost"), "{e}");
    assert!(!e.to_string().contains("secret-value"));
    assert_eq!((origin.connections(), target.connections()), (1, 0));
    assert!(client.get_stream(&origin.url("/")).is_err());
    assert_eq!(target.connections(), 0);
    // the first URL too: nothing is connected to
    let none = origin.client().hop_headers(|_| Err(Error::Http("no".into())));
    let before = origin.connections();
    assert!(none.get(&origin.url("/")).unwrap_err().to_string().contains("no"));
    assert_eq!(origin.connections(), before);
    // and a refused hop leaves the request as it was: the URL, the method, the headers that were given for it
    let mut hop = client.start("POST".into(), &origin.url("/"), vec![], b"x".to_vec()).unwrap();
    let granted = hop.granted.clone();
    assert!(client.follow(&mut hop, 302, &[("Location".to_string(), as_host(&target, "localhost", "/"))], &mut 0).is_err());
    assert_eq!((hop.method.as_str(), hop.url.host.as_str(), hop.body.len(), hop.granted), ("POST", "127.0.0.1", 1, granted));
}

#[test]
fn the_hook_is_not_asked_about_a_url_that_the_rule_or_a_limit_refuses() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"")));
    let log: Log = Default::default();
    let client = origin.client().allowed_hosts(local(&["127.0.0.1"])).hop_headers(noting(&log, |_| Ok(vec![h("Authorization", "Bearer t")])));
    assert!(refused(&client.get(&origin.url("/")).unwrap_err()));
    // asked for the first URL, which the rule allows, and not for the redirect that it does not
    assert_eq!(log.lock().unwrap().len(), 1);
    assert_eq!(target.connections(), 0);
    log.lock().unwrap().clear();
    let limited_client = origin.client().url_limits(UrlLimits::new().max_length(10)).hop_headers(noting(&log, |_| Ok(vec![])));
    assert!(limited(&limited_client.get(&origin.url("/")).unwrap_err()));
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn a_header_from_the_hook_that_is_not_one_is_an_error_and_never_says_its_value() {
    let server = TestServer::start(|_| ok("hello"));
    for (name, value) in [
        ("Bad Name", "ok"),
        ("", "ok"),
        ("X-Ok", "secret\r\nX-Injected: yes"),
        ("X-Ok", "secret\nX-Injected: yes"),
        ("X-Ok", "se\0cret"),
        ("Host", "evil.example"),
        ("host", "evil.example"),
        ("Connection", "upgrade"),
        ("Content-Length", "0"),
    ] {
        let (n, v) = (name.to_string(), value.to_string());
        let client = server.client().hop_headers(move |_| Ok(vec![(n.clone(), v.clone())]));
        let e = client.get(&server.url("/")).unwrap_err();
        assert!(matches!(&e, Error::Http(m) if m.contains("hop hook")), "{name:?}: {e}");
        assert!(!e.to_string().contains("secret") && !e.to_string().contains("evil.example"), "{name:?}: {e}");
    }
    assert_eq!(server.connections(), 0, "nothing was sent");
}

#[test]
fn the_hook_is_asked_once_for_a_hop_that_is_sent_again() {
    // the pooled connection has been closed by the server: the request goes again on a new one, with the same headers and without asking again
    let server = TestServer::start(|_| ok("hello"));
    let log: Log = Default::default();
    let client = server.client().hop_headers(noting(&log, |_| Ok(vec![h("X-Token", "t")])));
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello");
    server.close_all();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello");
    assert_eq!(log.lock().unwrap().len(), 2, "one for each request: {:?}", log.lock().unwrap());
    assert!(server.requests().iter().all(|s| s.header("x-token") == Some("t")));
}

#[test]
fn the_method_the_hook_is_told_is_the_one_the_hop_is_sent_with() {
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()));
    let log: Log = Default::default();
    let client = client.hop_headers(noting(&log, |_| Ok(vec![])));
    for (status, method, sent_as) in [(303, "POST", "GET"), (302, "POST", "GET"), (301, "POST", "GET"), (307, "POST", "POST"), (308, "POST", "POST"), (302, "GET", "GET"), (303, "HEAD", "HEAD")] {
        log.lock().unwrap().clear();
        let mut hop = client.start(method.into(), "https://a.example/start", vec![], b"{}".to_vec()).unwrap();
        assert!(client.follow(&mut hop, status, &[("Location".to_string(), "https://b.example/x".to_string())], &mut 0).unwrap());
        assert_eq!(hop.method, sent_as, "{status} {method}");
        let told = log.lock().unwrap().clone();
        assert_eq!(told[1], format!("1 {sent_as} 443 443 true"), "{status} {method}: {told:?}");
    }
}

#[test]
fn the_async_client_and_the_clones_have_their_hooks_too() {
    let target = TestServer::start(|_| ok("target"));
    let landed = target.url("/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"")));
    let shared = origin.client();
    let a = shared.clone().hop_headers(|_| Ok(vec![h("X-Who", "a")]));
    let b = shared.clone().hop_headers(|_| Ok(vec![h("X-Who", "b")]));
    assert_eq!(block_on(a.clone().into_async().get(&origin.url("/"))).unwrap().text(), "target");
    assert_eq!(target.requests().last().unwrap().header("x-who"), Some("a"));
    assert_eq!(block_on(b.get_async(&origin.url("/"))).unwrap().text(), "target");
    assert_eq!(target.requests().last().unwrap().header("x-who"), Some("b"));
    // the client they came from has none, and a hook can be taken away
    shared.get(&origin.url("/")).unwrap();
    assert_eq!(target.requests().last().unwrap().header("x-who"), None);
    a.no_hop_headers().get(&origin.url("/")).unwrap();
    assert_eq!(target.requests().last().unwrap().header("x-who"), None);
    // (an error of the hook in the async client's first hop, too)
    let refusing = shared.clone().hop_headers(|_| Err(Error::Http("no".into()))).into_async();
    assert!(block_on(refusing.get(&origin.url("/"))).is_err());
}

// ------------------------------------------------------------------------------------------------ a refusal is its own kind of error

fn refusal(e: Error) -> Refused {
    match e {
        Error::Refused(r) => r,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[test]
fn a_refusal_is_not_a_network_error_and_says_which_hop_and_which_rule_refused() {
    let c = TestServer::start(|_| ok("end"));
    let c_url = as_host(&c, "localhost", "/c");
    let b = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {c_url}")], b"")));
    let b_url = b.url("/b");
    let a = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {b_url}")], b"")));
    // the host rule, at the third hop of a chain of redirects (the request itself is hop 0)
    let client = a.client().allowed_hosts(local(&["127.0.0.1"]));
    let r = refusal(client.get(&a.url("/a")).unwrap_err());
    assert_eq!((r.hop, r.by, r.is_redirect()), (2, RefusedBy::HostRule, true));
    assert!(r.reason.starts_with("host not allowed: localhost"), "{}", r.reason);
    assert_eq!(Error::Refused(r).to_string(), format!("redirect 2 refused: host not allowed: localhost:{} is not in the allowed hosts", port_of(&c)));
    // the request itself
    let r = refusal(a.client().allowed_hosts(rules(&["api.example.com"])).get(&a.url("/a")).unwrap_err());
    assert_eq!((r.hop, r.by, r.is_redirect()), (0, RefusedBy::HostRule, false));
    assert!(Error::Refused(r).to_string().starts_with("request refused: host not allowed"));
    // a limit on the URL: of the request itself, and (below) of a redirect
    let r = refusal(a.client().url_limits(UrlLimits::new().max_length(a.url("/a").len() - 1)).get(&a.url("/a")).unwrap_err());
    assert_eq!((r.hop, r.by), (0, RefusedBy::UrlLimit), "{r:?}");
    let creds = TestServer::start(|_| ok("x"));
    let to_creds = creds.url("/").replace("://", "://user:pw@");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {to_creds}")], b"")));
    let r = refusal(origin.client().url_limits(UrlLimits::new().refuse_credentials(true)).get(&origin.url("/")).unwrap_err());
    assert_eq!((r.hop, r.by), (1, RefusedBy::UrlLimit));
    assert_eq!(creds.connections(), 0);
    // the scheme: plain http where it is not allowed (the request itself), and a redirect from https to plain http
    let plain = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()));
    let before = a.connections();
    let r = refusal(plain.get(&a.url("/a")).unwrap_err());
    assert_eq!((r.hop, r.by), (0, RefusedBy::Scheme));
    assert_eq!(a.connections(), before, "nothing was connected to");
    let mut hop = plain.start("GET".into(), "https://a.example/", vec![], vec![]).unwrap();
    let r = refusal(plain.follow(&mut hop, 302, &[("Location".to_string(), "http://a.example/".to_string())], &mut 0).unwrap_err());
    assert_eq!((r.hop, r.by), (1, RefusedBy::Scheme));
    // a hook that says no, whatever kind of error it says it with
    for (given, reason) in [(Error::Http("no token for this host".into()), "no token for this host"), (Error::Io(std::io::Error::other("broken")), "broken"), (Error::Tls("t".into()), "t")] {
        let given = std::sync::Mutex::new(Some(given));
        let client = a.client().hop_headers(move |_| Err(given.lock().unwrap().take().unwrap_or_else(|| Error::Http("again".into()))));
        let r = refusal(client.get(&a.url("/a")).unwrap_err());
        assert_eq!((r.hop, r.by), (0, RefusedBy::Hook));
        assert!(r.reason.contains(reason), "{r:?}");
    }
    // (one the hook made itself, with a hop of its own choosing, is the hop it is: the client knows which it was)
    let client = a.client().hop_headers(|info| Err(Error::Refused(Refused { hop: 99, by: RefusedBy::Hook, reason: format!("not {}", info.url.host) })));
    let r = refusal(client.get(&a.url("/a")).unwrap_err());
    assert_eq!((r.hop, r.reason.as_str()), (0, "not 127.0.0.1"));
    // and a network failure is not a refusal
    let closed = TestServer::start(|_| ok("x"));
    let url = closed.url("/");
    drop(closed);
    let e = a.client().get(&url).unwrap_err();
    assert!(!matches!(e, Error::Refused(_)), "{e}");
}

#[test]
fn what_a_refusal_says_names_the_host_and_never_the_path_a_credential_or_a_value() {
    let client = marketplace().hop_headers(|_| Err(Error::Http("no token for this host".into())));
    // (the hook is asked last: these are refused by the rule or a limit before it is)
    for url in [
        "https://evil.example.org/private-path?token=abc123",
        "https://user:hunter2@x.gallerycdn.vsassets.io/private-path?token=abc123",
        "http://x.gallerycdn.vsassets.io/private-path?token=abc123",
        "https://x.gallerycdn.vsassets.io:8443/private-path?token=abc123",
    ] {
        let e = first(&client, url).unwrap_err();
        let said = format!("{e} {e:?}");
        for secret in ["private-path", "token=abc123", "hunter2", "abc123"] {
            assert!(!said.contains(secret), "{url}: {said}");
        }
    }
    // a long URL is refused with its length and not its text
    let long = format!("https://x.gallerycdn.vsassets.io/{}", "k".repeat(3000));
    let said = format!("{:?}", first(&client, &long).unwrap_err());
    assert!(said.contains("3033") && !said.contains("kkkk"), "{said}");
}

#[test]
fn a_request_can_require_tls13_and_cannot_allow_tls12_on_a_client_that_requires_tls13() {
    use crate::tls::TlsVersion::{Tls12, Tls13};
    let config = crate::tls::ClientConfig::new(crate::x509::TrustStore::empty());
    let hop = |min_tls| Hop { method: "GET".into(), url: Url::parse("https://example.com/").unwrap(), headers: vec![], body: vec![], granted: vec![], index: 0, decode: None, min_tls, running: None };
    let lenient = crate::Client::with_tls_config(config.clone());
    let strict = crate::Client::with_tls_config(config).min_tls_version(Tls13);
    let cases = [(&lenient, None, Tls12), (&lenient, Some(Tls12), Tls12), (&lenient, Some(Tls13), Tls13), (&strict, None, Tls13), (&strict, Some(Tls12), Tls13), (&strict, Some(Tls13), Tls13)];
    for (client, asked, expected) in cases {
        assert_eq!(client.min_tls_for(&hop(asked)), expected, "client {:?}, request {asked:?}", client.tls.min_version);
        // and the connection it would use is one made under that minimum
        let key = super::pool_key(&hop(asked).url, None, client.min_tls_for(&hop(asked)));
        assert_eq!(key.min_tls, expected);
    }
}

// ------------------------------------------------------------------------------------------------ the hook as a check of each hop

#[test]
fn the_hook_approves_or_refuses_a_hop_on_any_ground() {
    let target = TestServer::start(|_| ok("target"));
    let (to_admin, to_x) = (target.url("/admin/delete"), target.url("/x"));
    let origin = TestServer::start(move |s| {
        let to = match s.path() {
            "/to-admin" => to_admin.clone(),
            "/chain" => "/chain2".to_string(),
            _ => to_x.clone(),
        };
        Reply::Send(response(302, &[&format!("Location: {to}")], b""))
    });
    // a caller that goes to no path under /admin, follows one redirect at most, never sends a DELETE, and gives no header at all
    let checking = |info: &HopInfo<'_>| -> Result<Vec<(String, String)>, Error> {
        if info.url.path_and_query.starts_with("/admin") {
            return Err(Error::Http("not a path this caller goes to".into()));
        }
        if info.hop > 1 {
            return Err(Error::Http("more than one redirect".into()));
        }
        if info.method == "DELETE" {
            return Err(Error::Http("this caller deletes nothing".into()));
        }
        Ok(vec![])
    };
    let client = origin.client().hop_headers(checking);
    let at = |path: &str| origin.url(path);
    // approved: one redirect, to a path it goes to
    assert_eq!(client.get(&at("/to-x")).unwrap().text(), "target");
    let reached = target.connections();
    // refused, each with the hop it was and the hook's words, and nothing sent to where it would have gone
    for (method, path, hop, why) in [("GET", "/to-admin", 1, "not a path"), ("GET", "/chain", 2, "more than one"), ("DELETE", "/to-x", 0, "deletes nothing")] {
        let before = origin.connections();
        let r = refusal(client.request(method, &at(path)).send().unwrap_err());
        assert_eq!((r.hop, r.by), (hop, RefusedBy::Hook), "{method} {path}");
        assert!(r.reason.contains(why), "{method} {path}: {}", r.reason);
        if hop == 0 {
            assert_eq!(origin.connections(), before, "{method} {path}: the first hop was refused, and nothing connected");
        }
    }
    assert_eq!(target.connections(), reached, "the target was not reached by a refused hop");
    // a caller that stays on the origin it was sent to: the hop that crosses to another is refused, the one that does not is not
    let same_origin = origin.client().hop_headers(|info| if info.crosses_origin() { Err(Error::Http("another origin".into())) } else { Ok(vec![]) });
    let r = refusal(same_origin.get(&at("/chain")).unwrap_err());
    assert_eq!((r.hop, r.reason.as_str()), (2, "another origin"));
    assert_eq!(target.connections(), reached);
    // (and the async client asks it the same)
    let r = refusal(block_on(client.clone().into_async().get(&at("/to-admin"))).unwrap_err());
    assert_eq!((r.hop, r.by), (1, RefusedBy::Hook));
    assert_eq!(target.connections(), reached);
}

// ------------------------------------------------------------------------------------------------ what one request sets for itself

#[test]
fn a_request_has_a_rule_about_hosts_of_its_own_which_holds_with_the_clients() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |s| if s.path() == "/ok" { ok("fine") } else { Reply::Send(response(302, &[&format!("Location: {landed}")], b"")) });
    let only_origin = || local(&["127.0.0.1"]);
    // a client with no rule: the request's alone, at every hop
    let client = origin.client();
    assert_eq!(client.request("GET", &origin.url("/ok")).allowed_hosts(only_origin()).send().unwrap().text(), "fine");
    let r = refusal(client.request("GET", &origin.url("/redirect")).allowed_hosts(only_origin()).send().unwrap_err());
    assert_eq!((r.hop, r.by), (1, RefusedBy::HostRule));
    assert!(r.reason.starts_with("host not allowed: localhost") && r.reason.contains("request's allowed hosts"), "{}", r.reason);
    assert_eq!(target.connections(), 0);
    // the request that comes after it, with no rule, is not held by it
    assert_eq!(client.get(&origin.url("/redirect")).unwrap().text(), "target");
    // on a client with a rule, the request's narrows it and cannot widen it
    let wide = origin.client().allowed_hosts(local(&["127.0.0.1", "localhost"]));
    assert_eq!(wide.get(&origin.url("/redirect")).unwrap().text(), "target");
    assert!(refused(&wide.request("GET", &origin.url("/redirect")).allowed_hosts(only_origin()).send().unwrap_err()));
    let narrow = origin.client().allowed_hosts(only_origin());
    let e = narrow.request("GET", &origin.url("/redirect")).allowed_hosts(local(&["127.0.0.1", "localhost"])).send().unwrap_err();
    assert!(refused(&e) && e.to_string().contains("is not in the allowed hosts"), "{e}");
    // streamed, the blocking client's futures, and the async client
    let before = target.connections();
    let at = origin.url("/redirect");
    assert!(refused(&client.request("GET", &at).allowed_hosts(only_origin()).send_stream().err().unwrap()));
    assert!(refused(&block_on(client.request("GET", &at).allowed_hosts(only_origin()).send_async()).unwrap_err()));
    let a = origin.client().into_async();
    assert!(refused(&block_on(a.request("GET", &at).allowed_hosts(only_origin()).send()).unwrap_err()));
    assert!(refused(&block_on(a.request("GET", &at).allowed_hosts(only_origin()).send_stream()).err().unwrap()));
    assert_eq!(target.connections(), before, "no request that had the rule reached the target");
    assert_eq!(block_on(a.get(&at)).unwrap().text(), "target");
    // the rule as it is made is the tight one: the test server is not on the default port
    assert!(refused(&client.request("GET", &origin.url("/ok")).allowed_hosts(rules(&["127.0.0.1"])).send().unwrap_err()));
}

#[test]
fn a_request_has_time_limits_of_its_own_also_on_a_connection_from_the_pool() {
    use std::time::{Duration, Instant};
    let server = TestServer::start(|s| match s.path() {
        "/slow" => Reply::Run(Box::new(|w| {
            std::thread::sleep(Duration::from_millis(900));
            let _ = w.write_all(&response(200, &[], b"slow"));
            true
        })),
        _ => ok("hello"),
    });
    // (the client's limit is five seconds)
    let client = server.client();
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello");
    // the pooled connection was made under the client's limit: the request's is the one that holds on it
    let started = Instant::now();
    let e = client.request("GET", &server.url("/slow")).timeout(Duration::from_millis(200)).send().unwrap_err();
    assert!(started.elapsed() < Duration::from_millis(700), "{:?}: {e}", started.elapsed());
    assert_eq!(server.connections(), 1, "it went on the connection from the pool");
    // the next request has the client's limit again
    assert_eq!(client.get(&server.url("/slow")).unwrap().text(), "slow");
    // a total limit of its own, in place of the client's: shorter, and longer
    let started = Instant::now();
    assert!(client.request("GET", &server.url("/slow")).total_timeout(Duration::from_millis(200)).send().is_err());
    assert!(started.elapsed() < Duration::from_millis(700), "{:?}", started.elapsed());
    let hurried = server.client().total_timeout(Duration::from_millis(200));
    assert!(hurried.get(&server.url("/slow")).is_err());
    assert_eq!(hurried.request("GET", &server.url("/slow")).total_timeout(Duration::from_secs(10)).send().unwrap().text(), "slow");
    // the async client: its own pool, the same rule
    let a = server.client().into_async();
    assert_eq!(block_on(a.get(&server.url("/"))).unwrap().text(), "hello");
    let started = Instant::now();
    assert!(block_on(a.request("GET", &server.url("/slow")).timeout(Duration::from_millis(200)).send()).is_err());
    assert!(started.elapsed() < Duration::from_millis(700), "{:?}", started.elapsed());
    assert_eq!(block_on(a.get(&server.url("/slow"))).unwrap().text(), "slow");
}

#[test]
fn a_request_has_a_redirect_limit_of_its_own() {
    let server = TestServer::start(|s| match s.path().strip_prefix("/hop").and_then(|n| n.parse::<usize>().ok()) {
        Some(0) => ok("end"),
        Some(n) => Reply::Send(response(302, &[&format!("Location: /hop{}", n - 1)], b"")),
        None => ok("hello"),
    });
    let client = server.client().max_redirects(1);
    assert!(client.get(&server.url("/hop3")).unwrap_err().to_string().contains("too many redirects (limit 1)"));
    assert_eq!(client.request("GET", &server.url("/hop3")).max_redirects(3).send().unwrap().text(), "end");
    assert!(client.request("GET", &server.url("/hop3")).max_redirects(2).send().unwrap_err().to_string().contains("limit 2"));
    // none at all: the first redirect is the end of it, and nothing is sent where it points
    let before = server.requests().len();
    assert!(server.client().request("GET", &server.url("/hop1")).max_redirects(0).send().is_err());
    assert_eq!(server.requests().len(), before + 1);
    // the async client
    let a = client.clone().into_async();
    assert_eq!(block_on(a.request("GET", &server.url("/hop3")).max_redirects(3).send()).unwrap().text(), "end");
    assert!(block_on(a.get(&server.url("/hop3"))).is_err());
}

#[test]
fn an_http3_alternative_that_the_requests_rule_does_not_allow_is_not_dialed() {
    // the alternatives an origin offers are shared by the clones and by the requests, whose rules differ: the one a request's rule does
    // not allow is not dialed for it (the request goes over TCP), and the origin is not marked as unreachable for the others
    let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let alt_port = closed.local_addr().unwrap().port();
    drop(closed);
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .http3(true)
        .connect_timeout(std::time::Duration::from_secs(2))
        .allowed_hosts(rules(&["origin.example", &format!("127.0.0.1:{alt_port}")]));
    let url = Url::parse("https://origin.example/").unwrap();
    let key = super::pool_key(&url, None, crate::tls::TlsVersion::Tls12);
    let registry = client.h3.as_ref().unwrap().registry.clone();
    registry.learn(&key, [format!(r#"h3="127.0.0.1:{alt_port}""#).as_str()].into_iter(), &|_, _| true);
    let hop = Hop { method: "GET".into(), url, headers: vec![], body: vec![], granted: vec![], index: 0, decode: None, min_tls: None, running: None };
    let step = |c: &crate::Client| {
        let mut tries = super::H3Tries { attempts: 0, repeat_allowed: true };
        matches!(c.h3_step(&hop, &[], &key, None, super::wire::Limits::default(), true, &mut tries), Ok(super::H3Step::Skip))
    };
    // a request whose rule names the origin and not the alternative: over TCP, and no dial was made (nothing failed)
    let mut opts = super::RequestOpts { hosts: Some(Arc::new(rules(&["origin.example"]))), ..Default::default() };
    let narrowed = client.narrowed(&mut opts).unwrap();
    assert!(step(&narrowed));
    assert!(!registry.standing(&key).0, "the origin was not left to TCP: nothing was dialed");
    // the client's own rule allows it: it is dialed (nothing answers there, so the origin is then left to TCP for a while)
    assert!(step(&client));
    assert!(registry.standing(&key).0, "the alternative was dialed and failed");
}
