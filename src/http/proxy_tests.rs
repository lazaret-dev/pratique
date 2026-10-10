//! Which proxy a request goes through: the one the client was given, the one the environment names, the one the operating system is set
//! to use (when the environment says nothing), and whether the rule of [`Client::allowed_proxies`] lets it be used at all.

use super::testserver::*;
use super::{Client, HostRules, Proxy, SettingsSource, SystemProxy, PROXY_ENV};
use crate::asyncio::block_on;
use crate::error::{Error, RefusedBy};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A proxy that notes the request line of each connection (`CONNECT host:port HTTP/1.1`) and says no to it.
struct FakeProxy {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeProxy {
    fn start() -> FakeProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let noted = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
                noted.lock().unwrap().push(line.trim_end().to_string());
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            }
        });
        FakeProxy { port, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn proxy(&self) -> Proxy {
        Proxy { host: "127.0.0.1".into(), port: self.port, auth: None }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn client() -> Client {
    Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty())).timeout(Duration::from_secs(5))
}

/// Runs `f` with `vars` as the whole environment that proxies are chosen with (on this thread).
fn with_env<T>(vars: &[(&'static str, &str)], f: impl FnOnce() -> T) -> T {
    PROXY_ENV.with(|e| *e.borrow_mut() = Some(vars.iter().map(|(n, v)| (*n, v.to_string())).collect()));
    let out = f();
    PROXY_ENV.with(|e| *e.borrow_mut() = None);
    out
}

/// macOS's settings with a secure web proxy at `proxy`, and `*.corp.example` going direct.
fn system(proxy: Proxy) -> SystemProxy {
    SystemProxy { source: Some(SettingsSource::MacOs), https: Some(proxy), bypass: vec!["*.corp.example".into()], ..SystemProxy::default() }
}

fn at(p: Option<Proxy>) -> Option<String> {
    p.map(|p| format!("{}:{}", p.host, p.port))
}

#[test]
fn the_environment_comes_first_and_the_systems_settings_when_it_says_nothing() {
    let sys = Proxy { host: "sys.example".into(), port: 3128, auth: None };
    let c = client().with_system_proxy(system(sys));
    let via = |vars: &[(&'static str, &str)], url: &str| with_env(vars, || at(c.proxy_for_url(url).unwrap()));
    let system_one = Some("sys.example:3128".to_string());
    let env_one = Some("env.example:8080".to_string());
    // the environment says nothing: the system's proxy, and its list of hosts that go direct (and loopback, and plain http)
    assert_eq!(via(&[], "https://pypi.org/simple/"), system_one);
    assert_eq!(via(&[], "https://a.corp.example/"), None);
    assert_eq!(via(&[], "https://localhost:8443/"), None);
    assert_eq!(via(&[], "http://pypi.org/"), None);
    // (a variable that is set and empty says nothing, as in Python)
    assert_eq!(via(&[("HTTPS_PROXY", ""), ("NO_PROXY", " ")], "https://pypi.org/"), system_one);
    // it names a proxy for https: that one, and the system's list is not looked at (NO_PROXY is the list then)
    assert_eq!(via(&[("HTTPS_PROXY", "http://env.example:8080")], "https://pypi.org/"), env_one);
    assert_eq!(via(&[("https_proxy", "http://env.example:8080")], "https://a.corp.example/"), env_one);
    assert_eq!(via(&[("HTTPS_PROXY", "http://env.example:8080"), ("no_proxy", "pypi.org")], "https://pypi.org/"), None);
    // it says something about proxies and names none for https: direct, and not the system's (Python's `getproxies` keeps this order)
    for vars in [&[("NO_PROXY", "localhost")][..], &[("HTTP_PROXY", "http://web.example:80")], &[("ALL_PROXY", "socks5://s.example:1080")], &[("http_proxy", "x")]] {
        assert_eq!(via(vars, "https://pypi.org/"), None, "{vars:?}");
    }
    // a client that reads the environment alone does not look at the system's settings
    let env_only = client().proxy_from_env();
    assert_eq!(with_env(&[], || at(env_only.proxy_for_url("https://pypi.org/").unwrap())), None);
    assert_eq!(with_env(&[("HTTPS_PROXY", "http://env.example:8080")], || at(env_only.proxy_for_url("https://pypi.org/").unwrap())), env_one);
    // a proxy the environment names that cannot be used is an error, not a request sent elsewhere
    assert!(with_env(&[("HTTPS_PROXY", "https://tls.example:443")], || c.proxy_for_url("https://pypi.org/")).is_err());
    // what the client was given is what it says it was given
    assert_eq!(c.system_proxy().unwrap().https.as_ref().unwrap().port, 3128);
    assert!(client().proxy_from_env().system_proxy().is_none());
}

#[test]
fn a_request_goes_through_the_systems_proxy_when_the_environment_says_nothing() {
    let system_proxy = FakeProxy::start();
    let env_proxy = FakeProxy::start();
    let c = client().with_system_proxy(system(system_proxy.proxy()));
    let e = with_env(&[], || c.get("https://pypi.test/simple/").unwrap_err());
    assert!(e.to_string().contains("proxy refused CONNECT"), "{e}");
    assert_eq!(system_proxy.seen(), ["CONNECT pypi.test:443 HTTP/1.1"]);
    // the environment's, when it names one
    let named = env_proxy.url();
    assert!(with_env(&[("HTTPS_PROXY", &named)], || c.get("https://pypi.test/simple/")).is_err());
    assert_eq!((system_proxy.seen().len(), env_proxy.seen()), (1, vec!["CONNECT pypi.test:443 HTTP/1.1".to_string()]));
    // a host the system's list sends direct is not sent to the proxy (here nothing listens where it goes)
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let direct = c.clone().resolve_host("build.corp.example", &["127.0.0.1".parse().unwrap()]);
    let e = with_env(&[], || direct.get(&format!("https://build.corp.example:{port}/")).unwrap_err());
    assert!(!e.to_string().contains("proxy"), "{e}");
    assert_eq!(system_proxy.seen().len(), 1);
    // the async client chooses the same way
    let e = with_env(&[], || block_on(c.clone().into_async().get("https://files.test/x")).unwrap_err());
    assert!(e.to_string().contains("proxy refused CONNECT"), "{e}");
    assert_eq!(system_proxy.seen().last().unwrap(), "CONNECT files.test:443 HTTP/1.1");
}

fn refused_by_rule(e: &Error, hop: usize) -> bool {
    matches!(e, Error::Refused(r) if r.by == RefusedBy::ProxyRule && r.hop == hop && r.reason.starts_with("proxy not allowed: 127.0.0.1:"))
}

#[test]
fn a_proxy_the_rule_does_not_name_is_not_used_and_the_request_is_not_sent_direct_instead() {
    let fake = FakeProxy::start();
    let rule = |entries: &[&str]| HostRules::new(entries.iter().copied()).unwrap();
    let named = client().proxy(&fake.url()).unwrap();
    // not in the rule: refused before anything connects to it (and not sent direct: the error is the refusal)
    let other = named.clone().allowed_proxies(rule(&["proxy.corp.example:3128"]));
    let e = other.get("https://pypi.test/").unwrap_err();
    assert!(refused_by_rule(&e, 0), "{e}");
    assert!(e.to_string().contains(&format!("127.0.0.1:{} is not in the allowed proxies", fake.port)), "{e}");
    assert!(refused_by_rule(&other.proxy_for_url("https://pypi.test/").unwrap_err(), 0));
    assert!(fake.seen().is_empty());
    // in the rule, with its port: used
    let allowed = named.clone().allowed_proxies(rule(&[&format!("127.0.0.1:{}", fake.port)]));
    assert!(allowed.get("https://pypi.test/").unwrap_err().to_string().contains("proxy refused CONNECT"));
    assert_eq!(fake.seen().len(), 1);
    // an entry without a port is the default port of a proxy (8080) under the rule as it is made, and any port with the switch off
    assert!(refused_by_rule(&named.clone().allowed_proxies(rule(&["127.0.0.1"])).get("https://pypi.test/").unwrap_err(), 0));
    assert!(named.clone().allowed_proxies(rule(&["127.0.0.1"]).default_port_only(false)).proxy_for_url("https://pypi.test/").unwrap().is_some());
    // however the proxy was named: by the environment, by the system's settings
    let none = rule(&["proxy.corp.example:3128"]);
    let from_env = client().proxy_from_env().allowed_proxies(none.clone());
    assert!(refused_by_rule(&with_env(&[("HTTPS_PROXY", &fake.url())], || from_env.get("https://pypi.test/")).unwrap_err(), 0));
    let from_system = client().with_system_proxy(system(fake.proxy())).allowed_proxies(none.clone());
    assert!(refused_by_rule(&with_env(&[], || from_system.get("https://pypi.test/")).unwrap_err(), 0));
    // the async client, and a tunnel of the scanning proxy's
    assert!(refused_by_rule(&block_on(other.clone().into_async().get("https://pypi.test/")).unwrap_err(), 0));
    assert!(refused_by_rule(&other.tunnel("pypi.test", 443).unwrap_err(), 0));
    assert_eq!(fake.seen().len(), 1, "nothing more reached the proxy");
    // a request that goes direct is not affected (plain http has no proxy here), and a redirect from it to https is refused at its hop
    let to_https = TestServer::start(|s| if s.path() == "/go" { Reply::Send(response(302, &["Location: https://pypi.test/x"], b"")) } else { ok("direct") });
    let direct = other.clone().allow_insecure_http(true);
    assert_eq!(direct.get(&to_https.url("/")).unwrap().text(), "direct");
    assert!(refused_by_rule(&direct.get(&to_https.url("/go")).unwrap_err(), 1));
    // and with the rule taken away, any proxy goes again
    assert!(other.any_proxy().proxy_for_url("https://pypi.test/").unwrap().is_some());
}
