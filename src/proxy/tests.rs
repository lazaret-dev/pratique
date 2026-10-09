//! The scanning proxy (B-78) between this crate's client and a registry this crate's server plays: the CA and its name
//! constraint (as this crate's verifier and OpenSSL read it), requests relayed both ways over HTTP/1.1 and HTTP/2, the
//! scanner refusing, inspecting (in memory and in a file) and answering in the host's place, bodies too large to inspect
//! never passed on, a host whose certificate does not verify, tunnels, refusals and credentials, what may be asked
//! inside a tunnel, plain `http://` forwarding, and the files and variables that point programs at the proxy.

use super::*;
use crate::http::server::{Request, Response, ServerBuilder};
use crate::tls::pki::TestPki;
use crate::tls::server::ServerConfig;
use crate::tls::{ClientConfig, TlsStream};
use crate::x509::{Certificate, TrustStore};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// A gzip stream of `data` in one stored block (no compression: enough for a body to decode).
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1];
    let len = data.len() as u16;
    out.extend(len.to_le_bytes());
    out.extend((!len).to_le_bytes());
    out.extend(data);
    out.extend(crate::inflate::crc32(0, data).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

/// The registry: `registry.test` and `other.test` on one TLS server of its own PKI.
struct Registry {
    _server: Server,
    pki: TestPki,
    port: u16,
    hits: Arc<AtomicUsize>,
}

fn registry_handler(hits: Arc<AtomicUsize>) -> impl Fn(Request) -> Response + Send + Sync + 'static {
    move |mut req: Request| {
        hits.fetch_add(1, Ordering::SeqCst);
        let path = req.path().to_string();
        match path.as_str() {
            "/left-pad" | "/evil" => Response::bytes(200, "application/json", br#"{"name":"left-pad"}"#.to_vec()),
            "/left-pad/-/left-pad-1.3.0.tgz" => Response::bytes(200, "application/octet-stream", b"TARBALL".to_vec()),
            "/bad/-/bad-1.0.0.tgz" => Response::bytes(200, "application/octet-stream", b"a tarball with MALWARE inside".to_vec()),
            "/headers" => {
                let text: String = req.headers().iter().map(|(n, v)| format!("{n}: {v}\n")).collect();
                Response::text(200, text)
            }
            "/echo" => {
                let body = req.read_body(1 << 20).unwrap_or_default();
                Response::bytes(200, "application/octet-stream", body).with_header("x-method", req.method())
            }
            "/redirect" => Response::redirect(302, "/left-pad"),
            "/gz" => Response::bytes(200, "application/json", gzip_stored(br#"{"hello":"world"}"#)).with_header("content-encoding", "gzip"),
            "/chunked" => Response::stream(200, |w| {
                for i in 0..50 {
                    w.write_all(&pattern(1000 + i))?;
                }
                Ok(())
            }),
            p if p.starts_with("/size/") => {
                let n: usize = p["/size/".len()..].parse().unwrap_or(0);
                Response::reader(200, std::io::Cursor::new(pattern(n)), Some(n as u64))
            }
            _ => Response::text(404, "no such thing\n"),
        }
    }
}

fn registry() -> Registry {
    let pki = TestPki::new(&["registry.test", "other.test"]).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let tls = Arc::new(ServerConfig::from_pki(&pki).with_alpn(&["h2", "http/1.1"]));
    let server = ServerBuilder::new(registry_handler(hits.clone())).tls("127.0.0.1:0", tls).start().unwrap();
    let port = server.local_addrs()[0].port();
    Registry { _server: server, pki, port, hits }
}

/// The client the proxy reaches the registry with: it trusts the registry's PKI and knows where its names are.
fn upstream_client(trust: TrustStore) -> Client {
    Client::with_tls_config(ClientConfig::new(trust)).resolve_host("registry.test", &[LOCAL]).resolve_host("other.test", &[LOCAL])
}

struct Running {
    proxy: Proxy,
    server: Server,
    events: Arc<Mutex<Vec<String>>>,
}

impl Running {
    fn url(&self) -> String {
        format!("http://{}", self.server.local_addrs()[0])
    }

    /// A client that goes through the proxy and trusts its CA alone.
    fn client(&self) -> Client {
        let mut trust = TrustStore::empty();
        trust.add_der(self.proxy.ca().certificate()).unwrap();
        Client::with_tls_config(ClientConfig::new(trust)).proxy(&self.url()).unwrap().follow_redirects(false)
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn start(reg: &Registry, scanner: impl Scanner, configure: impl FnOnce(ProxyBuilder) -> ProxyBuilder) -> Running {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let builder = Proxy::builder(scanner)
        .intercept(&["registry.test"])
        .ports(&[443, reg.port])
        .client(upstream_client(reg.pki.trust_store()))
        .events(move |e| log.lock().unwrap().push(format!("{:?} {} {} {} {}", e.action, e.method, e.url, e.status, e.detail)));
    let proxy = configure(builder).build().unwrap();
    let server = proxy.start("127.0.0.1:0").unwrap();
    Running { proxy, server, events }
}

/// What a scanner saw, and the rules of the tests' scanner: refuse the package `evil`; read package files, `/gz` and
/// `/size/N` whole; refuse a body with MALWARE in it; answer `/gz` itself with what it decoded.
#[derive(Default)]
struct Rules {
    seen: Mutex<Vec<Exchange>>,
    sizes: Mutex<Vec<(u64, bool)>>,
}

impl Scanner for Arc<Rules> {
    fn request(&self, ex: &Exchange) -> Decision {
        self.seen.lock().unwrap().push(ex.clone());
        match ex.target.as_str() {
            "/evil" => Decision::Block("the package evil".into()),
            _ => Decision::Allow,
        }
    }
    fn response(&self, ex: &Exchange, _up: &Upstream) -> BodyAction {
        // (the registry here is not one `registry` knows, so its files are known by npm's `/-/`)
        if ex.target.contains("/-/") || ex.target == "/gz" || ex.target.starts_with("/size/") {
            BodyAction::Inspect
        } else {
            BodyAction::Pass
        }
    }
    fn inspect(&self, ex: &Exchange, up: &Upstream, body: &Inspected) -> Decision {
        let mut all = Vec::new();
        body.open().unwrap().read_to_end(&mut all).unwrap();
        self.sizes.lock().unwrap().push((body.len(), body.bytes().is_some()));
        assert_eq!(all.len() as u64, body.len());
        if all.windows(7).any(|w| w == b"MALWARE") {
            return Decision::Block("MALWARE found".into());
        }
        if ex.target == "/gz" {
            assert_eq!(up.header("content-encoding"), Some("gzip"));
            let plain = body.decoded(1 << 20).unwrap();
            return Decision::Respond(Response::text(200, format!("rewritten: {}", String::from_utf8_lossy(&plain))));
        }
        Decision::Allow
    }
}

#[test]
fn the_ca_is_limited_to_the_names_it_is_for() {
    let ca = ProxyCa::new("test CA", &["registry.test", "*.example.test", "a.example.test"], Duration::from_secs(3600)).unwrap();
    assert_eq!(ca.permitted(), ["registry.test", "example.test"], "a name already covered is not repeated");
    let cert = Certificate::from_der(ca.certificate()).unwrap();
    assert!(cert.is_ca && cert.path_len == Some(0));
    assert!((ca.not_after() - crate::sys::now_unix() - 3600).abs() < 5);
    assert!(ca.permits("registry.test") && ca.permits("x.example.test") && ca.permits("REGISTRY.test."));
    assert!(!ca.permits("other.test") && !ca.permits("notexample.test") && !ca.permits("127.0.0.1"));
    assert!(ca.leaf("other.test").is_err());
    let leaf = ca.leaf("registry.test").unwrap();
    assert!(Arc::ptr_eq(&leaf, &ca.leaf("Registry.Test").unwrap()), "made once, then kept");
    let mut trust = TrustStore::empty();
    trust.add_der(ca.certificate()).unwrap();
    let now = crate::sys::now_unix();
    assert!(trust.verify_server_chain(leaf.chain(), "registry.test", now).is_ok());
    // a leaf for a name outside the constraint, which the proxy never makes: this crate's verifier refuses it
    let evil = ca.issue_unchecked("evil.test");
    let err = trust.verify_server_chain(std::slice::from_ref(&evil), "evil.test", now).unwrap_err().to_string();
    assert!(err.to_lowercase().contains("constraint"), "{err}");
    for bad in [&[][..], &["127.0.0.1"][..], &["not a name"][..], &["*"][..]] {
        assert!(ProxyCa::new("x", bad, Duration::from_secs(60)).is_err(), "{bad:?}");
    }
    // and OpenSSL, when it is here
    if std::process::Command::new("openssl").arg("version").output().is_ok() {
        let dir = std::env::temp_dir().join(format!("pratique-proxy-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(dir.join("leaf.pem"), super::ca::pem("CERTIFICATE", &leaf.chain()[0])).unwrap();
        std::fs::write(dir.join("evil.pem"), super::ca::pem("CERTIFICATE", &evil)).unwrap();
        let verify = |file: &str, name: &str| {
            let out = std::process::Command::new("openssl")
                .args(["verify", "-purpose", "sslserver", "-verify_hostname", name, "-CAfile"])
                .arg(dir.join("ca.pem"))
                .arg(dir.join(file))
                .output()
                .unwrap();
            (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
        };
        let (ok, text) = verify("leaf.pem", "registry.test");
        assert!(ok, "{text}");
        let (ok, text) = verify("evil.pem", "evil.test");
        assert!(!ok && text.contains("permitted subtree violation"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn requests_go_through_and_come_back_as_the_host_sent_them() {
    let reg = registry();
    let p = start(&reg, NoScan, |b| b);
    let c = p.client();
    let base = format!("https://registry.test:{}", reg.port);
    let r = c.get(&format!("{base}/left-pad")).unwrap();
    assert_eq!((r.status, r.text().as_str()), (200, r#"{"name":"left-pad"}"#));
    let r = c.request("GET", &format!("{base}/headers")).header("user-agent", "npm/10.9.4").header("x-test", "1").send().unwrap();
    let text = r.text();
    assert!(text.contains("user-agent: npm/10.9.4\n") && text.contains("x-test: 1\n"), "{text}");
    let r = c.request("PUT", &format!("{base}/echo")).body(pattern(100_000)).send().unwrap();
    assert_eq!((r.body.len(), r.header("x-method")), (100_000, Some("PUT")));
    assert_eq!(r.body, pattern(100_000));
    // a redirect is the client's to follow
    let r = c.get(&format!("{base}/redirect")).unwrap();
    assert_eq!((r.status, r.header("location")), (302, Some("/left-pad")));
    // bodies of a length and chunked ones, passed on as they come
    let r = c.request("GET", &format!("{base}/size/20000000")).max_body_bytes(1 << 30).send().unwrap();
    assert_eq!(r.body.len(), 20_000_000);
    assert!(r.body == pattern(20_000_000));
    let r = c.get(&format!("{base}/chunked")).unwrap();
    let want: Vec<u8> = (0..50).flat_map(|i| pattern(1000 + i)).collect();
    assert_eq!(r.body, want);
    let r = c.request("HEAD", &format!("{base}/size/12345")).send().unwrap();
    assert_eq!((r.status, r.header("content-length"), r.body.len()), (200, Some("12345"), 0));
    // HTTP/2 inside the tunnel
    let r = p.client().http2(true).get(&format!("{base}/left-pad")).unwrap();
    assert_eq!((r.version, r.status), (crate::http::HttpVersion::Http2, 200));
    let events = p.events();
    assert!(events.iter().any(|e| e.starts_with(&format!("Intercept CONNECT registry.test:{} 200", reg.port))), "{events:?}");
    assert!(events.iter().any(|e| e.starts_with(&format!("Pass GET {base}/left-pad 200"))), "{events:?}");
}

#[test]
fn the_scanner_refuses_inspects_and_answers_in_the_hosts_place() {
    let reg = registry();
    let rules = Arc::new(Rules::default());
    let p = start(&reg, rules.clone(), |b| b);
    let c = p.client();
    let base = format!("https://registry.test:{}", reg.port);
    // refused before it is sent: the registry never hears of it
    let before = reg.hits.load(Ordering::SeqCst);
    let r = c.get(&format!("{base}/evil")).unwrap();
    assert_eq!(r.status, 403);
    assert!(r.text().contains("blocked by the scanning proxy: the package evil"), "{}", r.text());
    assert_eq!(reg.hits.load(Ordering::SeqCst), before);
    // read whole, then passed on, or refused
    let r = c.get(&format!("{base}/left-pad/-/left-pad-1.3.0.tgz")).unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"TARBALL"[..]));
    let r = c.get(&format!("{base}/bad/-/bad-1.0.0.tgz")).unwrap();
    assert_eq!(r.status, 403);
    assert!(r.text().contains("MALWARE found"));
    // the body as sent (gzip), decoded for the scanner, which answers with what it read
    let r = c.request("GET", &format!("{base}/gz")).header("accept-encoding", "br, gzip;q=0.8, zstd").send().unwrap();
    assert_eq!(r.text(), r#"rewritten: {"hello":"world"}"#);
    let seen = rules.seen.lock().unwrap();
    let gz = seen.iter().find(|e| e.target == "/gz").unwrap();
    assert_eq!(gz.header("accept-encoding"), Some("gzip;q=0.8"), "only what the scanner can decode is asked for");
    assert_eq!((gz.host.as_str(), gz.port, gz.scheme.as_str(), gz.method.as_str()), ("registry.test", reg.port, "https", "GET"));
    assert_eq!(gz.url(), format!("{base}/gz"));
    assert!(gz.client.is_some_and(|a| a.ip() == LOCAL));
    let events = p.events();
    for want in ["Block GET", "Inspect GET", "Replace GET"] {
        assert!(events.iter().any(|e| e.starts_with(want)), "{want}: {events:?}");
    }
}

#[test]
fn large_bodies_are_inspected_from_a_file_and_too_large_ones_are_never_passed_on() {
    let reg = registry();
    let rules = Arc::new(Rules::default());
    let spool = std::env::temp_dir().join(format!("pratique-proxy-spool-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spool);
    let p = start(&reg, rules.clone(), |b| b.inspect_in_memory(1 << 20).max_inspect(10 << 20).spool_dir(&spool));
    let c = p.client();
    let base = format!("https://registry.test:{}", reg.port);
    let r = c.request("GET", &format!("{base}/size/5000000")).max_body_bytes(1 << 30).send().unwrap();
    assert_eq!(r.status, 200);
    assert!(r.body == pattern(5_000_000));
    let r = c.get(&format!("{base}/size/1000")).unwrap();
    assert_eq!(r.body, pattern(1000));
    assert_eq!(*rules.sizes.lock().unwrap(), [(5_000_000, false), (1000, true)], "in a file past the memory's limit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&spool).unwrap().permissions().mode() & 0o777, 0o700);
    }
    // past the limit: refused, whether the host says its length or not
    let r = c.get(&format!("{base}/size/20000000")).unwrap();
    assert_eq!(r.status, 502);
    assert!(r.text().contains("larger than"), "{}", r.text());
    // nothing is left in the spool
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(std::fs::read_dir(&spool).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&spool);
}

#[test]
fn a_host_whose_certificate_does_not_verify_is_never_passed_on() {
    let reg = registry();
    // the proxy's client trusts another PKI
    let other = TestPki::new(&["registry.test"]).unwrap();
    let p = start(&reg, NoScan, |b| b.client(upstream_client(other.trust_store())));
    let r = p.client().get(&format!("https://registry.test:{}/left-pad", reg.port)).unwrap();
    assert_eq!(r.status, 502);
    assert!(r.text().contains("could not get"), "{}", r.text());
    assert!(p.events().iter().any(|e| e.starts_with("Fail GET")));
}

#[test]
fn other_hosts_are_tunnelled_or_refused_and_credentials_are_asked_for() {
    let reg = registry();
    let p = start(&reg, NoScan, |b| b);
    // a tunnel: TLS from end to end, the registry's own certificate
    let end_to_end = Client::with_tls_config(ClientConfig::new(reg.pki.trust_store())).proxy(&p.url()).unwrap();
    let r = end_to_end.get(&format!("https://other.test:{}/left-pad", reg.port)).unwrap();
    assert_eq!(r.status, 200);
    assert!(p.events().iter().any(|e| e.starts_with(&format!("Tunnel CONNECT other.test:{} 200", reg.port))));
    // a port that is not allowed
    let err = p.client().get("https://registry.test:8443/left-pad").unwrap_err().to_string();
    assert!(err.contains("403"), "{err}");
    // a proxy that tunnels nothing
    let strict = start(&reg, NoScan, |b| b.others(Others::Refuse));
    let err = Client::with_tls_config(ClientConfig::new(reg.pki.trust_store())).proxy(&strict.url()).unwrap().get(&format!("https://other.test:{}/", reg.port)).unwrap_err().to_string();
    assert!(err.contains("403"), "{err}");
    // credentials
    let locked = start(&reg, NoScan, |b| b.credentials("lazaret", "s3cret:x"));
    let err = locked.client().get(&format!("https://registry.test:{}/left-pad", reg.port)).unwrap_err().to_string();
    assert!(err.contains("407"), "{err}");
    let mut trust = TrustStore::empty();
    trust.add_der(locked.proxy.ca().certificate()).unwrap();
    let addr = locked.server.local_addrs()[0];
    let with = Client::with_tls_config(ClientConfig::new(trust)).proxy(&format!("http://lazaret:s3cret:x@{addr}")).unwrap();
    assert_eq!(with.get(&format!("https://registry.test:{}/left-pad", reg.port)).unwrap().status, 200);
}

/// CONNECT to `host:port` through the proxy at `proxy`, then TLS for `sni` trusting `ca`.
fn tunnel(proxy: SocketAddr, target: &str, sni: &str, ca: &[u8]) -> crate::error::Result<TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect(proxy).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(tcp, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(tcp.read(&mut b).unwrap(), 1, "{}", String::from_utf8_lossy(&head));
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    let mut trust = TrustStore::empty();
    trust.add_der(ca).unwrap();
    TlsStream::connect(tcp, sni, &ClientConfig::new(trust))
}

fn exchange(s: &mut impl ReadWrite, request: &str) -> String {
    s.write_all(request.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[test]
fn inside_a_tunnel_only_its_host_and_none_of_the_connections_fields() {
    let reg = registry();
    let p = start(&reg, NoScan, |b| b);
    let addr = p.server.local_addrs()[0];
    let target = format!("registry.test:{}", reg.port);
    let mut s = tunnel(addr, &target, "registry.test", p.proxy.ca().certificate()).unwrap();
    let text = exchange(&mut s, &format!("GET /left-pad HTTP/1.1\r\nHost: other.test:{}\r\nConnection: close\r\n\r\n", reg.port));
    assert!(text.starts_with("HTTP/1.1 421"), "{text}");
    let mut s = tunnel(addr, &target, "registry.test", p.proxy.ca().certificate()).unwrap();
    let text = exchange(&mut s, &format!("GET /headers HTTP/1.1\r\nHost: {target}\r\nConnection: close, x-drop\r\nX-Drop: 1\r\nX-Keep: 2\r\nTE: trailers\r\nKeep-Alive: 5\r\n\r\n"));
    assert!(text.starts_with("HTTP/1.1 200") && text.contains("x-keep: 2\n"), "{text}");
    for gone in ["x-drop", "te:", "keep-alive"] {
        assert!(!text.to_ascii_lowercase().contains(&format!("\n{gone}")), "{gone}: {text}");
    }
    // the certificate is for the host of the CONNECT alone
    assert!(tunnel(addr, &target, "other.test", p.proxy.ca().certificate()).is_err());
    // a client that does not trust the CA: the handshake fails, and the proxy says why
    let stranger = TestPki::new(&["x.test"]).unwrap();
    assert!(tunnel(addr, &target, "registry.test", &stranger.root).is_err());
    std::thread::sleep(Duration::from_millis(100));
    assert!(p.events().iter().any(|e| e.starts_with("Fail CONNECT") && e.contains("does it trust the proxy's CA")), "{:?}", p.events());
}

#[test]
fn plain_http_requests_are_sent_on_and_scanned() {
    let hits = Arc::new(AtomicUsize::new(0));
    let plain = ServerBuilder::new(registry_handler(hits.clone())).plain("127.0.0.1:0").start().unwrap();
    let port = plain.local_addrs()[0].port();
    let reg = registry();
    let p = start(&reg, Arc::new(Rules::default()), |b| b.ports(&[443, port]));
    let addr = p.server.local_addrs()[0];
    let ask = |url: &str| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        exchange(&mut s, &format!("GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    };
    let text = ask(&format!("http://registry.test:{port}/left-pad"));
    assert!(text.starts_with("HTTP/1.1 200") && text.ends_with(r#"{"name":"left-pad"}"#), "{text}");
    let text = ask(&format!("http://registry.test:{port}/evil"));
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // not intercepted: sent on unscanned, or refused
    let text = ask(&format!("http://other.test:{port}/evil"));
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    // a port neither the scheme's nor allowed
    let text = ask("http://other.test:25/");
    assert!(text.starts_with("HTTP/1.1 403") && text.contains("port 25"), "{text}");
    let strict = start(&reg, NoScan, |b| b.others(Others::Refuse));
    let mut s = TcpStream::connect(strict.server.local_addrs()[0]).unwrap();
    let text = exchange(&mut s, &format!("GET http://other.test:{port}/left-pad HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    // not a proxy request at all
    let mut s = TcpStream::connect(addr).unwrap();
    let text = exchange(&mut s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
}

#[test]
fn the_files_and_variables_that_point_programs_at_the_proxy() {
    let reg = registry();
    let p = start(&reg, NoScan, |b| b.credentials("lazaret", "p@ss word"));
    let dir = std::env::temp_dir().join(format!("pratique-proxy-env-{}", std::process::id()));
    let files = p.proxy.write_trust_files_with(&dir, &reg.pki.trust_store()).unwrap();
    let ca = std::fs::read_to_string(&files.ca).unwrap();
    assert_eq!(ca, p.proxy.ca().certificate_pem());
    let bundle = std::fs::read_to_string(&files.bundle).unwrap();
    assert!(bundle.starts_with(&reg.pki.root_pem()) && bundle.ends_with(&ca), "the roots, then the CA");
    let addr: SocketAddr = "0.0.0.0:3128".parse().unwrap();
    let env = p.proxy.client_env(addr, &files);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
    assert_eq!(get("HTTPS_PROXY"), "http://lazaret:p%40ss%20word@127.0.0.1:3128");
    assert_eq!(get("npm_config_https_proxy"), get("HTTPS_PROXY"));
    assert_eq!(get("PIP_PROXY"), get("HTTPS_PROXY"));
    assert_eq!(get("NO_PROXY"), "localhost,127.0.0.1,::1");
    for k in ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PIP_CERT", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"] {
        assert_eq!(get(k), files.bundle.display().to_string(), "{k}");
    }
    assert_eq!(shell_exports(&[("A".into(), "it's".into())]), "export A='it'\\''s'\n");
    // the proxy itself, through the variables' URL
    let mut trust = TrustStore::empty();
    trust.add_der(p.proxy.ca().certificate()).unwrap();
    let url = get("HTTPS_PROXY").replace("3128", &p.server.local_addrs()[0].port().to_string());
    let c = Client::with_tls_config(ClientConfig::new(trust)).proxy(&url).unwrap();
    assert_eq!(c.get(&format!("https://registry.test:{}/left-pad", reg.port)).unwrap().status, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_fields_of_a_connection_are_not_passed_on() {
    let h = |pairs: &[(&str, &str)]| pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect::<Vec<_>>();
    let kept = super::relay::end_to_end(&h(&[("Connection", "close, X-Gone"), ("x-gone", "1"), ("TE", "trailers"), ("Accept", "*/*"), ("Proxy-Authorization", "Basic x"), ("Upgrade", "h2c")]), &["host"]);
    assert_eq!(kept, h(&[("Accept", "*/*")]));
    assert_eq!(super::relay::decodable("br, zstd"), "identity");
    assert_eq!(super::relay::decodable("gzip, deflate, br"), "gzip, deflate");
    assert_eq!(super::relay::decodable("*"), "identity");
}

#[test]
fn behind_a_gateway_that_inspects_tls() {
    // the gateway's root (here: the registry's own PKI, which no system store has) is in a file that a variable names,
    // as an administrator or the gateway's installer leaves it; another variable names a file with it again and one more
    let reg = registry();
    let other = TestPki::new(&["x.test"]).unwrap();
    let dir = std::env::temp_dir().join(format!("pratique-proxy-gateway-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("corp.pem"), reg.pki.root_pem()).unwrap();
    std::fs::write(dir.join("node.pem"), format!("{}{}", reg.pki.root_pem(), other.root_pem())).unwrap();
    let (corp, node) = (dir.join("corp.pem").display().to_string(), dir.join("node.pem").display().to_string());
    let env = move |name: &str| match name {
        "SSL_CERT_FILE" => Some(corp.clone()),
        "NODE_EXTRA_CA_CERTS" => Some(node.clone()),
        "REQUESTS_CA_BUNDLE" => Some("/nonexistent/bundle.pem".into()),
        _ => None,
    };
    let roots = env::local_roots_from(&env, false).unwrap();
    assert_eq!(roots.len(), 2, "each certificate once");
    assert!(env::local_roots_from(&|_| None, false).is_err());
    // the proxy trusts the gateway on its way to the registry
    let client = Client::with_tls_config(ClientConfig::new(env::local_roots_from(&env, false).unwrap())).resolve_host("registry.test", &[LOCAL]).resolve_host("other.test", &[LOCAL]);
    let p = start(&reg, NoScan, |b| b.client(client));
    assert_eq!(p.client().get(&format!("https://registry.test:{}/left-pad", reg.port)).unwrap().status, 200);
    // and the programs, given the bundle alone, still trust it for the hosts the proxy tunnels
    let files = p.proxy.write_trust_files_with(&dir.join("trust"), &roots).unwrap();
    let mut from_bundle = TrustStore::empty();
    assert_eq!(from_bundle.add_pem(&std::fs::read_to_string(&files.bundle).unwrap()), 3);
    let tunnelled = Client::with_tls_config(ClientConfig::new(from_bundle)).proxy(&p.url()).unwrap();
    assert_eq!(tunnelled.get(&format!("https://other.test:{}/left-pad", reg.port)).unwrap().status, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_proxy_url_that_names_the_proxy_itself() {
    let at = |s: &str| s.parse::<SocketAddr>().unwrap();
    assert!(super::names_address("127.0.0.1", 3128, at("127.0.0.1:3128")));
    assert!(super::names_address("localhost", 3128, at("0.0.0.0:3128")));
    assert!(super::names_address("[::1]", 3128, at("[::1]:3128")));
    assert!(super::names_address("127.0.0.1", 3128, at("0.0.0.0:3128")));
    assert!(!super::names_address("127.0.0.1", 3129, at("127.0.0.1:3128")));
    assert!(!super::names_address("10.0.0.7", 3128, at("127.0.0.1:3128")));
    assert!(!super::names_address("proxy.example.com", 3128, at("0.0.0.0:3128")));
}
