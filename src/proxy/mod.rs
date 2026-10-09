//! The scanning proxy (B-78): an HTTP proxy that opens the TLS of the hosts it is told to (package registries), so that
//! what they send can be looked at, and refused, before it reaches the program that asked for it; everything else it
//! passes through untouched, or refuses.
//!
//! **Not to be relied on yet** (behind the `server` feature): BACKLOG B-78 asks for an independent review of the server
//! and of the signing code (B-23) first. The threat model is `PROXY_THREAT_MODEL.md`.
//!
//! A package manager is pointed at the proxy with `HTTPS_PROXY` and told to trust the proxy's certificate authority
//! ([`Proxy::client_env`] gives the variables, [`Proxy::write_trust_files`] the files they name). Then, for each
//! connection it opens:
//!
//! * `CONNECT` to a host it intercepts (by default [`PACKAGE_REGISTRIES`]): the proxy answers the TLS handshake itself,
//!   with a certificate its own CA ([`ProxyCa`]: in memory, short-lived, limited by a name constraint to those hosts)
//!   signs for that host, serves HTTP/1.1 or HTTP/2 inside, and sends each request on to the real host over a TLS
//!   connection it verifies as any client does ([`Client`]). Each request and response goes past the [`Scanner`]:
//!   it may refuse a request before it is sent, pass a response on as it comes, or have the whole body read first
//!   (in memory, then in a file past a size) and decide on it, before the program sees a byte of it.
//! * `CONNECT` to any other host: a tunnel of bytes, as any proxy makes ([`Others::Tunnel`], the default), or a
//!   refusal ([`Others::Refuse`]). Either way only to the ports allowed ([`ProxyBuilder::ports`], 443 by default).
//! * A request for an `http://` URL (to port 80, or a port allowed): sent on, and scanned if its host is intercepted.
//!
//! ```no_run
//! use pratique::proxy::{BodyAction, Decision, Exchange, Inspected, Proxy, Scanner, Upstream};
//!
//! struct NoLeftPad;
//! impl Scanner for NoLeftPad {
//!     fn request(&self, ex: &Exchange) -> Decision {
//!         match ex.package() {
//!             Some(p) if p.name == "left-pad" => Decision::Block("left-pad is not allowed here".into()),
//!             _ => Decision::Allow,
//!         }
//!     }
//!     fn response(&self, ex: &Exchange, _up: &Upstream) -> BodyAction {
//!         // read each package file whole before it goes on
//!         if ex.package().is_some_and(|p| p.is_artifact()) { BodyAction::Inspect } else { BodyAction::Pass }
//!     }
//!     fn inspect(&self, _ex: &Exchange, _up: &Upstream, body: &Inspected) -> Decision {
//!         if body.len() == 0 { Decision::Block("an empty package".into()) } else { Decision::Allow }
//!     }
//! }
//!
//! let proxy = Proxy::builder(NoLeftPad).build()?;
//! let server = proxy.start("127.0.0.1:0")?;
//! let files = proxy.write_trust_files(std::path::Path::new("/tmp/scan-proxy"))?;
//! for (name, value) in proxy.client_env(server.local_addrs()[0], &files) {
//!     println!("export {name}='{value}'");
//! }
//! server.wait();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod ca;
mod env;
pub mod registry;
mod relay;

pub use ca::ProxyCa;
pub use env::{local_roots, shell_exports, TrustFiles, ROOT_FILE_VARIABLES};
pub use relay::{BodyAction, Decision, Exchange, Inspected, NoScan, Scanner, Upstream};

use crate::error::{Error, Result};
use crate::http::server::runtime::Ctl;
use crate::http::server::{serve_tls_ctl, HttpConfig, Limits, Request, Response, Server, ServerBuilder, Socket, Upgraded};
use crate::http::Client;
use crate::tls::server::{ServerConfig, ServerStream};
use crate::tls::{ClientConfig, Duplex};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// The hosts of the Python and JavaScript package registries: PyPI's index and files, npm's registry and Yarn's mirror
/// of it.
pub const PACKAGE_REGISTRIES: &[&str] = &["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com"];

/// What the proxy does with a `CONNECT` to a host it does not intercept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Others {
    /// A tunnel of bytes to the host (TLS from end to end: the proxy sees nothing).
    Tunnel,
    /// 403.
    Refuse,
}

/// What the proxy did, for its event log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// A `CONNECT` to a host it intercepts: opened.
    Intercept,
    /// A `CONNECT` to another host: tunnelled.
    Tunnel,
    /// Refused by the proxy itself: credentials, a port, a host it does not serve, a request it cannot read.
    Refuse,
    /// A response passed on unread (as the scanner chose, or unscanned: a plain `http://` request to a host that is not
    /// intercepted).
    Pass,
    /// A response read whole, inspected and passed on.
    Inspect,
    /// The scanner answered in the host's place (a rewritten response).
    Replace,
    /// The scanner refused the request or the response.
    Block,
    /// The proxy could not get an answer it may pass on: the host could not be reached, its certificate did not verify,
    /// a body too large to inspect.
    Fail,
}

/// One thing the proxy did.
#[derive(Debug)]
pub struct ProxyEvent<'a> {
    pub client: Option<SocketAddr>,
    pub action: Action,
    /// `CONNECT`, or the request's method.
    pub method: &'a str,
    /// `host:port` for a `CONNECT`, the URL for a request.
    pub url: &'a str,
    /// The status the client got (0 when it got none: a handshake that failed).
    pub status: u16,
    /// The body's length, when it is known.
    pub bytes: Option<u64>,
    /// Why: the scanner's reason, the error.
    pub detail: &'a str,
}

type EventLog = Arc<dyn Fn(&ProxyEvent<'_>) + Send + Sync>;

/// Builds a [`Proxy`].
pub struct ProxyBuilder {
    scanner: Arc<dyn Scanner>,
    intercept: Vec<String>,
    others: Others,
    ports: Vec<u16>,
    credentials: Option<String>,
    client: Option<Client>,
    ca_name: String,
    ca_lifetime: Duration,
    max_request_body: usize,
    inspect_in_memory: usize,
    max_inspect: u64,
    spool_dir: Option<PathBuf>,
    http: HttpConfig,
    limits: Limits,
    events: Option<EventLog>,
}

impl ProxyBuilder {
    /// The hosts to open (in place of [`PACKAGE_REGISTRIES`]): names, or `*.example.com` for every name under one. The
    /// proxy's CA is limited to these names.
    pub fn intercept(mut self, hosts: &[&str]) -> ProxyBuilder {
        self.intercept = hosts.iter().map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase()).collect();
        self
    }

    /// What to do with a `CONNECT` to any other host (default [`Others::Tunnel`]).
    pub fn others(mut self, others: Others) -> ProxyBuilder {
        self.others = others;
        self
    }

    /// The ports a `CONNECT` may reach, intercepted or not (default 443).
    pub fn ports(mut self, ports: &[u16]) -> ProxyBuilder {
        self.ports = ports.to_vec();
        self
    }

    /// Requires `Proxy-Authorization: Basic` with these credentials of every request (407 without them). For a proxy
    /// that other users of the machine should not be able to use; [`Proxy::client_env`] puts them in the proxy's URL.
    pub fn credentials(mut self, user: &str, password: &str) -> ProxyBuilder {
        self.credentials = Some(format!("{user}:{password}"));
        self
    }

    /// The client that reaches the real hosts: its trust store, timeouts, and its own proxy if it has one (a proxy
    /// behind which this one runs: the tunnels go through it too). The proxy sets it not to follow redirects, not to
    /// decode bodies, and to take bodies of any length. The default trusts the roots this machine trusts
    /// ([`local_roots`]: the system's file and store, and the files the usual variables name, where a TLS-inspecting
    /// gateway's root is) and goes through the proxy `HTTPS_PROXY` names in this process's environment, except for the
    /// hosts `NO_PROXY` names (an explicit corporate proxy; it may ask for Basic credentials in its URL, not NTLM or
    /// Kerberos).
    pub fn client(mut self, client: Client) -> ProxyBuilder {
        self.client = Some(client);
        self
    }

    /// The common name of the proxy's CA (default "pratique scanning proxy CA").
    pub fn ca_name(mut self, name: &str) -> ProxyBuilder {
        self.ca_name = name.to_string();
        self
    }

    /// How long the proxy's CA, and every certificate it signs, is valid (default a day; at least a minute, at most
    /// 398 days).
    pub fn ca_lifetime(mut self, lifetime: Duration) -> ProxyBuilder {
        self.ca_lifetime = lifetime;
        self
    }

    /// The largest request body sent on to an intercepted host (default 256 MiB; more is answered 413). It is read whole
    /// first.
    pub fn max_request_body(mut self, bytes: usize) -> ProxyBuilder {
        self.max_request_body = bytes;
        self
    }

    /// How much of a body being inspected is held in memory (default 32 MiB); the rest goes to a file.
    pub fn inspect_in_memory(mut self, bytes: usize) -> ProxyBuilder {
        self.inspect_in_memory = bytes;
        self
    }

    /// The largest body inspected (default 4 GiB): a larger one is refused (502), never passed on unread.
    pub fn max_inspect(mut self, bytes: u64) -> ProxyBuilder {
        self.max_inspect = bytes;
        self
    }

    /// Where bodies too large for memory are kept while they are inspected (default: a directory of the proxy's own in
    /// the system's temporary directory, readable by its owner only). Each file is removed once its body is sent on or
    /// refused.
    pub fn spool_dir(mut self, dir: impl Into<PathBuf>) -> ProxyBuilder {
        self.spool_dir = Some(dir.into());
        self
    }

    /// The HTTP limits of the proxy's listener and of the HTTP inside the tunnels it opens.
    pub fn http_config(mut self, config: HttpConfig) -> ProxyBuilder {
        self.http = config;
        self
    }

    /// The runtime's limits for [`Proxy::start`] (connections, timeouts; a tunnel may be quiet for
    /// [`Limits::upgraded_idle_timeout`]).
    pub fn limits(mut self, limits: Limits) -> ProxyBuilder {
        self.limits = limits;
        self
    }

    /// Calls `log` with each thing the proxy does.
    pub fn events(mut self, log: impl Fn(&ProxyEvent<'_>) + Send + Sync + 'static) -> ProxyBuilder {
        self.events = Some(Arc::new(log));
        self
    }

    /// Makes the proxy's CA (a new key, in memory) and the proxy.
    pub fn build(self) -> Result<Proxy> {
        if self.intercept.is_empty() {
            return Err(Error::Http("a scanning proxy that intercepts no host".into()));
        }
        for h in &self.intercept {
            if !ca::is_dns_name(h.strip_prefix("*.").unwrap_or(h)) {
                return Err(Error::Http(format!("{h:?} is not a host name the proxy can intercept")));
            }
        }
        let names: Vec<&str> = self.intercept.iter().map(String::as_str).collect();
        let ca = Arc::new(ProxyCa::new(&self.ca_name, &names, self.ca_lifetime)?);
        let from_env = self.client.is_none();
        let client = match self.client {
            Some(c) => c,
            None => Client::with_tls_config(ClientConfig::new(env::local_roots()?)).proxy_from_env(),
        };
        let client = client.follow_redirects(false).decompress(false).max_body_bytes(u64::MAX).allow_insecure_http(true);
        // the TLS of every tunnel: these settings, and the certificate of the tunnel's host (set per tunnel)
        let tls = ServerConfig::with_resolver(Arc::new(NoCertificate)).with_alpn(&["h2", "http/1.1"]);
        let spool = self.spool_dir.unwrap_or_else(|| {
            let tag = crate::crypto::rand::bytes::<6>().map(|b| crate::util::hex(&b)).unwrap_or_default();
            std::env::temp_dir().join(format!("pratique-proxy-{}-{tag}", std::process::id()))
        });
        Ok(Proxy(Arc::new(Inner {
            scanner: self.scanner,
            intercept: self.intercept,
            others: self.others,
            ports: self.ports,
            credentials: self.credentials,
            client,
            ca,
            tls,
            http: self.http,
            limits: self.limits,
            max_request_body: self.max_request_body,
            inspect_in_memory: self.inspect_in_memory,
            max_inspect: self.max_inspect,
            spool,
            spool_made: Mutex::new(false),
            events: self.events,
            client_from_env: from_env,
        })))
    }
}

/// The placeholder resolver of the proxy's base TLS configuration: each tunnel's has its own.
struct NoCertificate;

impl crate::tls::certs::ResolvesServerCert for NoCertificate {
    fn resolve(&self, _hello: &crate::tls::certs::ClientHelloInfo) -> Option<Arc<crate::tls::certs::CertifiedKey>> {
        None
    }
}

/// A scanning proxy. Cheap to clone.
#[derive(Clone)]
pub struct Proxy(Arc<Inner>);

struct Inner {
    scanner: Arc<dyn Scanner>,
    intercept: Vec<String>,
    others: Others,
    ports: Vec<u16>,
    credentials: Option<String>,
    client: Client,
    ca: Arc<ProxyCa>,
    tls: ServerConfig,
    http: HttpConfig,
    limits: Limits,
    max_request_body: usize,
    inspect_in_memory: usize,
    max_inspect: u64,
    spool: PathBuf,
    spool_made: Mutex<bool>,
    events: Option<EventLog>,
    /// the client is the default one, which goes through the proxy `HTTPS_PROXY` names
    client_from_env: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A host as the proxy compares it: lower case, without a final dot.
fn normal_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `host:port` (a proxy's URL) reaches the listener at `addr`.
fn names_address(host: &str, port: u16, addr: SocketAddr) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    port == addr.port()
        && match host.parse::<std::net::IpAddr>() {
            Ok(ip) => ip == addr.ip() || (ip.is_loopback() && (addr.ip().is_unspecified() || addr.ip().is_loopback())),
            Err(_) => host.eq_ignore_ascii_case("localhost") && (addr.ip().is_loopback() || addr.ip().is_unspecified()),
        }
}

/// `host:port` (or `[v6]:port`) split; `None` if it is not that.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        s.rsplit_once(':')?
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    (!host.is_empty() && !host.contains(['[', ']', '/', '@'])).then(|| (normal_host(host), port))
}

impl Proxy {
    /// A proxy that puts what it intercepts past `scanner`.
    pub fn builder(scanner: impl Scanner) -> ProxyBuilder {
        ProxyBuilder {
            scanner: Arc::new(scanner),
            intercept: PACKAGE_REGISTRIES.iter().map(|h| h.to_string()).collect(),
            others: Others::Tunnel,
            ports: vec![443],
            credentials: None,
            client: None,
            ca_name: "pratique scanning proxy CA".into(),
            ca_lifetime: Duration::from_secs(86_400),
            max_request_body: 256 << 20,
            inspect_in_memory: 32 << 20,
            max_inspect: 4 << 30,
            spool_dir: None,
            http: HttpConfig::default(),
            limits: Limits::default(),
            events: None,
        }
    }

    /// The proxy's certificate authority.
    pub fn ca(&self) -> &ProxyCa {
        &self.0.ca
    }

    /// Whether the proxy opens `host`.
    pub fn intercepts(&self, host: &str) -> bool {
        let host = normal_host(host);
        self.0.intercept.iter().any(|p| match p.strip_prefix("*.") {
            Some(base) => host.strip_suffix(base).is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
            None => host == *p,
        })
    }

    /// Starts the proxy on `addr` (`127.0.0.1:0` for a free port on this machine alone), under the server's runtime.
    pub fn start(&self, addr: &str) -> io::Result<Server> {
        let server = ServerBuilder::new(self.handler()).plain(addr).http_config(self.0.http.clone()).limits(self.0.limits.clone()).start()?;
        // the default client goes through the proxy HTTPS_PROXY names: not this one, which would send its own requests
        // round and round (a shell that has this proxy's variables already, say)
        if self.0.client_from_env {
            for name in ["HTTPS_PROXY", "https_proxy"] {
                let Some(p) = std::env::var(name).ok().and_then(|v| crate::http::Proxy::parse(&v).ok()) else { continue };
                if server.local_addrs().iter().any(|a| names_address(&p.host, p.port, *a)) {
                    server.shutdown(Duration::ZERO);
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{name} names this proxy itself ({}:{}), so it would send its own requests to itself", p.host, p.port)));
                }
                break;
            }
        }
        Ok(server)
    }

    /// The proxy as a handler, for a listener of a [`ServerBuilder`] of your own (a plain one: clients speak plain HTTP to
    /// a proxy).
    pub fn handler(&self) -> impl crate::http::server::Handler {
        let proxy = self.clone();
        move |req: Request| proxy.handle(req)
    }

    #[allow(clippy::too_many_arguments)]
    fn event(&self, client: Option<SocketAddr>, action: Action, method: &str, url: &str, status: u16, bytes: Option<u64>, detail: &str) {
        if let Some(log) = &self.0.events {
            log(&ProxyEvent { client, action, method, url, status, bytes, detail });
        }
    }

    fn refuse(&self, req: &Request, status: u16, why: &str) -> Response {
        self.event(req.connection().peer, Action::Refuse, req.method(), req.target(), status, None, why);
        Response::text(status, format!("{why}\n")).with_header("cache-control", "no-store")
    }

    fn handle(&self, req: Request) -> Response {
        if let Some(expected) = &self.0.credentials {
            let given = req
                .header("proxy-authorization")
                .and_then(|v| v.trim().split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
                .and_then(|(_, b)| crate::pem::base64_decode_strict(b.trim()))
                .unwrap_or_default();
            if !crate::util::ct_eq(&given, expected.as_bytes()) {
                return self.refuse(&req, 407, "the proxy wants its credentials").with_header("proxy-authenticate", "Basic realm=\"pratique scanning proxy\"");
            }
        }
        if req.method() == "CONNECT" {
            return self.connect(req);
        }
        let lower = req.target().get(..8).unwrap_or("").to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return self.forward(req);
        }
        self.refuse(&req, 400, "this is a proxy: ask it for a URL, or for a tunnel with CONNECT")
    }

    fn connect(&self, req: Request) -> Response {
        let Some((host, port)) = split_host_port(req.target()) else { return self.refuse(&req, 400, "a CONNECT target that is not host:port") };
        if !self.0.ports.contains(&port) {
            return self.refuse(&req, 403, &format!("the proxy does not open tunnels to port {port}"));
        }
        let peer = req.connection().peer;
        let target = format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.clone() });
        if self.intercepts(&host) {
            self.event(peer, Action::Intercept, "CONNECT", &target, 200, None, "");
            let (proxy, info, ctl) = (self.clone(), req.connection().clone(), req.ctl.clone());
            return Response::upgrade(200, move |up| proxy.intercepted(up, host, port, info, ctl));
        }
        if self.0.others == Others::Refuse {
            return self.refuse(&req, 403, &format!("the proxy does not open tunnels to {host}"));
        }
        match self.0.client.tunnel(&host, port) {
            Ok(upstream) => {
                self.event(peer, Action::Tunnel, "CONNECT", &target, 200, None, "");
                let idle = self.0.limits.upgraded_idle_timeout;
                let ctl = req.ctl.clone();
                Response::upgrade(200, move |up| pump(up, upstream, idle, ctl))
            }
            Err(e) => {
                let why = format!("the proxy could not reach {target}: {e}");
                self.event(peer, Action::Fail, "CONNECT", &target, 502, None, &why);
                Response::text(502, format!("{why}\n"))
            }
        }
    }

    /// A request for a URL (`http://`, or `https://` from a client that asks the proxy to make the TLS connection).
    fn forward(&self, req: Request) -> Response {
        let Ok(url) = crate::http::Url::parse(req.target()) else { return self.refuse(&req, 400, "a request URL that does not parse") };
        let scan = self.intercepts(&url.host);
        if !scan && self.0.others == Others::Refuse {
            return self.refuse(&req, 403, &format!("the proxy does not fetch from {}", url.host));
        }
        let scheme = if url.is_https() { "https" } else { "http" };
        // the scheme's own port, or one a tunnel may reach: not a way to speak HTTP to any service of the network
        if url.port != if url.is_https() { 443 } else { 80 } && !self.0.ports.contains(&url.port) {
            return self.refuse(&req, 403, &format!("the proxy does not fetch from port {}", url.port));
        }
        let target = url.path_and_query.clone();
        self.relay(req, scheme, &normal_host(&url.host), url.port, target, scan)
    }

    /// A tunnel to a host the proxy opens: its own TLS server with the host's certificate, and HTTP inside.
    fn intercepted(&self, up: Upgraded, host: String, port: u16, info: crate::http::server::ConnInfo, ctl: Option<Arc<Ctl>>) {
        let ctl = ctl.unwrap_or_else(Ctl::detached);
        let (r, w) = up.split();
        let socket = TunnelSocket { r: Arc::new(Mutex::new(r)), w: Arc::new(Mutex::new(w)), ctl: ctl.clone() };
        if let Some(t) = &ctl.timer {
            t.until(Instant::now() + ctl.limits.handshake_timeout);
        }
        let mut config = self.0.tls.clone();
        config.certs = Arc::new(ca::TunnelCert { ca: self.0.ca.clone(), host: host.clone() });
        let target = format!("{host}:{port}");
        match ServerStream::accept(socket, &Arc::new(config)) {
            Ok(stream) => {
                let relay = Arc::new(relay::Tunnel { proxy: self.clone(), host, port });
                let _ = serve_tls_ctl(stream, info, relay, &self.0.http, ctl);
            }
            Err(e) => {
                let why = format!("the TLS handshake with the client failed (does it trust the proxy's CA?): {e}");
                self.event(info.peer, Action::Fail, "CONNECT", &target, 0, None, &why);
            }
        }
    }
}

/// The client's end of a tunnel the proxy opens, as one socket the TLS and HTTP servers can drive: the halves of the
/// upgraded connection (the connection's timer, underneath, keeps the deadlines).
struct TunnelSocket {
    r: Arc<Mutex<Box<dyn Read + Send>>>,
    w: Arc<Mutex<Box<dyn Write + Send>>>,
    ctl: Arc<Ctl>,
}

impl Read for TunnelSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        lock(&self.r).read(buf)
    }
}

impl Write for TunnelSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        lock(&self.w).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        lock(&self.w).flush()
    }
}

impl Duplex for TunnelSocket {
    fn duplicate(&self) -> io::Result<Self> {
        Ok(TunnelSocket { r: self.r.clone(), w: self.w.clone(), ctl: self.ctl.clone() })
    }
}

impl Socket for TunnelSocket {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn shutdown(&self) {
        self.ctl.stop();
    }
    fn shutdown_write(&self) {}
}

/// A tunnel of bytes between the client and `upstream`, until one of them is done, or quiet for `idle`.
fn pump(up: Upgraded, upstream: TcpStream, idle: Duration, ctl: Option<Arc<Ctl>>) {
    let (mut from_client, mut to_client) = up.split();
    let _ = upstream.set_read_timeout(Some(idle));
    let _ = upstream.set_write_timeout(Some(idle));
    let Ok(mut to_upstream) = upstream.try_clone() else { return };
    let mut from_upstream = upstream;
    let outbound = thread::Builder::new().name("pratique-proxy-tunnel".into()).spawn(move || {
        let _ = io::copy(&mut from_client, &mut to_upstream);
        let _ = to_upstream.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut from_upstream, &mut to_client);
    let _ = to_client.flush();
    // the host is done: so is the client's side (its reading thread is woken by closing the socket's reading side)
    let _ = from_upstream.shutdown(std::net::Shutdown::Both);
    if let Some(ctl) = &ctl {
        ctl.stop();
    }
    if let Ok(t) = outbound {
        let _ = t.join();
    }
}

#[cfg(test)]
mod tests;
