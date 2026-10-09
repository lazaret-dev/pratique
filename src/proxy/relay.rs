//! The proxy's relay: each request to a host it opens goes past the [`Scanner`], on to the host over a connection the
//! proxy verifies, and back past the scanner again.

use super::registry::Package;
use super::{normal_host, Action, Proxy};
use crate::http::server::{Handler, Request, Response, ResponseBody};
use crate::inflate::{self, Format};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// One request through the proxy to a host it opens, as the scanner sees it.
#[derive(Clone, Debug)]
pub struct Exchange {
    /// The address of the program that asked.
    pub client: Option<SocketAddr>,
    /// `https` (inside a tunnel), or `http`.
    pub scheme: String,
    /// The host, lower case.
    pub host: String,
    pub port: u16,
    pub method: String,
    /// The path and query.
    pub target: String,
    /// The request's header fields as they are sent on (the proxy's own and the connection's taken out).
    pub headers: Vec<(String, String)>,
}

impl Exchange {
    /// The request's URL.
    pub fn url(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default {
            format!("{}://{host}{}", self.scheme, self.target)
        } else {
            format!("{}://{host}:{}{}", self.scheme, self.port, self.target)
        }
    }

    /// The first header field of this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The package the request is for, if it is one a registry serves (see [`registry`](super::registry)).
    pub fn package(&self) -> Option<Package> {
        super::registry::package(&self.host, &self.target)
    }
}

/// The head of the host's response.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub status: u16,
    /// The header fields as they will be sent on (the connection's taken out).
    pub headers: Vec<(String, String)>,
    /// The body's length, when the host said it.
    pub content_length: Option<u64>,
}

impl Upstream {
    /// The first header field of this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// What the scanner decides of a request, or of a body it read.
pub enum Decision {
    /// Go on.
    Allow,
    /// Refuse, with the reason (the client gets a 403 that says it).
    Block(String),
    /// Answer with this response instead (a rewritten metadata document, say).
    Respond(Response),
}

/// What the scanner decides from the head of a response.
pub enum BodyAction {
    /// Pass the body on as it comes, unread.
    Pass,
    /// Read the body whole first (up to [`max_inspect`](super::ProxyBuilder::max_inspect)) and call
    /// [`Scanner::inspect`]: nothing of it reaches the client before the scanner has decided.
    Inspect,
    /// Refuse, with the reason.
    Block(String),
    /// Answer with this response instead.
    Respond(Response),
}

impl fmt::Debug for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allow => f.write_str("Allow"),
            Decision::Block(r) => write!(f, "Block({r:?})"),
            Decision::Respond(r) => write!(f, "Respond({})", r.status()),
        }
    }
}

impl fmt::Debug for BodyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyAction::Pass => f.write_str("Pass"),
            BodyAction::Inspect => f.write_str("Inspect"),
            BodyAction::Block(r) => write!(f, "Block({r:?})"),
            BodyAction::Respond(r) => write!(f, "Respond({})", r.status()),
        }
    }
}

/// What looks at the requests to the hosts the proxy opens, and at what they answer. Called from many threads at once.
/// Every method has a default that lets everything through.
pub trait Scanner: Send + Sync + 'static {
    /// A request, before it is sent on (its body is not read yet).
    fn request(&self, exchange: &Exchange) -> Decision {
        let _ = exchange;
        Decision::Allow
    }

    /// The head of the host's answer, before any of its body is read.
    fn response(&self, exchange: &Exchange, upstream: &Upstream) -> BodyAction {
        let _ = (exchange, upstream);
        BodyAction::Pass
    }

    /// The whole body, when [`response`](Scanner::response) asked for it.
    fn inspect(&self, exchange: &Exchange, upstream: &Upstream, body: &Inspected) -> Decision {
        let _ = (exchange, upstream, body);
        Decision::Allow
    }
}

/// A scanner that looks at nothing: the proxy then only relays (and logs).
pub struct NoScan;

impl Scanner for NoScan {}

/// A body read whole for the scanner: in memory, or in a file when it is larger than
/// [`inspect_in_memory`](super::ProxyBuilder::inspect_in_memory). As the host sent it: encoded, if its
/// `Content-Encoding` says so ([`decoded`](Inspected::decoded) undoes gzip and deflate).
pub struct Inspected {
    memory: Vec<u8>,
    file: Option<PathBuf>,
    len: u64,
    encoding: Option<String>,
}

impl fmt::Debug for Inspected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Inspected({} bytes{}{})", self.len, if self.file.is_some() { ", in a file" } else { "" }, self.encoding.as_deref().map(|e| format!(", {e}")).unwrap_or_default())
    }
}

impl Inspected {
    /// Its length, as sent.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes, if they are in memory.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.file.is_none().then_some(self.memory.as_slice())
    }

    /// A reader of the bytes, wherever they are.
    pub fn open(&self) -> io::Result<Box<dyn Read + Send + '_>> {
        match &self.file {
            None => Ok(Box::new(io::Cursor::new(self.memory.as_slice()))),
            Some(p) => Ok(Box::new(File::open(p)?)),
        }
    }

    /// The body's `Content-Encoding`, if it has one other than `identity`.
    pub fn encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }

    /// The body with its `Content-Encoding` (gzip or deflate) undone, if it decodes to at most `max` bytes; as it is if
    /// it has none. An error for a coding this crate cannot undo (the proxy asks hosts for gzip and deflate alone), or a
    /// body that does not decode or decodes to more.
    pub fn decoded(&self, max: u64) -> io::Result<Vec<u8>> {
        let mut raw = Vec::new();
        self.open()?.read_to_end(&mut raw)?;
        let format = match self.encoding.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None => {
                if raw.len() as u64 > max {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "the body is larger than the limit"));
                }
                return Ok(raw);
            }
            Some("gzip") | Some("x-gzip") => Format::Gzip,
            Some("deflate") => Format::ZlibOrDeflate,
            Some(other) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a body encoded with {other:?}, which cannot be undone here"))),
        };
        inflate::decode_all(format, &raw, inflate::Limits::new(max)).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("the body does not decode: {e:?}")))
    }
}

impl Drop for Inspected {
    fn drop(&mut self) {
        if let Some(p) = self.file.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// A file being sent on, removed when it has been (or the client went away).
struct Spooled {
    file: File,
    path: PathBuf,
}

impl Read for Spooled {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Drop for Spooled {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The header fields that belong to one connection (RFC 9110 section 7.6.1), and those the proxy writes itself.
const HOP_BY_HOP: [&str; 9] = ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade"];

/// `headers` without the fields of the connection they came on: the hop-by-hop ones, those `Connection` names, and
/// `extra`.
pub(super) fn end_to_end(headers: &[(String, String)], extra: &[&str]) -> Vec<(String, String)> {
    let named: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    headers
        .iter()
        .filter(|(n, _)| {
            let n = n.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&n.as_str()) && !extra.contains(&n.as_str()) && !named.contains(&n)
        })
        .cloned()
        .collect()
}

/// An `Accept-Encoding` with only the codings the scanner can have undone (gzip, deflate, identity); `identity` if none
/// is left.
pub(super) fn decodable(accept: &str) -> String {
    let kept: Vec<&str> = accept
        .split(',')
        .map(str::trim)
        .filter(|t| {
            let coding = t.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            matches!(coding.as_str(), "gzip" | "x-gzip" | "deflate" | "identity")
        })
        .collect();
    if kept.is_empty() { "identity".into() } else { kept.join(", ") }
}

fn blocked(reason: &str) -> Response {
    Response::text(403, format!("blocked by the scanning proxy: {reason}\n")).with_header("cache-control", "no-store")
}

/// The handler inside a tunnel the proxy opened to `host`.
pub(crate) struct Tunnel {
    pub(crate) proxy: Proxy,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Handler for Tunnel {
    fn handle(&self, req: Request) -> Response {
        // a request inside the tunnel is for the tunnel's host alone (RFC 9110 section 7.4: 421 for another)
        let (host, port) = match super::split_host_port(req.authority()) {
            Some(hp) => hp,
            None => (normal_host(req.authority()), 443),
        };
        if host != self.host || port != self.port {
            return self.proxy.refuse(&req, 421, &format!("this tunnel is to {}:{}, not {}", self.host, self.port, req.authority()));
        }
        let target = if req.target().starts_with('/') {
            req.target().to_string()
        } else {
            match crate::http::Url::parse(req.target()) {
                Ok(u) if u.is_https() && normal_host(&u.host) == self.host && u.port == self.port => u.path_and_query.clone(),
                _ => return self.proxy.refuse(&req, 400, "a request target that is not a path on the tunnel's host"),
            }
        };
        self.proxy.relay(req, "https", &self.host, self.port, target, true)
    }
}

impl Proxy {
    /// Sends `req` on to scheme://host:port/target and the answer back, past the scanner when `scan`.
    pub(super) fn relay(&self, mut req: Request, scheme: &str, host: &str, port: u16, target: String, scan: bool) -> Response {
        let inner = &self.0;
        let client = req.connection().peer;
        let method = req.method().to_string();
        let mut headers = end_to_end(req.headers(), &["host", "content-length", "expect"]);
        if scan {
            for (n, v) in headers.iter_mut() {
                if n.eq_ignore_ascii_case("accept-encoding") {
                    *v = decodable(v);
                }
            }
        }
        let exchange = Exchange { client, scheme: scheme.into(), host: host.into(), port, method: method.clone(), target, headers };
        let url = exchange.url();
        if scan {
            match inner.scanner.request(&exchange) {
                Decision::Allow => {}
                Decision::Block(why) => {
                    self.event(client, Action::Block, &method, &url, 403, None, &why);
                    return blocked(&why);
                }
                Decision::Respond(r) => {
                    self.event(client, Action::Replace, &method, &url, r.status(), None, "the scanner answered the request");
                    return r;
                }
            }
        }
        let body = match req.read_body(inner.max_request_body) {
            Ok(b) => b,
            Err(e) => {
                let status = if e.kind() == io::ErrorKind::InvalidData { 413 } else { 400 };
                return self.refuse(&req, status, &format!("the request body: {e}"));
            }
        };
        let mut builder = inner.client.request(&method, &url);
        for (n, v) in &exchange.headers {
            builder = builder.header(n, v);
        }
        if !body.is_empty() {
            builder = builder.body(body);
        }
        let resp = match builder.send_stream() {
            Ok(r) => r,
            Err(e) => {
                let why = format!("the proxy could not get {url}: {e}");
                self.event(client, Action::Fail, &method, &url, 502, None, &why);
                return Response::text(502, format!("{why}\n")).with_header("cache-control", "no-store");
            }
        };
        let no_body = method == "HEAD" || matches!(resp.status, 100..=199 | 204 | 304);
        let upstream = Upstream { status: resp.status, headers: end_to_end(&resp.headers, &[]), content_length: if no_body { None } else { resp.content_length } };
        let action = if scan { inner.scanner.response(&exchange, &upstream) } else { BodyAction::Pass };
        match action {
            BodyAction::Block(why) => {
                self.event(client, Action::Block, &method, &url, 403, upstream.content_length, &why);
                blocked(&why)
            }
            BodyAction::Respond(r) => {
                self.event(client, Action::Replace, &method, &url, r.status(), None, "the scanner answered in the host's place");
                r
            }
            BodyAction::Pass => {
                self.event(client, Action::Pass, &method, &url, upstream.status, upstream.content_length, "");
                let body = if no_body { ResponseBody::Empty } else { ResponseBody::Reader { reader: Box::new(resp), length: upstream.content_length } };
                Response { status: upstream.status, headers: upstream.headers, body }
            }
            BodyAction::Inspect => {
                let collected = if no_body { Ok(Inspected { memory: Vec::new(), file: None, len: 0, encoding: None }) } else { self.collect(resp, upstream.content_length) };
                let mut inspected = match collected {
                    Ok(i) => i,
                    Err(e) => {
                        let why = format!("the body could not be inspected: {e}");
                        self.event(client, Action::Fail, &method, &url, 502, upstream.content_length, &why);
                        return Response::text(502, format!("{why}\n")).with_header("cache-control", "no-store");
                    }
                };
                inspected.encoding = upstream.header("content-encoding").map(str::trim).filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("identity")).map(str::to_string);
                match inner.scanner.inspect(&exchange, &upstream, &inspected) {
                    Decision::Allow => {
                        self.event(client, Action::Inspect, &method, &url, upstream.status, Some(inspected.len), "");
                        let body = if no_body {
                            ResponseBody::Empty
                        } else {
                            match inspected.file.take() {
                                None => ResponseBody::Bytes(std::mem::take(&mut inspected.memory)),
                                Some(path) => match File::open(&path) {
                                    Ok(file) => ResponseBody::Reader { reader: Box::new(Spooled { file, path }), length: Some(inspected.len) },
                                    Err(e) => {
                                        let _ = std::fs::remove_file(&path);
                                        return Response::text(502, format!("the inspected body could not be read back: {e}\n"));
                                    }
                                },
                            }
                        };
                        Response { status: upstream.status, headers: upstream.headers, body }
                    }
                    Decision::Block(why) => {
                        self.event(client, Action::Block, &method, &url, 403, Some(inspected.len), &why);
                        blocked(&why)
                    }
                    Decision::Respond(r) => {
                        self.event(client, Action::Replace, &method, &url, r.status(), Some(inspected.len), "the scanner answered in the host's place");
                        r
                    }
                }
            }
        }
    }

    /// Reads a body whole for the scanner: in memory up to `inspect_in_memory`, then in a file of the spool directory,
    /// up to `max_inspect` (an error past it: the body is never passed on unread).
    fn collect(&self, mut body: impl Read, declared: Option<u64>) -> io::Result<Inspected> {
        let inner = &self.0;
        if declared.is_some_and(|n| n > inner.max_inspect) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("it is larger than the {} bytes the proxy inspects", inner.max_inspect)));
        }
        let mut memory = Vec::new();
        (&mut body).take(inner.inspect_in_memory as u64 + 1).read_to_end(&mut memory)?;
        if memory.len() <= inner.inspect_in_memory {
            let len = memory.len() as u64;
            return Ok(Inspected { memory, file: None, len, encoding: None });
        }
        let path = self.spool_file()?;
        // (from here the file is the Inspected's, removed when it is dropped)
        let mut inspected = Inspected { memory: Vec::new(), file: Some(path.clone()), len: 0, encoding: None };
        let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.write_all(&memory)?;
        let rest = io::copy(&mut (&mut body).take(inner.max_inspect.saturating_sub(memory.len() as u64) + 1), &mut file)?;
        let len = memory.len() as u64 + rest;
        if len > inner.max_inspect {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("it is larger than the {} bytes the proxy inspects", inner.max_inspect)));
        }
        file.sync_all()?;
        inspected.len = len;
        Ok(inspected)
    }

    /// A new, empty file in the spool directory, readable by its owner only.
    fn spool_file(&self) -> io::Result<PathBuf> {
        let dir = &self.0.spool;
        {
            let mut made = super::lock(&self.0.spool_made);
            if !*made {
                make_private_dir(dir)?;
                *made = true;
            }
        }
        let name = crate::util::hex(&crate::crypto::rand::bytes::<12>()?);
        let path = dir.join(format!("body-{name}"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path)?;
        Ok(path)
    }
}

pub(crate) fn make_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    #[cfg(unix)]
    std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    Ok(())
}
