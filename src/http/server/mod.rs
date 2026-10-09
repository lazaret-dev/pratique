//! An HTTP server: HTTP/1.1 and HTTP/2 behind one handler API (B-111), over the crate's TLS 1.3 server or plain TCP.
//!
//! **Not for production yet** (behind the `server` feature; BACKLOG B-109 to B-114: no independent review yet).
//! [`ServerBuilder`] is the runtime (B-112): listeners, limits on connections, timeouts, graceful shutdown (see
//! [`runtime`]); [`acme`] gets and renews its certificates (B-113). The functions that serve one connection
//! ([`serve_tls`], [`serve_plain`], [`serve_h2c`]) are the protocol layer alone, with no limits or timeouts: for a caller
//! that brings its own.
//!
//! A [`Handler`] gets a [`Request`] and returns a [`Response`]. The request body is a stream ([`Body`], which implements
//! `Read`): nothing is read until the handler reads it, and an HTTP/1.1 client that sent `Expect: 100-continue` is told to
//! go on only then. The response body is bytes, a reader, or a function that writes it ([`Response::stream`]), and can end
//! with trailers; it is sent as it is made, with `Content-Length` when its length is known and chunked (HTTP/1.1) or in
//! DATA frames as the client's windows allow (HTTP/2) when it is not. A `CONNECT` answered with 2xx, or a 101 Switching
//! Protocols, hands the handler the connection itself ([`Response::upgrade`], [`Upgraded`]).
//!
//! ```no_run
//! use pratique::http::server::{serve_plain, ConnInfo, HttpConfig, Request, Response};
//! use std::sync::Arc;
//!
//! let handler = Arc::new(|req: Request| Response::text(200, format!("you asked for {}\n", req.path())));
//! let listener = std::net::TcpListener::bind("127.0.0.1:8080")?;
//! for conn in listener.incoming() {
//!     let (conn, handler) = (conn?, handler.clone());
//!     std::thread::spawn(move || {
//!         let info = ConnInfo::of(&conn);
//!         let _ = serve_plain(conn, info, handler, &HttpConfig::default());
//!     });
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! What the server is strict about, because a server that is lenient where a proxy in front of it is strict (or the
//! other way round) can be made to see two requests where the proxy saw one (request smuggling):
//!
//! * HTTP/1.1: a request with both `Content-Length` and `Transfer-Encoding`, two lengths, a length
//!   that is not plain digits, a transfer coding other than `chunked` alone, `Transfer-Encoding` in HTTP/1.0, obsolete line
//!   folding, white space between a field name and its colon, a bare CR or LF, control characters, a chunk size that is
//!   not plain hexadecimal or does not fit 64 bits, chunk extensions that are not well formed, and chunk data not followed
//!   by CRLF are all refused (400, or 501 for a coding it does not know), and the connection is closed after the answer.
//! * HTTP/2: the frame and header checks of RFC 9113 (pseudo-headers, connection-specific fields, lower case names,
//!   `Content-Length` against the DATA), and limits on what a client can make it do: the streams it may have open at once,
//!   resets (CVE-2023-44487), header blocks spread over CONTINUATION frames (CVE-2024-27316), SETTINGS, PING, empty frames
//!   and tiny window updates (the 2019 HTTP/2 advisories), and HPACK (the table size, the list size measured before it is
//!   copied).

pub mod acme;
mod date;
#[cfg(pratique_fuzzing)]
#[doc(hidden)]
pub mod fuzz;
mod h1;
mod h2;
mod helpers;
pub mod runtime;
#[cfg(test)]
mod acme_tests;
#[cfg(test)]
mod h1_tests;
#[cfg(test)]
mod h2_tests;
#[cfg(test)]
mod runtime_tests;
#[cfg(test)]
mod test_util;

pub use helpers::{redirect_to_https, AcmeHttp01};
pub use runtime::{refresh_ocsp_staples, reload_certificates, AccessEntry, AccessLog, ErrorLog, Limits, Reloader, Server, ServerBuilder, ServerHandle, Stats};

use crate::tls::server::ServerStream;
use crate::tls::Duplex;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

// ------------------------------------------------------------------------------------------------ configuration

/// Limits and settings of the HTTP server. The defaults suit a server on the internet.
#[derive(Clone, Debug)]
pub struct HttpConfig {
    /// The longest HTTP/1.1 request line (method, target and version); longer is answered 414.
    pub max_request_line: usize,
    /// The most bytes of header fields in a request (HTTP/1.1: the header section and the trailers; HTTP/2: the decoded
    /// header list, as SETTINGS_MAX_HEADER_LIST_SIZE measures it); more is answered 431.
    pub max_header_bytes: usize,
    /// The most header fields in a request; more is answered 431.
    pub max_headers: usize,
    /// The largest request body taken, if any limit: a larger `Content-Length` is answered 413 before the handler sees
    /// the request, and a body that grows past it fails to read.
    pub max_body: Option<u64>,
    /// After this many requests on one HTTP/1.1 connection, the last response says `Connection: close`.
    pub max_requests_per_connection: usize,
    /// How much of a request body the handler did not read the server reads past to keep an HTTP/1.1 connection; with
    /// more left over, the connection is closed after the response.
    pub drain_limit: u64,
    /// A `Server` header for every response, if any.
    pub server_header: Option<String>,
    /// HTTP/2.
    pub h2: H2Config,
}

impl Default for HttpConfig {
    fn default() -> HttpConfig {
        HttpConfig {
            max_request_line: 8 * 1024,
            max_header_bytes: 64 * 1024,
            max_headers: 100,
            max_body: Some(64 << 20),
            max_requests_per_connection: 1000,
            drain_limit: 256 * 1024,
            server_header: None,
            h2: H2Config::default(),
        }
    }
}

/// HTTP/2 settings and the limits on what a client may make the server do.
#[derive(Clone, Debug)]
pub struct H2Config {
    /// SETTINGS_MAX_CONCURRENT_STREAMS: the requests a client may have open at once. A stream the client resets keeps its
    /// place until its handler has returned, so that resets cannot make the server run more handlers than this.
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE: how much of a request body may wait unread, per stream.
    pub stream_window: u32,
    /// The connection's window: how much of all request bodies may wait unread.
    pub connection_window: u32,
    /// SETTINGS_MAX_FRAME_SIZE.
    pub max_frame_size: u32,
    /// SETTINGS_HEADER_TABLE_SIZE: the HPACK table the client may use.
    pub header_table_size: u32,
    /// How much response data a handler may have waiting to be sent, per stream, before its writes wait.
    pub stream_send_buffer: usize,
    /// The connection's floods (each a number of frames, refilled at a tenth of it per second): resets of streams by the
    /// client and streams refused, SETTINGS, PING, empty frames (DATA without data or END_STREAM, empty HEADERS and
    /// CONTINUATION), PRIORITY (and frames of unknown types), and window updates of less than 128 bytes. Past one, the
    /// connection is closed with ENHANCE_YOUR_CALM.
    pub flood_resets: u32,
    pub flood_settings: u32,
    pub flood_pings: u32,
    pub flood_empty: u32,
    pub flood_priority: u32,
    pub flood_small_updates: u32,
    /// The most CONTINUATION frames one header block may take.
    pub max_continuations: u32,
}

impl Default for H2Config {
    fn default() -> H2Config {
        H2Config {
            max_concurrent_streams: 100,
            stream_window: 1 << 20,
            connection_window: 4 << 20,
            max_frame_size: 16_384,
            header_table_size: 4096,
            stream_send_buffer: 256 * 1024,
            flood_resets: 200,
            flood_settings: 50,
            flood_pings: 100,
            flood_empty: 200,
            flood_priority: 1000,
            flood_small_updates: 1000,
            max_continuations: 32,
        }
    }
}

// ------------------------------------------------------------------------------------------------ the connection

/// What is known about the connection a request came on.
#[derive(Clone, Debug, Default)]
pub struct ConnInfo {
    /// The client's address.
    pub peer: Option<SocketAddr>,
    /// The address the client connected to.
    pub local: Option<SocketAddr>,
    /// The TLS session, if the connection is over TLS.
    pub tls: Option<TlsInfo>,
}

impl ConnInfo {
    /// The addresses of a TCP connection.
    pub fn of(stream: &TcpStream) -> ConnInfo {
        ConnInfo { peer: stream.peer_addr().ok(), local: stream.local_addr().ok(), tls: None }
    }
}

/// What the TLS handshake settled.
#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    /// The name the client asked for (SNI).
    pub server_name: Option<String>,
    /// The ALPN protocol chosen.
    pub alpn: Option<String>,
    /// The cipher suite, by its IANA name.
    pub cipher_suite: Option<&'static str>,
    /// Whether the session was resumed from a ticket.
    pub resumed: bool,
    /// The client's certificate chain (DER, leaf first), if it presented one that the server checked.
    pub client_certificates: Vec<Vec<u8>>,
}

impl TlsInfo {
    fn of<S: Read + Write>(stream: &ServerStream<S>) -> TlsInfo {
        TlsInfo {
            server_name: stream.server_name().map(str::to_string),
            alpn: stream.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
            cipher_suite: stream.cipher_suite().map(|s| s.name()),
            resumed: stream.is_resumed(),
            client_certificates: stream.peer_certificates().to_vec(),
        }
    }
}

/// A socket the server can run a connection on: TCP, or a Unix socket.
pub trait Socket: Duplex + Send + 'static {
    /// Sets the socket's read timeout.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Sets the socket's write timeout.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Shuts the socket down in both directions (the other handles to it too).
    fn shutdown(&self);
    /// Shuts down the sending direction only.
    fn shutdown_write(&self);
}

impl Socket for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
    fn shutdown(&self) {
        let _ = TcpStream::shutdown(self, std::net::Shutdown::Both);
    }
    fn shutdown_write(&self) {
        let _ = TcpStream::shutdown(self, std::net::Shutdown::Write);
    }
}

#[cfg(unix)]
impl Socket for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, timeout)
    }
    fn shutdown(&self) {
        let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Both);
    }
    fn shutdown_write(&self) {
        let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Write);
    }
}

/// The transport of an HTTP/1.1 connection, which an upgrade takes apart into a reading and a writing handle.
pub(crate) trait Transport: Read + Write + Send + 'static {
    /// A handle that reads and one that writes, used at once from two threads.
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)>;
    /// Before closing after a refusal: stop writing and read what the client is still sending, a little
    /// ([`runtime::linger`]).
    fn linger(&mut self) {}
}

impl<S: Socket> Transport for S {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let other = self.duplicate()?;
        Ok((self, Box::new(other)))
    }
    fn linger(&mut self) {
        runtime::linger(self);
    }
}

/// An accepted TLS connection over a socket.
struct Tls<S: Socket>(ServerStream<S>);

impl<S: Socket> Read for Tls<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Socket> Write for Tls<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<S: Socket> Transport for Tls<S> {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (r, w) = self.0.split()?;
        Ok((Box::new(r), Box::new(w)))
    }
    fn linger(&mut self) {
        let _ = self.0.close();
        runtime::linger(self.0.get_mut());
    }
}

/// Serves one TLS connection until it ends: HTTP/2 if ALPN chose `h2`, HTTP/1.1 otherwise; closed at once if it chose
/// `acme-tls/1` (an ACME validator, see [`acme::AcmeTlsAlpn01`]). `info.tls` is filled in from the stream.
pub fn serve_tls<S: Socket>(stream: ServerStream<S>, info: ConnInfo, handler: Arc<dyn Handler>, config: &HttpConfig) -> io::Result<()> {
    serve_tls_ctl(stream, info, handler, config, runtime::Ctl::detached())
}

pub(crate) fn serve_tls_ctl<S: Socket>(stream: ServerStream<S>, mut info: ConnInfo, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<runtime::Ctl>) -> io::Result<()> {
    let tls = TlsInfo::of(&stream);
    if stream.alpn_protocol() == Some(crate::tls::server::ACME_TLS_1) {
        // an ACME validator, which has what it came for (the TLS-ALPN-01 challenge certificate) and sends nothing more
        let mut stream = stream;
        return stream.close();
    }
    let h2 = tls.alpn.as_deref() == Some("h2");
    info.tls = Some(tls);
    if h2 {
        let (r, w) = stream.split()?;
        h2::serve(Box::new(r), Box::new(w), Arc::new(info), handler, config, ctl)
    } else {
        h1::serve(Box::new(Tls(stream)), Arc::new(info), handler, config, ctl)
    }
}

/// Serves one plain connection until it ends: HTTP/1.1, or HTTP/2 if the client begins with the HTTP/2 connection preface
/// ("prior knowledge", RFC 9113 section 3.3).
pub fn serve_plain<S: Socket>(socket: S, info: ConnInfo, handler: Arc<dyn Handler>, config: &HttpConfig) -> io::Result<()> {
    serve_plain_ctl(socket, info, handler, config, runtime::Ctl::detached())
}

pub(crate) fn serve_plain_ctl<S: Socket>(socket: S, info: ConnInfo, handler: Arc<dyn Handler>, config: &HttpConfig, ctl: Arc<runtime::Ctl>) -> io::Result<()> {
    let mut socket = socket;
    if let Some(timer) = &ctl.timer {
        timer.until(std::time::Instant::now() + ctl.limits.idle_timeout);
    }
    // the first bytes say which: "PRI * HTTP/2.0" cannot begin an HTTP/1.1 request the server would take
    let mut first = Vec::new();
    let mut buf = [0u8; 24];
    while first.len() < h2::PREFACE.len() && h2::PREFACE.starts_with(&first) {
        let n = socket.read(&mut buf[..h2::PREFACE.len() - first.len()])?;
        if n == 0 {
            break;
        }
        first.extend_from_slice(&buf[..n]);
    }
    let info = Arc::new(info);
    if first == h2::PREFACE {
        let writer = socket.duplicate()?;
        return h2::serve_after_preface(Box::new(socket), Box::new(writer), info, handler, config, ctl);
    }
    h1::serve_with(Box::new(socket), first, info, handler, config, ctl)
}

/// Serves one plain connection that must be HTTP/2 with prior knowledge (a listener for HTTP/2 alone, behind a proxy
/// that speaks it, say): a client that does not begin with the connection preface gets a GOAWAY.
pub fn serve_h2c<S: Socket>(socket: S, info: ConnInfo, handler: Arc<dyn Handler>, config: &HttpConfig) -> io::Result<()> {
    let writer = socket.duplicate()?;
    h2::serve(Box::new(socket), Box::new(writer), Arc::new(info), handler, config, runtime::Ctl::detached())
}

// ------------------------------------------------------------------------------------------------ handlers

/// What answers requests. Implemented for every `Fn(Request) -> Response + Send + Sync`.
///
/// It is called on the connection's thread for HTTP/1.1 (one request at a time, in order) and on a thread of its own for
/// each HTTP/2 stream. A handler that panics gets the client a 500 (if nothing has been sent yet) and the connection
/// closed.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> Response;
}

impl<F: Fn(Request) -> Response + Send + Sync + 'static> Handler for F {
    fn handle(&self, request: Request) -> Response {
        self(request)
    }
}

/// Runs the handler, turning a panic into a 500 that closes the connection.
pub(crate) fn call(handler: &dyn Handler, request: Request) -> (Response, bool) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| handler.handle(request))) {
        Ok(r) => (r, false),
        Err(_) => (Response::text(500, "internal server error\n"), true),
    }
}

/// The version of HTTP a request came in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
    Http2,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
            Version::Http2 => "HTTP/2",
        })
    }
}

/// A request, as the handler gets it: the head, read and checked, and the body still to be read.
pub struct Request {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) authority: String,
    pub(crate) scheme: String,
    pub(crate) version: Version,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Body,
    pub(crate) info: Arc<ConnInfo>,
    pub(crate) interim: Option<Interim>,
    /// The connection's control, for a handler of this crate that takes the connection over (the scanning proxy's
    /// CONNECT): HTTP/1.1 under the runtime.
    pub(crate) ctl: Option<Arc<runtime::Ctl>>,
}

/// Sends an interim (1xx) response on the request's connection or stream.
pub(crate) type Interim = Arc<dyn Fn(u16, &[(String, String)]) -> io::Result<()> + Send + Sync>;

impl Request {
    /// The method, as sent (methods are case-sensitive).
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target as sent: a path and query (`/a/b?c`), a whole URL (to a proxy), `host:port` (CONNECT) or `*`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The path of the target, without the query: `/a/b` (and for a whole URL, its path; empty for CONNECT and `*`).
    pub fn path(&self) -> &str {
        let t = self.target.as_str();
        let t = if t.starts_with('/') {
            t
        } else if let Some(rest) = t.find("://").map(|i| &t[i + 3..]) {
            rest.find(['/', '?']).map_or("/", |i| if rest[i..].starts_with('/') { &rest[i..] } else { "/" })
        } else {
            return "";
        };
        t.split(['?', '#']).next().unwrap_or("")
    }

    /// The query of the target (after `?`), if there is one.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or(""))
    }

    /// The host (and port) the request is for: `:authority` in HTTP/2, the authority of a whole-URL target, or `Host`.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// `https` over TLS, `http` otherwise (HTTP/2: `:scheme` as sent).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn version(&self) -> Version {
        self.version
    }

    /// The header fields, names in lower case, in the order they came (HTTP/2's pseudo-headers are not among them).
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first field with this name (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Every field with this name (any case), in order.
    pub fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The length of the body, if the client said (`Content-Length`).
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    /// The body, to read.
    pub fn body(&mut self) -> &mut Body {
        &mut self.body
    }

    /// The body, for a handler that keeps it (to read on another thread, say).
    pub fn into_body(self) -> Body {
        self.body
    }

    /// Reads the whole body, refusing one longer than `limit` bytes.
    pub fn read_body(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        (&mut self.body).take(limit as u64 + 1).read_to_end(&mut out)?;
        if out.len() > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the request body is longer than the handler takes"));
        }
        Ok(out)
    }

    /// The connection the request came on.
    pub fn connection(&self) -> &ConnInfo {
        &self.info
    }

    /// Sends an interim response now, before the final one: 103 Early Hints (RFC 8297), say, with `link` fields for what
    /// the page will need. Only 102 to 199 (100 is the server's, sent when the body is first read; 101 is
    /// [`Response::upgrade`]); not to an HTTP/1.0 client, which would not understand it (that is not an error: nothing is
    /// sent); an error once the final response has begun.
    pub fn send_interim(&self, status: u16, headers: &[(&str, &str)]) -> io::Result<()> {
        if !(102..=199).contains(&status) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "an interim response is 102 to 199"));
        }
        let fields: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.to_string())).collect();
        if fields.iter().any(|(n, v)| n.is_empty() || !n.bytes().all(is_tchar) || !is_field_value(v)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "an interim response's fields are not well formed"));
        }
        match &self.interim {
            Some(send) => send(status, &fields),
            None => Ok(()),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").field("method", &self.method).field("target", &self.target).field("authority", &self.authority).field("version", &self.version).finish_non_exhaustive()
    }
}

/// Where a request body comes from.
pub(crate) trait BodySource: Send {
    /// Reads some of the body; 0 at its end.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// The trailers, once the body has been read to its end.
    fn trailers(&self) -> Vec<(String, String)>;
}

/// A request body: implements [`Read`]. Reading it to its end makes the trailers available, if the client sent any.
pub struct Body {
    source: Option<Box<dyn BodySource>>,
    ended: bool,
    trailers: Vec<(String, String)>,
}

impl Body {
    pub(crate) fn new(source: Option<Box<dyn BodySource>>) -> Body {
        Body { ended: source.is_none(), source, trailers: Vec::new() }
    }

    /// A body that is these bytes (for testing handlers).
    pub fn from_bytes(bytes: Vec<u8>) -> Body {
        struct Bytes(io::Cursor<Vec<u8>>);
        impl BodySource for Bytes {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
            fn trailers(&self) -> Vec<(String, String)> {
                Vec::new()
            }
        }
        Body::new(Some(Box::new(Bytes(io::Cursor::new(bytes)))))
    }

    /// The trailers (names in lower case), once the body has been read to its end; empty before, or if there were none.
    pub fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    /// Whether the body has been read to its end.
    pub fn is_ended(&self) -> bool {
        self.ended
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.ended || buf.is_empty() {
            return Ok(0);
        }
        let Some(source) = self.source.as_mut() else { return Ok(0) };
        let n = source.read(buf)?;
        if n == 0 {
            self.ended = true;
            self.trailers = source.trailers();
        }
        Ok(n)
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body").field("ended", &self.ended).finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------------------------------------ responses

/// What a response body is.
pub enum ResponseBody {
    Empty,
    Bytes(Vec<u8>),
    /// Read to its end, or to `length` bytes if that is given (and then sent with that `Content-Length`).
    Reader { reader: Box<dyn Read + Send>, length: Option<u64> },
    /// Called with a writer once the head is sent; what it writes is the body.
    Stream(Box<dyn FnOnce(&mut BodyWriter<'_>) -> io::Result<()> + Send>),
    /// For a 2xx answer to CONNECT or a 101: called with the connection itself once the head is sent.
    Upgrade(Box<dyn FnOnce(Upgraded) + Send>),
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseBody::Empty => f.write_str("Empty"),
            ResponseBody::Bytes(b) => write!(f, "Bytes({} bytes)", b.len()),
            ResponseBody::Reader { length, .. } => write!(f, "Reader {{ length: {length:?} }}"),
            ResponseBody::Stream(_) => f.write_str("Stream"),
            ResponseBody::Upgrade(_) => f.write_str("Upgrade"),
        }
    }
}

/// A response: a status, header fields and a body. `Content-Length`, `Transfer-Encoding` and `Connection` are the
/// server's to write (a handler's are dropped; a handler's `Connection: close` closes the connection after the response),
/// and so is `Date` unless the handler gives one.
#[derive(Debug)]
pub struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: ResponseBody,
}

impl Response {
    /// A response with no body.
    pub fn new(status: u16) -> Response {
        Response { status, headers: Vec::new(), body: ResponseBody::Empty }
    }

    /// A text response (`text/plain; charset=utf-8`).
    pub fn text(status: u16, text: impl Into<String>) -> Response {
        Response::bytes(status, "text/plain; charset=utf-8", text.into().into_bytes())
    }

    /// A response with these bytes and this `Content-Type`.
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        Response { status, headers: vec![("content-type".into(), content_type.into())], body: ResponseBody::Bytes(body) }
    }

    /// A response whose body is read from `reader` as it is sent, `length` bytes if given.
    pub fn reader(status: u16, reader: impl Read + Send + 'static, length: Option<u64>) -> Response {
        Response { status, headers: Vec::new(), body: ResponseBody::Reader { reader: Box::new(reader), length } }
    }

    /// A response whose body `write` writes once the head is sent (and may end with trailers).
    pub fn stream(status: u16, write: impl FnOnce(&mut BodyWriter<'_>) -> io::Result<()> + Send + 'static) -> Response {
        Response { status, headers: Vec::new(), body: ResponseBody::Stream(Box::new(write)) }
    }

    /// A 2xx answer to CONNECT, or a 101 (with its `Upgrade` field): once the head is sent, `then` gets the connection.
    pub fn upgrade(status: u16, then: impl FnOnce(Upgraded) + Send + 'static) -> Response {
        Response { status, headers: Vec::new(), body: ResponseBody::Upgrade(Box::new(then)) }
    }

    /// A redirect to `location`.
    pub fn redirect(status: u16, location: &str) -> Response {
        Response::new(status).with_header("location", location)
    }

    /// Adds a header field.
    pub fn with_header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn body(&self) -> &ResponseBody {
        &self.body
    }

    /// The first field with this name (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// What a [`BodyWriter`] writes into.
pub(crate) trait BodySink {
    fn write_body(&mut self, data: &[u8]) -> io::Result<()>;
    fn flush_body(&mut self) -> io::Result<()>;
}

/// Writes a streamed response body ([`Response::stream`]). Writes are buffered a little; [`flush`](Write::flush) sends what
/// is buffered.
pub struct BodyWriter<'a> {
    pub(crate) sink: &'a mut dyn BodySink,
    pub(crate) trailers: Vec<(String, String)>,
    pub(crate) written: u64,
}

impl BodyWriter<'_> {
    /// Trailers to end the body with (HTTP/2, and chunked HTTP/1.1; dropped when the body is not chunked).
    pub fn set_trailers(&mut self, trailers: Vec<(String, String)>) {
        self.trailers = trailers;
    }

    /// The bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }
}

impl Write for BodyWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink.write_body(buf)?;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush_body()
    }
}

/// A connection handed to the handler after a 2xx answer to CONNECT or a 101 ([`Response::upgrade`]): bytes in both
/// directions. Over HTTP/1.1 it is the connection itself (the TLS session, if there is one); over HTTP/2 it is the stream.
/// [`split`](Upgraded::split) gives a half for each direction, for two threads.
pub struct Upgraded {
    pub(crate) reader: Box<dyn Read + Send>,
    pub(crate) writer: Box<dyn Write + Send>,
}

impl Upgraded {
    /// The half that reads and the half that writes.
    pub fn split(self) -> (Box<dyn Read + Send>, Box<dyn Write + Send>) {
        (self.reader, self.writer)
    }
}

impl Read for Upgraded {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for Upgraded {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// ------------------------------------------------------------------------------------------------ shared checks

/// The characters of a token (RFC 9110 section 5.6.2): field names and methods.
pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Whether `v` may be a field value: visible characters, spaces and tabs (and UTF-8), no other control characters, and no
/// white space at either end.
pub(crate) fn is_field_value(v: &str) -> bool {
    v.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f)) && v == v.trim_matches([' ', '\t'])
}

/// The reason phrase of a status code.
pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// The header fields of a response as the server sends them: the handler's, checked, without the ones the server writes
/// itself, and `Date` and `Server` added. `Err` if the handler's are not well formed (the response becomes a 500).
/// Also says whether the handler asked for the connection to be closed, and its `Content-Length` if it gave one.
pub(crate) struct Head {
    pub(crate) fields: Vec<(String, String)>,
    pub(crate) close: bool,
    pub(crate) content_length: Option<u64>,
}

pub(crate) fn response_head(headers: &[(String, String)], config: &HttpConfig) -> Result<Head, String> {
    let mut fields = Vec::with_capacity(headers.len() + 2);
    let mut close = false;
    let mut content_length = None;
    let mut date = false;
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(format!("the handler's field name {name:?} is not a token"));
        }
        if !value.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f)) {
            return Err(format!("the handler's value of {name} has a control character"));
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "content-length" => content_length = value.trim().parse().ok(),
            "connection" => close |= value.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")),
            "transfer-encoding" | "keep-alive" | "proxy-connection" => {}
            _ => {
                date |= lower == "date";
                fields.push((lower, value.trim_matches([' ', '\t']).to_string()));
            }
        }
    }
    if !date {
        fields.push(("date".into(), date::now()));
    }
    if let Some(server) = &config.server_header {
        if !fields.iter().any(|(n, _)| n == "server") {
            fields.push(("server".into(), server.clone()));
        }
    }
    Ok(Head { fields, close, content_length })
}
