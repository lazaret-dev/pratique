//! An HTTP client over TLS 1.3: HTTP/1.1, and HTTP/2 when asked for (or plain TCP, HTTP/1.1 only, when explicitly allowed).
//!
//! ```no_run
//! let client = pratique::Client::new()?.proxy_from_env();
//! let resp = client.get("https://example.com/")?;
//! println!("{} {}", resp.status, resp.text());
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! # Connections
//!
//! Connections are kept alive and reused (HTTP/1.1 persistent connections). When a response has
//! been read to its end and the connection is fit for another request, it waits in the client's
//! pool, shared by every clone of the [`Client`], and the next request to the same scheme, host,
//! port and proxy takes it instead of connecting and shaking hands again. A connection is only
//! reused when the response was framed (a Content-Length, chunked, or no body), the server did not
//! say `Connection: close`, nothing came after the message, and the socket is quiet when it is
//! taken out again. One that has gone stale (the server closed it while it waited) is replaced
//! by a new one, and a request that fails on a reused connection before any of the answer arrived
//! is sent once more on a new connection if it is idempotent (GET, HEAD, OPTIONS, TRACE, PUT,
//! DELETE, or any request with an `Idempotency-Key` header). Idle connections are closed after
//! [`pool_idle_timeout`](Client::pool_idle_timeout) (or the server's `Keep-Alive: timeout`, if
//! shorter) when the pool is next used; there is no background thread. [`keep_alive`](Client::keep_alive)
//! turns all of it off, and each request then says `Connection: close`.
//!
//! # Bodies
//!
//! [`send`](RequestBuilder::send) buffers the whole body, up to [`max_body_bytes`](Client::max_body_bytes).
//! [`send_stream`](RequestBuilder::send_stream) returns a [`ResponseStream`] as soon as the headers
//! are in: the status, headers and declared length are there to look at, and the body is read
//! from it as a [`Read`] as it arrives, with no memory proportional to its size and
//! no copy beyond the one out of the TLS layer, so a download can be hashed, unpacked and scanned
//! on the way. The size limit and the timeouts apply to a stream as they do to a buffered body.
//! Requests send `Accept-Encoding: identity`, unless the client was asked to decode compressed bodies (below).
//!
//! # Compressed bodies
//!
//! [`Client::decompress`] makes the client ask for `gzip` and `deflate` and undo them, with the bomb in mind: the
//! decoder is this crate's own ([`inflate`](crate::inflate)), written to produce no more than it is allowed, and the limits are the caller's.
//! The size of what comes out is limited by [`max_decoded_bytes`](Client::max_decoded_bytes) (by default the same number as
//! [`max_body_bytes`](Client::max_body_bytes), which limits the compressed bytes on the wire), a ratio can be limited too
//! ([`max_decode_ratio`](Client::max_decode_ratio)), and a body over a limit is an error ([`Error::Decode`]), never a cut one. Only a
//! single `gzip`, `x-gzip` or `deflate` is decoded; a response with another coding, or a list of them, comes as it is, with its
//! `Content-Encoding`, and so does one to `HEAD` or a 206 (a range of the encoded body). A decoded response has no `Content-Encoding`
//! and no `Content-Length` and says [`Response::uncompressed`]. The same options exist per request, on the [`RequestBuilder`].
//!
//! ```no_run
//! let client = pratique::Client::new()?.decompress(true).max_decoded_bytes(256 << 20);
//! let resp = client.get("https://example.com/data.json")?;
//! assert!(resp.uncompressed || resp.header("content-encoding").is_none());
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! # HTTP/2
//!
//! [`Client::http2`] turns on HTTP/2 for servers that choose it in the TLS handshake (ALPN `h2`); the rest of
//! the API is unchanged and [`Response::version`] says which protocol answered. All requests to one origin share one
//! connection, so a burst of parallel downloads needs one handshake, not one each:
//!
//! ```no_run
//! let client = pratique::Client::new()?.http2(true);
//! let resp = client.get("https://example.com/")?;
//! println!("{} {}", resp.version, resp.status);
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! The flow-control windows are 8 MiB per stream and 32 MiB per connection, with credit going back to the server
//! as the application reads, so a connection never holds more than 32 MiB of body that nobody has read, and a
//! fast path with a long delay is not left waiting for credit. One connection is read and decrypted by one thread
//! (and written by another); a transfer that is bounded by that is faster over several HTTP/1.1 connections.
//! Not done: the async client does not speak HTTP/2 (see `BACKLOG.md`, B-72), trailers are dropped, push is
//! refused and priorities are ignored.
//!
//! ```no_run
//! use std::io::Read;
//! let client = pratique::Client::new()?;
//! let mut resp = client.request("GET", "https://example.com/big.tgz").max_body_bytes(1 << 30).send_stream()?;
//! println!("{} bytes to come", resp.content_length.unwrap_or(0));
//! let mut chunk = [0u8; 64 * 1024];
//! while resp.read(&mut chunk)? > 0 { /* hash, unpack, scan */ }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! From async code, use the `*_async` methods (see [`crate::asyncio`]):
//!
//! ```no_run
//! # async fn demo() -> pratique::error::Result<()> {
//! let client = pratique::Client::new()?;
//! let resp = client.request("POST", "https://example.com/api").header("X-Id", "7").body("hi").send_async().await?;
//! # let _ = resp; Ok(()) }
//! ```
//!
//! # HTTP/3
//!
//! HTTP/3 is the caller's option and is off by default; without it the order is what it was: HTTP/2 for a server that
//! chooses it (with [`Client::http2`]), else HTTP/1.1. [`Client::http3`] makes the client use QUIC, over UDP, for an origin that has
//! said it offers it, in an `Alt-Svc` field of an ordinary response (`alt-svc: h3=":443"; ma=86400`); the first request to an origin
//! goes over TCP, as it would without the option, and learns that. [`Client::http3_eager`] tries QUIC for every origin without waiting
//! to be told. A network that does not carry QUIC costs one try (a handshake of a few seconds, at most) and then the origin is left to
//! TCP for minutes, and longer each time the same happens; the request that found out goes over TCP, and so does every
//! request that would have been spoken to over HTTP/3 and cannot be. The request, the response and the errors are the same as over HTTP/2
//! ([`Response::version`] says [`HttpVersion::Http3`]); the connection is shared by every request to the origin.
//!
//! ```no_run
//! let client = pratique::Client::new()?.http2(true).http3(true);
//! let first = client.get("https://example.com/")?;   // over TCP: HTTP/2 or HTTP/1.1; learns the Alt-Svc
//! let next = client.get("https://example.com/")?;    // over QUIC, if the origin offered it
//! println!("{} then {}", first.version, next.version);
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! Not done: the async client does not speak HTTP/3 (the `*_async` methods of this client do), 0-RTT, connection migration and
//! priorities are not there, and a request through a proxy is never sent over QUIC.
//!
//! # Host rules
//!
//! [`Client::allowed_hosts`] limits a client to the hosts of a [`HostRules`] (hosts, `host:port`, addresses, `*.example.com`); the rule is
//! applied to the request and to every redirect it follows, before anything connects, by the blocking and the async client alike. The
//! rule is loose unless it is told otherwise: [`one_label_wildcards`](HostRules::one_label_wildcards) makes `*.example.com` match exactly one
//! label, [`default_port_only`](HostRules::default_port_only) makes an entry match the default port only, and
//! [`Client::url_limits`] with [`UrlLimits::strict`] refuses a URL that is not https, has credentials, is not printable ASCII or is longer
//! than 2,048 bytes. [`Client::hop_headers`] gives each hop (the request and every redirect) the headers the hook says for the host it goes
//! to, which is where credentials belong: a token is sent to that host and does not follow a redirect to another.
//!
//! ```no_run
//! use pratique::http::{HostRules, UrlLimits};
//! let module = pratique::Client::new()?
//!     .allowed_hosts(HostRules::new(["api.example.com", "*.cdn.example.net"])?.one_label_wildcards(true).default_port_only(true))
//!     .url_limits(UrlLimits::strict());
//! let r = module.request("POST", "https://api.example.com/v1/search").header("Accept", "application/json")
//!     .header("Content-Type", "application/json").body(r#"{"q":"tools"}"#).send()?;
//! assert!(module.get("https://elsewhere.example.org/").is_err()); // not in the rule: nothing is sent
//! # let _ = r; Ok::<(), pratique::error::Error>(())
//! ```

mod altsvc;
mod async_client;
pub mod connect;
mod cookie;
mod crl_source;
mod ocsp_source;
// TUF over HTTPS, and Sigstore's trusted root and npm's keys through it (BACKLOG B-82)
pub mod tuf_source;
mod decode;
#[cfg(test)]
mod decode_tests;
#[cfg(test)]
mod expect_tests;
#[cfg(test)]
mod async_timeout_tests;
#[cfg(test)]
mod revocation_fetch_tests;
#[cfg(test)]
mod cookie_tests;
mod hostrules;
pub mod schedule;
// the HTTP/2 protocol layers (sans-IO) and the blocking client's transport on top of them
mod h2;
// HTTP/3: QPACK now, then the frames and the connection over `quic`
mod h3;
mod h2_transport;
// the blocking client's transport over HTTP/3: a UDP socket, reader and timer threads, the Alt-Svc cache
mod h3_transport;
// a small HTTP/2 server for tests and tools: the same opt-in as `tls::server`
#[cfg(any(test, feature = "server"))]
pub mod h2_server;
mod idle;
pub(crate) mod parser;
mod stream;
#[cfg(test)]
mod egress_tests;
#[cfg(pratique_fuzzing)]
mod egress_fuzz;
#[cfg(test)]
mod h2_client_tests;
#[cfg(test)]
mod h2_server_tests;
#[cfg(test)]
mod h2_testserver;
#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod establish_tests;
#[cfg(test)]
mod schedule_tests;
#[cfg(test)]
mod testserver;
pub mod url;
pub(crate) mod wire;

pub use async_client::{AsyncClient, AsyncRequestBuilder, AsyncResponseStream, Connect, ThreadConnector};
pub use cookie::CookieJar;
pub use crl_source::HttpCrlSource;
pub use ocsp_source::HttpOcspSource;
pub use tuf_source::TufSource;
pub use hostrules::HostRules;
pub use schedule::{Batch, Scheduler};
pub use stream::ResponseStream;
pub use url::{Url, UrlLimits};

/// Entry points for the coverage-guided fuzzer in `fuzz/`; compiled only with
/// `--cfg pratique_fuzzing`. Not part of the API.
#[cfg(pratique_fuzzing)]
#[doc(hidden)]
pub mod fuzz_hooks {
    use super::parser::Buffered;
    use super::wire::Limits;

    // the HTTP/2 layers: header blocks, frames, the client's connection and the server's
    pub use super::h3::fuzz_hooks::{qpack_decoder as h3_qpack_decoder, qpack_encoder as h3_qpack_encoder, qpack_example_decoder_scripts as h3_qpack_example_decoder_scripts, qpack_example_encoder_scripts as h3_qpack_example_encoder_scripts, qpack_example_exchange_scripts as h3_qpack_example_exchange_scripts, qpack_exchange as h3_qpack_exchange, frames as h3_frames, frame_example_streams as h3_frame_example_streams, connection_exchange as h3_connection_exchange, connection_example_scripts as h3_connection_example_scripts};
    // what a client with a rule about hosts, limits on a URL and a hook for each hop decides about a request and its redirects
    pub use super::egress_fuzz::{egress, example_inputs as egress_example_inputs};
    pub use super::h2::fuzz_hooks::{client as h2_client, example_client_flights as h2_example_client_flights, example_header_blocks as h2_example_header_blocks, example_server_flights as h2_example_server_flights, frames as h2_frames, hpack as h2_hpack};

    /// The value of an `Alt-Svc` field (`data` read as text): see `altsvc.rs`.
    pub fn alt_svc(data: &[u8]) {
        super::altsvc::check(&String::from_utf8_lossy(data));
    }

    /// Values of `Alt-Svc` that real servers send, and some that are wrong.
    pub fn alt_svc_examples() -> Vec<Vec<u8>> {
        [
            r#"h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000"#,
            r#"h3=":443"; ma=86400"#,
            r#"h3="alt.example.com:8443"; ma=60; persist=1"#,
            r#"h3="[2001:db8::1]:443""#,
            r#"h2=":443"; ma=3600, h3=":443""#,
            "clear",
            r#"h3=":0""#,
            r#"h3=":443"; ma=99999999999999999999"#,
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect()
    }

    /// Feeds `data[4..]` to the response parser in pieces; `data[..4]` choose the request method,
    /// the header and body limits and the piece size. Returns the status and body length of a
    /// response that parsed. Panics if a body is longer than the limit the parser was given.
    pub fn response(data: &[u8]) -> Option<(u16, usize)> {
        if data.len() < 4 {
            return None;
        }
        let method = ["GET", "HEAD", "POST", "CONNECT"][(data[0] % 4) as usize];
        let limits = Limits { max_header_bytes: 64 + data[1] as usize * 16, max_body_bytes: data[2] as u64 * 16 };
        let piece = 1 + (data[3] as usize % 97);
        let mut parser = Buffered::new(method, limits);
        let mut rest = &data[4..];
        while !parser.is_done() {
            if rest.is_empty() {
                if parser.finish_eof().is_err() {
                    return None;
                }
                break;
            }
            let want = parser.max_read().min(piece).min(rest.len());
            if parser.feed(&rest[..want]).is_err() {
                return None;
            }
            rest = &rest[want..];
        }
        if !parser.is_done() {
            return None;
        }
        let r = parser.into_response();
        assert!(r.body.len() as u64 <= limits.max_body_bytes, "a body longer than the limit was accepted");
        Some((r.status, r.body.len()))
    }
}

/// The server's connection, for the fuzzer (see `h2/fuzz_hooks.rs`). A module of its own because the line between
/// the pure part and the net part is checked line by line, and a `cfg` on a function inside a module is not one it
/// reads.
#[cfg(all(pratique_fuzzing, feature = "server"))]
#[doc(hidden)]
pub mod fuzz_hooks_server {
    pub fn h2_server(data: &[u8]) {
        super::h2::fuzz_hooks::server(data)
    }
}

use crate::asyncio::net::{deadline_error, Io};
use crate::asyncio::slots::{Permit, Slots};
use schedule::{Interrupt, Membership, Running, Ticket};
use crate::asyncio::{BlockingTask, Pool};
use crate::error::{Error, Refused, RefusedBy, Result};
use crate::pem::base64_encode;
use crate::tls::{ClientConfig, TlsStream, TlsVersion};
use h2_transport::{Acquired, Registry, StartError, Waits};
use h3_transport::{DialOptions, Registry as H3Registry};
use idle::{IdlePool, Key, Policy};
use std::future::Future;
use std::io::{self, Read, Write};
use connect::Establish;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use decode::{DecodeLimits, RequestOpts};
use stream::{BodyReader, Conn, Failure, Home, MuxBody};
use wire::Limits;

/// Request bodies up to this size are serialized together with the head into one buffer.
const SMALL_BODY: usize = 16 * 1024;

/// What a request must share with another to use the same connection.
pub(crate) fn pool_key(url: &Url, proxy: Option<&Proxy>, min_tls: TlsVersion) -> Key {
    Key {
        tls: url.is_https(),
        host: url.host.to_ascii_lowercase(),
        port: url.port,
        proxy: proxy.map(|p| (p.host.to_ascii_lowercase(), p.port, p.auth.clone())),
        min_tls,
    }
}

/// A redirect's body is read and dropped, so that its connection can be used again, when it is
/// no larger than this; a larger one costs more than a new connection.
pub(crate) const REDIRECT_BODY_LIMIT: u64 = 64 * 1024;

/// True if a request may be sent again when its connection turns out to have been closed before
/// anything came back: the methods RFC 9110 calls idempotent, or any request that carries an
/// `Idempotency-Key`.
pub(crate) fn is_replayable(method: &str, headers: &[(String, String)]) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE") || headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"))
}

/// The protocol a response came over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpVersion {
    Http11,
    Http2,
    Http3,
}

impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
            HttpVersion::Http3 => "HTTP/3",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// The reason phrase of the status line; empty over HTTP/2 and HTTP/3, which have none.
    pub reason: String,
    /// The protocol the response came over.
    pub version: HttpVersion,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The URL that produced this response (after redirects).
    pub url: Url,
    /// The version of TLS the response came over (`None` over plain http). HTTP/3 is always TLS 1.3.
    pub tls_version: Option<TlsVersion>,
    /// True if the body came compressed (`gzip` or `deflate`) and this client undid that, because it was asked to (see
    /// [`Client::decompress`]): `headers` then has no `Content-Encoding` and no `Content-Length`, which described the bytes on the wire.
    pub uncompressed: bool,
}

impl Response {
    /// First header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// All headers with this (case-insensitive) name.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as text; invalid UTF-8 is replaced.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// "user:password" for Basic proxy authentication.
    pub auth: Option<String>,
}

impl Proxy {
    /// Parses `http://[user:pass@]host:port` (or just `host:port`).
    pub fn parse(s: &str) -> Result<Proxy> {
        let s = s.trim();
        let with_scheme = if s.contains("://") { s.to_string() } else { format!("http://{}", s) };
        if with_scheme.to_ascii_lowercase().starts_with("https://") {
            return Err(Error::Http("proxies reached over TLS are not supported; use an http:// proxy URL".into()));
        }
        let u = Url::parse(&with_scheme)?;
        if u.scheme != "http" {
            return Err(Error::Http("unsupported proxy scheme".into()));
        }
        let port = if with_scheme.rsplit('/').next().map_or(false, |h| h.contains(':') && !h.ends_with(']')) { u.port } else { 8080 };
        Ok(Proxy { host: u.host, port, auth: u.userinfo })
    }
}

#[derive(Clone)]
enum ProxySetting {
    None,
    FromEnv,
    Explicit(Proxy),
}

/// An HTTP(S) client. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    tls: ClientConfig,
    timeout: Duration,
    connect_timeout: Duration,
    total_timeout: Option<Duration>,
    pool: Option<Pool>,
    max_redirects: usize,
    user_agent: String,
    allow_insecure_http: bool,
    limits: Limits,
    proxy: ProxySetting,
    policy: Policy,
    /// Connections waiting for another request; shared by the clones of this client.
    idle: Arc<IdlePool<Conn>>,
    /// HTTP/2, if switched on: see [`Client::http2`].
    h2: Option<H2Support>,
    /// HTTP/3, if switched on: see [`Client::http3`].
    h3: Option<H3Support>,
    /// The hosts a request may go to, if there is a rule: see [`Client::allowed_hosts`].
    hosts: Option<Arc<HostRules>>,
    /// What the URL of a request, and of every redirect, may not be: see [`Client::url_limits`].
    url_limits: UrlLimits,
    /// What gives each hop its own headers (its host's credentials): see [`Client::hop_headers`].
    hop_hook: Option<Arc<HopHook>>,
    /// Whether compressed bodies are decoded: see [`Client::decompress`].
    decompress: bool,
    /// How much a decoded body may come to: see [`Client::max_decoded_bytes`].
    decode: DecodeLimits,
    /// How long a request that says `Expect: 100-continue` waits for the go-ahead: see [`Client::expect_continue_timeout`].
    expect_timeout: Duration,
    /// Where cookies are kept, if anywhere: see [`Client::cookie_jar`].
    cookies: Option<CookieJar>,
    /// How connections are made: the resolver and its cache, and the delay between attempts (see [`Client::dns_cache`] and
    /// [`Client::connection_attempt_delay`]).
    establish: Establish,
    /// The per-host limit on connections, if there is one: see [`Client::max_connections_per_host`].
    conn_limit: Option<Arc<Slots>>,
    /// What lets requests go, if anything: see [`Client::scheduler`].
    scheduler: Option<Scheduler>,
    /// The batch every request of this client belongs to, if any: see [`Client::in_batch`].
    batch: Option<Batch>,
}

/// What a hop hook is told about the request that is about to be sent: see [`Client::hop_headers`].
#[derive(Clone, Copy, Debug)]
pub struct HopInfo<'a> {
    /// Where it goes: the URL of the request itself or of the redirect, after the client's host rule and the limits on a URL have allowed it
    /// (the hook never sees a URL that they refuse).
    pub url: &'a Url,
    /// The method it is sent with (a 303 makes a GET of a POST, and the hook is told so).
    pub method: &'a str,
    /// 0 for the request itself, 1 for the first redirect it is sent on, and so on.
    pub hop: usize,
    /// The URL whose redirect this is; `None` for the request itself.
    pub from: Option<&'a Url>,
}

impl HopInfo<'_> {
    /// Whether this hop goes to another origin (scheme, host or port) than the one that redirected to it. False for the request itself.
    pub fn crosses_origin(&self) -> bool {
        self.from.is_some_and(|from| from.origin() != self.url.origin())
    }
}

/// The headers the client sets itself, and that a caller's (or a hook's) of the same name does not replace.
const OWN_HEADERS: [&str; 3] = ["host", "connection", "content-length"];

/// What a hop hook is: see [`Client::hop_headers`].
type HopHook = dyn Fn(&HopInfo<'_>) -> Result<Vec<(String, String)>> + Send + Sync;

/// What a client that speaks HTTP/3 has besides the TCP machinery.
#[derive(Clone)]
struct H3Support {
    /// The connections and what is known of the origins' alternatives, shared by the clones of the client.
    registry: Arc<H3Registry>,
    /// QUIC is tried for origins that have not said they offer it (see [`Client::http3_eager`]).
    eager: bool,
}

/// What a client that speaks HTTP/2 has besides the HTTP/1.1 machinery.
#[derive(Clone)]
struct H2Support {
    /// The TLS settings with `h2` offered first and `http/1.1` second.
    tls: ClientConfig,
    /// The connections, shared by the clones of the client.
    registry: Arc<Registry>,
}

impl Client {
    /// A client that trusts the operating system's CA bundle.
    pub fn new() -> Result<Client> {
        Ok(Client::with_tls_config(ClientConfig::with_system_roots()?))
    }

    pub fn with_tls_config(tls: ClientConfig) -> Client {
        Client {
            tls,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            total_timeout: None,
            pool: None,
            max_redirects: 10,
            user_agent: concat!("pratique/", env!("CARGO_PKG_VERSION")).to_string(),
            allow_insecure_http: false,
            limits: Limits::default(),
            proxy: ProxySetting::None,
            policy: Policy::default(),
            idle: Arc::new(IdlePool::new()),
            h2: None,
            h3: None,
            hosts: None,
            url_limits: UrlLimits::new(),
            hop_hook: None,
            decompress: false,
            decode: DecodeLimits::default(),
            expect_timeout: Duration::from_secs(1),
            cookies: None,
            establish: Establish::default(),
            conn_limit: None,
            scheduler: None,
            batch: None,
        }
    }

    /// Read and write timeout for each socket operation.
    pub fn timeout(mut self, t: Duration) -> Client {
        self.timeout = t;
        self
    }

    /// Limit for making a connection (default 10 s): resolving the host name and connecting, over all its addresses
    /// (see [`connect`](crate::http::connect)).
    pub fn connect_timeout(mut self, t: Duration) -> Client {
        self.connect_timeout = t;
        self
    }

    /// How long a host name's addresses are kept after a lookup (default [`connect::DEFAULT_DNS_TTL`], 30 s; zero keeps
    /// none). The system's resolver does not say how long a record may be kept, so this one time is used for all. The
    /// cache is new, for this client and the clones made from it from now on (see [`connect`](crate::http::connect)).
    pub fn dns_cache(mut self, ttl: Duration) -> Client {
        self.establish.resolver = Arc::new(connect::Resolver::new(ttl));
        self
    }

    /// How long an attempt to connect to one of a host's addresses has before the next address is tried as well (RFC
    /// 8305, "Happy Eyeballs"; default [`connect::DEFAULT_ATTEMPT_DELAY`], 250 ms, kept between 10 ms and 2 s): what an
    /// address that does not answer costs (see [`connect`](crate::http::connect)).
    pub fn connection_attempt_delay(mut self, delay: Duration) -> Client {
        self.establish.attempt_delay = delay.clamp(connect::MIN_ATTEMPT_DELAY, connect::MAX_ATTEMPT_DELAY);
        self
    }

    /// At most `n` TCP connections to one host and port at a time, idle ones included (0, the default: no limit). A
    /// request that needs a new connection when there are `n` closes an idle one to that host that it cannot use (one
    /// made for another proxy or another TLS minimum), or else waits for one to close or to come back to the pool, which
    /// it then uses; it waits up to its deadline ([`total_timeout`](Client::total_timeout)) or, without one, the
    /// client's [`timeout`](Client::timeout). An HTTP/2 connection counts once however many requests it carries; HTTP/3
    /// connections are not counted. The count is shared by the clones made from this client from now on; an
    /// [`AsyncClient`] made from it keeps a count of its own.
    pub fn max_connections_per_host(mut self, n: usize) -> Client {
        self.conn_limit = (n > 0).then(|| Slots::new(n));
        self
    }

    /// Lets this client's requests go through `scheduler` (and its limits on requests in flight, in all and per host, and
    /// on bytes), which other clients, blocking or async, may share; see [`schedule`](crate::http::schedule).
    pub fn scheduler(mut self, scheduler: &Scheduler) -> Client {
        self.scheduler = Some(scheduler.clone());
        self
    }

    /// A client whose every request belongs to `batch` (unless the request names another): they share its deadline and
    /// are cancelled with it. See [`Batch`].
    pub fn in_batch(&self, batch: &Batch) -> Client {
        Client { batch: Some(batch.clone()), ..self.clone() }
    }

    /// Limit on the whole request, redirects included (default: none). The per-operation
    /// [`timeout`](Client::timeout) restarts on every read and write, so a server that sends one
    /// byte at a time can hold a request open indefinitely; this cannot be outlasted. Resolving a
    /// host name counts too (the lookup runs on a thread of its own, see [`connect`](crate::http::connect)).
    pub fn total_timeout(mut self, t: Duration) -> Client {
        self.total_timeout = Some(t);
        self
    }

    /// The worker threads the `*_async` methods run on (default: [`Pool::global`]).
    pub fn pool(mut self, pool: Pool) -> Client {
        self.pool = Some(pool);
        self
    }

    pub fn max_redirects(mut self, n: usize) -> Client {
        self.max_redirects = n;
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Client {
        self.user_agent = ua.into();
        self
    }

    /// Permits `http://` URLs. Off by default: this crate is an HTTPS client.
    pub fn allow_insecure_http(mut self, allow: bool) -> Client {
        self.allow_insecure_http = allow;
        self
    }

    /// Largest response body accepted, in bytes (default 64 MiB). Streamed bodies obey it too;
    /// [`RequestBuilder::max_body_bytes`] sets it for one request.
    pub fn max_body_bytes(mut self, n: u64) -> Client {
        self.limits.max_body_bytes = n;
        self
    }

    /// Decodes compressed response bodies (off by default): requests ask for `gzip, deflate` and a body that comes as a single `gzip`,
    /// `x-gzip` or `deflate` is decoded on the way, whether it is read whole, streamed or read by the async client. The caller gets
    /// the decoded bytes, no `Content-Encoding` and no `Content-Length` (they described the wire), and [`Response::uncompressed`]
    /// true. What is not decoded comes as it is: another coding, a list of codings, a response to `HEAD`, a 204, a 304, a 206 (part
    /// of the encoded body) and every response when the option is off; a request that sets its own `Accept-Encoding` keeps it,
    /// and a body it gets back in a coding that is known is decoded all the same. A request with a `Range` header does not ask.
    ///
    /// Compressed data from a stranger can be a bomb (about 1,000 times its size, and more with a stack of codings, which this client
    /// does not undo), so the decoder is held to [`max_decoded_bytes`](Client::max_decoded_bytes) (by default the same as
    /// [`max_body_bytes`](Client::max_body_bytes)) and, if set, [`max_decode_ratio`](Client::max_decode_ratio); a stream that would
    /// pass a limit fails with [`Error::Decode`] and is not delivered in part. The compressed stream
    /// must end where the body does (bytes after it are an error), an empty body is an empty body, and after a failure nothing more
    /// of the body is read (so its connection is closed, unless all of it had arrived). The decoder is the crate's own,
    /// [`inflate`](crate::inflate).
    pub fn decompress(mut self, on: bool) -> Client {
        self.decompress = on;
        self
    }

    /// The most bytes a decoded body may have (see [`decompress`](Client::decompress)); by default the same number as
    /// [`max_body_bytes`](Client::max_body_bytes), which limits the compressed body as it is on the wire. Set it higher to take large
    /// bodies that compress well, and keep it as low as the application can live with: it is the bound on what a hostile
    /// server can make this process write to memory (or to the sink of a stream).
    pub fn max_decoded_bytes(mut self, n: u64) -> Client {
        self.decode.max_output = Some(n);
        self
    }

    /// Refuses a decoded body that comes to more than `ratio` times its compressed size, once it is `floor` bytes long (0 for
    /// no ratio limit, the default). DEFLATE cannot exceed 1,032 to 1, and honest data that is nothing but one byte repeated gets
    /// near that, so a ratio below about 1,100 refuses such data; ordinary files stay under 20 to 1 and text under 10 to 1.
    pub fn max_decode_ratio(mut self, ratio: u64, floor: u64) -> Client {
        self.decode.max_ratio = ratio;
        self.decode.ratio_floor = floor;
        self
    }

    /// How long a request that says `Expect: 100-continue` (see [`RequestBuilder::expect_continue`]) waits for the server's go-ahead
    /// before it sends its body anyway (default one second, as curl does). Over HTTP/1.1, in the blocking client and the async
    /// one alike: HTTP/2 and HTTP/3 send the body with the head.
    pub fn expect_continue_timeout(mut self, wait: Duration) -> Client {
        self.expect_timeout = wait;
        self
    }

    /// Keeps the cookies that responses set in `jar` and sends them back (off by default: without a jar, `Set-Cookie` is ignored and
    /// no `Cookie` is sent but the caller's own). Each cookie goes back to the host that set it and to no other, whatever its `Domain`
    /// says, for the reasons [`CookieJar`] gives; the cookies of every response are kept, redirects included, and each hop of a
    /// request gets the cookies of its own host. A request that has its own `Cookie` header sends that one and none from the jar.
    /// The jar can be shared: give clones of one jar to several clients, and look into it or fill it with its own methods.
    pub fn cookie_jar(mut self, jar: CookieJar) -> Client {
        self.cookies = Some(jar);
        self
    }

    /// The cookie jar of this client, if it has one.
    pub fn cookies(&self) -> Option<&CookieJar> {
        self.cookies.as_ref()
    }

    /// The oldest TLS version spoken (TLS 1.2 by default; see [`ClientConfig::min_version`] for what TLS 1.2 here is and is not).
    /// `TlsVersion::Tls13` makes every request TLS 1.3 only, and no request can then loosen it; [`RequestBuilder::min_tls_version`]
    /// makes one request TLS 1.3 only. Each response says which version it came over ([`Response::tls_version`]).
    pub fn min_tls_version(mut self, version: TlsVersion) -> Client {
        self.tls.min_version = version;
        if let Some(h2) = &mut self.h2 {
            h2.tls.min_version = version;
        }
        self
    }

    /// Reuses connections for later requests (HTTP/1.1 keep-alive; on by default). Off, every
    /// request opens its own connection and says `Connection: close`. See the module documentation
    /// for what makes a connection fit for reuse.
    pub fn keep_alive(mut self, on: bool) -> Client {
        self.policy.keep_alive = on;
        self
    }

    /// How long an idle connection may wait for another request (default 90 s); a server that says
    /// `Keep-Alive: timeout=N` is believed if it asks for less. Expired connections are closed when
    /// the pool is next used.
    pub fn pool_idle_timeout(mut self, t: Duration) -> Client {
        self.policy.idle_timeout = t;
        self
    }

    /// The most idle connections kept for one host (default 8); 0 turns reuse off. Parallel
    /// requests each need their own connection, so a burst of more than this many leaves only this
    /// many behind.
    pub fn pool_max_idle_per_host(mut self, n: usize) -> Client {
        self.policy.max_idle_per_host = n;
        self
    }

    /// Closes every idle connection this client (and its clones) is holding.
    pub fn close_idle_connections(&self) {
        self.idle.clear();
        if let Some(h2) = &self.h2 {
            h2.registry.close_idle();
        }
        if let Some(h3) = &self.h3 {
            h3.registry.close_idle();
        }
    }

    /// The number of idle connections waiting for another request.
    pub fn idle_connections(&self) -> usize {
        self.idle.len() + self.h2.as_ref().map_or(0, |h2| h2.registry.idle()) + self.h3.as_ref().map_or(0, |h3| h3.registry.idle())
    }

    /// How many reads of the HTTP/2 sockets were made by callers waiting for their own responses, and how many by the
    /// connections' reader threads (tests of the transport).
    #[cfg(test)]
    pub(crate) fn h2_reads(&self) -> (usize, usize) {
        self.h2.as_ref().map_or((0, 0), |h2| h2.registry.reads())
    }

    /// How many bytes of HTTP/2 bodies read in pieces went straight into the callers' buffers, and how many through the
    /// streams' buffers (tests of the transport).
    #[cfg(test)]
    pub(crate) fn h2_body_bytes(&self) -> (usize, usize) {
        self.h2.as_ref().map_or((0, 0), |h2| h2.registry.body_bytes())
    }

    /// Speaks HTTP/2 to servers that choose it (off by default). The client then offers `h2` and `http/1.1` in
    /// the TLS handshake; a server that picks `h2` gets one connection, which all requests to that origin share
    /// (up to the number of concurrent streams the server allows, and then another connection), and one that
    /// picks `http/1.1` or nothing is spoken to as before. The `https` scheme only: there is no HTTP/2 over
    /// plain TCP.
    ///
    /// The windows are 8 MiB for a stream and 32 MiB for the connection. For a body that is read in pieces
    /// ([`send_stream`](RequestBuilder::send_stream)) credit goes back to the server as the application reads (a
    /// megabyte at a time), so at most 32 MiB of body that has not been read is held, and a long, fast path is not
    /// left waiting; a body that is read whole ([`send`](RequestBuilder::send)) is kept as it comes (up to
    /// [`max_body_bytes`](Client::max_body_bytes), which is then also the limit on what is held), credit goes back as it
    /// arrives, and it reaches the caller without being copied again. One connection is read and decrypted by
    /// one thread, which on a fast path is as fast as one HTTP/1.1 connection (see `tools/bench_h2.sh`); when
    /// one thread is not enough for the bytes, several HTTP/1.1 connections would use more cores.
    ///
    /// An HTTP/2 connection has two threads, one that reads from it and one that writes to it, for as long as it
    /// is open; it is closed when it has been idle for [`pool_idle_timeout`](Client::pool_idle_timeout), when the
    /// server says to go away, when the network ends it, and when the last clone of the client is dropped (once
    /// its requests are done). [`keep_alive(false)`](Client::keep_alive) and a pool of size 0 switch it off for
    /// the requests that follow, as they do for HTTP/1.1 reuse.
    ///
    /// The request and the response are the same as over HTTP/1.1, with these differences: the response has no
    /// reason phrase (`reason` is empty), header names are in lower case, and trailers are dropped. A request
    /// the server did not act on (it refused the stream, or said in GOAWAY that it had not got that far) is sent
    /// again on another connection, whatever its method; one that was cut off by a connection that had been in
    /// use is sent again once if its method may be repeated, as for HTTP/1.1.
    ///
    /// The async client ([`AsyncClient`]) does not speak HTTP/2 yet; the `*_async` methods of this client, which
    /// run the blocking client on worker threads, do.
    pub fn http2(mut self, on: bool) -> Client {
        self.h2 = on.then(|| {
            let mut tls = self.tls.clone();
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            // the connections of an earlier setting are kept (and used) if it was on already
            let registry = self.h2.as_ref().map_or_else(|| Arc::new(Registry::new()), |h| h.registry.clone());
            H2Support { tls, registry }
        });
        self
    }

    /// Speaks HTTP/3 (over QUIC, on UDP) to origins that offer it (off by default). An origin offers it in an
    /// [`Alt-Svc`](https://www.rfc-editor.org/rfc/rfc7838) header of an ordinary response (`alt-svc: h3=":443"; ma=86400`):
    /// the client remembers that for as long as the origin said (at most 30 days, 24 hours if it did not say), and
    /// the next request to that origin goes over QUIC. The first request to an origin, and every request while the
    /// first QUIC connection is being made, goes the way it would without this: over HTTP/2 if [`http2`](Client::http2) is on and
    /// the server chooses it, else HTTP/1.1.
    ///
    /// QUIC is not always possible (a network that drops UDP, a firewall that lets TCP through only), so it is tried
    /// with a short handshake (3 seconds, or [`connect_timeout`](Client::connect_timeout) if that is shorter); an origin
    /// that could not be reached over QUIC is left to TCP for five minutes, and twice as long after each
    /// further failure, up to a day, so that a network that drops UDP costs the first request that tries a few
    /// seconds and no request after that. A request that is refused or cut off in a way that allows it is sent again
    /// (see [`http2`](Client::http2) for the rules, which are the same), and a connection that fails before it has carried a
    /// response, for a request that may be repeated, makes the request go over TCP instead.
    ///
    /// One QUIC connection is shared by all requests to an origin (more are opened if the server's limit on concurrent
    /// streams is reached). It has two threads while it is open, and is closed when it has been idle for
    /// [`pool_idle_timeout`](Client::pool_idle_timeout), when the server says to go away, when the network ends it, and when
    /// the last clone of the client is dropped. A request through a proxy is never sent over HTTP/3 (the proxies this
    /// client speaks to tunnel TCP), nor is one while [`keep_alive`](Client::keep_alive) is off.
    ///
    /// The server is authenticated as the origin's host name, as for TLS over TCP: an alternative at another host
    /// has to present a certificate for the origin's name. The response is as over HTTP/2: no reason phrase, header
    /// names in lower case, trailers dropped. [`Response::version`] says [`HttpVersion::Http3`].
    ///
    /// The async client ([`AsyncClient`]) does not speak HTTP/3; the `*_async` methods of this client do.
    pub fn http3(mut self, on: bool) -> Client {
        self.h3 = on.then(|| {
            // the connections of an earlier setting are kept (and used) if it was on already
            let (registry, eager) = self.h3.as_ref().map_or_else(|| (Arc::new(H3Registry::new()), false), |h| (h.registry.clone(), h.eager));
            H3Support { registry, eager }
        });
        self
    }

    /// Like [`http3`](Client::http3) (it turns it on), but also tries QUIC for origins that have not said they offer it, at the
    /// host and port of the request, instead of waiting to be told in an `Alt-Svc` header (curl's `--http3`, and what a
    /// browser does for a host it has been told about out of band). It is for a client that talks to servers it knows speak
    /// HTTP/3: the first request to an origin waits for the QUIC handshake, which is given the whole
    /// [`connect_timeout`](Client::connect_timeout), and the requests that come while it is made wait for it; if it fails, the
    /// origin goes to TCP for the time given for [`http3`](Client::http3). `eager(false)` goes back to waiting to be told.
    pub fn http3_eager(mut self, on: bool) -> Client {
        if on {
            self = self.http3(true);
        }
        if let Some(h3) = &mut self.h3 {
            h3.eager = on;
        }
        self
    }

    /// Limits the hosts this client (and what is cloned from it afterwards) may reach to those the rule names (none by default: any host).
    /// The rule is applied to the URL of the request and to the URL of **every redirect that is followed**, before anything is sent to
    /// that host; a request or a redirect to a host that the rule does not name is an error (`Error::Http`, whose message begins
    /// `host not allowed`) and nothing is sent. See [`HostRules`] for what an entry may be (a host, an address, `*.example.com`, `host:port`),
    /// for what a wildcard does and does not cover, and for the two switches that make a rule tighter
    /// ([`one_label_wildcards`](HostRules::one_label_wildcards), [`default_port_only`](HostRules::default_port_only)). With a rule, an HTTP/3
    /// alternative offered by an origin is used only if the rule allows its host and port too.
    ///
    /// Clones share their connections, so one client can serve several callers that each have a rule of their own:
    /// `client.clone().allowed_hosts(rules)` is a client for that caller (the limits of [`timeout`](Client::timeout),
    /// [`total_timeout`](Client::total_timeout), [`max_redirects`](Client::max_redirects), [`max_body_bytes`](Client::max_body_bytes) and
    /// [`url_limits`](Client::url_limits) can be set on the clone in the same way).
    pub fn allowed_hosts(mut self, rules: HostRules) -> Client {
        self.hosts = Some(Arc::new(rules));
        self
    }

    /// Takes the rule of [`allowed_hosts`](Client::allowed_hosts) away: any host may be reached.
    pub fn any_host(mut self) -> Client {
        self.hosts = None;
        self
    }

    /// Sets what the URL of a request, and the URL of every redirect that is followed, may not be (nothing is refused by default): see
    /// [`UrlLimits`]. A URL that a limit refuses is an error (`Error::Http`, whose message begins `URL not allowed`) and nothing is sent.
    /// With [`allowed_hosts`](Client::allowed_hosts) and `UrlLimits::strict()` the client keeps to what a module that may reach a few
    /// servers over https, and no others, needs.
    pub fn url_limits(mut self, limits: UrlLimits) -> Client {
        self.url_limits = limits;
        self
    }

    /// Gives each hop of a request its own headers, which is where a caller puts the credentials of the host a hop goes to: `f` is called
    /// for the request itself (hop 0) and for **every redirect that is followed**, after the host rule and the limits on a URL have allowed
    /// that URL and before anything is sent there, and the headers it returns are sent with that hop and with no other (a redirect to another
    /// host gets what `f` says for that host, not what the host before it was given). An `Err` from `f` refuses the hop: nothing is sent
    /// there and the request fails with that error.
    ///
    /// A header that `f` gives replaces a header of the same name that the caller set on the request (so `Authorization` from `f` is the
    /// one sent), and is checked as the caller's are (a bad name or value is an error, and so is `Host`, `Connection` or `Content-Length`,
    /// which the client owns); the error names the header and never says its value. `f` is called once for each hop, also when the request
    /// is sent again on another connection (a pooled one that had closed, HTTP/3 falling back to TCP). It runs on the thread that makes the
    /// request, in the async client too, so it should not wait for anything.
    ///
    /// Send credentials this way and not as headers of the request: a header the caller sets stays with a redirect to another origin (only
    /// `Authorization`, `Cookie` and `Proxy-Authorization` are dropped there), where one that `f` gives does not.
    ///
    /// ```no_run
    /// use pratique::{Client, error::Error};
    /// let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    /// let client = Client::new()?.max_redirects(5).hop_headers(move |hop| match hop.url.host.as_str() {
    ///     // the token goes to GitHub's API and to nobody else, whatever the redirect chain does
    ///     "api.github.com" if !token.is_empty() => Ok(vec![("Authorization".into(), format!("Bearer {token}"))]),
    ///     "api.github.com" | "objects.githubusercontent.com" => Ok(vec![]),
    ///     other => Err(Error::Http(format!("{other} is not a host this client talks to"))),
    /// });
    /// # let _ = client; Ok::<(), Error>(())
    /// ```
    pub fn hop_headers<F>(mut self, f: F) -> Client
    where
        F: Fn(&HopInfo<'_>) -> Result<Vec<(String, String)>> + Send + Sync + 'static,
    {
        self.hop_hook = Some(Arc::new(f));
        self
    }

    /// Takes the hook of [`hop_headers`](Client::hop_headers) away.
    pub fn no_hop_headers(mut self) -> Client {
        self.hop_hook = None;
        self
    }

    /// What the hook gives for a hop that is about to be sent, checked: nothing if there is no hook.
    fn granted_for(&self, info: &HopInfo<'_>) -> Result<Vec<(String, String)>> {
        let Some(hook) = &self.hop_hook else { return Ok(Vec::new()) };
        let granted = hook(info).map_err(|e| match e {
            // (a hook that says no, as an error of its own or as one of ours, has refused the hop)
            Error::Refused(r) => Error::Refused(Refused { hop: info.hop, ..r }),
            Error::Http(reason) => Error::Refused(Refused { hop: info.hop, by: RefusedBy::Hook, reason }),
            other => Error::Refused(Refused { hop: info.hop, by: RefusedBy::Hook, reason: other.to_string() }),
        })?;
        for (name, value) in &granted {
            if !wire::is_valid_header_name(name) || !wire::is_valid_header_value(value) {
                return Err(Error::Http(format!("invalid header {name:?} from the hop hook")));
            }
            if OWN_HEADERS.iter().any(|own| name.eq_ignore_ascii_case(own)) {
                return Err(Error::Http(format!("the hop hook may not give {name:?}: the client sets it")));
            }
        }
        Ok(granted)
    }

    /// Refuses a URL (as the text it came in) that a limit refuses; the cheap check, made before the text is parsed.
    pub(crate) fn check_text(&self, text: &str, hop: usize) -> Result<()> {
        self.url_limits.check_text(text).map_err(|reason| Error::Refused(Refused { hop, by: RefusedBy::UrlLimit, reason }))
    }

    /// Refuses a URL that a limit or the host rule does not allow. Called for the first URL and for every redirect, before a connection.
    pub(crate) fn check_target(&self, url: &Url, hop: usize) -> Result<()> {
        self.url_limits.check(url).map_err(|reason| Error::Refused(Refused { hop, by: RefusedBy::UrlLimit, reason }))?;
        match &self.hosts {
            Some(rules) if !rules.allows_url(url) => Err(Error::Refused(Refused {
                hop,
                by: RefusedBy::HostRule,
                reason: format!("host not allowed: {} is not in the allowed hosts", url.host_header()),
            })),
            _ => Ok(()),
        }
    }

    /// Tunnels https requests through the proxy named by `HTTPS_PROXY`/`https_proxy`
    /// (honouring `NO_PROXY`/`no_proxy`).
    pub fn proxy_from_env(mut self) -> Client {
        self.proxy = ProxySetting::FromEnv;
        self
    }

    /// Tunnels https requests through an HTTP proxy using CONNECT.
    pub fn proxy(mut self, proxy_url: &str) -> Result<Client> {
        self.proxy = ProxySetting::Explicit(Proxy::parse(proxy_url)?);
        Ok(self)
    }

    pub fn get(&self, url: &str) -> Result<Response> {
        self.request("GET", url).send()
    }

    pub fn head(&self, url: &str) -> Result<Response> {
        self.request("HEAD", url).send()
    }

    /// [`get`](Client::get) with the body left to read as it arrives; see [`ResponseStream`].
    pub fn get_stream(&self, url: &str) -> Result<ResponseStream> {
        self.request("GET", url).send_stream()
    }

    pub fn post(&self, url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
        self.request("POST", url).body(body).send()
    }

    pub fn request(&self, method: &str, url: &str) -> RequestBuilder<'_> {
        RequestBuilder { client: self, method: method.to_string(), url: url.to_string(), headers: Vec::new(), body: Vec::new(), opts: RequestOpts::default() }
    }

    /// [`get`](Client::get) as a future. The request runs on a worker thread (see [`Pool`]), so
    /// it needs no particular executor; dropping the future before it completes abandons the
    /// request (a request that has not started is never sent).
    pub fn get_async(&self, url: &str) -> ResponseFuture {
        self.request("GET", url).send_async()
    }

    /// [`head`](Client::head) as a future; see [`get_async`](Client::get_async).
    pub fn head_async(&self, url: &str) -> ResponseFuture {
        self.request("HEAD", url).send_async()
    }

    /// [`post`](Client::post) as a future; see [`get_async`](Client::get_async).
    pub fn post_async(&self, url: &str, body: impl Into<Vec<u8>>) -> ResponseFuture {
        self.request("POST", url).body(body).send_async()
    }
}

/// The future returned by the `*_async` methods. `Send` and `'static`; it uses only
/// `std::task::Waker`, so any executor can drive it.
pub struct ResponseFuture {
    task: BlockingTask<Result<Response>>,
}

impl Future for ResponseFuture {
    type Output = Result<Response>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        }
    }
}

pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    opts: RequestOpts,
}

impl<'a> RequestBuilder<'a> {
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Largest response body accepted for this request, in bytes; see [`Client::max_body_bytes`].
    pub fn max_body_bytes(mut self, n: u64) -> Self {
        self.opts.max_body = Some(n);
        self
    }

    /// Makes this request part of `batch` (in place of the client's, if it has one): see [`Batch`].
    pub fn batch(mut self, batch: &Batch) -> Self {
        self.opts.batch = Some(batch.clone());
        self
    }

    /// How many bytes this request expects to bring, for the byte budget of the client's [`Scheduler`]: it waits until
    /// that much fits, and holds it until the head of the response says how much it is.
    pub fn expected_bytes(mut self, n: u64) -> Self {
        self.opts.expected = Some(n);
        self
    }

    /// Decodes (or does not decode) a compressed response to this request, whatever the client's setting; see [`Client::decompress`].
    pub fn decompress(mut self, on: bool) -> Self {
        self.opts.decompress = Some(on);
        self
    }

    /// The most bytes the decoded body of this response may have; see [`Client::max_decoded_bytes`].
    pub fn max_decoded_bytes(mut self, n: u64) -> Self {
        self.opts.max_decoded = Some(n);
        self
    }

    /// The oldest TLS version this request accepts: `TlsVersion::Tls13` keeps it TLS 1.3 only, and a server that cannot do 1.3
    /// is then refused. It can only make the client's minimum ([`Client::min_tls_version`]) stricter: `TlsVersion::Tls12` on a
    /// client that requires TLS 1.3 changes nothing. It holds for every redirect the request follows, and connections are not
    /// shared between requests that accept TLS 1.2 and ones that do not.
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.opts.min_tls = Some(version);
        self
    }

    /// Says `Expect: 100-continue` (the same as adding that header): over HTTP/1.1 the head goes first and the body only when the
    /// server says to go on, or after [`Client::expect_continue_timeout`] if it says nothing. A server that answers at once (a 401, a
    /// redirect, a 413 for a body too large) is answered without the body having been sent, which is what this is for: a large upload
    /// that is refused costs its head and nothing more. The body is then sent again, whole, if a redirect is followed (307 and 308
    /// keep it) or if the server does not do expectations (417, after which the request goes once more without one).
    pub fn expect_continue(self) -> Self {
        if self.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue")) {
            return self;
        }
        self.header("Expect", "100-continue")
    }

    pub fn send(self) -> Result<Response> {
        self.client.execute(self.method, &self.url, self.headers, self.body, self.opts)
    }

    /// Sends the request and returns as soon as the response headers are in; the body is read from
    /// the [`ResponseStream`] as it arrives. Redirects are followed first, as for
    /// [`send`](RequestBuilder::send); the stream is the final response.
    pub fn send_stream(self) -> Result<ResponseStream> {
        self.client.execute_stream(self.method, &self.url, self.headers, self.body, self.opts, false)
    }

    /// Sends the request without blocking the caller: it runs on a worker thread and the
    /// returned future completes with the response. See [`Client::get_async`].
    pub fn send_async(self) -> ResponseFuture {
        let client = self.client.clone();
        let pool = client.pool.clone().unwrap_or_else(Pool::global);
        let (method, url, headers, body, opts) = (self.method, self.url, self.headers, self.body, self.opts);
        ResponseFuture { task: pool.spawn_blocking(move || client.execute(method, &url, headers, body, opts)) }
    }
}

/// What a connector should honour when it opens a connection.
#[derive(Clone, Copy, Debug)]
pub struct ConnectOptions {
    /// Limit for establishing the connection.
    pub connect_timeout: Duration,
    /// Limit for one read or write on the connection.
    pub timeout: Duration,
    /// When the whole request must be finished (see [`Client::total_timeout`]).
    pub deadline: Option<Instant>,
}

/// Resolves `host` and connects, racing its addresses (see [`connect`](crate::http::connect)); the socket honours `opts`, and holds `permit`
/// (the connection's slot under a per-host limit) for as long as it is open.
pub(crate) fn tcp_connect(host: &str, port: u16, opts: ConnectOptions, est: &Establish, permit: Option<Permit>) -> Result<Io> {
    let now = Instant::now();
    let by_timeout = now.checked_add(opts.connect_timeout).unwrap_or(now + Duration::from_secs(365 * 86_400));
    let until = match opts.deadline {
        Some(d) if d <= now => return Err(Error::Io(deadline_error())),
        Some(d) => d.min(by_timeout),
        None => by_timeout,
    };
    let tcp = match connect::connect(est, host, port, until) {
        Ok(tcp) => tcp,
        // (the time ran out because the whole request's did)
        Err(e) if e.kind() == io::ErrorKind::TimedOut && opts.deadline.is_some_and(|d| d < by_timeout && Instant::now() >= d) => {
            return Err(Error::Io(deadline_error()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::Http(e.to_string())),
        Err(e) => return Err(Error::Io(e)),
    };
    tcp.set_read_timeout(Some(opts.timeout))?;
    tcp.set_write_timeout(Some(opts.timeout))?;
    let _ = tcp.set_nodelay(true);
    Ok(Io { tcp, timeout: opts.timeout, deadline: opts.deadline, permit, armed: crate::asyncio::net::Armed::both(opts.timeout) })
}

/// The key of a per-host connection limit: the host and port connected to (through a proxy, the origin's).
pub(crate) fn slot_key(url: &Url) -> String {
    format!("{}:{}", url.host, url.port)
}

/// No slot came free in time under a per-host connection limit.
pub(crate) fn no_slot(key: &str, max: usize, deadline: Option<Instant>, waited: Duration) -> Error {
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return Error::Io(deadline_error());
    }
    Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("no connection to {key} came free within {waited:?} (at most {max} at a time: Client::max_connections_per_host)"),
    ))
}

/// What a request holds while it is in flight, from its scheduler and its batch, given back when its response is over.
pub(crate) struct InFlight {
    ticket: Option<Ticket>,
    membership: Option<Membership>,
    /// Bytes of the body handed out so far.
    received: u64,
}

impl InFlight {
    pub(crate) fn new(ticket: Option<Ticket>, membership: Option<Membership>) -> Option<InFlight> {
        (ticket.is_some() || membership.is_some()).then_some(InFlight { ticket, membership, received: 0 })
    }

    /// The length the response says its body has.
    pub(crate) fn length(&mut self, length: Option<u64>) {
        if let (Some(t), Some(n)) = (self.ticket.as_mut(), length) {
            t.length_known(n);
        }
    }

    /// `n` more bytes of the body were handed out (counted against the budget when the body has no length).
    pub(crate) fn received(&mut self, n: usize, length: Option<u64>) {
        self.received += n as u64;
        if let (Some(t), None) = (self.ticket.as_mut(), length) {
            t.received(self.received);
        }
    }

    /// Whether the request's batch was cancelled.
    pub(crate) fn cancelled(&self) -> bool {
        self.membership.as_ref().is_some_and(|m| m.running.is_cancelled())
    }

    /// The request's control, if it belongs to a batch.
    pub(crate) fn running(&self) -> Option<&Running> {
        self.membership.as_ref().map(|m| &m.running)
    }
}

/// What a request that needs a new connection gets under a per-host connection limit.
enum Room {
    /// A slot to open one with (none when there is no limit).
    Slot(Option<Permit>),
    /// A connection for the request's key that came back to the pool while it waited.
    Parked(Conn),
}

/// Whether a request's headers say `Expect: 100-continue`.
pub(crate) fn expects_continue(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue"))
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn no_proxy_matches(host: &str) -> bool {
    let list = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")).unwrap_or_default();
    list.split(',').map(str::trim).filter(|e| !e.is_empty()).any(|e| {
        let e = e.trim_start_matches('.').to_ascii_lowercase();
        e == "*" || host == e || host.ends_with(&format!(".{}", e))
    })
}

/// One request on its way: what is sent now, and what a redirect may change.
pub(crate) struct Hop {
    pub(crate) method: String,
    pub(crate) url: Url,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    /// What the client's hop hook gave for this hop (see [`Client::hop_headers`]): sent with this hop and no other, and not part of
    /// `headers`, which a redirect carries on to the next hop.
    pub(crate) granted: Vec<(String, String)>,
    /// 0 for the request itself, 1 for the first redirect it was sent on, and so on.
    pub(crate) index: usize,
    /// If compressed bodies are to be asked for and decoded: the limits of the decoding. Decided once for the request and kept by its redirects.
    pub(crate) decode: Option<DecodeLimits>,
    /// The oldest TLS version the request accepts, if it says (else the client's): see [`RequestBuilder::min_tls_version`].
    pub(crate) min_tls: Option<TlsVersion>,
    /// The control of the request when it belongs to a batch: cancelled or not, and what stops it.
    pub(crate) running: Option<Running>,
}

impl Hop {
    /// The names (lower case) of the headers that the hook gave for this hop: credentials, which a compression table must not keep.
    pub(crate) fn secret_names(&self) -> Vec<String> {
        self.granted.iter().map(|(n, _)| n.to_ascii_lowercase()).collect()
    }
}

/// What a dial made.
enum Dialed {
    H2(Arc<h2_transport::Shared>),
    Http1(Conn),
}

/// What one try at a request over HTTP/2 came to.
enum H2Step {
    Response(ResponseStream),
    /// Try again (on another connection).
    Again,
    /// The origin does not speak HTTP/2: go on the HTTP/1.1 way, with this connection if one was dialed.
    Http1(Option<Conn>),
}

/// How a request's tries over HTTP/2 stand.
struct H2Tries {
    attempts: usize,
    /// A request cut off by a lost connection may be sent once more (it has not been yet, and its method allows it).
    repeat_allowed: bool,
}

/// The most times one request is started over HTTP/2 (connections that were full, refused streams, GOAWAYs).
const H2_ATTEMPTS: usize = 8;

/// What one try at a request over HTTP/3 came to.
enum H3Step {
    Response(ResponseStream),
    /// Try again (on another connection).
    Again,
    /// Not over QUIC: go the TCP way (the origin has not offered it, it could not be reached, or the request was lost on a connection that
    /// does not work).
    Skip,
}

/// How a request's tries over HTTP/3 stand.
struct H3Tries {
    attempts: usize,
    /// A request cut off by a lost connection may be sent once more (it has not been yet, and its method allows it).
    repeat_allowed: bool,
}

/// The most times one request is started over HTTP/3 before it is left to TCP.
const H3_ATTEMPTS: usize = 4;

impl Client {
    fn execute(&self, method: String, url: &str, headers: Vec<(String, String)>, body: Vec<u8>, opts: RequestOpts) -> Result<Response> {
        self.execute_stream(method, url, headers, body, opts, true)?.into_response()
    }

    /// The oldest TLS version a request accepts: its own, else the client's.
    /// The oldest TLS version a hop accepts: the client's, or the request's when that is stricter. A request can keep itself to
    /// TLS 1.3 on a client that allows 1.2, and cannot allow 1.2 on a client that requires 1.3.
    pub(crate) fn min_tls_for(&self, hop: &Hop) -> TlsVersion {
        hop.min_tls.map_or(self.tls.min_version, |v| v.max(self.tls.min_version))
    }

    /// The limits of the decoding for a request with `opts`, or `None` if its response is not to be decoded.
    pub(crate) fn decode_for(&self, opts: &RequestOpts) -> Option<DecodeLimits> {
        opts.decompress.unwrap_or(self.decompress).then(|| DecodeLimits { max_output: opts.max_decoded.or(self.decode.max_output), ..self.decode })
    }

    /// Sends the request, follows redirects, and returns the final response as soon as its headers
    /// have arrived.
    fn execute_stream(&self, method: String, url: &str, headers: Vec<(String, String)>, body: Vec<u8>, opts: RequestOpts, whole: bool) -> Result<ResponseStream> {
        let membership = self.membership(&opts)?;
        let running = membership.as_ref().map(|m| m.running.clone());
        let mut hop = self.start(method, url, headers, body)?;
        hop.decode = self.decode_for(&opts);
        hop.min_tls = opts.min_tls;
        hop.running = running.clone();
        let deadline = self.request_deadline(membership.as_ref());
        let limits = Limits { max_body_bytes: opts.max_body.unwrap_or(self.limits.max_body_bytes), ..self.limits };
        let cancelled = |e: Error| if running.as_ref().is_some_and(Running::is_cancelled) { Error::Cancelled } else { e };
        let mut ticket = match &self.scheduler {
            Some(s) => Some(s.admit(&slot_key(&hop.url), opts.expected.unwrap_or(0), deadline, running.as_ref())?),
            None => None,
        };
        let mut hops = 0;
        loop {
            if let Some(t) = ticket.as_mut() {
                t.move_to(&slot_key(&hop.url), deadline, running.as_ref())?;
            }
            let mut resp = self.once(&hop, deadline, limits, whole).map_err(cancelled)?;
            self.learn_alternatives(&hop, &resp);
            if let Some(jar) = &self.cookies {
                jar.store_from(&hop.url, resp.headers_named("set-cookie"));
            }
            if !self.follow(&mut hop, resp.status, &resp.headers, &mut hops)? {
                // (the final response, and the only one whose body the caller gets)
                let resp = match &hop.decode {
                    Some(d) => match decode::coding_of(&hop.method, resp.status, &resp.headers) {
                        Some(format) => resp.with_decoder(format, d.for_body(limits.max_body_bytes)),
                        None => resp,
                    },
                    None => resp,
                };
                // the request is in flight until its response is over
                return Ok(resp.in_flight(InFlight::new(ticket, membership)));
            }
            // what is left of the redirect's body, if it is small, so that its connection can be used again
            if resp.content_length.map_or(true, |n| n <= REDIRECT_BODY_LIMIT) {
                resp.discard(REDIRECT_BODY_LIMIT);
            }
        }
    }

    /// The request's place in its batch (its own, else the client's), if it has one; an error if the batch is cancelled.
    pub(crate) fn membership(&self, opts: &RequestOpts) -> Result<Option<Membership>> {
        let Some(batch) = opts.batch.as_ref().or(self.batch.as_ref()) else { return Ok(None) };
        let m = batch.join();
        m.running.check()?;
        Ok(Some(m))
    }

    /// When a request must be over: the client's total timeout from now, or its batch's deadline, whichever comes first.
    pub(crate) fn request_deadline(&self, membership: Option<&Membership>) -> Option<Instant> {
        match (self.deadline(), membership.and_then(|m| m.batch().deadline())) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Notes what a response says about HTTP/3 (`Alt-Svc`), if the client was asked to use it. Only a response that came over TLS or QUIC
    /// (to a request that did not go through a proxy) is believed: one over plain http, or one that a proxy could have changed, is not.
    fn learn_alternatives(&self, hop: &Hop, resp: &ResponseStream) {
        let Some(h3) = &self.h3 else { return };
        if !hop.url.is_https() {
            return;
        }
        let key = match self.proxy_for(&hop.url) {
            Ok(None) => pool_key(&hop.url, None, self.min_tls_for(hop)),
            _ => return,
        };
        let hosts = self.hosts.as_deref();
        h3.registry.learn(&key, resp.headers_named("alt-svc"), &|host, port| hosts.map_or(true, |rules| rules.allows(host, port, 443)));
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.total_timeout.and_then(|t| Instant::now().checked_add(t))
    }

    /// Validates a request and parses its URL.
    pub(crate) fn start(&self, method: String, url: &str, headers: Vec<(String, String)>, body: Vec<u8>) -> Result<Hop> {
        for (n, v) in &headers {
            if !wire::is_valid_header_name(n) || !wire::is_valid_header_value(v) {
                return Err(Error::Http(format!("invalid header {:?}", n)));
            }
        }
        if !wire::is_valid_header_name(&method) {
            return Err(Error::Http("invalid request method".into()));
        }
        self.check_text(url, 0)?;
        let url = Url::parse(url)?;
        self.check_target(&url, 0)?;
        let method = method.to_ascii_uppercase();
        let granted = self.granted_for(&HopInfo { url: &url, method: &method, hop: 0, from: None })?;
        Ok(Hop { method, url, headers, body, granted, index: 0, decode: None, min_tls: None, running: None })
    }

    /// Decides what a response means for the request: `Ok(true)` if `hop` now describes the
    /// redirected request to send next, `Ok(false)` if `resp` is the final answer.
    pub(crate) fn follow(&self, hop: &mut Hop, status: u16, headers: &[(String, String)], hops: &mut usize) -> Result<bool> {
        let location = if is_redirect(status) { headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone()) } else { None };
        let Some(location) = location else { return Ok(false) };
        if *hops >= self.max_redirects {
            return Err(Error::Http(format!("too many redirects (limit {})", self.max_redirects)));
        }
        *hops += 1;
        // (what the server said, and what it comes to: both before anything is sent there)
        self.check_text(&location, *hops)?;
        let next = hop.url.join(&location)?;
        self.check_text(&next.to_string(), *hops)?;
        if hop.url.is_https() && !next.is_https() {
            return Err(Error::Refused(Refused { hop: *hops, by: RefusedBy::Scheme, reason: "refusing redirect from https to plain http".into() }));
        }
        self.check_target(&next, *hops)?;
        let drop_body = status == 303 && hop.method != "HEAD" || (status == 301 || status == 302) && hop.method == "POST";
        // (the hook is asked last, with the method the request will have; a hop that it refuses leaves the request as it was)
        let method = if drop_body { "GET" } else { hop.method.as_str() };
        let granted = self.granted_for(&HopInfo { url: &next, method, hop: *hops, from: Some(&hop.url) })?;
        if drop_body {
            hop.method = "GET".to_string();
            hop.body.clear();
            hop.headers.retain(|(n, _)| !n.to_ascii_lowercase().starts_with("content-"));
        }
        if next.origin() != hop.url.origin() {
            hop.headers.retain(|(n, _)| !["authorization", "cookie", "proxy-authorization"].iter().any(|s| n.eq_ignore_ascii_case(s)));
        }
        hop.url = next;
        hop.granted = granted;
        hop.index = *hops;
        Ok(true)
    }

    /// The header list sent with `hop`: ours first, then the caller's (minus those we own).
    pub(crate) fn request_headers(&self, hop: &Hop) -> Result<Vec<(String, String)>> {
        let (method, url, body) = (hop.method.as_str(), &hop.url, &hop.body);
        if !url.is_https() && !self.allow_insecure_http {
            return Err(Error::Refused(Refused {
                hop: hop.index,
                by: RefusedBy::Scheme,
                reason: "plain http:// URLs are disabled; call allow_insecure_http(true) to permit them".into(),
            }));
        }
        // the caller's headers, except those of a name that the hook gave for this hop, and then what the hook gave
        let extra: Vec<(String, String)> = hop
            .headers
            .iter()
            .filter(|(n, _)| !hop.granted.iter().any(|(g, _)| g.eq_ignore_ascii_case(n)))
            .chain(hop.granted.iter())
            .cloned()
            .collect();
        let has = |name: &str| extra.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        let mut headers: Vec<(String, String)> = Vec::new();
        headers.push(("Host".into(), url.host_header()));
        if !has("user-agent") {
            headers.push(("User-Agent".into(), self.user_agent.clone()));
        }
        if !has("accept") {
            headers.push(("Accept".into(), "*/*".into()));
        }
        if !has("accept-encoding") {
            // (not for a range of a body: it is a range of the encoded one, which nothing can decode in part)
            let encodings = if hop.decode.is_some() && !has("range") { "gzip, deflate" } else { "identity" };
            headers.push(("Accept-Encoding".into(), encodings.into()));
        }
        if !self.policy.keep_alive {
            headers.push(("Connection".into(), "close".into()));
        }
        if let (Some(jar), false) = (&self.cookies, has("cookie")) {
            if let Some(cookies) = jar.header_for(url) {
                headers.push(("Cookie".into(), cookies));
            }
        }
        if let (Some(ui), false) = (&url.userinfo, has("authorization")) {
            headers.push(("Authorization".into(), format!("Basic {}", base64_encode(ui.as_bytes()))));
        }
        if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }
        headers.extend(extra.into_iter().filter(|(n, _)| !OWN_HEADERS.iter().any(|s| n.eq_ignore_ascii_case(s))));
        Ok(headers)
    }

    /// One request on one connection (a shared HTTP/2 one, a pooled HTTP/1.1 one if there is a good one, else a
    /// new one), up to the arrival of the response headers.
    fn once(&self, hop: &Hop, deadline: Option<Instant>, limits: Limits, whole: bool) -> Result<ResponseStream> {
        let mut headers = self.request_headers(hop)?;
        let (method, url, body) = (hop.method.as_str(), &hop.url, hop.body.as_slice());
        let proxy = self.proxy_for(url)?;
        let key = pool_key(url, proxy.as_ref(), self.min_tls_for(hop));
        let mut head = wire::write_request_head(method, &url.path_and_query, &headers);
        // a body that waits for the server's go-ahead (over HTTP/1.1)
        let mut expect = (!body.is_empty() && expects_continue(&headers)).then_some(self.expect_timeout);
        let mut retry_allowed = self.policy.parks() && is_replayable(method, &hop.headers);
        let mut pooled_allowed = true;
        let h2_on = self.h2.is_some() && url.is_https() && self.policy.parks();
        let mut h2_tries = H2Tries { attempts: 0, repeat_allowed: retry_allowed };
        // (QUIC is never used through a proxy: the proxies this client speaks to tunnel TCP)
        let h3_on = self.h3.is_some() && url.is_https() && proxy.is_none() && self.policy.parks();
        let mut h3_tries = H3Tries { attempts: 0, repeat_allowed: retry_allowed };
        loop {
            if let Some(r) = &hop.running {
                r.check()?;
            }
            // HTTP/3 if the caller asked for it and the origin offers it; anything else goes the TCP way, below
            if h3_on {
                match self.h3_step(hop, &headers, &key, deadline, limits, whole, &mut h3_tries)? {
                    H3Step::Response(stream) => return Ok(stream),
                    H3Step::Again => continue,
                    H3Step::Skip => {}
                }
            }
            // HTTP/2 next: a shared connection, or the dial that finds out whether the server speaks it
            let mut fresh = None;
            if h2_on {
                match self.h2_step(hop, &headers, &key, proxy.as_ref(), deadline, limits, whole, &mut h2_tries)? {
                    H2Step::Response(stream) => return Ok(stream),
                    H2Step::Again => continue,
                    H2Step::Http1(conn) => fresh = conn,
                }
            }
            let reused = if fresh.is_none() && pooled_allowed { self.checkout(&key, deadline) } else { None };
            let mut was_reused = reused.is_some();
            let conn = match (fresh, reused) {
                (Some(c), _) | (None, Some(c)) => c,
                (None, None) => match self.room(url, pooled_allowed.then_some(&key), deadline)? {
                    Room::Parked(c) => {
                        was_reused = true;
                        c
                    }
                    Room::Slot(permit) => self.connect(url, proxy.as_ref(), deadline, key.min_tls, permit)?,
                },
            };
            let mut conn = conn;
            if let Some(r) = &hop.running {
                // a cancel shuts the connection down, which stops a read or a write that waits on it
                if let Ok(socket) = conn.io_mut().tcp.try_clone() {
                    r.set(Interrupt::Socket(socket));
                }
            }
            let home = self.policy.parks().then(|| Home { pool: self.idle.clone(), key: key.clone(), policy: self.policy, slots: self.conn_limit.clone() });
            match self.exchange(conn, method, url, &head, body, limits, home, expect) {
                // a server that does not do expectations says so (RFC 9110, 15.5.18): the request, which it has not acted on, goes
                // once more without one, and with its body
                Ok(stream) if stream.status == 417 && expect.is_some() => {
                    drop(stream);
                    headers.retain(|(n, _)| !n.eq_ignore_ascii_case("expect"));
                    head = wire::write_request_head(method, &url.path_and_query, &headers);
                    expect = None;
                }
                Ok(stream) => return Ok(stream),
                // the server closed a connection that had been waiting: the request never reached
                // anything that could have acted on it, so it is sent once more on a new connection
                Err(f) if f.peer_closed && was_reused && retry_allowed => {
                    retry_allowed = false;
                    pooled_allowed = false;
                }
                Err(f) => return Err(f.error),
            }
        }
    }

    /// The request over HTTP/2, if the origin speaks it: a response, or `Again` (a connection could not take it,
    /// or it was refused or cut off in a way that allows another try), or the news that the origin is an HTTP/1.1
    /// one (with the connection that was dialed to find out, if there was one).
    #[allow(clippy::too_many_arguments)]
    fn h2_step(&self, hop: &Hop, headers: &[(String, String)], key: &Key, proxy: Option<&Proxy>, deadline: Option<Instant>, limits: Limits, whole: bool, tries: &mut H2Tries) -> Result<H2Step> {
        let support = self.h2.as_ref().expect("HTTP/2 is on");
        let opts = self.connect_options(deadline);
        let waits = Waits { timeout: opts.timeout, deadline };
        tries.attempts += 1;
        if tries.attempts > H2_ATTEMPTS {
            return Err(Error::Http("the request could not be started on an HTTP/2 connection".into()));
        }
        let (conn, reused) = match support.registry.acquire(key, waits, opts.connect_timeout + opts.timeout)? {
            Acquired::Http1 => return Ok(H2Step::Http1(None)),
            Acquired::Conn(conn) => (conn, true),
            Acquired::Dial(ticket) => match self.dial(&hop.url, proxy, deadline, true, key.min_tls, self.slot(&hop.url, deadline)?)? {
                Dialed::H2(conn) => {
                    ticket.h2(conn.clone());
                    (conn, false)
                }
                Dialed::Http1(conn) => {
                    ticket.http1();
                    return Ok(H2Step::Http1(Some(conn)));
                }
            },
        };
        let authority = hop.url.host_header();
        let secret = hop.secret_names();
        let request = h2::connection::Request { method: &hop.method, scheme: "https", authority: &authority, path: &hop.url.path_and_query, headers, secret: &secret };
        let started = conn.start(&request, &hop.body, waits);
        if let (Ok(stream), Some(r)) = (&started, &hop.running) {
            r.set(Interrupt::Call(Box::new(stream.canceller())));
        }
        let failure = match started {
            Ok(mut stream) if whole => match stream.response(limits.max_body_bytes, waits) {
                // the caller wants it all: head and body were waited for together, and the body is here
                Ok((head, bytes)) => {
                    let bodiless = hop.method == "HEAD" || matches!(head.status, 204 | 304);
                    let body = MuxBody::complete(bytes, waits, limits);
                    return Ok(H2Step::Response(ResponseStream::from_h2(head.status, head.headers, hop.url.clone(), body, bodiless, conn.tls_version())?));
                }
                Err(f) => f,
            },
            Ok(mut stream) => match stream.head(waits) {
                Ok(head) => {
                    let bodiless = hop.method == "HEAD" || matches!(head.status, 204 | 304);
                    let body = MuxBody::new(stream, waits, limits);
                    return Ok(H2Step::Response(ResponseStream::from_h2(head.status, head.headers, hop.url.clone(), body, bodiless, conn.tls_version())?));
                }
                Err(f) => f,
            },
            Err(StartError::Full) | Err(StartError::Unavailable) => return Ok(H2Step::Again),
            Err(StartError::Failed(f)) => f,
        };
        if failure.retry_safe {
            // the server did not act on it
            return Ok(H2Step::Again);
        }
        if failure.peer_closed && reused && tries.repeat_allowed {
            // a connection that had been in use was lost under it, before any answer
            tries.repeat_allowed = false;
            return Ok(H2Step::Again);
        }
        Err(failure.error)
    }

    /// The request over HTTP/3, if the caller asked for it and the origin offers it: a response, or `Again` (a connection could not
    /// take it, or it was refused or cut off in a way that allows another try), or `Skip`: go the TCP way.
    #[allow(clippy::too_many_arguments)]
    fn h3_step(&self, hop: &Hop, headers: &[(String, String)], key: &Key, deadline: Option<Instant>, limits: Limits, whole: bool, tries: &mut H3Tries) -> Result<H3Step> {
        let support = self.h3.as_ref().expect("HTTP/3 is on");
        let opts = self.connect_options(deadline);
        let waits = Waits { timeout: opts.timeout, deadline };
        tries.attempts += 1;
        if tries.attempts > H3_ATTEMPTS {
            return Ok(H3Step::Skip);
        }
        let (conn, reused) = match support.registry.acquire(key, &hop.url.host, hop.url.port, support.eager, waits, opts.connect_timeout + opts.timeout) {
            h3_transport::Acquired::Skip => return Ok(H3Step::Skip),
            h3_transport::Acquired::Conn(conn) => (conn, true),
            h3_transport::Acquired::Dial(ticket, host, port) => {
                // an origin that merely said it offers QUIC is not waited for long; one that the caller said speaks it is
                let handshake_timeout = if support.eager { self.connect_timeout } else { self.connect_timeout.min(h3_transport::ALT_HANDSHAKE_TIMEOUT) };
                let dial = DialOptions { handshake_timeout, idle_timeout: self.policy.idle_timeout, deadline, resolver: self.establish.resolver.clone() };
                match h3_transport::dial(&host, port, &hop.url.host, &self.tls, dial) {
                    Ok(conn) => {
                        ticket.connected(conn.clone());
                        (conn, false)
                    }
                    // (the time the whole request was given ran out: that says nothing of the origin)
                    Err(_) if deadline.is_some_and(|d| Instant::now() >= d) => return Ok(H3Step::Skip),
                    Err(_) => {
                        ticket.failed();
                        return Ok(H3Step::Skip);
                    }
                }
            }
        };
        let authority = hop.url.host_header();
        let secret = hop.secret_names();
        let request = h2::connection::Request { method: &hop.method, scheme: "https", authority: &authority, path: &hop.url.path_and_query, headers, secret: &secret };
        let failure = match conn.start(&request, &hop.body, waits) {
            Ok(mut stream) => match stream.head(waits) {
                Ok(head) => {
                    let bodiless = hop.method == "HEAD" || matches!(head.status, 204 | 304);
                    let (status, headers) = (head.status, head.headers);
                    if whole {
                        // the caller wants it all: it is waited for here, so that a connection lost under it can be answered with another try
                        match stream.collect(limits.max_body_bytes, waits) {
                            Ok(bytes) => {
                                let body = MuxBody::complete(bytes, waits, limits);
                                return Ok(H3Step::Response(ResponseStream::from_h3(status, headers, hop.url.clone(), body, bodiless)?));
                            }
                            Err(f) => f,
                        }
                    } else {
                        let body = MuxBody::new_h3(stream, waits, limits);
                        return Ok(H3Step::Response(ResponseStream::from_h3(status, headers, hop.url.clone(), body, bodiless)?));
                    }
                }
                Err(f) => f,
            },
            Err(StartError::Full) | Err(StartError::Unavailable) => return Ok(H3Step::Again),
            Err(StartError::Failed(f)) => f,
        };
        if failure.retry_safe {
            // the server did not act on it
            return Ok(H3Step::Again);
        }
        if failure.peer_closed && tries.repeat_allowed {
            tries.repeat_allowed = false;
            if reused {
                // a connection that had been in use was lost under it, before any answer
                return Ok(H3Step::Again);
            }
            // a connection that was new did not carry an answer: it is the origin's QUIC that does not work, and TCP might
            support.registry.broken(key);
            return Ok(H3Step::Skip);
        }
        Err(failure.error)
    }

    /// Sends the request on `conn` (the body after a go-ahead, if it waits for one: see [`RequestBuilder::expect_continue`]) and reads the
    /// response headers.
    #[allow(clippy::too_many_arguments)]
    fn exchange(&self, conn: Conn, method: &str, url: &Url, head: &[u8], body: &[u8], limits: Limits, home: Option<Home>, expect: Option<Duration>) -> std::result::Result<ResponseStream, Failure> {
        let tls_version = conn.tls_version();
        let mut reader = BodyReader::new(conn, method, limits, home);
        match expect {
            Some(wait) => reader.send_request_expecting_continue(head, body, wait)?,
            None => reader.send_request(head, body, body.len() <= SMALL_BODY)?,
        }
        let response_head = reader.receive_head()?;
        Ok(ResponseStream::new(response_head, url.clone(), reader, tls_version))
    }

    /// An idle connection to `key` that the peer has not closed in the meantime, with the limits of
    /// the request that will use it.
    fn checkout(&self, key: &Key, deadline: Option<Instant>) -> Option<Conn> {
        if !self.policy.parks() {
            return None;
        }
        let opts = self.connect_options(deadline);
        while let Some(mut conn) = self.idle.take(key, Instant::now()) {
            let io = conn.io_mut();
            if io.rearm(opts.timeout, opts.deadline).is_ok() && io.peer_quiet() {
                return Some(conn);
            }
        }
        None
    }

    fn tcp_connect(&self, host: &str, port: u16, deadline: Option<Instant>, permit: Option<Permit>) -> Result<Io> {
        tcp_connect(host, port, self.connect_options(deadline), &self.establish, permit)
    }

    /// A slot for a new connection to `url`'s host under [`max_connections_per_host`](Client::max_connections_per_host)
    /// (none without a limit), or, if `reuse` names the request's key, a connection for it that came back to the pool
    /// while this waited.
    fn room(&self, url: &Url, reuse: Option<&Key>, deadline: Option<Instant>) -> Result<Room> {
        let Some(slots) = &self.conn_limit else { return Ok(Room::Slot(None)) };
        let key = slot_key(url);
        let started = Instant::now();
        let until = deadline.unwrap_or_else(|| started + self.timeout);
        loop {
            let seen = match slots.try_take(&key) {
                Ok(permit) => return Ok(Room::Slot(Some(permit))),
                Err(seen) => seen,
            };
            if let Some(conn) = reuse.and_then(|k| self.checkout(k, deadline)) {
                return Ok(Room::Parked(conn));
            }
            // an idle connection to the host that this request cannot use (made for another proxy or TLS minimum, or one
            // that went stale) is closed to make room
            if let Some(idle) = self.idle.take_oldest_to(&url.host, url.port) {
                drop(idle);
                continue;
            }
            if !slots.wait(seen, Some(until)) {
                return Err(no_slot(&key, slots.max(), deadline, started.elapsed()));
            }
        }
    }

    pub(crate) fn connect_options(&self, deadline: Option<Instant>) -> ConnectOptions {
        ConnectOptions { connect_timeout: self.connect_timeout, timeout: self.timeout, deadline }
    }

    fn proxy_for(&self, url: &Url) -> Result<Option<Proxy>> {
        if !url.is_https() {
            return Ok(None);
        }
        match &self.proxy {
            ProxySetting::None => Ok(None),
            ProxySetting::Explicit(p) => Ok(Some(p.clone())),
            ProxySetting::FromEnv => {
                let var = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")).unwrap_or_default();
                if var.trim().is_empty() || no_proxy_matches(&url.host) {
                    return Ok(None);
                }
                Ok(Some(Proxy::parse(&var)?))
            }
        }
    }

    /// A slot for a new connection to `url`'s host (waiting for one if the per-host limit is reached), with nothing to
    /// reuse instead: for a dial that may become an HTTP/2 connection.
    fn slot(&self, url: &Url, deadline: Option<Instant>) -> Result<Option<Permit>> {
        match self.room(url, None, deadline)? {
            Room::Slot(permit) => Ok(permit),
            Room::Parked(_) => Err(Error::Http("internal: a parked connection where none was asked for".into())),
        }
    }

    /// A new connection for an HTTP/1.1 request, holding `permit`.
    fn connect(&self, url: &Url, proxy: Option<&Proxy>, deadline: Option<Instant>, min_tls: TlsVersion, permit: Option<Permit>) -> Result<Conn> {
        if !url.is_https() {
            return Ok(Conn::Plain(self.tcp_connect(&url.host, url.port, deadline, permit)?));
        }
        match self.dial(url, proxy, deadline, false, min_tls, permit)? {
            Dialed::Http1(conn) => Ok(conn),
            Dialed::H2(_) => Err(Error::Http("internal: an HTTP/2 connection where HTTP/1.1 was asked for".into())),
        }
    }

    /// A new TLS connection to an https origin (through the proxy, if there is one). With `offer_h2` the client
    /// offers `h2` in ALPN, and a server that picks it gets an HTTP/2 connection.
    fn dial(&self, url: &Url, proxy: Option<&Proxy>, deadline: Option<Instant>, offer_h2: bool, min_tls: TlsVersion, permit: Option<Permit>) -> Result<Dialed> {
        let mut io = match proxy {
            Some(p) => self.proxy_tunnel(p, &url.host, url.port, deadline, permit)?,
            None => self.tcp_connect(&url.host, url.port, deadline, permit)?,
        };
        let config = match (&self.h2, offer_h2) {
            (Some(h2), true) => &h2.tls,
            _ => &self.tls,
        };
        // (a request may ask for a newer version than the client's oldest)
        let narrowed;
        let config = if config.min_version == min_tls {
            config
        } else {
            narrowed = config.clone().with_min_version(min_tls);
            &narrowed
        };
        let tls = crate::tls::handshake(&mut io, &url.host, config)?;
        match tls.alpn_protocol() {
            Some(b"h2") if offer_h2 => {
                let shared = h2_transport::spawn(io.tcp, io.permit, tls, self.policy.idle_timeout, self.timeout)?;
                Ok(Dialed::H2(shared))
            }
            Some(b"h2") => Err(Error::Http("the server chose HTTP/2, which this request was not set up to speak (see Client::http2)".into())),
            _ => Ok(Dialed::Http1(Conn::Tls(Box::new(TlsStream::from_parts(io, tls))))),
        }
    }

    /// The CONNECT request that asks `proxy` for a tunnel to host:port.
    pub(crate) fn connect_request(&self, proxy: &Proxy, host: &str, port: u16) -> String {
        let target = if host.contains(':') { format!("[{}]:{}", host, port) } else { format!("{}:{}", host, port) };
        let mut req = format!("CONNECT {t} HTTP/1.1\r\nHost: {t}\r\nUser-Agent: {ua}\r\n", t = target, ua = self.user_agent);
        if let Some(a) = &proxy.auth {
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64_encode(a.as_bytes())));
        }
        req.push_str("\r\n");
        req
    }

    /// Opens a CONNECT tunnel through `proxy` to host:port.
    fn proxy_tunnel(&self, proxy: &Proxy, host: &str, port: u16, deadline: Option<Instant>, permit: Option<Permit>) -> Result<Io> {
        let mut s = self.tcp_connect(&proxy.host, proxy.port, deadline, permit)?;
        s.write_all(self.connect_request(proxy, host, port).as_bytes())?;
        // Read the response head one byte at a time so no tunnel data is consumed.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > CONNECT_HEAD_LIMIT {
                return Err(Error::Http("proxy response headers too large".into()));
            }
            if s.read(&mut byte)? == 0 {
                return Err(Error::Http("proxy closed the connection during CONNECT".into()));
            }
            head.push(byte[0]);
        }
        check_connect_response(&head)?;
        Ok(s)
    }
}

/// Longest proxy response head accepted after CONNECT.
pub(crate) const CONNECT_HEAD_LIMIT: usize = 16 * 1024;

/// Fails unless the proxy's response head starts with a 2xx status.
pub(crate) fn check_connect_response(head: &[u8]) -> Result<()> {
    let first = String::from_utf8_lossy(head.split(|&b| b == b'\n').next().unwrap_or(&[])).trim().to_string();
    let ok = first.split_whitespace().nth(1).map_or(false, |c| c.starts_with('2'));
    if !ok {
        return Err(Error::Http(format!("proxy refused CONNECT: {}", first)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Minimal scripted plain-HTTP server. `handler(request_head, body)` returns the raw response bytes.
    /// Returns (port, log of request heads).
    fn spawn_server(
        connections: usize,
        handler: impl Fn(&str, &[u8]) -> Vec<u8> + Send + 'static,
    ) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut s, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    let end = line == "\r\n";
                    head.push_str(&line);
                    if end {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).unwrap();
                log2.lock().unwrap().push(head.clone());
                let _ = s.write_all(&handler(&head, &body));
            }
        });
        (port, log)
    }

    fn plain_client() -> Client {
        Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty())).allow_insecure_http(true).timeout(Duration::from_secs(5))
    }

    #[test]
    fn plain_get_with_default_headers() {
        let (port, log) = spawn_server(1, |_, _| b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello".to_vec());
        let r = plain_client().get(&format!("http://127.0.0.1:{}/path?q=1", port)).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.text(), "hello");
        assert_eq!(r.header("x-test"), Some("yes"));
        let head = log.lock().unwrap()[0].clone();
        assert!(head.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{}", head);
        assert!(head.contains(&format!("Host: 127.0.0.1:{}\r\n", port)));
        assert!(!head.to_ascii_lowercase().contains("connection:"), "a keep-alive client has nothing to say about the connection: {head}");
        assert!(head.contains("Accept-Encoding: identity\r\n"));
        assert!(head.contains("User-Agent: pratique/"));
    }

    #[test]
    fn without_keep_alive_every_request_says_connection_close() {
        let (port, log) = spawn_server(1, |_, _| b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
        plain_client().keep_alive(false).get(&format!("http://127.0.0.1:{}/", port)).unwrap();
        assert!(log.lock().unwrap()[0].contains("Connection: close\r\n"));
    }

    #[test]
    fn post_sends_body_and_custom_headers() {
        let (port, log) = spawn_server(1, |_, body| {
            let mut r = b"HTTP/1.1 201 Created\r\nContent-Length: ".to_vec();
            r.extend_from_slice(body.len().to_string().as_bytes());
            r.extend_from_slice(b"\r\n\r\n");
            r.extend_from_slice(body);
            r
        });
        let r = plain_client()
            .request("POST", &format!("http://127.0.0.1:{}/", port))
            .header("Content-Type", "application/json")
            .body(br#"{"a":1}"#.to_vec())
            .send()
            .unwrap();
        assert_eq!((r.status, r.text().as_str()), (201, r#"{"a":1}"#));
        let head = log.lock().unwrap()[0].clone();
        assert!(head.contains("Content-Length: 7\r\n") && head.contains("Content-Type: application/json\r\n"), "{}", head);
    }

    #[test]
    fn large_post_body_roundtrips_through_the_split_write_path() {
        // Above SMALL_BODY the head and body are written separately, straight from the caller's slice.
        for size in [SMALL_BODY, SMALL_BODY + 1, 300_000] {
            let body: Vec<u8> = (0..size).map(|i| (i * 13 % 251) as u8).collect();
            let (port, log) = spawn_server(1, |_, body| {
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                r.extend_from_slice(body);
                r
            });
            let r = plain_client().request("POST", &format!("http://127.0.0.1:{}/up", port)).body(body.clone()).send().unwrap();
            assert_eq!(r.status, 200);
            assert!(r.body == body, "echoed body differs for size {size}");
            assert!(log.lock().unwrap()[0].contains(&format!("Content-Length: {size}\r\n")));
        }
    }

    #[test]
    fn follows_redirects_and_rewrites_post_to_get() {
        let (port, log) = spawn_server(3, |head, _| {
            if head.starts_with("POST /start") {
                b"HTTP/1.1 302 Found\r\nLocation: /middle\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else if head.starts_with("GET /middle") {
                b"HTTP/1.1 301 Moved\r\nLocation: final?x=1\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone".to_vec()
            }
        });
        let r = plain_client().post(&format!("http://127.0.0.1:{}/start", port), b"data".to_vec()).unwrap();
        assert_eq!(r.text(), "done");
        assert_eq!(r.url.path_and_query, "/final?x=1");
        let log = log.lock().unwrap();
        assert!(log[1].starts_with("GET /middle") && !log[1].contains("Content-Length"), "{}", log[1]);
        assert!(log[2].starts_with("GET /final?x=1"));
    }

    #[test]
    fn redirect_loop_is_cut_off() {
        let (port, _) = spawn_server(4, |_, _| b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec());
        let err = plain_client().max_redirects(3).get(&format!("http://127.0.0.1:{}/", port)).unwrap_err();
        assert!(err.to_string().contains("too many redirects"), "{}", err);
    }

    #[test]
    fn credentials_not_forwarded_to_other_origin() {
        let (port_b, log_b) = spawn_server(1, |_, _| b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
        let (port_a, log_a) = spawn_server(1, move |_, _| {
            format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{}/b\r\nContent-Length: 0\r\n\r\n", port_b).into_bytes()
        });
        let r = plain_client()
            .request("GET", &format!("http://127.0.0.1:{}/a", port_a))
            .header("Authorization", "Bearer secret")
            .header("X-Keep", "1")
            .send()
            .unwrap();
        assert_eq!(r.text(), "ok");
        assert!(log_a.lock().unwrap()[0].contains("Authorization: Bearer secret"));
        let b = log_b.lock().unwrap()[0].clone();
        assert!(!b.contains("Authorization"), "credentials leaked to another origin: {}", b);
        assert!(b.contains("X-Keep: 1"));
    }

    #[test]
    fn userinfo_becomes_basic_auth() {
        let (port, log) = spawn_server(1, |_, _| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        plain_client().get(&format!("http://user:pw@127.0.0.1:{}/", port)).unwrap();
        // base64("user:pw") = dXNlcjpwdw==
        assert!(log.lock().unwrap()[0].contains("Authorization: Basic dXNlcjpwdw==\r\n"));
    }

    #[test]
    fn plain_http_is_refused_by_default() {
        let c = Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty()));
        assert!(c.get("http://127.0.0.1:1/").unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn header_injection_is_refused() {
        let c = plain_client();
        assert!(c.request("GET", "http://127.0.0.1:1/").header("X", "a\r\nEvil: 1").send().is_err());
        assert!(c.request("GET", "http://127.0.0.1:1/").header("Bad Name", "v").send().is_err());
        assert!(c.request("GE T", "http://127.0.0.1:1/").send().is_err());
        assert!(c.get("http://127.0.0.1:1/x\r\nEvil: 1").is_err());
    }

    // ---- async

    use crate::asyncio::{block_on, join_all, Pool};
    use std::task::{Context, Poll};

    #[test]
    fn async_get_returns_the_same_response_as_the_blocking_call() {
        let (port, log) = spawn_server(1, |_, _| b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello".to_vec());
        let r = block_on(plain_client().get_async(&format!("http://127.0.0.1:{}/a?b=1", port))).unwrap();
        assert_eq!((r.status, r.text().as_str(), r.header("x-test")), (200, "hello", Some("yes")));
        assert!(log.lock().unwrap()[0].starts_with("GET /a?b=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn async_builder_sends_headers_and_body_and_follows_redirects() {
        let (port, log) = spawn_server(2, |head, body| {
            if head.starts_with("POST /start") {
                b"HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else {
                assert!(body.is_empty());
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext".to_vec()
            }
        });
        let r = block_on(
            plain_client()
                .request("POST", &format!("http://127.0.0.1:{}/start", port))
                .header("X-Id", "7")
                .body(b"payload".to_vec())
                .send_async(),
        )
        .unwrap();
        assert_eq!((r.status, r.text().as_str(), r.url.path_and_query.as_str()), (200, "next", "/next"));
        let log = log.lock().unwrap();
        assert!(log[0].contains("X-Id: 7\r\n") && log[0].contains("Content-Length: 7\r\n"), "{}", log[0]);
        assert!(log[1].starts_with("GET /next") && log[1].contains("X-Id: 7\r\n"), "{}", log[1]);
    }

    #[test]
    fn async_head_and_post_helpers() {
        let (port, log) = spawn_server(2, |head, body| {
            if head.starts_with("HEAD") {
                b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n".to_vec()
            } else {
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                r.extend_from_slice(body);
                r
            }
        });
        let c = plain_client();
        let h = block_on(c.head_async(&format!("http://127.0.0.1:{}/h", port))).unwrap();
        assert_eq!((h.status, h.body.len()), (200, 0));
        let p = block_on(c.post_async(&format!("http://127.0.0.1:{}/p", port), "echo me")).unwrap();
        assert_eq!(p.text(), "echo me");
        assert!(log.lock().unwrap()[0].starts_with("HEAD /h"));
    }

    #[test]
    fn async_errors_arrive_through_the_future() {
        let c = plain_client();
        // rejected before anything is sent
        let e = block_on(c.request("GET", "http://127.0.0.1:1/").header("X", "a\r\nEvil: 1").send_async()).unwrap_err();
        assert!(e.to_string().contains("invalid header"), "{}", e);
        let e = block_on(Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty())).get_async("http://127.0.0.1:1/")).unwrap_err();
        assert!(e.to_string().contains("disabled"), "{}", e);
        // nothing is listening: the connection error comes back as an error, not a hang
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(matches!(block_on(c.get_async(&format!("http://127.0.0.1:{}/", port))), Err(Error::Io(_))));
    }

    /// A server that answers only once `n` requests are open at the same time.
    fn rendezvous_server(n: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        thread::spawn(move || {
            for _ in 0..n {
                let Ok((mut s, _)) = listener.accept() else { return };
                let arrived = arrived.clone();
                thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    arrived.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let give_up = Instant::now() + Duration::from_secs(5);
                    while arrived.load(std::sync::atomic::Ordering::SeqCst) < n && Instant::now() < give_up {
                        thread::sleep(Duration::from_millis(2));
                    }
                    let ok = arrived.load(std::sync::atomic::Ordering::SeqCst) >= n;
                    let _ = s.write_all(if ok { b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" } else { b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n" });
                });
            }
        });
        port
    }

    #[test]
    fn async_requests_run_concurrently() {
        // Each of the four requests is answered only when all four are in flight. Run one after
        // another they would all get the 504.
        let port = rendezvous_server(4);
        let c = plain_client().pool(Pool::new(4));
        let futs: Vec<_> = (0..4).map(|i| c.get_async(&format!("http://127.0.0.1:{}/{}", port, i))).collect();
        for r in block_on(join_all(futs)) {
            assert_eq!(r.unwrap().status, 200);
        }
    }

    #[test]
    fn a_request_dropped_before_it_starts_is_never_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let pool = Pool::new(1);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let blocker = pool.spawn_blocking(move || {
            wait.recv().ok();
        });
        let c = plain_client().pool(pool.clone());
        drop(c.get_async(&format!("http://127.0.0.1:{}/", port))); // queued behind the blocker, then abandoned
        release.send(()).unwrap();
        block_on(blocker).unwrap();
        block_on(pool.spawn_blocking(|| ())).unwrap(); // the worker has now passed the abandoned job
        assert!(listener.accept().is_err(), "an abandoned request was sent anyway");
    }

    // ---- total timeout

    /// Accepts connections; for each, reads the request head, then sends `head` and `drip` one
    /// byte at a time, `gap` apart.
    fn slow_server(connections: usize, head: &'static str, drip: &'static [u8], gap: Duration) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut s, _)) = listener.accept() else { return };
                thread::spawn(move || {
                    let mut seen = Vec::new();
                    let mut b = [0u8; 1];
                    while !seen.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).unwrap_or(0) == 0 {
                            return;
                        }
                        seen.push(b[0]);
                    }
                    if s.write_all(head.as_bytes()).is_err() {
                        return;
                    }
                    for byte in drip {
                        thread::sleep(gap);
                        if s.write_all(&[*byte]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn total_timeout_stops_a_server_that_drips_bytes() {
        // every single read is well inside the 5 s per-operation limit, but the body takes 2 s
        let port = slow_server(2, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n", b"01234567890123456789", Duration::from_millis(100));
        let url = format!("http://127.0.0.1:{}/", port);
        let started = Instant::now();
        let err = plain_client().total_timeout(Duration::from_millis(400)).get(&url).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1), "took {:?}", started.elapsed());
        assert!(matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut), "{:?}", err);
        assert!(err.to_string().contains("total time limit"), "{}", err);
        // the same server and a generous limit: the request succeeds
        let ok = plain_client().total_timeout(Duration::from_secs(10)).get(&url).unwrap();
        assert_eq!(ok.body.len(), 20);
    }

    #[test]
    fn total_timeout_covers_every_redirect_hop_together() {
        // Each hop takes about 150 ms: fine alone, too slow for 250 ms in total.
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second = slow_server(1, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n", b"x", Duration::from_millis(150));
        thread::spawn(move || {
            let (mut s, _) = first.accept().unwrap();
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            while !seen.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut byte).unwrap();
                seen.push(byte[0]);
            }
            thread::sleep(Duration::from_millis(150));
            let _ = s.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/two\r\nContent-Length: 0\r\n\r\n", second).as_bytes());
        });
        let url = format!("http://127.0.0.1:{}/one", first_port);
        let err = plain_client().total_timeout(Duration::from_millis(250)).get(&url).unwrap_err();
        assert!(err.to_string().contains("total time limit"), "{}", err);
    }

    // ---- AsyncClient

    #[test]
    fn async_client_get_post_redirect_and_headers() {
        let (port, log) = spawn_server(3, |head, body| {
            if head.starts_with("POST /start") {
                b"HTTP/1.1 302 Found\r\nLocation: /middle\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else if head.starts_with("GET /middle") {
                assert!(body.is_empty());
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndone\r\n0\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()
            }
        });
        let c = plain_client().into_async();
        let r = block_on(c.request("POST", &format!("http://127.0.0.1:{}/start", port)).header("X-Id", "9").body("payload").send()).unwrap();
        assert_eq!((r.status, r.text().as_str(), r.url.path_and_query.as_str()), (200, "done", "/middle"));
        let r = block_on(c.get(&format!("http://127.0.0.1:{}/plain", port))).unwrap();
        assert_eq!(r.text(), "hi");
        let log = log.lock().unwrap();
        assert!(log[0].contains("Content-Length: 7\r\n") && log[0].contains("X-Id: 9\r\n"), "{}", log[0]);
        assert!(log[1].starts_with("GET /middle") && log[1].contains("X-Id: 9\r\n") && !log[1].contains("Content-Length"), "{}", log[1]);
    }

    #[test]
    fn async_client_large_upload_and_head() {
        let (port, _) = spawn_server(2, |head, body| {
            if head.starts_with("HEAD") {
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n".to_vec()
            } else {
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                r.extend_from_slice(body);
                r
            }
        });
        let c = plain_client().into_async();
        let body: Vec<u8> = (0..400_000).map(|i| (i * 31 % 253) as u8).collect();
        let r = block_on(c.post(&format!("http://127.0.0.1:{}/up", port), body.clone())).unwrap();
        assert!(r.body == body);
        let h = block_on(c.head(&format!("http://127.0.0.1:{}/h", port))).unwrap();
        assert_eq!((h.status, h.body.len()), (200, 0));
    }

    #[test]
    fn async_client_refuses_what_the_blocking_client_refuses() {
        let c = plain_client().into_async();
        let e = block_on(c.request("GET", "http://127.0.0.1:1/").header("X", "a\r\nEvil: 1").send()).unwrap_err();
        assert!(e.to_string().contains("invalid header"), "{}", e);
        assert!(block_on(c.request("GE T", "http://127.0.0.1:1/").send()).is_err());
        assert!(block_on(c.get("http://127.0.0.1:1/x\r\nEvil: 1")).is_err());
        let strict = Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty())).into_async();
        assert!(block_on(strict.get("http://127.0.0.1:1/")).unwrap_err().to_string().contains("disabled"));
        let (port, _) = spawn_server(3, |_, _| b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec());
        let err = block_on(plain_client().max_redirects(2).into_async().get(&format!("http://127.0.0.1:{}/", port))).unwrap_err();
        assert!(err.to_string().contains("too many redirects"), "{}", err);
    }

    #[test]
    fn async_client_runs_requests_concurrently() {
        let port = rendezvous_server(4);
        let c = plain_client().pool(Pool::new(8)).into_async();
        let urls: Vec<String> = (0..4).map(|i| format!("http://127.0.0.1:{}/{}", port, i)).collect();
        let futs: Vec<_> = urls.iter().map(|u| Box::pin(c.get(u))).collect();
        for r in block_on(join_all(futs)) {
            assert_eq!(r.unwrap().status, 200);
        }
    }

    #[test]
    fn async_client_total_timeout_cuts_off_a_dripping_server() {
        let port = slow_server(1, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n", b"01234567890123456789", Duration::from_millis(100));
        let started = Instant::now();
        let err = block_on(plain_client().total_timeout(Duration::from_millis(400)).into_async().get(&format!("http://127.0.0.1:{}/", port))).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1), "took {:?}", started.elapsed());
        assert!(err.to_string().contains("total time limit"), "{}", err);
    }

    /// Wraps a connector so that every connection moves one byte per read and three per write,
    /// and records what the client asked of it.
    struct Dribbling {
        inner: ThreadConnector,
        seen: Arc<Mutex<Vec<(String, u16, ConnectOptions)>>>,
    }

    struct Narrow<S>(S);

    impl<S: crate::asyncio::AsyncRead + Unpin> crate::asyncio::AsyncRead for Narrow<S> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
            let n = buf.len().min(1);
            Pin::new(&mut self.0).poll_read(cx, &mut buf[..n])
        }
    }

    impl<S: crate::asyncio::AsyncWrite + Unpin> crate::asyncio::AsyncWrite for Narrow<S> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let n = buf.len().min(3);
            Pin::new(&mut self.0).poll_write(cx, &buf[..n])
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_close(cx)
        }
    }

    impl Connect for Dribbling {
        type Stream = Narrow<crate::asyncio::ThreadedStream>;
        fn connect<'a>(&'a self, host: &'a str, port: u16, opts: ConnectOptions) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>> {
            self.seen.lock().unwrap().push((host.to_string(), port, opts));
            let fut = self.inner.connect(host, port, opts);
            Box::pin(async move { Ok(Narrow(fut.await?)) })
        }
    }

    #[test]
    fn async_client_works_over_any_connector() {
        let body = "0123456789".repeat(100);
        let reply = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body);
        let (port, log) = spawn_server(1, move |_, _| reply.clone().into_bytes());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connector = Dribbling { inner: ThreadConnector::new(Pool::new(4)), seen: seen.clone() };
        let client = plain_client().total_timeout(Duration::from_secs(30));
        let c = AsyncClient::with_connector(client, connector);
        let r = block_on(c.post(&format!("http://127.0.0.1:{}/x", port), "abcdefghij")).unwrap();
        assert_eq!(r.text(), body);
        assert!(log.lock().unwrap()[0].contains("Content-Length: 10\r\n"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].0.as_str(), seen[0].1), ("127.0.0.1", port));
        assert!(seen[0].2.deadline.is_some(), "the connector was not told about the total deadline");
        assert_eq!(seen[0].2.timeout, Duration::from_secs(5));
    }

    #[test]
    fn async_client_tunnels_through_a_proxy() {
        // a proxy that refuses, then one that accepts the CONNECT and hangs up
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        thread::spawn(move || {
            for status in ["403 Forbidden", "200 Connection established"] {
                let (mut s, _) = listener.accept().unwrap();
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    s.read_exact(&mut b).unwrap();
                    head.push(b[0]);
                }
                seen2.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
                s.write_all(format!("HTTP/1.1 {}\r\n\r\n", status).as_bytes()).unwrap();
            }
        });
        let c = plain_client().proxy(&format!("http://u:p@127.0.0.1:{}", port)).unwrap().into_async();
        let err = block_on(c.get("https://example.com/")).unwrap_err();
        assert!(err.to_string().contains("proxy refused CONNECT") && err.to_string().contains("403"), "{}", err);
        // the tunnel opens, but the "server" behind it is not there: the TLS handshake fails
        let err = block_on(c.get("https://example.com:8443/")).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{:?}", err);
        let seen = seen.lock().unwrap();
        assert!(seen[0].starts_with("CONNECT example.com:443 HTTP/1.1\r\n") && seen[0].contains("Proxy-Authorization: Basic dTpw\r\n"), "{}", seen[0]);
        assert!(seen[1].starts_with("CONNECT example.com:8443 HTTP/1.1\r\n"), "{}", seen[1]);
    }

    #[test]
    fn proxy_parsing() {
        let p = Proxy::parse("http://user:pw@proxy.local:3128").unwrap();
        assert_eq!((p.host.as_str(), p.port, p.auth.as_deref()), ("proxy.local", 3128, Some("user:pw")));
        assert_eq!(Proxy::parse("proxy.local:8888").unwrap().port, 8888);
        assert_eq!(Proxy::parse("http://proxy.local").unwrap().port, 8080);
        assert!(Proxy::parse("https://proxy.local:3128").is_err());
    }

    #[test]
    fn connect_tunnel_and_refusal() {
        // a proxy that accepts CONNECT, then one that refuses it
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(String::new()));
        let seen2 = seen.clone();
        thread::spawn(move || {
            for status in ["200 Connection established", "403 Forbidden"] {
                let (mut s, _) = listener.accept().unwrap();
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    s.read_exact(&mut b).unwrap();
                    head.push(b[0]);
                }
                *seen2.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
                s.write_all(format!("HTTP/1.1 {}\r\n\r\n", status).as_bytes()).unwrap();
            }
        });
        let c = plain_client();
        let p = Proxy { host: "127.0.0.1".into(), port, auth: Some("u:p".into()) };
        assert!(c.proxy_tunnel(&p, "example.com", 443, None, None).is_ok());
        let head = seen.lock().unwrap().clone();
        assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"), "{}", head);
        assert!(head.contains("Proxy-Authorization: Basic dTpw\r\n"), "{}", head);
        let err = c.proxy_tunnel(&p, "example.com", 443, None, None).unwrap_err();
        assert!(err.to_string().contains("403"), "{}", err);
    }
}
