//! The HTTP client for async code: the same requests, redirects, proxy tunnelling and framing as
//! [`Client`], over any asynchronous transport.
//!
//! The standard library has no async sockets or DNS, so the transport is supplied through the
//! [`Connect`] trait. [`ThreadConnector`] (the default) opens connections on the worker pool and
//! needs no setup; to use a runtime's own sockets, implement `Connect` with an adapter that
//! implements this crate's [`AsyncRead`] and [`AsyncWrite`] over them.
//!
//! ```no_run
//! use pratique::{asyncio::block_on, Client};
//! let client = Client::new()?.proxy_from_env().into_async();
//! let resp = block_on(client.get("https://example.com/"))?;
//! println!("{} {}", resp.status, resp.text());
//! # Ok::<(), pratique::error::Error>(())
//! ```
//!
//! Timeouts: `connect_timeout`, `timeout` (one read or write) and `total_timeout` (the whole request, redirects and body
//! included) hold whatever the connector: the client times its connector's `connect` and puts a
//! [`Timed`](crate::asyncio::Timed) over the stream it gets, on the timer thread of [`crate::asyncio`]. [`ThreadConnector`]
//! enforces them on its sockets itself (they are blocking calls on worker threads), so its streams are not timed twice; a
//! connector that does the same says so with [`Connect::enforces_timeouts`]. `Expect: 100-continue` waits for the go-ahead
//! as the blocking client does.

use super::decode::{self, BodyDecoder, Next, RequestOpts};
use super::idle::{IdlePool, Key, Policy};
use super::parser::{keep_alive_timeout, Head, ResponseParser};
use super::stream::{is_peer_close, Failure};
use super::wire::{self, Limits};
use super::connect::Establish;
use super::schedule::{Batch, Running};
use super::{
    check_connect_response, is_replayable, no_slot, pool_key, slot_key, tcp_connect, Client, ConnectOptions, Hop, InFlight, Proxy, Response, Url,
    CONNECT_HEAD_LIMIT, REDIRECT_BODY_LIMIT, SMALL_BODY,
};
use crate::asyncio::slots::{Permit, Slots};
use crate::asyncio::{timeout_at, AsyncRead, AsyncReadExt, AsyncTlsStream, AsyncWrite, AsyncWriteExt, Pool, ThreadedStream, Timed};
use crate::error::{Error, Result};
use crate::inflate::{Format, Limits as InflateLimits};
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

/// Size of the buffer that chunk framing and the headers pass through.
const SCRATCH: usize = 32 * 1024;

/// Opens transport connections for an [`AsyncClient`].
pub trait Connect: Send + Sync {
    /// The connection type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Resolves `host` and connects to `port`. Plain TCP only: the client adds TLS itself.
    /// `opts` carries the client's timeouts; honour what the transport can.
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        opts: ConnectOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>>;

    /// Prepares a connection that has been waiting in the client's pool for a new request: apply
    /// the timeouts and deadline in `opts` to it (the ones it was opened with belong to an earlier
    /// request) and say whether it is still good, which means the peer has not closed it or sent
    /// anything while it waited. The default says no, so a connector gets no connection reuse
    /// until it implements this: a stream that does not know how to apply new limits, or to tell
    /// whether the peer hung up, would otherwise fail requests in ways that are hard to see.
    fn reuse(&self, stream: &mut Self::Stream, opts: ConnectOptions) -> bool {
        let _ = (stream, opts);
        false
    }

    /// Whether this connector's streams enforce the read and write timeouts and the deadline of the [`ConnectOptions`] they
    /// were opened (or [reused](Connect::reuse)) with, and its `connect` the connect timeout. If not (the default), the
    /// client times them itself.
    fn enforces_timeouts(&self) -> bool {
        false
    }

    /// Applies the limits in `opts` to a stream this connector opened. The client asks this only of a connector that
    /// [enforces its own timeouts](Connect::enforces_timeouts), to shorten the read timeout while it waits for a
    /// `100 Continue` and to put it back afterwards; a connector that does not implement it has the wait last up to its
    /// read timeout.
    fn set_limits(&self, stream: &mut Self::Stream, opts: ConnectOptions) {
        let _ = (stream, opts);
    }
}

/// The default [`Connect`]: name resolution and connection run on a worker [`Pool`] (with the address racing and the
/// cache of [`connect`](super::connect)), and the socket is a [`ThreadedStream`]. Works with any executor and enforces
/// all of the client's timeouts.
#[derive(Clone, Debug)]
pub struct ThreadConnector {
    pool: Pool,
    establish: Establish,
}

impl ThreadConnector {
    /// A connector with a resolver of its own (one made by [`Client::into_async`] shares the client's).
    pub fn new(pool: Pool) -> ThreadConnector {
        ThreadConnector { pool, establish: Establish::default() }
    }
}

impl Connect for ThreadConnector {
    type Stream = ThreadedStream;

    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        opts: ConnectOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<ThreadedStream>> + Send + 'a>> {
        let host = host.to_string();
        let pool = self.pool.clone();
        let establish = self.establish.clone();
        let task = self.pool.spawn_blocking(move || tcp_connect(&host, port, opts, &establish, None));
        Box::pin(async move {
            let io = task.await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.map_err(|e| match e {
                Error::Io(e) => e,
                other => io::Error::new(io::ErrorKind::Other, other.to_string()),
            })?;
            Ok(ThreadedStream::from_io(io, pool))
        })
    }

    fn reuse(&self, stream: &mut ThreadedStream, opts: ConnectOptions) -> bool {
        stream.rearm(opts.timeout, opts.deadline) && stream.peer_quiet()
    }

    fn enforces_timeouts(&self) -> bool {
        true
    }

    fn set_limits(&self, stream: &mut ThreadedStream, opts: ConnectOptions) {
        let _ = stream.rearm(opts.timeout, opts.deadline);
    }
}

/// An HTTP(S) client for async code. Cheap to clone when the connector is.
///
/// Built from a configured [`Client`] (`client.into_async()` or [`AsyncClient::with_connector`]):
/// TLS settings, user agent, redirect limit, size limits, proxy, timeouts and the keep-alive
/// settings all come from it. The connections it keeps for reuse are its own (shared by its
/// clones), not the blocking client's.
pub struct AsyncClient<C: Connect = ThreadConnector> {
    client: Client,
    connector: C,
    idle: Arc<IdlePool<AsyncConn<C::Stream>>>,
}

impl<C: Connect + Clone> Clone for AsyncClient<C> {
    fn clone(&self) -> AsyncClient<C> {
        AsyncClient { client: self.client.clone(), connector: self.connector.clone(), idle: self.idle.clone() }
    }
}

impl Client {
    /// An async client with this client's settings, connecting through [`ThreadConnector`] on
    /// this client's pool (see [`Client::pool`]).
    pub fn into_async(self) -> AsyncClient {
        let connector = ThreadConnector { pool: self.pool.clone().unwrap_or_else(Pool::global), establish: self.establish.clone() };
        AsyncClient::with_connector(self, connector)
    }
}

impl<C: Connect> AsyncClient<C> {
    /// An async client with `client`'s settings that opens connections with `connector`.
    pub fn with_connector(mut client: Client, connector: C) -> AsyncClient<C> {
        // a per-host connection limit counts this client's connections, apart from the blocking client's (whose idle
        // connections it could not close to make room)
        client.conn_limit = client.conn_limit.as_ref().map(|s| Slots::new(s.max()));
        AsyncClient { client, connector, idle: Arc::new(IdlePool::new()) }
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        self.request("GET", url).send().await
    }

    pub async fn head(&self, url: &str) -> Result<Response> {
        self.request("HEAD", url).send().await
    }

    pub async fn post(&self, url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
        self.request("POST", url).body(body).send().await
    }

    /// [`get`](AsyncClient::get) with the body left to read as it arrives; see [`AsyncResponseStream`].
    pub async fn get_stream(&self, url: &str) -> Result<AsyncResponseStream<C::Stream>> {
        self.request("GET", url).send_stream().await
    }

    pub fn request(&self, method: &str, url: &str) -> AsyncRequestBuilder<'_, C> {
        AsyncRequestBuilder { client: self, method: method.to_string(), url: url.to_string(), headers: Vec::new(), body: Vec::new(), opts: RequestOpts::default() }
    }

    /// Closes every idle connection this client (and its clones) is holding.
    pub fn close_idle_connections(&self) {
        self.idle.clear();
    }

    /// The number of idle connections waiting for another request.
    pub fn idle_connections(&self) -> usize {
        self.idle.len()
    }

    /// The whole request under its batch's control (see [`execute_stream_controlled`](Self::execute_stream_controlled)).
    async fn execute_controlled(&self, method: String, url: &str, headers: Vec<(String, String)>, body: Vec<u8>, opts: RequestOpts) -> Result<Response> {
        self.execute_stream_controlled(method, url, headers, body, opts).await?.into_response().await
    }

    /// The request, under its batch's control: a cancel wakes the task, which drops what it was doing (and the connection
    /// with it) and fails with [`Error::Cancelled`].
    async fn execute_stream_controlled(
        &self,
        method: String,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        opts: RequestOpts,
    ) -> Result<AsyncResponseStream<C::Stream>> {
        let membership = self.client.membership(&opts)?;
        let Some(running) = membership.as_ref().map(|m| m.running.clone()) else {
            return self.execute_stream(method, url, headers, body, opts, None).await;
        };
        let request = self.execute_stream(method, url, headers, body, opts, membership);
        let mut request = std::pin::pin!(request);
        poll_fn(|cx| {
            if running.is_cancelled() {
                return Poll::Ready(Err(Error::Cancelled));
            }
            running.set_waker(cx.waker());
            request.as_mut().poll(cx)
        })
        .await
    }

    async fn execute_stream(
        &self,
        method: String,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        opts: RequestOpts,
        membership: Option<super::schedule::Membership>,
    ) -> Result<AsyncResponseStream<C::Stream>> {
        let running: Option<Running> = membership.as_ref().map(|m| m.running.clone());
        let mut hop = self.client.start(method, url, headers, body)?;
        hop.decode = self.client.decode_for(&opts);
        hop.min_tls = opts.min_tls;
        let deadline = self.client.request_deadline(membership.as_ref());
        let limits = Limits { max_body_bytes: opts.max_body.unwrap_or(self.client.limits.max_body_bytes), ..self.client.limits };
        let mut ticket = match &self.client.scheduler {
            Some(s) => Some(s.admit_async(&slot_key(&hop.url), opts.expected.unwrap_or(0), deadline, running.as_ref()).await?),
            None => None,
        };
        let mut hops = 0;
        loop {
            if let Some(t) = ticket.as_mut() {
                t.move_to_async(&slot_key(&hop.url), deadline, running.as_ref()).await?;
            }
            let mut resp = self.once(&hop, deadline, limits).await?;
            if let Some(jar) = &self.client.cookies {
                jar.store_from(&hop.url, resp.headers_named("set-cookie"));
            }
            if !self.client.follow(&mut hop, resp.status, &resp.headers, &mut hops)? {
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
                resp.discard(REDIRECT_BODY_LIMIT).await;
            }
        }
    }

    /// One request on one connection (a pooled one if there is a good one, else a new one), up to the
    /// arrival of the response headers.
    async fn once(&self, hop: &Hop, deadline: Option<Instant>, limits: Limits) -> Result<AsyncResponseStream<C::Stream>> {
        let mut headers = self.client.request_headers(hop)?;
        let (method, url, body) = (hop.method.as_str(), &hop.url, hop.body.as_slice());
        let proxy = self.client.proxy_for(url)?;
        let key = pool_key(url, proxy.as_ref(), self.client.min_tls_for(hop));
        let mut head = wire::write_request_head(method, &url.path_and_query, &headers);
        // a body that waits for the server's go-ahead
        let mut expect = (!body.is_empty() && super::expects_continue(&headers)).then_some(self.client.expect_timeout);
        let limit = |t: &mut Timed<C::Stream>, opts: ConnectOptions| self.apply_limits(t, opts);
        let opts = self.client.connect_options(deadline);
        let policy = self.client.policy;
        let mut retry_allowed = policy.parks() && is_replayable(method, &hop.headers);
        let mut pooled_allowed = true;
        loop {
            let reused = if pooled_allowed { self.checkout(&key, deadline) } else { None };
            let mut was_reused = reused.is_some();
            let conn = match reused {
                Some(c) => c,
                None => match self.room(url, pooled_allowed.then_some(&key), deadline).await? {
                    AsyncRoom::Parked(c) => {
                        was_reused = true;
                        c
                    }
                    AsyncRoom::Slot(permit) => self.connect(url, proxy.as_ref(), deadline, key.min_tls, permit).await?,
                },
            };
            let home = policy.parks().then(|| AsyncHome { pool: self.idle.clone(), key: key.clone(), policy, slots: self.client.conn_limit.clone() });
            let wait = expect.map(|wait| ExpectWait { wait, opts, limit: &limit });
            match exchange(conn, method, url, &head, body, limits, home, wait).await {
                // a server that does not do expectations says so (RFC 9110, 15.5.18): the request, which it has not acted on,
                // goes once more without one, and with its body
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

    /// A slot for a new connection to `url`'s host under the per-host limit (none without one), or, if `reuse` names the
    /// request's key, a connection for it that came back to the pool while this waited; as the blocking client's.
    async fn room(&self, url: &Url, reuse: Option<&Key>, deadline: Option<Instant>) -> Result<AsyncRoom<C::Stream>> {
        let Some(slots) = &self.client.conn_limit else { return Ok(AsyncRoom::Slot(None)) };
        let key = slot_key(url);
        let started = Instant::now();
        let until = deadline.unwrap_or_else(|| started + self.client.timeout);
        loop {
            let seen = match slots.try_take(&key) {
                Ok(permit) => return Ok(AsyncRoom::Slot(Some(permit))),
                Err(seen) => seen,
            };
            if let Some(conn) = reuse.and_then(|k| self.checkout(k, deadline)) {
                return Ok(AsyncRoom::Parked(conn));
            }
            if let Some(idle) = self.idle.take_oldest_to(&url.host, url.port) {
                drop(idle);
                continue;
            }
            if timeout_at(until, slots.changed(seen)).await.is_err() {
                return Err(no_slot(&key, slots.max(), deadline, started.elapsed()));
            }
        }
    }

    /// An idle connection to `key` that the connector says is still good, with the limits of the
    /// request that will use it.
    fn checkout(&self, key: &Key, deadline: Option<Instant>) -> Option<AsyncConn<C::Stream>> {
        if !self.client.policy.parks() {
            return None;
        }
        let opts = self.client.connect_options(deadline);
        while let Some(mut conn) = self.idle.take(key, Instant::now()) {
            if self.connector.reuse(conn.transport_mut().get_mut(), opts) {
                // the limits of this request, not of the one the connection was made for
                let limits = self.timed_limits(opts);
                conn.transport_mut().set_limits(limits.0, limits.0, limits.1);
                return Some(conn);
            }
        }
        None
    }

    /// Puts the limits of `opts` on a stream: through the connector if it keeps them itself, else on the client's [`Timed`].
    fn apply_limits(&self, stream: &mut Timed<C::Stream>, opts: ConnectOptions) {
        if self.connector.enforces_timeouts() {
            self.connector.set_limits(stream.get_mut(), opts);
        } else {
            stream.set_limits(Some(opts.timeout), Some(opts.timeout), opts.deadline);
        }
    }

    /// The read and write timeout and the deadline the client puts on its connector's streams: none if the connector enforces
    /// them itself.
    fn timed_limits(&self, opts: ConnectOptions) -> (Option<std::time::Duration>, Option<Instant>) {
        if self.connector.enforces_timeouts() {
            (None, None)
        } else {
            (Some(opts.timeout), opts.deadline)
        }
    }

    /// A transport connection from the connector, within the connect timeout (or, for a connector that enforces that
    /// itself, within the deadline), with the client's limits on it.
    async fn open(&self, host: &str, port: u16, opts: ConnectOptions, permit: Option<Permit>) -> Result<Timed<C::Stream>> {
        let by = if self.connector.enforces_timeouts() {
            opts.deadline
        } else {
            let t = Instant::now().checked_add(opts.connect_timeout);
            match (t, opts.deadline) {
                (Some(t), Some(d)) => Some(t.min(d)),
                (t, d) => t.or(d),
            }
        };
        let connecting = self.connector.connect(host, port, opts);
        let stream = match by {
            Some(by) => match timeout_at(by, connecting).await {
                Ok(r) => r?,
                Err(_) if opts.deadline.is_some_and(|d| by >= d) => return Err(Error::Io(crate::asyncio::net::deadline_error())),
                Err(_) => return Err(Error::Io(io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {host}:{port} took longer than {:?}", opts.connect_timeout)))),
            },
            None => connecting.await?,
        };
        let (timeout, deadline) = self.timed_limits(opts);
        let mut timed = Timed::new(stream);
        timed.set_limits(timeout, timeout, deadline);
        timed.hold(permit);
        Ok(timed)
    }

    async fn connect(&self, url: &Url, proxy: Option<&Proxy>, deadline: Option<Instant>, min_tls: crate::tls::TlsVersion, permit: Option<Permit>) -> Result<AsyncConn<C::Stream>> {
        let opts = self.client.connect_options(deadline);
        if !url.is_https() {
            return Ok(AsyncConn::Plain(self.open(&url.host, url.port, opts, permit).await?));
        }
        let stream = match proxy {
            Some(proxy) => {
                let mut s = self.open(&proxy.host, proxy.port, opts, permit).await?;
                s.write_all(self.client.connect_request(proxy, &url.host, url.port).as_bytes()).await?;
                s.flush().await?;
                // one byte at a time, so no tunnel data is consumed
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if head.len() > CONNECT_HEAD_LIMIT {
                        return Err(Error::Http("proxy response headers too large".into()));
                    }
                    if s.read(&mut byte).await? == 0 {
                        return Err(Error::Http("proxy closed the connection during CONNECT".into()));
                    }
                    head.push(byte[0]);
                }
                check_connect_response(&head)?;
                s
            }
            None => self.open(&url.host, url.port, opts, permit).await?,
        };
        let narrowed;
        let config = if self.client.tls.min_version == min_tls {
            &self.client.tls
        } else {
            narrowed = self.client.tls.clone().with_min_version(min_tls);
            &narrowed
        };
        // revocation sources wait for the network: the handshake leaves them for later, and they are asked on the worker pool
        // before the connection is used, so that the executor's thread never waits for a responder
        if config.revocation.fetches() && config.verify_server_certificate {
            let mut deferring = config.clone();
            deferring.revocation = config.revocation.deferred();
            let mut tls = AsyncTlsStream::connect(stream, &url.host, &deferring).await?;
            // (a handshake that left the check for later always hands it out; without it the connection is not used)
            let Some(unchecked) = tls.take_unchecked() else {
                return Err(Error::Tls("internal: the revocation check that the handshake left for later is missing".into()));
            };
            let revocation = config.revocation.clone();
            let now = config.time_override.unwrap_or_else(crate::sys::now_unix);
            let pool = self.client.pool.clone().unwrap_or_else(Pool::global);
            match pool.spawn_blocking(move || unchecked.check(&revocation, now)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(e) => return Err(Error::Io(io::Error::new(io::ErrorKind::Other, e))),
            }
            return Ok(AsyncConn::Tls(Box::new(tls)));
        }
        Ok(AsyncConn::Tls(Box::new(AsyncTlsStream::connect(stream, &url.host, config).await?)))
    }
}

/// What a request that says `Expect: 100-continue` needs for its wait.
struct ExpectWait<'a, S> {
    /// How long to wait for the go-ahead.
    wait: Duration,
    /// The request's limits, which the wait shortens and then puts back.
    opts: ConnectOptions,
    /// Puts limits on the stream (through the connector, or on the client's [`Timed`]).
    limit: &'a (dyn Fn(&mut Timed<S>, ConnectOptions) + Sync),
}

/// Sends the request on `conn` and reads the response headers.
#[allow(clippy::too_many_arguments)]
async fn exchange<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: AsyncConn<S>,
    method: &str,
    url: &Url,
    head: &[u8],
    body: &[u8],
    limits: Limits,
    home: Option<AsyncHome<S>>,
    expect: Option<ExpectWait<'_, S>>,
) -> std::result::Result<AsyncResponseStream<S>, Failure> {
    let tls_version = match &conn {
        AsyncConn::Plain(_) => None,
        AsyncConn::Tls(s) => s.protocol_version(),
    };
    let mut reader = AsyncBody::new(conn, method, limits, home);
    match expect {
        Some(wait) => reader.send_request_expecting_continue(head, body, &wait).await?,
        None => reader.send_request(head, body).await?,
    }
    let response_head = reader.receive_head().await?;
    Ok(AsyncResponseStream::new(response_head, url.clone(), reader, tls_version))
}

/// A request being built; see [`AsyncClient::request`].
pub struct AsyncRequestBuilder<'a, C: Connect> {
    client: &'a AsyncClient<C>,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    opts: RequestOpts,
}

impl<'a, C: Connect> AsyncRequestBuilder<'a, C> {
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

    /// The oldest TLS version this request accepts; see [`RequestBuilder::min_tls_version`](super::RequestBuilder::min_tls_version).
    pub fn min_tls_version(mut self, version: crate::tls::TlsVersion) -> Self {
        self.opts.min_tls = Some(version);
        self
    }

    /// Makes this request part of `batch` (in place of the client's, if it has one): see [`Batch`].
    pub fn batch(mut self, batch: &Batch) -> Self {
        self.opts.batch = Some(batch.clone());
        self
    }

    /// How many bytes this request expects to bring, for the byte budget of the client's scheduler; see
    /// [`RequestBuilder::expected_bytes`](super::RequestBuilder::expected_bytes).
    pub fn expected_bytes(mut self, n: u64) -> Self {
        self.opts.expected = Some(n);
        self
    }

    /// Says `Expect: 100-continue`: the body waits for the server's go-ahead, as with the blocking client (see
    /// [`RequestBuilder::expect_continue`](super::RequestBuilder::expect_continue): the wait, `Client::expect_continue_timeout`;
    /// an answer before the body means the body is never sent; a 417 sends the request again without the expectation).
    pub fn expect_continue(self) -> Self {
        if super::expects_continue(&self.headers) {
            return self;
        }
        self.header("Expect", "100-continue")
    }

    pub async fn send(self) -> Result<Response> {
        self.client.execute_controlled(self.method, &self.url, self.headers, self.body, self.opts).await
    }

    /// Sends the request and returns as soon as the response headers are in; the body is read from
    /// the [`AsyncResponseStream`] as it arrives. Redirects are followed first; the stream is the
    /// final response.
    pub async fn send_stream(self) -> Result<AsyncResponseStream<C::Stream>> {
        self.client.execute_stream_controlled(self.method, &self.url, self.headers, self.body, self.opts).await
    }
}

/// Plain or TLS, so the request code does not care which. The connector's stream is under the client's time limits (which
/// are none when the connector keeps them itself).
pub(super) enum AsyncConn<S> {
    Plain(Timed<S>),
    Tls(Box<AsyncTlsStream<Timed<S>>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncConn<S> {
    /// The transport under the TLS, if there is any.
    fn transport_mut(&mut self) -> &mut Timed<S> {
        match self {
            AsyncConn::Plain(s) => s,
            AsyncConn::Tls(s) => s.get_mut(),
        }
    }

    /// Digests what arrived with the end of the last response and says whether the connection is
    /// fit to wait for another request.
    fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        match self {
            AsyncConn::Plain(_) => Poll::Ready(true),
            AsyncConn::Tls(s) => s.poll_settle(cx),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncConn<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncConn<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_flush(cx),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            AsyncConn::Plain(s) => Pin::new(s).poll_close(cx),
            AsyncConn::Tls(s) => Pin::new(&mut **s).poll_close(cx),
        }
    }
}

/// Where a finished connection goes if it can be used again.
pub(super) struct AsyncHome<S> {
    pool: Arc<IdlePool<AsyncConn<S>>>,
    key: Key,
    policy: Policy,
    /// The client's per-host connection limit, whose waiters are told when a connection is parked.
    slots: Option<Arc<Slots>>,
}

/// What a request that needs a new connection gets under a per-host connection limit.
enum AsyncRoom<S> {
    /// A slot to open one with (none when there is no limit).
    Slot(Option<Permit>),
    /// A connection for the request's key that came back to the pool while it waited.
    Parked(AsyncConn<S>),
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// The connection, the parser and the not-yet-delivered body bytes of one response: the
/// counterpart of the blocking client's `BodyReader`, driven by polling.
struct AsyncBody<S> {
    conn: Option<AsyncConn<S>>,
    parser: ResponseParser,
    home: Option<AsyncHome<S>>,
    /// Body bytes the parser produced that have not been handed out: `pending[pos..]`.
    pending: Vec<u8>,
    pos: usize,
    scratch: Vec<u8>,
    failed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncBody<S> {
    fn new(conn: AsyncConn<S>, method: &str, limits: Limits, home: Option<AsyncHome<S>>) -> AsyncBody<S> {
        AsyncBody { conn: Some(conn), parser: ResponseParser::new(method, limits), home, pending: Vec::new(), pos: 0, scratch: Vec::new(), failed: false }
    }

    async fn send_request(&mut self, head: &[u8], body: &[u8]) -> std::result::Result<(), Failure> {
        let conn = self.conn.as_mut().expect("a connection");
        let sent = async {
            if body.len() <= SMALL_BODY {
                let mut one = Vec::with_capacity(head.len() + body.len());
                one.extend_from_slice(head);
                one.extend_from_slice(body);
                conn.write_all(&one).await?;
            } else {
                // a large upload goes from the caller's slice, not through a second copy of it
                conn.write_all(head).await?;
                conn.write_all(body).await?;
            }
            conn.flush().await
        };
        sent.await.map_err(|e| {
            let error = Error::Io(e);
            Failure { peer_closed: is_peer_close(&error), error }
        })
    }

    /// Sends the head, waits for the go-ahead (`100 Continue`), an answer or the end of the wait, and then sends the body,
    /// unless an answer came first: then the body is never sent and the connection is not used again (the server may still be
    /// waiting for it). The wait is a shorter read timeout on the stream for as long as it lasts, never past the request's
    /// deadline, as in the blocking client, so that no read is left waiting when the body goes.
    async fn send_request_expecting_continue(&mut self, head: &[u8], body: &[u8], expect: &ExpectWait<'_, S>) -> std::result::Result<(), Failure> {
        fn failure(e: io::Error) -> Failure {
            let error = Error::Io(e);
            Failure { peer_closed: is_peer_close(&error), error }
        }
        {
            let conn = self.conn.as_mut().expect("a connection");
            conn.write_all(head).await.map_err(failure)?;
            conn.flush().await.map_err(failure)?;
            let deadline = expect.opts.deadline;
            let left = deadline.map_or(expect.wait, |d| expect.wait.min(d.saturating_duration_since(Instant::now())));
            (expect.limit)(conn.transport_mut(), ConnectOptions { timeout: left.max(Duration::from_millis(1)), ..expect.opts });
        }
        let heard = poll_fn(|cx| self.poll_word(cx, expect.opts.deadline)).await;
        if let Some(conn) = self.conn.as_mut() {
            (expect.limit)(conn.transport_mut(), expect.opts);
        }
        heard?;
        if self.parser.head_complete() {
            // the answer came before the body: it is the response, and the body stays here
            self.home = None;
            return Ok(());
        }
        let conn = self.conn.as_mut().expect("a connection");
        conn.write_all(body).await.map_err(failure)?;
        conn.flush().await.map_err(failure)
    }

    /// Reads during the wait for a go-ahead: until a `100 Continue`, the head of an answer, or a read that times out before
    /// the request's deadline (the end of the wait, which is not an error).
    fn poll_word(&mut self, cx: &mut Context<'_>, deadline: Option<Instant>) -> Poll<std::result::Result<(), Failure>> {
        if self.scratch.is_empty() {
            self.scratch = vec![0u8; SCRATCH];
        }
        while !self.parser.continued() && !self.parser.head_complete() {
            let want = self.parser.max_read().min(self.scratch.len());
            let conn = self.conn.as_mut().expect("a connection");
            let outcome = match Pin::new(conn).poll_read(cx, &mut self.scratch[..want]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => match self.parser.finish_eof(&mut self.pending) {
                    Err(e) => Err(e),
                    Ok(()) => Err(Error::Http("the connection was closed before the response".into())),
                },
                Poll::Ready(Ok(n)) => self.parser.feed(&self.scratch[..n], &mut self.pending),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                // no word in time (and the request's own time is not up): the body goes
                Poll::Ready(Err(e)) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) && !deadline.is_some_and(|d| Instant::now() >= d) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => Err(Error::Io(e)),
            };
            if let Err(error) = outcome {
                let peer_closed = !self.parser.started() && is_peer_close(&error);
                self.conn = None;
                self.failed = true;
                return Poll::Ready(Err(Failure { error, peer_closed }));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads until the headers of the final response are complete and returns them.
    async fn receive_head(&mut self) -> std::result::Result<Head, Failure> {
        poll_fn(|cx| self.poll_head(cx)).await
    }

    fn poll_head(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<Head, Failure>> {
        if self.scratch.is_empty() {
            self.scratch = vec![0u8; SCRATCH];
        }
        while !self.parser.head_complete() {
            let want = self.parser.max_read().min(self.scratch.len());
            let conn = self.conn.as_mut().expect("a connection");
            let outcome = match Pin::new(conn).poll_read(cx, &mut self.scratch[..want]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => match self.parser.finish_eof(&mut self.pending) {
                    Err(e) => Err(e),
                    Ok(()) => Err(Error::Http("the response ended before its headers were complete".into())),
                },
                Poll::Ready(Ok(n)) => self.parser.feed(&self.scratch[..n], &mut self.pending),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                Poll::Ready(Err(e)) => Err(Error::Io(e)),
            };
            if let Err(error) = outcome {
                let peer_closed = !self.parser.started() && is_peer_close(&error);
                self.conn = None;
                self.failed = true;
                return Poll::Ready(Err(Failure { error, peer_closed }));
            }
        }
        let head = self.parser.take_head().expect("the head was complete");
        if let Some(home) = &mut self.home {
            // the server says how long it will wait: never wait longer than that for it
            if let Some(t) = keep_alive_timeout(&head.headers) {
                home.policy.idle_timeout = home.policy.idle_timeout.min(t);
            }
        }
        if self.parser.is_done() {
            // a connection that is not reused is closed politely, if that does not have to wait
            let _ = self.poll_complete(cx);
        }
        Poll::Ready(Ok(head))
    }

    /// The message has been read to its end: the connection goes back to the pool if it can be used
    /// again and is closed otherwise. Pending only while the TLS layer has something to send first.
    fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(conn) = self.conn.as_mut() else { return Poll::Ready(()) };
        let keep = match &self.home {
            Some(home) => self.parser.reusable() && home.policy.parks(),
            None => false,
        };
        if keep {
            match conn.poll_settle(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if let (Some(conn), Some(home)) = (self.conn.take(), self.home.take()) {
                        home.pool.put(home.key, conn, home.policy.idle_timeout, &home.policy, Instant::now());
                        if let Some(slots) = &home.slots {
                            slots.poke();
                        }
                    }
                    return Poll::Ready(());
                }
                Poll::Ready(false) => {}
            }
        }
        // goodbye (TLS close_notify) if the transport takes it at once; errors do not matter now
        let _ = Pin::new(&mut *conn).poll_close(cx);
        self.conn = None;
        self.home = None;
        Poll::Ready(())
    }

    fn broken(&mut self, e: Error) -> Error {
        self.conn = None;
        self.home = None;
        self.failed = true;
        e
    }

    /// Reads body bytes into `out`; 0 is the end of the body. The size limit, the framing and the
    /// timeouts are enforced here.
    fn poll_read_body(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.failed {
            return Poll::Ready(Err(Error::Http("the response failed earlier and cannot be read further".into())));
        }
        loop {
            if self.pos < self.pending.len() {
                let n = (self.pending.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(n));
            }
            self.pending.clear();
            self.pos = 0;
            if self.parser.is_done() {
                ready!(self.poll_complete(cx));
                return Poll::Ready(Ok(0));
            }
            let window = self.parser.direct_window();
            let Some(conn) = self.conn.as_mut() else { return Poll::Ready(Ok(0)) };
            if window > 0 {
                // body bytes that need no parsing go straight to the caller
                let want = window.min(out.len());
                match Pin::new(conn).poll_read(cx, &mut out[..want]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(e) = self.parser.consume_direct(n) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                        if self.parser.is_done() {
                            let _ = self.poll_complete(cx);
                        }
                        return Poll::Ready(Ok(n));
                    }
                    Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(self.broken(Error::Io(e)))),
                }
            } else {
                if self.scratch.is_empty() {
                    self.scratch = vec![0u8; SCRATCH];
                }
                let want = self.parser.max_read().min(self.scratch.len());
                match Pin::new(conn).poll_read(cx, &mut self.scratch[..want]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        if let Err(e) = self.parser.finish_eof(&mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(e) = self.parser.feed(&self.scratch[..n], &mut self.pending) {
                            return Poll::Ready(Err(self.broken(e)));
                        }
                        if self.parser.is_done() {
                            let _ = self.poll_complete(cx);
                        }
                    }
                    Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(self.broken(Error::Io(e)))),
                }
            }
        }
    }

    async fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        poll_fn(|cx| self.poll_read_body(cx, out)).await
    }

    /// Reads and drops up to `limit` bytes of what is left of the body, so that a connection whose
    /// response nobody wants (a redirect's) can be used again. Gives up, and closes the connection,
    /// beyond that.
    async fn discard(&mut self, limit: u64) {
        let mut sink = [0u8; 8192];
        let mut seen = 0u64;
        while seen < limit {
            match self.read_body(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(n) => seen += n as u64,
            }
        }
        // too much to be worth it
        self.conn = None;
        self.home = None;
    }
}

/// A response whose head has arrived and whose body is read as it comes, for async code: the
/// counterpart of [`ResponseStream`](super::ResponseStream).
///
/// `status`, `headers` and `content_length` are known when this is returned; the body is read with
/// [`AsyncRead`] ([`into_response`](AsyncResponseStream::into_response) buffers what is left). The
/// body is limited by the client's [`max_body_bytes`](Client::max_body_bytes) (or the request's own)
/// and by the client's timeouts. A body over the limit is an error, reported by the request itself
/// if the head declares a length over the limit or the first read already holds more than the limit,
/// and by a later read otherwise. A connection whose body was read to its end may be reused;
/// dropping the stream earlier closes it.
pub struct AsyncResponseStream<S = ThreadedStream> {
    pub status: u16,
    pub reason: String,
    /// The protocol the response came over (always HTTP/1.1 for now: this client does not speak HTTP/2).
    pub version: super::HttpVersion,
    pub headers: Vec<(String, String)>,
    /// The URL that produced this response (after redirects).
    pub url: Url,
    /// The Content-Length the server declared, if it declared one and the body is not chunked.
    /// Known before the body is read. For a response to HEAD, the length a GET would have.
    pub content_length: Option<u64>,
    /// The version of TLS the response came over (`None` over plain http).
    pub tls_version: Option<crate::tls::TlsVersion>,
    /// True if the body came compressed and the client is decoding it as it is read (see [`Client::decompress`]).
    pub uncompressed: bool,
    body: AsyncBody<S>,
    decoder: Option<Box<BodyDecoder>>,
    /// What the request holds while it is in flight (its scheduler's place, its batch's), given back when the body is over.
    in_flight: Option<InFlight>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncResponseStream<S> {
    fn new(head: Head, url: Url, body: AsyncBody<S>, tls_version: Option<crate::tls::TlsVersion>) -> AsyncResponseStream<S> {
        AsyncResponseStream {
            status: head.status,
            reason: head.reason,
            version: super::HttpVersion::Http11,
            headers: head.headers,
            url,
            content_length: head.content_length,
            tls_version,
            uncompressed: false,
            body,
            decoder: None,
            in_flight: None,
        }
    }

    /// The same response, holding what its request holds in flight until its body is over (or it is dropped).
    fn in_flight(mut self, in_flight: Option<InFlight>) -> AsyncResponseStream<S> {
        let Some(mut f) = in_flight else { return self };
        if self.body.parser.is_done() {
            return self;
        }
        f.length(self.content_length);
        self.in_flight = Some(f);
        self
    }

    /// The same response with its body decoded as it is read: the headers that describe the encoded body are gone and so is the length.
    fn with_decoder(mut self, format: Format, limits: InflateLimits) -> AsyncResponseStream<S> {
        decode::strip_encoding_headers(&mut self.headers);
        self.content_length = None;
        self.uncompressed = true;
        self.decoder = Some(Box::new(BodyDecoder::new(format, limits)));
        self
    }

    /// Reads up to `out.len()` bytes of the body as the caller gets it (decoded, if it is): 0 is the end.
    fn poll_read_some(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize>> {
        let Some(f) = self.in_flight.as_mut() else { return self.poll_read_plain(cx, out) };
        if f.cancelled() {
            self.in_flight = None;
            return Poll::Ready(Err(Error::Cancelled));
        }
        if let Some(r) = f.running() {
            // a cancel wakes this task
            r.set_waker(cx.waker());
        }
        let r = ready!(self.poll_read_plain(cx, out));
        let f = self.in_flight.as_mut().expect("still in flight");
        Poll::Ready(match r {
            Ok(0) => {
                self.in_flight = None;
                Ok(0)
            }
            Ok(n) => {
                f.received(n, self.content_length);
                Ok(n)
            }
            Err(e) => {
                let cancelled = f.cancelled();
                self.in_flight = None;
                Err(if cancelled { Error::Cancelled } else { e })
            }
        })
    }

    fn poll_read_plain(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize>> {
        let Some(decoder) = self.decoder.as_mut() else { return self.body.poll_read_body(cx, out) };
        loop {
            match decoder.next(out).map_err(Error::Decode)? {
                Next::Data(n) => return Poll::Ready(Ok(n)),
                Next::End => return Poll::Ready(Ok(0)),
                Next::Wire => {
                    let n = ready!(self.body.poll_read_body(cx, decoder.wire_buf()))?;
                    decoder.wire(n).map_err(Error::Decode)?;
                }
            }
        }
    }

    async fn read_some(&mut self, out: &mut [u8]) -> Result<usize> {
        poll_fn(|cx| self.poll_read_some(cx, out)).await
    }

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

    /// Reads the rest of the body into memory and returns the whole [`Response`].
    pub async fn into_response(mut self) -> Result<Response> {
        let mut body: Vec<u8> = Vec::new();
        if !self.body.parser.is_done() {
            // what the server says is coming is a hint, not a promise: never reserve more than a megabyte up front
            body.reserve(self.content_length.unwrap_or(0).min(1 << 20) as usize);
        }
        loop {
            if body.capacity() - body.len() < 4096 {
                body.reserve(body.len().max(32 * 1024));
            }
            let len = body.len();
            let room = (body.capacity() - len).min(1 << 20);
            body.resize(len + room, 0);
            match self.read_some(&mut body[len..]).await {
                Ok(0) => {
                    body.truncate(len);
                    break;
                }
                Ok(n) => body.truncate(len + n),
                Err(e) => return Err(e),
            }
        }
        Ok(Response { status: self.status, reason: self.reason, version: self.version, headers: self.headers, body, url: self.url, tls_version: self.tls_version, uncompressed: self.uncompressed })
    }

    /// Reads the rest of the body into `sink`; returns how many bytes it was.
    pub async fn copy_to<W: AsyncWrite + Unpin>(&mut self, sink: &mut W) -> Result<u64> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            match self.read_some(&mut buf).await? {
                0 => return Ok(total),
                n => {
                    sink.write_all(&buf[..n]).await?;
                    total += n as u64;
                }
            }
        }
    }

    async fn discard(&mut self, limit: u64) {
        self.body.discard(limit).await;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for AsyncResponseStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.poll_read_some(cx, buf).map_err(to_io)
    }
}

impl<S> std::fmt::Debug for AsyncResponseStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncResponseStream").field("status", &self.status).field("url", &self.url.to_string()).field("content_length", &self.content_length).finish_non_exhaustive()
    }
}
