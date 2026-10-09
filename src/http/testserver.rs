//! A scripted HTTP/1.1 server for the tests of connection reuse and streaming, over plain TCP or over TLS (the
//! crate's own TLS server, `tls::server`, with a throwaway certificate). It keeps connections open and answers
//! each request as the test's handler says, and it counts connections and requests. A request that says
//! `Expect: 100-continue` gets a `100 Continue` before its body is read, unless its path starts with `/silent`.

use crate::tls::pki::TestPki;
use crate::tls::server::{ServerConfig, ServerStream};
use crate::tls::ClientConfig;
use crate::Client;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A request as the server saw it.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    /// Which accepted connection it came on (0 for the first).
    pub(crate) conn: usize,
    /// Which request on that connection (0 for the first).
    pub(crate) nth: usize,
    /// The request line and headers, with the final blank line.
    pub(crate) head: String,
    pub(crate) body: Vec<u8>,
}

impl Seen {
    pub(crate) fn path(&self) -> &str {
        self.head.split(' ').nth(1).unwrap_or("")
    }

    pub(crate) fn method(&self) -> &str {
        self.head.split(' ').next().unwrap_or("")
    }

    pub(crate) fn has_header(&self, line: &str) -> bool {
        self.head.lines().any(|l| l.eq_ignore_ascii_case(line))
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
    }
}

/// What the server writes to (the TCP stream, or the TLS stream over it). The methods after the first two do
/// something only over TLS (over plain TCP they write the data and nothing else).
pub(crate) trait Wire: Read + Write + Send {
    /// Sends a KeyUpdate (and flushes it), asking the client to rotate its keys too if `request_peer`.
    fn key_update(&mut self, _request_peer: bool) {}

    /// Sends `count` NewSessionTicket messages (and flushes them).
    fn tickets(&mut self, _count: usize) {}

    /// Writes `data` and a KeyUpdate in one go: they reach the client together, in one read.
    fn write_then_key_update(&mut self, data: &[u8], _request_peer: bool) {
        self.write_all(data).unwrap();
    }

    /// Writes `data` and `count` session tickets in one go.
    fn write_then_tickets(&mut self, data: &[u8], _count: usize) {
        self.write_all(data).unwrap();
    }
}

impl Wire for TcpStream {}

fn queue_all(conn: &mut crate::tls::server::ServerConnection, mut data: &[u8]) {
    while !data.is_empty() {
        let n = conn.write_plaintext(data).unwrap();
        data = &data[n..];
    }
}

impl Wire for ServerStream<TcpStream> {
    fn key_update(&mut self, request_peer: bool) {
        self.connection_mut().send_key_update(request_peer).unwrap();
        self.flush_queued().unwrap();
    }

    fn tickets(&mut self, count: usize) {
        self.connection_mut().send_session_tickets(count).unwrap();
        self.flush_queued().unwrap();
    }

    fn write_then_key_update(&mut self, data: &[u8], request_peer: bool) {
        queue_all(self.connection_mut(), data);
        self.connection_mut().send_key_update(request_peer).unwrap();
        self.flush_queued().unwrap();
    }

    fn write_then_tickets(&mut self, data: &[u8], count: usize) {
        queue_all(self.connection_mut(), data);
        self.connection_mut().send_session_tickets(count).unwrap();
        self.flush_queued().unwrap();
    }
}

/// What to do about a request.
pub(crate) enum Reply {
    /// Send these bytes and wait for the next request on the connection.
    Send(Vec<u8>),
    /// Send these bytes and close the connection (for TLS, with a close_notify).
    SendAndClose(Vec<u8>),
    /// Close the connection without answering (for TLS, with a close_notify).
    Close,
    /// Cut the connection without answering: a TCP close, and no close_notify.
    Cut,
    /// Do something with the connection (write pieces, wait for the test); `true` keeps it open.
    Run(Box<dyn FnOnce(&mut dyn Wire) -> bool + Send>),
}

pub(crate) fn ok(body: &str) -> Reply {
    Reply::Send(response(200, &[], body.as_bytes()))
}

/// A complete response with a Content-Length.
pub(crate) fn response(status: u16, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n", body.len()).into_bytes();
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

pub(crate) struct TestServer {
    pub(crate) port: u16,
    pub(crate) connections: Arc<AtomicUsize>,
    pub(crate) requests: Arc<Mutex<Vec<Seen>>>,
    open: Arc<Mutex<Vec<TcpStream>>>,
    stop: Arc<AtomicBool>,
    pki: Option<TestPki>,
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

impl TestServer {
    /// Plain TCP; use [`client`](TestServer::client), which allows `http://` URLs.
    pub(crate) fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> TestServer {
        TestServer::launch(Arc::new(handler), None, |config| config)
    }

    /// TLS, with a certificate for `127.0.0.1` and `localhost` under a root that [`client`](TestServer::client) trusts.
    pub(crate) fn start_tls(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> TestServer {
        TestServer::start_tls_with(handler, |config| config)
    }

    /// TLS with the server configured further (suites, records, tickets, ...).
    pub(crate) fn start_tls_with(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static, configure: impl FnOnce(ServerConfig) -> ServerConfig) -> TestServer {
        let pki = TestPki::new(&["127.0.0.1", "localhost"]).unwrap();
        TestServer::launch(Arc::new(handler), Some(pki), configure)
    }

    fn launch(handler: Handler, pki: Option<TestPki>, configure: impl FnOnce(ServerConfig) -> ServerConfig) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let open = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let tls = pki.as_ref().map(|p| Arc::new(configure(ServerConfig::from_pki(p))));
        {
            let (connections, requests, open, stop) = (connections.clone(), requests.clone(), open.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let conn = connections.fetch_add(1, Ordering::SeqCst);
                            let raw = stream.try_clone().unwrap();
                            open.lock().unwrap().push(stream.try_clone().unwrap());
                            let (handler, requests, tls) = (handler.clone(), requests.clone(), tls.clone());
                            thread::spawn(move || {
                                let wire: Box<dyn Wire> = match &tls {
                                    None => Box::new(stream),
                                    Some(config) => {
                                        let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                                        match ServerStream::accept(stream, config) {
                                            Ok(s) => Box::new(s),
                                            Err(_) => return, // the client did not like the certificate, or left
                                        }
                                    }
                                };
                                serve(conn, wire, &raw, &*handler, &requests)
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(2)),
                    }
                }
            });
        }
        TestServer { port, connections, requests, open, stop, pki }
    }

    /// A client for this server: it trusts the server's root (TLS) or may use `http://` (plain), and times out
    /// after five seconds.
    pub(crate) fn client(&self) -> Client {
        match &self.pki {
            Some(pki) => Client::with_tls_config(ClientConfig::new(pki.trust_store())),
            None => Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty())).allow_insecure_http(true),
        }
        .timeout(Duration::from_secs(5))
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}://127.0.0.1:{}{}", if self.pki.is_some() { "https" } else { "http" }, self.port, path)
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn requests(&self) -> Vec<Seen> {
        self.requests.lock().unwrap().clone()
    }

    /// Closes every connection the server holds, as a server does when a connection has been idle too long
    /// (a TCP close with no TLS close_notify first).
    pub(crate) fn close_all(&self) {
        for s in self.open.lock().unwrap().iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.close_all();
    }
}

/// Reads requests from one connection until it is closed and answers each as `handler` says.
fn serve(conn: usize, mut stream: Box<dyn Wire>, raw: &TcpStream, handler: &(dyn Fn(&Seen) -> Reply + Send + Sync), requests: &Mutex<Vec<Seen>>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut nth = 0;
    loop {
        // the head
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let length: usize =
            head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
        // a request that waits for the go-ahead gets it before its body is read, unless its path starts with /silent (a server
        // that does not do expectations, and waits for the body)
        let path = head.split(' ').nth(1).unwrap_or("");
        if length > 0 && buf.len() < length && !path.starts_with("/silent") && head.lines().any(|l| l.eq_ignore_ascii_case("expect: 100-continue")) {
            if stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").and_then(|_| stream.flush()).is_err() {
                return;
            }
        }
        while buf.len() < length {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body: Vec<u8> = buf.drain(..length).collect();
        let seen = Seen { conn, nth, head, body };
        nth += 1;
        requests.lock().unwrap().push(seen.clone());
        match handler(&seen) {
            Reply::Send(bytes) => {
                if stream.write_all(&bytes).and_then(|_| stream.flush()).is_err() {
                    return;
                }
            }
            Reply::SendAndClose(bytes) => {
                let _ = stream.write_all(&bytes).and_then(|_| stream.flush());
                drop(stream); // a TLS stream says close_notify as it goes
                let _ = raw.shutdown(Shutdown::Both);
                return;
            }
            Reply::Close => {
                drop(stream);
                let _ = raw.shutdown(Shutdown::Both);
                return;
            }
            Reply::Cut => {
                let _ = raw.shutdown(Shutdown::Both);
                return;
            }
            Reply::Run(f) => {
                if !f(&mut *stream) {
                    drop(stream);
                    let _ = raw.shutdown(Shutdown::Both);
                    return;
                }
                if stream.flush().is_err() {
                    return;
                }
            }
        }
    }
}
