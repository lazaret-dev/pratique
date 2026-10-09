//! A scripted HTTP/2 server for the tests of the client's HTTP/2 transport: the crate's own TLS server with ALPN
//! `h2` (or whatever the test configures), and on each connection [`h2_server::serve_with`] playing out the steps
//! the test's handler returns for each request. It counts connections and records each request (and what the
//! server found wrong with it: [`H2Server::complaints`] must stay empty in a test of a well-behaved client).

use super::h2_server::{serve_with, Request, ServerConn, Settings, Step};
use crate::tls::pki::TestPki;
use crate::tls::server::{ServerConfig, ServerStream};
use crate::tls::ClientConfig;
use crate::Client;
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
    pub(crate) request: Request,
}

impl Seen {
    pub(crate) fn path(&self) -> &str {
        &self.request.path
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.request.body
    }

    /// The first header field with this (lower case) name.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.request.header(name)
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Vec<Step> + Send + Sync>;

pub(crate) struct H2Server {
    pub(crate) port: u16,
    connections: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Seen>>>,
    complaints: Arc<Mutex<Vec<String>>>,
    open: Arc<Mutex<Vec<TcpStream>>>,
    stop: Arc<AtomicBool>,
    pki: TestPki,
}

impl H2Server {
    /// A server that selects `h2` and answers as `handler` says.
    pub(crate) fn start(handler: impl Fn(&Seen) -> Vec<Step> + Send + Sync + 'static) -> H2Server {
        H2Server::start_with(handler, Settings::default(), |config| config)
    }

    /// With the server's HTTP/2 settings and its TLS configuration (the ALPN protocols, say) as given.
    pub(crate) fn start_with(handler: impl Fn(&Seen) -> Vec<Step> + Send + Sync + 'static, settings: Settings, configure: impl FnOnce(ServerConfig) -> ServerConfig) -> H2Server {
        let pki = TestPki::new(&["127.0.0.1", "localhost"]).unwrap();
        let tls = Arc::new(configure(ServerConfig::from_pki(&pki).with_alpn(&["h2"])));
        let handler: Handler = Arc::new(handler);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let complaints = Arc::new(Mutex::new(Vec::new()));
        let open = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (connections, ended, requests, complaints, open, stop) = (connections.clone(), ended.clone(), requests.clone(), complaints.clone(), open.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let conn = connections.fetch_add(1, Ordering::SeqCst);
                            let raw = stream.try_clone().unwrap();
                            open.lock().unwrap().push(stream.try_clone().unwrap());
                            let (handler, requests, complaints, tls, settings, ended) = (handler.clone(), requests.clone(), complaints.clone(), tls.clone(), settings.clone(), ended.clone());
                            thread::spawn(move || {
                                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                                let Ok(mut io) = ServerStream::accept(stream, &tls) else {
                                    ended.fetch_add(1, Ordering::SeqCst);
                                    return;
                                };
                                let mut server = ServerConn::new(settings);
                                let mut on_request = |r: &Request| {
                                    let seen = Seen { conn, request: r.clone() };
                                    requests.lock().unwrap().push(seen.clone());
                                    handler(&seen)
                                };
                                let result = serve_with(&mut io, &mut server, &mut on_request);
                                complaints.lock().unwrap().extend(server.complaints().iter().map(|c| format!("connection {conn}: {c}")));
                                match result {
                                    Ok(super::h2_server::Ended::Cut) => {
                                        let _ = raw.shutdown(Shutdown::Both);
                                    }
                                    _ => {
                                        drop(io);
                                        let _ = raw.shutdown(Shutdown::Both);
                                    }
                                }
                                ended.fetch_add(1, Ordering::SeqCst);
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(2)),
                    }
                }
            });
        }
        H2Server { port, connections, ended, requests, complaints, open, stop, pki }
    }

    /// A client that trusts the server's root, speaks HTTP/2, and gives up on a silent server after five seconds.
    pub(crate) fn client(&self) -> Client {
        Client::with_tls_config(ClientConfig::new(self.pki.trust_store())).http2(true).timeout(Duration::from_secs(5))
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.port, path)
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn requests(&self) -> Vec<Seen> {
        self.requests.lock().unwrap().clone()
    }

    /// How many of the accepted connections have ended on the server's side.
    pub(crate) fn ended_connections(&self) -> usize {
        self.ended.load(Ordering::SeqCst)
    }

    /// The trust store that holds the server's root.
    pub(crate) fn client_trust(&self) -> crate::x509::TrustStore {
        self.pki.trust_store()
    }

    /// Closes every connection, waits for the server's side of each to finish, and returns what the server found
    /// wrong with what the client sent: empty for a client that follows the protocol.
    pub(crate) fn end_and_complaints(&self) -> Vec<String> {
        self.close_all();
        let give_up = std::time::Instant::now() + Duration::from_secs(3);
        while self.ended.load(Ordering::SeqCst) < self.connections.load(Ordering::SeqCst) && std::time::Instant::now() < give_up {
            thread::sleep(Duration::from_millis(5));
        }
        self.complaints.lock().unwrap().clone()
    }

    /// Closes every connection the server holds, with no goodbye.
    pub(crate) fn close_all(&self) {
        for s in self.open.lock().unwrap().iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for H2Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.close_all();
    }
}
