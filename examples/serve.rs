//! A small HTTPS test server on pratique's TLS 1.3 server, for pointing other programs at: `openssl s_client`,
//! `curl`, a Go client, a browser that has been told to trust the root.
//!
//! The HTTP is the production server's (`pratique::http::server`, B-111: HTTP/1.1, and HTTP/2 when ALPN picks `h2`),
//! under its runtime (`ServerBuilder`, B-112: the default limits and timeouts), with the pages below as its handler; `server=test` runs the test servers the crate's own client tests script
//! instead (an HTTP/1.1 loop written here, and `pratique::http::h2_server`), which can also push.
//!
//! FOR TESTS: the server is not ready for production yet (BACKLOG B-114: no review yet; `acme_serve` is the example
//! with ACME). The throwaway certificate and its key are made fresh at each start and mean nothing. Do not expose this to
//! a network.
//!
//!     cargo run --release --features server --example serve -- [options]
//!
//!   port=N            listen on 127.0.0.1:N (default 0: a free port, printed)
//!   names=a,b         DNS names or IP addresses of the certificate (default localhost,127.0.0.1,::1)
//!   keytype=NAME      the throwaway certificate's key: ed25519 (default), p256 or p384
//!   rootkey=NAME      the throwaway root's key, the same choices (browsers take no Ed25519 in a chain: use p256)
//!   certfile=FILE     serve this certificate chain (PEM, leaf first) instead of a throwaway one, with
//!   keyfile=FILE      its private key (PEM: PKCS#8, SEC 1 or PKCS#1; ECDSA P-256/P-384, Ed25519 or RSA)
//!   names2=a,b        a second throwaway certificate under the same root, for these names (the client's SNI picks)
//!   clientca=FILE     ask for client certificates that lead to the CA certificates in FILE (PEM), and with
//!   clientauth=MODE   require them (`required`, the default) or take them if offered (`optional`)
//!   ca=FILE           write the root certificate (PEM) there (default: serve-root.pem)
//!   alpn=h2,http/1.1  ALPN protocols, in the server's order (default: none)
//!   suite=NAME        only this cipher suite: aes128, aes256 or chacha
//!   group=NAME        only this key exchange group: x25519, p256 or p384
//!   fragment=N        at most N bytes of plaintext per record
//!   tickets=N         NewSessionTicket messages after the handshake (default 1)
//!   late_tickets=1    send them after the first response bytes instead of before
//!   rekey=N           rotate our keys after N records
//!   server=test       the test servers instead of the production one (see above)
//!   plain=1           plain HTTP instead of TLS (the production server: HTTP/1.1, or HTTP/2 with prior knowledge)
//!   plain=h2          plain HTTP/2 with prior knowledge only (what h2spec expects of a server)
//!   quiet=1           no line per request (for load tests)
//!
//! It prints `listening 127.0.0.1:PORT` once it is ready, and one line per connection and per request.
//!
//! The pages: `/` a short text; `/size/N` N bytes of a repeating pattern; `/echo` (any method) answers with the
//! request body; `/chunked/N` N bytes sent chunked; `/close` answers and closes the connection; `/slow/N` N
//! bytes, one at a time with a pause. Connections are kept alive as HTTP/1.1 does.
//!
//! With `alpn=h2` (or `h2,http/1.1`) a client that offers h2 gets HTTP/2, with the same pages (`/chunked/N` is N
//! bytes in pieces of 1000) and some more: `/trailers` (a body and trailers), `/interim` (a 103 and then the answer),
//! `/reset` (RST_STREAM INTERNAL_ERROR after a part of a body; over HTTP/1.1, a chunked body that is cut off),
//! `/goaway` (the answer, then a GOAWAY with no error: the client is to use another connection), `/headers/N` (N
//! header fields of 100 bytes in the response, so that the header block takes CONTINUATION frames), `/status/N`
//! (status N, no body), and, from the test server only, `/push` (a PUSH_PROMISE, which a client that switched push off
//! must treat as an error). Each request is checked as it comes; a connection the server finds fault with is reported
//! on its line ("the server found fault").

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use pratique::http::h2_server::{self, Action, Step};
use pratique::http::server::{Request, Response, ServerBuilder, Version};
use pratique::crypto::ecdsa::Curve;
use pratique::tls::certs::{CertStore, CertifiedKey};
use pratique::tls::pki::{issue, CertSpec, KeyPair, TestPki};
use pratique::x509::TrustStore;
use pratique::tls::server::{ClientAuth, ServerConfig, ServerStream};
use pratique::tls::Suite;

fn main() {
    let mut opts = std::collections::HashMap::new();
    for a in std::env::args().skip(1) {
        match a.split_once('=') {
            Some((k, v)) => {
                opts.insert(k.to_string(), v.to_string());
            }
            None => {
                eprintln!("{}", include_str!("serve.rs").lines().take_while(|l| l.starts_with("//")).map(|l| l.trim_start_matches("//").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
                std::process::exit(2);
            }
        }
    }
    let get = |k: &str, default: &str| opts.get(k).cloned().unwrap_or_else(|| default.to_string());

    let names = get("names", "localhost,127.0.0.1,::1");
    let names: Vec<&str> = names.split(',').collect();
    let ca_path = get("ca", "serve-root.pem");
    let mut config = match (opts.get("certfile"), opts.get("keyfile")) {
        (Some(c), Some(k)) => {
            let chain = std::fs::read_to_string(c).expect("read certfile");
            let key = std::fs::read_to_string(k).expect("read keyfile");
            ServerConfig::from_pem(&chain, &key).unwrap_or_else(|e| panic!("{e}"))
        }
        (None, None) => {
            let key_of = |option: &str| {
                match get(option, "ed25519").as_str() {
                    "ed25519" => KeyPair::generate(),
                    "p256" => KeyPair::generate_ecdsa(Curve::P256),
                    "p384" => KeyPair::generate_ecdsa(Curve::P384),
                    other => panic!("unknown {option} {other}"),
                }
                .expect("random numbers")
            };
            let server_key = key_of("keytype");
            let root_key = key_of("rootkey");
            let pki = TestPki::with_keys(CertSpec::server(&names), &root_key, server_key);
            std::fs::write(&ca_path, pki.root_pem()).expect("write the root certificate");
            let store = CertStore::single(CertifiedKey::new(pki.chain.clone(), pki.server_key.signing_key().clone()).expect("the test certificate"));
            if let Some(n2) = opts.get("names2") {
                // a second certificate under the same root ("pratique test root", as TestPki names it)
                let names2: Vec<&str> = n2.split(',').collect();
                let key2 = KeyPair::generate_ecdsa(Curve::P256).expect("random numbers");
                let der = issue(&CertSpec::server(&names2), &key2, Some(("pratique test root", &root_key)));
                store.add(CertifiedKey::new(vec![der], key2.signing_key().clone()).expect("the second certificate"));
            }
            ServerConfig::with_certificates(store)
        }
        _ => panic!("certfile= and keyfile= go together"),
    };
    if let Some(a) = opts.get("alpn") {
        config = config.with_alpn(&a.split(',').collect::<Vec<_>>());
    }
    if let Some(path) = opts.get("clientca") {
        let mut roots = TrustStore::empty();
        let n = roots.add_pem(&std::fs::read_to_string(path).expect("read clientca"));
        assert!(n > 0, "no certificate in {path}");
        let roots = Arc::new(roots);
        config = config.with_client_auth(match get("clientauth", "required").as_str() {
            "required" => ClientAuth::Required(roots),
            "optional" => ClientAuth::Optional(roots),
            other => panic!("unknown clientauth {other}"),
        });
    }
    if let Some(s) = opts.get("suite") {
        let suite = match s.as_str() {
            "aes128" => Suite::Aes128GcmSha256,
            "aes256" => Suite::Aes256GcmSha384,
            "chacha" => Suite::Chacha20Poly1305Sha256,
            other => panic!("unknown suite {other}"),
        };
        config = config.with_suites(&[suite]);
    }
    if let Some(g) = opts.get("group") {
        config = config.with_groups(&[match g.as_str() {
            "x25519" => 0x001d,
            "p256" => 0x0017,
            "p384" => 0x0018,
            other => panic!("unknown group {other}"),
        }]);
    }
    if let Some(n) = opts.get("fragment") {
        config = config.with_max_fragment(n.parse().expect("fragment=N"));
    }
    config.tickets = get("tickets", "1").parse().expect("tickets=N");
    config.tickets_after_first_write = opts.contains_key("late_tickets");
    if let Some(n) = opts.get("rekey") {
        config = config.with_rekey_after_records(n.parse().expect("rekey=N"));
    }
    let config = Arc::new(config);
    let test_server = get("server", "production") == "test";
    QUIET.store(opts.contains_key("quiet"), std::sync::atomic::Ordering::Relaxed);
    let plain = opts.contains_key("plain");
    let h2c = opts.get("plain").is_some_and(|v| v == "h2");
    let addr = format!("127.0.0.1:{}", get("port", "0"));
    if !test_server {
        // the production server, under its runtime (B-112): its listener, limits and timeouts
        let builder = ServerBuilder::new(page)
            .error_log(|peer, e| {
                let who = peer.map(|p| p.to_string()).unwrap_or_default();
                if e.kind() == std::io::ErrorKind::InvalidData {
                    println!("connection from {who}: the server found fault: {e}");
                } else {
                    println!("connection from {who}: ended: {e}");
                }
            });
        let builder = if h2c {
            builder.h2c(&addr)
        } else if plain {
            builder.plain(&addr)
        } else {
            builder.tls(&addr, config)
        };
        let server = builder.start().expect("start the server");
        println!("listening {}", server.local_addrs()[0]);
        println!("root certificate in {ca_path}");
        server.wait();
        return;
    }
    let listener = TcpListener::bind(&addr).expect("bind");
    println!("listening {}", listener.local_addr().unwrap());
    println!("root certificate in {ca_path}");
    for (n, socket) in listener.incoming().enumerate() {
        let Ok(socket) = socket else { continue };
        let config = config.clone();
        thread::spawn(move || {
            socket.set_read_timeout(Some(Duration::from_secs(30))).ok();
            match ServerStream::accept(socket, &config) {
                Ok(stream) => {
                    println!(
                        "connection {n}: {:?} group {:#06x} alpn {:?} sni {:?} resumed {} client certificates {}",
                        stream.cipher_suite().map(|s| s.name()),
                        stream.group().unwrap_or(0),
                        stream.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
                        stream.server_name(),
                        stream.is_resumed(),
                        stream.peer_certificates().len()
                    );
                    if stream.alpn_protocol() == Some(b"h2".as_slice()) {
                        serve_h2(n, stream);
                    } else {
                        serve(n, stream);
                    }
                }
                Err(e) => println!("connection {n}: handshake failed: {e}"),
            }
        });
    }
}

/// Answers requests on one connection until the client is done.
fn serve(n: usize, mut stream: ServerStream<TcpStream>) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(k) => buf.extend_from_slice(&chunk[..k]),
                Err(e) => {
                    println!("connection {n}: {e}");
                    return;
                }
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or("").to_string();
        let mut parts = request_line.split(' ');
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
        let header = |name: &str| lines.clone().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()));
        let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        while buf.len() < length {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(k) => buf.extend_from_slice(&chunk[..k]),
            }
        }
        let body: Vec<u8> = buf.drain(..length).collect();
        println!("connection {n}: {request_line}");
        let close = header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close")) || path == "/close";
        let connection = if close { "Connection: close\r\n" } else { "" };
        let ok = |len: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n{connection}\r\n");
        let pattern = |len: usize| -> Vec<u8> { (0..len).map(|i| b'a' + (i % 26) as u8).collect() };
        let written = if let Some(k) = path.strip_prefix("/size/") {
            let data = pattern(k.parse().unwrap_or(0));
            stream.write_all(ok(data.len()).as_bytes()).and_then(|_| stream.write_all(&data))
        } else if path == "/echo" {
            stream.write_all(ok(body.len()).as_bytes()).and_then(|_| stream.write_all(&body))
        } else if let Some(k) = path.strip_prefix("/chunked/") {
            let data = pattern(k.parse().unwrap_or(0));
            let mut out = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n{connection}\r\n").into_bytes();
            for piece in data.chunks(1000) {
                out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                out.extend_from_slice(piece);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
            stream.write_all(&out)
        } else if let Some(k) = path.strip_prefix("/slow/") {
            let data = pattern(k.parse().unwrap_or(0));
            let mut r = stream.write_all(ok(data.len()).as_bytes());
            for b in &data {
                if r.is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
                r = stream.write_all(&[*b]).and_then(|_| stream.flush());
            }
            r
        } else if method == "HEAD" {
            stream.write_all(ok(5).as_bytes())
        } else {
            let text = b"hello from pratique\n";
            stream.write_all(ok(text.len()).as_bytes()).and_then(|_| stream.write_all(text))
        };
        if written.and_then(|_| stream.flush()).is_err() || close {
            return;
        }
    }
}

/// Answers the requests of one HTTP/2 connection until the client is done.
fn serve_h2(n: usize, mut stream: ServerStream<TcpStream>) {
    let mut conn = h2_server::ServerConn::new(h2_server::Settings::default());
    let mut handler = |r: &h2_server::Request| -> Vec<Step> {
        println!("connection {n}: h2 stream {} {} {}", r.stream, r.method, r.path);
        h2_page(r)
    };
    let ended = h2_server::serve_with(&mut stream, &mut conn, &mut handler);
    for c in conn.complaints() {
        println!("connection {n}: h2 complaint: {c}");
    }
    println!("connection {n}: h2 ended: {ended:?}");
}

fn h2_page(r: &h2_server::Request) -> Vec<Step> {
    let pattern = |len: usize| -> Vec<u8> { (0..len).map(|i| b'a' + (i % 26) as u8).collect() };
    let number = |prefix: &str| r.path.strip_prefix(prefix).and_then(|k| k.parse::<usize>().ok());
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let head = |status: u16, headers: Vec<(String, String)>, end: bool| Step::now(Action::Head { status, headers, end });
    if let Some(k) = number("/size/") {
        let len = pattern(k).len().to_string();
        let mut steps = vec![head(200, vec![pair("content-length", &len)], k == 0 || r.method == "HEAD")];
        if k > 0 && r.method != "HEAD" {
            steps.push(Step::now(Action::Data(pattern(k))));
            steps.push(Step::now(Action::End));
        }
        steps
    } else if r.path == "/echo" {
        h2_server::response(200, &[("content-length", &r.body.len().to_string())], &r.body)
    } else if let Some(k) = number("/chunked/") {
        let mut steps = vec![head(200, vec![], false)];
        for piece in pattern(k).chunks(1000) {
            steps.push(Step::now(Action::Data(piece.to_vec())));
        }
        steps.push(Step::now(Action::End));
        steps
    } else if let Some(k) = number("/slow/") {
        let mut steps = vec![head(200, vec![pair("content-length", &k.to_string())], k == 0)];
        for b in pattern(k) {
            steps.push(Step::later(Duration::from_millis(20), Action::Data(vec![b])));
        }
        steps.push(Step::now(Action::End));
        steps
    } else if r.path == "/close" {
        let mut steps = h2_server::response(200, &[], b"closing\n");
        steps.push(Step::now(Action::GoAway { code: 0, last_stream: None }));
        steps
    } else if r.path == "/trailers" {
        vec![
            head(200, vec![pair("trailer", "x-sum")], false),
            Step::now(Action::Data(b"a body with trailers\n".to_vec())),
            Step::now(Action::Trailers(vec![pair("x-sum", "21")])),
        ]
    } else if r.path == "/interim" {
        let mut steps = vec![Step::now(Action::Interim { status: 103, headers: vec![pair("link", "</style.css>; rel=preload")] })];
        steps.extend(h2_server::response(200, &[], b"after the interim response\n"));
        steps
    } else if r.path == "/reset" {
        vec![head(200, vec![], false), Step::now(Action::Data(pattern(1000))), Step::now(Action::Reset(2))]
    } else if r.path == "/goaway" {
        let mut steps = h2_server::response(200, &[], b"going away\n");
        steps.push(Step::now(Action::GoAway { code: 0, last_stream: None }));
        steps
    } else if let Some(k) = number("/headers/") {
        let headers: Vec<(String, String)> = (0..k).map(|i| (format!("x-header-{i}"), format!("{i:0>100}"))).collect();
        vec![head(200, headers, false), Step::now(Action::Data(b"many headers\n".to_vec())), Step::now(Action::End)]
    } else if let Some(k) = number("/status/") {
        vec![head(k as u16, vec![], true)]
    } else if r.path == "/push" {
        let promised = vec![pair(":method", "GET"), pair(":scheme", "https"), pair(":authority", &r.authority), pair(":path", "/pushed")];
        let mut steps = vec![Step::now(Action::PushPromise { promised: 2, headers: promised })];
        steps.extend(h2_server::response(200, &[], b"with a promise\n"));
        steps
    } else if r.method == "HEAD" {
        vec![head(200, vec![pair("content-length", "5")], true)]
    } else {
        h2_server::response(200, &[], b"hello from pratique\n")
    }
}

static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The pages, for the production server.
fn page(req: Request) -> Response {
    let pattern = |len: usize| -> Vec<u8> { (0..len).map(|i| b'a' + (i % 26) as u8).collect() };
    let path = req.path().to_string();
    let number = |prefix: &str| path.strip_prefix(prefix).and_then(|k| k.parse::<usize>().ok());
    if !QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        let tls = req.connection().tls.as_ref().map(|t| format!(" {} alpn {:?} sni {:?} resumed {} client certificates {}", t.cipher_suite.unwrap_or("?"), t.alpn, t.server_name, t.resumed, t.client_certificates.len())).unwrap_or_default();
        println!("request from {}: {} {} {}{tls}", req.connection().peer.map(|p| p.to_string()).unwrap_or_default(), req.method(), req.target(), req.version());
    }
    if let Some(k) = number("/size/") {
        Response::bytes(200, "text/plain", cached_pattern(k))
    } else if path == "/echo" {
        let length = req.content_length();
        Response::reader(200, req.into_body(), length)
    } else if let Some(k) = number("/chunked/") {
        Response::stream(200, move |w| {
            for piece in pattern(k).chunks(1000) {
                w.write_all(piece)?;
                w.flush()?;
            }
            Ok(())
        })
    } else if let Some(k) = number("/slow/") {
        Response::reader(200, Slow(pattern(k), 0), Some(k as u64))
    } else if path == "/close" {
        let text: &[u8] = if req.version() == Version::Http2 { b"closing\n" } else { b"hello from pratique\n" };
        Response::bytes(200, "text/plain", text.to_vec()).with_header("connection", "close")
    } else if path == "/trailers" {
        Response::stream(200, |w| {
            w.write_all(b"a body with trailers\n")?;
            w.set_trailers(vec![("x-sum".into(), "21".into())]);
            Ok(())
        })
        .with_header("trailer", "x-sum")
    } else if path == "/interim" {
        let _ = req.send_interim(103, &[("link", "</style.css>; rel=preload")]);
        Response::text(200, "after the interim response\n")
    } else if path == "/reset" {
        Response::stream(200, move |w| {
            w.write_all(&pattern(1000))?;
            w.flush()?;
            Err(std::io::Error::other("the page stops here, on purpose"))
        })
    } else if path == "/goaway" {
        Response::text(200, "going away\n").with_header("connection", "close")
    } else if let Some(k) = number("/headers/") {
        let mut r = Response::text(200, "many headers\n");
        for i in 0..k {
            r = r.with_header(&format!("x-header-{i}"), &format!("{i:0>100}"));
        }
        r
    } else if let Some(k) = number("/status/") {
        Response::new(k as u16)
    } else {
        Response::text(200, "hello from pratique\n")
    }
}

/// The pattern of `/size/N`, made once per size (as the Go server of tools/bench_server.go does), and copied.
fn cached_pattern(n: usize) -> Vec<u8> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<usize, Arc<Vec<u8>>>>> = std::sync::OnceLock::new();
    if n > 16 << 20 {
        return (0..n).map(|i| b'a' + (i % 26) as u8).collect();
    }
    let cache = CACHE.get_or_init(Default::default);
    let mut c = cache.lock().unwrap();
    c.entry(n).or_insert_with(|| Arc::new((0..n).map(|i| b'a' + (i % 26) as u8).collect())).as_ref().clone()
}

/// A body that comes a byte at a time, 20 ms apart.
struct Slow(Vec<u8>, usize);

impl Read for Slow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1 == self.0.len() || buf.is_empty() {
            return Ok(0);
        }
        thread::sleep(Duration::from_millis(20));
        buf[0] = self.0[self.1];
        self.1 += 1;
        Ok(1)
    }
}
