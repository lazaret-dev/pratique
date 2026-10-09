//! A small HTTPS test server on pratique's TLS 1.3 server, for pointing other programs at: `openssl s_client`,
//! `curl`, a Go client, a browser that has been told to trust the root.
//!
//! EXPERIMENTAL, FOR TESTS: the signing is not constant-time and nothing here has been reviewed. The certificate
//! and its key are made fresh at each start and mean nothing. Do not expose this to a network.
//!
//!     cargo run --release --features server --example serve -- [options]
//!
//!   port=N            listen on 127.0.0.1:N (default 0: a free port, printed)
//!   names=a,b         DNS names or IP addresses of the certificate (default localhost,127.0.0.1,::1)
//!   ca=FILE           write the root certificate (PEM) there (default: serve-root.pem)
//!   alpn=h2,http/1.1  ALPN protocols, in the server's order (default: none)
//!   suite=NAME        only this cipher suite: aes128, aes256 or chacha
//!   group=NAME        only this key exchange group: x25519, p256 or p384
//!   fragment=N        at most N bytes of plaintext per record
//!   tickets=N         NewSessionTicket messages after the handshake (default 1)
//!   late_tickets=1    send them after the first response bytes instead of before
//!   rekey=N           rotate our keys after N records
//!
//! It prints `listening 127.0.0.1:PORT` once it is ready, and one line per connection and per request.
//!
//! The pages: `/` a short text; `/size/N` N bytes of a repeating pattern; `/echo` (any method) answers with the
//! request body; `/chunked/N` N bytes sent chunked; `/close` answers and closes the connection; `/slow/N` N
//! bytes, one at a time with a pause. Connections are kept alive as HTTP/1.1 does.
//!
//! With `alpn=h2` (or `h2,http/1.1`) a client that offers h2 gets HTTP/2 (`pratique::http::h2_server`), with
//! the same pages (`/chunked/N` is N bytes in pieces of 1000) and some more: `/trailers` (a body and trailers),
//! `/interim` (a 103 and then the answer), `/reset` (RST_STREAM INTERNAL_ERROR after a part of a body), `/goaway`
//! (the answer, then a GOAWAY with no error: the client is to use another connection), `/headers/N` (N header
//! fields of 100 bytes in the response, so that the header block takes CONTINUATION frames), `/status/N`
//! (status N, no body), and `/push` (a PUSH_PROMISE, which a client that switched push off must treat as an
//! error). Each request is checked as it comes; a request the server finds fault with is reported on the
//! connection's line.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use pratique::http::h2_server::{self, Action, Step};
use pratique::tls::pki::{CertSpec, TestPki};
use pratique::tls::server::{ServerConfig, ServerStream};
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
    let pki = TestPki::with_spec(CertSpec::server(&names)).expect("random numbers");
    let ca_path = get("ca", "serve-root.pem");
    std::fs::write(&ca_path, pki.root_pem()).expect("write the root certificate");

    let mut config = ServerConfig::from_pki(&pki);
    if let Some(a) = opts.get("alpn") {
        config = config.with_alpn(&a.split(',').collect::<Vec<_>>());
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

    let listener = TcpListener::bind(format!("127.0.0.1:{}", get("port", "0"))).expect("bind");
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
                        "connection {n}: {:?} group {:#06x} alpn {:?} sni {:?}",
                        stream.cipher_suite().map(|s| s.name()),
                        stream.group().unwrap_or(0),
                        stream.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
                        stream.server_name()
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
