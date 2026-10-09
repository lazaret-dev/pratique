//! The network side on loopback (BACKLOG B-54): handshake latency, requests per second with and without keep-alive, small
//! messages, and bulk throughput for each cipher suite. The peer is the crate's own TLS 1.3 server (the `server` feature)
//! in this process on 127.0.0.1, so it shares the CPUs with the client and its certificate is Ed25519 (what the test server
//! signs with): these are figures to compare between builds and between machines, not a measure of a real network or of a
//! real server's certificate.
//!
//! ```text
//! cargo run --release --features server --example bench_net -- [--quick] [--tsv FILE] [--label NAME]
//! ```
//!
//! `--quick` takes a tenth of the samples. Latencies are medians (with the 90th percentile shown); rates and throughputs
//! are the best of three runs. See `examples/bench.rs` for `--tsv` and `--label`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use pratique::http::h2_server;
use pratique::tls::pki::TestPki;
use pratique::tls::server::{ServerConfig, ServerStream};
use pratique::tls::{ClientConfig, Resumption, Suite, TlsStream};
use pratique::Client;

#[path = "common/report.rs"]
mod report;
use report::{has_flag, Report};

/// What a server does with a connection once the handshake is done.
#[derive(Clone, Copy)]
enum Service {
    /// Writes one byte (so the client reads the tickets that come before it), then waits for the client to go.
    Handshake,
    /// HTTP/1.1: answers every request with `SMALL_BODY` bytes, keeping the connection open unless asked not to.
    Http1,
    /// HTTP/2: the same over h2.
    Http2,
    /// Reads an 8-byte count, then that many bytes in whatever records come, then writes one byte back.
    Sink,
    /// Reads an 8-byte count, then writes that many bytes in 16 KiB writes.
    Source,
}

/// The body of each HTTP response.
const SMALL_BODY: usize = 100;

/// Starts a server on 127.0.0.1 that does `service` with every connection, on a thread each.
fn serve(config: ServerConfig, service: Service) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { continue };
            socket.set_nodelay(true).ok();
            let config = config.clone();
            thread::spawn(move || {
                let Ok(mut stream) = ServerStream::accept(socket, &config) else { return };
                match service {
                    Service::Handshake => {
                        if stream.write_all(b"k").and_then(|_| stream.flush()).is_ok() {
                            let _ = stream.read(&mut [0u8; 16]);
                        }
                    }
                    Service::Http1 => http1(stream),
                    Service::Http2 => {
                        let mut conn = h2_server::ServerConn::new(h2_server::Settings::default());
                        let body = vec![b'x'; SMALL_BODY];
                        let mut handler = |_: &h2_server::Request| h2_server::response(200, &[("content-length", &SMALL_BODY.to_string())], &body);
                        let _ = h2_server::serve_with(&mut stream, &mut conn, &mut handler);
                    }
                    Service::Sink => {
                        let mut n = [0u8; 8];
                        if stream.read_exact(&mut n).is_ok() {
                            let mut left = u64::from_be_bytes(n);
                            let mut buf = vec![0u8; 1 << 16];
                            while left > 0 {
                                match stream.read(&mut buf) {
                                    Ok(0) | Err(_) => return,
                                    Ok(k) => left = left.saturating_sub(k as u64),
                                }
                            }
                            let _ = stream.write_all(b"k").and_then(|_| stream.flush());
                        }
                    }
                    Service::Source => {
                        let mut n = [0u8; 8];
                        if stream.read_exact(&mut n).is_ok() {
                            let mut left = u64::from_be_bytes(n) as usize;
                            let chunk = vec![0xa5u8; 16_384];
                            while left > 0 {
                                let k = left.min(chunk.len());
                                if stream.write_all(&chunk[..k]).is_err() {
                                    return;
                                }
                                left -= k;
                            }
                            let _ = stream.flush();
                            let _ = stream.read(&mut [0u8; 16]);
                        }
                    }
                }
            });
        }
    });
    addr
}

/// HTTP/1.1 requests on one connection, each answered with `SMALL_BODY` bytes, until the client closes or asks to.
fn http1(mut stream: ServerStream<TcpStream>) {
    let body = vec![b'x'; SMALL_BODY];
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(k) => buf.extend_from_slice(&chunk[..k]),
            }
        };
        let close = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase().contains("\r\nconnection: close");
        buf.drain(..end);
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {SMALL_BODY}\r\n{}\r\n", if close { "Connection: close\r\n" } else { "" });
        let mut out = head.into_bytes();
        out.extend_from_slice(&body);
        if stream.write_all(&out).and_then(|_| stream.flush()).is_err() || close {
            return;
        }
    }
}

/// The median and the 90th percentile of `samples` (seconds), in milliseconds.
fn median_p90(mut samples: Vec<f64>) -> (f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize] * 1e3;
    (at(0.5), at(0.9))
}

/// The best of three runs of `run`, which returns how many things it did and in how many seconds: things per second.
fn best_rate(mut run: impl FnMut() -> (usize, f64)) -> f64 {
    let _ = run(); // warm up
    (0..3).map(|_| run()).map(|(n, secs)| n as f64 / secs).fold(0.0, f64::max)
}

fn main() {
    let mut r = Report::from_args();
    let scale = if has_flag("--quick") { 10 } else { 1 };
    let pki = TestPki::new(&["localhost", "127.0.0.1"]).expect("a test PKI");
    let trust = || ClientConfig::new(pki.trust_store());
    println!("(loopback, against the crate's own TLS 1.3 server in this process; its certificate is Ed25519)");

    // ---- handshake latency: TCP connect + TLS handshake, as the client sees it
    let handshakes = 400 / scale;
    let latency = |addr: SocketAddr, config: &ClientConfig, expect_resumed: bool| -> Vec<f64> {
        let mut samples = Vec::with_capacity(handshakes);
        for i in 0..handshakes + 10 {
            let t = Instant::now();
            let tcp = TcpStream::connect(addr).expect("connect");
            tcp.set_nodelay(true).ok();
            let mut tls = TlsStream::connect(tcp, "localhost", config).expect("handshake");
            let secs = t.elapsed().as_secs_f64();
            assert_eq!(tls.is_resumed(), expect_resumed && i > 0, "resumed or not, as expected");
            // the byte the server writes comes after its tickets: reading it keeps them for the next connection
            let mut k = [0u8; 1];
            tls.read_exact(&mut k).expect("the server's byte");
            if i >= 10 {
                samples.push(secs);
            }
        }
        samples
    };
    let full = trust().with_resumption(Resumption::off());
    for (name, group) in [("X25519", None), ("P-256, by HelloRetryRequest", Some(0x0017u16)), ("P-384, by HelloRetryRequest", Some(0x0018u16))] {
        let mut config = ServerConfig::from_pki(&pki);
        if let Some(g) = group {
            config = config.with_groups(&[g]);
        }
        let addr = serve(config, Service::Handshake);
        let (median, p90) = median_p90(latency(addr, &full, false));
        r.row(&format!("TLS 1.3 handshake, full, {name} (median)"), median, "ms");
        println!("{:<58} {p90:9.2} ms", "    (90th percentile)");
    }
    let addr = serve(ServerConfig::from_pki(&pki), Service::Handshake);
    let resuming = trust();
    let (median, p90) = median_p90(latency(addr, &resuming, true));
    r.row("TLS 1.3 handshake, resumed, X25519 (median)", median, "ms");
    println!("{:<58} {p90:9.2} ms", "    (90th percentile)");

    // ---- requests per second, one at a time, 100-byte bodies
    let requests = 2000 / scale;
    let addr = serve(ServerConfig::from_pki(&pki), Service::Http1);
    let url = format!("https://localhost:{}/", addr.port());
    let rate = |client: &Client, n: usize| {
        best_rate(|| {
            let t = Instant::now();
            for _ in 0..n {
                let resp = client.get(&url).expect("a response");
                assert_eq!((resp.status, resp.body.len()), (200, SMALL_BODY));
            }
            (n, t.elapsed().as_secs_f64())
        })
    };
    let keep = Client::with_tls_config(trust());
    r.row("HTTP/1.1 requests, keep-alive", rate(&keep, requests), "per s");
    let fresh = Client::with_tls_config(trust()).keep_alive(false);
    r.row("HTTP/1.1 requests, a connection each, resumed", rate(&fresh, requests / 4), "per s");
    let fresh_full = Client::with_tls_config(trust().with_resumption(Resumption::off())).keep_alive(false);
    r.row("HTTP/1.1 requests, a connection each, full handshake", rate(&fresh_full, requests / 4), "per s");
    let addr2 = serve(ServerConfig::from_pki(&pki).with_alpn(&["h2"]), Service::Http2);
    let url2 = format!("https://localhost:{}/", addr2.port());
    let h2 = Client::with_tls_config(trust()).http2(true);
    let rate2 = best_rate(|| {
        let t = Instant::now();
        for _ in 0..requests {
            let resp = h2.get(&url2).expect("a response");
            assert_eq!((resp.status, resp.body.len()), (200, SMALL_BODY));
        }
        (requests, t.elapsed().as_secs_f64())
    });
    r.row("HTTP/2 requests, one connection", rate2, "per s");
    let h2 = Arc::new(h2);
    let rate2p = best_rate(|| {
        let t = Instant::now();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (h2, url2) = (h2.clone(), url2.clone());
                thread::spawn(move || {
                    for _ in 0..requests / 8 {
                        assert_eq!(h2.get(&url2).expect("a response").status, 200);
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().expect("a worker");
        }
        (requests / 8 * 8, t.elapsed().as_secs_f64())
    });
    r.row("HTTP/2 requests, 8 threads on one connection", rate2p, "per s");

    // ---- small messages: one record each, client to server
    let addr = serve(ServerConfig::from_pki(&pki), Service::Sink);
    for size in [100usize, 1000] {
        let count = 50_000 / scale;
        let msg = vec![0x5au8; size];
        let per_s = best_rate(|| {
            let tcp = TcpStream::connect(addr).expect("connect");
            tcp.set_nodelay(true).ok();
            let mut tls = TlsStream::connect(tcp, "localhost", &trust()).expect("handshake");
            tls.write_all(&((count * size) as u64).to_be_bytes()).unwrap();
            let t = Instant::now();
            for _ in 0..count {
                tls.write_all(&msg).unwrap();
            }
            tls.flush().unwrap();
            let mut k = [0u8; 1];
            tls.read_exact(&mut k).expect("the server's byte");
            (count, t.elapsed().as_secs_f64())
        });
        r.row(&format!("small messages, {size} B a write (one record each)"), per_s, "per s");
        r.row(&format!("small messages, {size} B a write: throughput"), per_s * size as f64 / 1e6, "MB/s");
    }

    // ---- bulk, server to client, each suite
    let bytes = (256usize << 20) / scale;
    for (name, suite) in [("AES-128-GCM", Suite::Aes128GcmSha256), ("AES-256-GCM", Suite::Aes256GcmSha384), ("ChaCha20-Poly1305", Suite::Chacha20Poly1305Sha256)] {
        let addr = serve(ServerConfig::from_pki(&pki).with_suites(&[suite]), Service::Source);
        let mbps = best_rate(|| {
            let tcp = TcpStream::connect(addr).expect("connect");
            let mut tls = TlsStream::connect(tcp, "localhost", &trust()).expect("handshake");
            assert_eq!(tls.cipher_suite(), Some(suite));
            let t = Instant::now();
            tls.write_all(&(bytes as u64).to_be_bytes()).unwrap();
            tls.flush().unwrap();
            let mut buf = vec![0u8; 1 << 16];
            let mut got = 0usize;
            while got < bytes {
                match tls.read(&mut buf) {
                    Ok(0) => panic!("the server stopped at {got} of {bytes} bytes"),
                    Ok(k) => got += k,
                    Err(e) => panic!("{e}"),
                }
            }
            (bytes, t.elapsed().as_secs_f64())
        }) / 1e6;
        r.row(&format!("bulk download over TLS 1.3, {name}"), mbps, "MB/s");
    }
}
