//! Makes a QUIC handshake with a server over a UDP socket and prints what happened: a way to try the client's QUIC layer against
//! an implementation it was not written with (for instance `tools/quic_interop_server.py`, which is aioquic).
//!
//! Usage: cargo run --release --example quic_probe -- HOST:PORT SERVER_NAME CA.pem [--ping N] [--get PATH] [--post N]
//!        [--key-update-after N] [--idle-ms MS --quiet-for SECS]
//!
//! It connects, waits for the handshake to be confirmed and opens the three streams that every HTTP/3 client begins with (the
//! control stream with its SETTINGS, and QPACK's two; a server may close a connection that never sends them). Then, with `--get
//! PATH`, it sends one HTTP/3 request on a stream (a header block that uses nothing but the QPACK static table, which is all a
//! probe needs; the HTTP/3 client of the library is `pratique::http`), reads the response, takes the DATA frames apart, and
//! checks the body if the path is `/bytes/N` of the interop server. With `--post N` it sends a request with a body of N bytes to
//! `/echo` and checks what comes back. Otherwise it sends N PING frames (default 3), each one acknowledged before the next. It
//! ends by closing the connection with the application error 0, and prints the statistics. It gives up when nothing has
//! happened for 60 s (no PING answered, no byte of the response, none of the request written).
//!
//! `--key-update-after N` has the client update its keys every N packets (the server has to follow each update). `--quiet-for
//! SECS` waits that long after the handshake before it does anything, with the connection kept alive (as it is while a request
//! waits for its response): with `--idle-ms MS` below SECS, the connection lives through it only by the keep-alive PINGs. It says
//! "kept alive through" when the quiet time is over and the connection is still open.

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use pratique::quic::connection::{CloseReason, Config, Connection, Event};
use pratique::quic::streams::{StreamError, StreamEvent};
use pratique::tls::ClientConfig;
use pratique::x509::TrustStore;

fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        16384..=1073741823 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

fn get_varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let first = *b.get(*at)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*at..*at + len)?;
    let mut v = (first & 0x3f) as u64;
    for x in &bytes[1..] {
        v = (v << 8) | *x as u64;
    }
    *at += len;
    Some(v)
}

/// The request as an HTTP/3 HEADERS frame: `GET path` with the host, in a QPACK block with no dynamic table (RFC 9204).
fn request(method_index: u8, path: &str, authority: &str) -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // required insert count 0, base 0
    block.push(0xc0 | method_index); // :method GET (static index 17) or POST (20)
    block.push(0xc0 | 23); // :scheme https (23)
    // :path with a literal value, name from the static table (index 1)
    block.push(0x50 | 1);
    put_varint_prefixed(&mut block, path.as_bytes());
    // :authority (index 0)
    block.push(0x50);
    put_varint_prefixed(&mut block, authority.as_bytes());
    let mut frame = Vec::new();
    put_varint(&mut frame, 0x01); // HEADERS
    put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

/// A string literal of a QPACK field line: a length in 7 bits (no Huffman coding) and the bytes.
fn put_varint_prefixed(out: &mut Vec<u8>, s: &[u8]) {
    if s.len() < 127 {
        out.push(s.len() as u8);
    } else {
        out.push(127);
        let mut rest = s.len() - 127;
        while rest >= 128 {
            out.push((rest & 127) as u8 | 128);
            rest >>= 7;
        }
        out.push(rest as u8);
    }
    out.extend_from_slice(s);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: quic_probe HOST:PORT SERVER_NAME CA.pem [--ping N] [--get PATH]");
        std::process::exit(2);
    }
    let option = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let pings: usize = option("--ping").and_then(|n| n.parse().ok()).unwrap_or(3);
    let post: Option<usize> = option("--post").and_then(|n| n.parse().ok());
    let get = if post.is_some() { Some("/echo".to_string()) } else { option("--get") };
    let addr = args[0].to_socket_addrs().expect("address").next().expect("an address");
    let mut store = TrustStore::empty();
    let ca = std::fs::read_to_string(&args[2]).expect("the CA file");
    assert!(store.add_pem(&ca) > 0, "no certificate in the CA file");
    let mut tls = ClientConfig::new(store);
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let socket = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).expect("a socket");
    socket.connect(addr).expect("connect");
    let started = Instant::now();
    let mut config = Config::default();
    if let Some(n) = option("--key-update-after").and_then(|n| n.parse().ok()) {
        config.key_update_after = n;
    }
    if let Some(ms) = option("--idle-ms").and_then(|n| n.parse().ok()) {
        config.max_idle_timeout = Duration::from_millis(ms);
    }
    let quiet_for = option("--quiet-for").and_then(|n| n.parse().ok()).map(Duration::from_secs);
    let mut conn = Connection::connect(&config, &tls, &args[1], started).expect("a connection");

    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut read_buf = vec![0u8; 65536];
    let mut pings_sent = 0;
    let mut closed_by_us = false;
    let mut confirmed_at: Option<Instant> = None;
    let mut ping_marker: Option<u64> = None;
    // for --get
    let mut request_stream: Option<u64> = None;
    let mut response: Vec<u8> = Vec::new();
    let mut response_end = false;
    let mut request_started: Option<Instant> = None;
    // the rest of a request body to write: the bytes, and how many are written
    let mut upload: Vec<u8> = Vec::new();
    let mut uploaded = 0usize;
    // the three streams HTTP/3 begins with are open
    let mut h3_opened = false;
    // when something last happened (a PING answered, a byte of the response, some of the request written)
    let mut last_progress = Instant::now();
    let mut quiet_over = false;
    loop {
        let now = Instant::now();
        while conn.poll_transmit(now, &mut out) {
            if let Err(e) = socket.send(&out) {
                eprintln!("send failed: {e}");
            }
        }
        while let Some(event) = conn.poll_event() {
            println!("{:>8.1} ms  {:?}", started.elapsed().as_secs_f64() * 1000.0, event);
            match event {
                Event::Confirmed => {
                    confirmed_at = Some(Instant::now());
                    last_progress = Instant::now();
                }
                Event::Closed(reason) => {
                    println!("closed: {reason:?}");
                    summary(&conn, started);
                    let ok = matches!(reason, CloseReason::Application { .. } | CloseReason::IdleTimeout) || closed_by_us;
                    std::process::exit(if ok && confirmed_at.is_some() { 0 } else { 1 });
                }
                Event::Established => {}
            }
        }
        // the streams
        while let Some(event) = conn.poll_stream_event() {
            if let StreamEvent::Readable(id) = event {
                loop {
                    match conn.stream_read(id, &mut read_buf) {
                        Ok((n, fin)) => {
                            if Some(id) == request_stream {
                                if n > 0 {
                                    last_progress = Instant::now();
                                }
                                response.extend_from_slice(&read_buf[..n]);
                                response_end |= fin;
                            }
                            if fin || n == 0 {
                                break;
                            }
                        }
                        Err(StreamError::Blocked) => break,
                        Err(e) => {
                            println!("stream {id}: {e}");
                            break;
                        }
                    }
                }
            }
        }
        // (the quiet time after the handshake: kept alive, nothing else)
        let quiet = match (confirmed_at, quiet_for) {
            (Some(t), Some(q)) => {
                let quiet = t.elapsed() < q;
                conn.set_keep_alive(quiet);
                if quiet {
                    last_progress = Instant::now();
                } else if !quiet_over {
                    quiet_over = true;
                    let k = conn.stats().keep_alives;
                    println!("{:>8.1} ms  kept alive through {:.1} s of quiet ({k} keep-alive PINGs)", started.elapsed().as_secs_f64() * 1000.0, q.as_secs_f64());
                }
                quiet
            }
            _ => false,
        };
        if confirmed_at.is_some() && !closed_by_us && !h3_opened {
            // the control stream (type 0, and an empty SETTINGS frame), and the streams of QPACK (types 2 and 3), which a client
            // opens at the start of every HTTP/3 connection (RFC 9114 section 6.2.1)
            for first in [&[0x00u8, 0x04, 0x00][..], &[0x02][..], &[0x03][..]] {
                let id = conn.open_stream(false).expect("a unidirectional stream");
                assert_eq!(conn.stream_write(id, first, false), Ok(first.len()));
            }
            h3_opened = true;
            continue;
        }
        if confirmed_at.is_some() && !closed_by_us && !quiet {
            if let Some(path) = &get {
                if let Some(id) = request_stream {
                    if uploaded < upload.len() {
                        match conn.stream_write(id, &upload[uploaded..], true) {
                            Ok(n) => {
                                uploaded += n;
                                if n > 0 {
                                    last_progress = Instant::now();
                                    continue;
                                }
                            }
                            Err(StreamError::Blocked) => {}
                            Err(e) => {
                                println!("writing the request: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
                if request_stream.is_none() {
                    let id = conn.open_stream(true).expect("a stream");
                    request_stream = Some(id);
                    request_started = Some(Instant::now());
                    if let Some(n) = post {
                        // HEADERS, and one DATA frame with all of the body, which is written as the stream takes it
                        upload = request(20, path, &args[1]);
                        put_varint(&mut upload, 0x00);
                        put_varint(&mut upload, n as u64);
                        upload.extend((0..n).map(|i| (i % 251) as u8));
                    } else {
                        upload = request(17, path, &args[1]);
                    }
                    continue; // (send it now)
                } else if response_end {
                    report(&response, path, request_started.unwrap(), post);
                    conn.close(Instant::now(), 0, b"done");
                    closed_by_us = true;
                    continue;
                }
            } else {
                // some pings, each one acknowledged before the next, then the end
                let idle = match ping_marker {
                    Some(sent_before) => conn.stats().packets_sent > sent_before && conn.bytes_in_flight() == 0,
                    None => conn.bytes_in_flight() == 0,
                };
                if idle {
                    if pings_sent < pings {
                        last_progress = Instant::now();
                        ping_marker = Some(conn.stats().packets_sent);
                        conn.ping();
                        pings_sent += 1;
                        continue;
                    }
                    conn.close(Instant::now(), 0, b"done");
                    closed_by_us = true;
                    continue;
                }
            }
        }
        let wait = match conn.timeout() {
            Some(t) => t.saturating_duration_since(Instant::now()),
            None => Duration::from_secs(1),
        };
        if last_progress.elapsed() > Duration::from_secs(60) {
            println!("gave up: nothing happened for 60 s ({} PINGs answered, {} bytes of the response so far)", pings_sent.saturating_sub(1), response.len());
            summary(&conn, started);
            std::process::exit(1);
        }
        let wait = wait.max(Duration::from_micros(100)).min(Duration::from_millis(100));
        socket.set_read_timeout(Some(wait)).unwrap();
        match socket.recv(&mut buf) {
            Ok(n) => {
                conn.recv(Instant::now(), &mut buf[..n]);
                // more that is there already, without waiting
                socket.set_nonblocking(true).unwrap();
                while let Ok(n) = socket.recv(&mut buf) {
                    conn.recv(Instant::now(), &mut buf[..n]);
                }
                socket.set_nonblocking(false).unwrap();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("receive failed: {e}");
            }
        }
        if conn.timeout().is_some_and(|t| t <= Instant::now()) {
            conn.on_timeout(Instant::now());
        }
    }
}

/// Takes the HTTP/3 frames of the response apart, and checks the body of a `/bytes/N` response against the pattern of the server.
fn report(response: &[u8], path: &str, started: Instant, post: Option<usize>) {
    let mut at = 0;
    let (mut headers, mut body) = (0usize, Vec::new());
    let mut other = Vec::new();
    while at < response.len() {
        let (Some(ty), Some(len)) = (get_varint(response, &mut at), get_varint(response, &mut at)) else {
            println!("the response ends in the middle of a frame header");
            break;
        };
        let Some(payload) = response.get(at..at + len as usize) else {
            println!("the response ends in the middle of a frame (type {ty}, {len} bytes)");
            break;
        };
        at += len as usize;
        match ty {
            0x00 => body.extend_from_slice(payload),
            0x01 => headers += payload.len(),
            t => other.push(t),
        }
    }
    let took = started.elapsed();
    println!("response: {} bytes on the stream, headers {} bytes, body {} bytes, other frames {:?}", response.len(), headers, body.len(), other);
    if let Some(n) = path.strip_prefix("/bytes/").and_then(|n| n.parse::<usize>().ok()) {
        let right = body.len() == n && body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8);
        println!("body {} bytes, {}", n, if right { "correct" } else { "WRONG" });
        println!("{:.1} ms, {:.1} MB/s", took.as_secs_f64() * 1000.0, n as f64 / took.as_secs_f64() / 1e6);
        if !right {
            std::process::exit(1);
        }
    } else if let Some(n) = post {
        let right = body.len() == n && body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8);
        println!("echo of {} bytes: {}", n, if right { "correct" } else { "WRONG" });
        println!("{:.1} ms, {:.1} MB/s each way", took.as_secs_f64() * 1000.0, n as f64 / took.as_secs_f64() / 1e6);
        if !right {
            std::process::exit(1);
        }
    } else {
        println!("body: {:?}", String::from_utf8_lossy(&body[..body.len().min(200)]));
    }
}

fn summary(conn: &Connection, started: Instant) {
    println!("alpn: {:?}", conn.alpn().map(|p| String::from_utf8_lossy(p).into_owned()));
    println!("certificates: {}", conn.peer_certificates().len());
    println!("smoothed rtt: {:?}, in flight: {}, window: {}", conn.smoothed_rtt(), conn.bytes_in_flight(), conn.congestion().window());
    println!("stats: {:?}", conn.stats());
    println!("took {:.1} ms", started.elapsed().as_secs_f64() * 1000.0);
}
