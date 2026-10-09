//! The HTTP/2 client against a server that is not ours: Go's net/http (`tools/h2_oracle_server.go`, which makes its own
//! certificates and speaks HTTP/2 over TLS 1.3 with ALPN `h2`).
//!
//! The server is built once with `go build` and started once per test (on a port of its choosing). The tests are skipped,
//! with a message, when `go` is not installed. What each test asserts is what an HTTP/2 client has to get right whatever
//! server it talks to: the bodies come back whole and in order, many requests share one connection, flow control moves
//! megabytes in both directions, header blocks that need CONTINUATION frames, interim responses, resets and GOAWAYs, and
//! a server that does not offer h2 at all.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use pratique::http::HttpVersion;
use pratique::tls::{ClientConfig, TlsVersion};
use pratique::Client;

/// The oracle server's executable, built on first use; `None` if there is no Go toolchain.
fn oracle_binary() -> Option<&'static Path> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let go_ok = Command::new("go").arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
            if !go_ok {
                return None;
            }
            let dir = std::env::temp_dir().join(format!("pratique_h2_oracle_{}", std::process::id()));
            std::fs::create_dir_all(&dir).ok()?;
            let exe = dir.join("h2_oracle_server");
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/h2_oracle_server.go");
            let out = Command::new("go").arg("build").arg("-o").arg(&exe).arg(&source).current_dir(&dir).output().ok()?;
            if !out.status.success() {
                eprintln!("go build failed: {}", String::from_utf8_lossy(&out.stderr));
                return None;
            }
            Some(exe)
        })
        .as_deref()
}

/// A running oracle server.
struct Oracle {
    child: Child,
    port: u16,
    ca: PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.ca);
    }
}

/// Starts the oracle with these extra arguments, or returns `None` (and says so) when there is no Go.
fn start(name: &str, args: &[&str]) -> Option<Oracle> {
    let Some(exe) = oracle_binary() else {
        eprintln!("skipped {name}: no `go` toolchain to build the oracle server with");
        return None;
    };
    let ca = std::env::temp_dir().join(format!("pratique_h2_oracle_{}_{}.pem", std::process::id(), name));
    let mut child = Command::new(exe).arg("-ca").arg(&ca).args(args).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("the oracle server starts");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).expect("the oracle says where it listens");
    let port: u16 = line.trim().strip_prefix("listening 127.0.0.1:").unwrap_or_else(|| panic!("unexpected first line {line:?}")).parse().unwrap();
    Some(Oracle { child, port, ca })
}

impl Oracle {
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.port, path)
    }

    fn client(&self) -> Client {
        let trust = pratique::sys::trust_store_from_pem_file(self.ca.to_str().unwrap()).expect("the oracle's root");
        Client::with_tls_config(ClientConfig::new(trust)).http2(true).timeout(Duration::from_secs(30)).max_body_bytes(100 << 20)
    }

    /// `(protocol, requests)` for each connection the server has accepted so far, in order. (The request that asks is
    /// counted on its own connection.)
    fn stats(&self, client: &Client) -> Vec<(String, usize)> {
        let resp = client.get(&self.url("/stats")).expect("stats");
        let text = String::from_utf8(resp.body).unwrap();
        let mut lines = text.lines();
        let count: usize = lines.next().unwrap().strip_prefix("connections ").unwrap().parse().unwrap();
        let conns: Vec<(String, usize)> = lines
            .map(|l| {
                let mut f = l.split(' ');
                assert_eq!(f.next(), Some("connection"));
                f.next();
                let proto = f.next().unwrap().to_string();
                let requests = f.next().unwrap().parse().unwrap();
                (proto, requests)
            })
            .collect();
        assert_eq!(conns.len(), count);
        conns
    }
}

/// The oracle's pattern: byte `i` is `a + i % 26`.
fn pattern_ok(body: &[u8]) -> bool {
    body.iter().enumerate().all(|(i, b)| *b == b'a' + (i % 26) as u8)
}

/// Some bytes that no pattern of the transport's could mimic by accident.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn bodies_of_every_size_come_back_whole() {
    let Some(oracle) = start("sizes", &[]) else { return };
    let client = oracle.client();
    // around the frame size (16384) and the default window (65535), then more than a stream window (8 MiB)
    for n in [0usize, 1, 16_383, 16_384, 16_385, 65_535, 65_536, 65_537, 1_000_000, 20_000_000] {
        let resp = client.get(&oracle.url(&format!("/size/{n}"))).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(resp.version, HttpVersion::Http2);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.len(), n, "{n} bytes");
        assert!(pattern_ok(&resp.body), "{n}: the bytes are not the pattern");
        assert_eq!(resp.header("content-length"), Some(n.to_string().as_str()));
    }
    // one connection did all of it
    let conns = oracle.stats(&client);
    assert_eq!(conns.len(), 1, "{conns:?}");
    assert_eq!(conns[0].0, "HTTP/2.0");
    assert_eq!(conns[0].1, 11);
}

#[test]
fn a_body_with_no_length_comes_in_many_frames() {
    let Some(oracle) = start("chunks", &[]) else { return };
    let client = oracle.client();
    let resp = client.get(&oracle.url("/chunk/1000000")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http2);
    assert_eq!(resp.header("content-length"), None);
    assert_eq!(resp.body.len(), 1_000_000);
    assert!(pattern_ok(&resp.body));
}

#[test]
fn what_is_posted_is_echoed_through_both_flow_control_windows() {
    let Some(oracle) = start("echo", &[]) else { return };
    let client = oracle.client();
    // Go's server allows 1 MiB of request body per stream before it reads, so the larger bodies wait for credit
    for (n, seed) in [(0usize, 1u64), (1, 2), (100_000, 3), (1_500_000, 4), (5_000_000, 5)] {
        let sent = noise(n, seed);
        let resp = client.post(&oracle.url("/echo"), sent.clone()).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(resp.version, HttpVersion::Http2);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.len(), n, "{n} bytes echoed");
        assert!(resp.body == sent, "{n}: the echo differs");
    }
}

#[test]
fn many_requests_at_once_share_one_connection() {
    let Some(oracle) = start("shared", &[]) else { return };
    let client = oracle.client();
    let started = Instant::now();
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..32)
            .map(|i| {
                let (client, oracle) = (&client, &oracle);
                scope.spawn(move || {
                    // some of them wait on the server, so that they overlap
                    let path = if i % 2 == 0 { format!("/size/{}", 100_000 + i) } else { format!("/delay/{}", 100 + i) };
                    client.get(&oracle.url(&path)).map(|r| (i, r))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in results {
        let (i, resp) = r.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, HttpVersion::Http2);
        if i % 2 == 0 {
            assert_eq!(resp.body.len(), 100_000 + i);
            assert!(pattern_ok(&resp.body));
        } else {
            assert_eq!(resp.body, format!("after {} ms", 100 + i).into_bytes());
        }
    }
    // the delays of 100-131 ms ran side by side, not one after the other (that would be more than two seconds)
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    let conns = oracle.stats(&client);
    assert_eq!(conns.len(), 1, "32 requests should have shared one connection: {conns:?}");
    assert_eq!(conns[0].1, 33);
}

#[test]
fn header_blocks_that_need_continuation_frames() {
    let Some(oracle) = start("headers", &[]) else { return };
    let client = oracle.client();
    // 300 fields of 100 bytes: about 40 KB, so three frames; one field of 20000 bytes does not fit in one frame either
    let resp = client.get(&oracle.url("/headers/300")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http2);
    assert_eq!(resp.body, b"many headers\n");
    for i in [0usize, 1, 150, 299] {
        assert_eq!(resp.header(&format!("x-header-{i}")), Some(format!("{i:0100}").as_str()), "field {i}");
    }
    let resp = client.get(&oracle.url("/big-header")).unwrap();
    assert_eq!(resp.header("x-big").map(str::len), Some(20_000));
    assert_eq!(resp.body, b"one big header\n");
    // a header list past what the client takes (64 KiB) is an error, not a crash, and the connection stays usable
    let err = client.get(&oracle.url("/headers/1000"));
    assert!(err.is_err(), "a header list of 140 KB was accepted");
    assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    let conns = oracle.stats(&client);
    assert!(conns.iter().all(|c| c.0 == "HTTP/2.0"), "{conns:?}");
}

#[test]
fn requests_look_right_to_the_server() {
    let Some(oracle) = start("mirror", &[]) else { return };
    let client = oracle.client();
    let resp = client.request("GET", &oracle.url("/mirror?a=b&c=d")).header("X-Mixed-Case", "Some Value").header("Accept-Language", "en").send().unwrap();
    assert_eq!(resp.version, HttpVersion::Http2);
    let text = String::from_utf8(resp.body).unwrap();
    // Go's server refuses a request whose header block is malformed (an upper case name, a connection-specific field,
    // a pseudo-header out of place), so getting an answer at all says most of this; the rest is read back
    assert!(text.contains("proto HTTP/2.0\n"), "{text}");
    assert!(text.contains("method GET\n"), "{text}");
    assert!(text.contains(&format!("host 127.0.0.1:{}\n", oracle.port)), "{text}");
    assert!(text.contains("uri /mirror?a=b&c=d\n"), "{text}");
    assert!(text.contains("X-Mixed-Case: Some Value\n"), "{text}");
    assert!(text.contains("Accept-Language: en\n"), "{text}");
    for forbidden in ["Connection:", "Keep-Alive:", "Transfer-Encoding:", "Upgrade:", "Te:"] {
        assert!(!text.contains(forbidden), "{forbidden} was sent: {text}");
    }
}

#[test]
fn head_and_status_codes() {
    let Some(oracle) = start("status", &[]) else { return };
    let client = oracle.client();
    let head = client.head(&oracle.url("/size/1000")).unwrap();
    assert_eq!(head.version, HttpVersion::Http2);
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length"), Some("1000"));
    assert!(head.body.is_empty());
    for code in [204u16, 304, 404, 500, 503] {
        let resp = client.get(&oracle.url(&format!("/status/{code}"))).unwrap();
        assert_eq!(resp.status, code);
        assert!(resp.body.is_empty(), "{code}");
    }
}

#[test]
fn trailers_and_interim_responses_are_not_taken_for_the_answer() {
    let Some(oracle) = start("interim", &[]) else { return };
    let client = oracle.client();
    let resp = client.get(&oracle.url("/trailers")).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"a body with trailers\n");
    assert_eq!(resp.header("x-sum"), None, "trailers are not header fields");
    let resp = client.get(&oracle.url("/early")).unwrap();
    assert_eq!(resp.status, 200, "the 103 is not the answer");
    assert_eq!(resp.body, b"after the early hints\n");
    assert_eq!(resp.header("link"), None, "a field of the 103 is not a field of the answer");
}

#[test]
fn a_reset_fails_that_request_and_no_other() {
    let Some(oracle) = start("reset", &[]) else { return };
    let client = oracle.client();
    let started = Instant::now();
    std::thread::scope(|scope| {
        let neighbour = scope.spawn(|| client.get(&oracle.url("/size/500000")));
        // some body, then RST_STREAM
        let err = client.get(&oracle.url("/reset"));
        assert!(err.is_err(), "a response that was cut by RST_STREAM looked complete");
        assert_eq!(neighbour.join().unwrap().unwrap().body.len(), 500_000);
    });
    assert!(started.elapsed() < Duration::from_secs(10));
    // the connection went on
    assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    assert_eq!(oracle.stats(&client).len(), 1);
}

#[test]
fn a_goaway_after_an_answer_moves_the_next_request_to_a_new_connection() {
    let Some(oracle) = start("goaway", &[]) else { return };
    let client = oracle.client();
    let resp = client.get(&oracle.url("/goaway")).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"going away\n");
    for _ in 0..3 {
        assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    }
    let conns = oracle.stats(&client);
    assert!(conns.len() >= 2, "the connection that was told to go away was used again: {conns:?}");
    assert_eq!(conns[0].1, 1, "{conns:?}");
}

#[test]
fn a_server_that_allows_three_streams_gets_more_connections() {
    let Some(oracle) = start("streams", &["-streams", "3"]) else { return };
    let client = oracle.client();
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12).map(|_| scope.spawn(|| client.get(&oracle.url("/delay/400")))).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &results {
        let resp = r.as_ref().unwrap();
        assert_eq!((resp.status, resp.version), (200, HttpVersion::Http2));
    }
    let conns = oracle.stats(&client);
    // twelve requests that overlap, three at a time on a connection: at least four connections, and no stream was
    // refused for want of room (a refusal is retried, but the server counts the connections it saw)
    assert!(conns.len() >= 4, "{conns:?}");
    assert!(conns.len() <= 12, "{conns:?}");
}

#[test]
fn a_connection_the_server_closed_for_being_idle_is_replaced() {
    let Some(oracle) = start("idle", &["-idle", "1s"]) else { return };
    let client = oracle.client();
    assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    std::thread::sleep(Duration::from_millis(2500));
    // the server has closed the first connection by now; the client has to notice, or retry
    for _ in 0..3 {
        assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    }
    let conns = oracle.stats(&client);
    assert_eq!(conns.len(), 2, "{conns:?}");
}

#[test]
fn a_body_that_is_dropped_half_read_cancels_its_stream_only() {
    let Some(oracle) = start("cancel", &[]) else { return };
    let client = oracle.client();
    let mut stream = client.get_stream(&oracle.url("/size/30000000")).unwrap();
    let mut first = vec![0u8; 100_000];
    stream.read_exact(&mut first).unwrap();
    assert!(pattern_ok(&first));
    drop(stream);
    // 30 MB were on their way: the connection must be as good as new, and not busy for long
    let started = Instant::now();
    assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert_eq!(oracle.stats(&client).len(), 1);
}

#[test]
fn a_slow_body_is_read_as_it_comes_and_the_time_limit_cuts_off_a_silent_one() {
    let Some(oracle) = start("slow", &[]) else { return };
    let client = oracle.client();
    // 40 bytes, one every 10 ms
    let resp = client.get(&oracle.url("/slow/40")).unwrap();
    assert_eq!(resp.body.len(), 40);
    assert!(pattern_ok(&resp.body));
    // an answer after 3 s against a limit of 500 ms
    let impatient = oracle.client().timeout(Duration::from_millis(500));
    let started = Instant::now();
    assert!(impatient.get(&oracle.url("/delay/3000")).is_err());
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    // and the connection is fine for the next request
    assert_eq!(client.get(&oracle.url("/hello")).unwrap().body, b"hello /hello");
}

#[test]
fn a_server_without_h2_is_spoken_to_in_http_1_1() {
    let Some(oracle) = start("h1", &["-h1"]) else { return };
    let client = oracle.client();
    for _ in 0..3 {
        let resp = client.get(&oracle.url("/size/100000")).unwrap();
        assert_eq!(resp.version, HttpVersion::Http11);
        assert_eq!(resp.body.len(), 100_000);
        assert!(pattern_ok(&resp.body));
    }
    let resp = client.post(&oracle.url("/echo"), b"hello".to_vec()).unwrap();
    assert_eq!((resp.version, resp.body.as_slice()), (HttpVersion::Http11, b"hello".as_slice()));
    let conns = oracle.stats(&client);
    assert!(conns.iter().all(|c| c.0 == "HTTP/1.1"), "{conns:?}");
}

// ------------------------------------------------------------------------------------------------ TLS 1.2

#[test]
fn http2_and_http1_over_tls12_with_a_go_server_and_tls13_where_it_is_asked_for() {
    for (args, proto) in [(&["-tls12"][..], pratique::http::HttpVersion::Http2), (&["-tls12", "-h1"][..], pratique::http::HttpVersion::Http11)] {
        let Some(oracle) = start(&format!("tls12_{}", args.len()), args) else { return };
        let client = oracle.client();
        for _ in 0..3 {
            let r = client.get(&oracle.url("/size/10000")).unwrap();
            assert!(pattern_ok(&r.body) && r.body.len() == 10_000);
            assert_eq!((r.version, r.tls_version), (proto, Some(TlsVersion::Tls12)), "{args:?}");
        }
        // the requests shared one connection (the stats request asks on it too)
        let stats = oracle.stats(&client);
        assert_eq!(stats.len(), 1, "{args:?}: {stats:?}");
        // a request that requires TLS 1.3 does not take the TLS 1.2 connection, and the server cannot give it what it wants
        let e = client.request("GET", &oracle.url("/size/10")).min_tls_version(TlsVersion::Tls13).send().unwrap_err();
        assert!(e.to_string().contains("alert"), "{args:?}: {e}");
        // nor does a client that requires it
        let strict = oracle.client().min_tls_version(TlsVersion::Tls13);
        assert!(strict.get(&oracle.url("/size/10")).is_err());
        // and a request on that client cannot loosen it
        assert!(strict.request("GET", &oracle.url("/size/10")).min_tls_version(TlsVersion::Tls12).send().is_err());
        // and the client's own requests go on on the connection they had
        assert_eq!(client.get(&oracle.url("/size/10")).unwrap().tls_version, Some(TlsVersion::Tls12));
        // (the refused handshakes were connections too, with no request on them)
        let stats = oracle.stats(&client);
        assert_eq!(stats.len(), 4, "{args:?}: {stats:?}");
        assert_eq!(stats.iter().filter(|(_, requests)| *requests > 0).count(), 1, "{args:?}: {stats:?}");
    }
}

#[test]
fn a_go_server_that_can_do_tls13_does() {
    let Some(oracle) = start("tls13_default", &[]) else { return };
    let r = oracle.client().get(&oracle.url("/size/10")).unwrap();
    assert_eq!(r.tls_version, Some(TlsVersion::Tls13));
}

