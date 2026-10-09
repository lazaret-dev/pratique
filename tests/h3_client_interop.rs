//! The client's HTTP/3 against a server that is not ours: aioquic (`tools/quic_interop_server.py`), which also serves the same
//! routes over HTTPS on a TCP port, so that the client can be told about the HTTP/3 side the way a browser is, in an `Alt-Svc` field.
//!
//! The server is a Python process; certificates are made with the `openssl` command line tool at run time. The tests are skipped,
//! with a message, when `python3` with aioquic (`AIOQUIC_PATH=/dir` if it is installed with `pip install --target /dir
//! aioquic==1.3.0`) or `openssl` is not there. What they assert is what a client that speaks HTTP/3 has to get right whatever the
//! server: bodies whole and in order over one shared connection, requests in parallel, redirects, the end of a response that is not
//! a body, a stream reset that costs only its request, `Alt-Svc` heeded (and taken back), and, above all, that a network that does
//! not carry QUIC costs one try and not one per request.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use pratique::http::HttpVersion;
use pratique::tls::ClientConfig;
use pratique::Client;

/// The Python to run the server with and where its aioquic is (`None`: it is installed for that Python), or `None` if there is none.
fn python() -> Option<(String, Option<String>)> {
    let path = std::env::var("AIOQUIC_PATH").ok();
    let mut probe = Command::new("python3");
    probe.arg("-I").arg("-c").arg("import sys; sys.path.insert(0, sys.argv[1]) if len(sys.argv) > 1 else None; import aioquic");
    if let Some(p) = &path {
        probe.arg(p);
    }
    let ok = probe.stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    ok.then(|| ("python3".to_string(), path))
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn openssl(args: &[&str], dir: &Path) {
    let out = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl runs");
    assert!(out.status.success(), "openssl {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
}

/// A throwaway CA and a server certificate for 127.0.0.1 (and `localhost`).
struct Certs {
    dir: PathBuf,
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

impl Certs {
    fn new() -> Certs {
        let dir = std::env::temp_dir().join(format!("pratique_h3_{}_{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"];
        let mut args = vec!["req", "-x509"];
        args.extend(ec);
        args.extend(["-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3650", "-subj", "/CN=H3 Test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-sha256"]);
        openssl(&args, &dir);
        let mut args = vec!["req"];
        args.extend(ec);
        args.extend(["-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost"]);
        openssl(&args, &dir);
        fs::write(dir.join("ext.cnf"), "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem", "-days", "3650", "-sha256", "-extfile", "ext.cnf"], &dir);
        Certs { dir }
    }
}

impl Drop for Certs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A port that nothing uses, for UDP and TCP both.
fn free_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A running server.
struct Server {
    child: Child,
    certs: Certs,
    /// The UDP port of HTTP/3.
    udp: u16,
    /// The TCP port of HTTPS, if there is one.
    tcp: Option<u16>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What a test wants of its server.
#[derive(Default)]
struct Setup {
    /// Also serve HTTPS over TCP.
    tcp: bool,
    /// The `alt-svc` field of every response (`{udp}` is replaced by the HTTP/3 port).
    alt_svc: Option<String>,
}

impl Setup {
    /// An HTTPS origin over TCP that says, in every response, that HTTP/3 is at `alt_svc`.
    fn advertising(alt_svc: &str) -> Setup {
        Setup { tcp: true, alt_svc: Some(alt_svc.to_string()) }
    }
}

fn start(name: &str, setup: Setup) -> Option<Server> {
    let Some((python, aioquic)) = python() else {
        eprintln!("skipped {name}: no python3 with aioquic (set AIOQUIC_PATH)");
        return None;
    };
    if !have_openssl() {
        eprintln!("skipped {name}: no `openssl` to make certificates with");
        return None;
    }
    let certs = Certs::new();
    let udp = free_port();
    let tcp = setup.tcp.then(free_port);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/quic_interop_server.py");
    let mut cmd = Command::new(python);
    cmd.arg(&script).arg("--cert").arg(certs.dir.join("srv.pem")).arg("--key").arg(certs.dir.join("srv.key")).arg("--port").arg(udp.to_string());
    if let Some(t) = tcp {
        cmd.arg("--tcp-port").arg(t.to_string());
    }
    if let Some(a) = &setup.alt_svc {
        cmd.arg("--alt-svc").arg(a.replace("{udp}", &udp.to_string()));
    }
    if let Some(p) = aioquic {
        cmd.env("AIOQUIC_PATH", p);
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("the server starts");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).expect("the server says it is ready");
    assert_eq!(line.trim(), format!("listening {udp}"), "unexpected first line {line:?}");
    Some(Server { child, certs, udp, tcp })
}

impl Server {
    /// An origin by its UDP port (the one an eager client asks).
    fn h3_url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.udp, path)
    }

    /// An origin by its TCP port.
    fn tcp_url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.tcp.expect("a TCP side"), path)
    }

    fn base(&self) -> Client {
        let trust = pratique::sys::trust_store_from_pem_file(self.certs.dir.join("ca.pem")).expect("the test CA");
        Client::with_tls_config(ClientConfig::new(trust)).timeout(Duration::from_secs(20)).max_body_bytes(100 << 20)
    }

    /// A client that tries HTTP/3 without being told.
    fn eager(&self) -> Client {
        self.base().http3_eager(true)
    }

    /// A client that is told in `Alt-Svc`.
    fn told(&self) -> Client {
        self.base().http3(true)
    }

    /// `(connections, requests on each)` that the HTTP/3 side has accepted so far. (The request that asks is counted.)
    fn stats(&self, client: &Client) -> Vec<usize> {
        self.stats_at(client, &self.h3_url("/stats"))
    }

    /// The same, asked at this URL (for a client that is not eager, the origin is the TCP one).
    fn stats_at(&self, client: &Client, url: &str) -> Vec<usize> {
        let resp = client.get(url).expect("stats");
        assert_eq!(resp.version, HttpVersion::Http3);
        let text = String::from_utf8(resp.body).unwrap();
        let mut lines = text.lines();
        let count: usize = lines.next().unwrap().strip_prefix("connections ").unwrap().parse().unwrap();
        let conns: Vec<usize> = lines.map(|l| l.rsplit(' ').next().unwrap().parse().unwrap()).collect();
        assert_eq!(conns.len(), count);
        conns
    }
}

/// The server's pattern: byte `i` is `i % 251`.
fn pattern_ok(body: &[u8]) -> bool {
    body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8)
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
fn a_request_over_http3() {
    let Some(server) = start("get", Setup::default()) else { return };
    let client = server.eager();
    let resp = client.get(&server.h3_url("/")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http3);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.reason, "", "HTTP/3 has no reason phrase");
    assert_eq!(resp.body, b"hello");
    assert_eq!(resp.header("content-type"), Some("text/plain"));
    assert_eq!(resp.header("content-length"), Some("5"));
    assert_eq!(resp.url.to_string(), server.h3_url("/"));
    // what the server saw of the request
    let seen = String::from_utf8(client.get(&server.h3_url("/headers")).unwrap().body).unwrap();
    assert!(seen.contains(&format!(":authority: 127.0.0.1:{}\n", server.udp)), "{seen}");
    assert!(seen.contains(":scheme: https\n") && seen.contains(":method: GET\n") && seen.contains(":path: /headers\n"), "{seen}");
    assert!(seen.contains("user-agent: pratique/"), "{seen}");
    for forbidden in ["connection:", "keep-alive:", "transfer-encoding:", "upgrade:", "proxy-connection:"] {
        assert!(!seen.contains(forbidden), "{forbidden} is not allowed in HTTP/3: {seen}");
    }
    // one connection did both
    assert_eq!(server.stats(&client), vec![3]);
}

#[test]
fn bodies_of_every_size_come_back_whole() {
    let Some(server) = start("sizes", Setup::default()) else { return };
    let client = server.eager();
    // around the size of a packet's payload, a frame, a window, then a few megabytes (more than a stream's initial window)
    for n in [0usize, 1, 1_199, 1_200, 1_201, 16_383, 16_384, 65_535, 65_536, 1_000_000, 4_000_000] {
        let resp = client.get(&server.h3_url(&format!("/bytes/{n}"))).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(resp.version, HttpVersion::Http3);
        assert_eq!(resp.body.len(), n, "{n} bytes");
        assert!(pattern_ok(&resp.body), "{n}: the bytes are not the pattern");
    }
    assert_eq!(server.stats(&client), vec![12]);
}

#[test]
fn a_body_is_sent_and_comes_back() {
    let Some(server) = start("echo", Setup::default()) else { return };
    let client = server.eager();
    for n in [0usize, 1, 1_000, 65_536, 1_000_000] {
        let sent = noise(n, n as u64 + 7);
        let resp = client.post(&server.h3_url("/echo"), sent.clone()).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(resp.version, HttpVersion::Http3);
        assert_eq!(resp.status, 200);
        assert!(resp.body == sent, "{n} bytes did not come back as they were sent");
    }
}

#[test]
fn requests_in_parallel_share_one_connection() {
    let Some(server) = start("parallel", Setup::default()) else { return };
    let client = server.eager();
    // the first request settles the connection; the rest come together
    assert_eq!(client.get(&server.h3_url("/")).unwrap().version, HttpVersion::Http3);
    let threads: Vec<_> = (0..16)
        .map(|t| {
            let client = client.clone();
            let url = server.h3_url("/bytes/300000");
            let echo = server.h3_url("/echo");
            std::thread::spawn(move || {
                for i in 0..3 {
                    let resp = client.get(&url).unwrap_or_else(|e| panic!("{t}/{i}: {e}"));
                    assert_eq!(resp.version, HttpVersion::Http3);
                    assert_eq!(resp.body.len(), 300_000);
                    assert!(pattern_ok(&resp.body));
                    let sent = noise(50_000, (t * 3 + i) as u64);
                    assert!(client.post(&echo, sent.clone()).unwrap().body == sent);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(server.stats(&client), vec![1 + 16 * 6 + 1], "one connection, and every request on it");
}

#[test]
fn the_requests_that_come_while_the_first_connects_wait_for_it_when_eager() {
    let Some(server) = start("first", Setup::default()) else { return };
    let client = server.eager();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (client, url) = (client.clone(), server.h3_url("/bytes/1000"));
            std::thread::spawn(move || {
                let resp = client.get(&url).unwrap();
                assert_eq!(resp.version, HttpVersion::Http3);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(server.stats(&client), vec![9]);
}

#[test]
fn a_streamed_body_is_read_in_pieces_and_a_dropped_one_costs_nothing() {
    let Some(server) = start("stream", Setup::default()) else { return };
    let client = server.eager();
    let mut resp = client.get_stream(&server.h3_url("/slow/60000")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http3);
    assert_eq!(resp.content_length, Some(60_000));
    let mut got = Vec::new();
    let mut piece = [0u8; 4096];
    loop {
        let n = resp.read(&mut piece).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&piece[..n]);
    }
    assert_eq!(got.len(), 60_000);
    assert!(pattern_ok(&got));
    // a response that is given up on half way: the server is told to stop, and the connection goes on
    let mut resp = client.get_stream(&server.h3_url("/slow/2000000")).unwrap();
    assert_eq!(resp.read(&mut piece).unwrap().min(1), 1);
    drop(resp);
    let again = client.get(&server.h3_url("/bytes/100000")).unwrap();
    assert_eq!(again.body.len(), 100_000);
    assert_eq!(server.stats(&client).len(), 1, "the connection was kept");
}

#[test]
fn redirects_are_followed_over_http3() {
    let Some(server) = start("redirect", Setup::default()) else { return };
    let client = server.eager();
    let resp = client.get(&server.h3_url("/redirect?to=/bytes/10")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http3);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), 10);
    assert_eq!(resp.url.to_string(), server.h3_url("/bytes/10"));
    // not followed if the caller does not want that
    let stopped = server.eager().max_redirects(0).get(&server.h3_url("/redirect?to=/")).unwrap_err().to_string();
    assert!(stopped.contains("redirect"), "{stopped}");
}

#[test]
fn statuses_heads_and_trailers() {
    let Some(server) = start("statuses", Setup::default()) else { return };
    let client = server.eager();
    let resp = client.get(&server.h3_url("/status/503")).unwrap();
    assert_eq!((resp.status, resp.body.as_slice()), (503, b"status 503".as_slice()));
    let resp = client.get(&server.h3_url("/status/204")).unwrap();
    assert_eq!(resp.status, 204);
    let head = client.head(&server.h3_url("/bytes/1000")).unwrap();
    assert_eq!(head.version, HttpVersion::Http3);
    assert_eq!(head.header("content-length"), Some("1000"));
    assert!(head.body.is_empty());
    // a response with trailers: the body is whole, the trailers are not mixed into it
    let resp = client.get(&server.h3_url("/trailers")).unwrap();
    assert_eq!(resp.body, b"body");
    assert!(resp.header("x-trailer").is_none());
    assert_eq!(server.stats(&client).len(), 1);
}

#[test]
fn a_stream_the_server_resets_fails_that_request_only() {
    let Some(server) = start("reset", Setup::default()) else { return };
    let client = server.eager();
    assert_eq!(client.get(&server.h3_url("/")).unwrap().body, b"hello");
    let started = Instant::now();
    let err = client.get(&server.h3_url("/reset")).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "the reset was not noticed: {err}");
    // (a streamed one fails when it is read to the place where the stream was cut)
    let mut resp = client.get_stream(&server.h3_url("/reset")).unwrap();
    let mut sink = Vec::new();
    assert!(resp.read_to_end(&mut sink).is_err());
    assert_eq!(client.get(&server.h3_url("/bytes/100")).unwrap().body.len(), 100);
    assert_eq!(server.stats(&client).len(), 1, "the connection was not lost");
}

#[test]
fn a_request_that_takes_too_long_gives_up_and_the_client_goes_on() {
    let Some(server) = start("total", Setup::default()) else { return };
    let client = server.eager().total_timeout(Duration::from_secs(1));
    assert_eq!(client.get(&server.h3_url("/")).unwrap().body, b"hello");
    let started = Instant::now();
    let err = client.get(&server.h3_url("/slow/3000000")).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(4), "{err}");
    assert!(matches!(err, pratique::error::Error::Io(_)), "{err}");
    assert_eq!(client.get(&server.h3_url("/bytes/10")).unwrap().body.len(), 10);
}

#[test]
fn idle_connections_are_counted_and_closed_on_request() {
    let Some(server) = start("idle", Setup::default()) else { return };
    let client = server.eager();
    assert_eq!(client.idle_connections(), 0);
    client.get(&server.h3_url("/")).unwrap();
    assert_eq!(client.idle_connections(), 1);
    client.close_idle_connections();
    assert_eq!(client.idle_connections(), 0);
    // the next request makes a new connection
    assert_eq!(client.get(&server.h3_url("/")).unwrap().version, HttpVersion::Http3);
    assert_eq!(server.stats(&client).len(), 2);
}

#[test]
fn alt_svc_makes_the_next_request_go_over_http3() {
    let Some(server) = start("alt_svc", Setup::advertising(r#"h3=":{udp}"; ma=3600"#)) else { return };
    let client = server.told().http2(true);
    // the first request has nothing to go on: TCP (this server speaks no HTTP/2, so HTTP/1.1)
    let first = client.get(&server.tcp_url("/")).unwrap();
    assert_eq!(first.version, HttpVersion::Http11);
    assert_eq!(first.body, b"hello");
    assert_eq!(first.header("alt-svc"), Some(format!(r#"h3=":{}"; ma=3600"#, server.udp).as_str()));
    // the next ones are over QUIC, the origin being the TCP one (and the server authenticated as that origin's name)
    for _ in 0..3 {
        let resp = client.get(&server.tcp_url("/bytes/50000")).unwrap();
        assert_eq!(resp.version, HttpVersion::Http3);
        assert_eq!(resp.body.len(), 50_000);
    }
    assert_eq!(server.stats_at(&client, &server.tcp_url("/stats")), vec![4]);
    // a client that was not asked to speak HTTP/3 does not, whatever the server says
    let plain = server.base();
    for _ in 0..2 {
        assert_eq!(plain.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    }
    assert_eq!(server.stats(&server.eager()), vec![4, 1], "nothing else came over QUIC but the stats request that asked");
}

#[test]
fn alt_svc_clear_takes_it_back() {
    let Some(server) = start("clear", Setup::advertising(r#"h3=":{udp}"; ma=3600"#)) else { return };
    let client = server.told();
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http3);
    // the origin says to forget it (over the connection that has been made): what follows goes the TCP way
    let resp = client.get(&server.tcp_url("/clear")).unwrap();
    assert_eq!(resp.version, HttpVersion::Http3);
    assert_eq!(resp.header("alt-svc"), Some("clear"));
    for _ in 0..3 {
        assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    }
    // and nothing else came over QUIC (the connection that served two requests is not asked for a third; this is another)
    assert_eq!(server.stats(&server.eager()), vec![2, 1]);
    // (the origin has stopped saying that HTTP/3 is there: the response to this is the first that says so again, and what follows is believed)
    assert_eq!(client.get(&server.tcp_url("/advertise")).unwrap().version, HttpVersion::Http11);
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http3);
}

#[test]
fn an_alternative_nobody_listens_on_falls_back_to_tcp() {
    // the TCP side says that HTTP/3 is at a port where there is nothing (the operating system answers a datagram with an error)
    let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let Some(server) = start("dead", Setup::advertising(&format!(r#"h3=":{dead_port}"; ma=3600"#))) else { return };
    let client = server.told();
    let started = Instant::now();
    for i in 0..4 {
        let resp = client.get(&server.tcp_url("/bytes/1000")).unwrap_or_else(|e| panic!("{i}: {e}"));
        assert_eq!(resp.version, HttpVersion::Http11, "{i}");
        assert_eq!(resp.body.len(), 1000);
    }
    assert!(started.elapsed() < Duration::from_secs(5), "the refused attempt was waited for: {:?}", started.elapsed());
}

#[test]
fn a_network_that_drops_udp_costs_one_handshake_timeout() {
    // an alternative that takes datagrams and says nothing
    let hole = UdpSocket::bind("127.0.0.1:0").unwrap();
    hole.set_nonblocking(true).unwrap();
    let hole_port = hole.local_addr().unwrap().port();
    let Some(server) = start("hole", Setup::advertising(&format!(r#"h3=":{hole_port}"; ma=3600"#))) else { return };
    let client = server.told().connect_timeout(Duration::from_secs(1));
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    // the second request tries QUIC, waits for the handshake for as long as the connect timeout says, and goes the TCP way
    let started = Instant::now();
    let resp = client.get(&server.tcp_url("/")).unwrap();
    let took = started.elapsed();
    assert_eq!(resp.version, HttpVersion::Http11);
    assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(4), "{took:?}");
    let count = |hole: &UdpSocket| {
        let mut buf = [0u8; 2048];
        let mut n = 0;
        while hole.recv(&mut buf).is_ok() {
            n += 1;
        }
        n
    };
    let tried = count(&hole);
    assert!(tried >= 1, "no handshake was sent to the alternative");
    // the ones after that do not try again
    let started = Instant::now();
    for _ in 0..5 {
        assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    }
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(count(&hole), 0, "a datagram went to an alternative that had been given up on");
}

#[test]
fn an_eager_client_falls_back_when_nothing_speaks_quic_at_the_origin() {
    // an origin that is HTTPS on a TCP port, with nothing on that UDP port
    let Some(server) = start("eager_fallback", Setup { tcp: true, alt_svc: None }) else { return };
    let client = server.eager();
    let started = Instant::now();
    for _ in 0..3 {
        let resp = client.get(&server.tcp_url("/")).unwrap();
        assert_eq!(resp.version, HttpVersion::Http11);
        assert_eq!(resp.body, b"hello");
    }
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

#[test]
fn http3_is_not_used_without_keep_alive() {
    let Some(server) = start("not_used", Setup::advertising(r#"h3=":{udp}"; ma=3600"#)) else { return };
    let client = server.told().keep_alive(false);
    for _ in 0..3 {
        assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    }
    assert_eq!(server.stats(&server.eager()), vec![1], "the connections of the first client were never made");
}

#[test]
fn http3_is_not_used_through_a_proxy() {
    let Some(server) = start("proxy", Setup::default()) else { return };
    // a proxy that is not there: the request has to go through it (over TCP, which is what a proxy tunnels), so it fails, and is not
    // sent over QUIC around it
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://127.0.0.1:{}", dead.local_addr().unwrap().port());
    drop(dead);
    let client = server.eager().proxy(&proxy).unwrap();
    assert!(client.get(&server.h3_url("/")).is_err());
    assert_eq!(server.stats(&server.eager()), vec![1], "nothing came over QUIC but the stats request that asked");
}

#[test]
fn a_body_over_the_limit_fails_whole_or_streamed() {
    let Some(server) = start("limit", Setup::default()) else { return };
    let client = server.eager().max_body_bytes(50_000);
    assert_eq!(client.get(&server.h3_url("/bytes/50000")).unwrap().body.len(), 50_000);
    // declared too large: refused at once
    assert!(client.get(&server.h3_url("/bytes/50001")).unwrap_err().to_string().contains("size limit"));
    // not declared (the end of the stream says where the body ends): refused when it has got that far, whole or in pieces
    assert!(client.get(&server.h3_url("/nolength/200000")).unwrap_err().to_string().contains("size limit"));
    let mut resp = client.get_stream(&server.h3_url("/nolength/200000")).unwrap();
    let mut sink = Vec::new();
    let err = resp.read_to_end(&mut sink).unwrap_err();
    assert!(err.to_string().contains("size limit"), "{err}");
    assert!(sink.len() <= 50_000 + 64 * 1024, "{}", sink.len());
    // the one request's limit is not the client's
    assert_eq!(client.request("GET", &server.h3_url("/nolength/200000")).max_body_bytes(300_000).send().unwrap().body.len(), 200_000);
    assert_eq!(client.get(&server.h3_url("/bytes/10")).unwrap().body.len(), 10);
}

#[test]
fn a_new_connection_that_dies_under_a_request_sends_it_the_tcp_way_if_it_may_be_repeated() {
    let Some(server) = start("die", Setup::advertising(r#"h3=":{udp}"; ma=3600"#)) else { return };
    let client = server.told();
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    // the QUIC connection is made, the server closes it instead of answering: a request that may be repeated goes the TCP way
    let resp = client.get(&server.tcp_url("/die")).unwrap();
    assert_eq!((resp.version, resp.body.as_slice()), (HttpVersion::Http11, b"still here".as_slice()));
    // and the origin is left to TCP after that
    for _ in 0..3 {
        assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    }
    assert_eq!(server.stats(&server.eager()), vec![1, 1], "one connection that was tried, and the one that asks");
}

#[test]
fn a_request_that_may_not_be_repeated_is_not_when_its_connection_dies() {
    let Some(server) = start("die_post", Setup::advertising(r#"h3=":{udp}"; ma=3600"#)) else { return };
    let client = server.told();
    assert_eq!(client.get(&server.tcp_url("/")).unwrap().version, HttpVersion::Http11);
    // (it might have been acted on: a POST is not sent again)
    assert!(client.post(&server.tcp_url("/die"), b"x".to_vec()).is_err());
    assert_eq!(server.stats(&server.eager()), vec![1, 1], "the request was made once");
}

#[test]
fn a_response_that_is_being_read_outlives_the_client() {
    let Some(server) = start("outlive", Setup::default()) else { return };
    // the client is dropped with the request in flight (the last clone of it): the connection closes when the response has been read
    let mut resp = {
        let client = server.eager();
        client.get_stream(&server.h3_url("/slow/60000")).unwrap()
    };
    let mut got = Vec::new();
    resp.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), 60_000);
    assert!(pattern_ok(&got));
}
