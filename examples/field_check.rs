//! The checks of `tools/mac_field_check.sh` that need the library: BACKLOG B-06 (a smoke test against real public
//! servers), B-08 (real certificate chains, kept as fixtures) and B-65 (real OCSP responses and CRLs, kept as fixtures). The
//! script builds and runs this for you; by hand:
//!
//! ```text
//! cargo run --release --example field_check -- smoke  tools/field_hosts.txt [--cacert FILE|mozilla|native] [--tsv FILE] [--tls-only] [--no-resume] [--proxy] [--timeout SECONDS]
//! cargo run --release --example field_check -- verify field_results [--cacert FILE]
//! cargo run --release --example field_check -- revocation field_results [--max-crl-kib N]
//! ```
//!
//! `smoke` connects to every host of the list with the library's own TLS client (1.3, or 1.2 with a server that speaks only
//! that) and the system CA bundle (or, with `--cacert mozilla` and `--features mozilla-roots`, the roots built into the
//! crate; with `--cacert native`, the operating system's own store of roots), directly (the
//! environment's proxy variables are not read unless `--proxy` is given), and says for each whether it did what the list
//! expects of that host:
//!
//! * `ok`: the handshake must succeed, the chain must verify through the public `verify_chain` too, and a GET of `/` must
//!   answer (any status; a 404 or a 403 is an answer);
//! * `refuse`: the certificate is expired, self-signed, for another host or from a root nobody trusts, and must be refused
//!   as a certificate error;
//! * `info`: whatever happens is written down and is not a pass or a fail (a chain with the intermediate left out, a 100 KB
//!   certificate, a root a bundle may not have yet);
//! * `refuse-handshake`: the server offers only what the library will not speak (TLS 1.0 or 1.1, CBC, RSA key exchange,
//!   finite-field Diffie-Hellman, no encryption), and the handshake must fail as a TLS error;
//! * `revoked`: the certificate's CA has revoked it; checked with hard-fail revocation and the `http::HttpOcspSource` and
//!   `http::HttpCrlSource` the certificate names, it must be refused as `certificate_revoked`.
//!
//! After an `ok` host has answered the GET, the handshake is made once more with the same configuration (BACKLOG B-35): if the
//! server sent session tickets, the library offers one, and the column `resumption` says what came of it: `resumed`,
//! `declined` (a full handshake, checked in full), `no-ticket` (the server sent none, or spoke TLS 1.2), `other-name` (tickets
//! only for the host a redirect went to) or `failed` (the handshake that offered the ticket was refused: a `FAIL`, since the
//! same server took the full handshake). `--no-resume` leaves this out.
//!
//! `ok-tls12` and `refuse-tls12` are `ok` and `refuse` for servers that speak only TLS 1.2: they are judged the same way, and
//! the TLS version that was spoken is written down for every host. A host marked `no-ems` after its name speaks TLS 1.2 without
//! the extended master secret, which the library requires: the handshake must be refused for exactly that (a `PASS`), and
//! only `mac_field_check.sh capture` says anything about its certificate.
//!
//! A host that cannot be reached at all (no address, no route, a connect timeout) is `SKIP`, never a failure. Only a
//! `FAIL` makes the exit status 1.
//!
//! `verify` reads what `mac_field_check.sh capture` wrote (`manifest.tsv` and `chains/`, chains captured by OpenSSL, not by
//! this library) and checks each chain with the library at the moment it was captured, so that a certificate that has
//! expired since still counts. It compares the verdict with OpenSSL's, tries to break every chain that verified (another host
//! name, a second outside the validity, a flipped bit in the leaf) and must see all of those refused, and writes
//! `real_chains/` (`fixtures.tsv`, `chains/`, `anchors/`): the fixtures that `tests/real_chains.rs` replays on any machine.
//!
//! `revocation` reads `revocation/manifest.tsv` (what `mac_field_check.sh revocation` asked of each captured leaf's OCSP
//! responder, with LibreSSL, and downloaded from its CRL distribution point, with the time of each) and checks every response
//! and list with the library, under hard-fail, at the moment it was fetched: a good response must settle the certificate,
//! and so must a list that does not name it; then a second after the window, more than five minutes before it, three
//! flipped bits and the leaf as its own issuer must not. It says what each is (signed by the CA or by a delegated
//! responder, the hash of the certificate ID, the signature algorithm; a list's size, scope and how long it took), and
//! writes `real_revocation/` (`fixtures.tsv`, `certs/`, `ocsp/`, `crl/`, lists over `--max-crl-kib`, default 256, left
//! out): the candidates from which `tests/data/real_revocation/` keeps a selection for `tests/real_revocation.rs`.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use pratique::error::Error;
use pratique::http::{HttpCrlSource, HttpOcspSource};
use pratique::revocation::{self, ChainEvidence, Crl, Revocation};
use pratique::tls::{ClientConfig, Resumption, TlsStream};
use pratique::x509::{Certificate, PublicKey, TrustStore, VerifyOptions};
use pratique::{asn1, pem, sys, Client};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("smoke") if args.len() >= 2 => smoke(&args[1..]),
        Some("verify") if args.len() >= 2 => verify(&args[1..]),
        Some("revocation") if args.len() >= 2 => revocation_mode(&args[1..]),
        _ => {
            eprintln!("usage: field_check smoke HOSTS_FILE [--cacert FILE] [--tsv FILE] [--tls-only] [--no-resume] [--proxy] [--timeout SECONDS]");
            eprintln!("       field_check verify DIR [--cacert FILE]");
            eprintln!("       field_check revocation DIR [--max-crl-kib N]");
            2
        }
    };
    std::process::exit(code);
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn load_trust(cacert: &Option<String>) -> Result<TrustStore, Error> {
    match cacert.as_deref() {
        // the roots built into the crate (BACKLOG B-31), when it is built with them
        #[cfg(feature = "mozilla-roots")]
        Some("mozilla") => Ok(pratique::mozilla_roots::trust_store()),
        #[cfg(not(feature = "mozilla-roots"))]
        Some("mozilla") => Err(Error::Tls("--cacert mozilla needs the example built with --features mozilla-roots".into())),
        // the operating system's own store (BACKLOG B-101): the Keychain trust settings on macOS, the certificate stores on
        // Windows
        Some("native") => sys::native_trust_store(),
        Some(path) => sys::trust_store_from_pem_file(path),
        None => sys::system_trust_store(),
    }
}

/// One line of a tab-separated file: no tab or line break may be left in a field.
fn field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn key_name(key: &PublicKey) -> String {
    match key {
        PublicKey::Rsa(_) => "RSA".to_string(),
        PublicKey::Ec { curve, .. } => format!("EC-{:?}", curve),
        PublicKey::Ed25519(_) => "Ed25519".to_string(),
        _ => "other".to_string(),
    }
}

fn pem_encode(der: &[u8]) -> String {
    let b64 = pem::base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn read_chain(path: &Path) -> Vec<Vec<u8>> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect()
}

/// The part of a name that is the host: `host:port` without the port.
fn host_part(host: &str) -> &str {
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

// ------------------------------------------------------------------------------------------------ smoke

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Group {
    Ok,
    Refuse,
    Info,
    /// A server that speaks TLS 1.2 without the extended master secret (RFC 7627), which the library requires (BACKLOG B-36): the
    /// handshake must be refused for that, whatever the certificate. Marked `no-ems` after the host in the list.
    NoEms,
    /// A server that offers only what the library will not speak (TLS 1.0 or 1.1, CBC, RSA key exchange, finite-field
    /// Diffie-Hellman, no encryption): the handshake must fail as a TLS error, whatever the certificate.
    RefuseHandshake,
    /// A certificate that its CA has revoked: checked with hard-fail revocation and the OCSP and CRL sources of the `net`
    /// feature, it must be refused as revoked.
    Revoked,
}

impl Group {
    fn name(self) -> &'static str {
        match self {
            Group::Ok => "ok",
            Group::Refuse => "refuse",
            Group::Info => "info",
            Group::NoEms => "no-ems",
            Group::RefuseHandshake => "refuse-handshake",
            Group::Revoked => "revoked",
        }
    }
}

struct Site {
    group: Group,
    host: String,
    port: u16,
}

fn parse_hosts(text: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(group), Some(target)) = (words.next(), words.next()) else { continue };
        // a third word `no-ems`: the server does TLS 1.2 without the extended master secret, so the smoke test expects the
        // handshake to be refused for that (the group still says what `mac_field_check.sh capture` expects of the chain)
        let no_ems = match words.next() {
            None => false,
            Some("no-ems") => true,
            Some(other) => {
                eprintln!("hosts file: unknown mark {other:?} (only no-ems) in: {line}");
                continue;
            }
        };
        let group = match group {
            // the -tls12 names mark servers that speak only TLS 1.2 (BACKLOG B-36): judged as the others since the library
            // speaks 1.2 too, and `mac_field_check.sh capture` takes their chains like the others
            "ok" | "ok-tls12" => Group::Ok,
            "refuse" | "refuse-tls12" => Group::Refuse,
            "info" => Group::Info,
            "refuse-handshake" => Group::RefuseHandshake,
            "revoked" => Group::Revoked,
            other => {
                eprintln!("hosts file: unknown group {other:?} (ok, refuse, info, ok-tls12, refuse-tls12, refuse-handshake or revoked) in: {line}");
                continue;
            }
        };
        let (host, port) = match target.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => continue,
            },
            None => (target.to_string(), 443),
        };
        let group = if no_ems { Group::NoEms } else { group };
        sites.push(Site { group, host, port });
    }
    sites
}

/// What one attempt to reach a host came to.
enum Attempt {
    /// No address, no route, a connect timeout: nothing about the library.
    Unreachable(String),
    /// It worked; what was seen.
    Accepted(String),
    /// The library refused (or the server did), and in what class: `cert`, `tls`, `timeout`, `io`, `http`, `refused` or `other`.
    Rejected(&'static str, String),
    /// Two parts of the library disagree about the same chain: always a failure.
    Bug(String),
}

fn class_of(e: &Error) -> &'static str {
    match e {
        Error::Verify(_) => "cert",
        Error::Tls(_) | Error::Alert(..) => "tls",
        Error::Io(io) if matches!(io.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => "timeout",
        Error::Io(_) => "io",
        Error::Http(_) => "http",
        Error::Refused(_) => "refused",
        Error::Decode(_) => "http",
        // (the enum may grow)
        _ => "other",
    }
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| format!("no address: {e}"))?;
    let mut last = "no address".to_string();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// The handshake alone, over a direct connection, and then the same chain through the public `verify_chain`.
fn attempt_direct(site: &Site, config: &ClientConfig, timeout: Duration) -> Attempt {
    handshake_direct(site, config, timeout).0
}

/// [`attempt_direct`], and whether the handshake resumed a session.
fn handshake_direct(site: &Site, config: &ClientConfig, timeout: Duration) -> (Attempt, bool) {
    let tcp = match connect(&site.host, site.port, timeout) {
        Ok(t) => t,
        Err(e) => return (Attempt::Unreachable(e), false),
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let _ = tcp.set_nodelay(true);
    let tls = match TlsStream::connect(tcp, &site.host, config) {
        Ok(t) => t,
        Err(e) => return (Attempt::Rejected(class_of(&e), e.to_string()), false),
    };
    let resumed = tls.is_resumed();
    let now = sys::now_unix();
    // (a resumed handshake reports the chain of the full handshake its session came from, which must still verify)
    let chain = tls.peer_certificates();
    let verified = match config.trust_store.verify_chain(chain, &VerifyOptions::tls_server(&site.host, now)) {
        Ok(v) => v,
        Err(e) => return (Attempt::Bug(format!("the handshake accepted the chain but verify_chain refuses it: {e}")), resumed),
    };
    let anchor = Certificate::from_der(verified.anchor()).map(|c| c.subject_summary()).unwrap_or_else(|_| "?".to_string());
    let attempt = Attempt::Accepted(format!(
        "{} {} alpn={} sent={} path={} leaf={} issuer=[{}] anchor=[{}] expires_in={}d",
        tls.protocol_version().map_or("?".to_string(), |v| v.to_string()),
        tls.cipher_suite_name().unwrap_or("?"),
        tls.alpn_protocol().map_or("-".to_string(), |p| String::from_utf8_lossy(p).into_owned()),
        chain.len(),
        verified.path.len(),
        key_name(&verified.leaf.public_key),
        verified.leaf.issuer_summary(),
        anchor,
        (verified.leaf.not_after - now) / 86_400
    ));
    (attempt, resumed)
}

/// What came of the handshake made again after the GET, with the tickets that connection kept (BACKLOG B-35).
enum Resume {
    /// Not tried (not an `ok` host, the GET did not answer, `--tls-only`, `--no-resume`, or through a proxy).
    NotTried,
    /// The server sent no ticket (or spoke TLS 1.2, where the library does not resume).
    NoTicket,
    /// Tickets only for another name (the host a redirect went to): none was offered.
    OtherName,
    Resumed(String),
    /// A ticket was offered and the server made a full handshake instead.
    Declined(String),
    Unreachable(String),
    /// The handshake that offered a ticket was refused, or contradicted itself: (class, detail).
    Failed(String, String),
}

impl Resume {
    fn name(&self) -> &'static str {
        match self {
            Resume::NotTried => "-",
            Resume::NoTicket => "no-ticket",
            Resume::OtherName => "other-name",
            Resume::Resumed(_) => "resumed",
            Resume::Declined(_) => "declined",
            Resume::Unreachable(_) => "unreachable",
            Resume::Failed(..) => "failed",
        }
    }
}

/// The handshake again, offering one of the tickets `config` kept. A ticket is taken out of the store when it is offered,
/// and this connection reads nothing after its handshake, so it keeps none: the count of kept tickets going down is the
/// offer.
fn attempt_resume(site: &Site, config: &ClientConfig, timeout: Duration) -> Resume {
    let before = config.resumption.sessions();
    if before == 0 {
        return Resume::NoTicket;
    }
    let (attempt, resumed) = handshake_direct(site, config, timeout);
    let offered = config.resumption.sessions() < before;
    match attempt {
        Attempt::Unreachable(m) => Resume::Unreachable(m),
        Attempt::Rejected(c, m) if offered => Resume::Failed(c.to_string(), format!("the handshake that offered a session ticket was refused: {m}")),
        Attempt::Rejected(c, m) => Resume::Failed(c.to_string(), format!("the handshake again (no ticket offered) was refused: {m}")),
        Attempt::Bug(m) => Resume::Failed("inconsistent".to_string(), m),
        Attempt::Accepted(_) if resumed && !offered => Resume::Failed("inconsistent".to_string(), "resumed without a ticket being taken from the store".to_string()),
        Attempt::Accepted(s) if resumed => Resume::Resumed(s),
        Attempt::Accepted(s) if offered => Resume::Declined(s),
        Attempt::Accepted(_) => Resume::OtherName,
    }
}

/// A GET of `/` (redirects followed), reading at most 64 KiB of the body.
fn attempt_http(site: &Site, config: &ClientConfig, via_proxy: bool, timeout: Duration) -> Attempt {
    let mut client = Client::with_tls_config(config.clone())
        .http2(true)
        .timeout(timeout)
        .connect_timeout(timeout)
        .total_timeout(timeout * 3)
        .max_redirects(5)
        .user_agent("pratique-field-check");
    if via_proxy {
        client = client.proxy_from_env();
    }
    let url = if site.port == 443 { format!("https://{}/", site.host) } else { format!("https://{}:{}/", site.host, site.port) };
    let started = Instant::now();
    let mut stream = match client.get_stream(&url) {
        Ok(s) => s,
        Err(e) => return Attempt::Rejected(class_of(&e), e.to_string()),
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0usize;
    while total < 64 * 1024 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Attempt::Rejected("io", format!("reading the body of {} after {} bytes: {e}", stream.status, total)),
        }
    }
    let tls = stream.tls_version.map_or("no TLS".to_string(), |v| v.to_string());
    Attempt::Accepted(format!("{} {} over {tls}, {} bytes read, {} ms", stream.version, stream.status, total, started.elapsed().as_millis()))
}

/// (verdict, class, detail) for one site.
fn judge(group: Group, first: Attempt, second: Option<Attempt>) -> (&'static str, String, String) {
    match (group, first) {
        (_, Attempt::Bug(m)) => ("FAIL", "inconsistent".to_string(), m),
        (_, Attempt::Unreachable(m)) => ("SKIP", "unreachable".to_string(), m),
        (Group::Ok, Attempt::Accepted(s)) => match second {
            Some(Attempt::Rejected(c, m)) => ("FAIL", c.to_string(), format!("the handshake worked ({s}) but the request failed: {m}")),
            Some(Attempt::Bug(m)) => ("FAIL", "inconsistent".to_string(), m),
            Some(Attempt::Accepted(h)) => ("PASS", "-".to_string(), format!("{s}; {h}")),
            Some(Attempt::Unreachable(m)) => ("FAIL", "unreachable".to_string(), format!("the handshake worked ({s}) but the request could not connect: {m}")),
            None => ("PASS", "-".to_string(), s),
        },
        (Group::Ok, Attempt::Rejected(c, m)) => ("FAIL", c.to_string(), m),
        (Group::Refuse, Attempt::Accepted(s)) => ("FAIL", "accepted".to_string(), format!("a certificate that must be refused was accepted: {s}")),
        (Group::Refuse, Attempt::Rejected("cert", m)) => ("PASS", "cert".to_string(), m),
        (Group::Refuse, Attempt::Rejected(c, m)) => ("WEAK", c.to_string(), format!("refused, but not as a certificate error: {m}")),
        (Group::Info, Attempt::Accepted(s)) => ("INFO", "accepted".to_string(), s),
        (Group::Info, Attempt::Rejected(c, m)) => ("INFO", c.to_string(), format!("refused: {m}")),
        (Group::NoEms, Attempt::Rejected("tls", m)) if m.contains("extended master secret") => ("PASS", "no-ems".to_string(), m),
        (Group::NoEms, Attempt::Rejected(c, m)) => ("WEAK", c.to_string(), format!("refused, but not for want of the extended master secret: {m}")),
        // the library takes TLS 1.2 only with the extended master secret, so the server does it now, or speaks TLS 1.3 (or something
        // on the way does: a gateway that terminates TLS): the mark is out of date, or this network is not a direct one
        (Group::NoEms, Attempt::Accepted(s)) => {
            let why = if s.starts_with("TLS 1.3") { "the server, or something on the way, speaks TLS 1.3" } else { "the server does the extended master secret now" };
            ("INFO", "accepted".to_string(), format!("{why} (the no-ems mark is out of date, or this network is not direct): {s}"))
        }
        (Group::RefuseHandshake, Attempt::Accepted(s)) => ("FAIL", "accepted".to_string(), format!("a server that offers only what the library must not speak was accepted: {s}")),
        (Group::RefuseHandshake, Attempt::Rejected("tls", m)) => ("PASS", "tls".to_string(), m),
        (Group::RefuseHandshake, Attempt::Rejected(c, m)) => ("WEAK", c.to_string(), format!("refused, but not at the TLS level: {m}")),
        (Group::Revoked, Attempt::Accepted(s)) => ("FAIL", "accepted".to_string(), format!("a revoked certificate was accepted under hard-fail with the OCSP and CRL sources: {s}")),
        (Group::Revoked, Attempt::Rejected("cert", m)) if m.contains("certificate_revoked") => ("PASS", "revoked".to_string(), m),
        (Group::Revoked, Attempt::Rejected(c, m)) => ("WEAK", c.to_string(), format!("refused, but not as revoked: {m}")),
    }
}

fn smoke(args: &[String]) -> i32 {
    let hosts_path = &args[0];
    let cacert = option(args, "--cacert");
    let tsv_path = option(args, "--tsv");
    let via_proxy = flag(args, "--proxy");
    let tls_only = flag(args, "--tls-only");
    let resume = !flag(args, "--no-resume");
    let timeout = Duration::from_secs(option(args, "--timeout").and_then(|s| s.parse().ok()).unwrap_or(15));
    let text = match std::fs::read_to_string(hosts_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {hosts_path}: {e}");
            return 2;
        }
    };
    let sites = parse_hosts(&text);
    if sites.is_empty() {
        eprintln!("{hosts_path} lists no hosts");
        return 2;
    }
    let trust = match load_trust(&cacert) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot load the CA bundle: {e}");
            return 2;
        }
    };
    println!(
        "smoke test: {} hosts, {} trust anchors, {}, timeout {} s{}",
        sites.len(),
        trust.len(),
        if via_proxy { "through the proxy of the environment (a test of the mechanics, not of B-06)" } else { "direct" },
        timeout.as_secs(),
        if tls_only { ", handshakes only" } else { "" }
    );
    let config = ClientConfig::new(trust);
    // for the revoked group: hard-fail, and the responders and distribution points the certificates name are asked
    let mut checking = config.clone();
    checking.revocation =
        Revocation::hard_fail().with_ocsp_source(Arc::new(HttpOcspSource::new())).with_crl_source(Arc::new(HttpCrlSource::new()));

    let mut rows: Vec<(Group, String, &'static str, String, u128, String, Resume)> = Vec::new();
    for site in &sites {
        let started = Instant::now();
        // a store of sessions of its own for each host, so that what the GET kept is this host's
        let fresh = config.clone().with_resumption(Resumption::new());
        let config = if site.group == Group::Revoked { &checking } else { &fresh };
        let (first, second) = if via_proxy {
            // through a proxy there is no handshake of ours to look at on its own: the request is the attempt
            (attempt_http(site, config, true, timeout), None)
        } else {
            let first = attempt_direct(site, config, timeout);
            let second = if site.group == Group::Ok && !tls_only && matches!(first, Attempt::Accepted(_)) {
                Some(attempt_http(site, config, false, timeout))
            } else {
                None
            };
            (first, second)
        };
        let answered = matches!(second, Some(Attempt::Accepted(_)));
        let (mut verdict, mut class, mut detail) = judge(site.group, first, second);
        let ms = started.elapsed().as_millis();
        let again = if resume && answered && verdict == "PASS" { attempt_resume(site, config, timeout) } else { Resume::NotTried };
        match &again {
            Resume::Resumed(s) | Resume::Declined(s) => detail = format!("{detail}; again: {} {s}", again.name()),
            Resume::Unreachable(m) => detail = format!("{detail}; again: could not connect: {m}"),
            Resume::Failed(c, m) => {
                (verdict, class) = ("FAIL", format!("resumption/{c}"));
                detail = format!("{m} (the full handshake and the GET worked: {detail})");
            }
            Resume::NotTried | Resume::NoTicket | Resume::OtherName => {}
        }
        let name = if site.port == 443 { site.host.clone() } else { format!("{}:{}", site.host, site.port) };
        let group = site.group.name();
        let r = again.name();
        println!("{verdict:<5} {group:<6} {name:<48} {ms:>5} ms  {class:<12} {r:<11} {detail}");
        rows.push((site.group, name, verdict, class, ms, detail, again));
    }

    if let Some(path) = tsv_path {
        let mut out = String::from("group\thost\tverdict\tclass\tms\tdetail\tresumption\n");
        for (group, name, verdict, class, ms, detail, again) in &rows {
            let g = group.name();
            out.push_str(&format!("{g}\t{name}\t{verdict}\t{class}\t{ms}\t{}\t{}\n", field(detail), again.name()));
        }
        if let Err(e) = std::fs::write(&path, out) {
            eprintln!("cannot write {path}: {e}");
        }
    }

    let count = |v: &str| rows.iter().filter(|r| r.2 == v).count();
    let ok_passed = rows.iter().filter(|r| r.0 == Group::Ok && r.2 == "PASS").count();
    let ok_total = rows.iter().filter(|r| r.0 == Group::Ok).count();
    let refuse_passed = rows.iter().filter(|r| r.0 == Group::Refuse && r.2 == "PASS").count();
    let refuse_total = rows.iter().filter(|r| r.0 == Group::Refuse).count();
    let no_ems_passed = rows.iter().filter(|r| r.0 == Group::NoEms && r.2 == "PASS").count();
    let no_ems_total = rows.iter().filter(|r| r.0 == Group::NoEms).count();
    let passed_of = |g: Group| (rows.iter().filter(|r| r.0 == g && r.2 == "PASS").count(), rows.iter().filter(|r| r.0 == g).count());
    let (handshake_passed, handshake_total) = passed_of(Group::RefuseHandshake);
    let (revoked_passed, revoked_total) = passed_of(Group::Revoked);
    println!();
    println!(
        "PASS {}  FAIL {}  WEAK {}  SKIP {}  INFO {}   (hosts that must connect: {}/{}; that must be refused: {}/{}; refused for want of the extended master secret: {}/{}; refused at the handshake: {}/{}; refused as revoked: {}/{})",
        count("PASS"),
        count("FAIL"),
        count("WEAK"),
        count("SKIP"),
        count("INFO"),
        ok_passed,
        ok_total,
        refuse_passed,
        refuse_total,
        no_ems_passed,
        no_ems_total,
        handshake_passed,
        handshake_total,
        revoked_passed,
        revoked_total
    );
    if resume && !via_proxy && !tls_only {
        let n = |k: &str| rows.iter().filter(|r| r.6.name() == k).count();
        let tried = rows.iter().filter(|r| !matches!(r.6, Resume::NotTried)).count();
        println!(
            "TLS 1.3 session resumption (B-35), the handshake again after the GET: resumed {}, declined by the server {}, no ticket sent {}, tickets only for a redirect's host {}, failed {}, unreachable {} (of {tried})",
            n("resumed"),
            n("declined"),
            n("no-ticket"),
            n("other-name"),
            n("failed"),
            n("unreachable")
        );
    }
    for (_, name, verdict, class, _, detail, _) in rows.iter().filter(|r| r.2 == "FAIL" || r.2 == "WEAK") {
        println!("  {verdict} {name} [{class}]: {detail}");
    }
    let mut code = 0;
    if count("FAIL") > 0 {
        println!("RESULT: FAIL. Each FAIL above is a new backlog item (a bug, or a server doing something the library should cope with).");
        code = 1;
    }
    if ok_passed < 10 && !via_proxy {
        println!("NOTE: fewer than 10 hosts answered ({ok_passed}); B-06 asks for at least 10. Hosts that were SKIPped could not be reached at all.");
        code = 1;
    }
    if code == 0 {
        println!("RESULT: ok");
    }
    code
}

// ------------------------------------------------------------------------------------------------ verify

struct Entry {
    name: String,
    host: String,
    time: i64,
    group: String,
    openssl: Option<i32>,
}

fn read_manifest(dir: &Path) -> Result<Vec<Entry>, String> {
    let path = dir.join("manifest.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 5 {
            return Err(format!("{}: a line with fewer than 5 columns: {line}", path.display()));
        }
        entries.push(Entry {
            name: cols[0].to_string(),
            host: cols[1].to_string(),
            time: cols[2].parse().map_err(|_| format!("{}: bad time in: {line}", path.display()))?,
            group: cols[3].to_string(),
            openssl: cols[4].trim().parse().ok(),
        });
    }
    Ok(entries)
}

/// A name the leaf is valid for, with a wildcard replaced by a label: what a client would have asked for.
fn a_name_of(leaf: &Certificate) -> Option<String> {
    leaf.dns_names.first().map(|n| n.strip_prefix("*.").map_or(n.clone(), |rest| format!("www.{rest}")))
}

/// The ways of altering a chain that verified, none of which may be accepted. Returns those that were.
fn accepted_alterations(trust: &TrustStore, chain: &[Vec<u8>], host: &str, time: i64, leaf: &Certificate) -> Vec<String> {
    let mut accepted = Vec::new();
    let mut try_it = |what: String, chain: &[Vec<u8>], host: &str, time: i64| {
        if trust.verify_chain(chain, &VerifyOptions::tls_server(host, time)).is_ok() {
            accepted.push(what);
        }
    };
    try_it("another host name".to_string(), chain, &format!("{host}.invalid"), time);
    try_it("one second after the leaf expires".to_string(), chain, host, leaf.not_after + 1);
    try_it("one second before the leaf is valid".to_string(), chain, host, leaf.not_before - 1);
    for (what, at) in [("the last byte of the leaf (the signature)", chain[0].len() - 1), ("a byte in the middle of the leaf", chain[0].len() / 2)] {
        let mut altered = chain.to_vec();
        altered[0][at] ^= 0x01;
        try_it(format!("a flipped bit in {what}"), &altered, host, time);
    }
    accepted
}

fn verify(args: &[String]) -> i32 {
    let dir = PathBuf::from(&args[0]);
    let cacert = option(args, "--cacert");
    let trust = match load_trust(&cacert) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot load the CA bundle: {e}");
            return 2;
        }
    };
    let entries = match read_manifest(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let out = dir.join("real_chains");
    let _ = std::fs::remove_dir_all(&out);
    for sub in ["chains", "anchors"] {
        if let Err(e) = std::fs::create_dir_all(out.join(sub)) {
            eprintln!("cannot create {}: {e}", out.join(sub).display());
            return 2;
        }
    }
    println!("verify: {} captured chains, {} trust anchors", entries.len(), trust.len());

    let mut fixtures = String::from("# name\thost\ttime\texpect\tanchor\n");
    let mut table = String::from("name\thost\ttime\tverdict\tdetail\n");
    let (mut pass, mut fail, mut weak, mut skip) = (0, 0, 0, 0);
    let (mut ok_fixtures, mut refusal_fixtures) = (0, 0);
    let mut keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors: BTreeMap<String, usize> = BTreeMap::new();

    for e in &entries {
        let chain = read_chain(&dir.join("chains").join(format!("{}.pem", e.name)));
        let host = host_part(&e.host).to_string();
        let mut anchor_der: Option<Vec<u8>> = None;
        let (verdict, expect, detail): (&str, Option<String>, String) = 'entry: {
            if chain.is_empty() {
                break 'entry ("SKIP", None, "no certificate was captured".to_string());
            }
            let Ok(leaf) = Certificate::from_der(&chain[0]) else {
                break 'entry ("WEAK", None, "the library cannot parse the leaf".to_string());
            };
            let ours = trust.verify_chain(&chain, &VerifyOptions::tls_server(&host, e.time));
            if e.group == "refuse" {
                match ours {
                    Ok(_) => break 'entry ("FAIL", None, "a chain that must be refused was accepted".to_string()),
                    Err(err) => {
                        // why: the same chain in the middle of its validity, or for a name it is valid for, or neither
                        let middle = (leaf.not_before + leaf.not_after) / 2;
                        if let Ok(v) = trust.verify_chain(&chain, &VerifyOptions::tls_server(&host, middle)) {
                            anchor_der = Some(v.anchor().to_vec());
                            break 'entry ("PASS", Some("refuse-time".to_string()), format!("refused ({err}); accepted in the middle of its validity"));
                        }
                        if let Some(name) = a_name_of(&leaf) {
                            if let Ok(v) = trust.verify_chain(&chain, &VerifyOptions::tls_server(&name, e.time)) {
                                anchor_der = Some(v.anchor().to_vec());
                                break 'entry ("PASS", Some("refuse-host".to_string()), format!("refused ({err}); accepted for {name}"));
                            }
                        }
                        break 'entry ("PASS", Some("refuse-path".to_string()), format!("refused ({err})"));
                    }
                }
            }
            match ours {
                Err(err) => {
                    if e.openssl == Some(0) {
                        ("FAIL", None, format!("the library refuses a chain that OpenSSL accepted: {err}"))
                    } else {
                        ("WEAK", None, format!("both refuse (OpenSSL code {:?}); does this network re-sign TLS? {err}", e.openssl))
                    }
                }
                Ok(v) => {
                    let wrongly = accepted_alterations(&trust, &chain, &host, e.time, &leaf);
                    anchor_der = Some(v.anchor().to_vec());
                    *keys.entry(key_name(&leaf.public_key)).or_insert(0) += 1;
                    let anchor_name = Certificate::from_der(v.anchor()).map(|c| c.subject_summary()).unwrap_or_default();
                    *anchors.entry(anchor_name.clone()).or_insert(0) += 1;
                    if !wrongly.is_empty() {
                        ("FAIL", None, format!("accepted an altered chain: {}", wrongly.join("; ")))
                    } else if e.openssl.is_some_and(|c| c != 0) {
                        ("WEAK", Some("ok".to_string()), format!("verified (path of {}, anchor [{anchor_name}]), but OpenSSL refused it (code {:?})", v.path.len(), e.openssl))
                    } else {
                        ("PASS", Some("ok".to_string()), format!("{} path of {} to [{anchor_name}]; every alteration refused", key_name(&leaf.public_key), v.path.len()))
                    }
                }
            }
        };
        match verdict {
            "PASS" => pass += 1,
            "FAIL" => fail += 1,
            "WEAK" => weak += 1,
            _ => skip += 1,
        }
        println!("{verdict:<5} {:<48} {}", e.name, detail);
        table.push_str(&format!("{}\t{}\t{}\t{verdict}\t{}\n", e.name, e.host, e.time, field(&detail)));

        // A fixture is kept for a chain whose verdict the library and the world agree on, and nothing else.
        if let (Some(expect), true) = (expect, verdict != "FAIL") {
            let anchor_file = match &anchor_der {
                Some(der) => {
                    let _ = std::fs::write(out.join("anchors").join(format!("{}.pem", e.name)), pem_encode(der));
                    format!("anchors/{}.pem", e.name)
                }
                None => "-".to_string(),
            };
            let chain_pem: String = chain.iter().map(|c| pem_encode(c)).collect();
            let _ = std::fs::write(out.join("chains").join(format!("{}.pem", e.name)), chain_pem);
            fixtures.push_str(&format!("{}\t{}\t{}\t{}\t{}\n", e.name, host, e.time, expect, anchor_file));
            if expect == "ok" {
                ok_fixtures += 1;
            } else {
                refusal_fixtures += 1;
            }
        }
    }
    let _ = std::fs::write(out.join("fixtures.tsv"), &fixtures);
    let _ = std::fs::write(dir.join("verify.tsv"), table);

    println!();
    println!("PASS {pass}  FAIL {fail}  WEAK {weak}  SKIP {skip}");
    println!("fixtures kept: {ok_fixtures} chains that verify, {refusal_fixtures} that must be refused; leaf keys: {keys:?}");
    println!("trust anchors reached: {}", anchors.iter().map(|(k, v)| format!("[{k}] x{v}")).collect::<Vec<_>>().join(", "));
    println!("written to {}", out.display());
    let mut code = 0;
    if fail > 0 {
        println!("RESULT: FAIL. Each FAIL above is a new backlog item.");
        code = 1;
    }
    if ok_fixtures < 10 {
        println!("NOTE: {ok_fixtures} real chains verified; B-08 asks for at least 10.");
        code = 1;
    }
    if !keys.contains_key("RSA") || !keys.keys().any(|k| k.starts_with("EC")) {
        println!("NOTE: the chains do not include both an RSA leaf and an ECDSA leaf (B-06 asks for both).");
    }
    if code == 0 {
        println!("RESULT: ok");
    }
    code
}

// ------------------------------------------------------------------------------------------------ revocation

/// One line of `revocation/manifest.tsv`: a host, when its responder and distribution point were asked, and what came back.
struct RevEntry {
    name: String,
    /// The group of the host in the hosts file (`ok` or `revoked`; `ok` in a manifest written before the column existed).
    group: String,
    time: i64,
    ocsp_url: Option<String>,
    ocsp_file: Option<String>,
    crl_url: Option<String>,
    crl_file: Option<String>,
}

fn read_revocation_manifest(dir: &Path) -> Result<Vec<RevEntry>, String> {
    let path = dir.join("revocation").join("manifest.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let dash = |s: &str| if s.trim() == "-" || s.trim().is_empty() { None } else { Some(s.trim().to_string()) };
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 6 {
            return Err(format!("{}: a line with fewer than 6 columns: {line}", path.display()));
        }
        out.push(RevEntry {
            name: c[0].to_string(),
            group: c.get(6).map_or("ok", |g| g.trim()).to_string(),
            time: c[1].parse().map_err(|_| format!("{}: bad time in: {line}", path.display()))?,
            ocsp_url: dash(c[2]),
            ocsp_file: dash(c[3]),
            crl_url: dash(c[4]),
            crl_file: dash(c[5]),
        });
    }
    Ok(out)
}

/// A signature algorithm's name, from the content of its AlgorithmIdentifier.
fn sig_alg_name(alg: &[u8]) -> String {
    let oid = asn1::Der::new(alg).expect(asn1::TAG_OID).map(|t| asn1::oid_to_string(t.content)).unwrap_or_default();
    match oid.as_str() {
        "1.2.840.113549.1.1.11" => "RSA-SHA256".into(),
        "1.2.840.113549.1.1.12" => "RSA-SHA384".into(),
        "1.2.840.113549.1.1.13" => "RSA-SHA512".into(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".into(),
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512".into(),
        "1.3.101.112" => "Ed25519".into(),
        _ => oid,
    }
}

/// What an OCSP response is, read without verifying anything: who signed it (the CA itself, or a responder certificate
/// it carries), the hash its certificate ID uses, its signature algorithm, the status and the window of its first answer.
struct OcspShape {
    signer: &'static str,
    id_hash: &'static str,
    sig: String,
    status: &'static str,
    this_update: i64,
    next_update: Option<i64>,
}

fn ocsp_shape(der: &[u8]) -> Option<OcspShape> {
    use asn1::{Der, TAG_BIT_STRING, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
    let mut resp = Der::new(der).sequence().ok()?;
    if resp.expect(0x0a).ok()?.content != [0] {
        return None;
    }
    let bytes = resp.expect(0xa0).ok()?;
    let mut rb = Der::new(bytes.content).sequence().ok()?;
    rb.expect(TAG_OID).ok()?;
    let mut basic = Der::new(rb.expect(TAG_OCTET_STRING).ok()?.content).sequence().ok()?;
    let tbs = basic.expect(TAG_SEQUENCE).ok()?;
    let alg = basic.expect(TAG_SEQUENCE).ok()?;
    basic.expect(TAG_BIT_STRING).ok()?;
    let certs = basic.optional(0xa0).ok()?.is_some();
    let mut data = Der::new(tbs.content);
    data.optional(0xa0).ok()?;
    let rid = data.next().ok()?;
    data.next().ok()?; // producedAt
    let mut sr = data.sequence().ok()?.sequence().ok()?;
    let mut id = Der::new(sr.expect(TAG_SEQUENCE).ok()?.content);
    let hash = asn1::oid_to_string(Der::new(id.expect(TAG_SEQUENCE).ok()?.content).expect(TAG_OID).ok()?.content);
    id.expect(TAG_OCTET_STRING).ok()?;
    let issuer_key_hash = id.expect(TAG_OCTET_STRING).ok()?.content;
    let status = match sr.next().ok()?.tag {
        0x80 => "good",
        0xa1 => "revoked",
        0x82 => "unknown",
        _ => "?",
    };
    let this_update = asn1::parse_time(&sr.next().ok()?).ok()?;
    let next_update = match sr.optional(0xa0).ok()? {
        Some(t) => Some(asn1::parse_time(&Der::new(t.content).next().ok()?).ok()?),
        None => None,
    };
    let id_hash = match hash.as_str() {
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => "?",
    };
    // A responder named by the hash of its key is the CA when that is the issuer key hash of a SHA-1 certificate ID.
    let by_key = (rid.tag == 0xa2).then(|| Der::new(rid.content).expect(TAG_OCTET_STRING).ok().map(|t| t.content)).flatten();
    let signer = match by_key {
        Some(h) if id_hash == "SHA-1" => {
            if h == issuer_key_hash {
                "issuer"
            } else {
                "delegated"
            }
        }
        _ if certs => "delegated?",
        _ => "issuer?",
    };
    Some(OcspShape { signer, id_hash, sig: sig_alg_name(alg.content), status, this_update, next_update })
}

/// A CRL's signature algorithm and whether it has an issuingDistributionPoint, read without verifying anything.
fn crl_shape(der: &[u8]) -> Option<(String, bool)> {
    use asn1::{Der, TAG_INTEGER, TAG_SEQUENCE};
    let mut list = Der::new(der).sequence().ok()?;
    let mut tbs = Der::new(list.expect(TAG_SEQUENCE).ok()?.content);
    tbs.optional(TAG_INTEGER).ok()?;
    let alg = tbs.expect(TAG_SEQUENCE).ok()?;
    let mut scoped = false;
    while let Ok(t) = tbs.next() {
        if t.tag == 0xa0 {
            let mut exts = Der::new(Der::new(t.content).expect(TAG_SEQUENCE).ok()?.content);
            while let Ok(mut ext) = exts.sequence() {
                if ext.expect(asn1::TAG_OID).ok()?.content == [0x55, 0x1d, 0x1c] {
                    scoped = true;
                }
            }
        }
    }
    Some((sig_alg_name(alg.content), scoped))
}

/// A file name for a CRL from its URL: the host and path with `_` for anything but letters, digits, `-` and `.`, or the
/// host and the last part of the path where that is too long.
fn crl_file_name(url: &str) -> String {
    let safe = |s: &str| -> String { s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect() };
    let tail = url.trim_start_matches("http://").trim_end_matches(".crl");
    let mut name = safe(tail);
    if name.len() > 80 {
        let host = tail.split('/').next().unwrap_or("");
        let last = safe(tail.rsplit('/').next().unwrap_or(""));
        name = format!("{}_{}", safe(host), &last[last.len().saturating_sub(60)..]);
    }
    format!("{name}.crl")
}

/// What hard-fail revocation checking made of a certificate with one piece of evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The evidence shows it is not revoked.
    Good,
    /// The evidence shows it is revoked.
    Revoked,
    /// The evidence was not used (refused, or not about it), with the library's words.
    Unsettled(String),
}

impl Outcome {
    fn name(&self) -> &str {
        match self {
            Outcome::Good => "good",
            Outcome::Revoked => "revoked",
            Outcome::Unsettled(_) => "unsettled",
        }
    }
}

/// Hard-fail revocation checking of `leaf` (issued by `issuer`) at `now` with `ocsp` (stapled) or `crl` (supplied).
fn rev_check(leaf: &[u8], issuer: &[u8], ocsp: Option<&[u8]>, crl: Option<&[u8]>, now: i64) -> Outcome {
    let mut cfg = Revocation::hard_fail();
    if let Some(der) = crl {
        match Crl::from_der(der) {
            Ok(c) => cfg = cfg.with_crl(c),
            Err(e) => return Outcome::Unsettled(format!("the list does not parse: {e}")),
        }
    }
    let path = vec![leaf.to_vec(), issuer.to_vec()];
    let staples = vec![ocsp.map(|o| o.to_vec())];
    match revocation::check_path(&cfg, &path, &ChainEvidence { sent: &path[..1], staples: &staples }, now) {
        Ok(()) => Outcome::Good,
        Err(e) if e.to_string().contains("certificate_revoked") => Outcome::Revoked,
        Err(e) => Outcome::Unsettled(e.to_string()),
    }
}

/// The alterations of a piece of evidence that settled a certificate (as `expected`), none of which may still settle it:
/// returns those that did. `ocsp` says which kind it is.
fn accepted_rev_alterations(leaf: &[u8], issuer: &[u8], evidence: &[u8], ocsp: bool, expected: &Outcome, this_update: i64, until: i64, time: i64) -> Vec<String> {
    let check = |issuer: &[u8], der: &[u8], at: i64| if ocsp { rev_check(leaf, issuer, Some(der), None, at) } else { rev_check(leaf, issuer, None, Some(der), at) };
    let mut accepted = Vec::new();
    for (what, at) in [("one second after its window", until + 1), ("more than five minutes before its thisUpdate", this_update - 301)] {
        if check(issuer, evidence, at) == *expected {
            accepted.push(what.to_string());
        }
    }
    for (what, at) in [("its last byte (the signature)", evidence.len() - 1), ("a byte in the middle", evidence.len() / 2), ("a byte near the start", 12.min(evidence.len() - 1))] {
        let mut altered = evidence.to_vec();
        altered[at] ^= 0x01;
        if check(issuer, &altered, time) == *expected {
            accepted.push(format!("a flipped bit in {what}"));
        }
    }
    if check(leaf, evidence, time) == *expected {
        accepted.push("the leaf as its own issuer".to_string());
    }
    accepted
}

fn revocation_mode(args: &[String]) -> i32 {
    let dir = PathBuf::from(&args[0]);
    let max_crl = option(args, "--max-crl-kib").and_then(|s| s.parse::<usize>().ok()).unwrap_or(256) << 10;
    let entries = match read_revocation_manifest(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let out = dir.join("real_revocation");
    let _ = std::fs::remove_dir_all(&out);
    for sub in ["certs", "ocsp", "crl"] {
        if let Err(e) = std::fs::create_dir_all(out.join(sub)) {
            eprintln!("cannot create {}: {e}", out.join(sub).display());
            return 2;
        }
    }
    println!("revocation: {} hosts", entries.len());
    let mut fixtures = String::from("# kind\tname\ttime\tevidence\tcerts\turl\tthis_update\tvalid_until\tshape\texpect\n");
    let (mut pass, mut fail, mut weak, mut skip) = (0, 0, 0, 0);
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    let mut crls_seen: BTreeMap<String, String> = BTreeMap::new();
    let mut slowest = (0.0f64, String::new());
    let mut revoked_hosts: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();

    for e in &entries {
        let host_dir = dir.join("revocation").join(&e.name);
        let certs: Vec<Vec<u8>> = ["cert1.pem", "cert2.pem"].iter().flat_map(|f| read_chain(&host_dir.join(f))).collect();
        let mut kept_certs = false;
        let mut keep_certs = |out: &Path| {
            if !kept_certs {
                let pem: String = certs.iter().map(|c| pem_encode(c)).collect();
                let _ = std::fs::write(out.join("certs").join(format!("{}.pem", e.name)), pem);
                kept_certs = true;
            }
        };
        if certs.len() < 2 {
            println!("SKIP  {:<34} the leaf and its issuer were not both captured", e.name);
            skip += 1;
            continue;
        }
        let (leaf, issuer) = (&certs[0], &certs[1]);
        if Certificate::from_der(leaf).is_err() || Certificate::from_der(issuer).is_err() {
            println!("WEAK  {:<34} the library cannot parse the leaf or its issuer", e.name);
            weak += 1;
            continue;
        }
        if e.group == "revoked" {
            revoked_hosts.insert(e.name.clone(), Vec::new());
        }

        // OCSP: what the response says (read from its bytes, and by LibreSSL), then the library
        if let (Some(url), Some(file)) = (&e.ocsp_url, &e.ocsp_file) {
            let der = std::fs::read(dir.join(file)).unwrap_or_default();
            let libressl = std::fs::read_to_string(host_dir.join("ocsp.txt"))
                .unwrap_or_default()
                .lines()
                .find_map(|l| {
                    let l = l.trim_end();
                    ["good", "revoked", "unknown"].into_iter().find(|w| l.ends_with(&format!(": {w}")))
                })
                .unwrap_or("?");
            let (verdict, detail) = match ocsp_shape(&der) {
                _ if der.is_empty() => ("SKIP", "no response was captured".to_string()),
                None => ("WEAK", format!("{} bytes that are not a successful basic OCSP response", der.len())),
                Some(s) => {
                    let until = s.next_update.unwrap_or(s.this_update + 7 * 86_400);
                    let shape = format!("{} {}-id {}", s.signer, s.id_hash, s.sig);
                    let expected = match s.status {
                        "good" => Some(Outcome::Good),
                        "revoked" => Some(Outcome::Revoked),
                        _ => None,
                    };
                    let got = rev_check(leaf, issuer, Some(&der), None, e.time);
                    match expected {
                        None => ("PASS", format!("{shape}: {}: {}", s.status, got.name())),
                        Some(want) if got != want => ("FAIL", format!("{shape}: a {} response, but the library says {got:?}", s.status)),
                        Some(want) => {
                            let wrongly = accepted_rev_alterations(leaf, issuer, &der, true, &want, s.this_update, until, e.time);
                            if !wrongly.is_empty() {
                                ("FAIL", format!("{shape}: still {} when altered: {}", s.status, wrongly.join("; ")))
                            } else if libressl != s.status {
                                ("WEAK", format!("{shape}: {}, but LibreSSL said {libressl}", s.status))
                            } else {
                                if want == Outcome::Revoked {
                                    revoked_hosts.entry(e.name.clone()).or_default().push("OCSP");
                                }
                                *shapes.entry(format!("OCSP {} {shape}", s.status)).or_insert(0) += 1;
                                keep_certs(&out);
                                let _ = std::fs::write(out.join("ocsp").join(format!("{}.der", e.name)), &der);
                                fixtures.push_str(&format!(
                                    "ocsp\t{}\t{}\tocsp/{}.der\tcerts/{}.pem\t{url}\t{}\t{until}\t{shape}\t{}\n",
                                    e.name, e.time, e.name, e.name, s.this_update, s.status
                                ));
                                ("PASS", format!("{} B, {shape}, {} for {:.1} h more; every alteration refused", der.len(), s.status, (until - e.time) as f64 / 3600.0))
                            }
                        }
                    }
                }
            };
            match verdict {
                "PASS" => pass += 1,
                "FAIL" => fail += 1,
                "WEAK" => weak += 1,
                _ => skip += 1,
            }
            println!("{verdict:<5} {:<34} OCSP {detail}", e.name);
        }

        // CRL: a host of the revoked group must be on it, any other must not
        if let (Some(url), Some(file)) = (&e.crl_url, &e.crl_file) {
            let der = std::fs::read(dir.join(file)).unwrap_or_default();
            let want = if e.group == "revoked" { Outcome::Revoked } else { Outcome::Good };
            let t0 = Instant::now();
            let parsed = Crl::from_der(&der);
            let got = rev_check(leaf, issuer, None, Some(&der), e.time);
            let ms = t0.elapsed().as_secs_f64() * 1e3;
            if ms > slowest.0 {
                slowest = (ms, format!("{} ({} B)", url, der.len()));
            }
            let (verdict, detail) = match &parsed {
                _ if der.is_empty() => ("SKIP", "no list was captured".to_string()),
                Err(err) => ("WEAK", format!("{} B that the library does not take: {err}", der.len())),
                Ok(_) if got != want => ("FAIL", format!("{} B: the certificate should be {} by this list, and the library says {got:?}", der.len(), want.name())),
                Ok(crl) => {
                    let (sig, scoped) = crl_shape(&der).unwrap_or_default();
                    let shape = format!("{} entries, {}, {sig}", crl.len(), if scoped { "scoped" } else { "unscoped" });
                    let wrongly = accepted_rev_alterations(leaf, issuer, &der, false, &want, crl.this_update(), crl.valid_until(), e.time);
                    if !wrongly.is_empty() {
                        ("FAIL", format!("{shape}: still {} when altered: {}", want.name(), wrongly.join("; ")))
                    } else {
                        if want == Outcome::Revoked {
                            revoked_hosts.entry(e.name.clone()).or_default().push("CRL");
                        }
                        if der.len() <= max_crl {
                            let name = crl_file_name(url);
                            if !crls_seen.contains_key(&name) {
                                let _ = std::fs::write(out.join("crl").join(&name), &der);
                                *shapes.entry(format!("CRL {}{}", if scoped { "scoped " } else { "" }, sig)).or_insert(0) += 1;
                            }
                            crls_seen.insert(name.clone(), url.clone());
                            keep_certs(&out);
                            fixtures.push_str(&format!(
                                "crl\t{}\t{}\tcrl/{name}\tcerts/{}.pem\t{url}\t{}\t{}\t{shape}\t{}\n",
                                e.name,
                                e.time,
                                e.name,
                                crl.this_update(),
                                crl.valid_until(),
                                want.name()
                            ));
                        }
                        ("PASS", format!("{} B, {shape}, {} by it, checked in {ms:.1} ms; every alteration refused", der.len(), want.name()))
                    }
                }
            };
            match verdict {
                "PASS" => pass += 1,
                "FAIL" => fail += 1,
                "WEAK" => weak += 1,
                _ => skip += 1,
            }
            println!("{verdict:<5} {:<34} CRL  {detail}", e.name);
        }
    }
    let _ = std::fs::write(out.join("fixtures.tsv"), &fixtures);

    println!();
    println!("PASS {pass}  FAIL {fail}  WEAK {weak}  SKIP {skip}");
    for (shape, n) in &shapes {
        println!("  kept: {shape} x{n}");
    }
    for (host, by) in &revoked_hosts {
        if by.is_empty() {
            println!("NOTE: {host} is in the revoked group, but no response or list captured for it says so");
        } else {
            println!("  revoked, according to: {host}: {}", by.join(" and "));
        }
    }
    println!("slowest list to parse and check: {:.1} ms, {}", slowest.0, slowest.1);
    println!("written to {} (lists over {} KiB left out)", out.display(), max_crl >> 10);
    if fail > 0 {
        println!("RESULT: FAIL. Each FAIL above is a new backlog item.");
        return 1;
    }
    println!("RESULT: ok");
    0
}
