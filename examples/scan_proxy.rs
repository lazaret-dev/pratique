//! The scanning proxy (`pratique::proxy`, B-78) with a block list: package managers pointed at it get the packages of
//! PyPI and npm through it, and a package on the list is refused before its metadata or its files reach them.
//!
//! NOT TO BE RELIED ON YET (BACKLOG B-78: the review of B-23 first). Its CA lives in memory for as long as the proxy runs
//! and is limited to the hosts it intercepts.
//!
//!     cargo run --release --features server --example scan_proxy -- [options] [-- command args...]
//!
//!   block=a,b          packages to refuse: npm names (`left-pad`, `@scope/name`) or PyPI names, each optionally
//!                      `@version` (`left-pad@1.3.0`, `requests@2.32.3`)
//!   inspect=1          read each package file whole before it goes on (its size and SHA-256 are printed)
//!   intercept=a,b      the hosts to open (default: pypi.org, files.pythonhosted.org, registry.npmjs.org,
//!                      registry.yarnpkg.com)
//!   others=refuse      refuse a CONNECT to any other host (default: tunnel it)
//!   ports=443,...      the ports a CONNECT may reach (default 443)
//!   listen=ADDR        the proxy's address (default 127.0.0.1:0, a free port)
//!   dir=DIR            where the CA (ca.pem) and the bundle of roots and CA (bundle.pem) are written (default: a new
//!                      directory in the system's temporary directory)
//!   user=U pass=P      credentials the proxy requires (they go into the proxy URL of the variables)
//!   upstream_ca=FILE   the roots the proxy trusts for the real hosts (PEM; default: the roots this machine trusts:
//!                      the system's file and store, and the files SSL_CERT_FILE and the like name, where a gateway
//!                      that inspects TLS, Zscaler or Netskope, has its root)
//!   upstream_proxy=URL a proxy the proxy goes through itself (default: the one HTTPS_PROXY names, if any, except for
//!                      the hosts NO_PROXY names; `none` for none)
//!   resolve=host:ip    where a host is, instead of asking DNS (for tests; repeat with commas)
//!   quiet=1            no line for each request
//!
//! Without a command it prints the variables as `export` lines (`eval "$(scan_proxy ...)"` in another shell is not the
//! way: it runs until stopped) and serves until it is stopped. With one after `--` it runs the command with the variables
//! set, then stops, and exits with the command's status.

use pratique::crypto::sha2::{Hash, Sha256};
use pratique::http::Client;
use pratique::proxy::registry::{pypi_normalize, Ecosystem};
use pratique::proxy::{shell_exports, Action, BodyAction, Decision, Exchange, Inspected, Others, Proxy, Scanner, Upstream};
use pratique::tls::ClientConfig;
use pratique::x509::TrustStore;
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

struct BlockList {
    /// (name, version): npm names as they are, PyPI names normalized
    blocked: Vec<(String, Option<String>)>,
    inspect: bool,
}

impl Scanner for BlockList {
    fn request(&self, ex: &Exchange) -> Decision {
        let Some(p) = ex.package() else { return Decision::Allow };
        let name = if p.ecosystem == Ecosystem::PyPI { pypi_normalize(&p.name) } else { p.name.clone() };
        for (n, v) in &self.blocked {
            let same_name = *n == name || (p.ecosystem == Ecosystem::PyPI && pypi_normalize(n) == name);
            let same_version = v.is_none() || v.as_deref() == p.version.as_deref();
            if same_name && same_version {
                return Decision::Block(format!("{}{} is on the block list", p.name, v.as_ref().map(|v| format!("@{v}")).unwrap_or_default()));
            }
        }
        Decision::Allow
    }

    fn response(&self, ex: &Exchange, up: &Upstream) -> BodyAction {
        if self.inspect && up.status == 200 && ex.package().is_some_and(|p| p.is_artifact()) {
            BodyAction::Inspect
        } else {
            BodyAction::Pass
        }
    }

    fn inspect(&self, ex: &Exchange, _up: &Upstream, body: &Inspected) -> Decision {
        let mut hash = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let Ok(mut r) = body.open() else { return Decision::Block("the body could not be read back".into()) };
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hash.update(&buf[..n]),
                Err(_) => return Decision::Block("the body could not be read back".into()),
            }
        }
        let digest = hash.finalize();
        eprintln!("scan_proxy: inspected {} ({} bytes, sha256 {})", ex.url(), body.len(), pratique::util::hex(&digest));
        if body.is_empty() {
            return Decision::Block("an empty package file".into());
        }
        Decision::Allow
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let split = args.iter().position(|a| a == "--");
    let (options, command) = match split {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (&args[..], &args[args.len()..]),
    };
    let mut opts = HashMap::new();
    for a in options {
        match a.split_once('=') {
            Some((k, v)) => {
                opts.insert(k.to_string(), v.to_string());
            }
            None => {
                eprintln!("{}", include_str!("scan_proxy.rs").lines().take_while(|l| l.starts_with("//")).map(|l| l.trim_start_matches("//").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
                std::process::exit(2);
            }
        }
    }
    let list = |k: &str| opts.get(k).map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>()).unwrap_or_default();

    let blocked = list("block")
        .into_iter()
        .map(|b| {
            // a version follows the last @ that is not the first character (@scope/name@1.0.0)
            match b.rfind('@').filter(|&i| i > 0) {
                Some(i) => (b[..i].to_string(), Some(b[i + 1..].to_string())),
                None => (b, None),
            }
        })
        .collect();
    let scanner = BlockList { blocked, inspect: opts.get("inspect").is_some_and(|v| v == "1") };

    // the proxy's own client: the default (the machine's roots, and the proxy HTTPS_PROXY names) unless told otherwise
    let custom = ["upstream_ca", "upstream_proxy", "resolve"].iter().any(|k| opts.contains_key(*k));
    let client = custom.then(|| {
        let roots = match opts.get("upstream_ca") {
            Some(path) => {
                let mut roots = TrustStore::empty();
                let n = roots.add_pem(&std::fs::read_to_string(path).expect("read upstream_ca"));
                assert!(n > 0, "no certificate in {path}");
                roots
            }
            None => pratique::proxy::local_roots().expect("the machine's roots"),
        };
        let mut client = Client::with_tls_config(ClientConfig::new(roots));
        for r in list("resolve") {
            let (host, ip) = r.rsplit_once(':').expect("resolve=host:ip");
            client = client.resolve_host(host, &[ip.parse::<IpAddr>().expect("an IP address")]);
        }
        match opts.get("upstream_proxy").map(String::as_str) {
            Some("none") => client,
            Some(p) => client.proxy(p).expect("upstream_proxy"),
            None => client.proxy_from_env(),
        }
    });

    let quiet = opts.get("quiet").is_some_and(|v| v == "1");
    let mut builder = Proxy::builder(scanner).events(move |e| {
        if quiet && !matches!(e.action, Action::Block | Action::Fail | Action::Refuse) {
            return;
        }
        let bytes = e.bytes.map(|b| format!(" {b} bytes")).unwrap_or_default();
        let detail = if e.detail.is_empty() { String::new() } else { format!(": {}", e.detail) };
        eprintln!("scan_proxy: {:?} {} {} {}{bytes}{detail}", e.action, e.method, e.url, e.status);
    });
    if let Some(c) = client {
        builder = builder.client(c);
    }
    let intercept = list("intercept");
    if !intercept.is_empty() {
        builder = builder.intercept(&intercept.iter().map(String::as_str).collect::<Vec<_>>());
    }
    if opts.get("others").is_some_and(|v| v == "refuse") {
        builder = builder.others(Others::Refuse);
    }
    let ports: Vec<u16> = list("ports").iter().map(|p| p.parse().expect("a port")).collect();
    if !ports.is_empty() {
        builder = builder.ports(&ports);
    }
    if let (Some(u), Some(p)) = (opts.get("user"), opts.get("pass")) {
        builder = builder.credentials(u, p);
    }
    let proxy = builder.build().unwrap_or_else(|e| panic!("{e}"));
    let server = proxy.start(&opts.get("listen").cloned().unwrap_or_else(|| "127.0.0.1:0".into())).unwrap_or_else(|e| panic!("listening: {e}"));
    let addr = server.local_addrs()[0];
    let dir = opts.get("dir").map(Into::into).unwrap_or_else(|| std::env::temp_dir().join(format!("scan-proxy-{}", std::process::id())));
    let files = proxy.write_trust_files(&dir).unwrap_or_else(|e| panic!("the trust files: {e}"));
    let env = proxy.client_env(addr, &files);
    eprintln!("scan_proxy: listening {addr}; CA in {}, valid until {}", files.ca.display(), proxy.ca().not_after());

    if command.is_empty() {
        print!("{}", shell_exports(&env));
        server.wait();
        return;
    }
    let status = Command::new(&command[0]).args(&command[1..]).envs(env).status();
    server.shutdown(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("scan_proxy: {}: {e}", command[0]);
            std::process::exit(127);
        }
    }
}
