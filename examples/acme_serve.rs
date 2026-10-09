//! An HTTPS server that gets and renews its own certificates with ACME (`pratique::http::server::acme`, B-113): the
//! production server and runtime with a page or two, the challenges answered on its own ports, and the certificates
//! kept in a state directory.
//!
//! FOR TRYING OUT: the server is not ready for production yet (BACKLOG B-114: no independent review yet). It asks Let's
//! Encrypt's staging service by default, whose certificates nothing trusts; `directory=production` asks the real one.
//!
//!     cargo run --release --features server --example acme_serve -- names=example.com,www.example.com [options]
//!
//!   names=a,b           the certificate's names (DNS names, *. wildcards, IP addresses); `;` starts another
//!                       certificate (names=a.example;b.example,c.example)
//!   directory=URL       the CA's directory (default: Let's Encrypt staging; `production` for Let's Encrypt)
//!   state=DIR           where the account key and the certificates are kept (default: acme-state)
//!   contact=URL         the account's contact (mailto:you@example.com)
//!   challenges=LIST     which to answer, in order of preference: tls-alpn-01, http-01, dns-01 (default
//!                       tls-alpn-01,http-01)
//!   https=ADDR          the HTTPS listener (default [::]:443); TLS-ALPN-01 is answered here
//!   http=ADDR           the plain listener (default [::]:80): HTTP-01, and a redirect to HTTPS for the rest
//!   dns01_cmd=PROGRAM   DNS-01's hook: run as `PROGRAM present|cleanup NAME VALUE`, it adds or removes the TXT
//!                       record VALUE at NAME (and `present` returns once the record is published)
//!   ca_file=FILE        trust the CA certificates in FILE (PEM) for reaching the ACME server (a test CA's)
//!   eab_kid=ID          an external account binding, for a CA that requires one, with
//!   eab_key=KEY         its MAC key (base64url)
//!   profile=NAME        the certificate profile to ask for (Let's Encrypt: classic, tlsserver, shortlived)
//!   once=1              exit once every certificate has been got (or loaded), after printing where it is saved
//!
//! It prints `listening ADDR` for each listener, and a line for each thing ACME does (`acme: ...`).

use pratique::http::server::acme::{self, Acme, AcmeConfig, AcmeTlsAlpn01, Dns01};
use pratique::http::server::{redirect_to_https, AcmeHttp01, Request, Response, ServerBuilder};
use pratique::http::Client;
use pratique::tls::certs::CertStore;
use pratique::tls::server::ServerConfig;
use pratique::tls::ClientConfig;
use pratique::x509::TrustStore;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// DNS-01 through a program the operator provides.
struct Hook(String);

impl Dns01 for Hook {
    fn present(&self, name: &str, value: &str) -> Result<(), String> {
        let status = Command::new(&self.0).args(["present", name, value]).status().map_err(|e| format!("{}: {e}", self.0))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} present {name}: {status}", self.0))
        }
    }
    fn cleanup(&self, name: &str, value: &str) {
        let _ = Command::new(&self.0).args(["cleanup", name, value]).status();
    }
}

fn main() {
    let mut opts = HashMap::new();
    for a in std::env::args().skip(1) {
        match a.split_once('=') {
            Some((k, v)) => {
                opts.insert(k.to_string(), v.to_string());
            }
            None => {
                eprintln!("{}", include_str!("acme_serve.rs").lines().take_while(|l| l.starts_with("//")).map(|l| l.trim_start_matches("//").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
                std::process::exit(2);
            }
        }
    }
    let get = |k: &str, default: &str| opts.get(k).cloned().unwrap_or_else(|| default.to_string());
    let Some(names) = opts.get("names") else {
        eprintln!("names= is required (try without arguments for the options)");
        std::process::exit(2);
    };
    let sets: Vec<Vec<String>> = names.split(';').map(|set| set.split(',').map(str::to_string).collect()).collect();
    let directory = match get("directory", "staging").as_str() {
        "staging" => acme::LETS_ENCRYPT_STAGING.to_string(),
        "production" => acme::LETS_ENCRYPT.to_string(),
        url => url.to_string(),
    };

    let mut config = AcmeConfig::new(&directory, get("state", "acme-state")).agree_to_terms();
    if let Some(c) = opts.get("contact") {
        config = config.contact(c);
    }
    let (http01, tls_alpn01) = (AcmeHttp01::new(), AcmeTlsAlpn01::new());
    for c in get("challenges", "tls-alpn-01,http-01").split(',') {
        config = match c {
            "tls-alpn-01" => config.tls_alpn01(&tls_alpn01),
            "http-01" => config.http01(&http01),
            "dns-01" => config.dns01(Hook(opts.get("dns01_cmd").cloned().expect("dns-01 needs dns01_cmd="))),
            other => panic!("unknown challenge {other}"),
        };
    }
    if let Some(path) = opts.get("ca_file") {
        let mut roots = TrustStore::empty();
        let n = roots.add_pem(&std::fs::read_to_string(path).expect("read ca_file"));
        assert!(n > 0, "no certificate in {path}");
        config = config.client(Client::with_tls_config(ClientConfig::new(roots)));
    }
    if let (Some(kid), Some(key)) = (opts.get("eab_kid"), opts.get("eab_key")) {
        config = config.external_account(kid, key);
    }
    if let Some(p) = opts.get("profile") {
        config = config.profile(p);
    }
    let acme = Acme::new(config).unwrap_or_else(|e| panic!("{e}"));

    let mut tls = ServerConfig::with_certificates(CertStore::new()).with_alpn(&["h2", "http/1.1"]);
    let store = tls.store.clone().expect("a configuration made with a store");
    tls.certs = tls_alpn01.wrap(tls.certs.clone());
    let https = get("https", "[::]:443");
    let https_port = https.rsplit(':').next().and_then(|p| p.parse().ok());
    let server = ServerBuilder::new(|req: Request| {
        let who = req.connection().tls.as_ref().and_then(|t| t.server_name.clone()).unwrap_or_default();
        Response::text(200, format!("hello from {who} over {:?}: {}\n", req.version(), req.path()))
    })
    .tls(&https, Arc::new(tls))
    .plain_with(&get("http", "[::]:80"), http01.wrap(redirect_to_https(https_port)))
    .start()
    .unwrap_or_else(|e| panic!("listening: {e}"));
    for a in server.local_addrs() {
        println!("listening {a}");
    }

    let once = opts.contains_key("once");
    let (done_tx, done_rx) = std::sync::mpsc::channel::<String>();
    let manager = acme::manage(acme.clone(), sets.clone(), store.clone(), move |m| {
        println!("acme: {m}");
        let _ = done_tx.send(m.to_string());
    });
    if once {
        // until every set has a certificate, or a failure
        let mut have = 0;
        while have < sets.len() {
            match done_rx.recv_timeout(Duration::from_secs(600)) {
                Ok(m) if m.starts_with("certificate for ") && (m.contains(" obtained") || m.contains(" loaded from") || m.contains(" renewed")) => have += 1,
                Ok(m) if m.starts_with("certificate for ") => {
                    eprintln!("failed: {m}");
                    std::process::exit(1);
                }
                Ok(_) => {}
                Err(_) => {
                    eprintln!("no certificate after ten minutes");
                    std::process::exit(1);
                }
            }
        }
        for set in &sets {
            let names: Vec<&str> = set.iter().map(String::as_str).collect();
            println!("saved {}", acme.certificate_dir(&names).expect("names").display());
        }
        drop(manager);
        server.shutdown(Duration::from_secs(1));
        return;
    }
    server.wait();
}
