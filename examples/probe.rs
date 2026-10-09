//! Prints what pratique negotiates with each host given on the command line (direct TCP, no proxy).
//!
//! Usage: cargo run --release --example probe -- host [host ...]

use std::net::TcpStream;
use std::time::{Duration, Instant};
use pratique::tls::{ClientConfig, TlsStream};
use pratique::x509::{Certificate, PublicKey};

fn main() {
    let config = match ClientConfig::with_system_roots() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot load CA bundle: {}", e);
            std::process::exit(1);
        }
    };
    for host in std::env::args().skip(1) {
        let started = Instant::now();
        let result = (|| -> Result<String, pratique::error::Error> {
            let tcp = TcpStream::connect((host.as_str(), 443))?;
            tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
            tcp.set_write_timeout(Some(Duration::from_secs(15)))?;
            let tls = TlsStream::connect(tcp, &host, &config)?;
            let leaf = Certificate::from_der(tls.peer_certificate().unwrap())?;
            let key = match &leaf.public_key {
                PublicKey::Rsa(_) => "RSA".to_string(),
                PublicKey::Ec { curve, .. } => format!("EC {:?}", curve),
                PublicKey::Ed25519(_) => "Ed25519".to_string(),
                _ => "unsupported".to_string(),
            };
            Ok(format!(
                "{} {} | leaf key {} | {} SANs | alpn {:?}",
                tls.protocol_version().map_or("?".to_string(), |v| v.to_string()),
                tls.cipher_suite_name().unwrap_or("?"),
                key,
                leaf.dns_names.len(),
                tls.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
            ))
        })();
        match result {
            Ok(s) => println!("OK   {:<28} {:>4} ms  {}", host, started.elapsed().as_millis(), s),
            Err(e) => println!("FAIL {:<28} {}", host, e),
        }
    }
}
