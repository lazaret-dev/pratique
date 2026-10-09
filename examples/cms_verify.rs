//! Checks a CMS / PKCS#7 signature file (a Java `META-INF/*.RSA`, a `.p7s`, an S/MIME signature,
//! a PEM `PKCS7` or `CMS` block) the way `cms::SignedData::verify` does, and prints who signed,
//! the chain to the trusted root, the time the chain was checked at, any RFC 3161 time stamp and
//! anything weak about it.
//!
//! ```text
//! cargo run --release --example cms_verify -- [--detached FILE] [--cacert FILE] [--purpose P]
//!                                             [--at UNIX_SECONDS] [--allow-sha1]
//!                                             [--timestamps ignore|verify|require] [--signature-only] MESSAGE
//! cargo run --release --example cms_verify -- --detached META-INF/MANIFEST.SF --purpose code META-INF/CERT.RSA
//! ```
//!
//! `P` is `code` (the default), `email`, `tls`, `client`, `timestamp` or `any`. The trusted roots
//! are `--cacert` (a PEM bundle) or the system bundle; for a signature made with a private chain,
//! pass that chain's root. `--at` is the time the chain must be valid at when no time stamp says
//! otherwise (the default is now). `--signature-only` checks only the digest and the signature
//! against the certificate in the message, which says nothing about who the signer is. The exit
//! status is 0 when every signer verified.

use std::error::Error;

use pratique::cms::{self, Options, SignedData, Timestamps};
use pratique::pem;
use pratique::sys;
use pratique::x509::{Certificate, Purpose};

fn usage() -> ! {
    eprintln!("usage: cms_verify [--detached FILE] [--cacert FILE] [--purpose code|email|tls|client|timestamp|any] [--at UNIX] [--allow-sha1] [--timestamps ignore|verify|require] [--signature-only] MESSAGE");
    std::process::exit(2);
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

/// The usual name of an algorithm OID, or the OID.
fn name(oid: String) -> String {
    let known = [
        ("1.3.14.3.2.26", "SHA-1"),
        ("2.16.840.1.101.3.4.2.1", "SHA-256"),
        ("2.16.840.1.101.3.4.2.2", "SHA-384"),
        ("2.16.840.1.101.3.4.2.3", "SHA-512"),
        ("1.2.840.113549.1.1.1", "RSA"),
        ("1.2.840.113549.1.1.5", "SHA-1 with RSA"),
        ("1.2.840.113549.1.1.11", "SHA-256 with RSA"),
        ("1.2.840.113549.1.1.12", "SHA-384 with RSA"),
        ("1.2.840.113549.1.1.13", "SHA-512 with RSA"),
        ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
        ("1.2.840.10045.2.1", "ECDSA"),
        ("1.2.840.10045.4.1", "ECDSA with SHA-1"),
        ("1.2.840.10045.4.3.2", "ECDSA with SHA-256"),
        ("1.2.840.10045.4.3.3", "ECDSA with SHA-384"),
        ("1.2.840.10045.4.3.4", "ECDSA with SHA-512"),
        ("1.3.101.112", "Ed25519"),
    ];
    known.iter().find(|(o, _)| *o == oid).map(|(_, n)| n.to_string()).unwrap_or(oid)
}

fn when(t: i64) -> String {
    // days since 1970-01-01 to a civil date (Howard Hinnant's algorithm), enough for a report
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn run() -> Result<bool, Box<dyn Error>> {
    let (mut detached, mut cacert, mut message) = (None::<String>, None::<String>, None::<String>);
    let mut purpose = Purpose::CodeSigning;
    let (mut at, mut allow_sha1, mut stamps, mut signature_only) = (None::<i64>, false, Timestamps::Verify, false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--detached" => detached = args.next(),
            "--cacert" => cacert = args.next(),
            "--purpose" => {
                purpose = match args.next().as_deref() {
                    Some("code") => Purpose::CodeSigning,
                    Some("email") => Purpose::EmailProtection,
                    Some("tls") => Purpose::ServerAuth,
                    Some("client") => Purpose::ClientAuth,
                    Some("timestamp") => Purpose::TimeStamping,
                    Some("any") => Purpose::Any,
                    _ => usage(),
                }
            }
            "--at" => at = Some(args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--allow-sha1" => allow_sha1 = true,
            "--timestamps" => {
                stamps = match args.next().as_deref() {
                    Some("ignore") => Timestamps::Ignore,
                    Some("verify") => Timestamps::Verify,
                    Some("require") => Timestamps::Require,
                    _ => usage(),
                }
            }
            "--signature-only" => signature_only = true,
            "-h" | "--help" => usage(),
            _ if message.is_none() => message = Some(a),
            _ => usage(),
        }
    }
    let message = std::fs::read(message.unwrap_or_else(|| usage()))?;
    let detached = detached.map(std::fs::read).transpose()?;

    // PEM armor (PKCS7 or CMS) or the DER/BER itself
    let der = match std::str::from_utf8(&message) {
        Ok(text) if text.contains("-----BEGIN ") => pem::parse(text)
            .into_iter()
            .find(|b| b.label == "PKCS7" || b.label == "CMS")
            .ok_or("no PKCS7 or CMS block in the PEM file")?
            .data,
        _ => message,
    };
    let sd = SignedData::parse(&der)?;
    println!("content type {}, {} signer(s), {} certificate(s) in the message ({} unreadable)", sd.content_type(), sd.signers().len(), sd.certificates().len(), sd.skipped_certificates());
    println!("content: {}", match (sd.content(), &detached) {
        (Some(c), _) => format!("attached, {} bytes", c.len()),
        (None, Some(d)) => format!("detached, {} bytes supplied", d.len()),
        (None, None) => "detached, none supplied".to_string(),
    });

    let trust = match &cacert {
        Some(path) => sys::trust_store_from_pem_file(path)?,
        None => sys::system_trust_store()?,
    };
    let now = sys::now_unix();
    let mut options = Options::new(&trust, purpose, at.unwrap_or(now));
    options.timestamps = stamps;
    options.allow_sha1 = allow_sha1;

    let mut all_ok = !sd.signers().is_empty();
    for (i, signer) in sd.signers().iter().enumerate() {
        println!("\nsigner {i}: digest {}, signature {}", name(signer.digest_algorithm()), name(signer.signature_algorithm()));
        if let Some(t) = signer.claimed_signing_time() {
            println!("  signingTime the signer wrote (not trusted): {}", when(t));
        }
        let result = if signature_only {
            sd.verify_signature(i, detached.as_deref(), &[]).map(|check| {
                if let Ok(cert) = Certificate::from_der(&check.certificate_der) {
                    println!("  certificate {} (issuer {})", cert.subject_summary(), cert.issuer_summary());
                }
                println!("  digest and signature are valid; nothing is said about who the signer is");
                check.weaknesses
            })
        } else {
            sd.verify_signer(i, detached.as_deref(), &options).map(|v| {
                println!("  chain to a trusted root, valid at {}{}:", when(v.chain_time), if v.timestamp.is_some() { " (the time stamp's time)" } else { "" });
                for der in &v.chain.path {
                    match Certificate::from_der(der) {
                        Ok(c) => println!("    {}", c.subject_summary()),
                        Err(_) => println!("    (unreadable)"),
                    }
                }
                if let Some(t) = &v.timestamp {
                    println!("  time stamp: {} by {}, policy {}", when(t.time), t.chain.leaf.subject_summary(), t.policy);
                }
                v.weaknesses
            })
        };
        match result {
            Ok(weak) => {
                for w in weak {
                    println!("  weak: {w:?} (SHA-1 is used by the signature or its time stamp; let through only because --allow-sha1 or --signature-only was given)");
                }
                println!("  verified");
            }
            Err(e) => {
                all_ok = false;
                let hint = if matches!(e, cms::Error::WeakDigest) { " (--allow-sha1 lets SHA-1 through)" } else { "" };
                println!("  NOT verified: {e}{hint}");
            }
        }
    }
    Ok(all_ok)
}
