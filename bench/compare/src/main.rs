//! pratique against ring, aws-lc-rs and RustCrypto (primitives), and against rustls (TLS 1.3 client on loopback),
//! each library through its own API, all timed by the same loop on the same machine (BENCHMARKS.md).
//!
//!   sh make_certs.sh                 once: a throwaway P-256 CA and `localhost` certificate for the TLS part (in certs/)
//!   cargo run --release -- prims     the primitives
//!   cargo run --release -- tls       TLS 1.3 handshakes and bulk download, every client against the same rustls server
//!   cargo run --release -- hs        the handshake rows alone
//!   cargo run --release -- prof [n]  n handshakes of pratique's client alone, for a profiler (B-104)
//!   cargo run --release              both
//!
//! The keys of `data/` were made with OpenSSL once and thrown away: only the public keys, the message and the signatures
//! are kept, and every library verifies the same bytes.

use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MSG: &[u8] = include_bytes!("../data/msg.bin");
const P256_PUB: &[u8] = include_bytes!("../data/p256.pub");
const P256_SIG: &[u8] = include_bytes!("../data/p256.sig");
const ED_PUB: &[u8] = include_bytes!("../data/ed.pub");
const ED_SIG: &[u8] = include_bytes!("../data/ed.sig");
const RSA_N: &[u8] = include_bytes!("../data/rsa_n.bin");
const RSA_PKCS1: &[u8] = include_bytes!("../data/rsa_pkcs1.der");
const RSA_SIG: &[u8] = include_bytes!("../data/rsa.sig");

/// A file of `certs/`, which `make_certs.sh` writes.
fn cert_file(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certs").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e} (run `sh make_certs.sh` first)", path.display()))
}

/// Seconds per call: a warm-up that also finds a batch of at least 50 ms, then the best of five such batches.
fn best_secs(mut f: impl FnMut()) -> f64 {
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        if t.elapsed() >= Duration::from_millis(50) {
            break;
        }
        n *= 2;
    }
    (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_secs_f64() / n as f64
        })
        .fold(f64::MAX, f64::min)
}

/// This thread's CPU time, in seconds.
fn thread_cpu() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
}

const LIBS: [&str; 4] = ["pratique", "ring", "aws-lc-rs", "RustCrypto"];

struct Table {
    rows: Vec<(String, String, [Option<f64>; 4])>,
}

impl Table {
    fn row(&mut self, name: &str, unit: &str, v: [Option<f64>; 4]) {
        let cells: Vec<String> = v.iter().map(|x| x.map_or("-".into(), |x| fmt(x))).collect();
        println!("{name:<44} {:>12} {:>12} {:>12} {:>12}  {unit}", cells[0], cells[1], cells[2], cells[3]);
        self.rows.push((name.into(), unit.into(), v));
    }
}

fn fmt(x: f64) -> String {
    if x >= 100.0 {
        format!("{x:.0}")
    } else if x >= 1.0 {
        format!("{x:.2}")
    } else {
        format!("{x:.4}")
    }
}

fn prims() {
    let mut t = Table { rows: Vec::new() };
    println!("{:<44} {:>12} {:>12} {:>12} {:>12}", "", LIBS[0], LIBS[1], LIBS[2], LIBS[3]);
    let nonce = [7u8; 12];

    // ---- AEAD seal, in place, MB/s
    for (alg, key_len) in [("AES-128-GCM", 16usize), ("AES-256-GCM", 32), ("ChaCha20-Poly1305", 32)] {
        let key = vec![0x42u8; key_len];
        for (size, label) in [(16_384usize, "16 KiB"), (1024, "1 KiB"), (100, "100 B")] {
            let mut buf = vec![0xa5u8; size + 16];
            let mbps = |secs: f64| Some(size as f64 / secs / 1e6);
            // pratique
            let ours = {
                use pratique::crypto::chacha20poly1305::ChaCha20Poly1305;
                use pratique::crypto::gcm::AesGcm;
                if alg == "ChaCha20-Poly1305" {
                    let c = ChaCha20Poly1305::new(&key);
                    best_secs(|| {
                        c.seal_in_place(&nonce, b"", &mut buf);
                        black_box(&buf);
                    })
                } else {
                    let c = AesGcm::new(&key);
                    best_secs(|| {
                        c.seal_in_place(&nonce, b"", &mut buf);
                        black_box(&buf);
                    })
                }
            };
            let ring = {
                use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
                let a = match alg {
                    "AES-128-GCM" => &AES_128_GCM,
                    "AES-256-GCM" => &AES_256_GCM,
                    _ => &CHACHA20_POLY1305,
                };
                let k = LessSafeKey::new(UnboundKey::new(a, &key).unwrap());
                best_secs(|| {
                    let _ = black_box(k.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf[..size]).unwrap());
                })
            };
            let awslc = {
                use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
                let a = match alg {
                    "AES-128-GCM" => &AES_128_GCM,
                    "AES-256-GCM" => &AES_256_GCM,
                    _ => &CHACHA20_POLY1305,
                };
                let k = LessSafeKey::new(UnboundKey::new(a, &key).unwrap());
                best_secs(|| {
                    let _ = black_box(k.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf[..size]).unwrap());
                })
            };
            let rc = {
                use aes_gcm::aead::{AeadInOut, KeyInit};
                match alg {
                    "AES-128-GCM" => {
                        let c = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
                        let n = aes_gcm::aead::Nonce::<aes_gcm::Aes128Gcm>::try_from(&nonce[..]).unwrap();
                        best_secs(|| {
                            black_box(c.encrypt_inout_detached(&n, b"", (&mut buf[..size]).into()).unwrap());
                        })
                    }
                    "AES-256-GCM" => {
                        let c = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
                        let n = aes_gcm::aead::Nonce::<aes_gcm::Aes256Gcm>::try_from(&nonce[..]).unwrap();
                        best_secs(|| {
                            black_box(c.encrypt_inout_detached(&n, b"", (&mut buf[..size]).into()).unwrap());
                        })
                    }
                    _ => {
                        use chacha20poly1305::aead::{AeadInOut, KeyInit};
                        let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
                        let n = chacha20poly1305::aead::Nonce::<chacha20poly1305::ChaCha20Poly1305>::try_from(&nonce[..]).unwrap();
                        best_secs(|| {
                            black_box(c.encrypt_inout_detached(&n, b"", (&mut buf[..size]).into()).unwrap());
                        })
                    }
                }
            };
            t.row(&format!("{alg} seal, {label}"), "MB/s", [mbps(ours), mbps(ring), mbps(awslc), mbps(rc)]);
        }
    }

    // ---- SHA-256, 1 MiB
    let data = vec![0x5au8; 1 << 20];
    let mb = |secs: f64| Some(data.len() as f64 / secs / 1e6);
    let ours = best_secs(|| {
        use pratique::crypto::sha2::{Hash, Sha256};
        black_box(Sha256::digest(&data));
    });
    let ring = best_secs(|| {
        black_box(ring::digest::digest(&ring::digest::SHA256, &data));
    });
    let awslc = best_secs(|| {
        black_box(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data));
    });
    let rc = best_secs(|| {
        use sha2::Digest;
        black_box(sha2::Sha256::digest(&data));
    });
    t.row("SHA-256, 1 MiB", "MB/s", [mb(ours), mb(ring), mb(awslc), mb(rc)]);

    // ---- signatures: parse the public key and verify (what a TLS client does with each certificate), microseconds
    let us = |secs: f64| Some(secs * 1e6);
    // ECDSA P-256 with SHA-256
    {
        use pratique::crypto::ecdsa::{self, Curve};
        use pratique::crypto::sha2::HashAlg;
        assert!(ecdsa::verify(Curve::P256, P256_PUB, HashAlg::Sha256, MSG, P256_SIG));
        let ours = best_secs(|| assert!(ecdsa::verify(Curve::P256, P256_PUB, HashAlg::Sha256, MSG, P256_SIG)));
        let ring = best_secs(|| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, P256_PUB).verify(MSG, P256_SIG).unwrap();
        });
        let awslc = best_secs(|| {
            aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1, P256_PUB).verify(MSG, P256_SIG).unwrap();
        });
        let rc = best_secs(|| {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(P256_PUB).unwrap();
            let sig = p256::ecdsa::Signature::from_der(P256_SIG).unwrap();
            vk.verify(MSG, &sig).unwrap();
        });
        t.row("ECDSA P-256 verify (with key parse)", "us", [us(ours), us(ring), us(awslc), us(rc)]);
    }
    // Ed25519
    {
        use pratique::crypto::ed25519;
        assert!(ed25519::verify(ED_PUB, MSG, ED_SIG));
        let ours = best_secs(|| assert!(ed25519::verify(ED_PUB, MSG, ED_SIG)));
        let ring = best_secs(|| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, ED_PUB).verify(MSG, ED_SIG).unwrap();
        });
        let awslc = best_secs(|| {
            aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, ED_PUB).verify(MSG, ED_SIG).unwrap();
        });
        let rc = best_secs(|| {
            use ed25519_dalek::Verifier;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(ED_PUB.try_into().unwrap()).unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(ED_SIG.try_into().unwrap());
            vk.verify(MSG, &sig).unwrap();
        });
        t.row("Ed25519 verify (with key parse)", "us", [us(ours), us(ring), us(awslc), us(rc)]);
    }
    // RSA-2048, PKCS#1 v1.5 with SHA-256
    {
        use pratique::crypto::rsa::RsaPublicKey;
        use pratique::crypto::sha2::HashAlg;
        assert!(RsaPublicKey::from_components(RSA_N, &[1, 0, 1]).unwrap().verify_pkcs1(HashAlg::Sha256, MSG, RSA_SIG));
        let ours = best_secs(|| assert!(RsaPublicKey::from_components(RSA_N, &[1, 0, 1]).unwrap().verify_pkcs1(HashAlg::Sha256, MSG, RSA_SIG)));
        let ring = best_secs(|| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1).verify(MSG, RSA_SIG).unwrap();
        });
        let awslc = best_secs(|| {
            aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1).verify(MSG, RSA_SIG).unwrap();
        });
        let rc = best_secs(|| {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::signature::Verifier;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(RSA_PKCS1).unwrap();
            let vk = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(RSA_SIG).unwrap();
            vk.verify(MSG, &sig).unwrap();
        });
        t.row("RSA-2048 verify (with key parse)", "us", [us(ours), us(ring), us(awslc), us(rc)]);
    }
    // ---- X25519: a key pair and a shared secret (two scalar multiplications), as a TLS client makes them
    {
        let peer = pratique::crypto::x25519::public_key(&[0x33u8; 32]);
        let mut k = [9u8; 32];
        let ours = best_secs(|| {
            k[0] = k[0].wrapping_add(1);
            black_box(pratique::crypto::x25519::public_key(&k));
            black_box(pratique::crypto::x25519::x25519(&k, &peer));
        });
        let rng = ring::rand::SystemRandom::new();
        let ring = best_secs(|| {
            use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
            let sk = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            black_box(sk.compute_public_key().unwrap());
            black_box(agree_ephemeral(sk, &UnparsedPublicKey::new(&X25519, &peer), |s| s[0]).unwrap());
        });
        let arng = aws_lc_rs::rand::SystemRandom::new();
        let awslc = best_secs(|| {
            use aws_lc_rs::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
            let sk = EphemeralPrivateKey::generate(&X25519, &arng).unwrap();
            black_box(sk.compute_public_key().unwrap());
            black_box(agree_ephemeral(sk, UnparsedPublicKey::new(&X25519, &peer), aws_lc_rs::error::Unspecified, |s| Ok(s[0])).unwrap());
        });
        let mut kd = [9u8; 32];
        let rc = best_secs(|| {
            kd[0] = kd[0].wrapping_add(1);
            let s = x25519_dalek::StaticSecret::from(kd);
            black_box(x25519_dalek::PublicKey::from(&s));
            black_box(s.diffie_hellman(&x25519_dalek::PublicKey::from(peer)));
        });
        t.row("X25519 key pair + shared secret", "us", [us(ours), us(ring), us(awslc), us(rc)]);
    }
    println!("(ring and aws-lc-rs draw a random key for X25519, the others take one; RustCrypto is aes-gcm, chacha20poly1305, sha2, p256, ed25519-dalek, rsa, x25519-dalek)");
}

// ---------------------------------------------------------------- TLS

#[derive(Clone, Copy)]
enum Service {
    /// Writes one byte after the handshake, then waits for the client to go.
    Handshake,
    /// Reads an 8-byte count, then writes that many bytes in 16 KiB writes.
    Source,
}

fn server_config(suite: rustls::SupportedCipherSuite) -> Arc<rustls::ServerConfig> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider.cipher_suites = vec![suite];
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_file("chain.pem")).map(|c| c.unwrap()).collect();
    let key = PrivateKeyDer::from_pem_slice(&cert_file("leaf.key")).unwrap();
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    c.send_tls13_tickets = 0;
    Arc::new(c)
}

fn serve(config: Arc<rustls::ServerConfig>, service: Service) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { continue };
            socket.set_nodelay(true).ok();
            let config = config.clone();
            thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut s = rustls::StreamOwned::new(conn, socket);
                match service {
                    Service::Handshake => {
                        if s.write_all(b"k").and_then(|_| s.flush()).is_ok() {
                            let _ = s.read(&mut [0u8; 16]);
                        }
                    }
                    Service::Source => {
                        let mut n = [0u8; 8];
                        if s.read_exact(&mut n).is_ok() {
                            let mut left = u64::from_be_bytes(n) as usize;
                            let chunk = vec![0xa5u8; 16_384];
                            while left > 0 {
                                let k = left.min(chunk.len());
                                if s.write_all(&chunk[..k]).is_err() {
                                    return;
                                }
                                left -= k;
                            }
                            let _ = s.flush();
                            let _ = s.read(&mut [0u8; 16]);
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A client: connects, completes the handshake, and returns something to read from and write to.
trait Client {
    fn connect(&self, addr: SocketAddr) -> Box<dyn ReadWrite>;
}
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct Ours(pratique::tls::ClientConfig);
impl Client for Ours {
    fn connect(&self, addr: SocketAddr) -> Box<dyn ReadWrite> {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_nodelay(true).ok();
        Box::new(pratique::tls::TlsStream::connect(tcp, "localhost", &self.0).unwrap())
    }
}

struct Rustls(Arc<rustls::ClientConfig>);
impl Client for Rustls {
    fn connect(&self, addr: SocketAddr) -> Box<dyn ReadWrite> {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_nodelay(true).ok();
        let conn = rustls::ClientConnection::new(self.0.clone(), "localhost".try_into().unwrap()).unwrap();
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).unwrap();
        }
        Box::new(s)
    }
}

fn rustls_client(provider: rustls::crypto::CryptoProvider) -> Rustls {
    let mut roots = rustls::RootCertStore::empty();
    use rustls_pki_types::pem::PemObject;
    for c in rustls_pki_types::CertificateDer::pem_slice_iter(&cert_file("ca.pem")) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.resumption = rustls::client::Resumption::disabled();
    Rustls(Arc::new(c))
}

fn tls() {
    tls_parts(true);
}

/// The handshake rows alone (`hs`), or with the downloads too.
fn tls_parts(downloads: bool) {
    let ours = {
        let mut store = pratique::x509::TrustStore::empty();
        assert!(store.add_pem(&String::from_utf8(cert_file("ca.pem")).unwrap()) > 0);
        Ours(pratique::tls::ClientConfig::new(store).with_resumption(pratique::tls::Resumption::off()))
    };
    let mut aws = rustls::crypto::aws_lc_rs::default_provider();
    aws.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut ring = rustls::crypto::ring::default_provider();
    ring.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let clients: [(&str, Box<dyn Client>); 3] =
        [("pratique", Box::new(ours)), ("rustls + ring", Box::new(rustls_client(ring))), ("rustls + aws-lc-rs", Box::new(rustls_client(aws)))];
    println!("(every client against the same rustls + aws-lc-rs TLS 1.3 server on loopback: ECDSA P-256 chain of two, X25519 only, no resumption)");
    println!("{:<44} {:>14} {:>16} {:>20}", "", clients[0].0, clients[1].0, clients[2].0);

    // ---- full handshakes: connect + handshake as the client sees it, and the client thread's CPU time
    let addr = serve(server_config(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256), Service::Handshake);
    let mut wall = Vec::new();
    let mut cpu = Vec::new();
    for (_, c) in &clients {
        let (mut w, mut u) = (Vec::new(), Vec::new());
        for i in 0..410 {
            let (t, c0) = (Instant::now(), thread_cpu());
            let mut s = c.connect(addr);
            let (dt, dc) = (t.elapsed().as_secs_f64(), thread_cpu() - c0);
            let mut k = [0u8; 1];
            s.read_exact(&mut k).unwrap();
            if i >= 10 {
                w.push(dt * 1e3);
                u.push(dc * 1e3);
            }
        }
        w.sort_by(f64::total_cmp);
        u.sort_by(f64::total_cmp);
        wall.push(w[w.len() / 2]);
        cpu.push(u[u.len() / 2]);
    }
    println!("{:<44} {:>14.3} {:>16.3} {:>20.3}  ms", "full handshake, median wall time", wall[0], wall[1], wall[2]);
    println!("{:<44} {:>14.3} {:>16.3} {:>20.3}  ms", "full handshake, median client CPU", cpu[0], cpu[1], cpu[2]);

    if !downloads {
        return;
    }
    // ---- bulk download, 256 MiB, best of three after a warm-up: throughput and the client's CPU per byte
    let bytes = 256usize << 20;
    for (name, suite) in [
        ("AES-128-GCM", rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256),
        ("AES-256-GCM", rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384),
        ("ChaCha20-Poly1305", rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
    ] {
        let addr = serve(server_config(suite), Service::Source);
        let mut tput = Vec::new();
        let mut per_core = Vec::new();
        for (_, c) in &clients {
            let run = || {
                let mut s = c.connect(addr);
                let (t, c0) = (Instant::now(), thread_cpu());
                s.write_all(&(bytes as u64).to_be_bytes()).unwrap();
                s.flush().unwrap();
                let mut buf = vec![0u8; 1 << 16];
                let mut got = 0usize;
                while got < bytes {
                    match s.read(&mut buf) {
                        Ok(0) => panic!("the server stopped at {got} of {bytes}"),
                        Ok(k) => got += k,
                        Err(e) => panic!("{e}"),
                    }
                }
                (t.elapsed().as_secs_f64(), thread_cpu() - c0)
            };
            let _ = run();
            let runs: Vec<(f64, f64)> = (0..3).map(|_| run()).collect();
            let best = runs.iter().map(|r| r.0).fold(f64::MAX, f64::min);
            let best_cpu = runs.iter().map(|r| r.1).fold(f64::MAX, f64::min);
            tput.push(bytes as f64 / best / 1e6);
            per_core.push(bytes as f64 / best_cpu / 1e6);
        }
        println!("{:<44} {:>14.0} {:>16.0} {:>20.0}  MB/s", format!("download, {name}"), tput[0], tput[1], tput[2]);
        println!("{:<44} {:>14.0} {:>16.0} {:>20.0}  MB per client CPU second", format!("download, {name}: client cost"), per_core[0], per_core[1], per_core[2]);
    }
}

/// `prof [n]`: n full handshakes of this crate's client and nothing else (and the server's, in a thread), for a profiler.
fn prof(n: usize) {
    let mut store = pratique::x509::TrustStore::empty();
    assert!(store.add_pem(&String::from_utf8(cert_file("ca.pem")).unwrap()) > 0);
    let ours = Ours(pratique::tls::ClientConfig::new(store).with_resumption(pratique::tls::Resumption::off()));
    let addr = serve(server_config(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256), Service::Handshake);
    for _ in 0..n {
        let mut s = ours.connect(addr);
        let mut k = [0u8; 1];
        s.read_exact(&mut k).unwrap();
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("prims") => prims(),
        Some("tls") => tls(),
        Some("hs") => tls_parts(false),
        Some("prof") => prof(std::env::args().nth(2).and_then(|n| n.parse().ok()).unwrap_or(200)),
        _ => {
            prims();
            println!();
            tls();
        }
    }
}
