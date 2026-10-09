//! Throughput and cost of the primitives, single thread, release build (BACKLOG B-54; the network side is
//! `examples/bench_net.rs`).
//!
//! ```text
//! cargo run --release --example bench -- [--tsv FILE] [--label NAME]
//! ```
//!
//! Every figure is the best of several runs, after one that only warms up (page faults, caches, the CPU's clock), so that
//! one interrupted run does not decide it; on a shared or virtual machine the run-to-run spread is still 10 to 30 percent.
//! `--tsv FILE` appends one line per figure (label, date, figure, value, unit), which `tools/bench.sh` keeps in
//! `bench/results.tsv` and compares with the machine's last run.

use pratique::crypto::chacha20poly1305::ChaCha20Poly1305;
use pratique::crypto::ecdsa::{self, Curve};
use pratique::crypto::gcm::AesGcm;
use pratique::crypto::rsa::RsaPublicKey;
use pratique::crypto::sha2::{Hash, HashAlg, Sha256, Sha384};
use pratique::crypto::{ecdh, ed25519, x25519};
use pratique::pem;
use pratique::x509::{Certificate, TrustStore};

#[path = "common/report.rs"]
mod report;
use report::{best_secs, Report};

fn mbps(bytes: usize, secs: f64) -> f64 {
    bytes as f64 / 1e6 / secs
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// An ECDSA signature in DER from r and s in hex.
fn der_sig(r: &str, s: &str) -> Vec<u8> {
    let int = |b: Vec<u8>| {
        let mut v: Vec<u8> = b.into_iter().skip_while(|&x| x == 0).collect();
        if v.first().is_none_or(|&x| x & 0x80 != 0) {
            v.insert(0, 0);
        }
        let mut o = vec![2, v.len() as u8];
        o.extend(v);
        o
    };
    let mut body = int(hex(r));
    body.extend(int(hex(s)));
    let mut o = vec![0x30, body.len() as u8];
    o.extend(body);
    o
}

fn main() {
    let mut r = Report::from_args();
    let data = vec![0xa5u8; 1 << 20];
    let nonce = [7u8; 12];

    println!("AES backend         {}", if pratique::crypto::aes::hardware_accelerated() { "hardware (AES instructions + carry-less multiply)" } else { "portable (bitsliced, constant time)" });

    // ---- the record ciphers: bulk (1 MiB a call), a TLS record (16 KiB), and small messages (1 KB, 100 B), sealed in place
    let g128 = AesGcm::new(&[1u8; 16]);
    let g256 = AesGcm::new(&[1u8; 32]);
    let cc = ChaCha20Poly1305::new(&[2u8; 32]);
    type Seal<'a> = Box<dyn Fn(&mut [u8]) + 'a>;
    let aeads: [(&str, Seal); 3] = [
        ("AES-128-GCM", Box::new(|b: &mut [u8]| g128.seal_in_place(&nonce, b"", b))),
        ("AES-256-GCM", Box::new(|b: &mut [u8]| g256.seal_in_place(&nonce, b"", b))),
        ("ChaCha20-Poly1305", Box::new(|b: &mut [u8]| cc.seal_in_place(&nonce, b"", b))),
    ];
    for (name, seal) in &aeads {
        for (size, what) in [(1 << 20, "1 MiB"), (16_384, "16 KiB"), (1000, "1 KB"), (100, "100 B")] {
            let mut buf = vec![0xa5u8; size + 16];
            let secs = best_secs(|| {
                seal(&mut buf);
                std::hint::black_box(&buf);
            });
            r.row(&format!("{name} seal, {what} messages"), mbps(size, secs), "MB/s");
        }
    }
    // the block cipher alone (CTR), to tell its cost from GHASH's in the GCM rows
    let ctr = pratique::crypto::aes::Aes::new(&[1u8; 16]);
    let mut buf = data.clone();
    let secs = best_secs(|| {
        ctr.ctr_xor(&nonce, 2, &mut buf);
        std::hint::black_box(&buf);
    });
    r.row("AES-128-CTR, 1 MiB", mbps(data.len(), secs), "MB/s");
    let secs = best_secs(|| {
        std::hint::black_box(Sha256::digest(&data));
    });
    r.row("SHA-256, 1 MiB", mbps(data.len(), secs), "MB/s");

    // ---- key exchange and signatures
    let mut k = [9u8; 32];
    let secs = best_secs(|| {
        k[0] = k[0].wrapping_add(1);
        std::hint::black_box(x25519::public_key(&k));
    });
    r.row("X25519 (one scalar multiplication)", secs * 1e3, "ms");
    let peer = x25519::public_key(&[0x33u8; 32]);
    let secs = best_secs(|| {
        k[0] = k[0].wrapping_add(1);
        std::hint::black_box(x25519::x25519(&k, &peer));
    });
    r.row("X25519 (shared secret, the ladder)", secs * 1e3, "ms");
    for (curve, name) in [(Curve::P256, "P-256"), (Curve::P384, "P-384")] {
        let (_, peer) = ecdh::generate(curve).expect("a key pair");
        let (k, _) = ecdh::generate(curve).expect("a key pair");
        let secs = best_secs(|| {
            std::hint::black_box(ecdh::shared_secret(curve, &k, &peer));
        });
        r.row(&format!("ECDH {name} (shared secret)"), secs * 1e3, "ms");
    }
    // RFC 6979 A.2.5 and A.2.6 (message "sample")
    let p256_pub = hex("0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    let p256_sig = der_sig("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    let d256 = Sha256::digest(b"sample");
    assert!(ecdsa::verify_prehashed(Curve::P256, &p256_pub, &d256, &p256_sig), "the P-256 vector verifies");
    let secs = best_secs(|| assert!(ecdsa::verify_prehashed(Curve::P256, &p256_pub, &d256, &p256_sig)));
    r.row("ECDSA P-256 verification", secs * 1e3, "ms");
    let p384_pub = hex("04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720");
    let p384_sig = der_sig("94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46", "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8");
    let d384 = Sha384::digest(b"sample");
    assert!(ecdsa::verify_prehashed(Curve::P384, &p384_pub, &d384, &p384_sig), "the P-384 vector verifies");
    let secs = best_secs(|| assert!(ecdsa::verify_prehashed(Curve::P384, &p384_pub, &d384, &p384_sig)));
    r.row("ECDSA P-384 verification", secs * 1e3, "ms");
    // RFC 8032 section 7.1, test 1
    let ed_pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let ed_sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    assert!(ed25519::verify(&ed_pub, b"", &ed_sig), "the Ed25519 vector verifies");
    let secs = best_secs(|| assert!(ed25519::verify(&ed_pub, b"", &ed_sig)));
    r.row("Ed25519 verification", secs * 1e3, "ms");
    // signing (B-109): what a server spends on its CertificateVerify
    for (curve, name) in [(Curve::P256, "P-256"), (Curve::P384, "P-384")] {
        let key = pratique::sign::EcdsaSigningKey::generate(curve).expect("a key");
        let alg = pratique::crypto::ecdsa_sign::default_hash(curve);
        let secs = best_secs(|| {
            std::hint::black_box(key.sign(alg, b"a handshake's signed content").expect("a signature"));
        });
        r.row(&format!("ECDSA {name} signing"), secs * 1e3, "ms");
    }
    let ed = pratique::sign::Ed25519SigningKey::from_seed(&[7u8; 32]);
    let secs = best_secs(|| {
        std::hint::black_box(ed.sign(b"a handshake's signed content"));
    });
    r.row("Ed25519 signing", secs * 1e3, "ms");
    for line in include_str!("../tests/data/rsa_signing_keys.txt").lines().filter(|l| !l.starts_with('#') && !l.starts_with("1024 ")) {
        let mut f = line.split(' ');
        let bits = f.next().unwrap();
        let key = pratique::sign::RsaSigningKey::from_pkcs1_der(&hex(f.next().unwrap())).expect("a test key");
        let secs = best_secs(|| {
            std::hint::black_box(key.sign_pss(pratique::crypto::sha2::HashAlg::Sha256, b"a handshake's signed content").expect("a signature"));
        });
        r.row(&format!("RSA-{bits} signing (PSS)"), secs * 1e3, "ms");
    }
    for bits in [2048usize, 4096] {
        // an odd modulus of the size and a "signature" below it: the exponentiation is the work of a real verification
        let mut n = vec![0xc3u8; bits / 8];
        n[0] = 0xd5;
        *n.last_mut().unwrap() = 0x6b;
        let mut sig = vec![0x5au8; bits / 8];
        sig[0] = 0x12;
        let secs = best_secs(|| {
            std::hint::black_box(RsaPublicKey::from_components(&n, &[1, 0, 1]).unwrap());
        });
        r.row(&format!("RSA-{bits}: the key's set-up"), secs * 1e3, "ms");
        let key = RsaPublicKey::from_components(&n, &[1, 0, 1]).unwrap();
        let secs = best_secs(|| {
            std::hint::black_box(key.verify_pkcs1(HashAlg::Sha256, b"m", &sig));
        });
        r.row(&format!("RSA-{bits} verification (e = 65537)"), secs * 1e3, "ms");
    }

    // ---- certificates: parse + signature checks + name checks, on the test fixtures
    let der = |t: &str| pem::parse(t).remove(0).data;
    let root_rsa = der(include_str!("../tests/data/root_rsa.pem"));
    let inter = der(include_str!("../tests/data/inter_p256.pem"));
    let leaf = der(include_str!("../tests/data/leaf_p384.pem"));
    let mut store = TrustStore::empty();
    store.add_der(&root_rsa).unwrap();
    let chain = vec![leaf.clone(), inter];
    let now = 1_789_430_400;
    let secs = best_secs(|| {
        std::hint::black_box(store.verify_server_chain(&chain, "example.test", now).unwrap());
    });
    r.row("chain check (1 RSA-2048 + 1 ECDSA P-256 verify + 3 cert parses)", secs * 1e3, "ms");
    let secs = best_secs(|| {
        std::hint::black_box(Certificate::from_der(&leaf).unwrap());
    });
    r.row("parse one certificate (P-384 key)", secs * 1e3, "ms");
    let secs = best_secs(|| {
        let mut s2 = TrustStore::empty();
        s2.add_der(&root_rsa).unwrap();
        std::hint::black_box(s2);
    });
    r.row("parse one RSA-2048 root into a trust store", secs * 1e3, "ms");
    if let Some(text) = ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"].iter().find_map(|p| std::fs::read_to_string(p).ok()) {
        let mut added = 0;
        let secs = best_secs(|| {
            let mut big = TrustStore::empty();
            added = big.add_pem(&text);
            std::hint::black_box(big);
        });
        println!("(the system CA bundle has {added} roots)");
        r.row("load the system CA bundle", secs * 1e3, "ms");
    }
}
