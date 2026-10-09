//! Deterministic mutation fuzzing of everything that parses bytes a peer controls.
//!
//! This is not a coverage-guided fuzzer (that would need a third-party engine; see backlog B-12).
//! It takes valid seeds, damages them in many structured ways, and checks that no parser or
//! verifier ever panics, and that tampered certificate chains are never accepted. Runs are
//! reproducible: every iteration derives its input from `(test name, iteration)`, and a failure
//! prints the iteration so it can be replayed. Set `PRATIQUE_FUZZ_SCALE=10` for a longer run.

use crate::crypto::{ecdsa, ed25519, rsa::RsaPublicKey, sha2::HashAlg, test_vectors as tv};
#[cfg(feature = "net")]
use crate::http::url::Url;
#[cfg(feature = "net")]
use crate::http::wire::{self, Limits};
use crate::util::unhex;
use crate::x509::{Certificate, TrustStore};
use crate::{asn1, pem};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

/// xorshift64* generator.
pub(crate) struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Picks one of `seeds` and damages it.
pub(crate) fn mutate_seed<T: AsRef<[u8]>>(rng: &mut Rng, seeds: &[T]) -> Vec<u8> {
    let i = rng.below(seeds.len());
    mutate(rng, seeds[i].as_ref())
}

/// `n` random bytes where `n` is below `max`.
pub(crate) fn random_up_to(rng: &mut Rng, max: usize) -> Vec<u8> {
    let n = rng.below(max);
    rng.bytes(n)
}

const INTERESTING: [u8; 9] = [0x00, 0x01, 0x02, 0x30, 0x7f, 0x80, 0x81, 0xfe, 0xff];

/// Damages `data` in one to four structured ways.
pub(crate) fn mutate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    for _ in 0..1 + rng.below(4) {
        let len = v.len();
        match rng.below(10) {
            0 if len > 0 => {
                let i = rng.below(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = *rng.pick(&INTERESTING);
            }
            2 => v.truncate(rng.below(len + 1)),
            3 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(8)).min(len);
                v.drain(a..b);
            }
            4 => {
                let at = rng.below(len + 1);
                let n = 1 + rng.below(8);
                let extra = rng.bytes(n);
                v.splice(at..at, extra);
            }
            5 if len > 1 => {
                let a = rng.below(len - 1);
                let b = (a + 1 + rng.below(32)).min(len);
                let chunk = v[a..b].to_vec();
                let at = rng.below(len + 1);
                v.splice(at..at, chunk);
            }
            6 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(8)).min(len);
                let r = rng.bytes(b - a);
                v[a..b].copy_from_slice(&r);
            }
            7 if len > 2 => {
                // a length field that claims far more than is there
                let i = rng.below(len - 1);
                v[i] = 0xff;
                v[i + 1] = 0xff;
            }
            8 if len > 0 => {
                let i = rng.below(len);
                v[i] = v[i].wrapping_add(1);
            }
            _ => {
                let n = 1 + rng.below(16);
                let extra = rng.bytes(n);
                v.extend_from_slice(&extra);
            }
        }
    }
    v
}

/// Runs `f` for `iters` deterministic iterations (times `PRATIQUE_FUZZ_SCALE`), reporting the
/// iteration if it panics so the failure can be replayed.
pub(crate) fn run(name: &str, iters: u64, f: impl Fn(&mut Rng)) {
    let scale: u64 = std::env::var("PRATIQUE_FUZZ_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let name_hash = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
    for i in 0..iters * scale {
        let mut rng = Rng::new(name_hash ^ i);
        if let Err(p) = catch_unwind(AssertUnwindSafe(|| f(&mut rng))) {
            eprintln!("fuzz target '{}' panicked on iteration {} (seed {:#x})", name, i, name_hash ^ i);
            resume_unwind(p);
        }
    }
}

macro_rules! fixture_pem {
    ($name:literal) => {
        include_str!(concat!("../tests/data/", $name, ".pem"))
    };
}

pub(crate) fn fixture_ders() -> Vec<Vec<u8>> {
    [
        fixture_pem!("root_rsa"),
        fixture_pem!("root_p384"),
        fixture_pem!("inter_p256"),
        fixture_pem!("inter2_p256"),
        fixture_pem!("inter_nc"),
        fixture_pem!("leaf_p384"),
        fixture_pem!("leaf_rsa"),
        fixture_pem!("leaf_expired"),
        fixture_pem!("leaf_nc_ok"),
        fixture_pem!("ks_leaf_rsa1024"),
        fixture_pem!("ks_root_rsa1024"),
    ]
    .iter()
    .map(|p| pem::parse(p).remove(0).data)
    .collect()
}

fn der_of(p: &str) -> Vec<u8> {
    pem::parse(p).remove(0).data
}

#[test]
fn certificate_parser_never_panics() {
    let seeds = fixture_ders();
    run("certificate_parser", 6000, |rng| {
        let der = if rng.chance(10) { random_up_to(rng, 400) } else { mutate_seed(rng, &seeds) };
        if let Ok(c) = Certificate::from_der(&der) {
            let _ = c.matches_hostname("example.test");
            let _ = c.matches_hostname("127.0.0.1");
            let _ = c.subject_summary();
            let _ = c.issuer_summary();
            let _ = c.verify_signed_by(&c);
        }
    });
}

#[test]
fn tampered_chains_are_never_accepted_and_never_panic() {
    let root = der_of(fixture_pem!("root_rsa"));
    let inter = der_of(fixture_pem!("inter_p256"));
    let leaf = der_of(fixture_pem!("leaf_p384"));
    let mut ts = TrustStore::empty();
    ts.add_der(&root).unwrap();
    const NOW: i64 = 1_789_430_400;
    // control
    ts.verify_server_chain(&[leaf.clone(), inter.clone()], "example.test", NOW).unwrap();
    run("tampered_chains", 3000, |rng| {
        let mut l = leaf.clone();
        let mut i = inter.clone();
        match rng.below(3) {
            0 => l = mutate(rng, &l),
            1 => i = mutate(rng, &i),
            _ => {
                l = mutate(rng, &l);
                i = mutate(rng, &i);
            }
        }
        let tampered = l != leaf || i != inter;
        let res = ts.verify_server_chain(&[l, i], "example.test", NOW);
        if tampered {
            assert!(res.is_err(), "a modified certificate chain was accepted");
        }
    });
    // and with a random-length, random-content extra chain
    run("random_chains", 500, |rng| {
        let n = rng.below(5);
        let chain: Vec<Vec<u8>> = (0..n).map(|_| random_up_to(rng, 300)).collect();
        assert!(ts.verify_server_chain(&chain, "example.test", NOW).is_err());
    });
}

#[test]
fn pem_and_base64_never_panic() {
    let seeds = [fixture_pem!("root_rsa"), fixture_pem!("leaf_p384"), fixture_pem!("inter_nc")];
    run("pem", 4000, |rng| {
        let text = String::from_utf8_lossy(&mutate_seed(rng, &seeds.iter().map(|s| s.as_bytes()).collect::<Vec<_>>())).into_owned();
        let blocks = pem::parse(&text);
        for b in &blocks {
            let _ = Certificate::from_der(&b.data);
        }
        let _ = pem::base64_decode(&text);
        let mut ts = TrustStore::empty();
        let _ = ts.add_pem(&text);
        let _ = ts.verify_server_chain(&[rng.bytes(50)], "x.test", 0);
    });
}

#[test]
fn asn1_reader_never_panics() {
    let seeds = fixture_ders();
    run("asn1", 6000, |rng| {
        let data = if rng.chance(30) { random_up_to(rng, 200) } else { mutate_seed(rng, &seeds) };
        // walk the structure generically: descend into anything that decodes
        fn walk(d: &[u8], depth: usize) {
            let mut r = asn1::Der::new(d);
            while !r.is_empty() {
                let Ok(t) = r.next() else { return };
                let _ = asn1::unsigned_integer(&t);
                let _ = asn1::bit_string_bytes(&t);
                let _ = asn1::parse_time(&t);
                if depth < 6 && (t.tag & 0x20 != 0 || t.tag == asn1::TAG_OCTET_STRING || t.tag == asn1::TAG_BIT_STRING) {
                    walk(t.content, depth + 1);
                }
            }
        }
        walk(&data, 0);
    });
}

#[test]
fn rsa_verification_never_panics() {
    let key_der = unhex(tv::RSA_PUBKEY_DER);
    let sigs = [unhex(tv::RSA_PKCS1_SHA256_SIG), unhex(tv::RSA_PSS_SHA256_SIG), unhex(tv::RSA_PKCS1_SHA512_SIG)];
    // the genuine key must still verify, so the harness is exercising real paths
    let genuine = RsaPublicKey::from_pkcs1_der(&key_der).unwrap();
    assert!(genuine.verify_pkcs1(HashAlg::Sha256, tv::RSA_MSG, &sigs[0]));
    run("rsa_mutated_key_and_sig", 3000, |rng| {
        let kd = if rng.chance(50) { key_der.clone() } else { mutate(rng, &key_der) };
        let sig = if rng.chance(70) { mutate_seed(rng, &sigs) } else { random_up_to(rng, 600) };
        if let Ok(k) = RsaPublicKey::from_pkcs1_der(&kd) {
            for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                let _ = k.verify_pkcs1(alg, tv::RSA_MSG, &sig);
                let _ = k.verify_pss(alg, tv::RSA_MSG, &sig);
            }
        }
    });
    // arbitrary moduli (odd, 1024..4096 bits, awkward top bytes) and exponents
    run("rsa_random_moduli", 600, |rng| {
        let len = 128 + rng.below(385);
        let mut n = rng.bytes(len);
        if rng.chance(30) {
            n.iter_mut().for_each(|b| *b = 0xff);
        }
        n[0] |= 0x80 >> rng.below(8);
        *n.last_mut().unwrap() |= 1;
        let e_len = 1 + rng.below(9);
        let e = if rng.chance(50) { vec![1, 0, 1] } else { rng.bytes(e_len) };
        if let Ok(k) = RsaPublicKey::from_components(&n, &e) {
            for siglen in [len, len - 1, len + 1, rng.below(600)] {
                let mut sig = rng.bytes(siglen);
                if rng.chance(30) {
                    sig.iter_mut().for_each(|b| *b = 0xff);
                }
                let _ = k.verify_pkcs1(HashAlg::Sha256, b"m", &sig);
                let _ = k.verify_pss(HashAlg::Sha256, b"m", &sig);
            }
        }
    });
}

#[test]
fn ecdsa_verification_never_panics() {
    let p256 = unhex(tv::P256_PUBKEY);
    let p384 = unhex(tv::P384_PUBKEY);
    let sigs = [unhex(tv::P256_SHA256_SIG), unhex(tv::P384_SHA384_SIG)];
    assert!(ecdsa::verify(ecdsa::Curve::P256, &p256, HashAlg::Sha256, tv::EC_MSG, &sigs[0]));
    run("ecdsa", 3000, |rng| {
        let (curve, key) = if rng.chance(50) { (ecdsa::Curve::P256, &p256) } else { (ecdsa::Curve::P384, &p384) };
        let mut k = if rng.chance(50) { key.clone() } else { mutate(rng, key) };
        if rng.chance(10) && k.len() > 1 {
            // coordinates that are not reduced mod p
            let n = k.len();
            k[1..n].iter_mut().for_each(|b| *b = 0xff);
        }
        let sig = if rng.chance(70) { mutate_seed(rng, &sigs) } else { random_up_to(rng, 150) };
        let digest = random_up_to(rng, 100);
        let _ = ecdsa::verify_prehashed(curve, &k, &digest, &sig);
        let _ = ecdsa::verify(curve, &k, HashAlg::Sha384, tv::EC_MSG, &sig);
    });
}

#[test]
fn ed25519_verification_never_panics_and_accepts_only_the_genuine_signature() {
    // RFC 8032 section 7.1, TEST 2
    let pk = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let msg = unhex("72");
    let sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    assert!(ed25519::verify(&pk, &msg, &sig));
    run("ed25519", 2000, |rng| {
        let k = if rng.chance(40) { pk.clone() } else { mutate(rng, &pk) };
        let m = if rng.chance(40) { msg.clone() } else { mutate(rng, &msg) };
        let s = if rng.chance(40) { sig.clone() } else { mutate(rng, &sig) };
        let ok = ed25519::verify(&k, &m, &s);
        // Anything else would be a forgery: the key is not small-order, R is compared as bytes and S is
        // canonical, so only the original triple verifies
        assert_eq!(ok, k == pk && m == msg && s == sig, "key {:x?} message {:x?} signature {:x?}", k, m, s);
        // keys and signatures that are not even the right shape, and extreme ones
        let _ = ed25519::verify(&random_up_to(rng, 40), &random_up_to(rng, 100), &random_up_to(rng, 80));
        let mut extreme_key = [0xffu8; 32];
        extreme_key[rng.below(32)] = rng.next_u64() as u8;
        let mut extreme_sig = [0xffu8; 64];
        extreme_sig[rng.below(64)] = rng.next_u64() as u8;
        let _ = ed25519::verify(&extreme_key, &m, &sig);
        let _ = ed25519::verify(&pk, &m, &extreme_sig);
        let _ = ed25519::verify(&extreme_key, &m, &extreme_sig);
    });
}

#[test]
fn signed_notes_never_panic_and_only_genuine_signatures_verify() {
    use crate::note::{self, Verifier};
    const LATEST: &[u8] = include_bytes!("../tests/data/sumdb/latest.txt");
    const LOOKUP: &[u8] = include_bytes!("../tests/data/sumdb/lookup.txt");
    let real = crate::sumdb::verifier();
    let at = LOOKUP.windows(2).position(|w| w == b"\n\n").unwrap() + 2;
    let seeds = [LATEST, &LOOKUP[at..]];
    let genuine: Vec<(String, String)> = seeds
        .iter()
        .map(|b| {
            let n = note::open(b, std::slice::from_ref(&real)).unwrap();
            (n.text.clone(), format!("{} {}", n.signatures[0].name, n.signatures[0].base64))
        })
        .collect();
    let other = Verifier::ed25519("other.example", &[9; 32]).unwrap();
    let known = [real.clone(), other];
    run("note", 6000, |rng| {
        let data = if rng.chance(5) { random_up_to(rng, 300) } else { mutate_seed(rng, &seeds) };
        if let Ok(n) = note::open(&data, &known) {
            for sig in &n.signatures {
                let line = format!("{} {}", sig.name, sig.base64);
                assert!(genuine.iter().any(|(t, l)| *t == n.text && *l == line), "a signature that was never made verified: {:?}", data);
            }
        }
        let _ = Verifier::from_key(&String::from_utf8_lossy(&mutate(rng, crate::sumdb::KEY.as_bytes())));
    });
}

#[test]
fn transparency_log_parsers_and_proof_checks_never_panic() {
    use crate::sumdb::{self, Check};
    use crate::tlog::{self, Tile, TileSet};
    const LOOKUP: &[u8] = include_bytes!("../tests/data/sumdb/lookup.txt");
    let seeds: [&[u8]; 4] = [
        LOOKUP,
        b"go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n",
        b"7\nline one\nline two\n\ngo.sum database tree\n",
        b"tile/8/1/x001/018.p/122",
    ];
    run("sumdb", 6000, |rng| {
        let data = if rng.chance(5) { random_up_to(rng, 200) } else { mutate_seed(rng, &seeds) };
        let text = String::from_utf8_lossy(&data).into_owned();
        let _ = sumdb::parse_tree(&text);
        let _ = sumdb::parse_record(&data);
        let _ = sumdb::lookup_path(&text, "v1.0.0");
        let _ = sumdb::lookup_path("golang.org/x/mod", &text);
        if let Ok(t) = Tile::parse_path(&text) {
            assert_eq!(t.path(), text);
        }
        let mut check = Check::new(sumdb::verifier());
        let _ = check.add_head(&data);
        let _ = check.add_lookup("golang.org/x/mod", "v0.17.0", &data);
        let _ = check.tiles_needed();
        let _ = check.finish(&TileSet::new());
    });
    run("tlog_proofs", 6000, |rng| {
        let h = |rng: &mut Rng| -> tlog::Hash { rng.bytes(32).try_into().unwrap() };
        let proof: Vec<tlog::Hash> = (0..rng.below(70)).map(|_| h(rng)).collect();
        let size = if rng.chance(30) { rng.next_u64() } else { rng.next_u64() >> rng.below(64) };
        let index = if rng.chance(50) { rng.next_u64() % size.max(1) } else { rng.next_u64() >> rng.below(64) };
        let (root, leaf) = (h(rng), h(rng));
        let _ = tlog::verify_inclusion(&proof, size, &root, index, &leaf);
        let old = if rng.chance(50) { rng.next_u64() % size.max(1) + 1 } else { rng.next_u64() >> rng.below(64) };
        let _ = tlog::verify_consistency(&proof, old, &root, size, &leaf);
        let tree = tlog::Tree { size: size >> rng.below(10), root };
        let height = rng.below(33) as u32;
        let _ = tlog::tiles_for_record(&tree, height, index);
        let _ = tlog::tiles_for_prefix(&tree, height, old);
        let _ = tlog::check_record(&tree, height, index, &leaf, &TileSet::new());
        let _ = tlog::check_prefix(&tlog::Tree { size: old, root: leaf }, &tree, height, &TileSet::new());
    });
}

#[cfg(feature = "net")]
const RESPONSES: [&[u8]; 6] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nSet-Cookie: a=b\r\n\r\n",
    b"HTTP/1.0 301 Moved\r\nLocation: https://example.com/a/../b?c=d#e\r\nConnection: close\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody until close",
];

/// The messages of tests/data/cms_fixtures.txt: certificates, detached contents and blobs, by name.
fn cms_fixtures() -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    let (mut certs, mut contents, mut blobs) = (Vec::new(), Vec::new(), Vec::new());
    for line in include_str!("../tests/data/cms_fixtures.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let p: Vec<&str> = line.split(' ').collect();
        let entry = (p[1].to_string(), unhex(p[2]));
        match p[0] {
            "cert" => certs.push(entry),
            "content" => contents.push(entry),
            _ => blobs.push(entry),
        }
    }
    (certs, contents, blobs)
}

#[test]
fn ber_reader_never_panics_and_what_it_writes_is_stable() {
    let (_, _, blobs) = cms_fixtures();
    let seeds: Vec<&[u8]> = blobs.iter().map(|(_, b)| b.as_slice()).collect();
    run("ber", 4000, |rng| {
        let data = if rng.chance(10) { random_up_to(rng, 200) } else { mutate_seed(rng, &seeds) };
        if let Ok((node, _)) = crate::ber::parse(&data) {
            if let Ok(der) = node.der() {
                // DER at the top, and written again the same
                let mut strict = asn1::Der::new(&der);
                let t = strict.next().expect("der() wrote something the DER reader refuses");
                assert!(strict.finish().is_ok() && t.raw == der.as_slice());
                assert_eq!(crate::ber::parse_exact(&der).unwrap().der().unwrap(), der);
                assert_eq!(node.der_content().unwrap(), t.content);
            }
        }
    });
}

#[test]
fn cms_never_panics_and_only_genuine_signatures_verify() {
    use crate::cms::{Options, SignedData};
    use crate::x509::Purpose;
    const NOW: i64 = 1_791_201_600;
    let (certs, contents, blobs) = cms_fixtures();
    let get = |list: &[(String, Vec<u8>)], name: &str| list.iter().find(|(n, _)| n == name).unwrap().1.clone();
    let mut trust = TrustStore::empty();
    trust.add_der(&get(&certs, "root")).unwrap();
    let extra = [Certificate::from_der(&get(&certs, "rsa")).unwrap(), Certificate::from_der(&get(&certs, "inter")).unwrap()];
    let detached = [None, Some(get(&contents, "hello")), Some(get(&contents, "jar_rsa")), Some(get(&contents, "jar_p256")), Some(get(&contents, "jar_ed"))];
    let mut options = Options::new(&trust, Purpose::CodeSigning, NOW);
    options.allow_sha1 = true;
    options.extra_certs = &extra;

    // what verifies unchanged, by signature value (with its content), which is what damage must not conjure
    let mut genuine: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (_, blob) in &blobs {
        let Ok(sd) = SignedData::parse(blob) else { continue };
        for d in &detached {
            for i in 0..sd.signers().len() {
                if sd.verify_signer(i, d.as_deref(), &options).is_ok() {
                    genuine.push((sd.signers()[i].signature().to_vec(), sd.content().or(d.as_deref()).unwrap().to_vec()));
                }
            }
        }
    }
    assert!(genuine.len() >= 15, "{}", genuine.len());
    let seeds: Vec<&[u8]> = blobs.iter().filter(|(n, _)| !n.starts_with("token_")).map(|(_, b)| b.as_slice()).collect();
    run("cms", 3000, |rng| {
        let data = if rng.chance(5) { random_up_to(rng, 300) } else { mutate_seed(rng, &seeds) };
        let Ok(sd) = SignedData::parse(&data) else { return };
        for d in &detached {
            for i in 0..sd.signers().len() {
                if sd.verify_signer(i, d.as_deref(), &options).is_ok() {
                    let key = (sd.signers()[i].signature().to_vec(), sd.content().or(d.as_deref()).unwrap().to_vec());
                    assert!(genuine.contains(&key), "a signature that was never made verified: {:?}", data);
                }
            }
        }
    });
}

#[cfg(feature = "net")]
#[test]
fn http_response_parser_never_panics() {
    run("http_response", 8000, |rng| {
        let data = if rng.chance(10) { random_up_to(rng, 300) } else { mutate_seed(rng, &RESPONSES) };
        let method = *rng.pick(&["GET", "HEAD", "POST", "CONNECT"]);
        let limits = Limits { max_header_bytes: 64 + rng.below(2000), max_body_bytes: rng.below(100) as u64 };
        let mut cur = std::io::Cursor::new(data);
        let _ = wire::read_response(&mut cur, method, limits);
    });
}

#[cfg(feature = "net")]
#[test]
fn url_parsing_never_panics() {
    let seeds = [
        "https://user:pw@example.com:8443/a/b/../c?x=1#frag",
        "https://[::1]:443/",
        "https://example.com",
        "/relative/path?q",
        "//other.example/x",
        "https://exämple.com/ü?ö#é",
    ];
    run("url", 8000, |rng| {
        let text = String::from_utf8_lossy(&mutate_seed(rng, &seeds.iter().map(|s| s.as_bytes()).collect::<Vec<_>>())).into_owned();
        if let Ok(u) = Url::parse(&text) {
            let _ = u.host_header();
            let _ = u.origin();
            let _ = u.is_https();
            let loc = String::from_utf8_lossy(&mutate_seed(rng, &seeds.iter().map(|s| s.as_bytes()).collect::<Vec<_>>())).into_owned();
            let _ = u.join(&loc);
        }
        let _ = Url::parse(&String::from_utf8_lossy(&random_up_to(rng, 60)));
    });
}

/// The decompressor on damaged copies of the streams of tests/data/inflate_vectors.txt: no panic, nothing past the limit, and the
/// same answer however the input and the output are cut (the coverage-guided target `inflate` in `fuzz/` checks more).
#[test]
fn inflate_never_panics_and_how_the_stream_is_cut_changes_nothing() {
    use crate::inflate::{decode_all, Error, Format, Inflater, Limits, Status};
    const VECTORS: &str = include_str!("../tests/data/inflate_vectors.txt");
    fn format_of(name: &str) -> Format {
        match name {
            "deflate" => Format::Deflate,
            "zlib" => Format::Zlib,
            _ => Format::Gzip,
        }
    }
    fn chunked(format: Format, data: &[u8], limits: Limits, inp: usize, out: usize) -> Result<Vec<u8>, Error> {
        let mut inf = Inflater::new(format, limits);
        let (mut result, mut buf, mut pos) = (Vec::new(), vec![0u8; out], 0usize);
        loop {
            let end = pos.saturating_add(inp).min(data.len());
            let p = inf.inflate(&data[pos..end], &mut buf)?;
            pos += p.consumed;
            result.extend_from_slice(&buf[..p.produced]);
            assert!(result.len() as u64 <= limits.max_output);
            match p.status {
                Status::Done => return if pos == data.len() && inf.take_unused().is_empty() { Ok(result) } else { Err(Error::Corrupt("trailing")) },
                Status::NeedOutput => {}
                Status::NeedInput if pos == data.len() => return inf.finish().map(|_| result),
                Status::NeedInput => {}
            }
        }
    }
    let seeds: Vec<(Format, Vec<u8>)> = VECTORS
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            (f[0] == "base").then(|| (format_of(f[2]), unhex(f[3])))
        })
        .collect();
    assert!(seeds.len() > 20);
    let formats = [Format::Deflate, Format::Zlib, Format::ZlibOrDeflate, Format::Gzip, Format::GzipMember];
    run("inflate", 3000, |rng| {
        let (format, seed) = &seeds[rng.below(seeds.len())];
        let data = mutate(rng, seed);
        let format = if rng.chance(15) { *rng.pick(&formats) } else { *format };
        let limits = match rng.below(4) {
            0 => Limits::new(1 << 20),
            1 => Limits::new(rng.below(2000) as u64),
            2 => Limits::new(1 << 20).with_ratio(1 + rng.below(20) as u64, rng.below(500) as u64),
            _ => Limits::new(0),
        };
        let whole = decode_all(format, &data, limits);
        let (inp, out) = *rng.pick(&[(1, 1), (3, 5), (7, 4096), (usize::MAX, 1), (1, 1 << 16)]);
        let cut = chunked(format, &data, limits, inp, out);
        let same = match (&whole, &cut) {
            (Err(Error::Corrupt(_)), Err(Error::Corrupt(_))) => true,
            (a, b) => a == b,
        };
        assert!(same, "{format:?}, input in {inp}s and output in {out}s: {:?} against {:?}", cut.as_ref().map(Vec::len), whole.as_ref().map(Vec::len));
    });
}
