//! Project Wycheproof vectors (BACKLOG B-33, and the start of B-92's second item): ECDSA over P-521 with SHA-512 (DER
//! signatures), and RSASSA-PSS with MGF1 and a salt as long as the hash, for SHA-256 and SHA-384 (2048-bit keys) and
//! SHA-512 (4096-bit keys): the parameters the Web PKI allows, which are the only ones the library reads (see
//! `x509::SigAlg::RsaPss`). Each vector is valid (it must verify) or invalid (it must not); none of these files has one
//! that is only "acceptable". The keys go in as SubjectPublicKeyInfo, so the P-521 key parser is exercised too. The files
//! are in `tests/data/wycheproof/` (see its README), gzip-compressed and read with the library's own inflate and JSON code.

use pratique::crypto::ecdsa::{self, Curve};
use pratique::crypto::sha2::HashAlg;
use pratique::inflate::{self, Format, Limits};
use pratique::json::{self, Value};
use pratique::x509::{parse_spki, PublicKey};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/wycheproof/{name}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let gz = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let text = inflate::decode_all(Format::Gzip, &gz, Limits::new(16 << 20)).expect("gzip");
    json::parse(&text).expect("JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "{s}");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_else(|| panic!("no {key}"))
}

/// Runs every test of `file`: `check(group, msg, sig)` says whether the library accepts. Returns (valid, invalid) counts
/// after asserting that each verdict is Wycheproof's, with the tcId of any that is not.
fn run(file: &str, mut check: impl FnMut(&Value, &[u8], &[u8]) -> bool) -> (usize, usize) {
    let doc = load(file);
    let expected = doc.get("numberOfTests").and_then(Value::as_uint64).expect("numberOfTests") as usize;
    let (mut valid, mut invalid) = (0, 0);
    let mut wrong = Vec::new();
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        for t in group.get("tests").and_then(Value::as_array).expect("tests") {
            let id = t.get("tcId").and_then(Value::as_uint64).expect("tcId");
            let accepted = check(group, &unhex(text(t, "msg")), &unhex(text(t, "sig")));
            match text(t, "result") {
                "valid" => {
                    valid += 1;
                    if !accepted {
                        wrong.push(format!("{id} (valid, refused: {})", text(t, "comment")));
                    }
                }
                "invalid" => {
                    invalid += 1;
                    if accepted {
                        wrong.push(format!("{id} (invalid, accepted: {})", text(t, "comment")));
                    }
                }
                other => panic!("{file} {id}: a result this file was not expected to have: {other}"),
            }
        }
    }
    assert!(wrong.is_empty(), "{file}: {} of {} verdicts differ from Wycheproof's: {wrong:?}", wrong.len(), valid + invalid);
    assert_eq!(valid + invalid, expected, "{file}: every test was run");
    (valid, invalid)
}

#[test]
fn ecdsa_p521_with_sha512() {
    let (valid, invalid) = run("ecdsa_secp521r1_sha512_test", |group, msg, sig| {
        assert_eq!(text(group, "sha"), "SHA-512");
        let key = parse_spki(&unhex(text(group, "publicKeyDer"))).expect("SubjectPublicKeyInfo");
        let PublicKey::Ec { curve: Curve::P521, point } = key else { panic!("not read as a P-521 key") };
        ecdsa::verify(Curve::P521, &point, HashAlg::Sha512, msg, sig)
    });
    assert_eq!((valid, invalid), (232, 310));
}

#[test]
fn rsa_pss_with_the_web_pki_parameters() {
    for (file, hash, salt, counts) in [
        ("rsa_pss_2048_sha256_mgf1_32_test", HashAlg::Sha256, 32, (63, 45)),
        ("rsa_pss_2048_sha384_mgf1_48_test", HashAlg::Sha384, 48, (95, 46)),
        ("rsa_pss_4096_sha512_mgf1_64_test", HashAlg::Sha512, 64, (132, 47)),
    ] {
        let got = run(file, |group, msg, sig| {
            // the parameters of the group are the ones `verify_pss` applies: MGF1 with the message hash, salt = hash length
            assert_eq!((text(group, "mgf"), group.get("sLen").and_then(Value::as_uint64)), ("MGF1", Some(salt)));
            assert_eq!(text(group, "sha"), text(group, "mgfSha"));
            let key = parse_spki(&unhex(text(group, "publicKeyDer"))).expect("SubjectPublicKeyInfo");
            let PublicKey::Rsa(k) = key else { panic!("not read as an RSA key") };
            k.verify_pss(hash, msg, sig)
        });
        assert_eq!(got, counts, "{file}");
    }
}
