//! Replays damaged CMS messages judged by OpenSSL (tests/data/cms_vectors.txt, made by
//! tools/gen_cms_vectors.py from the messages of tests/data/cms_fixtures.txt) against
//! `SignedData::verify_signature`.
//!
//! OpenSSL's verdict is `openssl cms -verify -noverify`: every signer's digest and signature, and
//! nothing about trust or time. Where the damage is in what the signature covers (the content, the
//! signed attributes, the signature, the signer's identifier and algorithms), this crate must say
//! exactly what OpenSSL says. Elsewhere the two differ on purpose, and each difference is spelled
//! out below; in no region may this crate accept what OpenSSL refuses unless the region is listed as
//! one where this crate is the more lenient.

use pratique::cms::SignedData;

const FIXTURES: &str = include_str!("data/cms_fixtures.txt");
const VECTORS: &str = include_str!("data/cms_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn apply(base: &[u8], edits: &str) -> Vec<u8> {
    let mut b = base.to_vec();
    if edits == "-" {
        return b;
    }
    for e in edits.split(',') {
        let mut p = e.splitn(3, ':');
        let (kind, off, arg) = (p.next().unwrap(), p.next().unwrap().parse::<usize>().unwrap(), p.next().unwrap());
        match kind {
            "x" => b[off] ^= unhex(arg)[0],
            "d" => {
                let end = (off + arg.parse::<usize>().unwrap()).min(b.len());
                b.drain(off..end);
            }
            "i" => {
                let tail = b.split_off(off);
                b.extend(unhex(arg));
                b.extend(tail);
            }
            "t" => b.truncate(off),
            _ => panic!("edit {e}"),
        }
    }
    b
}

/// Whether every signer of the message verifies, as `openssl cms -verify -noverify` would say.
fn ours(msg: &[u8], detached: Option<&[u8]>) -> &'static str {
    let Ok(sd) = SignedData::parse(msg) else { return "bad" };
    if sd.signers().is_empty() {
        return "bad";
    }
    let all = (0..sd.signers().len()).all(|i| sd.verify_signature(i, detached, &[]).is_ok());
    if all {
        "ok"
    } else {
        "bad"
    }
}

/// How a region of the message is allowed to differ. `Exact`: same verdict as OpenSSL. `Stricter`:
/// this crate may refuse what OpenSSL accepts, never the reverse. `Lenient`: this crate may accept
/// what OpenSSL refuses, never the reverse. `Free`: either, because each of the two does something
/// the other does not.
#[derive(PartialEq, Debug)]
enum Rule {
    Exact,
    Stricter,
    Lenient,
    Free,
}

fn rule(region: &str) -> Rule {
    match region {
        // what the signature covers, and the bytes of the signature
        "content" | "attrs" | "sig" | "none" => Rule::Exact,
        // OpenSSL does not look at the content type attribute or compare it with the content type of the
        // message; this crate checks it (RFC 5652 section 5.3)
        "econtent_type" => Rule::Stricter,
        // OpenSSL ignores version numbers, and compares the issuer of the signer's identifier as a
        // name (without regard to case); this crate wants the versions of RFC 5652 and the issuer's
        // bytes, and parameters on the signature algorithm that its OID does not take
        "version" | "signer_version" | "signer_sid" | "signer_algs" => Rule::Stricter,
        // OpenSSL decodes every certificate and fails the message if one is damaged; this crate reads
        // the one it needs for the signer's key (and refuses to if it is not completely readable)
        "certs" => Rule::Free,
        // OpenSSL cannot find the digest of a signer that is not named in the message's list of digest
        // algorithms and refuses (RFC 5652 section 5.1 says an implementation MAY do so); this crate
        // does not need that list, which is only a hint for one-pass processing, and does not look at it
        "digest_algs_set" => Rule::Lenient,
        // the identifier and length octets of the elements around the parts, and anything after the
        // end of the message other than zero padding
        "wrapper" | "tail" => Rule::Stricter,
        r => panic!("region {r}"),
    }
}

#[test]
fn damaged_messages_judged_by_openssl() {
    let mut blobs = std::collections::BTreeMap::new();
    let mut contents = std::collections::BTreeMap::new();
    for line in FIXTURES.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let p: Vec<&str> = line.split(' ').collect();
        match p[0] {
            "blob" => drop(blobs.insert(p[1], unhex(p[2]))),
            "content" => drop(contents.insert(p[1], unhex(p[2]))),
            _ => {}
        }
    }
    let detached_of = |name: &str| -> Option<&Vec<u8>> {
        match name {
            "rsa_sha256_detached" | "rsa_noattr_detached" | "pkcs7_detached" => contents.get("hello"),
            "jar_rsa" | "jar_p256" => contents.get(name),
            _ => None,
        }
    };

    let mut disagreements: Vec<String> = Vec::new();
    // how many vectors OpenSSL calls ok or bad, by region
    let mut counts = std::collections::BTreeMap::<(String, &str), usize>::new();
    let mut cases = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f[0], "case", "{line}");
        let (base, region, edits, openssl) = (f[1], f[2], f[3], f[4]);
        let msg = apply(&blobs[base], edits);
        let mine = ours(&msg, detached_of(base).map(|v| v.as_slice()));
        cases += 1;
        *counts.entry((region.to_string(), openssl)).or_default() += 1;
        let fine = mine == openssl
            || match rule(region) {
                Rule::Exact => false,
                Rule::Stricter => mine == "bad",
                Rule::Lenient => mine == "ok",
                Rule::Free => true,
            };
        if !fine {
            disagreements.push(format!("{base} {region} {edits}: OpenSSL says {openssl}, this crate {mine}"));
        }
    }
    assert!(disagreements.is_empty(), "{} of {cases}:\n{}", disagreements.len(), disagreements.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));

    // the vectors cover both verdicts in every region that matters, so they cannot all be agreeing about nothing
    assert!(cases > 1800, "{cases}");
    for region in ["content", "attrs", "sig", "signer_sid", "signer_algs"] {
        assert!(counts.get(&(region.to_string(), "bad")).copied().unwrap_or(0) > 40, "{region}");
    }
    for region in ["none", "tail", "certs", "signer_version"] {
        assert!(counts.get(&(region.to_string(), "ok")).copied().unwrap_or(0) > 10, "{region}");
    }
}
