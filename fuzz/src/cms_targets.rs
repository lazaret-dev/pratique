//! The fuzz targets of the CMS side: `ber` (the BER reader) and `cms` (SignedData and RFC 3161 time
//! stamps). Each asserts a property of the answer, not just "no panic":
//!
//! | target | what must hold |
//! |--------|----------------|
//! | `ber`  | whatever parses can be walked without surprises (a constructed element has children and no content, a primitive one the reverse); what `der()` writes is strict DER at the top (the `asn1` reader accepts it as one element with the same bytes), parses again, and writes itself again unchanged; `der_content()` is the content of `der()` |
//! | `cms`  | a message built from the fixtures (`tests/data/cms_fixtures.txt`, made by OpenSSL and the JDK) and changed by the input is accepted only if every signer that verifies carries a signature value, a content and a certificate that a fixture message verified with, and a chain time that is the caller's or a fixture time stamp's; a verified time-stamp token is one of the fixture tokens (the time and the serial number); the signature check alone never refuses what the full check accepts |
//!
//! The first byte of a `cms` input chooses what it is: bit 0 set means "verify this as a time-stamp
//! token for the message `stamped`", otherwise it is a SignedData, and bits 1 to 3 choose the
//! detached content (none, `hello`, or one of the three JAR signature files).

use std::collections::HashSet;
use std::sync::OnceLock;

use pratique::asn1::Der;
use pratique::ber;
use pratique::cms::{self, Options, SignedData};
use pratique::util::unhex;
use pratique::x509::{Certificate, Purpose, TrustStore};

const FIXTURES: &str = include_str!("../../tests/data/cms_fixtures.txt");
/// 2026-10-05 12:00:00 UTC.
const NOW: i64 = 1_791_201_600;

// ========================================================================================== ber

pub const CMS_DICT: &[&[u8]] = &[
    b"\x30\x80",
    b"\x31\x80",
    b"\xa0\x80",
    b"\x24\x80",
    b"\x00\x00",
    b"\x04\x00",
    b"\x30\x00",
    b"\x30\x82",
    b"\x30\x81",
    b"\x04\x82",
    b"\x04\x81",
    b"\x02\x01\x01",
    b"\x02\x01\x03",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a",
    b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01",
    b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03",
    b"\x06\x05\x2b\x0e\x03\x02\x1a",
    b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
    b"\x06\x03\x2b\x65\x70",
    b"\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e",
    b"\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04",
    b"\x04\x20",
    b"\x05\x00",
    b"\x18\x0f20260401123456Z",
    b"\xa0\x03\x02\x01\x02",
];

pub fn ber(data: &[u8]) {
    let Ok((node, rest)) = ber::parse(data) else { return };
    assert!(rest.len() < data.len(), "an element took no bytes");
    walk(&node, 0);
    if let Ok(der) = node.der() {
        // what is written is DER at its top level: the strict reader takes it as one element, byte for byte
        let mut strict = Der::new(&der);
        let t = strict.next().expect("der() wrote something the DER reader refuses");
        strict.finish().expect("der() wrote more than one element");
        assert_eq!(t.raw, der.as_slice());
        // it parses again, and again writes the same bytes
        let again = ber::parse_exact(&der).expect("der() wrote something that does not parse");
        assert_eq!(again.der().expect("a second der()"), der);
        // the content octets of the DER form are what der_content() gives
        assert_eq!(node.der_content().expect("der() worked, der_content() did not"), t.content);
        // and the same element under another tag has the same content
        let other = node.der_as(0xa5).expect("der_as");
        assert_eq!(Der::new(&other).next().unwrap().content, t.content);
    }
}

fn walk(n: &ber::Node, depth: usize) {
    assert!(depth <= ber::MAX_DEPTH + 1);
    assert_eq!(n.is_constructed(), n.tag() & 0x20 != 0, "the constructed bit and the form disagree");
    match n.children() {
        Ok(kids) => {
            assert!(n.is_constructed() && n.content().is_err() && n.tlv().is_err());
            let mut items = n.items().unwrap();
            for k in kids {
                assert_eq!(items.peek_tag(), Some(k.tag()));
                let got = items.next().unwrap();
                assert!(std::ptr::eq(got, k));
                walk(k, depth + 1);
            }
            assert!(items.is_empty() && items.finish().is_ok() && items.next().is_err());
        }
        Err(_) => {
            assert!(!n.is_constructed() && n.items().is_err());
            let content = n.content().unwrap();
            assert_eq!(n.tlv().unwrap().content, content);
            assert_eq!(n.octets().unwrap().as_ref(), content);
        }
    }
}

// ========================================================================================== cms

struct Data {
    certs: Vec<(String, Vec<u8>)>,
    /// `hello` and the three JAR signature files, in the order of the selector.
    detached: Vec<Vec<u8>>,
    stamped: Vec<u8>,
    blobs: Vec<(String, Vec<u8>)>,
    trust: TrustStore,
    extra: Vec<Certificate>,
    /// (signature value, content, leaf certificate) of every signer that verifies in a fixture.
    good: HashSet<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// The times that time stamps in the fixtures give.
    stamp_times: HashSet<i64>,
    /// (time, serial number) of the tokens that verify over `stamped`.
    tokens: HashSet<(i64, Vec<u8>)>,
}

fn options(d: &Data) -> Options<'_> {
    let mut o = Options::new(&d.trust, Purpose::CodeSigning, NOW);
    o.allow_sha1 = true;
    o.extra_certs = &d.extra;
    o
}

fn detached_for(d: &Data, sel: u8) -> Option<&[u8]> {
    match (sel >> 1) % 5 {
        0 => None,
        n => Some(d.detached[n as usize - 1].as_slice()),
    }
}

fn data() -> &'static Data {
    static D: OnceLock<Data> = OnceLock::new();
    D.get_or_init(|| {
        let mut certs = Vec::new();
        let mut contents = Vec::new();
        let mut blobs = Vec::new();
        for line in FIXTURES.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let p: Vec<&str> = line.split(' ').collect();
            let entry = (p[1].to_string(), unhex(p[2]));
            match p[0] {
                "cert" => certs.push(entry),
                "content" => contents.push(entry),
                "blob" => blobs.push(entry),
                _ => panic!("{line:.40}"),
            }
        }
        let get = |list: &[(String, Vec<u8>)], name: &str| list.iter().find(|(n, _)| n == name).unwrap().1.clone();
        let mut trust = TrustStore::empty();
        trust.add_der(&get(&certs, "root")).unwrap();
        let extra = vec![Certificate::from_der(&get(&certs, "rsa")).unwrap(), Certificate::from_der(&get(&certs, "inter")).unwrap()];
        let detached: Vec<Vec<u8>> = ["hello", "jar_rsa", "jar_p256", "jar_ed"].iter().map(|n| get(&contents, n)).collect();
        let stamped = get(&contents, "stamped");
        let mut d = Data { certs, detached, stamped, blobs, trust, extra, good: HashSet::new(), stamp_times: HashSet::new(), tokens: HashSet::new() };

        // The messages that are meant to be refused. What the fixtures verify as is taken from the library
        // below, so a flaw that accepts one of these would otherwise teach the target that it is good.
        const REFUSED: &[&str] = &[
            "rogue_signed",
            "tls_signed",
            "short_signed",
            "rsa_attrs_stripped",
            "rsa_econtent_type_swapped",
            "jar_rsa_alg_swapped",
            "rsa_ts_wrong_imprint",
            "rsa_ts_rogue_tsa",
            "rsa_ts_wrong_eku",
            "short_ts_late",
            "short_ts_early",
        ];
        const REFUSED_TOKENS: &[&str] = &["token_rogue_tsa", "token_wrong_eku"];

        // what the fixtures verify as, with every choice of detached content
        let mut good = HashSet::new();
        let mut times = HashSet::new();
        let mut tokens = HashSet::new();
        for (name, blob) in &d.blobs {
            if let Ok(t) = cms::verify_timestamp(blob, &d.stamped, &d.trust, true) {
                assert!(!REFUSED_TOKENS.contains(&name.as_str()), "{name} was accepted");
                tokens.insert((t.time, t.serial));
            } else {
                assert!(!name.starts_with("token_") || REFUSED_TOKENS.contains(&name.as_str()), "{name} was refused");
            }
            let Ok(sd) = SignedData::parse(blob) else { continue };
            for sel in [0u8, 2, 4, 6, 8] {
                let detached = detached_for(&d, sel);
                for i in 0..sd.signers().len() {
                    if let Ok(v) = sd.verify_signer(i, detached, &options(&d)) {
                        assert!(!REFUSED.contains(&name.as_str()), "{name} was accepted");
                        let content = sd.content().or(detached).unwrap().to_vec();
                        good.insert((sd.signers()[i].signature().to_vec(), content, v.chain.leaf.der.clone()));
                        if let Some(t) = &v.timestamp {
                            times.insert(t.time);
                        }
                    }
                }
            }
        }
        assert!(good.len() >= 15 && !times.is_empty() && tokens.len() >= 4, "the fixtures do not verify: {} {} {}", good.len(), times.len(), tokens.len());
        d.good = good;
        d.stamp_times = times;
        d.tokens = tokens;
        d
    })
}

pub fn seeds_cms() -> Vec<Vec<u8>> {
    let d = data();
    let mut seeds = Vec::new();
    for (name, blob) in &d.blobs {
        if name.starts_with("token_") {
            seeds.push([&[1u8][..], blob].concat());
            continue;
        }
        let sel = match name.as_str() {
            "rsa_sha256_detached" | "rsa_noattr_detached" | "pkcs7_detached" => 2,
            "jar_rsa" | "jar_rsa_alg_swapped" => 4,
            "jar_p256" => 6,
            "jar_ed" => 8,
            _ => 0,
        };
        seeds.push([&[sel][..], blob].concat());
    }
    seeds
}

pub fn cms(data_in: &[u8]) {
    let d = data();
    let Some((&sel, rest)) = data_in.split_first() else { return };
    if sel & 1 == 1 {
        if let Ok(t) = cms::verify_timestamp(rest, &d.stamped, &d.trust, true) {
            assert!(d.tokens.contains(&(t.time, t.serial.clone())), "a time-stamp token that is not one of the fixtures was accepted");
        }
        return;
    }
    let Ok(sd) = SignedData::parse(rest) else { return };
    let _ = (sd.content_type(), sd.certificates().len(), sd.skipped_certificates());
    let detached = detached_for(d, sel);
    for (i, signer) in sd.signers().iter().enumerate() {
        let _ = (signer.id(), signer.digest_algorithm(), signer.signature_algorithm(), signer.claimed_signing_time());
        let o = options(d);
        let full = sd.verify_signer(i, detached, &o);
        let arithmetic = sd.verify_signature(i, detached, &d.extra);
        if let Ok(v) = full {
            assert!(arithmetic.is_ok(), "the signature check refuses what the full check accepts");
            let content = sd.content().or(detached).expect("verified without content").to_vec();
            let key = (signer.signature().to_vec(), content, v.chain.leaf.der.clone());
            assert!(d.good.contains(&key), "a signer that no fixture message verifies with was accepted");
            assert!(d.certs.iter().any(|(_, der)| der == &v.chain.leaf.der));
            assert!(v.chain_time == NOW || d.stamp_times.contains(&v.chain_time), "chain time {} is neither now nor a time stamp's", v.chain_time);
            if let Some(t) = &v.timestamp {
                assert!(d.stamp_times.contains(&t.time) && t.time == v.chain_time);
            } else {
                assert_eq!(v.chain_time, NOW);
            }
        }
    }
}
