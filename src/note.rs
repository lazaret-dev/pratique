//! Signed notes: a short text with one or more signatures, the envelope of the Go checksum
//! database's tree heads and of the transparency-log "checkpoints" that follow the same
//! specification (c2sp.org/signed-note; Go's `golang.org/x/mod/sumdb/note`).
//!
//! # Format
//!
//! A note is a text ending in a newline, a blank line, and one or more signature lines
//!
//! ```text
//! go.sum database tree
//! 66746981
//! 3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=
//!
//! — sum.golang.org Az3grqkRef8magoKGF4PmqyvW/CmJrcunEFQN1T4NMJeotMtgBSPdkEhfSpvKl0y00aXEAYKvPqd5/lHlM/2lH+i2gc=
//! ```
//!
//! each an em dash and a space, the signer's name, a space and the Base64 of four bytes of key hash
//! followed by the signature. The signature covers the text, newline included, and nothing else.
//! The whole note must be valid UTF-8 without control characters other than newline.
//!
//! # Keys
//!
//! A verifier key is the string `<name>+<hash>+<base64 of the algorithm byte and the public key>`,
//! for example [`crate::sumdb::KEY`]. The hash is the first four bytes (as eight hex digits) of
//! `SHA-256(name || "\n" || algorithm byte || public key)`, so a signature line says which key
//! made it without naming the key. Only algorithm 1, Ed25519, exists here (and in the Go package).
//! A name is not empty, has no Unicode white space and no `+`.
//!
//! One more kind of key can be built from its parts, not read from a string: the ECDSA P-256 key of
//! Sigstore's Rekor v1 log ([`Verifier::ecdsa_p256_spki`]). Its checkpoints are signed notes whose
//! signatures are ASN.1 DER ECDSA over SHA-256, and whose four-byte key hash is not the rule above but the
//! first four bytes of the SHA-256 of the key's `SubjectPublicKeyInfo`, so such a key has no
//! `<name>+<hash>+<key>` string.
//!
//! # What [`open`] accepts
//!
//! It follows `note.Open` of the Go package: the note is parsed completely first; a signature from
//! a known key must verify or the whole note is refused, so a note that carries a bad signature
//! from a key you trust is never "partly" accepted; signatures from unknown keys are kept aside as
//! `unverified`; a note with no valid signature from a known key is an error; repeated signatures
//! by one key count once; at most 100 signature lines.
//!
//! Where it differs, it is stricter: Base64 must be canonical (padded, no whitespace, unused bits
//! zero), where Go's decoder tolerates stray bits in the last character. Nothing is accepted here
//! that Go would refuse.

use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::ed25519;
use crate::crypto::sha2::{Hash as _, HashAlg, Sha256};
use crate::pem::{base64_decode_strict, base64_encode};
use crate::x509::{self, PublicKey};

/// The most signature lines a note may carry.
pub const MAX_SIGNATURES: usize = 100;

const SIG_PREFIX: &str = "\u{2014} ";
const ALG_ED25519: u8 = 1;

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The text is not a well-formed signed note.
    MalformedNote,
    /// A verifier key string is malformed, its hash does not match, or its algorithm is not known.
    BadVerifierKey(&'static str),
    /// A signature by a known key does not verify.
    InvalidSignature { name: String, hash: u32 },
    /// Two of the known verifiers have the same name and key hash.
    AmbiguousKey { name: String, hash: u32 },
    /// The note is well-formed but no known key signed it. The note (with the signatures that were
    /// found, all unverified) is returned so it can be shown.
    Unverified(Box<Note>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MalformedNote => write!(f, "malformed note"),
            Error::BadVerifierKey(m) => write!(f, "bad verifier key: {m}"),
            Error::InvalidSignature { name, hash } => write!(f, "invalid signature for key {name}+{hash:08x}"),
            Error::AmbiguousKey { name, hash } => write!(f, "ambiguous key {name}+{hash:08x}"),
            Error::Unverified(_) => write!(f, "note has no verifiable signatures"),
        }
    }
}

impl std::error::Error for Error {}

/// One signature line of a note, verified or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signer's name.
    pub name: String,
    /// The key hash the line starts with.
    pub hash: u32,
    /// The Base64 of the hash and signature, as written.
    pub base64: String,
}

/// An opened note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The signed text, ending in a newline.
    pub text: String,
    /// The signatures by known keys, all verified.
    pub signatures: Vec<Signature>,
    /// The signatures by keys that are not known, which say nothing.
    pub unverified: Vec<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
enum Key {
    Ed25519([u8; 32]),
    /// An uncompressed SEC1 point on P-256, checked to be on the curve.
    EcdsaP256([u8; 65]),
}

/// A public key that can verify the signatures of one signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verifier {
    name: String,
    hash: u32,
    key: Key,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('+') && !name.chars().any(char::is_whitespace)
}

fn key_hash(name: &str, key: &[u8]) -> u32 {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update(key);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

impl Verifier {
    /// Parses a verifier key string, `<name>+<hash>+<keydata>`.
    pub fn from_key(vkey: &str) -> Result<Verifier, Error> {
        let (name, rest) = vkey.split_once('+').unwrap_or((vkey, ""));
        let (hash16, key64) = rest.split_once('+').unwrap_or((rest, ""));
        let id = Error::BadVerifierKey("malformed verifier id");
        if hash16.len() != 8 || !hash16.bytes().all(|b| b.is_ascii_hexdigit()) || !valid_name(name) {
            return Err(id);
        }
        let hash = u32::from_str_radix(hash16, 16).map_err(|_| id.clone())?;
        let key = match base64_decode_strict(key64) {
            Some(k) if !k.is_empty() => k,
            _ => return Err(id),
        };
        if hash != key_hash(name, &key) {
            return Err(Error::BadVerifierKey("key hash does not match the name and key"));
        }
        match key[0] {
            ALG_ED25519 => {
                let public: [u8; 32] = key[1..].try_into().map_err(|_| id)?;
                Ok(Verifier { name: name.to_string(), hash, key: Key::Ed25519(public) })
            }
            _ => Err(Error::BadVerifierKey("unknown key algorithm")),
        }
    }

    /// A verifier for an Ed25519 key under `name`.
    pub fn ed25519(name: &str, public_key: &[u8; 32]) -> Result<Verifier, Error> {
        if !valid_name(name) {
            return Err(Error::BadVerifierKey("malformed verifier id"));
        }
        let mut key = vec![ALG_ED25519];
        key.extend_from_slice(public_key);
        Ok(Verifier { name: name.to_string(), hash: key_hash(name, &key), key: Key::Ed25519(*public_key) })
    }

    /// A verifier for an ECDSA P-256 key given as a DER `SubjectPublicKeyInfo`, with the key hash that
    /// Rekor v1 checkpoints use: the first four bytes of the SHA-256 of that DER. Signatures are ASN.1 DER
    /// ECDSA over the SHA-256 of the text. The key must be a P-256 key and a point on the curve.
    pub fn ecdsa_p256_spki(name: &str, spki_der: &[u8]) -> Result<Verifier, Error> {
        if !valid_name(name) {
            return Err(Error::BadVerifierKey("malformed verifier id"));
        }
        let point = match x509::parse_spki(spki_der) {
            Ok(PublicKey::Ec { curve: Curve::P256, point }) if ecdsa::is_valid_public_key(Curve::P256, &point) => point,
            _ => return Err(Error::BadVerifierKey("not an ECDSA P-256 public key")),
        };
        let digest = Sha256::digest(spki_der);
        let hash = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Ok(Verifier { name: name.to_string(), hash, key: Key::EcdsaP256(point.try_into().map_err(|_| Error::BadVerifierKey("not an ECDSA P-256 public key"))?) })
    }

    /// The signer's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The four-byte key hash that identifies this key in signature lines.
    pub fn key_hash(&self) -> u32 {
        self.hash
    }

    /// The verifier key string, the form [`Verifier::from_key`] reads; `None` for a key that has none
    /// (the ECDSA key of [`Verifier::ecdsa_p256_spki`]).
    pub fn key_string(&self) -> Option<String> {
        match &self.key {
            Key::Ed25519(public) => {
                let mut key = vec![ALG_ED25519];
                key.extend_from_slice(public);
                Some(format!("{}+{:08x}+{}", self.name, self.hash, base64_encode(&key)))
            }
            Key::EcdsaP256(_) => None,
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match &self.key {
            Key::Ed25519(public) => ed25519::verify(public, msg, sig),
            Key::EcdsaP256(point) => ecdsa::verify(Curve::P256, point, HashAlg::Sha256, msg, sig),
        }
    }
}

/// Opens `msg`, checking its signatures against `known`. See the module documentation for the
/// rules.
pub fn open(msg: &[u8], known: &[Verifier]) -> Result<Note, Error> {
    // valid UTF-8, no control characters but newline
    let all = std::str::from_utf8(msg).map_err(|_| Error::MalformedNote)?;
    if all.chars().any(|c| c < ' ' && c != '\n') {
        return Err(Error::MalformedNote);
    }
    // the signature block follows the last blank line
    let split = all.rfind("\n\n").ok_or(Error::MalformedNote)?;
    let text = &all[..split + 1];
    let mut sigs = &all[split + 2..];
    if sigs.is_empty() || !sigs.ends_with('\n') {
        return Err(Error::MalformedNote);
    }

    let mut note = Note { text: text.to_string(), signatures: Vec::new(), unverified: Vec::new() };
    let mut seen: Vec<(&str, u32)> = Vec::new();
    let mut seen_unverified: Vec<&str> = Vec::new();
    let mut count = 0usize;
    while !sigs.is_empty() {
        let end = sigs.find('\n').ok_or(Error::MalformedNote)?;
        let line = &sigs[..end];
        sigs = &sigs[end + 1..];
        let line = line.strip_prefix(SIG_PREFIX).ok_or(Error::MalformedNote)?;
        let (name, b64) = line.split_once(' ').unwrap_or((line, ""));
        let raw = base64_decode_strict(b64).ok_or(Error::MalformedNote)?;
        if !valid_name(name) || b64.is_empty() || raw.len() < 5 {
            return Err(Error::MalformedNote);
        }
        let hash = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        count += 1;
        if count > MAX_SIGNATURES {
            return Err(Error::MalformedNote);
        }

        let mut matching = known.iter().filter(|v| v.name == name && v.hash == hash);
        let verifier = match (matching.next(), matching.next()) {
            (None, _) => {
                if !seen_unverified.contains(&line) {
                    seen_unverified.push(line);
                    note.unverified.push(Signature { name: name.to_string(), hash, base64: b64.to_string() });
                }
                continue;
            }
            (Some(_), Some(_)) => return Err(Error::AmbiguousKey { name: name.to_string(), hash }),
            (Some(v), None) => v,
        };
        if seen.contains(&(name, hash)) {
            continue;
        }
        seen.push((name, hash));
        if !verifier.verify(text.as_bytes(), &raw[4..]) {
            return Err(Error::InvalidSignature { name: name.to_string(), hash });
        }
        note.signatures.push(Signature { name: name.to_string(), hash, base64: b64.to_string() });
    }
    if note.signatures.is_empty() {
        return Err(Error::Unverified(Box::new(note)));
    }
    Ok(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumdb;

    const FIXTURES: &str = include_str!("../tests/data/note_fixtures.txt");
    const LATEST: &[u8] = include_bytes!("../tests/data/sumdb/latest.txt");
    const LOOKUP: &[u8] = include_bytes!("../tests/data/sumdb/lookup.txt");

    /// Test keys and the signatures they made (see tools/gen_note_fixtures.py).
    struct Fixtures {
        keys: Vec<(String, Verifier)>,
        texts: Vec<(String, Vec<u8>)>,
        sigs: Vec<(String, String, String)>,
    }

    fn fixtures() -> Fixtures {
        let mut f = Fixtures { keys: Vec::new(), texts: Vec::new(), sigs: Vec::new() };
        for line in FIXTURES.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let (kind, rest) = line.split_once(' ').unwrap();
            match kind {
                "key" => {
                    let (label, vkey) = rest.split_once(' ').unwrap();
                    f.keys.push((label.to_string(), Verifier::from_key(vkey).unwrap()));
                }
                "text" => {
                    let (label, hex) = rest.split_once(' ').unwrap();
                    f.texts.push((label.to_string(), crate::util::unhex(hex)));
                }
                "sig" => {
                    let mut p = rest.splitn(3, ' ');
                    f.sigs.push((p.next().unwrap().to_string(), p.next().unwrap().to_string(), p.next().unwrap().to_string()));
                }
                _ => panic!("{line}"),
            }
        }
        f
    }

    impl Fixtures {
        fn key(&self, label: &str) -> Verifier {
            self.keys.iter().find(|(l, _)| l == label).unwrap().1.clone()
        }

        fn text(&self, label: &str) -> &[u8] {
            &self.texts.iter().find(|(l, _)| l == label).unwrap().1
        }

        fn sig(&self, text: &str, key: &str) -> &str {
            &self.sigs.iter().find(|(t, k, _)| t == text && k == key).unwrap().2
        }

        /// A note: the text, a blank line, and the signature lines of these keys.
        fn note(&self, text: &str, signers: &[&str]) -> Vec<u8> {
            let mut n = self.text(text).to_vec();
            n.push(b'\n');
            for s in signers {
                n.extend_from_slice(self.sig(text, s).as_bytes());
                n.push(b'\n');
            }
            n
        }
    }

    fn names(sigs: &[Signature]) -> Vec<&str> {
        sigs.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn the_notes_of_sum_golang_org_open() {
        let known = [sumdb::verifier()];
        let note = open(LATEST, &known).unwrap();
        assert_eq!(note.text, "go.sum database tree\n66746896\ndZ4n3o/nb32Y8rCuyUc1VeuATkhefsubWOYVhA9QIc8=\n");
        assert_eq!(note.signatures.len(), 1);
        assert_eq!((note.signatures[0].name.as_str(), note.signatures[0].hash), ("sum.golang.org", 0x033de0ae));
        assert!(note.unverified.is_empty());
        // the lookup response holds the note after the record
        let at = LOOKUP.windows(2).position(|w| w == b"\n\n").unwrap() + 2;
        let note = open(&LOOKUP[at..], &known).unwrap();
        assert_eq!(note.text, "go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n");
        // with nothing known the same note is well-formed but unverified, and says who signed
        match open(LATEST, &[]) {
            Err(Error::Unverified(n)) => {
                assert!(n.signatures.is_empty());
                assert_eq!(names(&n.unverified), ["sum.golang.org"]);
                assert_eq!(n.text, note_text_of(LATEST));
            }
            other => panic!("{other:?}"),
        }
    }

    fn note_text_of(note: &[u8]) -> String {
        let s = std::str::from_utf8(note).unwrap();
        s[..s.rfind("\n\n").unwrap() + 1].to_string()
    }

    #[test]
    fn a_changed_bit_anywhere_in_a_real_note_is_refused() {
        let known = [sumdb::verifier()];
        for note in [LATEST, &LOOKUP[LOOKUP.windows(2).position(|w| w == b"\n\n").unwrap() + 2..]] {
            assert!(open(note, &known).is_ok());
            for at in 0..note.len() {
                for bit in [0u8, 3] {
                    let mut bad = note.to_vec();
                    bad[at] ^= 1 << bit;
                    assert!(open(&bad, &known).is_err(), "byte {at} bit {bit} changed and the note still opened");
                }
            }
        }
    }

    #[test]
    fn verifier_keys() {
        let v = Verifier::from_key(sumdb::KEY).unwrap();
        assert_eq!((v.name(), v.key_hash()), ("sum.golang.org", 0x033de0ae));
        assert_eq!(v.key_string().as_deref(), Some(sumdb::KEY));
        // upper-case hex digits are the same hash
        let upper = sumdb::KEY.replace("033de0ae", "033DE0AE");
        assert_eq!(Verifier::from_key(&upper).unwrap(), v);
        // a key made from its parts
        let KeyParts(name, pubkey) = KeyParts::of(&v);
        assert_eq!(Verifier::ed25519(&name, &pubkey).unwrap(), v);
        let f = fixtures();
        for (label, key) in &f.keys {
            assert_eq!(Verifier::from_key(&key.key_string().unwrap()).unwrap(), *key, "{label}");
        }

        let key64 = &sumdb::KEY["sum.golang.org+033de0ae+".len()..];
        let raw = crate::pem::base64_decode(key64).unwrap();
        let with = |name: &str, alg: u8, key: &[u8]| {
            let mut data = vec![alg];
            data.extend_from_slice(key);
            format!("{name}+{:08x}+{}", key_hash(name, &data), base64_encode(&data))
        };
        assert!(Verifier::from_key(&with("sum.golang.org", 1, &raw[1..])).is_ok());
        assert_eq!(Verifier::from_key(&with("sum.golang.org", 2, &raw[1..])), Err(Error::BadVerifierKey("unknown key algorithm")));
        assert_eq!(Verifier::from_key(&with("sum.golang.org", 0, &raw[1..])), Err(Error::BadVerifierKey("unknown key algorithm")));
        assert!(Verifier::from_key(&with("sum.golang.org", 1, &raw[1..32])).is_err(), "31-byte key");
        assert!(Verifier::from_key(&with("sum.golang.org", 1, &[raw[1..].to_vec(), vec![0]].concat())).is_err(), "33-byte key");
        for bad in [
            String::new(),
            "sum.golang.org".to_string(),
            "sum.golang.org+033de0ae".to_string(),
            "sum.golang.org+033de0ae+".to_string(),
            sumdb::KEY.replace("033de0ae", "033de0af"),                  // the hash does not match
            sumdb::KEY.replace("033de0ae", "33de0ae"),
            sumdb::KEY.replace("033de0ae", "0033de0ae"),
            sumdb::KEY.replace("033de0ae", "033de0a+"),
            sumdb::KEY.replace("033de0ae", "+33de0ae"),
            sumdb::KEY.replace("sum.golang.org", "sum.golang.com"),     // the name is part of the hash
            sumdb::KEY.replace("sum.golang.org", "sum golang.org"),
            sumdb::KEY.replace("sum.golang.org", "sum.golang.org\u{a0}"),
            sumdb::KEY.replace("sum.golang.org+", "+"),
            sumdb::KEY.replace("Ac4z", "Ac4"),
            sumdb::KEY.replace("Ac4z", "Ac4 z"),
            format!("{}=", sumdb::KEY),
            format!("{}\n", sumdb::KEY),
        ] {
            assert!(Verifier::from_key(&bad).is_err(), "{bad:?}");
        }
        assert!(Verifier::ed25519("", &[0; 32]).is_err());
        assert!(Verifier::ed25519("a b", &[0; 32]).is_err());
        assert!(Verifier::ed25519("a+b", &[0; 32]).is_err());
        assert!(Verifier::ed25519("a\u{2003}b", &[0; 32]).is_err(), "an em space is white space");
        assert!(Verifier::ed25519("a\u{200b}b", &[0; 32]).is_ok(), "a zero width space is not");
    }

    struct KeyParts(String, [u8; 32]);
    impl KeyParts {
        fn of(v: &Verifier) -> KeyParts {
            let Key::Ed25519(k) = &v.key else { panic!("not an Ed25519 key") };
            KeyParts(v.name.clone(), *k)
        }
    }

    #[test]
    fn several_signers() {
        let f = fixtures();
        let (a, b, c) = (f.key("alpha"), f.key("beta"), f.key("gamma"));
        for text in ["tree", "plain", "unicode", "lines"] {
            let two = f.note(text, &["alpha", "beta"]);
            let n = open(&two, &[a.clone(), b.clone()]).unwrap();
            assert_eq!(n.text.as_bytes(), f.text(text));
            assert_eq!(names(&n.signatures), ["alpha.example", "beta.example"], "{text}");
            assert!(n.unverified.is_empty());
            // one known: the other is kept aside, not trusted
            let n = open(&two, &[b.clone()]).unwrap();
            assert_eq!((names(&n.signatures), names(&n.unverified)), (vec!["beta.example"], vec!["alpha.example"]));
            // a key that did not sign is not a signer
            let n = open(&two, &[a.clone(), c.clone()]).unwrap();
            assert_eq!((names(&n.signatures), names(&n.unverified)), (vec!["alpha.example"], vec!["beta.example"]));
            // no known signer
            match open(&two, &[c.clone()]) {
                Err(Error::Unverified(n)) => assert_eq!((n.signatures.len(), names(&n.unverified)), (0, vec!["alpha.example", "beta.example"])),
                other => panic!("{other:?}"),
            }
            // order of lines and of known keys does not matter
            let swapped = f.note(text, &["beta", "alpha"]);
            let n = open(&swapped, &[b.clone(), a.clone()]).unwrap();
            assert_eq!(names(&n.signatures), ["beta.example", "alpha.example"]);
        }
        // a signature over another text is not valid
        let mut wrong = f.text("plain").to_vec();
        wrong.push(b'\n');
        wrong.extend_from_slice(f.sig("tree", "alpha").as_bytes());
        wrong.push(b'\n');
        assert_eq!(open(&wrong, &[a.clone()]), Err(Error::InvalidSignature { name: "alpha.example".into(), hash: a.key_hash() }));
        // ... but is merely unverified when the key is not known
        assert!(matches!(open(&wrong, &[b.clone()]), Err(Error::Unverified(_))));
    }

    #[test]
    fn one_bad_signature_from_a_known_key_spoils_the_note() {
        let f = fixtures();
        let (a, b) = (f.key("alpha"), f.key("beta"));
        // alpha's line carries beta's signature bits: alpha is known and wrong, beta is fine
        let a_line = f.sig("plain", "alpha");
        let b_line = f.sig("plain", "beta");
        let forged = format!("{}{}", &a_line[..a_line.rfind(' ').unwrap() + 1], &b_line[b_line.rfind(' ').unwrap() + 1..]);
        let mut n = f.text("plain").to_vec();
        n.extend_from_slice(format!("\n{forged}\n{b_line}\n").as_bytes());
        // the key hash inside is beta's, so the line names alpha but is looked up as an unknown key
        assert_eq!(names(&open(&n, &[a.clone(), b.clone()]).unwrap().unverified), ["alpha.example"]);
        // flip a bit of alpha's own signature instead
        let mut raw = crate::pem::base64_decode(a_line.rsplit(' ').next().unwrap()).unwrap();
        raw[20] ^= 1;
        let bad = format!("\u{2014} alpha.example {}", base64_encode(&raw));
        let mut n = f.text("plain").to_vec();
        n.extend_from_slice(format!("\n{b_line}\n{bad}\n").as_bytes());
        assert_eq!(open(&n, &[a.clone(), b.clone()]), Err(Error::InvalidSignature { name: "alpha.example".into(), hash: a.key_hash() }));
        // beta's good signature does not rescue it, whichever comes first
        let mut n = f.text("plain").to_vec();
        n.extend_from_slice(format!("\n{bad}\n{b_line}\n").as_bytes());
        assert!(matches!(open(&n, &[a.clone(), b.clone()]), Err(Error::InvalidSignature { .. })));
        // when alpha is not a known key, the bad line is only noted
        let opened = open(&n, &[b.clone()]).unwrap();
        assert_eq!((names(&opened.signatures), names(&opened.unverified)), (vec!["beta.example"], vec!["alpha.example"]));
    }

    #[test]
    fn repeated_signatures_count_once() {
        let f = fixtures();
        let (a, b) = (f.key("alpha"), f.key("beta"));
        let mut n = f.note("plain", &["alpha", "alpha", "beta", "alpha"]);
        let opened = open(&n, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(names(&opened.signatures), ["alpha.example", "beta.example"]);
        // identical unverified lines are dropped, different ones kept
        let c_line = f.sig("plain", "gamma").to_string();
        n.extend_from_slice(format!("{c_line}\n{c_line}\n").as_bytes());
        let opened = open(&n, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(names(&opened.unverified), ["gamma.example"]);
        // the same key twice in the known list is ambiguous once something is signed by it
        assert_eq!(open(&f.note("plain", &["alpha"]), &[a.clone(), a.clone()]), Err(Error::AmbiguousKey { name: "alpha.example".into(), hash: a.key_hash() }));
        assert!(open(&f.note("plain", &["beta"]), &[a.clone(), a.clone(), b.clone()]).is_ok(), "an ambiguous key that did not sign does not matter");
    }

    #[test]
    fn a_key_hash_that_matches_nothing_is_an_unknown_key() {
        let f = fixtures();
        let a = f.key("alpha");
        let line = f.sig("plain", "alpha");
        let mut raw = crate::pem::base64_decode(line.rsplit(' ').next().unwrap()).unwrap();
        raw[0] ^= 0x80;
        let n = [&f.text("plain")[..], b"\n", format!("\u{2014} alpha.example {}\n", base64_encode(&raw)).as_bytes()].concat();
        match open(&n, &[a]) {
            Err(Error::Unverified(n)) => assert_eq!(n.unverified.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn at_most_a_hundred_signature_lines() {
        let f = fixtures();
        let a = f.key("alpha");
        let mut lines = Vec::new();
        for i in 0..100u32 {
            let raw: Vec<u8> = (0..70u32).map(|j| (i * 7 + j) as u8).collect();
            lines.push(format!("\u{2014} other{i} {}\n", base64_encode(&raw)));
        }
        let make = |n: usize| {
            let mut note = f.text("plain").to_vec();
            note.push(b'\n');
            note.extend_from_slice(f.sig("plain", "alpha").as_bytes());
            note.push(b'\n');
            for l in &lines[..n] {
                note.extend_from_slice(l.as_bytes());
            }
            note
        };
        let ok = open(&make(99), &[a.clone()]).unwrap();
        assert_eq!((ok.signatures.len(), ok.unverified.len()), (1, 99));
        assert_eq!(open(&make(100), &[a.clone()]), Err(Error::MalformedNote), "101 lines");
        // repeats count too
        let mut many = f.note("plain", &[]);
        for _ in 0..101 {
            many.extend_from_slice(f.sig("plain", "alpha").as_bytes());
            many.push(b'\n');
        }
        assert_eq!(open(&many, &[a]), Err(Error::MalformedNote));
    }

    #[test]
    fn malformed_notes() {
        let f = fixtures();
        let a = f.key("alpha");
        let good = f.note("plain", &["alpha"]);
        assert!(open(&good, &[a.clone()]).is_ok());
        let text = f.text("plain").to_vec();
        let sig = f.sig("plain", "alpha").to_string();
        let join = |parts: &[&[u8]]| parts.concat();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("text only", text.clone()),
            ("no blank line", join(&[&text, sig.as_bytes(), b"\n"])),
            ("blank line but no signature", join(&[&text, b"\n"])),
            ("no final newline", join(&[&text, b"\n", sig.as_bytes()])),
            ("hyphen for em dash", join(&[&text, b"\n", sig.replace('\u{2014}', "-").as_bytes(), b"\n"])),
            ("no space after the dash", join(&[&text, b"\n", sig.replace("\u{2014} ", "\u{2014}").as_bytes(), b"\n"])),
            ("two spaces after the dash", join(&[&text, b"\n", sig.replace("\u{2014} ", "\u{2014}  ").as_bytes(), b"\n"])),
            ("a name with a plus", join(&[&text, b"\n", sig.replace("alpha.example", "alpha+example").as_bytes(), b"\n"])),
            ("an empty name", join(&[&text, b"\n", sig.replace("alpha.example", "").as_bytes(), b"\n"])),
            ("no signature", join(&[&text, "\n\u{2014} alpha.example\n".as_bytes()])),
            ("empty signature", join(&[&text, "\n\u{2014} alpha.example \n".as_bytes()])),
            ("signature of only a key hash", join(&[&text, "\n\u{2014} alpha.example U5ZVxw==\n".as_bytes()])),
            ("signature not Base64", join(&[&text, "\n\u{2014} alpha.example U5ZV*w==\n".as_bytes()])),
            ("unpadded Base64", join(&[&text, b"\n", sig.trim_end_matches('=').as_bytes(), b"\n"])),
            ("space inside the Base64", join(&[&text, b"\n", sig.replacen("U5ZV", "U5 ZV", 1).as_bytes(), b"\n"])),
            ("a line that is not a signature", join(&[&text, b"\n", sig.as_bytes(), b"\nhello\n"])),
            ("an empty line between signatures", join(&[&text, b"\n", sig.as_bytes(), b"\n\n"])),
            ("a control character in the text", join(&[b"hel\x07lo\n", b"\n", sig.as_bytes(), b"\n"])),
            ("a carriage return", join(&[b"hello\r\n", b"\n", sig.as_bytes(), b"\n"])),
            ("a tab in a signature line", join(&[&text, b"\n", sig.replace("alpha", "al\tpha").as_bytes(), b"\n"])),
            ("a NUL", join(&[&text, b"\n", sig.as_bytes(), b"\n\0"])),
            ("not UTF-8 in the text", join(&[b"h\xffllo\n", b"\n", sig.as_bytes(), b"\n"])),
            ("not UTF-8 in a line", join(&[&text, b"\n", sig.as_bytes(), b"\xff\n"])),
            ("an overlong encoding", join(&[b"h\xc0\xafllo\n", b"\n", sig.as_bytes(), b"\n"])),
            ("a surrogate", join(&[b"h\xed\xa0\x80llo\n", b"\n", sig.as_bytes(), b"\n"])),
        ];
        for (what, note) in cases {
            assert_eq!(open(&note, &[a.clone()]), Err(Error::MalformedNote), "{what}");
        }
        // The boundary cases that are well-formed: text of several lines, a text that is only a
        // newline, and DEL (which is not below U+0020).
        let a2 = a.clone();
        assert!(matches!(open(&join(&[b"hello\n\n", sig.as_bytes(), b"\n"]), &[a2.clone()]), Err(Error::InvalidSignature { .. })), "the text of a note always ends in the newline before the blank line");
        assert!(matches!(open(&join(&[b"\n\n", sig.as_bytes(), b"\n"]), &[a2.clone()]), Err(Error::InvalidSignature { .. })), "a text of one newline is well-formed (and the signature is not for it)");
        assert!(matches!(open(&join(&[b"x\x7fy\n\n", sig.as_bytes(), b"\n"]), &[a2.clone()]), Err(Error::InvalidSignature { .. })), "DEL is allowed in a note");
        assert!(matches!(open(&join(&[&text, b"\n", sig.as_bytes(), b"\n"]), &[]), Err(Error::Unverified(_))));
    }

    #[test]
    fn the_blank_line_is_the_last_one() {
        // A blank line before the last signature line moves the earlier lines into the text, which
        // changes what is signed: a note cannot be made to verify with its text cut differently.
        let f = fixtures();
        let (a, b) = (f.key("alpha"), f.key("beta"));
        let mut n = f.text("plain").to_vec();
        n.extend_from_slice(format!("\n{}\n\n{}\n", f.sig("plain", "alpha"), f.sig("plain", "beta")).as_bytes());
        // the text is now "hello, world\n\n— alpha.example ...\n" and beta signed something else
        assert!(matches!(open(&n, &[b.clone()]), Err(Error::InvalidSignature { .. })));
        assert!(matches!(open(&n, &[a.clone()]), Err(Error::Unverified(_))));
    }

    #[test]
    fn unicode_names_and_texts() {
        let f = fixtures();
        // the text with non-ASCII characters, supplementary plane included
        let n = open(&f.note("unicode", &["alpha"]), &[f.key("alpha")]).unwrap();
        assert_eq!(n.text, "h\u{e9}llo \u{2014} \u{2713} \u{1F600}\n");
        // a replacement character that is really in the text is fine
        let mut n = "caf\u{fffd}\n\n".as_bytes().to_vec();
        n.extend_from_slice(f.sig("plain", "alpha").as_bytes());
        n.push(b'\n');
        assert!(matches!(open(&n, &[]), Err(Error::Unverified(_))));
    }

    // ---- Rekor v1: an ECDSA P-256 key and the key hash of its checkpoints (real data, tests/data/rekor)

    const REKOR_KEY: &str = include_str!("../tests/data/rekor/v1_key.pem");
    const REKOR_V1: [(&str, u64); 4] = [
        (include_str!("../tests/data/rekor/v1_checkpoint_new.txt"), 2_976_019_742),
        (include_str!("../tests/data/rekor/v1_checkpoint_old.txt"), 2_953_640_305),
        (include_str!("../tests/data/rekor/v1_shard_4163431.txt"), 4_163_431),
        (include_str!("../tests/data/rekor/v1_shard_117740831.txt"), 117_740_831),
    ];
    const REKOR_V2: &str = include_str!("../tests/data/rekor/v2_checkpoint.txt");
    const REKOR_V2_KEY: &str = include_str!("../tests/data/rekor/v2_key.txt");

    fn rekor_spki() -> Vec<u8> {
        crate::pem::parse(REKOR_KEY).remove(0).data
    }

    fn rekor() -> Verifier {
        Verifier::ecdsa_p256_spki("rekor.sigstore.dev", &rekor_spki()).unwrap()
    }

    #[test]
    fn rekor_v1_checkpoints_open_with_the_ecdsa_key() {
        let v = rekor();
        // the key hash is the first four bytes of the SHA-256 of the SubjectPublicKeyInfo, not the signed-note rule
        assert_eq!(v.key_hash(), u32::from_be_bytes(Sha256::digest(&rekor_spki())[..4].try_into().unwrap()));
        assert_eq!(v.name(), "rekor.sigstore.dev");
        assert_eq!(v.key_string(), None);
        for (cp, size) in REKOR_V1 {
            let n = open(cp.as_bytes(), &[v.clone()]).unwrap();
            assert_eq!(n.signatures.len(), 1);
            assert!(n.unverified.is_empty());
            assert_eq!(n.signatures[0].hash, v.key_hash());
            let mut lines = n.text.lines();
            assert!(lines.next().unwrap().starts_with("rekor.sigstore.dev - "));
            assert_eq!(lines.next().unwrap().parse::<u64>().unwrap(), size);
        }
    }

    #[test]
    fn a_changed_bit_anywhere_in_a_real_rekor_checkpoint_is_refused() {
        let v = rekor();
        let cp = REKOR_V1[1].0.as_bytes();
        assert!(open(cp, &[v.clone()]).is_ok());
        for at in 0..cp.len() {
            for bit in [0u8, 5] {
                let mut bad = cp.to_vec();
                bad[at] ^= 1 << bit;
                assert!(open(&bad, &[v.clone()]).is_err(), "byte {at} bit {bit} changed and the checkpoint still opened");
            }
        }
        // a signature of one head does not carry to another
        let (a, b) = (REKOR_V1[0].0, REKOR_V1[1].0);
        let sigs_of_b = &b[b.rfind("\n\n").unwrap()..];
        let spliced = format!("{}{}", &a[..a.rfind("\n\n").unwrap()], sigs_of_b);
        assert_eq!(open(spliced.as_bytes(), &[v.clone()]), Err(Error::InvalidSignature { name: "rekor.sigstore.dev".into(), hash: v.key_hash() }));
    }

    #[test]
    fn a_key_is_looked_up_by_name_and_hash() {
        let v = rekor();
        let cp = REKOR_V1[0].0.as_bytes();
        // the same key under another name does not match the line, which is only noted
        let other = Verifier::ecdsa_p256_spki("rekor.example", &rekor_spki()).unwrap();
        assert_eq!(other.key_hash(), v.key_hash(), "the hash is of the key alone");
        match open(cp, &[other]) {
            Err(Error::Unverified(n)) => assert_eq!(names(&n.unverified), ["rekor.sigstore.dev"]),
            e => panic!("{e:?}"),
        }
        // the log's other key (Rekor v2 signs with Ed25519) neither verifies nor disturbs it
        let (v2name, spki_b64) = REKOR_V2_KEY.trim().split_once('\n').unwrap();
        let spki = crate::pem::base64_decode_strict(spki_b64).unwrap();
        let v2 = Verifier::ed25519(v2name, spki[12..].try_into().unwrap()).unwrap();
        let both = [v2.clone(), v.clone()];
        assert_eq!(names(&open(cp, &both).unwrap().signatures), ["rekor.sigstore.dev"]);
        assert_eq!(names(&open(REKOR_V2.as_bytes(), &both).unwrap().signatures), ["log2025-1.rekor.sigstore.dev"]);
        assert!(matches!(open(REKOR_V2.as_bytes(), &[v]), Err(Error::Unverified(_))));
        assert!(matches!(open(cp, &[v2]), Err(Error::Unverified(_))));
    }

    #[test]
    fn only_a_p256_point_on_the_curve_makes_an_ecdsa_verifier() {
        let spki = rekor_spki();
        assert_eq!(spki.len(), 91);
        let name = "rekor.sigstore.dev";
        let bad = Error::BadVerifierKey("not an ECDSA P-256 public key");
        // the same key with a coordinate that is off the curve, a compressed point, and the wrong lengths
        let mut off = spki.clone();
        off[90] ^= 1;
        assert_eq!(Verifier::ecdsa_p256_spki(name, &off), Err(bad.clone()), "y changed");
        let mut off = spki.clone();
        off[27] ^= 1;
        assert_eq!(Verifier::ecdsa_p256_spki(name, &off), Err(bad.clone()), "x changed");
        let mut not_uncompressed = spki.clone();
        not_uncompressed[26] = 0x03;
        assert_eq!(Verifier::ecdsa_p256_spki(name, &not_uncompressed), Err(bad.clone()));
        assert!(Verifier::ecdsa_p256_spki(name, &spki[..90]).is_err());
        assert!(Verifier::ecdsa_p256_spki(name, &[&spki[..], &[0u8][..]].concat()).is_err(), "trailing byte");
        assert!(Verifier::ecdsa_p256_spki(name, &[]).is_err());
        assert!(Verifier::ecdsa_p256_spki(name, &spki[26..]).is_err(), "the bare point is not a SubjectPublicKeyInfo");
        // another kind of key: Ed25519 (RFC 8410), and P-384 (a curve this verifier does not do)
        let (_, ed_b64) = REKOR_V2_KEY.trim().split_once('\n').unwrap();
        let ed = crate::pem::base64_decode_strict(ed_b64).unwrap();
        assert_eq!(Verifier::ecdsa_p256_spki(name, &ed), Err(bad.clone()));
        let mut p384 = vec![0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04];
        p384.extend_from_slice(&[7u8; 96]);
        assert_eq!(Verifier::ecdsa_p256_spki(name, &p384), Err(bad.clone()));
        // names follow the same rule as for every key
        for n in ["", "a b", "a+b", "a\u{2003}b"] {
            assert!(Verifier::ecdsa_p256_spki(n, &spki).is_err(), "{n:?}");
        }
        assert!(Verifier::ecdsa_p256_spki(name, &spki).is_ok());
    }
}
