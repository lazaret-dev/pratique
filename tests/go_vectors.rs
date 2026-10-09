//! Replays vectors judged by the Go reference implementation (golang.org/x/mod `sumdb/note` and
//! `sumdb/tlog`) against this crate's `note`, `sumdb` and `tlog` modules.
//!
//! The vector files are made by `tools/gen_sumdb_vectors.sh` and `tools/gen_tlog_vectors.sh`: Go
//! says what each damaged input is, and this crate must say the same, or, for the handful of inputs
//! where this crate is deliberately stricter (marked `bad-strict`), refuse what Go accepts. It
//! never accepts what Go refuses.

use pratique::note::{self, Verifier};
use pratique::sumdb;
use pratique::tlog::{self, Hash};

const SUMDB_VECTORS: &str = include_str!("data/sumdb_vectors.txt");
const TLOG_VECTORS: &str = include_str!("data/tlog_vectors.txt");
const FIXTURES: &str = include_str!("data/note_fixtures.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Applies a list of edits (`x:OFFSET:HEXBYTE` xor, `d:OFFSET:LENGTH` delete, `i:OFFSET:HEX` insert,
/// `t:LENGTH:` cut), or none (`-`).
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
                b.drain(off..off + arg.parse::<usize>().unwrap());
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

/// The keys of tests/data/note_fixtures.txt by label, and the key of sum.golang.org as `sumdb`.
fn key(label: &str) -> Verifier {
    if label == "sumdb" {
        return sumdb::verifier();
    }
    for line in FIXTURES.lines() {
        let mut p = line.splitn(3, ' ');
        if p.next() == Some("key") && p.next() == Some(label) {
            return Verifier::from_key(p.next().unwrap()).unwrap();
        }
    }
    panic!("no key {label}");
}

fn note_verdict(msg: &[u8], known: &[Verifier]) -> String {
    match note::open(msg, known) {
        Ok(n) => {
            let names: Vec<&str> = n.signatures.iter().map(|s| s.name.as_str()).collect();
            format!("ok:{}:{}", names.join(","), n.unverified.len())
        }
        Err(note::Error::MalformedNote) => "malformed".to_string(),
        Err(note::Error::InvalidSignature { .. }) => "invalid".to_string(),
        Err(note::Error::AmbiguousKey { .. }) => "ambiguous".to_string(),
        Err(note::Error::Unverified(_)) => "unverified".to_string(),
        Err(e) => panic!("unexpected {e:?}"),
    }
}

fn tree_verdict(text: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(text) else { return "bad".to_string() };
    match sumdb::parse_tree(text) {
        Ok(t) => format!("ok:{}:{}", t.size, hex(&t.root)),
        Err(_) => "refused".to_string(),
    }
}

fn record_verdict(msg: &[u8]) -> String {
    match sumdb::parse_record(msg) {
        Ok((id, text, rest)) => format!("ok:{id}:{}:{}", hex(text.as_bytes()), hex(rest)),
        Err(_) => "refused".to_string(),
    }
}

/// Go's verdict against ours: equal, or ours refuses where Go's `bad-strict` says that Go accepts
/// something this crate does not.
fn agree(go: &str, ours: &str) -> bool {
    match go {
        "bad" | "bad-strict" => ours == "refused" || ours == "bad",
        _ => go == ours,
    }
}

#[test]
fn sumdb_vectors_judged_by_go() {
    let mut bases: Vec<(String, Vec<Verifier>, Vec<u8>)> = Vec::new();
    let mut trees: Vec<(String, Vec<u8>)> = Vec::new();
    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    let (mut notes, mut tree_cases, mut record_cases) = (0, 0, 0);
    let mut seen = std::collections::BTreeMap::<String, usize>::new();

    for line in SUMDB_VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let mut p = line.splitn(4, ' ');
        let kind = p.next().unwrap();
        match kind {
            "base" => {
                let (id, keys, msg) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
                bases.push((id.to_string(), keys.split(',').map(key).collect(), unhex(msg)));
            }
            "treebase" => {
                let (id, data) = (p.next().unwrap(), p.next().unwrap());
                trees.push((id.to_string(), unhex(data)));
            }
            "recbase" => {
                let (id, data) = (p.next().unwrap(), p.next().unwrap());
                records.push((id.to_string(), unhex(data)));
            }
            "note" => {
                let (id, edits, go) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
                let (_, known, base) = bases.iter().find(|b| b.0 == id).unwrap();
                let msg = apply(base, edits);
                let ours = note_verdict(&msg, known);
                assert_eq!(go, ours, "note {id} edits {edits}");
                *seen.entry(ours.split(':').next().unwrap().to_string()).or_default() += 1;
                notes += 1;
            }
            "tree" => {
                let (id, edits, go) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
                let (_, base) = trees.iter().find(|b| b.0 == id).unwrap();
                let ours = tree_verdict(&apply(base, edits));
                assert!(agree(go, &ours), "tree {id} edits {edits}: Go says {go}, this crate {ours}");
                tree_cases += 1;
            }
            "treetext" => {
                let (data, go) = (p.next().unwrap(), p.next().unwrap());
                let ours = tree_verdict(&unhex(data));
                assert!(agree(go, &ours), "tree {data}: Go says {go}, this crate {ours}");
                tree_cases += 1;
            }
            "rec" => {
                let (id, edits, go) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
                let (_, base) = records.iter().find(|b| b.0 == id).unwrap();
                let ours = record_verdict(&apply(base, edits));
                assert!(agree(go, &ours), "record {id} edits {edits}: Go says {go}, this crate {ours}");
                record_cases += 1;
            }
            "recraw" => {
                let (data, go) = (p.next().unwrap(), p.next().unwrap());
                let ours = record_verdict(&unhex(data));
                assert!(agree(go, &ours), "record {data}: Go says {go}, this crate {ours}");
                record_cases += 1;
            }
            _ => panic!("{line}"),
        }
    }
    // the vectors really cover every kind of verdict, and the file was read whole
    for verdict in ["ok", "malformed", "invalid", "unverified", "ambiguous"] {
        assert!(seen.get(verdict).copied().unwrap_or(0) > 0, "no note vector says {verdict}");
    }
    assert!(notes > 700 && tree_cases > 400 && record_cases > 400, "{notes} {tree_cases} {record_cases}");
}

fn hash(s: &str) -> Hash {
    unhex(s).try_into().unwrap()
}

fn proof(s: &str) -> Vec<Hash> {
    if s == "-" {
        Vec::new()
    } else {
        s.split(',').map(hash).collect()
    }
}

/// Merkle proofs: made by a Python implementation of RFC 6962, judged by Go (and by that Python
/// reference's own verifier, which agreed everywhere), valid ones and every kind of damaged ones.
#[test]
fn tlog_proof_vectors_judged_by_go() {
    let (mut inclusions, mut consistencies, mut accepted) = (0, 0, 0);
    for line in TLOG_VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        let go = *f.last().unwrap();
        let ours = match f[0] {
            // incl SIZE INDEX LEAF ROOT PROOF VERDICT
            "incl" => {
                inclusions += 1;
                tlog::verify_inclusion(&proof(f[5]), f[1].parse().unwrap(), &hash(f[4]), f[2].parse().unwrap(), &hash(f[3]))
            }
            // cons OLD OLDROOT NEW NEWROOT PROOF VERDICT
            "cons" => {
                consistencies += 1;
                tlog::verify_consistency(&proof(f[5]), f[1].parse().unwrap(), &hash(f[2]), f[3].parse().unwrap(), &hash(f[4]))
            }
            _ => panic!("{line}"),
        };
        let ours = if ours.is_ok() { "ok" } else { "bad" };
        assert_eq!(go, ours, "{:.200}", line);
        accepted += (ours == "ok") as usize;
    }
    assert!(inclusions > 150 && consistencies > 200 && accepted > 200, "{inclusions} {consistencies} {accepted}");
}
