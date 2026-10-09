//! The fuzz targets of the transparency-log modules: `note` (signed notes and verifier keys), `tlog`
//! (Merkle proofs, tile paths, tile authentication) and `sumdb` (the Go checksum database's parsing
//! and checks). Each asserts a property of the answer, not just "no panic":
//!
//! | target  | what must hold |
//! |---------|----------------|
//! | `note`  | a note that opens carries only signatures that are, byte for byte, known good ones (`tests/data/note_fixtures.txt` and the real `sum.golang.org` notes), made by a key that was given; a verifier key that parses prints back as itself |
//! | `tlog`  | the iterative proof checks of RFC 9162 agree, on every input, with a second implementation written after the recursive definitions of RFC 6962; a tile path that parses prints back as the same text; for a tree built inside the target, tiles that are right authenticate and **any one byte changed in a needed tile, or a needed tile missing, is refused** (CVE-2026-56865 was a tile Go did not check) |
//! | `sumdb` | tree heads and lookup responses that parse print back as the bytes they came from; a lookup path that is made can be unescaped back; with a made-up log under a test key in two histories, nothing is accepted that was not signed, and no two histories are ever accepted together |

use std::sync::OnceLock;

use pratique::note::{self, Verifier};
use pratique::sumdb::{self, Check};
use pratique::tlog::{self, Hash, Tile, TileSet, Tree};
use pratique::util::unhex;

/// Reads fields from the input, giving zeros when it runs out, so every input means something.
struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    fn new(data: &'a [u8]) -> Input<'a> {
        Input { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        for x in &mut b {
            *x = self.byte();
        }
        u64::from_le_bytes(b)
    }

    fn hash(&mut self) -> Hash {
        let mut h = [0u8; 32];
        for x in &mut h {
            *x = self.byte();
        }
        h
    }

    fn rest(&mut self) -> &'a [u8] {
        let r = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len().max(self.pos);
        r
    }
}

fn hashes(bytes: &[u8]) -> Vec<Hash> {
    bytes.chunks_exact(32).map(|c| c.try_into().unwrap()).collect()
}

// ======================================================================================== note

const REAL_LATEST: &[u8] = include_bytes!("../../tests/data/sumdb/latest.txt");
const REAL_LOOKUP: &[u8] = include_bytes!("../../tests/data/sumdb/lookup.txt");

struct NoteData {
    /// `(label, verifier key string)` of the test keys.
    keys: Vec<(String, String)>,
    /// `(text, signature line without the dash)` of every signature known to be good.
    pairs: Vec<(Vec<u8>, String)>,
    /// Notes that open with the given key mask: the seeds.
    seeds: Vec<(u8, Vec<u8>)>,
}

/// Key mask bits: 1 the key of sum.golang.org, 2 alpha, 4 beta, 8 gamma.
fn note_data() -> &'static NoteData {
    static D: OnceLock<NoteData> = OnceLock::new();
    D.get_or_init(|| {
        let mut d = NoteData { keys: Vec::new(), pairs: Vec::new(), seeds: Vec::new() };
        let mut texts: Vec<(String, Vec<u8>)> = Vec::new();
        let mut sigs: Vec<(String, String, String)> = Vec::new();
        for line in include_str!("../../tests/data/note_fixtures.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let mut p = line.splitn(4, ' ');
            match p.next().unwrap() {
                "key" => d.keys.push((p.next().unwrap().to_string(), p.next().unwrap().to_string())),
                "text" => texts.push((p.next().unwrap().to_string(), unhex(p.next().unwrap()))),
                "sig" => sigs.push((p.next().unwrap().to_string(), p.next().unwrap().to_string(), p.next().unwrap().to_string())),
                _ => panic!("{line}"),
            }
        }
        for (text_label, key_label, line) in &sigs {
            let text = &texts.iter().find(|(l, _)| l == text_label).unwrap().1;
            let _ = key_label;
            d.pairs.push((text.clone(), line.strip_prefix("\u{2014} ").unwrap().to_string()));
        }
        for (text_label, text) in &texts {
            let lines = |keys: &[&str]| -> Vec<u8> {
                let mut n = text.clone();
                n.push(b'\n');
                for k in keys {
                    let (_, _, line) = sigs.iter().find(|(t, kl, _)| t == text_label && kl == k).unwrap();
                    n.extend_from_slice(line.as_bytes());
                    n.push(b'\n');
                }
                n
            };
            d.seeds.push((0b1110, lines(&["alpha"])));
            d.seeds.push((0b1110, lines(&["alpha", "beta", "gamma"])));
            d.seeds.push((0b0010, lines(&["beta", "alpha"])));
            d.seeds.push((0b1000, lines(&["gamma", "gamma", "alpha"])));
        }
        let real = sumdb::verifier();
        let at = REAL_LOOKUP.windows(2).position(|w| w == b"\n\n").unwrap() + 2;
        for bytes in [REAL_LATEST, &REAL_LOOKUP[at..]] {
            let n = note::open(bytes, std::slice::from_ref(&real)).unwrap();
            for s in &n.signatures {
                d.pairs.push((n.text.clone().into_bytes(), format!("{} {}", s.name, s.base64)));
            }
            d.seeds.push((1, bytes.to_vec()));
        }
        d
    })
}

fn note_known(mask: u8) -> Vec<Verifier> {
    let d = note_data();
    let mut known = Vec::new();
    if mask & 1 != 0 {
        known.push(sumdb::verifier());
    }
    for (bit, label) in [(2, "alpha"), (4, "beta"), (8, "gamma")] {
        if mask & bit != 0 {
            let vkey = &d.keys.iter().find(|(l, _)| l == label).unwrap().1;
            known.push(Verifier::from_key(vkey).unwrap());
        }
    }
    known
}

pub fn seeds_note() -> Vec<Vec<u8>> {
    let d = note_data();
    let mut seeds: Vec<Vec<u8>> = d.seeds.iter().map(|(mask, note)| [&[*mask][..], note].concat()).collect();
    // a few damaged ones and keys
    for (mask, note) in d.seeds.iter().step_by(3) {
        let mut broken = note.clone();
        let n = broken.len();
        broken[n - 6] ^= 1;
        seeds.push([&[*mask][..], &broken].concat());
        let mut no_blank = note.clone();
        no_blank.retain(|b| *b != b'\n');
        seeds.push([&[*mask][..], &no_blank].concat());
    }
    for (_, vkey) in &d.keys {
        seeds.push([&[0xc0][..], vkey.as_bytes()].concat());
    }
    seeds.push([&[0xc0][..], sumdb::KEY.as_bytes()].concat());
    seeds
}

pub const NOTE_DICT: &[&[u8]] = &[
    b"\n\n",
    b"\xe2\x80\x94 ",
    b"go.sum database tree\n",
    b"sum.golang.org",
    b"alpha.example",
    b"beta.example",
    b"gamma.example",
    b"AA==",
    b"=",
    b"+",
    b" ",
    b"\n",
    b"\xc2\xa0",
    b"\x00",
    b"\r",
];

pub fn note(data: &[u8]) {
    let mut inp = Input::new(data);
    let sel = inp.byte();
    let rest = inp.rest();
    if sel >> 6 == 3 {
        return verifier_key(rest);
    }
    let known = note_known(sel & 0x0f);
    let d = note_data();
    match note::open(rest, &known) {
        Ok(n) => {
            assert!(!known.is_empty(), "a note opened with no key to check it with");
            assert!(!n.signatures.is_empty());
            assert!(n.text.ends_with('\n') && rest.starts_with(n.text.as_bytes()), "the text is not the start of the note");
            let mut seen: Vec<(&str, u32)> = Vec::new();
            for s in &n.signatures {
                assert!(known.iter().any(|v| v.name() == s.name && v.key_hash() == s.hash), "a signature by a key that was not given");
                assert!(!seen.contains(&(s.name.as_str(), s.hash)), "one key counted twice");
                seen.push((&s.name, s.hash));
                let line = format!("{} {}", s.name, s.base64);
                assert!(
                    d.pairs.iter().any(|(t, l)| t == n.text.as_bytes() && *l == line),
                    "a signature that is not a known good one verified: text {:?} line {line:?}",
                    n.text
                );
            }
        }
        Err(note::Error::Unverified(n)) => {
            assert!(n.signatures.is_empty() && rest.starts_with(n.text.as_bytes()));
        }
        Err(_) => {}
    }
}

fn verifier_key(rest: &[u8]) {
    let s = String::from_utf8_lossy(rest);
    let Ok(v) = Verifier::from_key(&s) else { return };
    let printed = v.key_string().expect("a key read from a string has a string");
    assert_eq!(Verifier::from_key(&printed).as_ref(), Ok(&v), "a key does not read back as itself");
    let (name, tail) = printed.split_once('+').unwrap();
    let (hash, _) = tail.split_once('+').unwrap();
    assert_eq!(name, v.name());
    assert_eq!(u32::from_str_radix(hash, 16).unwrap(), v.key_hash());
    let mut given = s.splitn(3, '+');
    assert_eq!(given.next(), Some(name));
    assert_eq!(given.next().map(str::to_ascii_lowercase).as_deref(), Some(hash));
}

// ======================================================================================== tlog

/// The largest power of two below `n` (n >= 2).
fn lpt(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

/// The root an audit path leads to, RFC 6962 section 2.1.1 read backwards: the last hash of the
/// proof is the sibling at the top. `None` if the proof is not exactly as long as the path.
fn ref_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash]) -> Option<Hash> {
    if size == 1 {
        return if proof.is_empty() { Some(*leaf) } else { None };
    }
    let (last, rest) = proof.split_last()?;
    let k = lpt(size);
    if index < k {
        Some(tlog::node_hash(&ref_inclusion(index, k, leaf, rest)?, last))
    } else {
        Some(tlog::node_hash(last, &ref_inclusion(index - k, size - k, leaf, rest)?))
    }
}

/// The two roots a consistency proof leads to, RFC 6962 section 2.1.2 (`SUBPROOF(m, D[n], b)`) read
/// backwards: `(old, new)`. `old_root` is what the proof does not repeat when the old tree is a
/// complete subtree.
fn ref_consistency(m: u64, n: u64, b: bool, old_root: &Hash, proof: &[Hash]) -> Option<(Hash, Hash)> {
    if m == n {
        return match (b, proof) {
            (true, []) => Some((*old_root, *old_root)),
            (false, [h]) => Some((*h, *h)),
            _ => None,
        };
    }
    let (last, rest) = proof.split_last()?;
    let k = lpt(n);
    if m <= k {
        let (o, nw) = ref_consistency(m, k, b, old_root, rest)?;
        Some((o, tlog::node_hash(&nw, last)))
    } else {
        let (o, nw) = ref_consistency(m - k, n - k, false, old_root, rest)?;
        Some((tlog::node_hash(last, &o), tlog::node_hash(last, &nw)))
    }
}

fn tlog_inclusion(inp: &mut Input) {
    let mut size = inp.u64();
    let mut index = inp.u64();
    let flags = inp.byte();
    let leaf = inp.hash();
    let mut root = inp.hash();
    let proof = hashes(inp.rest());
    size >>= (flags >> 2) % 64;
    if flags & 2 == 0 {
        index %= size.max(1);
    }
    let reference = if (1..=tlog::MAX_TREE_SIZE).contains(&size) && index < size { ref_inclusion(index, size, &leaf, &proof) } else { None };
    if flags & 1 != 0 {
        if let Some(r) = reference {
            root = r; // the right root for this proof: it must be accepted
        }
    }
    let ok = tlog::verify_inclusion(&proof, size, &root, index, &leaf).is_ok();
    assert_eq!(ok, reference == Some(root), "inclusion proof of {index} in {size}: the checker says {ok}, the reference says {reference:?}");
}

fn tlog_consistency(inp: &mut Input) {
    let mut old = inp.u64();
    let mut new = inp.u64();
    let flags = inp.byte();
    let mut old_root = inp.hash();
    let mut new_root = inp.hash();
    let proof = hashes(inp.rest());
    let shift = (flags >> 2) % 64;
    new >>= shift;
    old >>= shift;
    if flags & 16 == 0 && new > 0 {
        old = old % new + 1; // 1 <= old <= new
    }
    let sizes_ok = old >= 1 && old <= new && new <= tlog::MAX_TREE_SIZE;
    if sizes_ok {
        if let Some((o, n)) = ref_consistency(old, new, true, &old_root, &proof) {
            // the roots this proof leads to, which must be accepted (when the old tree is complete the
            // proof does not repeat its root, so `o` is the root given and nothing changes)
            if flags & 2 != 0 {
                old_root = o;
            }
            if flags & 1 != 0 {
                new_root = n;
            }
        }
    }
    let expected = sizes_ok && ref_consistency(old, new, true, &old_root, &proof).map_or(false, |(o, n)| o == old_root && n == new_root);
    let ok = tlog::verify_consistency(&proof, old, &old_root, new, &new_root).is_ok();
    assert_eq!(ok, expected, "consistency proof of {old} in {new}: the checker says {ok}, the reference says {expected}");
}

fn tlog_tile_path(inp: &mut Input) {
    let flags = inp.byte();
    if flags & 1 == 0 {
        let text = String::from_utf8_lossy(inp.rest()).into_owned();
        if let Ok(t) = Tile::parse_path(&text) {
            assert_eq!(t.path(), text, "a tile path does not print back as itself");
            assert!(t.validate().is_ok());
            assert_eq!(Tile::parse_path(&t.full().path()), Ok(t.full()));
        }
    } else {
        let height = inp.byte() as u32 % 34;
        let level = inp.byte() as u32 % 40;
        let shift = inp.byte() % 64;
        let index = inp.u64() >> shift;
        let width = inp.u16() as u32 % 300;
        let t = Tile { height, level, index, width };
        if t.validate().is_ok() {
            assert_eq!(Tile::parse_path(&t.path()), Ok(t), "{t:?}");
        }
    }
}

/// A tree of `n` leaves built the plain way: `levels[l][i]` is the hash of the `2^l` leaves from
/// leaf `i << l`.
struct RefTree {
    levels: Vec<Vec<Hash>>,
}

impl RefTree {
    fn new(n: u64) -> RefTree {
        let leaves: Vec<Hash> = (0..n).map(|i| tlog::record_hash(&i.to_le_bytes())).collect();
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() >= 2 {
            let next = levels.last().unwrap().chunks_exact(2).map(|p| tlog::node_hash(&p[0], &p[1])).collect();
            levels.push(next);
        }
        RefTree { levels }
    }

    fn mth(&self, lo: u64, hi: u64) -> Hash {
        let n = hi - lo;
        if n.is_power_of_two() && lo % n == 0 {
            return self.levels[n.trailing_zeros() as usize][(lo / n) as usize];
        }
        let k = lpt(n);
        tlog::node_hash(&self.mth(lo, lo + k), &self.mth(lo + k, hi))
    }

    fn tile_data(&self, t: &Tile) -> Vec<u8> {
        let level = (t.height * t.level) as usize;
        let start = (t.index << t.height) as usize;
        let entries = self.levels.get(level).and_then(|l| l.get(start..start + t.width as usize)).unwrap_or_else(|| panic!("the plan asks for a tile outside the tree: {t:?}"));
        entries.concat()
    }
}

enum Job {
    Record { id: u64, leaf: Hash },
    Prefix { older: Tree },
}

fn run_job(job: &Job, tree: &Tree, height: u32, tiles: &TileSet) -> Result<(), tlog::Error> {
    match job {
        Job::Record { id, leaf } => tlog::check_record(tree, height, *id, leaf, tiles),
        Job::Prefix { older } => tlog::check_prefix(older, tree, height, tiles),
    }
}

fn tlog_tiles(inp: &mut Input) {
    let height = 1 + inp.byte() as u32 % 4;
    let n = 1 + inp.u16() as u64 % if height == 1 { 300 } else { 700 };
    let kind = inp.byte();
    let which = inp.u16() as u64;
    let (pick, off, xor) = (inp.u16() as usize, inp.u16() as usize, inp.byte().max(1));

    let rt = RefTree::new(n);
    let tree = Tree { size: n, root: rt.mth(0, n) };
    let (job, plan, wrong) = if kind & 1 == 0 {
        let id = which % n;
        let leaf = rt.levels[0][id as usize];
        let plan = tlog::tiles_for_record(&tree, height, id).expect("a plan for a record inside the tree");
        let mut other = leaf;
        other[0] ^= 1;
        (Job::Record { id, leaf }, plan, Job::Record { id, leaf: other })
    } else {
        let m = 1 + which % n;
        let older = Tree { size: m, root: rt.mth(0, m) };
        let plan = tlog::tiles_for_prefix(&tree, height, m).expect("a plan for a prefix");
        let mut bad = older;
        bad.root[0] ^= 1;
        (Job::Prefix { older }, plan, Job::Prefix { older: bad })
    };
    let mut data: Vec<(Tile, Vec<u8>)> = plan.iter().map(|t| (*t, rt.tile_data(t))).collect();
    let damage = (kind >> 1) % 5;
    let mut damaged = false;
    if !data.is_empty() {
        let i = pick % data.len();
        match damage {
            1 => {
                let len = data[i].1.len();
                data[i].1[off % len] ^= xor;
                damaged = true;
            }
            2 => {
                data.remove(i);
                damaged = true;
            }
            _ => {}
        }
    }
    let mut set = TileSet::new();
    for (t, d) in data {
        set.insert(t, d).expect("tile data of the right length");
    }
    if damage == 3 {
        // a stray tile nobody asked for changes nothing
        let _ = set.insert(Tile { height, level: 0, index: n / (1 << height) + 5, width: 1 }, vec![xor; 32]);
    }
    let verdict = run_job(&job, &tree, height, &set);
    if damaged {
        assert!(verdict.is_err(), "a tile of the plan was changed or left out ({damage}, tile {pick}, byte {off}) and the check still passed: size {n}, height {height}");
    } else {
        assert_eq!(verdict, Ok(()), "genuine tiles were refused: size {n}, height {height}");
        assert!(run_job(&wrong, &tree, height, &set).is_err(), "a wrong leaf or root passed");
    }
}

pub fn seeds_tlog() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let h = |i: u8| vec![i; 32];
    // inclusion proofs of the right length for assorted shapes, with the right root asked for
    for (size, index, depth) in [(1u64, 0u64, 0usize), (2, 1, 1), (3, 2, 1), (5, 4, 1), (7, 3, 3), (8, 5, 3), (13, 9, 4), (100, 63, 7), (1 << 40, 12345, 40)] {
        let mut s = vec![0u8];
        s.extend_from_slice(&size.to_le_bytes());
        s.extend_from_slice(&index.to_le_bytes());
        s.push(3);
        s.extend(h(1));
        s.extend(h(2));
        for d in 0..depth {
            s.extend(h(10 + d as u8));
        }
        seeds.push(s);
    }
    // consistency proofs: the length depends on the pair
    for (old, new, depth) in [(1u64, 1u64, 0usize), (1, 2, 1), (2, 5, 2), (3, 7, 3), (4, 8, 1), (6, 8, 3), (7, 13, 4), (50, 100, 6)] {
        let mut s = vec![1u8];
        s.extend_from_slice(&old.to_le_bytes());
        s.extend_from_slice(&new.to_le_bytes());
        s.push(3 | 16);
        s.extend(h(1));
        s.extend(h(2));
        for d in 0..depth {
            s.extend(h(20 + d as u8));
        }
        seeds.push(s);
    }
    for path in ["tile/8/0/000", "tile/8/0/x097/482", "tile/8/1/x001/018.p/122", "tile/8/2/003.p/250", "tile/8/3/000.p/3", "tile/30/62/x999/999.p/2", "tile/1/0/001", "tile/8/0/000.p/0"] {
        seeds.push([&[2u8, 0][..], path.as_bytes()].concat());
    }
    // tile authentication: (height, size, kind, which, pick, offset, xor)
    for (height, n, kind) in [(1u8, 5u16, 0u8), (1, 37, 1), (2, 100, 2), (2, 63, 3), (3, 400, 4), (3, 511, 5), (4, 650, 6), (4, 33, 7)] {
        let mut s = vec![3u8, height - 1];
        s.extend_from_slice(&(n - 1).to_le_bytes());
        s.push(kind);
        s.extend_from_slice(&7u16.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
        s.extend_from_slice(&5u16.to_le_bytes());
        s.push(0x40);
        seeds.push(s);
    }
    seeds
}

pub const TLOG_DICT: &[&[u8]] = &[b"tile/", b"/entries", b".p/", b"/x001/", b"/x", b"/000", b"/255", b"/1/", b"/8/", b"tile/8/", b"\x00\x00\x00\x00\x00\x00\x00\x40", b"\xff\xff\xff\xff\xff\xff\xff\x7f"];

pub fn tlog(data: &[u8]) {
    let mut inp = Input::new(data);
    match inp.byte() % 4 {
        0 => tlog_inclusion(&mut inp),
        1 => tlog_consistency(&mut inp),
        2 => tlog_tile_path(&mut inp),
        _ => tlog_tiles(&mut inp),
    }
}

// ======================================================================================== sumdb

struct Synth {
    verifier: Verifier,
    /// `(name, note)`, h200 and h300 of history H, f250 and f300 of history F.
    heads: Vec<(String, Vec<u8>)>,
    /// `(name, module, version, response)`.
    lookups: Vec<(String, String, String, Vec<u8>)>,
    /// `(history, tile, data)`.
    tiles: Vec<(char, Tile, Vec<u8>)>,
    /// The text of each head with the history it belongs to and its size.
    head_texts: Vec<(String, char, u64)>,
    /// `(id, text, history)` of the records the log has (`B` for both histories).
    records: Vec<(u64, String, char)>,
}

fn synth() -> &'static Synth {
    static S: OnceLock<Synth> = OnceLock::new();
    S.get_or_init(|| {
        let mut s = Synth { verifier: sumdb::verifier(), heads: Vec::new(), lookups: Vec::new(), tiles: Vec::new(), head_texts: Vec::new(), records: Vec::new() };
        for line in include_str!("../../tests/data/sumdb_synthetic.txt").lines().filter(|l| !l.starts_with('#')) {
            let p: Vec<&str> = line.split(' ').collect();
            match p[0] {
                "key" => s.verifier = Verifier::from_key(p[1]).unwrap(),
                "head" => s.heads.push((p[1].to_string(), unhex(p[2]))),
                "lookup" => s.lookups.push((p[1].to_string(), p[2].to_string(), p[3].to_string(), unhex(p[4]))),
                "tile" => s.tiles.push((p[1].chars().next().unwrap(), Tile::parse_path(p[2]).unwrap(), unhex(p[3]))),
                _ => panic!("{line}"),
            }
        }
        for (name, bytes) in &s.heads {
            let text = note::open(bytes, std::slice::from_ref(&s.verifier)).unwrap().text;
            let size = sumdb::parse_tree(&text).unwrap().size;
            let history = if name.starts_with('h') { 'H' } else { 'F' };
            s.head_texts.push((text, history, size));
        }
        for (name, _, _, response) in &s.lookups {
            let (id, text, _) = sumdb::parse_record(response).unwrap();
            let history = match name.as_str() {
                "h300_17" => 'H',
                "f300_17" | "mix_17" => 'F',
                _ => 'B',
            };
            if !s.records.iter().any(|(i, t, _)| *i == id && t == text) {
                s.records.push((id, text.to_string(), history));
            }
        }
        s
    })
}

pub fn seeds_sumdb() -> Vec<Vec<u8>> {
    let s = synth();
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    // op 0: tree heads, 1: lookup responses, 2: lookup paths
    for text in ["go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n", "go.sum database tree\n0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nmore\n"] {
        seeds.push([&[0u8][..], text.as_bytes()].concat());
    }
    seeds.push([&[1u8][..], REAL_LOOKUP].concat());
    for (_, _, _, r) in s.lookups.iter().take(2) {
        seeds.push([&[1u8][..], r].concat());
    }
    for (m, v) in [("golang.org/x/mod", "v0.17.0"), ("github.com/BurntSushi/toml", "v1.0.0-RC1"), ("example.com/x", "v1.0.0/go.mod"), ("example.com//x", "v1")] {
        seeds.push([&[2u8][..], m.as_bytes(), b"\n", v.as_bytes()].concat());
    }
    // op 3: scenarios over the made-up log: (item selectors), tile history
    let scenarios: [(&[u8], u8); 8] = [
        (&[0, 5], 0),        // h200, then the lookup of record 250 under h300: one history
        (&[1, 3], 0),        // h300 and f300: a fork of equal size
        (&[0, 3], 1),        // h200 and f300 with F's tiles
        (&[1, 2], 0),        // h300 and f250
        (&[5, 6, 4], 0),     // lookups under one head
        (&[7], 1),           // the forked record 17 under its own head
        (&[8], 0),           // the forked record under the honest head
        (&[2, 1, 5, 4], 2),  // all sorts
    ];
    for (items, hist) in scenarios {
        let mut sd = vec![3u8, items.len() as u8 - 1];
        for it in items {
            sd.extend_from_slice(&[*it, 0, 0, 0, 0]);
        }
        sd.push(hist);
        sd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        seeds.push(sd);
    }
    // op 4: raw head and response, real key and made-up key
    seeds.push([&[4u8, 0][..], REAL_LATEST, b"\0", REAL_LOOKUP].concat());
    seeds.push([&[4u8, 1][..], &s.heads[1].1, b"\0", &s.lookups[0].3].concat());
    seeds
}

pub const SUMDB_DICT: &[&[u8]] = &[b"go.sum database tree\n", b"\n\n", b"\n", b"\xe2\x80\x94 sum.golang.org ", b"example.com/m250", b"v1.0.0", b"/go.mod", b"!", b"0", b"9223372036854775807", b"4611686018427387904", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", b"golang.org/x/mod v0.17.0 h1:"];

fn unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '!' {
            let n = it.next()?;
            if !n.is_ascii_lowercase() {
                return None;
            }
            out.push(n.to_ascii_uppercase());
        } else if c.is_ascii_uppercase() {
            return None;
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn sumdb_parse(inp: &mut Input, op: u8) {
    let rest = inp.rest();
    match op {
        0 => {
            let Ok(text) = std::str::from_utf8(rest) else { return };
            if let Ok(t) = sumdb::parse_tree(text) {
                assert!(t.size <= tlog::MAX_TREE_SIZE);
                assert!(text.starts_with(&sumdb::format_tree(&t)), "a tree head does not print back as what was parsed: {text:?}");
            }
        }
        1 => {
            if let Ok((id, text, tail)) = sumdb::parse_record(rest) {
                assert!(text.ends_with('\n') && !text.contains("\n\n") && !text.chars().any(|c| c < ' ' && c != '\n'));
                let mut again = format!("{id}\n{text}\n").into_bytes();
                again.extend_from_slice(tail);
                assert_eq!(again, rest, "a lookup response does not print back as what was parsed");
            }
        }
        _ => {
            let text = String::from_utf8_lossy(rest).into_owned();
            let (module, version) = text.split_once('\n').unwrap_or((&text, "v1.0.0"));
            if let Ok(path) = sumdb::lookup_path(module, version) {
                let tail = path.strip_prefix("lookup/").expect("a lookup path starts with lookup/");
                assert!(tail.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._~+/!@-".contains(&b)), "{path:?}");
                let (m, v) = tail.split_once('@').expect("a lookup path has an @");
                assert!(!v.contains('@') && !m.contains("//") && !m.starts_with('/') && !m.ends_with('/'));
                assert_eq!(unescape(m).as_deref(), Some(module), "{path:?}");
                assert_eq!(unescape(v).as_deref(), Some(version.strip_suffix("/go.mod").unwrap_or(version)), "{path:?}");
            }
        }
    }
}

/// Heads and lookups of the made-up log, damaged by the input, checked against tiles of either
/// history (or both, one over the other), also damaged. Whatever is accepted must be genuine and of
/// one history.
fn sumdb_made_up(inp: &mut Input) {
    let s = synth();
    let items = 1 + inp.byte() % 4;
    let mut check = Check::new(s.verifier.clone());
    let mut added: Vec<(u8, Vec<u8>)> = Vec::new();
    for _ in 0..items {
        let sel = inp.byte() % 9;
        let (edit, off, xor) = (inp.byte(), inp.u16() as usize, inp.byte());
        let mut data = if sel < 4 { s.heads[sel as usize].1.clone() } else { s.lookups[sel as usize - 4].3.clone() };
        if edit & 1 != 0 {
            let i = off % data.len();
            data[i] ^= xor;
        }
        let ok = if sel < 4 {
            check.add_head(&data).is_ok()
        } else {
            let (_, module, version, _) = &s.lookups[sel as usize - 4];
            check.add_lookup(module, version, &data).is_ok()
        };
        if ok {
            added.push((sel, data));
        }
    }
    let history = inp.byte() % 3;
    let mut tiles: Vec<(Tile, Vec<u8>)> = Vec::new();
    for (h, tile, data) in &s.tiles {
        if history == 2 || (history == 0) == (*h == 'H') {
            tiles.retain(|(t, _)| t != tile);
            tiles.push((*tile, data.clone()));
        }
    }
    if history == 2 {
        // F over H: the tiles of the second history replace the first's where they overlap
        for (h, tile, data) in &s.tiles {
            if *h == 'F' {
                tiles.retain(|(t, _)| t != tile);
                tiles.push((*tile, data.clone()));
            }
        }
    }
    for _ in 0..2 {
        let (pick, off, xor) = (inp.u16() as usize, inp.u16() as usize, inp.byte());
        if xor != 0 && !tiles.is_empty() {
            let i = pick % tiles.len();
            let len = tiles[i].1.len();
            tiles[i].1[off % len] ^= xor;
        }
    }
    let mut set = TileSet::new();
    for (t, d) in tiles {
        let _ = set.insert(t, d);
    }
    let Ok(outcome) = check.finish(&set) else { return };

    // everything accepted is genuine, and all of it is of one history
    let mut histories: Vec<char> = Vec::new();
    let mut latest = 0u64;
    let known_head = |bytes: &[u8]| -> (char, u64) {
        let text = note::open(bytes, std::slice::from_ref(&s.verifier)).expect("an accepted head opens").text;
        let (_, h, size) = s.head_texts.iter().find(|(t, _, _)| *t == text).unwrap_or_else(|| panic!("accepted a tree head that was never signed: {text:?}"));
        (*h, *size)
    };
    for (sel, data) in &added {
        let head_bytes: &[u8] = if *sel < 4 {
            data
        } else {
            let (id, text, tail) = sumdb::parse_record(data).expect("an accepted response parses");
            let (_, _, history) = s.records.iter().find(|(i, t, _)| *i == id && t == text).unwrap_or_else(|| panic!("accepted a record the log never had: {id} {text:?}"));
            histories.push(*history);
            tail
        };
        let (h, size) = known_head(head_bytes);
        histories.push(h);
        latest = latest.max(size);
    }
    histories.retain(|h| *h != 'B');
    histories.dedup();
    assert!(histories.len() <= 1, "two histories were accepted together: {histories:?} ({added:?})");
    assert_eq!(outcome.latest.size, latest, "the latest head is not the largest one added");
    if latest > 0 {
        assert_eq!(known_head(&outcome.latest_note).1, latest);
    } else {
        assert!(outcome.latest_note.is_empty() && outcome.records.is_empty());
    }
}

/// Raw bytes as a head and as a lookup response, against the real key or the made-up one. Nothing
/// is accepted that was not signed.
fn sumdb_raw(inp: &mut Input) {
    let s = synth();
    let real = inp.byte() & 1 == 0;
    let rest = inp.rest();
    let (head, response) = match rest.iter().position(|b| *b == 0) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &rest[..0]),
    };
    let (verifier, known_texts): (Verifier, Vec<String>) = if real {
        let v = sumdb::verifier();
        let at = REAL_LOOKUP.windows(2).position(|w| w == b"\n\n").unwrap() + 2;
        let texts = [REAL_LATEST, &REAL_LOOKUP[at..]].iter().map(|b| note::open(b, std::slice::from_ref(&v)).unwrap().text).collect();
        (v, texts)
    } else {
        (s.verifier.clone(), s.head_texts.iter().map(|(t, _, _)| t.clone()).collect())
    };
    let mut check = Check::new(verifier.clone());
    if check.add_head(head).is_ok() {
        let text = note::open(head, std::slice::from_ref(&verifier)).unwrap().text;
        assert!(known_texts.contains(&text), "accepted a tree head that was never signed: {text:?}");
    }
    if check.add_lookup("example.com/m250", "v1.0.0", response).is_ok() {
        let (_, _, tail) = sumdb::parse_record(response).unwrap();
        let text = note::open(tail, std::slice::from_ref(&verifier)).unwrap().text;
        assert!(known_texts.contains(&text), "accepted a lookup under a tree head that was never signed: {text:?}");
    }
    if let Ok(tiles) = check.tiles_needed() {
        for t in tiles {
            assert!(t.validate().is_ok());
            assert_eq!(Tile::parse_path(&t.path()), Ok(t));
        }
    }
    let _ = check.finish(&TileSet::new());
}

pub fn sumdb(data: &[u8]) {
    let mut inp = Input::new(data);
    match inp.byte() % 5 {
        op @ 0..=2 => sumdb_parse(&mut inp, op),
        3 => sumdb_made_up(&mut inp),
        _ => sumdb_raw(&mut inp),
    }
}
