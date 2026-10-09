//! The Go checksum database, `sum.golang.org`: checking what it says the way the `go` command does,
//! with the fetching left to the caller.
//!
//! The database is a transparency log of `go.sum` lines. For each `module@version` it holds one
//! record, the module's two lines
//!
//! ```text
//! golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=
//! golang.org/x/mod v0.17.0/go.mod h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c=
//! ```
//!
//! and signs the root of the Merkle tree over all records (a *tree head*, a signed note whose text
//! is `go.sum database tree`, the number of records and the root hash). A server that tells two
//! clients different things about one module has to show two different trees, and a client that
//! remembers the last tree head it saw can notice: the new tree must contain the old one. That is
//! what makes the database useful against a malicious module proxy, which cannot sign.
//!
//! # What a check does
//!
//! For each lookup response (`GET /lookup/<module>@<version>`: the record number, the record, a blank
//! line and a tree head note) [`Check`] does what `sumdb.Client.Lookup` in Go's `x/mod` does:
//!
//! 1. checks the tree head's signature against the pinned key ([`KEY`]) and reads the tree;
//! 2. merges the tree into the timeline of heads it has seen: a newer head must contain the latest
//!    one and an older head must be contained in it (a mismatch is [`tlog::Error::Fork`]: the log
//!    has told two stories);
//! 3. checks that the record's hash is the leaf the log has at that number, using authenticated
//!    tiles ([`tlog`]);
//! 4. returns the lines of the record that start with `<module> <version> `, and refuses the record if there
//!    are none (a genuine record of another module is not an answer about this one).
//!
//! Nothing is believed until the signature has been checked and every tile has been authenticated
//! against the signed root (see [`tlog`]). [`Check`] is sans-IO: you add what the server returned,
//! ask which tiles are needed, fetch them, and finish.
//!
//! ```no_run
//! use pratique::sumdb::{self, Check};
//! use pratique::tlog::{Tile, TileSet};
//! # fn get(path: &str) -> Option<Vec<u8>> { unimplemented!() }
//!
//! let mut check = Check::new(sumdb::verifier());
//! // a head saved by an earlier run goes first, if there is one: check.add_head(&saved_note)?;
//! let response = get(&sumdb::lookup_path("golang.org/x/mod", "v0.17.0")?).unwrap();
//! check.add_lookup("golang.org/x/mod", "v0.17.0", &response)?;
//!
//! let mut tiles = TileSet::new();
//! for tile in check.tiles_needed()? {
//!     // a partial tile that is gone is served as the full tile
//!     let data = get(&tile.path()).or_else(|| get(&tile.full().path())).unwrap();
//!     tiles.insert(if data.len() as u64 == tile.data_len() { tile } else { tile.full() }, data)?;
//! }
//! let outcome = check.finish(&tiles)?;
//! for line in &outcome.records[0].lines {
//!     println!("{line}");
//! }
//! // outcome.latest_note is the head to keep for next time
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Differences from Go
//!
//! Decisions stricter than Go's, none looser: Base64 must be canonical; a record number or tree size
//! is plain decimal digits (no sign, no leading zeros; a tree size is at most 2^62); module paths and versions in
//! [`lookup_path`] are limited to the characters real ones use (the Go functions accept a few more);
//! lines are taken from the record only, where Go scans the whole response; a lookup whose record has no line
//! for the module and version is an error, where Go returns no lines; two signed heads of equal
//! size with different roots are a fork on their own (Go reads tiles to find that out); and the
//! tiles are always fully authenticated (Go before x/mod 0.40.0 was not, CVE-2026-56865).

use std::collections::BTreeSet;
use std::fmt;

use crate::note::{self, Verifier};
use crate::pem::{base64_decode_strict, base64_encode};
use crate::tlog::{self, Hash, Tile, TileSet, Tree, MAX_TREE_SIZE};

/// The verifier key of `sum.golang.org`, as pinned in the Go toolchain (`cmd/go/internal/modfetch`).
pub const KEY: &str = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

/// The height of the database's tiles.
pub const TILE_HEIGHT: u32 = 8;

const TREE_PREFIX: &str = "go.sum database tree\n";

/// The pinned key of `sum.golang.org` as a [`Verifier`].
pub fn verifier() -> Verifier {
    Verifier::from_key(KEY).expect("the pinned key of sum.golang.org is well-formed")
}

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The tree head note is not signed by the key (or is malformed).
    Note(note::Error),
    /// The log's hashes do not check out: a bad tile, a missing tile, or a fork.
    Log(tlog::Error),
    /// The note's text is not a tree description.
    MalformedTree,
    /// The record is not a lookup response.
    MalformedRecord,
    /// The module path or version cannot be looked up.
    BadName(&'static str),
    /// The record number is not inside the tree (`id >= size`), so it cannot be checked.
    RecordOutsideTree { id: u64, size: u64 },
    /// The record holds no line for the module and version asked about. The record may be genuine (a server, or
    /// someone in between, answered with the record of another module or version), but it says nothing about this one.
    NoLineForVersion { module: String, version: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Note(e) => write!(f, "reading tree note: {e}"),
            Error::Log(e) => write!(f, "{e}"),
            Error::MalformedTree => write!(f, "malformed tree note"),
            Error::MalformedRecord => write!(f, "malformed record data"),
            Error::BadName(m) => write!(f, "cannot look up: {m}"),
            Error::RecordOutsideTree { id, size } => write!(f, "cannot validate record {id} in tree of size {size}"),
            Error::NoLineForVersion { module, version } => write!(f, "the record has no go.sum line for {module} {version}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<note::Error> for Error {
    fn from(e: note::Error) -> Error {
        Error::Note(e)
    }
}

impl From<tlog::Error> for Error {
    fn from(e: tlog::Error) -> Error {
        Error::Log(e)
    }
}

fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    // What fits an int64, as in Go (`strconv.ParseInt`); a tree size is held to less by the caller.
    s.parse::<u64>().ok().filter(|n| *n <= i64::MAX as u64)
}

/// Reads the text of a tree head: `go.sum database tree`, the size, the root in Base64, each on a
/// line. Further lines are ignored, as in Go.
pub fn parse_tree(text: &str) -> Result<Tree, Error> {
    if !text.starts_with(TREE_PREFIX) || text.matches('\n').count() < 3 || text.len() > 1_000_000 {
        return Err(Error::MalformedTree);
    }
    let mut lines = text.splitn(4, '\n');
    lines.next();
    let size = lines.next().and_then(decimal).filter(|n| *n <= MAX_TREE_SIZE).ok_or(Error::MalformedTree)?;
    let root = lines.next().and_then(base64_decode_strict).ok_or(Error::MalformedTree)?;
    let root: Hash = root.try_into().map_err(|_| Error::MalformedTree)?;
    Ok(Tree { size, root })
}

/// The text of a tree head, as the server signs it.
pub fn format_tree(tree: &Tree) -> String {
    format!("{TREE_PREFIX}{}\n{}\n", tree.size, base64_encode(&tree.root))
}

fn valid_record_text(text: &str) -> bool {
    let mut last = '\0';
    for c in text.chars() {
        if (c < ' ' && c != '\n') || (last == '\n' && c == '\n') {
            return false;
        }
        last = c;
    }
    last == '\n'
}

/// Splits a lookup response into the record number, the record text (the `go.sum` lines, each
/// ending in a newline) and the rest, which is the signed tree head.
pub fn parse_record(response: &[u8]) -> Result<(u64, &str, &[u8]), Error> {
    let i = response.iter().position(|b| *b == b'\n').ok_or(Error::MalformedRecord)?;
    let id = std::str::from_utf8(&response[..i]).ok().and_then(decimal).ok_or(Error::MalformedRecord)?;
    let body = &response[i + 1..];
    let j = body.windows(2).position(|w| w == b"\n\n").ok_or(Error::MalformedRecord)?;
    let text = std::str::from_utf8(&body[..j + 1]).map_err(|_| Error::MalformedRecord)?;
    if !valid_record_text(text) {
        return Err(Error::MalformedRecord);
    }
    Ok((id, text, &body[j + 2..]))
}

/// The path (no leading slash) of the lookup for `module@version` on a checksum database server:
/// `lookup/<escaped module>@<escaped version>`, with capital letters written `!` and the lower-case
/// letter. A `/go.mod` suffix on the version is dropped, as `go` does: the record holds both lines.
///
/// Only the characters real paths and versions use are accepted: for the module ASCII letters,
/// digits and `-._~`, in non-empty `/`-separated elements that do not start with a dot; for the
/// version a leading `v`, then letters, digits and `-._~+`.
pub fn lookup_path(module: &str, version: &str) -> Result<String, Error> {
    let version = version.strip_suffix("/go.mod").unwrap_or(version);
    if module.is_empty() || module.split('/').any(|e| e.is_empty() || e.starts_with('.')) {
        return Err(Error::BadName("module path has an empty or dot element"));
    }
    if !module.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b)) {
        return Err(Error::BadName("module path has a character that is not allowed"));
    }
    if !version.starts_with('v') || !version.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~+".contains(&b)) {
        return Err(Error::BadName("version must start with v and use letters, digits and -._~+"));
    }
    let escape = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_ascii_uppercase() {
                out.push('!');
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    };
    Ok(format!("lookup/{}@{}", escape(module), escape(version)))
}

/// The path of the server's current tree head, `latest`.
pub const LATEST_PATH: &str = "latest";

/// A record that has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub module: String,
    pub version: String,
    /// The record's number in the log.
    pub id: u64,
    /// The whole record text.
    pub text: String,
    /// The lines of the record that start with `<module> <version> ` (for a version without a
    /// `/go.mod` suffix that is the module's content hash line, with the suffix the go.mod line). Never empty:
    /// [`Check::add_lookup`] refuses a record that has none.
    pub lines: Vec<String>,
}

/// What [`Check::finish`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The latest tree head seen, with its signed note: keep the note and give it to
    /// [`Check::add_head`] first next time, so the log cannot quietly rewrite what it has told you.
    pub latest: Tree,
    pub latest_note: Vec<u8>,
    /// The records added, in the order they were added.
    pub records: Vec<VerifiedRecord>,
}

#[derive(Clone, Debug)]
enum Obligation {
    /// `older` must be contained in `newer`.
    Prefix { older: Tree, newer: Tree },
    /// Record `id` of the log `tree` must hash to `hash`.
    Record { tree: Tree, id: u64, hash: Hash },
}

/// A set of checks against the checksum database: the heads and records added so far, the tiles they
/// need and, once the tiles are in, the verdict. See the module documentation.
pub struct Check {
    verifier: Verifier,
    latest: Tree,
    latest_note: Vec<u8>,
    obligations: Vec<Obligation>,
    records: Vec<VerifiedRecord>,
}

impl Check {
    /// A check that trusts `verifier` (normally [`verifier()`]) and has seen no head: it starts
    /// from the empty log.
    pub fn new(verifier: Verifier) -> Check {
        Check { verifier, latest: Tree { size: 0, root: tlog::EMPTY_ROOT }, latest_note: Vec::new(), obligations: Vec::new(), records: Vec::new() }
    }

    /// What adding the head `tree` (from the signed note `note`) to the timeline would require, and
    /// the new latest head if it is newer.
    fn merge(&self, tree: Tree, note: &[u8]) -> (Vec<Obligation>, Option<(Tree, Vec<u8>)>) {
        if tree.size <= self.latest.size {
            // an old head: it must be inside the latest
            (vec![Obligation::Prefix { older: tree, newer: self.latest }], None)
        } else {
            // a new head: it must contain the latest, and becomes the latest
            (vec![Obligation::Prefix { older: self.latest, newer: tree }], Some((tree, note.to_vec())))
        }
    }

    fn open_head(&self, note_bytes: &[u8]) -> Result<Tree, Error> {
        let opened = note::open(note_bytes, std::slice::from_ref(&self.verifier))?;
        parse_tree(&opened.text)
    }

    /// Adds a signed tree head: the server's `latest`, or a head saved by an earlier run (add that
    /// one first). The signature is checked now; whether the head belongs to the same history as the
    /// others is checked in [`Check::finish`].
    pub fn add_head(&mut self, note_bytes: &[u8]) -> Result<(), Error> {
        let tree = self.open_head(note_bytes)?;
        let (obligations, newer) = self.merge(tree, note_bytes);
        self.obligations.extend(obligations);
        if let Some((t, n)) = newer {
            self.latest = t;
            self.latest_note = n;
        }
        Ok(())
    }

    /// Adds a lookup response for `module@version` (the body of `GET /lookup/<module>@<version>`).
    /// Returns the index of the record in [`Outcome::records`]. Nothing is changed if it fails. A record with
    /// no line for `module` and `version` is an error ([`Error::NoLineForVersion`]); Go's `Lookup` returns no
    /// lines instead and leaves it to the caller, which is how a genuine record of another module, served in
    /// answer to this question, would pass for "the database has nothing to say".
    pub fn add_lookup(&mut self, module: &str, version: &str, response: &[u8]) -> Result<usize, Error> {
        let (id, text, note_bytes) = parse_record(response)?;
        let tree = self.open_head(note_bytes)?;
        let (mut obligations, newer) = self.merge(tree, note_bytes);
        let latest = newer.as_ref().map(|(t, _)| *t).unwrap_or(self.latest);
        if id >= latest.size {
            return Err(Error::RecordOutsideTree { id, size: latest.size });
        }
        obligations.push(Obligation::Record { tree: latest, id, hash: tlog::record_hash(text.as_bytes()) });
        let prefix = format!("{module} {version} ");
        let lines: Vec<String> = text.split('\n').filter(|l| l.starts_with(&prefix)).map(str::to_string).collect();
        if lines.is_empty() {
            return Err(Error::NoLineForVersion { module: module.to_string(), version: version.to_string() });
        }

        self.obligations.extend(obligations);
        if let Some((t, n)) = newer {
            self.latest = t;
            self.latest_note = n;
        }
        self.records.push(VerifiedRecord { module: module.to_string(), version: version.to_string(), id, text: text.to_string(), lines });
        Ok(self.records.len() - 1)
    }

    /// The tiles [`Check::finish`] will read, without repeats. Fetch each (see the example in the
    /// module documentation) and put it in a [`TileSet`]. Many records share most of their tiles.
    pub fn tiles_needed(&self) -> Result<Vec<Tile>, Error> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for o in &self.obligations {
            let tiles = match o {
                Obligation::Prefix { older, newer } => tlog::tiles_for_prefix(newer, TILE_HEIGHT, older.size)?,
                Obligation::Record { tree, id, .. } => tlog::tiles_for_record(tree, TILE_HEIGHT, *id)?,
            };
            for t in tiles {
                if seen.insert(t) {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }

    /// Runs every check. Only on success are the records returned: if any head is inconsistent with
    /// another, or any tile or record does not match the signed trees, it is an error and nothing
    /// is vouched for.
    pub fn finish(self, tiles: &TileSet) -> Result<Outcome, Error> {
        for o in &self.obligations {
            match o {
                Obligation::Prefix { older, newer } => tlog::check_prefix(older, newer, TILE_HEIGHT, tiles)?,
                Obligation::Record { tree, id, hash } => tlog::check_record(tree, TILE_HEIGHT, *id, hash, tiles)?,
            }
        }
        Ok(Outcome { latest: self.latest, latest_note: self.latest_note, records: self.records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlog::record_hash;

    // Captured by the author from https://sum.golang.org on 2026-10-05 with curl: `latest` and the
    // lookup of golang.org/x/mod@v0.17.0 at about 21:46 UTC, the seven tiles at 22:06 UTC. The tiles
    // are what the Go client would fetch for these two heads and the record (found by running the
    // Go code with a logging tile reader); the three partial ones were still served at their old
    // widths. See tests/data/sumdb/README.txt.
    const LATEST: &[u8] = include_bytes!("../tests/data/sumdb/latest.txt");
    const LOOKUP: &[u8] = include_bytes!("../tests/data/sumdb/lookup.txt");
    const TILES: [(&str, &[u8]); 7] = [
        ("tile/8/0/x097/482", include_bytes!("../tests/data/sumdb/tile/8/0/x097/482")),
        ("tile/8/0/x260/730.p/101", include_bytes!("../tests/data/sumdb/tile/8/0/x260/730.p/101")),
        ("tile/8/1/380", include_bytes!("../tests/data/sumdb/tile/8/1/380")),
        ("tile/8/1/x001/018.p/122", include_bytes!("../tests/data/sumdb/tile/8/1/x001/018.p/122")),
        ("tile/8/2/001", include_bytes!("../tests/data/sumdb/tile/8/2/001")),
        ("tile/8/2/003.p/250", include_bytes!("../tests/data/sumdb/tile/8/2/003.p/250")),
        ("tile/8/3/000.p/3", include_bytes!("../tests/data/sumdb/tile/8/3/000.p/3")),
    ];
    const MODULE: &str = "golang.org/x/mod";
    const VERSION: &str = "v0.17.0";
    const H1: &str = "golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=";
    const GOMOD_H1: &str = "golang.org/x/mod v0.17.0/go.mod h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c=";

    fn tile_set() -> TileSet {
        let mut set = TileSet::new();
        for (path, data) in TILES {
            set.insert(Tile::parse_path(path).unwrap(), data.to_vec()).unwrap();
        }
        set
    }

    fn paths(tiles: &[Tile]) -> Vec<String> {
        let mut p: Vec<String> = tiles.iter().map(Tile::path).collect();
        p.sort();
        p
    }

    fn all_tile_paths() -> Vec<String> {
        let mut p: Vec<String> = TILES.iter().map(|(p, _)| p.to_string()).collect();
        p.sort();
        p
    }

    /// The check of the real capture, in the order the Go client meets the data: the older head
    /// (`latest`), then the lookup, whose head is newer.
    fn real_check() -> Check {
        let mut check = Check::new(verifier());
        check.add_head(LATEST).unwrap();
        assert_eq!(check.add_lookup(MODULE, VERSION, LOOKUP).unwrap(), 0);
        check
    }

    #[test]
    fn the_pinned_key_is_what_the_go_toolchain_pins() {
        let v = verifier();
        assert_eq!((v.name(), v.key_hash()), ("sum.golang.org", 0x033de0ae));
        assert_eq!(v.key_string().as_deref(), Some(KEY));
    }

    #[test]
    fn the_real_lookup_checks_out() {
        let check = real_check();
        // the tiles the Go client reads for these two heads and this record, from the Go code
        assert_eq!(paths(&check.tiles_needed().unwrap()), all_tile_paths());
        let outcome = check.finish(&tile_set()).unwrap();
        assert_eq!(outcome.latest.size, 66746981);
        assert_eq!(crate::pem::base64_encode(&outcome.latest.root), "3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=");
        assert!(LOOKUP.ends_with(&outcome.latest_note), "the note to keep is the one from the lookup");
        assert_eq!(outcome.records.len(), 1);
        let r = &outcome.records[0];
        assert_eq!((r.module.as_str(), r.version.as_str(), r.id), (MODULE, VERSION, 24955599));
        assert_eq!(r.lines, vec![H1.to_string()]);
        assert_eq!(r.text, format!("{H1}\n{GOMOD_H1}\n"));
    }

    #[test]
    fn the_go_mod_line_is_a_lookup_of_the_same_record() {
        let mut check = Check::new(verifier());
        let i = check.add_lookup(MODULE, "v0.17.0/go.mod", LOOKUP).unwrap();
        let outcome = check.finish(&tile_set()).unwrap();
        assert_eq!(outcome.records[i].lines, vec![GOMOD_H1.to_string()]);
    }

    #[test]
    fn a_record_of_something_else_is_not_an_answer() {
        // a genuine response for golang.org/x/mod@v0.17.0, served in answer to a question about anything else
        let mut check = Check::new(verifier());
        for (module, version) in [(MODULE, "v0.17.1"), ("golang.org/x/net", VERSION), (MODULE, "v0.17"), ("golang.org/x", "v0.17.0")] {
            let err = check.add_lookup(module, version, LOOKUP).unwrap_err();
            assert_eq!(err, Error::NoLineForVersion { module: module.to_string(), version: version.to_string() });
            assert!(err.to_string().contains(module), "{err}");
        }
        // nothing was kept: no record, no tile to fetch
        assert_eq!(check.tiles_needed().unwrap(), Vec::new());
        // and the right question still works afterwards
        let i = check.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        let outcome = check.finish(&tile_set()).unwrap();
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[i].lines, vec![H1.to_string()]);
    }

    #[test]
    fn the_order_the_heads_arrive_in_does_not_matter() {
        let mut check = Check::new(verifier());
        check.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        check.add_head(LATEST).unwrap(); // the older head, after the newer: it must be inside it
        assert_eq!(paths(&check.tiles_needed().unwrap()), all_tile_paths());
        let outcome = check.finish(&tile_set()).unwrap();
        assert_eq!(outcome.latest.size, 66746981);
        assert!(LOOKUP.ends_with(&outcome.latest_note));
        // the same head twice, and the lookup alone, need no more
        let mut check = Check::new(verifier());
        check.add_head(LATEST).unwrap();
        check.add_head(LATEST).unwrap();
        assert!(check.tiles_needed().unwrap().is_empty(), "equal heads need no tiles");
        assert_eq!(check.finish(&TileSet::new()).unwrap().latest.size, 66746896);
        let mut check = Check::new(verifier());
        check.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        assert_eq!(check.tiles_needed().unwrap().len(), 7, "the record alone needs the same seven tiles");
        check.finish(&tile_set()).unwrap();
    }

    #[test]
    fn a_saved_head_is_merged_like_any_other() {
        // the next run starts from the head the last one kept
        let mut first = Check::new(verifier());
        first.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        let saved = first.finish(&tile_set()).unwrap().latest_note;
        let mut next = Check::new(verifier());
        next.add_head(&saved).unwrap();
        next.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        assert!(!next.tiles_needed().unwrap().is_empty());
        next.finish(&tile_set()).unwrap();
        // an older saved head: the newer lookup must contain it
        let mut next = Check::new(verifier());
        next.add_head(LATEST).unwrap();
        next.add_lookup(MODULE, VERSION, LOOKUP).unwrap();
        next.finish(&tile_set()).unwrap();
    }

    #[test]
    fn missing_tiles_are_named_and_nothing_is_returned() {
        let paths = all_tile_paths();
        for skip in &paths {
            let mut set = TileSet::new();
            for (path, data) in TILES {
                if path != skip {
                    set.insert(Tile::parse_path(path).unwrap(), data.to_vec()).unwrap();
                }
            }
            match real_check().finish(&set) {
                Err(Error::Log(tlog::Error::MissingTile(t))) => assert_eq!(&t.path(), skip),
                other => panic!("without {skip}: {other:?}"),
            }
        }
        assert!(matches!(real_check().finish(&TileSet::new()), Err(Error::Log(tlog::Error::MissingTile(_)))));
    }

    #[test]
    fn full_tiles_stand_in_for_partial_ones() {
        // Once a partial tile has filled up a server serves only the full one, whose first entries
        // are the partial tile's. Here the entries the log did not have yet are filler: only the
        // first `width` entries are looked at, and those are still checked against the root.
        let mut set = TileSet::new();
        for (path, data) in TILES {
            let t = Tile::parse_path(path).unwrap();
            if t.is_full() {
                set.insert(t, data.to_vec()).unwrap();
            } else {
                let mut full = data.to_vec();
                full.resize(8192, 0xAA);
                set.insert(t.full(), full).unwrap();
            }
        }
        real_check().finish(&set).unwrap();
        // and a changed entry among the first ones is still caught
        let t = Tile::parse_path("tile/8/0/x260/730.p/101").unwrap();
        let mut full = TILES[1].1.to_vec();
        full.resize(8192, 0xAA);
        full[40] ^= 1;
        set.insert(t.full(), full).unwrap();
        assert_eq!(real_check().finish(&set).unwrap_err(), Error::Log(tlog::Error::TilesDoNotMatchRoot));
    }

    #[test]
    fn the_forged_leaf_tile_that_defeated_go_is_refused() {
        // CVE-2026-56865: before x/mod 0.40.0 the Go client did not check a tile against its parent
        // when the right edge of the tree needed several nodes from one tile (as here: 17 nodes in
        // 4 tiles). A proxy could then answer a lookup with a forged record and a leaf tile whose
        // entry is the hash of the forgery; the tree head and every right-edge tile were genuine, and
        // the client accepted the record. This builds exactly that from the real capture.
        let forged_line = "golang.org/x/mod v0.17.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        let forged_text = format!("{forged_line}{GOMOD_H1}\n");
        let (id, text, note) = parse_record(LOOKUP).unwrap();
        assert_eq!(text, format!("{H1}\n{GOMOD_H1}\n"));
        let mut response = format!("{id}\n{forged_text}\n").into_bytes();
        response.extend_from_slice(note);

        let leaf_tile = Tile::parse_path("tile/8/0/x097/482").unwrap();
        let entry = (id % 256) as usize * 32;
        let mut set = TileSet::new();
        for (path, data) in TILES {
            let t = Tile::parse_path(path).unwrap();
            let mut data = data.to_vec();
            if t == leaf_tile {
                assert_eq!(data[entry..entry + 32], record_hash(text.as_bytes()), "the real entry is the real record's hash");
                data[entry..entry + 32].copy_from_slice(&record_hash(forged_text.as_bytes()));
            }
            set.insert(t, data).unwrap();
        }
        // what the Go client compared: the entry of the leaf tile against the hash of the record. It matches.
        assert_eq!(set.get(&leaf_tile).unwrap()[entry..entry + 32], record_hash(forged_text.as_bytes()));

        let mut check = Check::new(verifier());
        check.add_lookup(MODULE, VERSION, &response).unwrap();
        match check.finish(&set) {
            Err(Error::Log(tlog::Error::TileDoesNotMatchParent(t))) => assert_eq!(t, leaf_tile),
            other => panic!("the forgery was not refused: {other:?}"),
        }
        // and with the forged record but the real tiles it is simply a different record
        let mut check = Check::new(verifier());
        check.add_lookup(MODULE, VERSION, &response).unwrap();
        assert_eq!(check.finish(&tile_set()).unwrap_err(), Error::Log(tlog::Error::RecordMismatch));
    }

    #[test]
    fn no_byte_of_the_real_tiles_can_be_changed() {
        for (path, data) in TILES {
            let t = Tile::parse_path(path).unwrap();
            // every 29th byte, and the edges of the first entries and of the tile
            let mut positions: Vec<usize> = (0..data.len()).step_by(29).collect();
            positions.extend([0, 31, 32, 63, data.len() - 1]);
            for at in positions {
                for bit in [0u8, 7] {
                    let mut bad = data.to_vec();
                    bad[at] ^= 1 << bit;
                    let mut set = tile_set();
                    set.insert(t, bad).unwrap();
                    let err = match real_check().finish(&set) {
                        Ok(_) => panic!("byte {at} of {path} changed and nothing noticed"),
                        Err(e) => e,
                    };
                    assert!(matches!(err, Error::Log(tlog::Error::TilesDoNotMatchRoot | tlog::Error::TileDoesNotMatchParent(_))), "{path} byte {at}: {err}");
                }
            }
        }
    }

    #[test]
    fn genuine_tiles_in_the_wrong_places_are_refused() {
        // two full tiles of the real log, swapped: each is authentic, neither is the one asked for
        let mut set = tile_set();
        let a = Tile::parse_path("tile/8/1/380").unwrap();
        let b = Tile::parse_path("tile/8/2/001").unwrap();
        let (da, db) = (set.get(&a).unwrap().to_vec(), set.get(&b).unwrap().to_vec());
        set.insert(a, db).unwrap();
        set.insert(b, da).unwrap();
        assert!(matches!(real_check().finish(&set), Err(Error::Log(tlog::Error::TileDoesNotMatchParent(_)))));
    }

    #[test]
    fn a_note_signed_by_someone_else_is_not_believed() {
        // the same bytes under a different pinned key: nobody we trust signed it
        let other = Verifier::ed25519("sum.golang.org", &[7; 32]).unwrap();
        let mut check = Check::new(other);
        assert!(matches!(check.add_lookup(MODULE, VERSION, LOOKUP), Err(Error::Note(note::Error::Unverified(_)))));
        assert!(matches!(check.add_head(LATEST), Err(Error::Note(note::Error::Unverified(_)))));
        // and a signature that has been changed is refused outright
        let mut bad = LOOKUP.to_vec();
        let at = bad.len() - 10;
        bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
        let mut check = Check::new(verifier());
        assert!(matches!(check.add_lookup(MODULE, VERSION, &bad), Err(Error::Note(note::Error::InvalidSignature { .. }))));
        // a changed tree size is not signed either
        let mut bad = LOOKUP.to_vec();
        let at = String::from_utf8_lossy(&bad).find("66746981").unwrap();
        bad[at + 7] = b'2';
        assert!(matches!(Check::new(verifier()).add_lookup(MODULE, VERSION, &bad), Err(Error::Note(note::Error::InvalidSignature { .. }))));
        // and a failed add changes nothing
        let mut check = Check::new(verifier());
        let _ = check.add_lookup(MODULE, VERSION, &bad);
        assert!(check.tiles_needed().unwrap().is_empty());
    }

    #[test]
    fn a_changed_record_is_caught_by_the_log() {
        // the genuine tree head and tiles with a changed record text: the leaf hash differs
        let (id, text, note) = parse_record(LOOKUP).unwrap();
        let changed = text.replace("zY54", "zY55");
        let mut response = format!("{id}\n{changed}\n").into_bytes();
        response.extend_from_slice(note);
        let mut check = Check::new(verifier());
        check.add_lookup(MODULE, VERSION, &response).unwrap();
        assert_eq!(check.finish(&tile_set()).unwrap_err(), Error::Log(tlog::Error::RecordMismatch));
        // the same record under another number is another leaf
        for other in [id - 1, id + 1, 0, 66746980] {
            let mut response = format!("{other}\n{text}\n").into_bytes();
            response.extend_from_slice(note);
            let mut check = Check::new(verifier());
            check.add_lookup(MODULE, VERSION, &response).unwrap();
            assert!(check.finish(&tile_set()).is_err(), "record {other}");
        }
        // a number beyond the tree cannot be checked
        let mut response = format!("66746981\n{text}\n").into_bytes();
        response.extend_from_slice(note);
        let mut check = Check::new(verifier());
        assert_eq!(check.add_lookup(MODULE, VERSION, &response), Err(Error::RecordOutsideTree { id: 66746981, size: 66746981 }));
        assert!(check.tiles_needed().unwrap().is_empty());
    }

    // ------------------------------------------------------------------ parsing

    #[test]
    fn tree_heads() {
        let t = parse_tree("go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n").unwrap();
        assert_eq!(t.size, 66746981);
        assert_eq!(format_tree(&t), "go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n");
        // more lines after the root are ignored (forward compatibility), as in Go
        assert_eq!(parse_tree("go.sum database tree\n5\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\nextra\nlines\n").unwrap().size, 5);
        let root = "3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=";
        for bad in [
            String::new(),
            format!("go.sum database tree\n5\n{root}"),                 // no final newline: fewer than 3 newlines
            format!("go.sum database tre\n5\n{root}\n"),
            format!("go.sum database tree\n05\n{root}\n"),             // leading zero
            format!("go.sum database tree\n+5\n{root}\n"),
            format!("go.sum database tree\n-5\n{root}\n"),
            format!("go.sum database tree\n5 \n{root}\n"),
            format!("go.sum database tree\n\n{root}\n"),
            format!("go.sum database tree\n99999999999999999999\n{root}\n"),
            format!("go.sum database tree\n{}\n{root}\n", MAX_TREE_SIZE + 1),
            format!("go.sum database tree\n5\n{}\n", &root[..43]),
            format!("go.sum database tree\n5\n{}A\n", &root[..43]),
            "go.sum database tree\n5\nAAAA\n".to_string(),
            format!("go.sum database tree\n5\n{}\n", root.replace('=', "")),
            format!("go.sum database tree\n5\n{root} \n"),
            format!(" go.sum database tree\n5\n{root}\n"),
        ] {
            assert_eq!(parse_tree(&bad), Err(Error::MalformedTree), "{bad:?}");
        }
        // the size 2^62 is the largest; the empty tree is allowed
        assert!(parse_tree(&format!("go.sum database tree\n{MAX_TREE_SIZE}\n{root}\n")).is_ok());
        assert_eq!(parse_tree(&format!("go.sum database tree\n0\n{root}\n")).unwrap().size, 0);
    }

    #[test]
    fn records() {
        let (id, text, rest) = parse_record(LOOKUP).unwrap();
        assert_eq!(id, 24955599);
        assert_eq!(text, format!("{H1}\n{GOMOD_H1}\n"));
        assert!(rest.starts_with(b"go.sum database tree\n"));
        assert_eq!(parse_record(b"7\nline\n\nrest").unwrap(), (7, "line\n", &b"rest"[..]));
        assert_eq!(parse_record(b"0\n\n\nrest").unwrap(), (0, "\n", &b"rest"[..]), "Go takes a lone newline as record text");
        for bad in [
            &b""[..],
            b"5",
            b"5\n",
            b"5\nno blank line\n",
            b"5\nline\n",                // no blank line
            b"\nline\n\n",               // no number
            b"x\nline\n\n",
            b"+5\nline\n\n",
            b"05\nline\n\n",
            b"-5\nline\n\n",
            b"5 \nline\n\n",
            b"99999999999999999999\nline\n\n",
            b"5\nli\x00ne\n\n",           // control character
            b"5\nli\rne\n\n",
            b"5\nli\xffne\n\n",           // not UTF-8
            b"5\nline\n\t\n\n",           // a tab is a control character
        ] {
            assert_eq!(parse_record(bad), Err(Error::MalformedRecord), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn lookup_paths() {
        assert_eq!(lookup_path("golang.org/x/mod", "v0.17.0").unwrap(), "lookup/golang.org/x/mod@v0.17.0");
        assert_eq!(lookup_path("golang.org/x/mod", "v0.17.0/go.mod").unwrap(), "lookup/golang.org/x/mod@v0.17.0");
        assert_eq!(lookup_path("github.com/Azure/azure-sdk-for-go", "v1.2.3+incompatible").unwrap(), "lookup/github.com/!azure/azure-sdk-for-go@v1.2.3+incompatible");
        assert_eq!(lookup_path("github.com/BurntSushi/toml", "v1.0.0-RC1").unwrap(), "lookup/github.com/!burnt!sushi/toml@v1.0.0-!r!c1");
        assert_eq!(lookup_path("example.com/x", "v0.0.0-20210101000000-abcdef123456").unwrap(), "lookup/example.com/x@v0.0.0-20210101000000-abcdef123456");
        for (m, v) in [
            ("", "v1.0.0"),
            ("example.com//x", "v1.0.0"),
            ("example.com/x/", "v1.0.0"),
            ("/example.com/x", "v1.0.0"),
            ("example.com/../x", "v1.0.0"),
            ("example.com/.x", "v1.0.0"),
            ("example.com/x?y", "v1.0.0"),
            ("example.com/x#y", "v1.0.0"),
            ("example.com/x%2f", "v1.0.0"),
            ("example.com/x y", "v1.0.0"),
            ("example.com/x@y", "v1.0.0"),
            ("example.com/x\\y", "v1.0.0"),
            ("example.com/\u{e9}", "v1.0.0"),
            ("example.com/x", ""),
            ("example.com/x", "1.0.0"),
            ("example.com/x", "v1.0.0/"),
            ("example.com/x", "v1.0.0/go.mod/go.mod"),
            ("example.com/x", "v1.0.0/x"),
            ("example.com/x", "v1.0.0@x"),
            ("example.com/x", "v1.0.0!"),
            ("example.com/x", "v1 0"),
            ("example.com/x", "v1.0.0\n"),
        ] {
            assert!(lookup_path(m, v).is_err(), "{m:?} {v:?}");
        }
    }

    // ------------------------------------------------------------------ a made-up log with forks

    /// A made-up log under a test key, in two histories that part at record 17 (see
    /// tools/gen_sumdb_synthetic.py): what a real server never shows, so that forks can be tried.
    struct Synthetic {
        verifier: Verifier,
        heads: Vec<(String, Vec<u8>)>,
        lookups: Vec<(String, String, String, Vec<u8>)>,
        tiles: Vec<(String, String, Vec<u8>)>,
    }

    fn synthetic() -> Synthetic {
        let unhex = crate::util::unhex;
        let mut s = Synthetic { verifier: verifier(), heads: Vec::new(), lookups: Vec::new(), tiles: Vec::new() };
        for line in include_str!("../tests/data/sumdb_synthetic.txt").lines().filter(|l| !l.starts_with('#')) {
            let p: Vec<&str> = line.split(' ').collect();
            match p[0] {
                "key" => s.verifier = Verifier::from_key(p[1]).unwrap(),
                "head" => s.heads.push((p[1].to_string(), unhex(p[2]))),
                "lookup" => s.lookups.push((p[1].to_string(), p[2].to_string(), p[3].to_string(), unhex(p[4]))),
                "tile" => s.tiles.push((p[1].to_string(), p[2].to_string(), unhex(p[3]))),
                _ => panic!("{line}"),
            }
        }
        s
    }

    impl Synthetic {
        fn check(&self) -> Check {
            Check::new(self.verifier.clone())
        }

        fn head(&self, name: &str) -> &[u8] {
            &self.heads.iter().find(|h| h.0 == name).unwrap().1
        }

        fn add_lookup(&self, check: &mut Check, name: &str) -> Result<usize, Error> {
            let (_, module, version, response) = self.lookups.iter().find(|l| l.0 == name).unwrap();
            check.add_lookup(module, version, response)
        }

        /// The tiles of history `H` or `F`, as a client that fetched them from that server would
        /// have them.
        fn tiles(&self, history: &str) -> TileSet {
            let mut set = TileSet::new();
            for (h, path, data) in &self.tiles {
                if h == history {
                    set.insert(Tile::parse_path(path).unwrap(), data.clone()).unwrap();
                }
            }
            set
        }
    }

    fn fork_size(e: Error) -> u64 {
        match e {
            Error::Log(tlog::Error::Fork { size, .. }) => size,
            other => panic!("not a fork: {other:?}"),
        }
    }

    #[test]
    fn the_made_up_log_checks_out_while_it_tells_one_story() {
        let s = synthetic();
        // an earlier head, then a newer head with a record: all one history
        let mut check = s.check();
        check.add_head(s.head("h200")).unwrap();
        assert_eq!(s.add_lookup(&mut check, "h300_250").unwrap(), 0);
        let outcome = check.finish(&s.tiles("H")).unwrap();
        assert_eq!(outcome.latest.size, 300);
        assert_eq!(outcome.latest_note, s.head("h300"));
        assert_eq!(outcome.records[0].lines.len(), 1);
        assert!(outcome.records[0].lines[0].starts_with("example.com/m250 v1.0.0 h1:"));
        // the same with the newer head first and an older record after it
        let mut check = s.check();
        s.add_lookup(&mut check, "h300_250").unwrap();
        s.add_lookup(&mut check, "h200_150").unwrap();
        s.add_lookup(&mut check, "h300_17").unwrap();
        assert!(check.finish(&s.tiles("H")).is_ok());
        // the other history is as good on its own
        let mut check = s.check();
        s.add_lookup(&mut check, "f300_17").unwrap();
        assert!(check.finish(&s.tiles("F")).is_ok());
    }

    #[test]
    fn two_roots_of_one_size_are_a_fork_and_no_tile_is_needed_to_see_it() {
        let s = synthetic();
        for (first, second) in [("h300", "f300"), ("f300", "h300")] {
            let mut check = s.check();
            check.add_head(s.head(first)).unwrap();
            check.add_head(s.head(second)).unwrap();
            assert!(check.tiles_needed().unwrap().is_empty());
            assert_eq!(fork_size(check.finish(&TileSet::new()).unwrap_err()), 300);
        }
        // a lookup whose head is the forked one, after the honest head is known
        let mut check = s.check();
        check.add_head(s.head("h300")).unwrap();
        s.add_lookup(&mut check, "f300_17").unwrap();
        assert_eq!(fork_size(check.finish(&s.tiles("F")).unwrap_err()), 300);
    }

    #[test]
    fn a_head_that_is_not_inside_a_newer_one_is_a_fork() {
        let s = synthetic();
        // the older head (200, honest) against the newer head of the other history (300, forked):
        // the newer head's own tiles say what the first 200 records were, and it is not that
        let mut check = s.check();
        check.add_head(s.head("h200")).unwrap();
        check.add_head(s.head("f300")).unwrap();
        assert_eq!(fork_size(check.finish(&s.tiles("F")).unwrap_err()), 200);
        // and the other way round: the older head (250, forked) against the honest 300
        let mut check = s.check();
        check.add_head(s.head("h300")).unwrap();
        check.add_head(s.head("f250")).unwrap();
        assert_eq!(fork_size(check.finish(&s.tiles("H")).unwrap_err()), 250);
        // the same fork when the forked head is the first one seen
        let mut check = s.check();
        check.add_head(s.head("f250")).unwrap();
        s.add_lookup(&mut check, "h300_250").unwrap();
        assert_eq!(fork_size(check.finish(&s.tiles("H")).unwrap_err()), 250);
    }

    #[test]
    fn tiles_of_the_wrong_history_do_not_pass_for_the_right_one() {
        let s = synthetic();
        // the head is honest and the tiles are the forked history's: they do not hash to its root
        let mut check = s.check();
        s.add_lookup(&mut check, "h300_17").unwrap();
        assert_eq!(check.finish(&s.tiles("F")).unwrap_err(), Error::Log(tlog::Error::TilesDoNotMatchRoot));
        // the forked record 17 under the honest head is not what the honest log holds there
        let mut check = s.check();
        s.add_lookup(&mut check, "mix_17").unwrap();
        assert_eq!(check.finish(&s.tiles("H")).unwrap_err(), Error::Log(tlog::Error::RecordMismatch));
        // and a tile of one history spliced into the other fails against the root
        let mut mixed = s.tiles("H");
        let full = Tile::parse_path("tile/8/0/000").unwrap();
        mixed.insert(full, s.tiles("F").get(&full).unwrap().to_vec()).unwrap();
        let mut check = s.check();
        s.add_lookup(&mut check, "h300_250").unwrap();
        assert!(matches!(check.finish(&mixed), Err(Error::Log(tlog::Error::TileDoesNotMatchParent(_)))));
    }
}

