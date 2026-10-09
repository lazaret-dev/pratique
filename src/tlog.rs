//! Transparency-log arithmetic: Merkle tree hashes, inclusion and consistency proofs, and tiles.
//!
//! This is the verification half of a Certificate-Transparency-style log as the Go checksum
//! database (`sum.golang.org`), Sigstore's Rekor and the other "tlog" logs use it, in pure functions
//! over bytes: no I/O, no clock, nothing to configure. Fetching is the caller's job; this module
//! says which pieces are needed and checks them.
//!
//! # Hashes
//!
//! Leaf hashes are `SHA-256(0x00 || record)` and interior nodes `SHA-256(0x01 || left || right)`
//! (RFC 6962 section 2.1, kept by RFC 9162). A tree of `n` leaves splits at the largest power of two
//! below `n`; the empty tree's root is `SHA-256("")`. A tree is described by a [`Tree`]: its size
//! and its root. Whoever vouches for a tree head (a signed note, see the `note` module) vouches for
//! both.
//!
//! # Proofs
//!
//! [`verify_inclusion`] checks that a leaf is in a tree of a given size and root, and
//! [`verify_consistency`] that an older tree is a prefix of a newer one. Both use the iterative
//! algorithms of RFC 9162 sections 2.1.3.2 and 2.1.4.2, which are also what RFC 6962 audit paths
//! and consistency proofs verify under. A proof with a missing, extra, reordered or altered hash is
//! refused, so is one for the wrong size, index or leaf.
//!
//! # Tiles
//!
//! A log that publishes proofs for every request is expensive; the Go checksum database instead
//! publishes the hashes themselves in static "tiles" (Russ Cox, "Transparent Logs for Skeptical
//! Clients"), and the client works the proofs out locally. A tile of height `h` at level `l`, index
//! `k` lists `w` consecutive hashes (`w` is `2^h` for a full tile, fewer for the partial tile on the
//! right edge) of tree level `h * l`, starting at position `k * 2^h`; the levels in between are
//! recomputed from them. Its path is `tile/<h>/<l>/<k>[.p/<w>]` with `k` written in groups of three
//! digits (`x001/x234/067`), see [`Tile::path`].
//!
//! Tile data from a server is not trusted. [`read_nodes`] hands back tree hashes only after
//! authenticating **every** tile it used: the tiles on the right edge of the tree must hash to the
//! root of the tree head, and each other tile must hash to the entry its parent tile has for it.
//! (Go's `x/mod/sumdb/tlog` before v0.40.0 skipped the second check for some tiles, which let a
//! malicious proxy forge them: CVE-2026-56865. A test here replays that against real data.)
//!
//! Sans-IO use: ask [`tiles_for_record`] or [`tiles_for_prefix`] which tiles are needed, fetch them
//! however you like (all at once, in parallel; a partial tile that is gone can be replaced by the
//! full tile, see [`TileSet::get`]), put them in a [`TileSet`], then call [`check_record`] or
//! [`check_prefix`].
//!
//! Limits: trees of up to 2^62 leaves, tile heights 1 to 30, hash tiles only (Go's "data" tiles,
//! which hold records, are not handled here).

use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::sha2::{Hash as _, Sha256};

/// The length of a hash in bytes.
pub const HASH_SIZE: usize = 32;

/// A SHA-256 hash.
pub type Hash = [u8; HASH_SIZE];

/// The root of the empty tree: `SHA-256("")`.
pub const EMPTY_ROOT: Hash = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// The largest tree size accepted, 2^62 leaves, so that every position and storage offset fits a
/// `u64`. (Go's `tlog` takes sizes up to 2^63 - 1 but never returns from the proof checks above
/// 2^62: its `maxpow2` loop overflows.)
pub const MAX_TREE_SIZE: u64 = 1 << 62;

/// The tallest tile accepted.
pub const MAX_TILE_HEIGHT: u32 = 30;

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An argument is outside what the function accepts (a tree too large, an index outside the
    /// tree, a malformed tile or tile path, tile data of the wrong length).
    Invalid(&'static str),
    /// A proof does not prove what it was given to prove.
    BadProof,
    /// A tile that authentication needs was not supplied.
    MissingTile(Tile),
    /// The tiles on the right edge of the tree do not hash to the tree's root. At least one of them
    /// is wrong; which one cannot be told.
    TilesDoNotMatchRoot,
    /// This tile does not hash to the entry its parent tile has for it.
    TileDoesNotMatchParent(Tile),
    /// The hash of the leaf found in the log is not the hash that was expected.
    RecordMismatch,
    /// The older tree's root, recomputed from the newer tree's tiles, is not the root that was
    /// vouched for the older tree: both heads are authentic, so the log has shown two histories
    /// (or, for equal sizes, two roots). Keep both heads as evidence.
    Fork { size: u64, expected: Hash, computed: Hash },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(m) => write!(f, "transparency log: {m}"),
            Error::BadProof => write!(f, "transparency log: invalid proof"),
            Error::MissingTile(t) => write!(f, "transparency log: tile {} was not supplied", t.path()),
            Error::TilesDoNotMatchRoot => write!(f, "transparency log: the tiles on the right edge do not hash to the tree root"),
            Error::TileDoesNotMatchParent(t) => write!(f, "transparency log: tile {} does not hash to the entry in its parent tile", t.path()),
            Error::RecordMismatch => write!(f, "transparency log: the record's hash is not the hash in the log"),
            Error::Fork { size, expected, computed } => write!(
                f,
                "transparency log: FORK: the tree of size {size} is signed with root {} but the newer tree's tiles give {}",
                crate::util::hex(expected),
                crate::util::hex(computed)
            ),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ------------------------------------------------------------------------------------- hashing

fn sha256_of(prefix: u8, a: &[u8], b: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(&[prefix]);
    h.update(a);
    h.update(b);
    let v = h.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&v);
    out
}

/// The hash of a leaf holding `record`: `SHA-256(0x00 || record)`.
pub fn record_hash(record: &[u8]) -> Hash {
    sha256_of(0x00, record, &[])
}

/// The hash of an interior node with the given children: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256_of(0x01, left, right)
}

/// A tree head: the number of leaves and the root hash. Alone it proves nothing; it is what a
/// signature (see the `note` module) is checked over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tree {
    pub size: u64,
    pub root: Hash,
}

/// A node of the tree: at `level` 0 a leaf, at level `l` the root of the `2^l` leaves starting at
/// leaf `index << l`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node {
    pub level: u32,
    pub index: u64,
}

// ------------------------------------------------------------------------------------- proofs

/// Checks that `leaf` (the hash of the record, see [`record_hash`]) is leaf number `index` of the
/// tree of `size` leaves whose root is `root`, given the audit `proof` (the sibling hashes from the
/// leaf up, RFC 9162 section 2.1.3.2).
pub fn verify_inclusion(proof: &[Hash], size: u64, root: &Hash, index: u64, leaf: &Hash) -> Result<()> {
    if size > MAX_TREE_SIZE {
        return Err(Error::Invalid("tree is too large"));
    }
    if index >= size {
        return Err(Error::Invalid("leaf index is not inside the tree"));
    }
    let mut f = index;
    let mut s = size - 1;
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return Err(Error::BadProof);
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 || r != *root {
        return Err(Error::BadProof);
    }
    Ok(())
}

/// Checks that the tree of `new_size` leaves and root `new_root` extends the tree of `old_size`
/// leaves and root `old_root`, given the consistency `proof` (RFC 9162 section 2.1.4.2). Both
/// sizes must be at least 1 and `old_size <= new_size`; for equal sizes the proof must be empty and
/// the roots equal.
pub fn verify_consistency(proof: &[Hash], old_size: u64, old_root: &Hash, new_size: u64, new_root: &Hash) -> Result<()> {
    if old_size == 0 || old_size > new_size || new_size > MAX_TREE_SIZE {
        return Err(Error::Invalid("consistency needs 1 <= old size <= new size <= the largest tree"));
    }
    if old_size == new_size {
        return if proof.is_empty() && old_root == new_root { Ok(()) } else { Err(Error::BadProof) };
    }
    // A power-of-two old tree is a complete subtree of the new one, so its root starts the proof
    // and the proof does not repeat it.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return Err(Error::BadProof);
    }
    let mut f = old_size - 1;
    let mut s = new_size - 1;
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if s == 0 {
            return Err(Error::BadProof);
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 || fr != *old_root || sr != *new_root {
        return Err(Error::BadProof);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------- tiles

/// A tile of hashes, see the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tile {
    /// The height `h`, 1 to 30; a full tile has `2^h` entries.
    pub height: u32,
    /// The level `l`: the tile lists hashes of tree level `height * level`.
    pub level: u32,
    /// The tile's number within its level.
    pub index: u64,
    /// The number of entries, 1 to `2^height`.
    pub width: u32,
}

impl Tile {
    /// `2^height` if it fits a tile's width (a `u32`), else `None`. (A tile that failed
    /// [`Tile::validate`] can have any height, and a shift by 32 or more must not panic.)
    fn full_width(&self) -> Option<u32> {
        1u64.checked_shl(self.height).and_then(|w| u32::try_from(w).ok())
    }

    /// Whether the tile has all `2^height` entries. (False for a height that no tile can have.)
    pub fn is_full(&self) -> bool {
        self.full_width() == Some(self.width)
    }

    /// The tile with every entry, same place. (A tile whose height is too large for that comes back
    /// unchanged; [`Tile::validate`] refuses it.)
    pub fn full(&self) -> Tile {
        Tile { width: self.full_width().unwrap_or(self.width), ..*self }
    }

    /// The number of bytes of tile data: `width * 32`.
    pub fn data_len(&self) -> u64 {
        self.width as u64 * HASH_SIZE as u64
    }

    /// Checks the fields against the limits of this module.
    pub fn validate(&self) -> Result<()> {
        if self.height < 1 || self.height > MAX_TILE_HEIGHT {
            return Err(Error::Invalid("tile height must be 1 to 30"));
        }
        if self.width < 1 || self.width as u64 > 1u64 << self.height {
            return Err(Error::Invalid("tile width must be 1 to 2^height"));
        }
        // the tile's first entry is a node of tree level height*level, so its leaf offset must stay
        // inside the 2^62 leaves that are the limit
        let lh = self.level as u64 * self.height as u64;
        if lh > 62 || (self.index as u128) << self.height >= 1u128 << (62 - lh) {
            return Err(Error::Invalid("tile is outside the largest tree"));
        }
        Ok(())
    }

    /// The tile's path on a tile server: `tile/<h>/<l>/<k>` with `<k>` in groups of three digits
    /// (all but the last group start with `x`), and `.p/<w>` after it for a partial tile.
    pub fn path(&self) -> String {
        let mut n = self.index;
        let mut k = format!("{:03}", n % 1000);
        while n >= 1000 {
            n /= 1000;
            k = format!("x{:03}/{}", n % 1000, k);
        }
        let partial = if self.is_full() { String::new() } else { format!(".p/{}", self.width) };
        format!("tile/{}/{}/{}{}", self.height, self.level, k, partial)
    }

    /// Parses a path made by [`Tile::path`]. Only canonical paths are accepted (no signs, no extra
    /// zeros, no `.p` on a full tile) and the Go "data" level is refused.
    pub fn parse_path(path: &str) -> Result<Tile> {
        const BAD: Error = Error::Invalid("malformed tile path");
        fn number(s: &str) -> Option<u64> {
            if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        }
        let mut f: Vec<&str> = path.split('/').collect();
        if f.len() < 4 || f[0] != "tile" {
            return Err(BAD);
        }
        let height = number(f[1]).filter(|h| (1..=MAX_TILE_HEIGHT as u64).contains(h)).ok_or(BAD)? as u32;
        let level = number(f[2]).filter(|l| *l <= 62).ok_or(BAD)? as u32;
        let mut width = 1u64 << height;
        if f[f.len() - 2].ends_with(".p") {
            let w = number(f[f.len() - 1]).filter(|w| *w >= 1 && *w < width).ok_or(BAD)?;
            width = w;
            let at = f.len() - 2;
            let name = f[at];
            f[at] = &name[..name.len() - 2];
            f.pop();
        }
        let mut index = 0u64;
        for part in &f[3..] {
            let digits = part.strip_prefix('x').unwrap_or(part);
            let v = number(digits).filter(|v| *v < 1000).ok_or(BAD)?;
            index = index.checked_mul(1000).and_then(|i| i.checked_add(v)).ok_or(BAD)?;
        }
        let tile = Tile { height, level, index, width: width as u32 };
        if tile.validate().is_err() || tile.path() != path {
            return Err(BAD);
        }
        Ok(tile)
    }
}

/// Tile data, by tile. Everything inserted is checked for length only; whether it belongs to a tree
/// is what [`read_nodes`] and the functions built on it check.
#[derive(Clone, Debug, Default)]
pub struct TileSet {
    tiles: BTreeMap<Tile, Vec<u8>>,
}

impl TileSet {
    pub fn new() -> TileSet {
        TileSet::default()
    }

    /// Adds the data of `tile` (`tile.width * 32` bytes), replacing what was there.
    pub fn insert(&mut self, tile: Tile, data: Vec<u8>) -> Result<()> {
        tile.validate()?;
        if data.len() as u64 != tile.data_len() {
            return Err(Error::Invalid("tile data is not width * 32 bytes"));
        }
        self.tiles.insert(tile, data);
        Ok(())
    }

    /// The data of `tile`, or, if only the full tile of the same place was inserted, its first
    /// `width * 32` bytes. (A server stops serving a partial tile once it has become full, so a
    /// client that asks for `tile/8/0/x260/730.p/101` gets the full `tile/8/0/x260/730` instead; the
    /// entries are the same, and the full tile is checked just as thoroughly.)
    pub fn get(&self, tile: &Tile) -> Option<&[u8]> {
        if let Some(d) = self.tiles.get(tile) {
            return Some(d);
        }
        let n = tile.data_len() as usize;
        self.tiles.get(&tile.full()).filter(|d| d.len() >= n).map(|d| &d[..n])
    }

    pub fn len(&self) -> usize {
        self.tiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tiles.is_empty()
    }
}

/// The root of the perfect subtree over `entries.len() / 32` hashes (a power of two of them).
fn subtree_hash(entries: &[u8]) -> Hash {
    if entries.len() == HASH_SIZE {
        let mut h = [0u8; HASH_SIZE];
        h.copy_from_slice(entries);
        return h;
    }
    let mid = entries.len() / 2;
    node_hash(&subtree_hash(&entries[..mid]), &subtree_hash(&entries[mid..]))
}

/// The maximal perfect subtrees that make up a tree of `size` leaves, largest (leftmost) first. At
/// most 63 of them: one per set bit of `size`.
fn subtrees(size: u64) -> Vec<Node> {
    let mut out = Vec::new();
    let mut at = 0u64;
    for level in (0..=62u32).rev() {
        if size >> level & 1 == 1 {
            out.push(Node { level, index: at >> level });
            at += 1 << level;
        }
    }
    out
}

/// The root of a tree from the roots of its maximal perfect subtrees, leftmost first.
fn fold_subtrees(hashes: &[Hash]) -> Hash {
    let mut it = hashes.iter().rev();
    let mut h = match it.next() {
        Some(h) => *h,
        None => return EMPTY_ROOT,
    };
    for x in it {
        h = node_hash(x, &h);
    }
    h
}

/// The smallest tile that holds `node`, and the range of entries (not bytes) of the tile that
/// are the leaves under the node. `node` must lie inside a tree of at most `MAX_TREE_SIZE` leaves.
fn node_tile(height: u32, node: Node) -> (Tile, usize, usize) {
    let level = node.level / height;
    let sub = node.level - level * height; // level of the node within its tile
    let index = (node.index << sub) >> height;
    let within = node.index - ((index << height) >> sub);
    let tile = Tile { height, level, index, width: ((within + 1) << sub) as u32 };
    (tile, (within << sub) as usize, ((within + 1) << sub) as usize)
}

/// The tile `k` levels above `t` that holds `t`'s entry, widened to what a tree of `size` leaves
/// has of it: full unless it is on the right edge. `None` if the tree has nothing there.
fn tile_ancestor(t: Tile, k: u32, size: u64) -> Option<Tile> {
    let level = t.level.checked_add(k)?;
    let lh = level as u64 * t.height as u64;
    if lh > 62 {
        return None;
    }
    let index = t.index >> (k as u64 * t.height as u64).min(63);
    let max = size >> lh; // the number of nodes the tree has on this tile level
    let start = (index as u128) << t.height;
    let mut width = 1u128 << t.height;
    if start + width >= max as u128 {
        if start >= max as u128 {
            return None;
        }
        width = max as u128 - start;
    }
    Some(Tile { height: t.height, level, index, width: width as u32 })
}

/// What `read_nodes` will look at: the tiles to fetch and where each requested node is.
struct Plan {
    tiles: Vec<Tile>,
    /// The right-edge nodes of the tree and the position in `tiles` of the tile of each.
    edge: Vec<(Node, usize)>,
    /// How many of `tiles` are right-edge tiles (they come first).
    edge_tiles: usize,
    /// The position in `tiles` of the tile of each requested node.
    node_tile: Vec<usize>,
}

fn plan(tree: &Tree, height: u32, nodes: &[Node]) -> Result<Plan> {
    if height < 1 || height > MAX_TILE_HEIGHT {
        return Err(Error::Invalid("tile height must be 1 to 30"));
    }
    if tree.size > MAX_TREE_SIZE {
        return Err(Error::Invalid("tree is larger than 2^62 leaves"));
    }
    for n in nodes {
        if n.level > 62 || ((n.index as u128 + 1) << n.level) > tree.size as u128 {
            return Err(Error::Invalid("node is not inside the tree"));
        }
    }
    let mut tiles: Vec<Tile> = Vec::new();
    let mut order: BTreeMap<Tile, usize> = BTreeMap::new();
    let mut edge = Vec::new();
    // The tiles that recompute the root.
    for x in subtrees(tree.size) {
        let (t, _, _) = node_tile(height, x);
        let t = tile_ancestor(t, 0, tree.size).ok_or(Error::Invalid("no tile for a right-edge node"))?;
        let at = *order.entry(t).or_insert_with(|| {
            tiles.push(t);
            tiles.len() - 1
        });
        edge.push((x, at));
    }
    let edge_tiles = tiles.len();
    // The tiles that hold the requested nodes, with whatever parents are needed to reach a tile that
    // is already planned (the parents come before the children).
    let mut node_tile_of = Vec::with_capacity(nodes.len());
    for x in nodes {
        let (t, _, _) = node_tile(height, *x);
        let mut k = 0u32;
        let found = loop {
            let p = tile_ancestor(t, k, tree.size).ok_or(Error::Invalid("no parent tile"))?;
            if let Some(&j) = order.get(&p) {
                break (k, j);
            }
            k += 1;
            if k > 64 {
                return Err(Error::Invalid("no parent tile"));
            }
        };
        let (top, j) = found;
        if top == 0 {
            node_tile_of.push(j);
            continue;
        }
        let mut mine = 0;
        for k in (0..top).rev() {
            let p = tile_ancestor(t, k, tree.size).ok_or(Error::Invalid("no parent tile"))?;
            if !p.is_full() {
                return Err(Error::Invalid("a partial tile has a parent"));
            }
            order.insert(p, tiles.len());
            if k == 0 {
                mine = tiles.len();
            }
            tiles.push(p);
        }
        node_tile_of.push(mine);
    }
    Ok(Plan { tiles, edge, edge_tiles, node_tile: node_tile_of })
}

/// The tiles needed to read `nodes` of the tree head `tree`, in the order [`read_nodes`] checks
/// them. Only the size of the tree matters here, not its root.
pub fn tiles_for(tree: &Tree, height: u32, nodes: &[Node]) -> Result<Vec<Tile>> {
    Ok(plan(tree, height, nodes)?.tiles)
}

/// Reads the hashes of `nodes` from tile data, after checking every tile that is used against
/// `tree`: the right-edge tiles must hash to `tree.root` and every other tile must hash to its
/// entry in its parent tile. A hash is returned only if the whole set it came from is consistent.
pub fn read_nodes(tree: &Tree, height: u32, nodes: &[Node], tiles: &TileSet) -> Result<Vec<Hash>> {
    let plan = plan(tree, height, nodes)?;
    let mut data: Vec<&[u8]> = Vec::with_capacity(plan.tiles.len());
    for t in &plan.tiles {
        let d = tiles.get(t).ok_or(Error::MissingTile(*t))?;
        if d.len() as u64 != t.data_len() {
            return Err(Error::Invalid("tile data is not width * 32 bytes"));
        }
        data.push(d);
    }
    if plan.edge.is_empty() {
        // an empty tree: there is nothing to read (and `plan` refused every node)
        return Ok(Vec::new());
    }
    // 1. the right edge must give the root
    let mut edge_hashes = Vec::with_capacity(plan.edge.len());
    for (node, at) in &plan.edge {
        edge_hashes.push(hash_from_tile(&plan.tiles[*at], data[*at], *node)?);
    }
    if fold_subtrees(&edge_hashes) != tree.root {
        return Err(Error::TilesDoNotMatchRoot);
    }
    // 2. everything else must hang off an authenticated parent (parents are listed before children)
    let position: BTreeMap<Tile, usize> = plan.tiles.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    for i in plan.edge_tiles..plan.tiles.len() {
        let t = plan.tiles[i];
        let parent = tile_ancestor(t, 1, tree.size).ok_or(Error::Invalid("no parent tile"))?;
        let pj = *position.get(&parent).filter(|pj| **pj < i).ok_or(Error::Invalid("a tile was planned before its parent"))?;
        // the parent lists this tile's root: tree level height*(level+1), number t.index
        let entry = Node { level: parent.level * height, index: t.index };
        if hash_from_tile(&parent, data[pj], entry)? != subtree_hash(data[i]) {
            return Err(Error::TileDoesNotMatchParent(t));
        }
    }
    // 3. now the hashes asked for
    let mut out = Vec::with_capacity(nodes.len());
    for (x, at) in nodes.iter().zip(&plan.node_tile) {
        out.push(hash_from_tile(&plan.tiles[*at], data[*at], *x)?);
    }
    Ok(out)
}

/// The hash of `node`, from tile `t` (or a wider tile of the same place) with data `data`.
fn hash_from_tile(t: &Tile, data: &[u8], node: Node) -> Result<Hash> {
    t.validate()?;
    if (data.len() as u64) < t.data_len() {
        return Err(Error::Invalid("tile data is too short"));
    }
    let (need, start, end) = node_tile(t.height, node);
    if t.level != need.level || t.index != need.index || t.width < need.width {
        return Err(Error::Invalid("the node is not in this tile"));
    }
    Ok(subtree_hash(&data[start * HASH_SIZE..end * HASH_SIZE]))
}

/// The tiles needed by [`check_record`].
pub fn tiles_for_record(tree: &Tree, height: u32, index: u64) -> Result<Vec<Tile>> {
    if index >= tree.size {
        return Err(Error::Invalid("record index is not inside the tree"));
    }
    tiles_for(tree, height, &[Node { level: 0, index }])
}

/// Checks that record number `index` of the log described by `tree` has the hash `leaf`
/// (see [`record_hash`]), reading the log's own hash from authenticated tiles.
pub fn check_record(tree: &Tree, height: u32, index: u64, leaf: &Hash, tiles: &TileSet) -> Result<()> {
    if index >= tree.size {
        return Err(Error::Invalid("record index is not inside the tree"));
    }
    let got = read_nodes(tree, height, &[Node { level: 0, index }], tiles)?;
    if got.first() == Some(leaf) {
        Ok(())
    } else {
        Err(Error::RecordMismatch)
    }
}

/// The tiles needed by [`check_prefix`] when `older` has the size `older_size`. (None are needed if
/// the sizes are equal or the older tree is empty.)
pub fn tiles_for_prefix(newer: &Tree, height: u32, older_size: u64) -> Result<Vec<Tile>> {
    if newer.size > MAX_TREE_SIZE {
        return Err(Error::Invalid("tree is larger than 2^62 leaves"));
    }
    if older_size > newer.size {
        return Err(Error::Invalid("the older tree is larger than the newer one"));
    }
    if older_size == 0 || older_size == newer.size {
        return Ok(Vec::new());
    }
    tiles_for(newer, height, &subtrees(older_size))
}

/// Checks that the tree `older` is a prefix of `newer` (no proof is supplied: the older tree's
/// root is recomputed from `newer`'s authenticated tiles and compared with `older.root`). A
/// mismatch is [`Error::Fork`]: the log has signed two histories.
pub fn check_prefix(older: &Tree, newer: &Tree, height: u32, tiles: &TileSet) -> Result<()> {
    if newer.size > MAX_TREE_SIZE {
        return Err(Error::Invalid("tree is larger than 2^62 leaves"));
    }
    if older.size > newer.size {
        return Err(Error::Invalid("the older tree is larger than the newer one"));
    }
    let computed = if older.size == 0 {
        EMPTY_ROOT
    } else if older.size == newer.size {
        newer.root
    } else {
        let hashes = read_nodes(newer, height, &subtrees(older.size), tiles)?;
        fold_subtrees(&hashes)
    };
    if computed != older.root {
        return Err(Error::Fork { size: older.size, expected: older.root, computed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    fn leaf(i: u64) -> Hash {
        record_hash(format!("record {i}").as_bytes())
    }

    /// A tree built the obvious way, straight from the definitions in RFC 6962 section 2.1, to check
    /// the code against: `levels[l][i]` is the hash of the perfect subtree of the `2^l` leaves
    /// starting at leaf `i << l`.
    struct Reference {
        levels: Vec<Vec<Hash>>,
    }

    impl Reference {
        fn new(n: u64) -> Reference {
            Reference::with_leaves((0..n).map(leaf).collect())
        }

        fn with_leaves(leaves: Vec<Hash>) -> Reference {
            let mut levels = vec![leaves];
            while levels.last().unwrap().len() >= 2 {
                let prev = levels.last().unwrap();
                let next = prev.chunks_exact(2).map(|p| node_hash(&p[0], &p[1])).collect();
                levels.push(next);
            }
            Reference { levels }
        }

        /// MTH(D[lo:hi]).
        fn mth(&self, lo: u64, hi: u64) -> Hash {
            let n = hi - lo;
            if n == 0 {
                return EMPTY_ROOT;
            }
            if n.is_power_of_two() && lo % n == 0 {
                return self.levels[n.trailing_zeros() as usize][(lo / n) as usize];
            }
            let k = n.next_power_of_two() / 2;
            node_hash(&self.mth(lo, lo + k), &self.mth(lo + k, hi))
        }

        fn root(&self, n: u64) -> Hash {
            self.mth(0, n)
        }

        fn tree(&self, n: u64) -> Tree {
            Tree { size: n, root: self.root(n) }
        }

        /// PATH(m, D[lo:hi]) with `m` counted from `lo`.
        fn path(&self, m: u64, lo: u64, hi: u64) -> Vec<Hash> {
            let n = hi - lo;
            if n == 1 {
                return Vec::new();
            }
            let k = n.next_power_of_two() / 2;
            if m < k {
                let mut p = self.path(m, lo, lo + k);
                p.push(self.mth(lo + k, hi));
                p
            } else {
                let mut p = self.path(m - k, lo + k, hi);
                p.push(self.mth(lo, lo + k));
                p
            }
        }

        fn inclusion(&self, index: u64, n: u64) -> Vec<Hash> {
            self.path(index, 0, n)
        }

        /// SUBPROOF(m, D[lo:hi], b).
        fn subproof(&self, m: u64, lo: u64, hi: u64, b: bool) -> Vec<Hash> {
            let n = hi - lo;
            if m == n {
                return if b { Vec::new() } else { vec![self.mth(lo, hi)] };
            }
            let k = n.next_power_of_two() / 2;
            if m <= k {
                let mut p = self.subproof(m, lo, lo + k, b);
                p.push(self.mth(lo + k, hi));
                p
            } else {
                let mut p = self.subproof(m - k, lo + k, hi, false);
                p.push(self.mth(lo, lo + k));
                p
            }
        }

        fn consistency(&self, m: u64, n: u64) -> Vec<Hash> {
            if m == n {
                Vec::new()
            } else {
                self.subproof(m, 0, n, true)
            }
        }

        /// The hash of a node, which must be a perfect subtree inside the tree.
        fn node(&self, level: u32, index: u64) -> Hash {
            self.levels[level as usize][index as usize]
        }

        fn tile_data(&self, t: &Tile) -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..t.width as u64 {
                out.extend_from_slice(&self.node(t.height * t.level, (t.index << t.height) + i));
            }
            out
        }

        /// Tile data for every tile `tiles` names.
        fn tile_set(&self, tiles: &[Tile]) -> TileSet {
            let mut set = TileSet::new();
            for t in tiles {
                set.insert(*t, self.tile_data(t)).unwrap();
            }
            set
        }
    }

    fn flip(h: &Hash, bit: usize) -> Hash {
        let mut h = *h;
        h[bit / 8 % 32] ^= 1 << (bit % 8);
        h
    }

    // ------------------------------------------------------------------------ hashes

    #[test]
    fn the_roots_of_the_certificate_transparency_reference_trees() {
        // The first eight leaves of the reference tree of the Certificate Transparency project (its
        // merkle_tree_test.cc and the Python and Go versions of it) and the root at each size. The
        // values were also recomputed with an independent implementation in Python.
        let leaves: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let reference = Reference::with_leaves(leaves.iter().map(|l| record_hash(l)).collect());
        for (i, want) in roots.iter().enumerate() {
            assert_eq!(hex(&reference.root(i as u64 + 1)), *want, "tree of {} leaves", i + 1);
        }
        // and the empty tree
        assert_eq!(hex(&reference.root(0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(EMPTY_ROOT, <[u8; 32]>::try_from(Sha256::digest(b"").as_slice()).unwrap());
    }

    // ------------------------------------------------------------------------ proofs

    #[test]
    fn every_inclusion_proof_of_every_small_tree_verifies() {
        let reference = Reference::new(70);
        for n in 1..=70u64 {
            let root = reference.root(n);
            for i in 0..n {
                let proof = reference.inclusion(i, n);
                assert_eq!(verify_inclusion(&proof, n, &root, i, &leaf(i)), Ok(()), "leaf {i} of {n}");
            }
        }
    }

    #[test]
    fn altered_inclusion_proofs_are_refused() {
        let reference = Reference::new(72);
        for n in 1..=70u64 {
            let root = reference.root(n);
            for i in 0..n {
                let proof = reference.inclusion(i, n);
                let ok = |p: &[Hash], size: u64, r: &Hash, idx: u64, l: &Hash| verify_inclusion(p, size, r, idx, l).is_ok();
                let l = leaf(i);
                assert!(!ok(&proof, n, &root, i, &leaf(i + 1000)), "another leaf: {i} of {n}");
                assert!(!ok(&proof, n, &flip(&root, i as usize), i, &l), "another root: {i} of {n}");
                // A proof does not pin the size down by itself (a leaf in a tree of 3 has the same
                // audit path as in a tree of 4 when the right subtree hangs off the same node), so a
                // wrong size is only certain to fail when it changes how many hashes the path has.
                for other in [n - 1, n + 1] {
                    if other > i && reference.inclusion(i, other).len() != proof.len() {
                        assert!(!ok(&proof, other, &root, i, &l), "size {other} instead of {n}, leaf {i}");
                    }
                }
                if n > 1 && !proof.is_empty() {
                    let other = (i + 1) % n;
                    if reference.inclusion(other, n)[0] != proof[0] || other < i {
                        // (a sibling pair shares its first hash only by being each other's sibling)
                        assert!(!ok(&proof, n, &root, other, &l), "index {other} instead of {i} of {n}");
                    }
                }
                assert!(!ok(&proof, n, &root, i + n, &l), "index outside the tree");
                for k in 0..proof.len() {
                    let mut p = proof.clone();
                    p[k] = flip(&p[k], 7 * k + i as usize);
                    assert!(!ok(&p, n, &root, i, &l), "bit flipped in hash {k}: {i} of {n}");
                    let mut p = proof.clone();
                    p.remove(k);
                    assert!(!ok(&p, n, &root, i, &l), "hash {k} removed: {i} of {n}");
                    let mut p = proof.clone();
                    p.insert(k, flip(&proof[k], 1));
                    assert!(!ok(&p, n, &root, i, &l), "hash {k} inserted: {i} of {n}");
                    if k + 1 < proof.len() && proof[k] != proof[k + 1] {
                        let mut p = proof.clone();
                        p.swap(k, k + 1);
                        assert!(!ok(&p, n, &root, i, &l), "hashes {k} and next swapped: {i} of {n}");
                    }
                }
                let mut p = proof.clone();
                p.push([0; 32]);
                assert!(!ok(&p, n, &root, i, &l), "extra hash at the end: {i} of {n}");
                // the proof of the neighbour is not a proof for this leaf (unless the two share it)
                if i + 1 < n {
                    let other = reference.inclusion(i + 1, n);
                    if other != proof {
                        assert!(!ok(&other, n, &root, i, &l), "the proof of leaf {}: {i} of {n}", i + 1);
                    }
                }
            }
        }
        assert_eq!(verify_inclusion(&[], 0, &EMPTY_ROOT, 0, &leaf(0)), Err(Error::Invalid("leaf index is not inside the tree")));
    }

    #[test]
    fn proofs_about_trees_beyond_the_limit_are_refused() {
        let h = [7u8; 32];
        let proof = [h; 63];
        for size in [MAX_TREE_SIZE + 1, u64::MAX] {
            assert!(matches!(verify_inclusion(&proof, size, &h, size / 2, &h), Err(Error::Invalid(_))));
            assert!(matches!(verify_consistency(&proof, 5, &h, size, &h), Err(Error::Invalid(_))));
        }
        // at the limit the checks run (and refuse these made-up hashes the ordinary way)
        assert_eq!(verify_inclusion(&proof[..62], MAX_TREE_SIZE, &h, 1 << 61, &h), Err(Error::BadProof));
        assert_eq!(verify_consistency(&proof[..61], 5, &h, MAX_TREE_SIZE, &h), Err(Error::BadProof));
    }

    #[test]
    fn every_consistency_proof_of_every_pair_of_small_trees_verifies() {
        let reference = Reference::new(70);
        for n in 1..=70u64 {
            for m in 1..=n {
                let proof = reference.consistency(m, n);
                assert_eq!(verify_consistency(&proof, m, &reference.root(m), n, &reference.root(n)), Ok(()), "{m} to {n}");
            }
        }
    }

    #[test]
    fn altered_consistency_proofs_are_refused() {
        let reference = Reference::new(50);
        let ok = |p: &[Hash], m: u64, mr: &Hash, n: u64, nr: &Hash| verify_consistency(p, m, mr, n, nr).is_ok();
        for n in 2..=48u64 {
            for m in 1..n {
                let proof = reference.consistency(m, n);
                let (mr, nr) = (reference.root(m), reference.root(n));
                let why = format!("{m} to {n}");
                assert!(ok(&proof, m, &mr, n, &nr), "{why}");
                assert!(!ok(&proof, m, &flip(&mr, n as usize), n, &nr), "another old root: {why}");
                assert!(!ok(&proof, m, &mr, n, &flip(&nr, m as usize)), "another new root: {why}");
                assert!(!ok(&proof, m, &nr, n, &mr), "roots swapped: {why}");
                // as for inclusion proofs, a wrong size is only certain to fail when it changes the length
                for (m2, n2) in [(m + 1, n), (m - 1, n), (m, n + 1), (m, n - 1)] {
                    if m2 >= 1 && m2 < n2 && reference.consistency(m2, n2).len() != proof.len() {
                        assert!(!ok(&proof, m2, &mr, n2, &nr), "sizes {m2} to {n2} instead of {why}");
                    }
                }
                for k in 0..proof.len() {
                    let mut p = proof.clone();
                    p[k] = flip(&p[k], 5 * k + m as usize);
                    assert!(!ok(&p, m, &mr, n, &nr), "bit flipped in hash {k}: {why}");
                    let mut p = proof.clone();
                    p.remove(k);
                    assert!(!ok(&p, m, &mr, n, &nr), "hash {k} removed: {why}");
                    let mut p = proof.clone();
                    p.insert(k, flip(&proof[k], 3));
                    assert!(!ok(&p, m, &mr, n, &nr), "hash {k} inserted: {why}");
                    if k + 1 < proof.len() && proof[k] != proof[k + 1] {
                        let mut p = proof.clone();
                        p.swap(k, k + 1);
                        assert!(!ok(&p, m, &mr, n, &nr), "hashes {k} and next swapped: {why}");
                    }
                }
                let mut p = proof.clone();
                p.push([7; 32]);
                assert!(!ok(&p, m, &mr, n, &nr), "extra hash at the end: {why}");
                if m.is_power_of_two() {
                    // the old root is part of the proof implicitly; a proof that repeats it is not accepted
                    let mut p = vec![mr];
                    p.extend_from_slice(&proof);
                    assert!(!ok(&p, m, &mr, n, &nr), "old root repeated: {why}");
                }
            }
        }
    }

    #[test]
    fn consistency_between_equal_and_empty_trees() {
        let reference = Reference::new(9);
        let r = reference.root(9);
        assert_eq!(verify_consistency(&[], 9, &r, 9, &r), Ok(()));
        assert_eq!(verify_consistency(&[], 9, &r, 9, &flip(&r, 0)), Err(Error::BadProof));
        assert_eq!(verify_consistency(&[r], 9, &r, 9, &r), Err(Error::BadProof));
        assert!(matches!(verify_consistency(&[], 0, &EMPTY_ROOT, 9, &r), Err(Error::Invalid(_))), "an empty old tree has no proof");
        assert!(matches!(verify_consistency(&[], 10, &r, 9, &r), Err(Error::Invalid(_))), "a tree does not shrink");
    }

    #[test]
    fn proofs_in_trees_of_a_thousand_and_more_leaves() {
        let reference = Reference::new(3000);
        for &n in &[999u64, 1000, 1023, 1024, 1025, 2047, 2048, 2049, 3000] {
            let root = reference.root(n);
            for &i in &[0, 1, n / 3, n / 2, n - 2, n - 1] {
                let proof = reference.inclusion(i, n);
                assert!(verify_inclusion(&proof, n, &root, i, &leaf(i)).is_ok(), "leaf {i} of {n}");
            }
            for &m in &[1u64, 2, 255, 256, 257, 512, 998, n - 1] {
                if m == 0 || m > n {
                    continue;
                }
                let proof = reference.consistency(m, n);
                assert!(verify_consistency(&proof, m, &reference.root(m), n, &root).is_ok(), "{m} to {n}");
            }
        }
    }

    #[test]
    fn proof_checks_do_not_overflow_on_huge_sizes() {
        let junk: Vec<Hash> = (0..70).map(|i| leaf(i)).collect();
        for &size in &[u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) + 1, 1 << 62] {
            for len in [0usize, 1, 5, 63, 64, 65, 70] {
                for &index in &[0u64, 1, size / 2, size - 1] {
                    assert!(verify_inclusion(&junk[..len], size, &leaf(0), index, &leaf(1)).is_err());
                }
                for &old in &[1u64, 2, 3, size / 2, size - 1, size] {
                    let _ = verify_consistency(&junk[..len], old, &leaf(0), size, &leaf(1));
                }
            }
        }
    }

    #[test]
    fn the_real_proofs_of_sum_golang_org_verify() {
        // Proofs for the real capture (see tests/data/sumdb), made by Go's tlog.ProveRecord and
        // ProveTree from the real tiles and checked there by tlog.CheckRecord and CheckTree: that
        // record 24955599 is in the tree of 66746981 records, and that the tree of 66746896 is a
        // prefix of it. These are the only proofs here that were not made by code of this crate or
        // by the reference implementation next to it.
    const INCLUSION: [&str; 26] = [
        "rfERqRVjGO5h2W9jXQnEu3TlrGcX/55kAWOF2vhEo7w=",
        "mn7xFfMw3fADAlFyS5GrrGh2LH+68I+6bjqyIm0wrQU=",
        "3ErWWb+C6ewAC03stU/Z26srAmR+8ACuaiwlSrfUWEQ=",
        "IEdtFQeTsx3jMC+m0+bZyc7ZD1ElNbQqtvkDsPL4KSA=",
        "ZWavXKBCVwQd33ECdndNt+NRieLrwkj+D2t0kEieBJM=",
        "zgqe79yqCainFrhOzaecBBP1dWsfcVkBxfAGV1w/Xow=",
        "fp1DrZ0hAAfm30IrXaTHZZk5SVUlRR2c/tPy7SKRFGg=",
        "0i5Y/yMqX1p7z8GUXxb9Y6B51roqncwdaM8jdurDpyQ=",
        "4E9tkh1fEdRzhCKytKmHKB9uBbTfwt/cZcmqtevnxAE=",
        "DE1fZNHAqKr7NeyNknoDU8DvxdD+IwUxWuOkZuo3qt4=",
        "WFSQHElkE+lgoL4rP+Wdf7zhDSgkZPER/6fTY4Szxak=",
        "3V+crfQ1C4VKIW7//Ra7ngDZQTHH8zTLgWUhOFbx7Vk=",
        "XGXEWeHCM/oqdIgErgLCfrwkRNIaOE2fZxZ6e8r4fTw=",
        "XE4DFS1hMjxSoDE+JDL3/XOHOfoKCPrcLsqICOa+gc8=",
        "q8k4z7LsSaDbbUecf7ajVXccI7kCpPmAyj+xNCmpT3M=",
        "ppMpmdexmCww+NprNuWxI0SUcVON6nAFqp4ihv8CaFo=",
        "oxoWqklYgiDqw4l5/tsnwv/DZ6YT3H9cryedM3TEVOg=",
        "sXFzC86eYTdKzqkb2nv7WBRyfP9fBuJA3vyhUbR4WlE=",
        "/3pp5uTMVaxeQpnUm/wbyR2b/twhecZIa9D9Y4XrYEQ=",
        "r7ijLWQStZbBbZnbyfVRghfU9AweBxyaaKMeHWp16g0=",
        "fdGPAOA5xLhhVP5WJlmxhWnJrgpJhL0cT+gmSl0GaVU=",
        "TWQs0Gq7mzUaa5fGQ8mTgeXSSo1bO4RAsF45pPCCKvI=",
        "ROjUzjXHDN0Yo/I6EeqHhpszFgIs7FCABVeQniliPTk=",
        "NTjIv8CJqIIGrOHhNQWSP9FV6XEPL6uGA4lmMfNKGJg=",
        "bwqUQG2wJXGxo1QLA2CFb3chH17xvlqXe6eQy43p0HY=",
        "EQDSw1BZS5Txp/vi6UvOl96iMySXhIow1QsfYwPuDW8=",
    ];
    const CONSISTENCY: [&str; 17] = [
        "c9ihnUhDNmWMqc08/Mvzft5zi0s9uNPG9GYom9AABNE=",
        "V9AENg5wtDMLGXqLbglBhcDeQ8lIlt3o7dK9mUQ7Jm4=",
        "l9Ou6mZhBILzdsVLk6YnQjz1iUAYUIHYJIg/SWYN47c=",
        "VmeOTOas0UfTFVR3VD4AiPtXwuGre/BE4EllqiuFhEQ=",
        "sQm37/0gnCCPXjEWSP8xvdFw+n4UOKNCRxVnPh5mYWA=",
        "gotSI2HndrVmqX0IJ4ZWG3ECe5L0dwkiHk89psXGt0I=",
        "KK18YzBGge2IBKmk9+Chqy3RMEju64kd+PNDpJ/Bh8w=",
        "u7yfSNMAgRfPOkdrGxnUyT2oJ9x9cEQQHGh6NmOTLm4=",
        "oXkz39T6sjh05I00ywd8WXxgw+fPg0Rn8tZrui+A64c=",
        "T4DT2nAl/Mkp2zOKvnzdKfe8k+PzLODWsoVvB3wsP9A=",
        "1Nftnp85/YX9SvG+/z5QQdyI1slrRbO13FuJoJ4a1kU=",
        "uegnZKdyiyV/S/Zs4KMgBEWfcjuvcWH2cTUNYmMidc8=",
        "N93UzP9OApexfiqGioqimDO27Kox9nIOns5dOFFTylg=",
        "2IzbyezmwwGZZPJ276ejAQZiAnar+RcjAUU3MEMtbIA=",
        "k3kfr9AECmkV+UA3/D6EMqaBDr67aubL5hXGsvJ+Nng=",
        "/WnQtddEqG03mbcU1XID1iws1nlKHVkJcaREWknCOiE=",
        "xJ20xXM4QItt5vxFOtolZ5l18p7ej1+RimNkgWmoRFM=",
    ];
        let b64 = |s: &str| -> Hash { crate::pem::base64_decode(s).unwrap().try_into().unwrap() };
        let new = Tree { size: 66746981, root: b64("3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=") };
        let old = Tree { size: 66746896, root: b64("dZ4n3o/nb32Y8rCuyUc1VeuATkhefsubWOYVhA9QIc8=") };
        let record = "golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=\ngolang.org/x/mod v0.17.0/go.mod h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c=\n";
        let leaf = record_hash(record.as_bytes());
        assert_eq!(crate::pem::base64_encode(&leaf), "Rvw4UpWZ9V67Bdyxyc7qtKjg8lt2lMRVbGt8x24H6Hg=");
        let inclusion: Vec<Hash> = INCLUSION.iter().map(|s| b64(s)).collect();
        let consistency: Vec<Hash> = CONSISTENCY.iter().map(|s| b64(s)).collect();
        assert_eq!(verify_inclusion(&inclusion, new.size, &new.root, 24955599, &leaf), Ok(()));
        assert_eq!(verify_consistency(&consistency, old.size, &old.root, new.size, &new.root), Ok(()));
        // and nothing else: not another record, another place, another tree, a damaged proof
        assert!(verify_inclusion(&inclusion, new.size, &new.root, 24955598, &leaf).is_err());
        assert!(verify_inclusion(&inclusion, new.size, &new.root, 24955599, &record_hash(b"other")).is_err());
        assert!(verify_inclusion(&inclusion, new.size, &old.root, 24955599, &leaf).is_err());
        assert!(verify_inclusion(&inclusion[1..], new.size, &new.root, 24955599, &leaf).is_err());
        assert!(verify_consistency(&consistency, old.size - 1, &old.root, new.size, &new.root).is_err());
        assert!(verify_consistency(&consistency, old.size, &new.root, new.size, &old.root).is_err());
        for k in 0..consistency.len() {
            let mut p = consistency.clone();
            p[k] = flip(&p[k], 100);
            assert!(verify_consistency(&p, old.size, &old.root, new.size, &new.root).is_err(), "hash {k}");
        }
        for k in 0..inclusion.len() {
            let mut p = inclusion.clone();
            p[k] = flip(&p[k], 100);
            assert!(verify_inclusion(&p, new.size, &new.root, 24955599, &leaf).is_err(), "hash {k}");
        }
    }

    // ------------------------------------------------------------------------ tile paths

    #[test]
    fn tile_paths() {
        // the examples in Go's documentation of the format
        let t = Tile { height: 3, level: 4, index: 1234067, width: 1 };
        assert_eq!(t.path(), "tile/3/4/x001/x234/067.p/1");
        assert_eq!(Tile { width: 8, ..t }.path(), "tile/3/4/x001/x234/067");
        assert_eq!(Tile::parse_path("tile/3/4/x001/x234/067.p/1"), Ok(t));
        assert_eq!(Tile::parse_path("tile/3/4/x001/x234/067"), Ok(Tile { width: 8, ..t }));
        // and the ones of the real capture
        assert_eq!(Tile { height: 8, level: 0, index: 260730, width: 101 }.path(), "tile/8/0/x260/730.p/101");
        assert_eq!(Tile { height: 8, level: 3, index: 0, width: 3 }.path(), "tile/8/3/000.p/3");
        assert_eq!(Tile { height: 8, level: 1, index: 380, width: 256 }.path(), "tile/8/1/380");
        assert_eq!(Tile { height: 8, level: 0, index: 97482, width: 256 }.path(), "tile/8/0/x097/482");
        // round trip over a spread of tiles
        for height in [1u32, 2, 8, 13, 30] {
            for level in [0u32, 1, 2] {
                for index in [0u64, 1, 9, 999, 1000, 1001, 123456789, 99_000_000_000] {
                    for width in [1u32, 1 << (height - 1), (1u32 << height) - 1, 1 << height] {
                        let t = Tile { height, level, index, width };
                        if t.validate().is_ok() {
                            assert_eq!(Tile::parse_path(&t.path()), Ok(t), "{}", t.path());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_tile_paths_are_refused() {
        for bad in [
            "",
            "tile",
            "tile/8/0",
            "tile/8/0/",
            "tiles/8/0/001",
            "tile/0/0/001",
            "tile/31/0/001",
            "tile/8/63/001",
            "tile/+8/0/001",
            "tile/08/0/001",
            "tile/8/00/001",
            "tile/8/0/1",
            "tile/8/0/0001",
            "tile/8/0/x001",
            "tile/8/0/x000/001", // a leading group of zeros is not how the number is written
            "tile/8/0/001/002",
            "tile/8/0/001.p",
            "tile/8/0/001.p/",
            "tile/8/0/001.p/0",
            "tile/8/0/001.p/256", // a full tile has no .p
            "tile/8/0/001.p/257",
            "tile/8/0/001.p/01",
            "tile/8/0/001.p/-1",
            "tile/8/0/001.p/5/6",
            "tile/8/data/001",
            "tile/8/-1/001",
            "/tile/8/0/001",
            "tile/8/0/001/",
            "tile/8/0/x999/x999/x999/x999/x999/999", // beyond the largest tree
            "tile/8/0/x999999999999999999999/001",
        ] {
            assert!(Tile::parse_path(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn tile_sets_check_lengths_and_serve_partial_tiles_from_full_ones() {
        let mut set = TileSet::new();
        let partial = Tile { height: 2, level: 0, index: 3, width: 3 };
        assert!(set.insert(partial, vec![0; 95]).is_err());
        assert!(set.insert(partial, vec![0; 97]).is_err());
        assert!(set.insert(Tile { height: 2, level: 0, index: 3, width: 5 }, vec![0; 160]).is_err());
        assert!(set.insert(Tile { height: 31, level: 0, index: 0, width: 1 }, vec![0; 32]).is_err());
        assert!(set.get(&partial).is_none());
        let full: Vec<u8> = (0..128u8).collect();
        set.insert(partial.full(), full.clone()).unwrap();
        assert_eq!(set.get(&partial), Some(&full[..96]));
        assert_eq!(set.get(&Tile { width: 1, ..partial }), Some(&full[..32]));
        assert_eq!(set.get(&partial.full()), Some(&full[..]));
        assert!(set.get(&Tile { index: 2, ..partial }).is_none());
        // an exact tile wins over a prefix of the full one
        set.insert(partial, vec![9; 96]).unwrap();
        assert_eq!(set.get(&partial), Some(&[9u8; 96][..]));
        assert_eq!(set.len(), 2);
    }

    // ------------------------------------------------------------------------ reading tiles

    /// The trees (size, tile height) the tile tests run over: every size around the places where the
    /// shape of the tiling changes, for tall and short tiles.
    fn tilings() -> Vec<(u64, u32)> {
        let mut v = Vec::new();
        for h in 1..=4u32 {
            for n in 1..=(3u64 << (2 * h)).min(150) {
                v.push((n, h));
            }
        }
        for n in [255u64, 256, 257, 258, 511, 512, 513, 65535, 65536, 65537, 65792, 70000] {
            v.push((n, 8));
        }
        v
    }

    #[test]
    fn every_node_of_every_tiling_reads_back() {
        let reference = Reference::new(70_000);
        for (n, h) in tilings() {
            let tree = reference.tree(n);
            // every perfect node that lies inside the tree, up to a bound that keeps this quick
            let mut nodes = Vec::new();
            for level in 0..=62u32 {
                let width = n >> level;
                if width == 0 {
                    break;
                }
                let step = (width / 40).max(1);
                let mut i = 0;
                while i < width {
                    nodes.push(Node { level, index: i });
                    i += step;
                }
                nodes.push(Node { level, index: width - 1 });
            }
            let tiles = tiles_for(&tree, h, &nodes).unwrap();
            let set = reference.tile_set(&tiles);
            let got = read_nodes(&tree, h, &nodes, &set).unwrap_or_else(|e| panic!("size {n}, height {h}: {e}"));
            for (node, hash) in nodes.iter().zip(&got) {
                assert_eq!(*hash, reference.node(node.level, node.index), "size {n}, height {h}, node {node:?}");
            }
            // one at a time gives the same answers and needs no tile the batch did not list
            for node in nodes.iter().step_by(7) {
                let one = tiles_for(&tree, h, &[*node]).unwrap();
                assert!(one.iter().all(|t| tiles.contains(t)), "size {n}, height {h}");
                let got = read_nodes(&tree, h, &[*node], &reference.tile_set(&one)).unwrap();
                assert_eq!(got[0], reference.node(node.level, node.index));
            }
        }
    }

    #[test]
    fn no_byte_of_any_tile_can_be_changed() {
        let reference = Reference::new(70_000);
        for (n, h) in tilings().into_iter().step_by(5) {
            let tree = reference.tree(n);
            for index in [0, n / 2, n - 1] {
                let node = Node { level: 0, index };
                let tiles = tiles_for(&tree, h, &[node]).unwrap();
                let good = reference.tile_set(&tiles);
                assert!(read_nodes(&tree, h, &[node], &good).is_ok());
                for t in &tiles {
                    let data = good.get(t).unwrap().to_vec();
                    let len = data.len();
                    let mut positions: Vec<usize> = vec![0, 1, 31, 32, len / 2, len - 1];
                    positions.extend((0..len).step_by(len / 13 + 1));
                    for at in positions {
                        if at >= len {
                            continue;
                        }
                        let mut bad = data.clone();
                        bad[at] ^= 0x10;
                        let mut set = good.clone();
                        set.insert(*t, bad).unwrap();
                        let err = read_nodes(&tree, h, &[node], &set).expect_err(&format!("size {n}, height {h}: byte {at} of {} changed", t.path()));
                        assert!(matches!(err, Error::TilesDoNotMatchRoot | Error::TileDoesNotMatchParent(_)), "{err}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_tile_that_is_missing_is_named() {
        let reference = Reference::new(1000);
        let tree = reference.tree(1000);
        let node = Node { level: 0, index: 5 };
        let tiles = tiles_for(&tree, 3, &[node]).unwrap();
        for skip in 0..tiles.len() {
            let rest: Vec<Tile> = tiles.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, t)| *t).collect();
            let err = read_nodes(&tree, 3, &[node], &reference.tile_set(&rest)).unwrap_err();
            assert_eq!(err, Error::MissingTile(tiles[skip]));
        }
    }

    #[test]
    fn tiles_of_another_tree_are_refused() {
        let a = Reference::new(500);
        // the same records but one is different
        let mut leaves: Vec<Hash> = (0..500).map(leaf).collect();
        leaves[137] = leaf(9999);
        let b = Reference::with_leaves(leaves);
        let tree = a.tree(500);
        let node = Node { level: 0, index: 136 };
        let tiles = tiles_for(&tree, 4, &[node]).unwrap();
        assert!(read_nodes(&tree, 4, &[node], &a.tile_set(&tiles)).is_ok());
        assert_eq!(read_nodes(&tree, 4, &[node], &b.tile_set(&tiles)).unwrap_err(), Error::TilesDoNotMatchRoot);
        // right tiles, wrong root
        let wrong = Tree { size: 500, root: b.root(500) };
        assert_eq!(read_nodes(&wrong, 4, &[node], &a.tile_set(&tiles)).unwrap_err(), Error::TilesDoNotMatchRoot);
    }

    #[test]
    fn records_and_prefixes_are_checked_against_the_tiles() {
        let reference = Reference::new(300);
        let tree = reference.tree(300);
        for index in [0u64, 1, 100, 255, 256, 299] {
            let tiles = tiles_for_record(&tree, 4, index).unwrap();
            let set = reference.tile_set(&tiles);
            assert_eq!(check_record(&tree, 4, index, &leaf(index), &set), Ok(()), "record {index}");
            assert_eq!(check_record(&tree, 4, index, &leaf(index + 1), &set), Err(Error::RecordMismatch), "record {index}");
        }
        assert!(matches!(check_record(&tree, 4, 300, &leaf(300), &TileSet::new()), Err(Error::Invalid(_))));
        assert!(matches!(tiles_for_record(&tree, 4, 300), Err(Error::Invalid(_))));
        for older in [0u64, 1, 2, 17, 255, 256, 257, 299, 300] {
            let old = reference.tree(older);
            let tiles = tiles_for_prefix(&tree, 4, older).unwrap();
            assert_eq!(tiles.is_empty(), older == 0 || older == 300, "tiles for a prefix of {older}");
            assert_eq!(check_prefix(&old, &tree, 4, &reference.tile_set(&tiles)), Ok(()), "prefix {older}");
        }
        assert!(matches!(check_prefix(&tree, &reference.tree(299), 4, &TileSet::new()), Err(Error::Invalid(_))), "a tree is not a prefix of a smaller one");
    }

    #[test]
    fn a_forked_history_is_reported_as_a_fork() {
        let honest = Reference::new(300);
        let mut leaves: Vec<Hash> = (0..300).map(leaf).collect();
        leaves[40] = leaf(77_777);
        let forked = Reference::with_leaves(leaves);
        // the log showed `honest` at size 100 and later `forked` at size 300, which rewrote record 40
        let old = honest.tree(100);
        let new = forked.tree(300);
        let tiles = tiles_for_prefix(&new, 4, 100).unwrap();
        match check_prefix(&old, &new, 4, &forked.tile_set(&tiles)) {
            Err(Error::Fork { size: 100, expected, computed }) => {
                assert_eq!(expected, old.root);
                assert_eq!(computed, forked.root(100));
            }
            other => panic!("expected a fork, got {other:?}"),
        }
        // a record after the rewritten one does not matter: the same history is also a fork at size 41
        assert!(matches!(check_prefix(&honest.tree(41), &new, 4, &forked.tile_set(&tiles_for_prefix(&new, 4, 41).unwrap())), Err(Error::Fork { .. })));
        // before the rewritten record the histories agree
        assert_eq!(check_prefix(&honest.tree(40), &new, 4, &forked.tile_set(&tiles_for_prefix(&new, 4, 40).unwrap())), Ok(()));
        // equal sizes with different roots need no tiles to be a fork
        let other = Tree { size: 300, root: honest.root(300) };
        assert!(matches!(check_prefix(&other, &new, 4, &TileSet::new()), Err(Error::Fork { size: 300, .. })));
        assert_eq!(check_prefix(&new, &new, 4, &TileSet::new()), Ok(()));
        // the empty tree is the prefix of everything, with exactly one root
        let empty = Tree { size: 0, root: EMPTY_ROOT };
        assert_eq!(check_prefix(&empty, &new, 4, &TileSet::new()), Ok(()));
        assert!(matches!(check_prefix(&Tree { size: 0, root: [1; 32] }, &new, 4, &TileSet::new()), Err(Error::Fork { size: 0, .. })));
    }

    #[test]
    fn limits_are_enforced() {
        let reference = Reference::new(10);
        let tree = reference.tree(10);
        let node = Node { level: 0, index: 0 };
        for h in [0u32, 31, 100] {
            assert!(matches!(tiles_for(&tree, h, &[node]), Err(Error::Invalid(_))), "height {h}");
        }
        assert!(matches!(tiles_for(&Tree { size: MAX_TREE_SIZE + 1, root: [0; 32] }, 8, &[]), Err(Error::Invalid(_))));
        assert!(tiles_for(&Tree { size: MAX_TREE_SIZE, root: [0; 32] }, 8, &[Node { level: 0, index: MAX_TREE_SIZE - 1 }]).is_ok());
        assert!(tiles_for(&Tree { size: MAX_TREE_SIZE, root: [0; 32] }, 8, &[Node { level: 62, index: 0 }]).is_ok());
        for bad in [Node { level: 0, index: 10 }, Node { level: 1, index: 5 }, Node { level: 4, index: 0 }, Node { level: 63, index: 0 }, Node { level: 200, index: 0 }, Node { level: 0, index: u64::MAX }] {
            assert!(matches!(tiles_for(&tree, 3, &[bad]), Err(Error::Invalid(_))), "{bad:?}");
        }
        // an empty tree has nothing to read
        let empty = Tree { size: 0, root: EMPTY_ROOT };
        assert_eq!(read_nodes(&empty, 8, &[], &TileSet::new()), Ok(Vec::new()));
        assert!(matches!(tiles_for(&empty, 8, &[node]), Err(Error::Invalid(_))));
        // a tree as big as the limit: the plan has one tile per level and the shapes do not overflow
        let huge = Tree { size: MAX_TREE_SIZE - 1, root: [0; 32] };
        for h in [1u32, 2, 7, 8, 30] {
            let plan = tiles_for(&huge, h, &[Node { level: 0, index: MAX_TREE_SIZE - 2 }, Node { level: 0, index: 0 }, Node { level: 31, index: 3 }]).unwrap();
            assert!(plan.iter().all(|t| t.validate().is_ok()), "height {h}");
        }
    }

    #[test]
    fn a_tile_of_any_height_can_be_asked_about_without_a_panic() {
        // Tile fields are public, so a tile can have a height that no tile has; the methods are for
        // looking at such a tile (and `validate` refuses it), not for stopping the program.
        for height in [0u32, 1, 8, 30, 31, 32, 33, 63, 64, 65, 1000, u32::MAX] {
            for width in [0u32, 1, 256, u32::MAX] {
                let t = Tile { height, level: 0, index: 12345, width };
                let _ = t.is_full();
                let _ = t.full();
                let _ = t.path();
                let _ = t.data_len();
                if height > MAX_TILE_HEIGHT {
                    assert!(t.validate().is_err(), "height {height}");
                }
                if height >= 32 {
                    // 2^height does not fit a width, so there is no full tile of this height
                    assert!(!t.is_full(), "height {height} width {width}");
                    assert_eq!(t.full(), t, "an impossible height changes nothing");
                }
            }
        }
        // for a real height they still mean what they did
        let t = Tile { height: 8, level: 0, index: 0, width: 256 };
        assert!(t.is_full() && t.full() == t);
        let p = Tile { width: 100, ..t };
        assert!(!p.is_full());
        assert_eq!(p.full().width, 256);
        assert_eq!(p.path(), "tile/8/0/000.p/100");
        assert!(Tile { height: 31, level: 0, index: 0, width: 1 << 31 }.is_full());
    }

    #[test]
    fn a_tree_over_the_size_limit_is_refused_by_the_prefix_check_as_well() {
        let big = Tree { size: u64::MAX, root: [7; 32] };
        let over = Tree { size: MAX_TREE_SIZE + 1, root: [7; 32] };
        let ok = Tree { size: MAX_TREE_SIZE, root: [7; 32] };
        let tiles = TileSet::new();
        for t in [&big, &over] {
            // equal sizes used to be answered from the roots alone, with no limit applied
            assert!(matches!(check_prefix(t, t, 8, &tiles), Err(Error::Invalid(_))), "{}", t.size);
            assert!(matches!(check_prefix(&Tree { size: 0, root: EMPTY_ROOT }, t, 8, &tiles), Err(Error::Invalid(_))));
            assert!(matches!(tiles_for_prefix(t, 8, t.size), Err(Error::Invalid(_))));
            assert!(matches!(tiles_for_prefix(t, 8, 0), Err(Error::Invalid(_))));
        }
        // at the limit itself, equal trees are a prefix of each other by their roots, as before
        assert!(check_prefix(&ok, &ok, 8, &tiles).is_ok());
        assert_eq!(tiles_for_prefix(&ok, 8, ok.size).unwrap(), Vec::new());
    }

    // ------------------------------------------------------------------------ the shape of a plan

    /// The width of tile (`level`, `index`) of a tree of `size` leaves with tiles of `height`, written out from the
    /// definition and not from `tlog.rs`: the tile lists tree level `height * level`, which has `size >> (height *
    /// level)` nodes, and it starts at node `index << height`. `None` where the tree has no such tile.
    fn expected_tile_width(size: u64, height: u32, level: u32, index: u64) -> Option<u64> {
        let shift = level as u64 * height as u64;
        if shift > 62 {
            return None;
        }
        let nodes = size >> shift;
        let start = (index as u128) << height;
        if start >= nodes as u128 {
            None
        } else {
            Some((1u64 << height).min(nodes - start as u64))
        }
    }

    /// Plans the tiles for `node` and checks every one of them against `expected_tile_width`.
    fn assert_plan_has_the_shape_of_the_tree(size: u64, height: u32, node: Node) -> usize {
        let tree = Tree { size, root: [7; 32] };
        let tiles = tiles_for(&tree, height, &[node]).unwrap_or_else(|e| panic!("size {size}, height {height}, {node:?}: {e}"));
        assert!(!tiles.is_empty(), "size {size}, height {height}, {node:?}");
        for t in &tiles {
            let want = expected_tile_width(size, height, t.level, t.index);
            assert_eq!(want, Some(t.width as u64), "size {size}, height {height}, {node:?}: {t:?}");
            assert_eq!(t.height, height);
            t.validate().unwrap_or_else(|e| panic!("size {size}, height {height}, {node:?}: {t:?}: {e}"));
        }
        tiles.len()
    }

    #[test]
    fn a_tile_is_planned_for_every_node_of_every_size_at_every_height() {
        // every node of every tree up to 130 leaves, with tiles of 2 to 64 entries: the right-hand edge of a tree
        // is where a partial tile and the parents of a node that has none to its right can go wrong
        let mut planned = 0;
        for size in 1..=130u64 {
            for height in 1..=6u32 {
                let tree = Tree { size, root: [7; 32] };
                let mut level = 0;
                while size >> level >= 1 {
                    let count = size >> level;
                    for index in 0..count {
                        planned += assert_plan_has_the_shape_of_the_tree(size, height, Node { level, index });
                    }
                    // the nodes just past the end of the level are not in the tree
                    for index in [count, count + 1, u64::MAX >> 8] {
                        assert!(tiles_for(&tree, height, &[Node { level, index }]).is_err(), "size {size}, height {height}, level {level}, index {index}");
                    }
                    level += 1;
                }
                // and a level above the root
                assert!(tiles_for(&tree, height, &[Node { level, index: 0 }]).is_err(), "size {size}, height {height}, level {level}");
            }
        }
        assert!(planned > 100_000, "{planned}");
    }

    #[test]
    fn the_plan_for_huge_trees_has_the_shape_of_the_tree_at_every_height() {
        let mut sizes: Vec<u64> = vec![MAX_TREE_SIZE, 1 << 20 | 12345, 1_000_000_007];
        for k in 0..=62u32 {
            // 2^k and its neighbours, and 3 * 2^k and its neighbours
            for base in [Some(1u64 << k), 3u64.checked_mul(1u64 << k)] {
                for d in [-2i64, -1, 0, 1, 2] {
                    if let Some(n) = base.and_then(|b| b.checked_add_signed(d)) {
                        if (1..=MAX_TREE_SIZE).contains(&n) {
                            sizes.push(n);
                        }
                    }
                }
            }
        }
        sizes.sort_unstable();
        sizes.dedup();
        let mut planned = 0;
        for &size in &sizes {
            for height in [1u32, 2, 3, 4, 7, 8, 13, 16, 29, MAX_TILE_HEIGHT] {
                let mut level = 0;
                while size >> level >= 1 {
                    let count = size >> level;
                    // the first node, the last, and the one in the middle of each level
                    for index in [0, count / 2, count - 1] {
                        planned += assert_plan_has_the_shape_of_the_tree(size, height, Node { level, index });
                    }
                    level += 1;
                }
            }
        }
        // the widest a tile can be (2^30 entries) is the widest the plan ever asks for, and it fits the u32 of `width`
        let widest = tiles_for(&Tree { size: MAX_TREE_SIZE, root: [7; 32] }, MAX_TILE_HEIGHT, &[Node { level: 0, index: 0 }]).unwrap();
        let bottom = widest.iter().find(|t| t.level == 0).expect("the tile of the leaves");
        assert_eq!(bottom.width, 1 << MAX_TILE_HEIGHT);
        assert_eq!(bottom.data_len(), 32u64 << MAX_TILE_HEIGHT);
        assert!(planned > 10_000, "{planned}");
    }

    #[test]
    fn the_ancestor_of_a_tile_is_none_where_the_tree_has_nothing() {
        // 200 leaves, tiles of 4. Tile level 0 lists the 200 leaves: 50 tiles, the last one full. Tile level 1 lists
        // the 50 nodes of tree level 2: 13 tiles, the last with 2. Tile level 2 lists the 12 nodes of tree level 4
        // (there is no 13th: it would need leaves 192 to 207): 3 full tiles. Tile level 3 lists the 3 nodes of tree
        // level 6: one tile with 3.
        let leaf_tile = |index| Tile { height: 2, level: 0, index, width: 4 };
        let ancestor = |index, k| tile_ancestor(leaf_tile(index), k, 200).map(|t| (t.level, t.index, t.width));
        assert_eq!(ancestor(49, 0), Some((0, 49, 4)));
        assert_eq!(ancestor(49, 1), Some((1, 12, 2)));
        assert_eq!(ancestor(49, 2), None); // the last leaves have no node of tree level 4 above them
        assert_eq!(ancestor(49, 3), Some((3, 0, 3)));
        assert_eq!(ancestor(0, 1), Some((1, 0, 4)));
        assert_eq!(ancestor(0, 2), Some((2, 0, 4)));
        // one tile past the last: the tree has nothing there, however it is reached
        assert_eq!(ancestor(50, 0), None);
        assert_eq!(ancestor(51, 0), None);
        assert_eq!(ancestor(52, 1), None);
        // above the top of the tree, and beyond the 62 levels there can be
        assert_eq!(tile_ancestor(Tile { height: 2, level: 0, index: 0, width: 4 }, 6, 200), None);
        assert_eq!(tile_ancestor(Tile { height: 30, level: 0, index: 0, width: 1 }, 3, MAX_TREE_SIZE), None);
        assert_eq!(tile_ancestor(Tile { height: 8, level: 1, index: 0, width: 1 }, u32::MAX, 200), None);
    }

    #[test]
    fn node_tile_never_truncates_the_width_it_computes() {
        for height in 1..=MAX_TILE_HEIGHT {
            for level in [0u32, 1, height - 1, height, height + 1, 2 * height, 61, 62] {
                if level > 62 {
                    continue;
                }
                let last = (MAX_TREE_SIZE >> level) - 1;
                for index in [0, 1, last / 2, last.saturating_sub(1), last] {
                    let node = Node { level, index };
                    let (tile, lo, hi) = node_tile(height, node);
                    let sub = level % height;
                    // the node covers 2^sub entries of the tile, ending at `hi`, and the tile is as wide as its last entry
                    assert_eq!(hi - lo, 1usize << sub, "height {height}, {node:?}");
                    assert!(hi as u64 <= 1u64 << height, "height {height}, {node:?}");
                    assert_eq!(tile.width as usize, hi, "height {height}, {node:?}");
                    assert_eq!(tile.level, level / height);
                }
            }
        }
    }
}
